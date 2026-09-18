//! Durable, hash-bound publication of immutable BNRAW segments.
//!
//! A segment becomes manifest authority only after its terminal ACK has been
//! checked against the exact, clean BNRAW file and the corresponding manifest
//! record has completed `sync_all`.  Damaged manifest tails are never appended
//! through or silently truncated; recovery copies the verified prefix into a
//! new artifact and preserves the source as evidence.

use crate::{
    DurabilityAckV1, DurableSink, RawSegmentGenesisV1, RawSegmentSealV1, Result,
    StreamDurabilityWatermarkV1, scan_raw_segment, seal_raw_segment,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const MANIFEST_MAGIC: &[u8; 8] = b"BNSEG\0\x01\n";
const MAX_MANIFEST_RECORD_BYTES: usize = 1024 * 1024;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManifestBodyV1 {
    schema: String,
    record_index: u64,
    previous_manifest_record_sha256: String,
    seal: RawSegmentSealV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RawSegmentManifestEntryV1 {
    pub schema: &'static str,
    pub record_index: u64,
    pub previous_manifest_record_sha256: String,
    pub manifest_record_sha256: String,
    pub seal: RawSegmentSealV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RawSegmentManifestAckV1 {
    pub schema: &'static str,
    pub record_index: u64,
    pub segment_index: u64,
    pub durable_through_offset: u64,
    pub record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RawSegmentManifestScanV1 {
    pub schema: &'static str,
    pub path: PathBuf,
    pub file_size: u64,
    pub records: u64,
    pub last_good_offset: u64,
    pub clean_eof: bool,
    pub reason: Option<String>,
    pub last_record_sha256: String,
    pub entries: Vec<RawSegmentManifestEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RawSegmentManifestRecoveryV1 {
    pub schema: &'static str,
    pub source: PathBuf,
    pub destination: PathBuf,
    pub source_file_size: u64,
    pub copied_valid_prefix_bytes: u64,
    pub excluded_tail_bytes: u64,
    pub recovered_records: u64,
    pub last_record_sha256: String,
}

/// Capability returned only after matching a terminal ACK to an exact BNRAW
/// segment.  The fields remain private so callers cannot fabricate a verified
/// segment and publish it through `RawSegmentManifestWriter`.
#[derive(Clone, Debug)]
pub struct VerifiedRawSegmentV1 {
    raw_path: PathBuf,
    genesis: RawSegmentGenesisV1,
    ack: DurabilityAckV1,
    seal: RawSegmentSealV1,
}

impl VerifiedRawSegmentV1 {
    pub fn raw_path(&self) -> &Path {
        &self.raw_path
    }

    pub fn genesis(&self) -> &RawSegmentGenesisV1 {
        &self.genesis
    }

    pub fn ack(&self) -> &DurabilityAckV1 {
        &self.ack
    }

    pub fn seal(&self) -> &RawSegmentSealV1 {
        &self.seal
    }
}

pub fn root_segment_genesis(connection_epoch: &str, stream: &str) -> Result<RawSegmentGenesisV1> {
    if connection_epoch.trim().is_empty() || stream.trim().is_empty() {
        return Err("root segment identity must not be empty".to_owned());
    }
    Ok(RawSegmentGenesisV1 {
        schema: "RawSegmentGenesisV1".to_owned(),
        segment_index: 0,
        previous_segment_terminal_sha256: ZERO_DIGEST.to_owned(),
        connection_epoch: connection_epoch.to_owned(),
        stream: stream.to_owned(),
        next_frame_index: 0,
    })
}

pub fn successor_segment_genesis(previous: &RawSegmentSealV1) -> Result<RawSegmentGenesisV1> {
    validate_seal_shape(previous)?;
    Ok(RawSegmentGenesisV1 {
        schema: "RawSegmentGenesisV1".to_owned(),
        segment_index: previous
            .segment_index
            .checked_add(1)
            .ok_or_else(|| "raw segment index overflow".to_owned())?,
        previous_segment_terminal_sha256: previous.terminal_record_sha256.clone(),
        connection_epoch: previous.connection_epoch.clone(),
        stream: previous.stream.clone(),
        next_frame_index: previous
            .last_frame_index
            .checked_add(1)
            .ok_or_else(|| "raw segment frame index overflow".to_owned())?,
    })
}

/// Verifies identity, frame range, record count, terminal digest, exact byte
/// boundary and clean EOF before creating a publishable seal capability.
pub fn verify_and_seal_raw_segment(
    raw_path: &Path,
    raw_file: &str,
    genesis: &RawSegmentGenesisV1,
    ack: &DurabilityAckV1,
) -> Result<VerifiedRawSegmentV1> {
    validate_relative_file(raw_file)?;
    if raw_path.file_name().and_then(|value| value.to_str()) != Some(raw_file) {
        return Err("raw segment path does not match manifest file name".to_owned());
    }
    let scan = scan_raw_segment(raw_path, genesis)?;
    if !scan.clean_eof {
        return Err(format!(
            "raw segment has no clean EOF: {}",
            scan.reason.as_deref().unwrap_or("unknown error")
        ));
    }
    if ack.schema != "DurabilityAckV1" || ack.streams.len() != 1 {
        return Err("invalid raw segment terminal ACK".to_owned());
    }
    let watermark = &ack.streams[0];
    if scan.file_size != ack.durable_through_offset
        || scan.last_good_offset != ack.durable_through_offset
        || scan.records != ack.durable_record_count
        || scan.last_record_sha256 != ack.last_record_sha256
        || scan.streams.as_slice() != ack.streams.as_slice()
        || watermark.connection_epoch != genesis.connection_epoch
        || watermark.stream != genesis.stream
    {
        return Err("terminal ACK does not match the exact raw segment".to_owned());
    }
    let seal = seal_raw_segment(genesis, raw_file, ack)?;
    validate_seal_shape(&seal)?;
    Ok(VerifiedRawSegmentV1 {
        raw_path: raw_path.to_path_buf(),
        genesis: genesis.clone(),
        ack: ack.clone(),
        seal,
    })
}

pub struct RawSegmentManifestWriter<S: DurableSink = File> {
    sink: S,
    record_count: u64,
    end_offset: u64,
    previous_digest: String,
    last_seal: Option<RawSegmentSealV1>,
    raw_files: HashSet<String>,
    poisoned: bool,
}

impl RawSegmentManifestWriter<File> {
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "create segment manifest parent {}: {error}",
                    parent.display()
                )
            })?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create segment manifest {}: {error}", path.display()))?;
        Self::from_sink(file)
    }
}

impl<S: DurableSink> RawSegmentManifestWriter<S> {
    pub fn from_sink(mut sink: S) -> Result<Self> {
        sink.write_all(MANIFEST_MAGIC)
            .map_err(|error| format!("write segment manifest magic: {error}"))?;
        sink.sync_all()
            .map_err(|error| format!("sync segment manifest magic: {error}"))?;
        Ok(Self {
            sink,
            record_count: 0,
            end_offset: MANIFEST_MAGIC.len() as u64,
            previous_digest: ZERO_DIGEST.to_owned(),
            last_seal: None,
            raw_files: HashSet::new(),
            poisoned: false,
        })
    }

    pub fn append_verified(
        &mut self,
        verified: &VerifiedRawSegmentV1,
    ) -> Result<RawSegmentManifestAckV1> {
        if self.poisoned {
            return Err("raw segment manifest writer is poisoned".to_owned());
        }
        // Close the scan/commit TOCTOU window under normal ownership: verify
        // the immutable file again immediately before serializing authority.
        let current = verify_and_seal_raw_segment(
            &verified.raw_path,
            &verified.seal.raw_file,
            &verified.genesis,
            &verified.ack,
        )?;
        if current.seal != verified.seal {
            return Err("raw segment changed after verification".to_owned());
        }
        validate_manifest_transition(
            self.record_count,
            self.last_seal.as_ref(),
            &self.raw_files,
            &current.seal,
        )?;
        let body = ManifestBodyV1 {
            schema: "RawSegmentManifestRecordV1".to_owned(),
            record_index: self.record_count,
            previous_manifest_record_sha256: self.previous_digest.clone(),
            seal: current.seal.clone(),
        };
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|error| format!("serialize segment manifest record: {error}"))?;
        if body_bytes.len() > MAX_MANIFEST_RECORD_BYTES {
            return Err("segment manifest record exceeds maximum size".to_owned());
        }
        let length = u32::try_from(body_bytes.len())
            .map_err(|_| "segment manifest record length does not fit u32".to_owned())?;
        let digest = Sha256::digest(&body_bytes);
        let mut encoded = Vec::with_capacity(4 + body_bytes.len() + digest.len());
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&body_bytes);
        encoded.extend_from_slice(&digest);
        let next_record_count = self
            .record_count
            .checked_add(1)
            .ok_or_else(|| "segment manifest record index overflow".to_owned())?;
        let next_end_offset = self
            .end_offset
            .checked_add(encoded.len() as u64)
            .ok_or_else(|| "segment manifest offset overflow".to_owned())?;
        if let Err(error) = self
            .sink
            .write_all(&encoded)
            .and_then(|_| self.sink.flush())
            .and_then(|_| self.sink.sync_all())
        {
            self.poisoned = true;
            return Err(format!(
                "sync raw segment manifest; writer poisoned: {error}"
            ));
        }
        let record_index = self.record_count;
        self.record_count = next_record_count;
        self.end_offset = next_end_offset;
        self.previous_digest = hex(&digest);
        self.raw_files.insert(current.seal.raw_file.clone());
        self.last_seal = Some(current.seal.clone());
        Ok(RawSegmentManifestAckV1 {
            schema: "RawSegmentManifestAckV1",
            record_index,
            segment_index: current.seal.segment_index,
            durable_through_offset: self.end_offset,
            record_sha256: self.previous_digest.clone(),
        })
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

pub fn scan_segment_manifest(path: &Path) -> Result<RawSegmentManifestScanV1> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_size = file
        .metadata()
        .map_err(|error| format!("metadata {}: {error}", path.display()))?
        .len();
    let mut magic = [0_u8; 8];
    if file.read_exact(&mut magic).is_err() || &magic != MANIFEST_MAGIC {
        return Ok(RawSegmentManifestScanV1 {
            schema: "RawSegmentManifestScanV1",
            path: path.to_path_buf(),
            file_size,
            records: 0,
            last_good_offset: 0,
            clean_eof: false,
            reason: Some("bad segment manifest magic".to_owned()),
            last_record_sha256: ZERO_DIGEST.to_owned(),
            entries: Vec::new(),
        });
    }
    let mut entries = Vec::new();
    let mut previous_digest = ZERO_DIGEST.to_owned();
    let mut last_good_offset = MANIFEST_MAGIC.len() as u64;
    let mut last_seal: Option<RawSegmentSealV1> = None;
    let mut raw_files = HashSet::new();
    let mut reason = None;
    loop {
        let mut prefix = [0_u8; 4];
        let first = file
            .read(&mut prefix[..1])
            .map_err(|error| format!("read segment manifest prefix: {error}"))?;
        if first == 0 {
            break;
        }
        if file.read_exact(&mut prefix[1..]).is_err() {
            reason = Some("partial segment manifest length prefix".to_owned());
            break;
        }
        let body_length = u32::from_be_bytes(prefix) as usize;
        if body_length == 0 || body_length > MAX_MANIFEST_RECORD_BYTES {
            reason = Some("segment manifest record length exceeds limit".to_owned());
            break;
        }
        let mut body_bytes = vec![0_u8; body_length];
        if file.read_exact(&mut body_bytes).is_err() {
            reason = Some("partial segment manifest body".to_owned());
            break;
        }
        let mut stored_digest = [0_u8; 32];
        if file.read_exact(&mut stored_digest).is_err() {
            reason = Some("partial segment manifest digest".to_owned());
            break;
        }
        let actual_digest: [u8; 32] = Sha256::digest(&body_bytes).into();
        if actual_digest != stored_digest {
            reason = Some("segment manifest record digest mismatch".to_owned());
            break;
        }
        let body: ManifestBodyV1 = match serde_json::from_slice(&body_bytes) {
            Ok(value) => value,
            Err(error) => {
                reason = Some(format!("invalid segment manifest JSON: {error}"));
                break;
            }
        };
        if body.schema != "RawSegmentManifestRecordV1"
            || body.record_index != entries.len() as u64
            || body.previous_manifest_record_sha256 != previous_digest
            || validate_manifest_transition(
                body.record_index,
                last_seal.as_ref(),
                &raw_files,
                &body.seal,
            )
            .is_err()
        {
            reason = Some("invalid segment manifest chain/record".to_owned());
            break;
        }
        let digest = hex(&stored_digest);
        last_good_offset = last_good_offset
            .checked_add((4 + body_length + 32) as u64)
            .ok_or_else(|| "segment manifest scan offset overflow".to_owned())?;
        raw_files.insert(body.seal.raw_file.clone());
        last_seal = Some(body.seal.clone());
        entries.push(RawSegmentManifestEntryV1 {
            schema: "RawSegmentManifestEntryV1",
            record_index: body.record_index,
            previous_manifest_record_sha256: body.previous_manifest_record_sha256,
            manifest_record_sha256: digest.clone(),
            seal: body.seal,
        });
        previous_digest = digest;
    }
    Ok(RawSegmentManifestScanV1 {
        schema: "RawSegmentManifestScanV1",
        path: path.to_path_buf(),
        file_size,
        records: entries.len() as u64,
        last_good_offset,
        clean_eof: reason.is_none(),
        reason,
        last_record_sha256: previous_digest,
        entries,
    })
}

/// Reopens and validates every manifest-selected BNRAW file.  No globbing or
/// filename ordering participates in authority.
pub fn verify_segment_manifest_files(
    scan: &RawSegmentManifestScanV1,
    base_directory: &Path,
) -> Result<Vec<VerifiedRawSegmentV1>> {
    if !scan.clean_eof {
        return Err("cannot verify files from an unclean segment manifest".to_owned());
    }
    let current_scan = scan_segment_manifest(&scan.path)?;
    if &current_scan != scan {
        return Err("segment manifest changed after it was scanned".to_owned());
    }
    let mut verified = Vec::with_capacity(scan.entries.len());
    for entry in &scan.entries {
        let seal = &entry.seal;
        let genesis = RawSegmentGenesisV1 {
            schema: "RawSegmentGenesisV1".to_owned(),
            segment_index: seal.segment_index,
            previous_segment_terminal_sha256: seal.previous_segment_terminal_sha256.clone(),
            connection_epoch: seal.connection_epoch.clone(),
            stream: seal.stream.clone(),
            next_frame_index: seal.first_frame_index,
        };
        let ack = ack_from_seal(seal);
        let artifact = verify_and_seal_raw_segment(
            &base_directory.join(&seal.raw_file),
            &seal.raw_file,
            &genesis,
            &ack,
        )?;
        if artifact.seal != *seal {
            return Err("manifest seal differs from verified raw segment".to_owned());
        }
        verified.push(artifact);
    }
    Ok(verified)
}

/// Reopens and validates only the exact manifest prefix selected by a terminal
/// segment index. The complete manifest itself must have a clean, stable EOF;
/// later entries remain excluded evidence and are never inferred by filename.
pub fn verify_segment_manifest_prefix_files(
    scan: &RawSegmentManifestScanV1,
    base_directory: &Path,
    through_segment_index: u64,
) -> Result<Vec<VerifiedRawSegmentV1>> {
    if !scan.clean_eof {
        return Err("cannot verify files from an unclean segment manifest".to_owned());
    }
    let current_scan = scan_segment_manifest(&scan.path)?;
    if &current_scan != scan {
        return Err("segment manifest changed after it was scanned".to_owned());
    }
    let count = through_segment_index
        .checked_add(1)
        .ok_or_else(|| "segment prefix index overflow".to_owned())?;
    let count = usize::try_from(count).map_err(|_| "segment prefix count overflow".to_owned())?;
    if count > scan.entries.len() {
        return Err(format!(
            "segment manifest has {} entries, cannot select through {through_segment_index}",
            scan.entries.len()
        ));
    }
    let mut verified = Vec::with_capacity(count);
    for entry in &scan.entries[..count] {
        let seal = &entry.seal;
        let genesis = RawSegmentGenesisV1 {
            schema: "RawSegmentGenesisV1".to_owned(),
            segment_index: seal.segment_index,
            previous_segment_terminal_sha256: seal.previous_segment_terminal_sha256.clone(),
            connection_epoch: seal.connection_epoch.clone(),
            stream: seal.stream.clone(),
            next_frame_index: seal.first_frame_index,
        };
        let ack = ack_from_seal(seal);
        let artifact = verify_and_seal_raw_segment(
            &base_directory.join(&seal.raw_file),
            &seal.raw_file,
            &genesis,
            &ack,
        )?;
        if artifact.seal != *seal {
            return Err("manifest seal differs from verified raw segment".to_owned());
        }
        verified.push(artifact);
    }
    Ok(verified)
}

pub fn recover_segment_manifest_prefix(
    source: &Path,
    destination: &Path,
) -> Result<RawSegmentManifestRecoveryV1> {
    let source_scan = scan_segment_manifest(source)?;
    if source_scan.clean_eof {
        return Err("source segment manifest already has a clean EOF".to_owned());
    }
    if source_scan.last_good_offset < MANIFEST_MAGIC.len() as u64 {
        return Err("source has no recoverable segment manifest prefix".to_owned());
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create recovered manifest parent {}: {error}",
                parent.display()
            )
        })?;
    }
    let mut input = File::open(source)
        .map_err(|error| format!("open recovery source {}: {error}", source.display()))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "create recovered segment manifest {}: {error}",
                destination.display()
            )
        })?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut input).take(source_scan.last_good_offset),
        &mut output,
    )
    .map_err(|error| format!("copy recoverable segment manifest prefix: {error}"))?;
    if copied != source_scan.last_good_offset {
        return Err("short copy while recovering segment manifest".to_owned());
    }
    output
        .flush()
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("sync recovered segment manifest: {error}"))?;
    let recovered = scan_segment_manifest(destination)?;
    if !recovered.clean_eof
        || recovered.entries != source_scan.entries
        || recovered.last_record_sha256 != source_scan.last_record_sha256
    {
        return Err("recovered segment manifest prefix failed verification".to_owned());
    }
    Ok(RawSegmentManifestRecoveryV1 {
        schema: "RawSegmentManifestRecoveryV1",
        source: source.to_path_buf(),
        destination: destination.to_path_buf(),
        source_file_size: source_scan.file_size,
        copied_valid_prefix_bytes: copied,
        excluded_tail_bytes: source_scan.file_size - copied,
        recovered_records: recovered.records,
        last_record_sha256: recovered.last_record_sha256,
    })
}

fn validate_manifest_transition(
    record_index: u64,
    previous: Option<&RawSegmentSealV1>,
    raw_files: &HashSet<String>,
    seal: &RawSegmentSealV1,
) -> Result<()> {
    validate_seal_shape(seal)?;
    if seal.segment_index != record_index || raw_files.contains(&seal.raw_file) {
        return Err("segment index/file is duplicate or out of order".to_owned());
    }
    match previous {
        None => {
            if seal.segment_index != 0
                || seal.first_frame_index != 0
                || seal.previous_segment_terminal_sha256 != ZERO_DIGEST
            {
                return Err("segment manifest must begin at the exact root".to_owned());
            }
        }
        Some(old) => {
            let expected_segment = old
                .segment_index
                .checked_add(1)
                .ok_or_else(|| "segment index overflow".to_owned())?;
            let expected_frame = old
                .last_frame_index
                .checked_add(1)
                .ok_or_else(|| "segment frame index overflow".to_owned())?;
            if seal.segment_index != expected_segment
                || seal.connection_epoch != old.connection_epoch
                || seal.stream != old.stream
                || seal.first_frame_index != expected_frame
                || seal.previous_segment_terminal_sha256 != old.terminal_record_sha256
            {
                return Err("segment manifest transition is not exactly contiguous".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_seal_shape(seal: &RawSegmentSealV1) -> Result<()> {
    if seal.schema != "RawSegmentSealV1"
        || seal.connection_epoch.trim().is_empty()
        || seal.stream.trim().is_empty()
        || seal.records == 0
        || seal.durable_through_offset <= MANIFEST_MAGIC.len() as u64
        || seal.last_frame_index < seal.first_frame_index
    {
        return Err("invalid raw segment seal".to_owned());
    }
    validate_relative_file(&seal.raw_file)?;
    validate_digest(
        &seal.previous_segment_terminal_sha256,
        "previous_segment_terminal_sha256",
    )?;
    validate_digest(&seal.terminal_record_sha256, "terminal_record_sha256")?;
    let expected_records = seal
        .last_frame_index
        .checked_sub(seal.first_frame_index)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| "raw segment seal frame range overflow".to_owned())?;
    if seal.records != expected_records {
        return Err("raw segment seal count does not match frame range".to_owned());
    }
    let root = seal.segment_index == 0
        && seal.first_frame_index == 0
        && seal.previous_segment_terminal_sha256 == ZERO_DIGEST;
    let successor = seal.segment_index > 0
        && seal.first_frame_index > 0
        && seal.previous_segment_terminal_sha256 != ZERO_DIGEST;
    if !root && !successor {
        return Err("raw segment seal is neither root nor successor".to_owned());
    }
    Ok(())
}

fn validate_relative_file(raw_file: &str) -> Result<()> {
    let mut components = Path::new(raw_file).components();
    if raw_file.trim().is_empty()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err("raw segment file must be one relative file name".to_owned());
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn ack_from_seal(seal: &RawSegmentSealV1) -> DurabilityAckV1 {
    DurabilityAckV1 {
        schema: "DurabilityAckV1".to_owned(),
        durable_record_count: seal.records,
        durable_through_offset: seal.durable_through_offset,
        last_record_sha256: seal.terminal_record_sha256.clone(),
        streams: vec![StreamDurabilityWatermarkV1 {
            connection_epoch: seal.connection_epoch.clone(),
            stream: seal.stream.clone(),
            durable_through_frame_index: seal.last_frame_index,
        }],
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
