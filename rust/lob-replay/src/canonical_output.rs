//! Durable canonical downstream output with explicit ownership transitions.

use crate::boundary::{BoundaryStreamKind, CanonicalObservationV1};
use crate::{DurableSink, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"BNPUB\0\x01\n";
const MAX_RECORD_BYTES: usize = 256 * 1024;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanonicalOutputAction {
    Initialized,
    Observation,
    OwnershipChanged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalOutputOwnerV1 {
    pub generation_id: String,
    pub connection_epoch: String,
    pub fencing_token: u64,
    pub last_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CanonicalOutputRecordV1 {
    schema: String,
    record_index: u64,
    action: CanonicalOutputAction,
    symbol: String,
    stream_kind: BoundaryStreamKind,
    owner: CanonicalOutputOwnerV1,
    observation: Option<CanonicalObservationV1>,
    ownership_activation_record_sha256: Option<String>,
    previous_record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalOutputAckV1 {
    pub schema: &'static str,
    pub action: CanonicalOutputAction,
    pub durable_record_count: u64,
    pub durable_through_offset: u64,
    pub last_record_sha256: String,
    pub owner: CanonicalOutputOwnerV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalOutputScanV1 {
    pub schema: &'static str,
    pub path: PathBuf,
    pub records: u64,
    pub observations: u64,
    pub ownership_changes: u64,
    pub last_good_offset: u64,
    pub clean_eof: bool,
    pub reason: Option<String>,
    pub symbol: Option<String>,
    pub stream_kind: Option<BoundaryStreamKind>,
    pub owner: Option<CanonicalOutputOwnerV1>,
    /// Last durably published market observation.  This is the exact BNRAW
    /// lineage cursor used to resume publication without guessing from a
    /// sequence number alone.  Ownership records never erase it.
    pub last_observation: Option<CanonicalObservationV1>,
    pub last_record_sha256: String,
}

pub struct CanonicalOutputWriter<S: DurableSink = File> {
    sink: S,
    symbol: String,
    stream_kind: BoundaryStreamKind,
    owner: CanonicalOutputOwnerV1,
    record_count: u64,
    end_offset: u64,
    previous_digest: String,
    poisoned: bool,
}

impl CanonicalOutputWriter<File> {
    pub fn create(
        path: &Path,
        symbol: &str,
        stream_kind: BoundaryStreamKind,
        owner: CanonicalOutputOwnerV1,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create output parent {}: {error}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create canonical output {}: {error}", path.display()))?;
        Self::from_sink(file, symbol, stream_kind, owner)
    }

    pub fn resume(path: &Path) -> Result<Self> {
        let scan = scan_canonical_output(path)?;
        if !scan.clean_eof || scan.records == 0 {
            return Err("canonical output cannot resume from an unclean journal".to_owned());
        }
        let symbol = scan
            .symbol
            .ok_or_else(|| "canonical output scan lacks symbol".to_owned())?;
        let stream_kind = scan
            .stream_kind
            .ok_or_else(|| "canonical output scan lacks stream kind".to_owned())?;
        let owner = scan
            .owner
            .ok_or_else(|| "canonical output scan lacks owner".to_owned())?;
        let sink = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|error| {
                format!(
                    "open canonical output for resume {}: {error}",
                    path.display()
                )
            })?;
        let opened_size = sink
            .metadata()
            .map_err(|error| format!("stat canonical output for resume: {error}"))?
            .len();
        if opened_size != scan.last_good_offset {
            return Err("canonical output changed during resume".to_owned());
        }
        Ok(Self {
            sink,
            symbol,
            stream_kind,
            owner,
            record_count: scan.records,
            end_offset: scan.last_good_offset,
            previous_digest: scan.last_record_sha256,
            poisoned: false,
        })
    }
}

impl<S: DurableSink> CanonicalOutputWriter<S> {
    pub fn from_sink(
        mut sink: S,
        symbol: &str,
        stream_kind: BoundaryStreamKind,
        owner: CanonicalOutputOwnerV1,
    ) -> Result<Self> {
        validate_identity(symbol, &owner)?;
        sink.write_all(MAGIC)
            .and_then(|_| sink.flush())
            .and_then(|_| sink.sync_all())
            .map_err(|error| format!("sync canonical output magic: {error}"))?;
        let mut writer = Self {
            sink,
            symbol: symbol.to_owned(),
            stream_kind,
            owner: owner.clone(),
            record_count: 0,
            end_offset: MAGIC.len() as u64,
            previous_digest: ZERO_DIGEST.to_owned(),
            poisoned: false,
        };
        writer.append_record(CanonicalOutputAction::Initialized, owner, None, None)?;
        Ok(writer)
    }

    pub fn publish(&mut self, observation: CanonicalObservationV1) -> Result<CanonicalOutputAckV1> {
        if observation.symbol != self.symbol
            || observation.stream_kind != self.stream_kind
            || observation.connection_epoch != self.owner.connection_epoch
        {
            return Err("canonical observation rejected by output ownership fence".to_owned());
        }
        let expected = self
            .owner
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| "canonical output sequence overflow".to_owned())?;
        let continuous = match self.stream_kind {
            BoundaryStreamKind::Depth => {
                observation.first_sequence <= expected && observation.final_sequence >= expected
            }
            BoundaryStreamKind::Trade => {
                observation.first_sequence == expected && observation.final_sequence == expected
            }
        };
        if !continuous {
            return Err(format!(
                "canonical output gap: expected {expected}, got {}..{}",
                observation.first_sequence, observation.final_sequence
            ));
        }
        let mut next = self.owner.clone();
        next.last_sequence = observation.final_sequence;
        let ack = self.append_record(
            CanonicalOutputAction::Observation,
            next.clone(),
            Some(observation),
            None,
        )?;
        self.owner = next;
        Ok(ack)
    }

    pub fn change_owner(
        &mut self,
        generation_id: &str,
        connection_epoch: &str,
        fencing_token: u64,
        boundary_sequence: u64,
        activation_record_sha256: &str,
    ) -> Result<CanonicalOutputAckV1> {
        if generation_id.trim().is_empty()
            || connection_epoch.trim().is_empty()
            || generation_id == self.owner.generation_id
            || connection_epoch == self.owner.connection_epoch
            || fencing_token != self.owner.fencing_token.checked_add(1).unwrap_or(0)
            || boundary_sequence != self.owner.last_sequence
            || !valid_digest(activation_record_sha256)
        {
            return Err("invalid canonical output ownership transition".to_owned());
        }
        let next = CanonicalOutputOwnerV1 {
            generation_id: generation_id.to_owned(),
            connection_epoch: connection_epoch.to_owned(),
            fencing_token,
            last_sequence: boundary_sequence,
        };
        let ack = self.append_record(
            CanonicalOutputAction::OwnershipChanged,
            next.clone(),
            None,
            Some(activation_record_sha256.to_owned()),
        )?;
        self.owner = next;
        Ok(ack)
    }

    pub fn owner(&self) -> &CanonicalOutputOwnerV1 {
        &self.owner
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn append_record(
        &mut self,
        action: CanonicalOutputAction,
        owner: CanonicalOutputOwnerV1,
        observation: Option<CanonicalObservationV1>,
        activation_sha256: Option<String>,
    ) -> Result<CanonicalOutputAckV1> {
        if self.poisoned {
            return Err("canonical output writer is poisoned".to_owned());
        }
        let record = CanonicalOutputRecordV1 {
            schema: "CanonicalOutputRecordV1".to_owned(),
            record_index: self.record_count,
            action,
            symbol: self.symbol.clone(),
            stream_kind: self.stream_kind,
            owner: owner.clone(),
            observation,
            ownership_activation_record_sha256: activation_sha256,
            previous_record_sha256: self.previous_digest.clone(),
        };
        let body = serde_json::to_vec(&record)
            .map_err(|error| format!("serialize canonical output: {error}"))?;
        if body.len() > MAX_RECORD_BYTES {
            return Err("canonical output record exceeds maximum size".to_owned());
        }
        let digest = Sha256::digest(&body);
        let mut encoded = Vec::with_capacity(4 + body.len() + 32);
        encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&body);
        encoded.extend_from_slice(&digest);
        if let Err(error) = self
            .sink
            .write_all(&encoded)
            .and_then(|_| self.sink.flush())
            .and_then(|_| self.sink.sync_all())
        {
            self.poisoned = true;
            return Err(format!("sync canonical output; writer poisoned: {error}"));
        }
        self.record_count += 1;
        self.end_offset += encoded.len() as u64;
        self.previous_digest = hex(&digest);
        Ok(CanonicalOutputAckV1 {
            schema: "CanonicalOutputAckV1",
            action,
            durable_record_count: self.record_count,
            durable_through_offset: self.end_offset,
            last_record_sha256: self.previous_digest.clone(),
            owner,
        })
    }
}

pub fn scan_canonical_output(path: &Path) -> Result<CanonicalOutputScanV1> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_size = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?
        .len();
    let mut reader = BufReader::new(file);
    let mut magic = [0_u8; 8];
    if reader.read_exact(&mut magic).is_err() || &magic != MAGIC {
        return Err("bad canonical output magic".to_owned());
    }
    let mut records = 0_u64;
    let mut observations = 0_u64;
    let mut ownership_changes = 0_u64;
    let mut offset = MAGIC.len() as u64;
    let mut previous = ZERO_DIGEST.to_owned();
    let mut symbol: Option<String> = None;
    let mut kind = None;
    let mut owner: Option<CanonicalOutputOwnerV1> = None;
    let mut last_observation: Option<CanonicalObservationV1> = None;
    let mut reason = None;
    loop {
        let mut prefix = [0_u8; 4];
        match reader.read(&mut prefix[..1]) {
            Ok(0) => break,
            Ok(1) => {}
            Ok(_) => unreachable!("one-byte read cannot return more than one byte"),
            Err(error) => {
                reason = Some(format!("read canonical output length: {error}"));
                break;
            }
        }
        if reader.read_exact(&mut prefix[1..]).is_err() {
            reason = Some("partial canonical output length".to_owned());
            break;
        }
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > MAX_RECORD_BYTES {
            reason = Some("invalid canonical output record length".to_owned());
            break;
        }
        let mut body = vec![0_u8; length];
        let mut digest = [0_u8; 32];
        if reader.read_exact(&mut body).is_err() || reader.read_exact(&mut digest).is_err() {
            reason = Some("partial canonical output record".to_owned());
            break;
        }
        if Sha256::digest(&body).as_slice() != digest {
            reason = Some("canonical output digest mismatch".to_owned());
            break;
        }
        let record: CanonicalOutputRecordV1 = match serde_json::from_slice(&body) {
            Ok(record) => record,
            Err(error) => {
                reason = Some(format!("invalid canonical output JSON: {error}"));
                break;
            }
        };
        if validate_scanned_record(
            &record,
            records,
            symbol.as_deref(),
            kind,
            owner.as_ref(),
            &previous,
        )
        .is_err()
        {
            reason = Some("invalid canonical output transition/continuity".to_owned());
            break;
        }
        if record.action == CanonicalOutputAction::Observation {
            observations += 1;
            last_observation = record.observation.clone();
        } else if record.action == CanonicalOutputAction::OwnershipChanged {
            ownership_changes += 1;
        }
        symbol.get_or_insert(record.symbol.clone());
        kind.get_or_insert(record.stream_kind);
        owner = Some(record.owner);
        previous = hex(&digest);
        records += 1;
        offset += 4 + length as u64 + 32;
    }
    Ok(CanonicalOutputScanV1 {
        schema: "CanonicalOutputScanV1",
        path: path.to_path_buf(),
        records,
        observations,
        ownership_changes,
        last_good_offset: offset,
        clean_eof: reason.is_none() && offset == file_size,
        reason,
        symbol,
        stream_kind: kind,
        owner,
        last_observation,
        last_record_sha256: previous,
    })
}

pub fn recover_canonical_output_prefix(
    source: &Path,
    destination: &Path,
) -> Result<CanonicalOutputScanV1> {
    let source_scan = scan_canonical_output(source)?;
    if source_scan.records == 0 {
        return Err("canonical output has no complete record to recover".to_owned());
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create canonical recovery parent {}: {error}",
                parent.display()
            )
        })?;
    }
    let source_file = File::open(source).map_err(|error| {
        format!(
            "open canonical recovery source {}: {error}",
            source.display()
        )
    })?;
    let source_size = source_file
        .metadata()
        .map_err(|error| format!("stat canonical recovery source: {error}"))?
        .len();
    if source_size < source_scan.last_good_offset {
        return Err("canonical recovery source shrank after scan".to_owned());
    }
    let mut destination_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| {
            format!(
                "create canonical recovered prefix {}: {error}",
                destination.display()
            )
        })?;
    let copied = std::io::copy(
        &mut source_file.take(source_scan.last_good_offset),
        &mut destination_file,
    )
    .map_err(|error| format!("copy canonical recovered prefix: {error}"))?;
    if copied != source_scan.last_good_offset {
        return Err("short copy while recovering canonical output".to_owned());
    }
    destination_file
        .flush()
        .and_then(|_| destination_file.sync_all())
        .map_err(|error| format!("sync canonical recovered prefix: {error}"))?;
    drop(destination_file);
    let recovered = scan_canonical_output(destination)?;
    if !recovered.clean_eof
        || recovered.records != source_scan.records
        || recovered.last_record_sha256 != source_scan.last_record_sha256
        || recovered.owner != source_scan.owner
    {
        return Err("recovered canonical prefix failed exact rescan".to_owned());
    }
    Ok(recovered)
}

fn validate_scanned_record(
    record: &CanonicalOutputRecordV1,
    index: u64,
    symbol: Option<&str>,
    kind: Option<BoundaryStreamKind>,
    previous_owner: Option<&CanonicalOutputOwnerV1>,
    previous_digest: &str,
) -> Result<()> {
    if record.schema != "CanonicalOutputRecordV1"
        || record.record_index != index
        || record.previous_record_sha256 != previous_digest
        || symbol.is_some_and(|value| value != record.symbol)
        || kind.is_some_and(|value| value != record.stream_kind)
    {
        return Err("canonical output record identity mismatch".to_owned());
    }
    validate_identity(&record.symbol, &record.owner)?;
    match record.action {
        CanonicalOutputAction::Initialized => {
            if index != 0
                || previous_owner.is_some()
                || record.observation.is_some()
                || record.ownership_activation_record_sha256.is_some()
            {
                return Err("illegal canonical output initialization".to_owned());
            }
        }
        CanonicalOutputAction::Observation => {
            let old =
                previous_owner.ok_or_else(|| "observation before initialization".to_owned())?;
            let observation = record
                .observation
                .as_ref()
                .ok_or_else(|| "observation record lacks observation".to_owned())?;
            let expected = old
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| "sequence overflow".to_owned())?;
            let continuous = match record.stream_kind {
                BoundaryStreamKind::Depth => {
                    observation.first_sequence <= expected && observation.final_sequence >= expected
                }
                BoundaryStreamKind::Trade => {
                    observation.first_sequence == expected && observation.final_sequence == expected
                }
            };
            if !continuous
                || observation.symbol != record.symbol
                || observation.stream_kind != record.stream_kind
                || observation.connection_epoch != old.connection_epoch
                || record.owner.generation_id != old.generation_id
                || record.owner.connection_epoch != old.connection_epoch
                || record.owner.fencing_token != old.fencing_token
                || record.owner.last_sequence != observation.final_sequence
                || record.ownership_activation_record_sha256.is_some()
            {
                return Err("invalid canonical output observation".to_owned());
            }
        }
        CanonicalOutputAction::OwnershipChanged => {
            let old = previous_owner
                .ok_or_else(|| "ownership change before initialization".to_owned())?;
            let digest = record
                .ownership_activation_record_sha256
                .as_deref()
                .ok_or_else(|| "ownership change lacks activation proof".to_owned())?;
            if !valid_digest(digest)
                || record.observation.is_some()
                || record.owner.generation_id == old.generation_id
                || record.owner.connection_epoch == old.connection_epoch
                || record.owner.fencing_token != old.fencing_token.checked_add(1).unwrap_or(0)
                || record.owner.last_sequence != old.last_sequence
            {
                return Err("invalid canonical output ownership change".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_identity(symbol: &str, owner: &CanonicalOutputOwnerV1) -> Result<()> {
    if !matches!(symbol, "BTCUSDT" | "ETHUSDT")
        || owner.generation_id.trim().is_empty()
        || owner.connection_epoch.trim().is_empty()
        || owner.fencing_token == 0
    {
        return Err("invalid canonical output identity".to_owned());
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("String write cannot fail");
    }
    output
}
