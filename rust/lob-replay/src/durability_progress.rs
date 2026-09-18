//! Durable, append-only publication of BNRAW group-commit watermarks.

use crate::boundary::CanonicalObservationV1;
use crate::{
    DurabilityAckV1, RawRecordEnvelopeV1, Result, StreamDurabilityWatermarkV1, hex,
    read_raw_record_range, read_raw_records, read_raw_records_through_offset,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProgressBodyV1 {
    schema: String,
    record_index: u64,
    raw_path: String,
    ack: DurabilityAckV1,
    previous_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProgressEnvelopeV1 {
    body: ProgressBodyV1,
    record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurabilityProgressScanV1 {
    pub schema: &'static str,
    pub path: PathBuf,
    pub records: u64,
    pub clean_eof: bool,
    pub reason: Option<String>,
    pub latest_ack: Option<DurabilityAckV1>,
    pub last_record_sha256: String,
    // Internal terminal-verification detail.  Keep the established serialized
    // scan report stable while allowing callers to bind an intermediate
    // durability publication to the exact BNACK record that made it durable.
    #[serde(skip_serializing)]
    pub acknowledgements: Vec<DurabilityAckV1>,
}

pub struct DurabilityProgressWriter {
    file: File,
    raw_path: String,
    record_count: u64,
    previous_digest: String,
    latest_ack: Option<DurabilityAckV1>,
    poisoned: bool,
}

impl DurabilityProgressWriter {
    /// Creates a legacy journal whose `raw_path` identity is the caller's
    /// display form. New segmented artifacts should use
    /// [`Self::create_with_reference`] so moving their containing directory
    /// does not invalidate the journal.
    pub fn create(path: &Path, raw_path: &Path) -> Result<Self> {
        create_progress_parent(path)?;
        Self::create_with_raw_identity(path, raw_path.display().to_string())
    }

    /// Creates a portable journal bound to a safe relative reference from the
    /// BNACK parent directory to the supplied BNRAW file.
    pub fn create_with_reference(
        path: &Path,
        raw_path: &Path,
        raw_reference: &str,
    ) -> Result<Self> {
        create_progress_parent(path)?;
        verify_portable_raw_reference(path, raw_path, raw_reference)?;
        Self::create_with_raw_identity(path, raw_reference.to_owned())
    }

    fn create_with_raw_identity(path: &Path, raw_identity: String) -> Result<Self> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create progress journal {}: {error}", path.display()))?;
        Ok(Self {
            file,
            raw_path: raw_identity,
            record_count: 0,
            previous_digest: ZERO_DIGEST.to_owned(),
            latest_ack: None,
            poisoned: false,
        })
    }

    pub fn append(&mut self, ack: DurabilityAckV1) -> Result<()> {
        if self.poisoned {
            return Err("durability progress writer is poisoned".to_owned());
        }
        validate_ack(&ack)?;
        if let Some(previous) = &self.latest_ack
            && (ack.durable_record_count <= previous.durable_record_count
                || ack.durable_through_offset <= previous.durable_through_offset)
        {
            return Err("durability progress must advance record count and offset".to_owned());
        }
        let body = ProgressBodyV1 {
            schema: "RawDurabilityProgressV1".to_owned(),
            record_index: self.record_count,
            raw_path: self.raw_path.clone(),
            ack: ack.clone(),
            previous_record_sha256: self.previous_digest.clone(),
        };
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|error| format!("serialize durability progress: {error}"))?;
        let digest = hex(&Sha256::digest(&body_bytes));
        let envelope = ProgressEnvelopeV1 {
            body,
            record_sha256: digest.clone(),
        };
        let mut encoded = serde_json::to_vec(&envelope)
            .map_err(|error| format!("serialize progress envelope: {error}"))?;
        encoded.push(b'\n');
        if let Err(error) = self
            .file
            .write_all(&encoded)
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_all())
        {
            self.poisoned = true;
            return Err(format!(
                "sync durability progress; writer poisoned: {error}"
            ));
        }
        self.record_count += 1;
        self.previous_digest = digest;
        self.latest_ack = Some(ack);
        Ok(())
    }

    pub fn latest_ack(&self) -> Option<&DurabilityAckV1> {
        self.latest_ack.as_ref()
    }
}

fn create_progress_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create progress parent {}: {error}", parent.display()))?;
    }
    Ok(())
}

pub(crate) fn validate_portable_raw_reference(raw_reference: &str) -> Result<()> {
    if raw_reference.is_empty()
        || raw_reference.trim() != raw_reference
        || raw_reference
            .chars()
            .any(|character| matches!(character, '\\' | ':' | '\0'))
    {
        return Err("raw reference must be a portable safe relative path".to_owned());
    }
    let path = Path::new(raw_reference);
    if path.is_absolute() {
        return Err("raw reference must be a portable safe relative path".to_owned());
    }
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => normal_components += 1,
            _ => return Err("raw reference must contain only normal path components".to_owned()),
        }
    }
    if normal_components == 0 {
        return Err("raw reference must contain a file path".to_owned());
    }
    Ok(())
}

pub(crate) fn verify_portable_raw_reference(
    progress_path: &Path,
    raw_path: &Path,
    raw_reference: &str,
) -> Result<()> {
    validate_portable_raw_reference(raw_reference)?;
    let progress_parent = progress_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let referenced_path = progress_parent.join(raw_reference);
    let referenced = std::fs::canonicalize(&referenced_path).map_err(|error| {
        format!(
            "resolve raw reference {} from {}: {error}",
            raw_reference,
            progress_parent.display()
        )
    })?;
    let supplied = std::fs::canonicalize(raw_path)
        .map_err(|error| format!("resolve raw path {}: {error}", raw_path.display()))?;
    if referenced != supplied {
        return Err("raw reference does not identify supplied raw path".to_owned());
    }
    Ok(())
}

pub fn scan_durability_progress(path: &Path) -> Result<DurabilityProgressScanV1> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let mut records = 0_u64;
    let mut previous = ZERO_DIGEST.to_owned();
    let mut latest_ack: Option<DurabilityAckV1> = None;
    let mut acknowledgements = Vec::new();
    let mut reason = None;
    let mut start = 0_usize;
    while start < bytes.len() {
        let Some(relative_end) = bytes[start..].iter().position(|byte| *byte == b'\n') else {
            reason = Some("partial durability progress tail".to_owned());
            break;
        };
        let end = start + relative_end;
        let envelope: ProgressEnvelopeV1 = match serde_json::from_slice(&bytes[start..end]) {
            Ok(value) => value,
            Err(error) => {
                reason = Some(format!("invalid durability progress JSON: {error}"));
                break;
            }
        };
        let body_bytes = serde_json::to_vec(&envelope.body)
            .map_err(|error| format!("reserialize durability progress: {error}"))?;
        let digest = hex(&Sha256::digest(body_bytes));
        if envelope.body.schema != "RawDurabilityProgressV1"
            || envelope.body.record_index != records
            || envelope.body.previous_record_sha256 != previous
            || envelope.record_sha256 != digest
            || validate_ack(&envelope.body.ack).is_err()
        {
            reason = Some("invalid durability progress chain/record".to_owned());
            break;
        }
        if let Some(old) = &latest_ack
            && (envelope.body.ack.durable_record_count <= old.durable_record_count
                || envelope.body.ack.durable_through_offset <= old.durable_through_offset)
        {
            reason = Some("non-monotonic durability progress".to_owned());
            break;
        }
        records += 1;
        previous = digest;
        acknowledgements.push(envelope.body.ack.clone());
        latest_ack = Some(envelope.body.ack);
        start = end + 1;
    }
    Ok(DurabilityProgressScanV1 {
        schema: "DurabilityProgressScanV1",
        path: path.to_path_buf(),
        records,
        clean_eof: reason.is_none(),
        reason,
        latest_ack,
        last_record_sha256: previous,
        acknowledgements,
    })
}

pub fn verify_progress_against_raw(
    scan: &DurabilityProgressScanV1,
    raw_path: &Path,
) -> Result<DurabilityAckV1> {
    let ack = scan
        .latest_ack
        .clone()
        .ok_or_else(|| "durability progress has no complete ACK".to_owned())?;
    let records = read_raw_records(raw_path)?;
    let count = usize::try_from(ack.durable_record_count)
        .map_err(|_| "durable record count does not fit memory index".to_owned())?;
    if count == 0 || records.len() < count {
        return Err("raw file does not contain the durable progress prefix".to_owned());
    }
    let last = &records[count - 1];
    if last.end_offset != ack.durable_through_offset
        || last.record_sha256 != ack.last_record_sha256
        || ack.streams.len() != 1
        || ack.streams[0].connection_epoch != last.frame.connection_epoch
        || ack.streams[0].stream != last.frame.stream
        || ack.streams[0].durable_through_frame_index != last.frame.frame_index
    {
        return Err("durability progress does not match the exact raw prefix".to_owned());
    }
    Ok(ack)
}

pub fn freeze_durable_raw_prefix(
    scan: &DurabilityProgressScanV1,
    raw_path: &Path,
    destination: &Path,
) -> Result<DurabilityAckV1> {
    let ack = scan
        .latest_ack
        .clone()
        .ok_or_else(|| "durability progress has no complete ACK".to_owned())?;
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!("create frozen prefix parent {}: {error}", parent.display())
        })?;
    }
    let source = File::open(raw_path)
        .map_err(|error| format!("open live raw {}: {error}", raw_path.display()))?;
    let source_size = source
        .metadata()
        .map_err(|error| format!("stat live raw {}: {error}", raw_path.display()))?
        .len();
    if source_size < ack.durable_through_offset {
        return Err("live raw is shorter than its durable watermark".to_owned());
    }
    let mut destination_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| format!("create frozen prefix {}: {error}", destination.display()))?;
    let copied = std::io::copy(
        &mut source.take(ack.durable_through_offset),
        &mut destination_file,
    )
    .map_err(|error| format!("copy durable raw prefix: {error}"))?;
    if copied != ack.durable_through_offset {
        return Err("short copy while freezing durable raw prefix".to_owned());
    }
    destination_file
        .flush()
        .and_then(|_| destination_file.sync_all())
        .map_err(|error| format!("sync frozen durable prefix: {error}"))?;
    let frozen = read_raw_records(destination)?;
    let count = usize::try_from(ack.durable_record_count)
        .map_err(|_| "durable record count does not fit memory index".to_owned())?;
    let last = frozen
        .last()
        .ok_or_else(|| "frozen durable prefix has no records".to_owned())?;
    if frozen.len() != count
        || last.end_offset != ack.durable_through_offset
        || last.record_sha256 != ack.last_record_sha256
        || ack.streams.len() != 1
        || ack.streams[0].connection_epoch != last.frame.connection_epoch
        || ack.streams[0].stream != last.frame.stream
        || ack.streams[0].durable_through_frame_index != last.frame.frame_index
    {
        return Err("frozen raw prefix does not match durability progress".to_owned());
    }
    Ok(ack)
}

pub fn read_durable_raw_delta(
    raw_path: &Path,
    previous: &DurabilityAckV1,
    next: &DurabilityAckV1,
) -> Result<Vec<RawRecordEnvelopeV1>> {
    validate_ack(previous)?;
    validate_ack(next)?;
    let old = &previous.streams[0];
    let new = &next.streams[0];
    if old.connection_epoch != new.connection_epoch
        || old.stream != new.stream
        || next.durable_record_count <= previous.durable_record_count
        || next.durable_through_offset <= previous.durable_through_offset
        || new.durable_through_frame_index <= old.durable_through_frame_index
    {
        return Err("durability delta does not strictly continue one raw stream".to_owned());
    }
    let records = read_raw_record_range(
        raw_path,
        previous.durable_through_offset,
        next.durable_through_offset,
        &previous.last_record_sha256,
        &old.connection_epoch,
        &old.stream,
        old.durable_through_frame_index
            .checked_add(1)
            .ok_or_else(|| "durability frame index overflow".to_owned())?,
    )?;
    let expected_count = next.durable_record_count - previous.durable_record_count;
    let last = records
        .last()
        .ok_or_else(|| "durability delta produced no records".to_owned())?;
    if records.len() as u64 != expected_count
        || last.record_sha256 != next.last_record_sha256
        || last.frame.frame_index != new.durable_through_frame_index
        || last.frame.connection_epoch != new.connection_epoch
        || last.frame.stream != new.stream
    {
        return Err("durability delta does not match its terminal ACK".to_owned());
    }
    Ok(records)
}

/// Reconstruct an exact durable BNRAW cursor from the lineage embedded in the
/// last canonical observation.  The terminal ACK remains the authority for
/// what is durable; this cursor merely identifies the already-published point
/// inside that prefix so `read_durable_raw_delta` can continue at the next
/// record without duplicates or gaps.
pub fn durable_cursor_at_observation(
    raw_path: &Path,
    terminal: &DurabilityAckV1,
    observation: &CanonicalObservationV1,
) -> Result<DurabilityAckV1> {
    validate_ack(terminal)?;
    let terminal_stream = &terminal.streams[0];
    if observation.connection_epoch != terminal_stream.connection_epoch
        || observation.stream != terminal_stream.stream
        || observation.frame_index > terminal_stream.durable_through_frame_index
    {
        return Err("canonical observation is outside the durable raw stream".to_owned());
    }
    let records = read_raw_records_through_offset(raw_path, terminal.durable_through_offset)?;
    if records.len() as u64 != terminal.durable_record_count {
        return Err("terminal ACK count differs from durable raw prefix".to_owned());
    }
    let terminal_record = records
        .last()
        .ok_or_else(|| "durable raw prefix is empty".to_owned())?;
    if terminal_record.record_sha256 != terminal.last_record_sha256
        || terminal_record.end_offset != terminal.durable_through_offset
    {
        return Err("terminal ACK differs from durable raw prefix".to_owned());
    }
    let mut matches = records.iter().filter(|record| {
        record.frame.connection_epoch == observation.connection_epoch
            && record.frame.stream == observation.stream
            && record.frame.frame_index == observation.frame_index
            && record.record_sha256 == observation.record_sha256
    });
    let record = matches
        .next()
        .ok_or_else(|| "canonical observation lineage is absent from durable raw".to_owned())?;
    if matches.next().is_some() {
        return Err("canonical observation lineage is not unique in durable raw".to_owned());
    }
    Ok(DurabilityAckV1 {
        schema: "DurabilityAckV1".to_owned(),
        durable_record_count: record.record_index + 1,
        durable_through_offset: record.end_offset,
        last_record_sha256: record.record_sha256.clone(),
        streams: vec![StreamDurabilityWatermarkV1 {
            connection_epoch: record.frame.connection_epoch.clone(),
            stream: record.frame.stream.clone(),
            durable_through_frame_index: record.frame.frame_index,
        }],
    })
}

fn validate_ack(ack: &DurabilityAckV1) -> Result<()> {
    if ack.schema != "DurabilityAckV1"
        || ack.durable_record_count == 0
        || ack.durable_through_offset == 0
        || ack.last_record_sha256.len() != 64
        || !ack
            .last_record_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || ack.streams.len() != 1
    {
        return Err("invalid durability ACK".to_owned());
    }
    Ok(())
}
