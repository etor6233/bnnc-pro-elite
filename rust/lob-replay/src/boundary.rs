//! Durable one-boundary journal for canonical A-to-B market-data handover.

use crate::{DurableSink, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"BNHND\0\x01\n";
const MAX_RECORD_BYTES: usize = 256 * 1024;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryStreamKind {
    Depth,
    Trade,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawPositionV1 {
    pub connection_epoch: String,
    pub stream: String,
    pub frame_index: u64,
    pub record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundaryDurabilityV1 {
    pub durable_through_frame_index: u64,
    pub durable_through_offset: u64,
    pub last_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandoverBoundaryV1 {
    pub schema: String,
    pub boundary_id: String,
    pub environment: String,
    pub symbol: String,
    pub stream_kind: BoundaryStreamKind,
    pub stream: String,
    pub predecessor_epoch: String,
    pub successor_epoch: String,
    pub boundary_sequence: u64,
    pub boundary_sha256: String,
    pub predecessor_last_selected: RawPositionV1,
    pub successor_boundary_observation: RawPositionV1,
    pub successor_first_selected: RawPositionV1,
    pub predecessor_durability: BoundaryDurabilityV1,
    pub successor_durability: BoundaryDurabilityV1,
    pub spec_revision: String,
    pub selector_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalObservationV1 {
    pub symbol: String,
    pub stream_kind: BoundaryStreamKind,
    pub stream: String,
    pub connection_epoch: String,
    pub frame_index: u64,
    pub first_sequence: u64,
    pub final_sequence: u64,
    pub record_sha256: String,
    pub observation_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedObservationV1 {
    pub connection_epoch: String,
    pub frame_index: u64,
    pub first_sequence: u64,
    pub final_sequence: u64,
    pub record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalSelectionV1 {
    pub schema: &'static str,
    pub boundary_id: String,
    pub symbol: String,
    pub stream_kind: BoundaryStreamKind,
    pub boundary_sequence: u64,
    pub selected: Vec<SelectedObservationV1>,
    pub excluded_overlap_records: u64,
    pub excluded_duplicate_records: u64,
    pub first_sequence: u64,
    pub final_sequence: u64,
    pub selection_sha256: String,
}

#[derive(Serialize)]
struct SelectionDigestMaterial<'a> {
    schema: &'static str,
    boundary_id: &'a str,
    symbol: &'a str,
    stream_kind: BoundaryStreamKind,
    boundary_sequence: u64,
    selected: &'a [SelectedObservationV1],
}

impl HandoverBoundaryV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "HandoverBoundaryV1"
            || self.boundary_id.trim().is_empty()
            || self.environment != "production-public-market-data"
            || !matches!(self.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
            || self.predecessor_epoch.trim().is_empty()
            || self.successor_epoch.trim().is_empty()
            || self.predecessor_epoch == self.successor_epoch
            || self.spec_revision.trim().is_empty()
            || self.selector_version.trim().is_empty()
        {
            return Err("invalid handover boundary identity/scope".to_owned());
        }
        validate_digest(&self.boundary_sha256)?;
        for digest in [
            &self.predecessor_last_selected.record_sha256,
            &self.successor_boundary_observation.record_sha256,
            &self.successor_first_selected.record_sha256,
            &self.predecessor_durability.last_record_sha256,
            &self.successor_durability.last_record_sha256,
        ] {
            validate_digest(digest)?;
        }
        if self.predecessor_last_selected.connection_epoch != self.predecessor_epoch
            || self.successor_boundary_observation.connection_epoch != self.successor_epoch
            || self.successor_first_selected.connection_epoch != self.successor_epoch
            || self.predecessor_last_selected.stream != self.stream
            || self.successor_boundary_observation.stream != self.stream
            || self.successor_first_selected.stream != self.stream
        {
            return Err("raw position does not match boundary epoch/stream".to_owned());
        }
        if self.successor_first_selected.frame_index
            <= self.successor_boundary_observation.frame_index
        {
            return Err(
                "successor first-selected position must follow overlap boundary".to_owned(),
            );
        }
        if self.predecessor_durability.durable_through_frame_index
            < self.predecessor_last_selected.frame_index
            || self.successor_durability.durable_through_frame_index
                < self.successor_first_selected.frame_index
        {
            return Err("boundary references a raw position beyond durable watermark".to_owned());
        }
        Ok(())
    }
}

pub fn select_canonical(
    boundary: &HandoverBoundaryV1,
    predecessor: &[CanonicalObservationV1],
    successor: &[CanonicalObservationV1],
) -> Result<CanonicalSelectionV1> {
    boundary.validate()?;
    validate_observations(boundary, predecessor, &boundary.predecessor_epoch)?;
    validate_observations(boundary, successor, &boundary.successor_epoch)?;
    let predecessor_boundary = find_position(predecessor, &boundary.predecessor_last_selected)?;
    let successor_boundary = find_position(successor, &boundary.successor_boundary_observation)?;
    let successor_first = find_position(successor, &boundary.successor_first_selected)?;
    validate_boundary_observations(
        boundary,
        predecessor_boundary,
        successor_boundary,
        successor_first,
    )?;

    let predecessor_selected = predecessor
        .iter()
        .filter(|observation| {
            observation.frame_index <= boundary.predecessor_last_selected.frame_index
        })
        .cloned();
    let successor_selected = successor
        .iter()
        .filter(|observation| {
            observation.frame_index >= boundary.successor_first_selected.frame_index
        })
        .cloned();
    let candidates = predecessor_selected
        .chain(successor_selected)
        .collect::<Vec<_>>();
    let excluded_overlap_records = predecessor
        .iter()
        .filter(|item| item.frame_index > boundary.predecessor_last_selected.frame_index)
        .count()
        + successor
            .iter()
            .filter(|item| item.frame_index < boundary.successor_first_selected.frame_index)
            .count();
    let (selected, excluded_duplicate_records) =
        validate_and_select_sequence(boundary.stream_kind, candidates)?;
    if selected.is_empty() {
        return Err("canonical selection is empty".to_owned());
    }
    let last_predecessor = selected
        .iter()
        .rfind(|item| item.connection_epoch == boundary.predecessor_epoch)
        .ok_or_else(|| "canonical selection has no predecessor boundary".to_owned())?;
    let first_successor = selected
        .iter()
        .find(|item| item.connection_epoch == boundary.successor_epoch)
        .ok_or_else(|| "canonical selection has no successor continuation".to_owned())?;
    if last_predecessor.final_sequence != boundary.boundary_sequence
        || first_successor.frame_index != boundary.successor_first_selected.frame_index
    {
        return Err("canonical splice does not match committed boundary".to_owned());
    }
    let selected_refs = selected
        .iter()
        .map(|item| SelectedObservationV1 {
            connection_epoch: item.connection_epoch.clone(),
            frame_index: item.frame_index,
            first_sequence: item.first_sequence,
            final_sequence: item.final_sequence,
            record_sha256: item.record_sha256.clone(),
        })
        .collect::<Vec<_>>();
    let first_sequence = selected_refs[0].first_sequence;
    let final_sequence = selected_refs
        .last()
        .expect("selection checked nonempty")
        .final_sequence;
    let material = SelectionDigestMaterial {
        schema: "CanonicalSelectionDigestV1",
        boundary_id: &boundary.boundary_id,
        symbol: &boundary.symbol,
        stream_kind: boundary.stream_kind,
        boundary_sequence: boundary.boundary_sequence,
        selected: &selected_refs,
    };
    let canonical = serde_json::to_vec(&material)
        .map_err(|error| format!("serialize canonical selection digest: {error}"))?;
    Ok(CanonicalSelectionV1 {
        schema: "CanonicalSelectionV1",
        boundary_id: boundary.boundary_id.clone(),
        symbol: boundary.symbol.clone(),
        stream_kind: boundary.stream_kind,
        boundary_sequence: boundary.boundary_sequence,
        selected: selected_refs,
        excluded_overlap_records: excluded_overlap_records as u64,
        excluded_duplicate_records,
        first_sequence,
        final_sequence,
        selection_sha256: hex(&Sha256::digest(&canonical)),
    })
}

fn validate_observations(
    boundary: &HandoverBoundaryV1,
    observations: &[CanonicalObservationV1],
    expected_epoch: &str,
) -> Result<()> {
    if observations.is_empty() {
        return Err("canonical source observations are empty".to_owned());
    }
    let mut previous_frame = None;
    for observation in observations {
        if observation.symbol != boundary.symbol
            || observation.stream_kind != boundary.stream_kind
            || observation.stream != boundary.stream
            || observation.connection_epoch != expected_epoch
            || observation.first_sequence > observation.final_sequence
        {
            return Err("observation identity/range does not match boundary".to_owned());
        }
        validate_digest(&observation.record_sha256)?;
        validate_digest(&observation.observation_sha256)?;
        if let Some(previous) = previous_frame
            && observation.frame_index != previous + 1
        {
            return Err("raw frame index gap/reorder in canonical source".to_owned());
        }
        previous_frame = Some(observation.frame_index);
    }
    Ok(())
}

fn find_position<'a>(
    observations: &'a [CanonicalObservationV1],
    position: &RawPositionV1,
) -> Result<&'a CanonicalObservationV1> {
    let observation = observations
        .iter()
        .find(|item| item.frame_index == position.frame_index)
        .ok_or_else(|| "committed raw position is absent from observations".to_owned())?;
    if observation.connection_epoch != position.connection_epoch
        || observation.stream != position.stream
        || observation.record_sha256 != position.record_sha256
    {
        return Err("committed raw position digest/identity mismatch".to_owned());
    }
    Ok(observation)
}

fn validate_boundary_observations(
    boundary: &HandoverBoundaryV1,
    predecessor: &CanonicalObservationV1,
    successor_boundary: &CanonicalObservationV1,
    successor_first: &CanonicalObservationV1,
) -> Result<()> {
    if predecessor.final_sequence != boundary.boundary_sequence
        || successor_boundary.final_sequence != boundary.boundary_sequence
        || predecessor.observation_sha256 != boundary.boundary_sha256
        || successor_boundary.observation_sha256 != boundary.boundary_sha256
    {
        return Err("A/B observations do not prove the committed convergence".to_owned());
    }
    let next = boundary
        .boundary_sequence
        .checked_add(1)
        .ok_or_else(|| "boundary sequence overflow".to_owned())?;
    match boundary.stream_kind {
        BoundaryStreamKind::Depth => {
            if successor_first.first_sequence > next || successor_first.final_sequence < next {
                return Err("successor depth frame does not bridge K+1".to_owned());
            }
        }
        BoundaryStreamKind::Trade => {
            if predecessor.first_sequence != boundary.boundary_sequence
                || successor_boundary.first_sequence != boundary.boundary_sequence
                || successor_first.first_sequence != next
                || successor_first.final_sequence != next
            {
                return Err("successor trade does not continue at T+1".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_and_select_sequence(
    kind: BoundaryStreamKind,
    candidates: Vec<CanonicalObservationV1>,
) -> Result<(Vec<CanonicalObservationV1>, u64)> {
    let mut selected: Vec<CanonicalObservationV1> = Vec::with_capacity(candidates.len());
    let mut duplicates = 0_u64;
    for observation in candidates {
        let Some(previous) = selected.last() else {
            selected.push(observation);
            continue;
        };
        let next = previous
            .final_sequence
            .checked_add(1)
            .ok_or_else(|| "canonical sequence overflow".to_owned())?;
        if observation.final_sequence < next {
            if observation.final_sequence == previous.final_sequence
                && observation.observation_sha256 == previous.observation_sha256
            {
                duplicates += 1;
                continue;
            }
            return Err("stale/conflicting canonical observation".to_owned());
        }
        if observation.first_sequence > next {
            return Err("gap in canonical observation sequence".to_owned());
        }
        if kind == BoundaryStreamKind::Trade
            && (observation.first_sequence != next || observation.final_sequence != next)
        {
            return Err("trade sequence is not exactly contiguous".to_owned());
        }
        selected.push(observation);
    }
    Ok((selected, duplicates))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryJournalAction {
    Proposed,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct BoundaryJournalRecordV1 {
    schema: String,
    record_index: u64,
    action: BoundaryJournalAction,
    boundary_id: String,
    boundary: Option<HandoverBoundaryV1>,
    proposal_record_sha256: Option<String>,
    previous_record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundaryJournalAckV1 {
    pub schema: &'static str,
    pub action: BoundaryJournalAction,
    pub boundary_id: String,
    pub durable_record_count: u64,
    pub durable_through_offset: u64,
    pub last_record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundaryJournalScanV1 {
    pub schema: &'static str,
    pub path: PathBuf,
    pub file_size: u64,
    pub records: u64,
    pub last_good_offset: u64,
    pub clean_eof: bool,
    pub reason: Option<String>,
    pub proposal: Option<HandoverBoundaryV1>,
    pub committed: Option<HandoverBoundaryV1>,
    pub last_record_sha256: String,
}

pub struct BoundaryJournalWriter<S: DurableSink = File> {
    sink: S,
    end_offset: u64,
    previous_digest: String,
    proposal: Option<(HandoverBoundaryV1, String)>,
    committed: bool,
    poisoned: bool,
}

impl BoundaryJournalWriter<File> {
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create journal parent {}: {error}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create boundary journal {}: {error}", path.display()))?;
        Self::from_sink(file)
    }
}

impl<S: DurableSink> BoundaryJournalWriter<S> {
    pub fn from_sink(mut sink: S) -> Result<Self> {
        sink.write_all(MAGIC)
            .map_err(|error| format!("write boundary magic: {error}"))?;
        sink.sync_all()
            .map_err(|error| format!("sync boundary magic: {error}"))?;
        Ok(Self {
            sink,
            end_offset: MAGIC.len() as u64,
            previous_digest: ZERO_DIGEST.to_owned(),
            proposal: None,
            committed: false,
            poisoned: false,
        })
    }

    pub fn propose(&mut self, boundary: HandoverBoundaryV1) -> Result<BoundaryJournalAckV1> {
        if self.proposal.is_some() || self.committed {
            return Err("boundary journal already has a proposal".to_owned());
        }
        boundary.validate()?;
        let record = BoundaryJournalRecordV1 {
            schema: "BoundaryJournalRecordV1".to_owned(),
            record_index: 0,
            action: BoundaryJournalAction::Proposed,
            boundary_id: boundary.boundary_id.clone(),
            boundary: Some(boundary.clone()),
            proposal_record_sha256: None,
            previous_record_sha256: self.previous_digest.clone(),
        };
        let ack = self.append_and_sync(record)?;
        self.proposal = Some((boundary, ack.last_record_sha256.clone()));
        Ok(ack)
    }

    pub fn commit(&mut self, boundary_id: &str) -> Result<BoundaryJournalAckV1> {
        if self.committed {
            return Err("boundary journal is already committed".to_owned());
        }
        let (boundary, proposal_digest) = self
            .proposal
            .as_ref()
            .ok_or_else(|| "boundary cannot commit before durable proposal".to_owned())?;
        if boundary.boundary_id != boundary_id {
            return Err("commit boundary ID does not match proposal".to_owned());
        }
        let record = BoundaryJournalRecordV1 {
            schema: "BoundaryJournalRecordV1".to_owned(),
            record_index: 1,
            action: BoundaryJournalAction::Committed,
            boundary_id: boundary_id.to_owned(),
            boundary: None,
            proposal_record_sha256: Some(proposal_digest.clone()),
            previous_record_sha256: self.previous_digest.clone(),
        };
        let ack = self.append_and_sync(record)?;
        self.committed = true;
        Ok(ack)
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn append_and_sync(&mut self, record: BoundaryJournalRecordV1) -> Result<BoundaryJournalAckV1> {
        if self.poisoned {
            return Err("boundary journal is poisoned".to_owned());
        }
        let body = serde_json::to_vec(&record)
            .map_err(|error| format!("serialize boundary record: {error}"))?;
        if body.len() > MAX_RECORD_BYTES {
            return Err("boundary journal record exceeds maximum size".to_owned());
        }
        let digest = Sha256::digest(&body);
        let length = u32::try_from(body.len())
            .map_err(|_| "boundary record length does not fit u32".to_owned())?;
        let mut encoded = Vec::with_capacity(4 + body.len() + 32);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&body);
        encoded.extend_from_slice(&digest);
        if let Err(error) = self
            .sink
            .write_all(&encoded)
            .and_then(|_| self.sink.flush())
            .and_then(|_| self.sink.sync_all())
        {
            self.poisoned = true;
            return Err(format!("sync boundary record; journal poisoned: {error}"));
        }
        self.end_offset = self
            .end_offset
            .checked_add(encoded.len() as u64)
            .ok_or_else(|| "boundary journal offset overflow".to_owned())?;
        self.previous_digest = hex(&digest);
        Ok(BoundaryJournalAckV1 {
            schema: "BoundaryJournalAckV1",
            action: record.action,
            boundary_id: record.boundary_id,
            durable_record_count: record.record_index + 1,
            durable_through_offset: self.end_offset,
            last_record_sha256: self.previous_digest.clone(),
        })
    }
}

pub fn scan_boundary_journal(path: &Path) -> Result<BoundaryJournalScanV1> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_size = file
        .metadata()
        .map_err(|error| format!("metadata {}: {error}", path.display()))?
        .len();
    let mut reader = BufReader::new(file);
    let mut magic = [0_u8; 8];
    if reader.read_exact(&mut magic).is_err() || &magic != MAGIC {
        return Ok(scan_failure(
            path,
            file_size,
            0,
            0,
            "bad boundary journal magic",
        ));
    }
    let mut records = 0_u64;
    let mut last_good_offset = MAGIC.len() as u64;
    let mut previous = ZERO_DIGEST.to_owned();
    let mut proposal: Option<(HandoverBoundaryV1, String)> = None;
    let mut committed = None;
    let mut reason = None;
    loop {
        let mut prefix = [0_u8; 4];
        match reader.read(&mut prefix[..1]) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => return Err(format!("read boundary prefix: {error}")),
        }
        if reader.read_exact(&mut prefix[1..]).is_err() {
            reason = Some("partial boundary length prefix".to_owned());
            break;
        }
        let body_length = u32::from_be_bytes(prefix) as usize;
        if body_length > MAX_RECORD_BYTES {
            reason = Some("boundary record length exceeds limit".to_owned());
            break;
        }
        let mut body = vec![0_u8; body_length];
        if reader.read_exact(&mut body).is_err() {
            reason = Some("partial boundary record body".to_owned());
            break;
        }
        let mut digest = [0_u8; 32];
        if reader.read_exact(&mut digest).is_err() {
            reason = Some("partial boundary record digest".to_owned());
            break;
        }
        let actual: [u8; 32] = Sha256::digest(&body).into();
        if actual != digest {
            reason = Some("boundary record digest mismatch".to_owned());
            break;
        }
        let record: BoundaryJournalRecordV1 = match serde_json::from_slice(&body) {
            Ok(record) => record,
            Err(error) => {
                reason = Some(format!("invalid boundary record JSON: {error}"));
                break;
            }
        };
        let record_digest = hex(&digest);
        let semantic = validate_scanned_record(
            &record,
            records,
            &previous,
            proposal.as_ref(),
            committed.is_some(),
        );
        if let Err(error) = semantic {
            reason = Some(error);
            break;
        }
        match record.action {
            BoundaryJournalAction::Proposed => {
                proposal = Some((
                    record.boundary.expect("validated proposal"),
                    record_digest.clone(),
                ));
            }
            BoundaryJournalAction::Committed => {
                committed = proposal.as_ref().map(|(boundary, _)| boundary.clone());
            }
        }
        records += 1;
        last_good_offset += (4 + body_length + 32) as u64;
        previous = record_digest;
    }
    Ok(BoundaryJournalScanV1 {
        schema: "BoundaryJournalScanV1",
        path: path.to_path_buf(),
        file_size,
        records,
        last_good_offset,
        clean_eof: reason.is_none(),
        reason,
        proposal: proposal.map(|(boundary, _)| boundary),
        committed,
        last_record_sha256: previous,
    })
}

fn validate_scanned_record(
    record: &BoundaryJournalRecordV1,
    expected_index: u64,
    previous: &str,
    proposal: Option<&(HandoverBoundaryV1, String)>,
    already_committed: bool,
) -> Result<()> {
    if record.schema != "BoundaryJournalRecordV1"
        || record.record_index != expected_index
        || record.previous_record_sha256 != previous
    {
        return Err("boundary journal chain/index mismatch".to_owned());
    }
    match record.action {
        BoundaryJournalAction::Proposed => {
            if expected_index != 0 || proposal.is_some() || already_committed {
                return Err("illegal duplicate boundary proposal".to_owned());
            }
            let boundary = record
                .boundary
                .as_ref()
                .ok_or_else(|| "proposal missing boundary".to_owned())?;
            boundary.validate()?;
            if boundary.boundary_id != record.boundary_id || record.proposal_record_sha256.is_some()
            {
                return Err("proposal identity/reference mismatch".to_owned());
            }
        }
        BoundaryJournalAction::Committed => {
            let (boundary, proposal_digest) =
                proposal.ok_or_else(|| "commit has no valid proposal".to_owned())?;
            if expected_index != 1
                || already_committed
                || record.boundary.is_some()
                || record.boundary_id != boundary.boundary_id
                || record.proposal_record_sha256.as_deref() != Some(proposal_digest)
            {
                return Err("commit identity/reference mismatch".to_owned());
            }
        }
    }
    Ok(())
}

fn scan_failure(
    path: &Path,
    file_size: u64,
    records: u64,
    last_good_offset: u64,
    reason: &str,
) -> BoundaryJournalScanV1 {
    BoundaryJournalScanV1 {
        schema: "BoundaryJournalScanV1",
        path: path.to_path_buf(),
        file_size,
        records,
        last_good_offset,
        clean_eof: false,
        reason: Some(reason.to_owned()),
        proposal: None,
        committed: None,
        last_record_sha256: ZERO_DIGEST.to_owned(),
    }
}

fn validate_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("digest must be 64 lowercase hexadecimal characters".to_owned());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
