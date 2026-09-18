//! Durable canonical live-source ownership, recovery and fencing.

use crate::boundary::{BoundaryStreamKind, HandoverBoundaryV1, scan_boundary_journal};
use crate::{DurableSink, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"BNOWN\0\x01\n";
const MAX_RECORD_BYTES: usize = 256 * 1024;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourcePointerSnapshotV1 {
    pub schema: String,
    pub symbol: String,
    pub generation_id: String,
    pub depth_epoch: String,
    pub trade_epoch: String,
    pub fencing_token: u64,
    pub depth_last_sequence: u64,
    pub trade_last_sequence: u64,
}

impl SourcePointerSnapshotV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "SourcePointerSnapshotV1"
            || !matches!(self.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
            || self.generation_id.trim().is_empty()
            || self.depth_epoch.trim().is_empty()
            || self.trade_epoch.trim().is_empty()
            || self.fencing_token == 0
        {
            return Err("invalid source pointer snapshot".to_owned());
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            depth_epoch: &'a str,
            depth_last_sequence: u64,
            fencing_token: u64,
            generation_id: &'a str,
            schema: &'a str,
            symbol: &'a str,
            trade_epoch: &'a str,
            trade_last_sequence: u64,
        }
        let encoded = serde_json::to_vec(&DigestMaterial {
            depth_epoch: &self.depth_epoch,
            depth_last_sequence: self.depth_last_sequence,
            fencing_token: self.fencing_token,
            generation_id: &self.generation_id,
            schema: &self.schema,
            symbol: &self.symbol,
            trade_epoch: &self.trade_epoch,
            trade_last_sequence: self.trade_last_sequence,
        })
        .map_err(|error| format!("serialize source pointer digest: {error}"))?;
        Ok(hex(&Sha256::digest(encoded)))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommittedBoundaryProofV1 {
    pub boundary: HandoverBoundaryV1,
    pub commit_record_sha256: String,
}

pub fn load_committed_boundary_proof(path: &Path) -> Result<CommittedBoundaryProofV1> {
    let scan = scan_boundary_journal(path)?;
    if !scan.clean_eof || scan.records != 2 {
        return Err("boundary journal lacks one complete committed boundary".to_owned());
    }
    let boundary = scan
        .committed
        .ok_or_else(|| "boundary journal is not committed".to_owned())?;
    validate_digest(&scan.last_record_sha256)?;
    Ok(CommittedBoundaryProofV1 {
        boundary,
        commit_record_sha256: scan.last_record_sha256,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnershipActivationV1 {
    pub schema: String,
    pub activation_id: String,
    pub symbol: String,
    pub predecessor_generation: String,
    pub successor_generation: String,
    pub predecessor_depth_epoch: String,
    pub predecessor_trade_epoch: String,
    pub successor_depth_epoch: String,
    pub successor_trade_epoch: String,
    pub depth_boundary_id: String,
    pub trade_boundary_id: String,
    pub depth_commit_record_sha256: String,
    pub trade_commit_record_sha256: String,
    pub depth_boundary_sequence: u64,
    pub trade_boundary_sequence: u64,
    pub fencing_token: u64,
}

impl OwnershipActivationV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != "OwnershipActivationV1"
            || self.activation_id.trim().is_empty()
            || !matches!(self.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
            || self.predecessor_generation.trim().is_empty()
            || self.successor_generation.trim().is_empty()
            || self.predecessor_generation == self.successor_generation
            || self.predecessor_depth_epoch.trim().is_empty()
            || self.predecessor_trade_epoch.trim().is_empty()
            || self.successor_depth_epoch.trim().is_empty()
            || self.successor_trade_epoch.trim().is_empty()
            || self.predecessor_depth_epoch == self.successor_depth_epoch
            || self.predecessor_trade_epoch == self.successor_trade_epoch
            || self.depth_boundary_id.trim().is_empty()
            || self.trade_boundary_id.trim().is_empty()
            || self.depth_boundary_id == self.trade_boundary_id
            || self.fencing_token == 0
        {
            return Err("invalid ownership activation identity".to_owned());
        }
        validate_digest(&self.depth_commit_record_sha256)?;
        validate_digest(&self.trade_commit_record_sha256)?;
        Ok(())
    }

    fn successor_snapshot(&self) -> SourcePointerSnapshotV1 {
        SourcePointerSnapshotV1 {
            schema: "SourcePointerSnapshotV1".to_owned(),
            symbol: self.symbol.clone(),
            generation_id: self.successor_generation.clone(),
            depth_epoch: self.successor_depth_epoch.clone(),
            trade_epoch: self.successor_trade_epoch.clone(),
            fencing_token: self.fencing_token,
            depth_last_sequence: self.depth_boundary_sequence,
            trade_last_sequence: self.trade_boundary_sequence,
        }
    }
}

pub fn derive_ownership_activation(
    activation_id: &str,
    successor_generation: &str,
    current: &SourcePointerSnapshotV1,
    depth: &CommittedBoundaryProofV1,
    trade: &CommittedBoundaryProofV1,
) -> Result<OwnershipActivationV1> {
    current.validate()?;
    depth.boundary.validate()?;
    trade.boundary.validate()?;
    validate_digest(&depth.commit_record_sha256)?;
    validate_digest(&trade.commit_record_sha256)?;
    if depth.boundary.stream_kind != BoundaryStreamKind::Depth
        || trade.boundary.stream_kind != BoundaryStreamKind::Trade
        || depth.boundary.symbol != current.symbol
        || trade.boundary.symbol != current.symbol
        || depth.boundary.predecessor_epoch != current.depth_epoch
        || trade.boundary.predecessor_epoch != current.trade_epoch
        || depth.boundary.boundary_sequence != current.depth_last_sequence
        || trade.boundary.boundary_sequence != current.trade_last_sequence
    {
        return Err("boundary proofs do not continue the active source generation".to_owned());
    }
    let fencing_token = current
        .fencing_token
        .checked_add(1)
        .ok_or_else(|| "fencing token overflow".to_owned())?;
    let activation = OwnershipActivationV1 {
        schema: "OwnershipActivationV1".to_owned(),
        activation_id: activation_id.to_owned(),
        symbol: current.symbol.clone(),
        predecessor_generation: current.generation_id.clone(),
        successor_generation: successor_generation.to_owned(),
        predecessor_depth_epoch: current.depth_epoch.clone(),
        predecessor_trade_epoch: current.trade_epoch.clone(),
        successor_depth_epoch: depth.boundary.successor_epoch.clone(),
        successor_trade_epoch: trade.boundary.successor_epoch.clone(),
        depth_boundary_id: depth.boundary.boundary_id.clone(),
        trade_boundary_id: trade.boundary.boundary_id.clone(),
        depth_commit_record_sha256: depth.commit_record_sha256.clone(),
        trade_commit_record_sha256: trade.commit_record_sha256.clone(),
        depth_boundary_sequence: depth.boundary.boundary_sequence,
        trade_boundary_sequence: trade.boundary.boundary_sequence,
        fencing_token,
    };
    activation.validate()?;
    validate_activation_proofs(&activation, depth, trade)?;
    Ok(activation)
}

fn validate_activation_proofs(
    activation: &OwnershipActivationV1,
    depth: &CommittedBoundaryProofV1,
    trade: &CommittedBoundaryProofV1,
) -> Result<()> {
    depth.boundary.validate()?;
    trade.boundary.validate()?;
    if depth.boundary.stream_kind != BoundaryStreamKind::Depth
        || trade.boundary.stream_kind != BoundaryStreamKind::Trade
        || activation.symbol != depth.boundary.symbol
        || activation.symbol != trade.boundary.symbol
        || activation.predecessor_depth_epoch != depth.boundary.predecessor_epoch
        || activation.predecessor_trade_epoch != trade.boundary.predecessor_epoch
        || activation.successor_depth_epoch != depth.boundary.successor_epoch
        || activation.successor_trade_epoch != trade.boundary.successor_epoch
        || activation.depth_boundary_id != depth.boundary.boundary_id
        || activation.trade_boundary_id != trade.boundary.boundary_id
        || activation.depth_boundary_sequence != depth.boundary.boundary_sequence
        || activation.trade_boundary_sequence != trade.boundary.boundary_sequence
        || activation.depth_commit_record_sha256 != depth.commit_record_sha256
        || activation.trade_commit_record_sha256 != trade.commit_record_sha256
    {
        return Err("ownership activation does not match committed boundary proofs".to_owned());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwnershipAction {
    Initialized,
    Prepared,
    Activated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct OwnershipRecordV1 {
    schema: String,
    record_index: u64,
    action: OwnershipAction,
    initial_owner: Option<SourcePointerSnapshotV1>,
    activation: Option<OwnershipActivationV1>,
    prepared_record_sha256: Option<String>,
    previous_record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OwnershipLedgerAckV1 {
    pub schema: &'static str,
    pub action: OwnershipAction,
    pub durable_record_count: u64,
    pub durable_through_offset: u64,
    pub last_record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OwnershipLedgerScanV1 {
    pub schema: &'static str,
    pub path: PathBuf,
    pub file_size: u64,
    pub records: u64,
    pub last_good_offset: u64,
    pub clean_eof: bool,
    pub reason: Option<String>,
    pub active_owner: Option<SourcePointerSnapshotV1>,
    pub pending_activation: Option<OwnershipActivationV1>,
    pub last_activation: Option<OwnershipActivationV1>,
    pub last_record_sha256: String,
}

pub struct OwnershipLedgerWriter<S: DurableSink = File> {
    sink: S,
    end_offset: u64,
    previous_digest: String,
    record_count: u64,
    active_owner: SourcePointerSnapshotV1,
    pending: Option<(OwnershipActivationV1, String)>,
    poisoned: bool,
}

impl OwnershipLedgerWriter<File> {
    pub fn create(path: &Path, initial: SourcePointerSnapshotV1) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!("create ownership parent {}: {error}", parent.display())
            })?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create ownership ledger {}: {error}", path.display()))?;
        Self::from_sink(file, initial)
    }
}

impl<S: DurableSink> OwnershipLedgerWriter<S> {
    pub fn from_sink(mut sink: S, initial: SourcePointerSnapshotV1) -> Result<Self> {
        initial.validate()?;
        sink.write_all(MAGIC)
            .map_err(|error| format!("write ownership magic: {error}"))?;
        sink.sync_all()
            .map_err(|error| format!("sync ownership magic: {error}"))?;
        let mut writer = Self {
            sink,
            end_offset: MAGIC.len() as u64,
            previous_digest: ZERO_DIGEST.to_owned(),
            record_count: 0,
            active_owner: initial.clone(),
            pending: None,
            poisoned: false,
        };
        writer.append_and_sync(OwnershipRecordV1 {
            schema: "OwnershipRecordV1".to_owned(),
            record_index: 0,
            action: OwnershipAction::Initialized,
            initial_owner: Some(initial),
            activation: None,
            prepared_record_sha256: None,
            previous_record_sha256: ZERO_DIGEST.to_owned(),
        })?;
        Ok(writer)
    }

    pub fn prepare(&mut self, activation: OwnershipActivationV1) -> Result<OwnershipLedgerAckV1> {
        if self.pending.is_some() {
            return Err("ownership ledger already has a pending activation".to_owned());
        }
        validate_activation_predecessor(&self.active_owner, &activation)?;
        let record = OwnershipRecordV1 {
            schema: "OwnershipRecordV1".to_owned(),
            record_index: self.record_count,
            action: OwnershipAction::Prepared,
            initial_owner: None,
            activation: Some(activation.clone()),
            prepared_record_sha256: None,
            previous_record_sha256: self.previous_digest.clone(),
        };
        let ack = self.append_and_sync(record)?;
        self.pending = Some((activation, ack.last_record_sha256.clone()));
        Ok(ack)
    }

    pub fn activate(&mut self, activation_id: &str) -> Result<OwnershipLedgerAckV1> {
        let (activation, prepared_digest) = self
            .pending
            .as_ref()
            .ok_or_else(|| "ownership cannot activate before durable prepare".to_owned())?;
        if activation.activation_id != activation_id {
            return Err("ownership activation ID does not match prepared record".to_owned());
        }
        let record = OwnershipRecordV1 {
            schema: "OwnershipRecordV1".to_owned(),
            record_index: self.record_count,
            action: OwnershipAction::Activated,
            initial_owner: None,
            activation: None,
            prepared_record_sha256: Some(prepared_digest.clone()),
            previous_record_sha256: self.previous_digest.clone(),
        };
        let ack = self.append_and_sync(record)?;
        let (activation, _) = self.pending.take().expect("pending checked above");
        self.active_owner = activation.successor_snapshot();
        Ok(ack)
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn append_and_sync(&mut self, record: OwnershipRecordV1) -> Result<OwnershipLedgerAckV1> {
        if self.poisoned {
            return Err("ownership ledger is poisoned".to_owned());
        }
        let body = serde_json::to_vec(&record)
            .map_err(|error| format!("serialize ownership record: {error}"))?;
        if body.len() > MAX_RECORD_BYTES {
            return Err("ownership record exceeds maximum size".to_owned());
        }
        let digest = Sha256::digest(&body);
        let length = u32::try_from(body.len())
            .map_err(|_| "ownership record length does not fit u32".to_owned())?;
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
            return Err(format!("sync ownership record; ledger poisoned: {error}"));
        }
        self.record_count += 1;
        self.end_offset = self
            .end_offset
            .checked_add(encoded.len() as u64)
            .ok_or_else(|| "ownership offset overflow".to_owned())?;
        self.previous_digest = hex(&digest);
        Ok(OwnershipLedgerAckV1 {
            schema: "OwnershipLedgerAckV1",
            action: record.action,
            durable_record_count: self.record_count,
            durable_through_offset: self.end_offset,
            last_record_sha256: self.previous_digest.clone(),
        })
    }
}

fn validate_activation_predecessor(
    active: &SourcePointerSnapshotV1,
    activation: &OwnershipActivationV1,
) -> Result<()> {
    active.validate()?;
    activation.validate()?;
    if activation.symbol != active.symbol
        || activation.predecessor_generation != active.generation_id
        || activation.predecessor_depth_epoch != active.depth_epoch
        || activation.predecessor_trade_epoch != active.trade_epoch
        || activation.fencing_token != active.fencing_token.checked_add(1).unwrap_or(0)
    {
        return Err("ownership activation does not exactly continue active owner".to_owned());
    }
    Ok(())
}

pub fn scan_ownership_ledger(path: &Path) -> Result<OwnershipLedgerScanV1> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_size = file
        .metadata()
        .map_err(|error| format!("metadata {}: {error}", path.display()))?
        .len();
    let mut reader = BufReader::new(file);
    let mut magic = [0_u8; 8];
    if reader.read_exact(&mut magic).is_err() || &magic != MAGIC {
        return Ok(OwnershipLedgerScanV1 {
            schema: "OwnershipLedgerScanV1",
            path: path.to_path_buf(),
            file_size,
            records: 0,
            last_good_offset: 0,
            clean_eof: false,
            reason: Some("bad ownership ledger magic".to_owned()),
            active_owner: None,
            pending_activation: None,
            last_activation: None,
            last_record_sha256: ZERO_DIGEST.to_owned(),
        });
    }
    let mut records = 0_u64;
    let mut previous = ZERO_DIGEST.to_owned();
    let mut last_good_offset = MAGIC.len() as u64;
    let mut active_owner: Option<SourcePointerSnapshotV1> = None;
    let mut pending: Option<(OwnershipActivationV1, String)> = None;
    let mut last_activation = None;
    let mut reason = None;
    loop {
        let mut prefix = [0_u8; 4];
        match reader.read(&mut prefix[..1]) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                reason = Some(format!("read ownership prefix: {error}"));
                break;
            }
        }
        if reader.read_exact(&mut prefix[1..]).is_err() {
            reason = Some("partial ownership length prefix".to_owned());
            break;
        }
        let body_length = u32::from_be_bytes(prefix) as usize;
        if body_length > MAX_RECORD_BYTES {
            reason = Some("ownership record length exceeds limit".to_owned());
            break;
        }
        let mut body = vec![0_u8; body_length];
        if reader.read_exact(&mut body).is_err() {
            reason = Some("partial ownership record body".to_owned());
            break;
        }
        let mut digest = [0_u8; 32];
        if reader.read_exact(&mut digest).is_err() {
            reason = Some("partial ownership record digest".to_owned());
            break;
        }
        if Sha256::digest(&body).as_slice() != digest {
            reason = Some("ownership record digest mismatch".to_owned());
            break;
        }
        let record: OwnershipRecordV1 = match serde_json::from_slice(&body) {
            Ok(record) => record,
            Err(error) => {
                reason = Some(format!("invalid ownership record JSON: {error}"));
                break;
            }
        };
        let result = (|| -> Result<()> {
            if record.schema != "OwnershipRecordV1"
                || record.record_index != records
                || record.previous_record_sha256 != previous
            {
                return Err("ownership ledger chain/index mismatch".to_owned());
            }
            match record.action {
                OwnershipAction::Initialized => {
                    if records != 0 || active_owner.is_some() || pending.is_some() {
                        return Err("illegal ownership initialization".to_owned());
                    }
                    let owner = record
                        .initial_owner
                        .ok_or_else(|| "ownership initialization lacks owner".to_owned())?;
                    if record.activation.is_some() || record.prepared_record_sha256.is_some() {
                        return Err("ownership initialization has illegal fields".to_owned());
                    }
                    owner.validate()?;
                    active_owner = Some(owner);
                }
                OwnershipAction::Prepared => {
                    let owner = active_owner
                        .as_ref()
                        .ok_or_else(|| "ownership prepare precedes initialization".to_owned())?;
                    if pending.is_some()
                        || record.initial_owner.is_some()
                        || record.prepared_record_sha256.is_some()
                    {
                        return Err("illegal ownership prepare".to_owned());
                    }
                    let activation = record
                        .activation
                        .ok_or_else(|| "ownership prepare lacks activation".to_owned())?;
                    validate_activation_predecessor(owner, &activation)?;
                    pending = Some((activation, hex(&digest)));
                }
                OwnershipAction::Activated => {
                    let (activation, prepared_digest) = pending
                        .take()
                        .ok_or_else(|| "ownership activation has no prepared record".to_owned())?;
                    if record.initial_owner.is_some()
                        || record.activation.is_some()
                        || record.prepared_record_sha256.as_deref() != Some(&prepared_digest)
                    {
                        return Err("ownership activation reference mismatch".to_owned());
                    }
                    active_owner = Some(activation.successor_snapshot());
                    last_activation = Some(activation);
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            reason = Some(error);
            break;
        }
        records += 1;
        last_good_offset = last_good_offset
            .checked_add((4 + body_length + 32) as u64)
            .ok_or_else(|| "ownership scan offset overflow".to_owned())?;
        previous = hex(&digest);
    }
    Ok(OwnershipLedgerScanV1 {
        schema: "OwnershipLedgerScanV1",
        path: path.to_path_buf(),
        file_size,
        records,
        last_good_offset,
        clean_eof: reason.is_none(),
        reason,
        active_owner,
        pending_activation: pending.map(|item| item.0),
        last_activation,
        last_record_sha256: previous,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LivePublicationState {
    Live,
    Gap,
}

#[derive(Debug, Serialize)]
pub struct CanonicalSourcePointer {
    pub owner: SourcePointerSnapshotV1,
    pub state: LivePublicationState,
    pub fenced_rejections: u64,
    pub gap_reason: Option<String>,
}

impl CanonicalSourcePointer {
    pub fn recover(
        scan: &OwnershipLedgerScanV1,
        committed_proofs: Option<(&CommittedBoundaryProofV1, &CommittedBoundaryProofV1)>,
    ) -> Result<Self> {
        if !scan.clean_eof || scan.records == 0 {
            return Err("ownership ledger is not a clean recoverable authority".to_owned());
        }
        let owner = scan
            .active_owner
            .clone()
            .ok_or_else(|| "ownership ledger has no active owner".to_owned())?;
        owner.validate()?;
        match (&scan.last_activation, committed_proofs) {
            (None, None) => {}
            (Some(activation), Some((depth, trade))) => {
                validate_activation_proofs(activation, depth, trade)?;
                if activation.successor_snapshot() != owner {
                    return Err("active owner does not match last durable activation".to_owned());
                }
            }
            (Some(_), None) => {
                return Err("activated ownership recovery requires both boundary proofs".to_owned());
            }
            (None, Some(_)) => {
                return Err(
                    "initial ownership recovery received unexpected boundary proofs".to_owned(),
                );
            }
        }
        Ok(Self {
            owner,
            state: LivePublicationState::Live,
            fenced_rejections: 0,
            gap_reason: None,
        })
    }

    pub fn accept_observation(
        &mut self,
        kind: BoundaryStreamKind,
        epoch: &str,
        fencing_token: u64,
        first_sequence: u64,
        final_sequence: u64,
    ) -> Result<()> {
        if self.state != LivePublicationState::Live {
            return Err("canonical publication is GAP".to_owned());
        }
        let (expected_epoch, last_sequence) = match kind {
            BoundaryStreamKind::Depth => {
                (&self.owner.depth_epoch, &mut self.owner.depth_last_sequence)
            }
            BoundaryStreamKind::Trade => {
                (&self.owner.trade_epoch, &mut self.owner.trade_last_sequence)
            }
        };
        if epoch != expected_epoch || fencing_token != self.owner.fencing_token {
            self.fenced_rejections += 1;
            return Err("publication rejected by active ownership fence".to_owned());
        }
        let expected = last_sequence
            .checked_add(1)
            .ok_or_else(|| "canonical sequence overflow".to_owned())?;
        let valid = match kind {
            BoundaryStreamKind::Depth => first_sequence <= expected && final_sequence >= expected,
            BoundaryStreamKind::Trade => first_sequence == expected && final_sequence == expected,
        };
        if !valid {
            let reason = format!(
                "active canonical sequence gap: expected {expected}, got {first_sequence}..{final_sequence}"
            );
            self.state = LivePublicationState::Gap;
            self.gap_reason = Some(reason.clone());
            return Err(reason);
        }
        *last_sequence = final_sequence;
        Ok(())
    }

    pub fn fail_active(&mut self, epoch: &str, reason: &str) -> Result<()> {
        if reason.trim().is_empty() {
            return Err("active failure reason is required".to_owned());
        }
        if epoch != self.owner.depth_epoch && epoch != self.owner.trade_epoch {
            self.fenced_rejections += 1;
            return Err("failure source is not the active owner".to_owned());
        }
        self.state = LivePublicationState::Gap;
        self.gap_reason = Some(reason.to_owned());
        Ok(())
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
