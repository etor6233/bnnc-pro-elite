//! Pure realtime arbitration core for the two redundant raw lanes.
//!
//! This module implements the ADR-16 live cross-lane arbitration as pure
//! state machines over already-materialized `CanonicalObservationV1` streams.
//! It never reads or rewrites BNRAW/BNACK: every input is an immutable,
//! durably acknowledged observation that already carries its exact raw
//! lineage.  The venue's own sequence is the arbitration key:
//!
//! - trades: `trade_id` is strictly increasing per symbol on every
//!   connection; the same trade carries the same ID on both lanes, so the
//!   canonical stream is the deduplicated union;
//! - depth: `U`/`u` update IDs form one venue-global sequence per symbol;
//!   a lane switch is proven only when the sibling's window covers the
//!   canonical next-expected update ID and the reconstructed book digests
//!   converge at the boundary (nautilus_trader-style correctness: gap-free
//!   is not the same as correct, so both conditions are mandatory).
//!
//! A gap is published only when the same events are missing from BOTH lanes.
//! No observation is ever bridged, reordered or duplicated.

use crate::Result;
use crate::boundary::{BoundaryStreamKind, CanonicalObservationV1};
use crate::hot_redundancy::CaptureLane;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Disposition of one observed trade under the union policy (ADR-16 fix).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TradeUnionDisposition {
    /// A contiguous batch of trade IDs below the live-lane watermark is now
    /// emittable in strictly increasing order, each with the lane of its
    /// first-arrival lineage.
    Publishable(Vec<(CaptureLane, CanonicalObservationV1)>),
    /// Buffered: the ID waits for every live lane's durable prefix to pass it
    /// (both lanes deliver in venue order, so nothing below the watermark can
    /// ever arrive later).
    Buffered,
    /// The ID is below the canonical position (a late delivery, e.g. from a
    /// lane that exceeded the lag bound): publish it as a typed
    /// `TRADE_LATE_CORRECTION` with its classification, never as a silent
    /// drop.
    Late {
        observation: CanonicalObservationV1,
        kind: LateCorrectionKind,
    },
    /// Two lanes delivered the same trade ID with different semantic payloads
    /// (different event digests): the union cannot choose arbitrarily.  This
    /// fires for buffered AND already-published IDs (identity is compared
    /// against the retained published set, never against a bare ID bound).
    Conflict {
        trade_id: u64,
        first_digest: String,
        second_digest: String,
    },
}

/// Classification of a late delivery of an already-published trade ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LateCorrectionKind {
    /// The retained published identity holds the same semantic digest: the
    /// sibling's identical duplicate of a published trade.
    Duplicate,
    /// The ID is below the canonical position but was never published (a
    /// venue drop the union repaired late) or its identity fell out of the
    /// bounded retention window; the lineage is preserved and the offline
    /// oracle resolves the exact class against the raw.
    Unknown,
}

/// One buffered trade: the first-arrival observation plus every lane's
/// lineage for the same ID.
#[derive(Clone, Debug)]
struct TradeUnionEntry {
    observation: CanonicalObservationV1,
    lineages: Vec<(CaptureLane, String)>,
}

/// Bounded retained identity of already-published trades: ID -> semantic
/// digest.  Identity comparison happens against this set, not against a bare
/// `id <= last_published` bound (TigerBeetle pattern: look up the persisted
/// identity and compare content before classifying a retry).
const PUBLISHED_CAP: usize = 65_536;

/// Durable append-only trade identity log (ADR-17 B4 completion).
///
/// The in-memory `published` retention window is bounded; eviction must not
/// silently degrade a post-publish contradiction into `Unknown`.  This log
/// persists every published trade's semantic identity (trade ID -> the
/// journal observation SHA-256) with the project's durability discipline so
/// the classification survives cache eviction and arbiter restarts.
///
/// On-disk layout (all little-endian):
///
/// - 32-byte header: magic `LOBIDLOG1` (8) + version u32 = 1 (4) + record
///   count u64 (8) + 12 reserved zero bytes;
/// - fixed 40-byte records: trade ID u64 + 32-byte raw SHA-256.
///
/// Records are appended in strictly increasing trade ID order (publication
/// order).  Inserts write the record, then the count, syncing both, so a
/// torn tail can never be read as a record.  Lookup is a binary search by
/// seek (O(log n) random reads), so the query cost is bounded and no
/// unbounded memory is retained.  The canonical journal remains the source
/// of truth: on resume, any published identity missing from this log is
/// rebuilt from the journal.
#[derive(Debug)]
pub struct TradeIdentityLog {
    file: File,
    count: u64,
    last_id: Option<u64>,
    /// Records written since the last header sync (the header count is the
    /// committed boundary; trailing uncommitted records are ignored on
    /// reopen and rebuilt from the journal on resume).
    dirty: bool,
}

const IDENTITY_LOG_MAGIC: &[u8; 8] = b"LOBIDLOG";
const IDENTITY_LOG_VERSION: u32 = 1;
const IDENTITY_LOG_HEADER_BYTES: u64 = 32;
const IDENTITY_LOG_RECORD_BYTES: u64 = 40;

fn hex_decode_32(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("trade identity digest is not a 64-character hex SHA-256".to_owned());
    }
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        let high = hex.as_bytes()[index * 2];
        let low = hex.as_bytes()[index * 2 + 1];
        let nibble = |byte: u8| -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => unreachable!("validated above"),
            }
        };
        *byte = (nibble(high) << 4) | nibble(low);
    }
    Ok(out)
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

impl TradeIdentityLog {
    /// Creates a NEW identity log (create-only discipline): the path must
    /// not already exist.
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create trade identity parent: {error}"))?;
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        let header = Self::header_bytes(0);
        file.write_all(&header)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("sync trade identity header: {error}"))?;
        Ok(Self {
            file,
            count: 0,
            last_id: None,
            dirty: false,
        })
    }

    /// Opens an existing identity log for append + lookup (resume).
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("open {}: {error}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("stat {}: {error}", path.display()))?;
        let length = metadata.len();
        if length < IDENTITY_LOG_HEADER_BYTES {
            return Err(format!(
                "trade identity log {} is shorter than its header",
                path.display()
            ));
        }
        let mut header = [0_u8; IDENTITY_LOG_HEADER_BYTES as usize];
        file.seek(SeekFrom::Start(0))
            .and_then(|_| file.read_exact(&mut header))
            .map_err(|error| format!("read trade identity header: {error}"))?;
        if &header[0..8] != IDENTITY_LOG_MAGIC
            || u32::from_le_bytes(header[8..12].try_into().expect("4 bytes"))
                != IDENTITY_LOG_VERSION
        {
            return Err(format!(
                "trade identity log {} carries an unknown header",
                path.display()
            ));
        }
        let count = u64::from_le_bytes(header[12..20].try_into().expect("8 bytes"));
        let expected = IDENTITY_LOG_HEADER_BYTES
            .checked_add(count.saturating_mul(IDENTITY_LOG_RECORD_BYTES))
            .ok_or_else(|| "trade identity log length overflow".to_owned())?;
        if length < expected {
            return Err(format!(
                "trade identity log {} is truncated: header declares {count} records",
                path.display()
            ));
        }
        let last_id = if count == 0 {
            None
        } else {
            Some(Self::read_record_at(&mut file, count - 1)?.0)
        };
        Ok(Self {
            file,
            count,
            last_id,
            dirty: false,
        })
    }

    fn header_bytes(count: u64) -> [u8; IDENTITY_LOG_HEADER_BYTES as usize] {
        let mut header = [0_u8; IDENTITY_LOG_HEADER_BYTES as usize];
        header[0..8].copy_from_slice(IDENTITY_LOG_MAGIC);
        header[8..12].copy_from_slice(&IDENTITY_LOG_VERSION.to_le_bytes());
        header[12..20].copy_from_slice(&count.to_le_bytes());
        header
    }

    fn read_record_at(file: &mut File, index: u64) -> Result<(u64, [u8; 32])> {
        let offset = IDENTITY_LOG_HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(IDENTITY_LOG_RECORD_BYTES)
                    .ok_or_else(|| "trade identity record offset overflow".to_owned())?,
            )
            .ok_or_else(|| "trade identity record offset overflow".to_owned())?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| format!("seek trade identity record: {error}"))?;
        let mut bytes = [0_u8; IDENTITY_LOG_RECORD_BYTES as usize];
        file.read_exact(&mut bytes)
            .map_err(|error| format!("read trade identity record: {error}"))?;
        let id = u64::from_le_bytes(bytes[0..8].try_into().expect("8 bytes"));
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes[8..40]);
        Ok((id, digest))
    }

    /// Appends one published identity (record write only; the caller batches
    /// the durability with `sync` after the whole publication batch, exactly
    /// like the journal appends).  IDs must be strictly increasing
    /// (publication order).  Records beyond the committed header count are a
    /// torn tail on reopen: ignored, and rebuilt from the journal on resume.
    pub fn insert(&mut self, id: u64, digest_hex: &str) -> Result<()> {
        if self.last_id.is_some_and(|last| id <= last) {
            return Err(format!(
                "trade identity log insert regressed: {id} after {}",
                self.last_id.expect("just checked")
            ));
        }
        let digest = hex_decode_32(digest_hex)?;
        let mut record = [0_u8; IDENTITY_LOG_RECORD_BYTES as usize];
        record[0..8].copy_from_slice(&id.to_le_bytes());
        record[8..40].copy_from_slice(&digest);
        self.file
            .seek(SeekFrom::End(0))
            .and_then(|_| self.file.write_all(&record))
            .map_err(|error| format!("write trade identity record: {error}"))?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| "trade identity log count overflow".to_owned())?;
        self.last_id = Some(id);
        self.dirty = true;
        Ok(())
    }

    /// Commits the buffered inserts: the header count is written and synced,
    /// making every record below it durable and observable.
    pub fn sync(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let header = Self::header_bytes(self.count);
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.write_all(&header))
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_all())
            .map_err(|error| format!("sync trade identity header: {error}"))?;
        self.dirty = false;
        Ok(())
    }

    /// Binary search by trade ID over the durable records.
    pub fn lookup(&mut self, id: u64) -> Result<Option<String>> {
        let mut low = 0_u64;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let (candidate, _) = Self::read_record_at(&mut self.file, middle)?;
            if candidate < id {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if low < self.count {
            let (candidate, digest) = Self::read_record_at(&mut self.file, low)?;
            if candidate == id {
                return Ok(Some(hex_encode_32(&digest)));
            }
        }
        Ok(None)
    }

    pub fn records(&self) -> u64 {
        self.count
    }

    pub fn last_id(&self) -> Option<u64> {
        self.last_id
    }

    /// Bounded full validation: header, record count, strictly increasing
    /// IDs and non-degenerate digests.  Used at resume and by auditors.
    pub fn validate(&mut self) -> Result<()> {
        let metadata = self
            .file
            .metadata()
            .map_err(|error| format!("stat trade identity log: {error}"))?;
        if metadata.len()
            < IDENTITY_LOG_HEADER_BYTES
                .saturating_add(self.count.saturating_mul(IDENTITY_LOG_RECORD_BYTES))
        {
            return Err("trade identity log is truncated".to_owned());
        }
        let mut previous: Option<u64> = None;
        for index in 0..self.count {
            let (id, digest) = Self::read_record_at(&mut self.file, index)?;
            if previous.is_some_and(|last| id <= last) {
                return Err(format!(
                    "trade identity log IDs are not strictly increasing at record {index}"
                ));
            }
            if digest == [0_u8; 32] {
                return Err(format!(
                    "trade identity log record {index} carries a zero digest"
                ));
            }
            previous = Some(id);
        }
        Ok(())
    }
}

/// Rebuilds any published identity missing from the durable log by walking a
/// canonical journal segment (the source of truth).  Callers run the
/// incremental chain scan first; this pass only inserts the trade identities
/// with IDs beyond the log's current head.  Returns how many identities were
/// materialized.
pub fn rebuild_trade_identity_from_journal(
    journal: &Path,
    log: &mut TradeIdentityLog,
) -> Result<u64> {
    let file =
        File::open(journal).map_err(|error| format!("open {}: {error}", journal.display()))?;
    let mut reader = BufReader::new(file);
    let mut rebuilt = 0_u64;
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let read = reader
            .read_until(b'\n', &mut buf)
            .map_err(|error| format!("read arbitration journal: {error}"))?;
        if read == 0 {
            break;
        }
        // The chain scan has already validated the complete prefix and the
        // resume declaration of any torn suffix. Rebuild only committed
        // newline-terminated records, including when the suffix cuts UTF-8.
        if buf.last() != Some(&b'\n') {
            break;
        }
        let line = &buf[..read - 1];
        if line.is_empty() {
            continue;
        }
        let envelope: LiveArbitrationJournalEnvelopeV1 = serde_json::from_slice(line)
            .map_err(|error| format!("invalid arbitration journal JSON: {error}"))?;
        let Some(event) = envelope.body.payload.get("event").and_then(Value::as_str) else {
            return Err("arbitration journal record lacks an event".to_owned());
        };
        if event == "TRADE_OBSERVATION" {
            let id = envelope
                .body
                .payload
                .get("trade_id")
                .and_then(Value::as_u64)
                .ok_or_else(|| "trade observation lacks an exact trade ID".to_owned())?;
            let digest = envelope
                .body
                .payload
                .get("observation_sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| "trade observation lacks its observation digest".to_owned())?;
            if log.last_id().is_none_or(|last| id > last) {
                log.insert(id, digest)?;
                rebuilt += 1;
            }
        }
    }
    log.sync()?;
    Ok(rebuilt)
}

/// Pure trade union arbiter (ADR-16 fix for the 428/209 measured omissions).
/// from the other lane was previously classified as stale even when it had
/// never been published (`PRIMARY=[100,102], SHADOW=[101,102]` lost `101`).
/// This state keeps every observed ID buffered until EVERY live lane's
/// durable prefix has passed it (per-lane delivery is venue-ordered, so an
/// ID below the minimum of the lanes' next IDs can never arrive later), then
/// emits the strictly increasing batch.  Duplicate IDs from both lanes are
/// merged when their semantic payloads agree; a disagreement is a typed
/// conflict, never an arbitrary choice — including after publication, where
/// the retained published identity decides duplicate vs conflict.  A lane
/// that exceeds the lag bound is excluded from the watermark by the caller
/// (`exclude_lane`); its later deliveries then surface as typed late
/// corrections, preserving lineage.
#[derive(Debug, Default)]
pub struct TradeUnionState {
    buffer: std::collections::BTreeMap<u64, TradeUnionEntry>,
    lane_next: std::collections::BTreeMap<CaptureLane, u64>,
    last_published_id: Option<u64>,
    /// Fast-forward boundary: IDs at or below it precede the canonical start
    /// and are never published (their lineage stays in the immutable raw).
    consumed_floor: Option<u64>,
    /// Retained identity of published trades (bounded by `PUBLISHED_CAP`).
    published: std::collections::BTreeMap<u64, String>,
    /// Late identities are ordered by discovery, not by ID. The journal is
    /// their durable authority; resume restores them separately from the
    /// monotone publication identity log.
    corrected: std::collections::BTreeMap<u64, String>,
    /// Durable identity log consulted when the bounded cache no longer holds
    /// an ID (ADR-17 B4): eviction and restarts must not degrade a
    /// post-publish contradiction into `Unknown`.
    durable: Option<TradeIdentityLog>,
    /// Handover emission clamps (ADR-17 B3/B5): while a lane has a
    /// predecessor generation whose trade tail is not yet fully sealed and
    /// consumed, the successor's records must not release the emission
    /// watermark past the predecessor's consumed head — records with IDs
    /// between the head and the successor's prefix may still arrive from the
    /// tail, and emitting past them would silently skip them forever
    /// (fault-gate defect hrs-438af564df4d: 100 ETHUSDT union trades lost at
    /// campaign handovers).  Each lane's clamp is the smallest unfinished
    /// predecessor head; the clamped watermark bounds EMISSION ONLY (the
    /// lane positions and the lag policy keep the true delivery cursor).
    emission_clamps: std::collections::BTreeMap<CaptureLane, u64>,
}

impl TradeUnionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches the durable identity log (live arbiter).  Every published
    /// trade is also inserted into the log, and post-publish classification
    /// falls back to it whenever the bounded in-memory set evicted the ID.
    pub fn set_identity_log(&mut self, log: TradeIdentityLog) {
        self.durable = Some(log);
    }

    /// Releases the durable identity log (e.g. to rebuild it on resume).
    pub fn take_identity_log(&mut self) -> Option<TradeIdentityLog> {
        self.durable.take()
    }

    pub fn restore_startup_floor(&mut self, floor: u64) {
        self.consumed_floor = Some(floor);
    }

    pub fn restore_corrected_identity(&mut self, id: u64, digest: String) -> Result<()> {
        if self
            .corrected
            .get(&id)
            .is_some_and(|previous| previous != &digest)
        {
            return Err("corrected trade identity conflicts on recovery".to_owned());
        }
        self.corrected.insert(id, digest);
        Ok(())
    }

    pub fn last_published_id(&self) -> Option<u64> {
        self.last_published_id
    }

    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// The current emission watermark: the minimum ID that some live lane has
    /// not yet passed.  `None` while no lane has delivered anything.
    pub fn watermark(&self) -> Option<u64> {
        self.lane_next.values().copied().min()
    }

    /// The number of live lanes whose next IDs bound the watermark.
    pub fn live_lanes(&self) -> usize {
        self.lane_next.len()
    }

    /// Arms the handover emission clamp for one lane (see the field docs):
    /// emission for that lane may not pass `first_unconsumed_or_head_plus_one`
    /// until the clamp is cleared, so a successor generation can never skip
    /// records that a not-yet-sealed predecessor tail may still deliver.
    /// Re-arming lowers/raises the bound; the caller keeps it at the
    /// smallest unfinished predecessor head.
    pub fn set_emission_clamp(&mut self, lane: CaptureLane, bound: u64) {
        self.emission_clamps.insert(lane, bound);
    }

    /// Disarms the handover emission clamp for one lane (every predecessor
    /// generation of that lane is sealed and fully consumed).
    pub fn clear_emission_clamp(&mut self, lane: CaptureLane) {
        self.emission_clamps.remove(&lane);
    }

    /// The emission watermark: the minimum of the lanes' delivery cursors,
    /// each additionally bounded by its handover clamp (unfinished
    /// predecessor tails).  `None` while no lane has delivered anything.
    fn emission_watermark(&self) -> Option<u64> {
        let mut bound: Option<u64> = None;
        for (lane, next) in &self.lane_next {
            let lane_bound = match self.emission_clamps.get(lane) {
                Some(clamp) => (*next).min(*clamp),
                None => *next,
            };
            bound = Some(match bound {
                Some(current) => current.min(lane_bound),
                None => lane_bound,
            });
        }
        bound
    }

    /// The minimum ID the given live lane has not yet delivered (`None` when
    /// the lane is excluded or unknown).
    pub fn lane_next(&self, lane: CaptureLane) -> Option<u64> {
        self.lane_next.get(&lane).copied()
    }

    /// Registers a live lane before any observation: an unregistered lane
    /// would not bound the watermark and a single lane could publish its own
    /// stream immediately, losing the union property.  A registered lane
    /// without deliveries bounds the watermark at 0 until its first trade
    /// arrives (per-connection order then makes every ID below its first
    /// delivery final from that lane's perspective).
    pub fn register_lane(&mut self, lane: CaptureLane) {
        self.lane_next.entry(lane).or_insert(0);
    }

    /// Consumes one historical trade of a lane's durable prefix at the
    /// canonical start: it advances the lane's position and the coverage
    /// floor without ever publishing it.
    pub fn fast_forward(
        &mut self,
        lane: CaptureLane,
        observation: &CanonicalObservationV1,
    ) -> Result<()> {
        if observation.stream_kind != BoundaryStreamKind::Trade {
            return Err("trade union received a non-trade observation".to_owned());
        }
        if observation.first_sequence != observation.final_sequence {
            return Err(
                "trade observation carries a range instead of one exact trade ID".to_owned(),
            );
        }
        let id = observation.final_sequence;
        let next = id.saturating_add(1);
        if self
            .lane_next
            .get(&lane)
            .is_none_or(|current| next > *current)
        {
            self.lane_next.insert(lane, next);
        }
        if self.consumed_floor.is_none_or(|floor| id > floor) {
            self.consumed_floor = Some(id);
        }
        Ok(())
    }

    /// Observes one trade from one lane and advances the union.
    pub fn observe(
        &mut self,
        lane: CaptureLane,
        observation: &CanonicalObservationV1,
    ) -> Result<TradeUnionDisposition> {
        if observation.stream_kind != BoundaryStreamKind::Trade {
            return Err("trade union received a non-trade observation".to_owned());
        }
        if observation.first_sequence != observation.final_sequence {
            return Err(
                "trade observation carries a range instead of one exact trade ID".to_owned(),
            );
        }
        let id = observation.final_sequence;
        if self.consumed_floor.is_some_and(|floor| id <= floor) {
            // Pre-canonical history: evidence lives in raw; outside the window.
            return Ok(TradeUnionDisposition::Buffered);
        }
        if self.last_published_id.is_some_and(|last| id <= last) {
            if let Some(digest) = self.corrected.get(&id) {
                return Ok(if digest == &observation.observation_sha256 {
                    TradeUnionDisposition::Late {
                        observation: observation.clone(),
                        kind: LateCorrectionKind::Duplicate,
                    }
                } else {
                    TradeUnionDisposition::Conflict {
                        trade_id: id,
                        first_digest: digest.clone(),
                        second_digest: observation.observation_sha256.clone(),
                    }
                });
            }
            // Post-publish classification against the RETAINED IDENTITY
            // (TigerBeetle pattern): same ID with the same content is the
            // sibling's identical duplicate; same ID with different content
            // is a typed conflict, never a silent acceptance.  The bounded
            // in-memory set is consulted first; when it evicted the ID, the
            // durable identity log answers the same question (ADR-17 B4:
            // eviction and restarts must not degrade a contradiction into
            // `Unknown`).  `Unknown` remains the honest answer only when the
            // ID was genuinely never published.
            let durable_digest = match self.durable.as_mut() {
                Some(log) => Some(log.lookup(id)?),
                None => None,
            };
            return Ok(match self.published.get(&id) {
                Some(digest) if *digest == observation.observation_sha256 => {
                    TradeUnionDisposition::Late {
                        observation: observation.clone(),
                        kind: LateCorrectionKind::Duplicate,
                    }
                }
                Some(digest) => TradeUnionDisposition::Conflict {
                    trade_id: id,
                    first_digest: digest.clone(),
                    second_digest: observation.observation_sha256.clone(),
                },
                None => match durable_digest {
                    Some(Some(digest)) if digest == observation.observation_sha256 => {
                        TradeUnionDisposition::Late {
                            observation: observation.clone(),
                            kind: LateCorrectionKind::Duplicate,
                        }
                    }
                    Some(Some(digest)) => TradeUnionDisposition::Conflict {
                        trade_id: id,
                        first_digest: digest,
                        second_digest: observation.observation_sha256.clone(),
                    },
                    _ => {
                        self.corrected
                            .insert(id, observation.observation_sha256.clone());
                        TradeUnionDisposition::Late {
                            observation: observation.clone(),
                            kind: LateCorrectionKind::Unknown,
                        }
                    }
                },
            });
        }
        match self.buffer.entry(id) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(TradeUnionEntry {
                    observation: observation.clone(),
                    lineages: vec![(lane, observation.record_sha256.clone())],
                });
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let entry = slot.get_mut();
                if entry.observation.observation_sha256 != observation.observation_sha256 {
                    return Ok(TradeUnionDisposition::Conflict {
                        trade_id: id,
                        first_digest: entry.observation.observation_sha256.clone(),
                        second_digest: observation.observation_sha256.clone(),
                    });
                }
                entry
                    .lineages
                    .push((lane, observation.record_sha256.clone()));
            }
        }
        let next = id.saturating_add(1);
        let advanced = self
            .lane_next
            .get(&lane)
            .is_none_or(|current| next > *current);
        if advanced {
            self.lane_next.insert(lane, next);
        }
        self.drain()
    }

    /// The lane's generation renewed (or exceeded the lag bound): its old
    /// stream will never deliver again, so it stops bounding the watermark.
    pub fn exclude_lane(&mut self, lane: CaptureLane) {
        self.lane_next.remove(&lane);
    }

    /// Restores one published identity into the bounded in-memory set on
    /// resume (ADR-17 B4): the resume walk replays the canonical journal's
    /// trade observations and then pins the published floor.
    pub fn restore_published_identity(&mut self, id: u64, digest: &str) {
        self.published.insert(id, digest.to_owned());
        while self.published.len() > PUBLISHED_CAP {
            let oldest = self
                .published
                .keys()
                .next()
                .copied()
                .expect("published map is non-empty");
            self.published.remove(&oldest);
        }
    }

    /// Pins the published position on resume: every ID at or below the floor
    /// is classified against the retained/durable identity instead of being
    /// buffered for first publication, so a restart can never duplicate a
    /// trade.  The fast-forward coverage floor is a separate boundary
    /// (pre-canonical history) and is restored by the resume fast-forward.
    pub fn restore_published_floor(&mut self, floor: u64) -> Result<()> {
        if self.last_published_id.is_some_and(|last| floor < last) {
            return Err("trade union published floor regressed".to_owned());
        }
        self.last_published_id = Some(floor);
        Ok(())
    }

    /// The fast-forward coverage floor (pre-canonical prefix head).
    pub fn consumed_floor(&self) -> Option<u64> {
        self.consumed_floor
    }

    /// Emits every buffered ID that has become final (used at the replay
    /// terminal, when every lane stream is exhausted).
    pub fn flush(&mut self) -> Result<TradeUnionDisposition> {
        self.drain()
    }

    /// Emits every buffered ID that is below the live watermark.  When no
    /// live lane remains (every stream is exhausted), everything buffered is
    /// final and publishes in order.
    fn drain(&mut self) -> Result<TradeUnionDisposition> {
        let watermark = match self.emission_watermark() {
            Some(watermark) => watermark,
            None if self.lane_next.is_empty() => u64::MAX,
            None => return Ok(TradeUnionDisposition::Buffered),
        };
        let mut batch = Vec::new();
        let mut inserted_identity = false;
        while let Some((&id, _)) = self.buffer.iter().next() {
            if id >= watermark {
                break;
            }
            let entry = self.buffer.remove(&id).expect("entry just seen");
            if self.last_published_id.is_some_and(|last| id <= last) {
                return Err("trade union emission order regressed".to_owned());
            }
            self.last_published_id = Some(id);
            // Retain the published identity (bounded): later deliveries of
            // this ID are classified against the digest, not the bare ID.
            self.published
                .insert(id, entry.observation.observation_sha256.clone());
            // Persist the same identity durably (ADR-17 B4): the journal
            // stays the source of truth and resume rebuilds any identity the
            // log lost to a crash between the two writes.
            if let Some(log) = self.durable.as_mut() {
                log.insert(id, &entry.observation.observation_sha256)?;
                inserted_identity = true;
            }
            while self.published.len() > PUBLISHED_CAP {
                let oldest = self
                    .published
                    .keys()
                    .next()
                    .copied()
                    .expect("published map is non-empty");
                self.published.remove(&oldest);
            }
            let lane = entry
                .lineages
                .first()
                .map(|(lane, _)| *lane)
                .unwrap_or(CaptureLane::Primary);
            batch.push((lane, entry.observation));
        }
        if inserted_identity {
            // One sync per publication batch: the header count commits every
            // inserted record durably, so the journal append and the durable
            // identity share the same publication boundary.
            self.durable
                .as_mut()
                .expect("identity log just inserted")
                .sync()?;
        }
        if batch.is_empty() {
            Ok(TradeUnionDisposition::Buffered)
        } else {
            Ok(TradeUnionDisposition::Publishable(batch))
        }
    }
}

/// Depth publication frontier classification (ADR-16 fix): the next publish
/// must be validated against the canonical cursor BEFORE anything persists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepthFrontierDisposition {
    /// `first == expected`: the canonical sequence continues exactly.
    Contiguous,
    /// `first > expected`: updates are missing from this lane; a switch or a
    /// typed gap is required, never a silent publication.
    Missing { expected: u64, first: u64 },
    /// `first < expected <= final`: a legal Binance straddle; only legal as a
    /// post-bootstrap first frame, where the book state comes from a fresh
    /// snapshot instead of the canonical continuation.
    Straddle {
        expected: u64,
        first: u64,
        final_sequence: u64,
    },
    /// `final < expected`: the event is fully covered already.
    Covered { expected: u64, final_sequence: u64 },
}

/// Classifies one depth observation against the canonical next-expected
/// update ID.  `expected` is `None` right after a typed gap/bootstrapping,
/// where the next frame starts a fresh book from the activated snapshot.
pub fn classify_depth_frontier(
    expected: Option<u64>,
    first: u64,
    final_sequence: u64,
) -> Result<DepthFrontierDisposition> {
    if first == 0 || final_sequence < first {
        return Err("depth observation carries an invalid update-ID range".to_owned());
    }
    let Some(expected) = expected else {
        return Ok(DepthFrontierDisposition::Straddle {
            expected: 0,
            first,
            final_sequence,
        });
    };
    if first == expected {
        Ok(DepthFrontierDisposition::Contiguous)
    } else if first > expected {
        Ok(DepthFrontierDisposition::Missing { expected, first })
    } else if expected <= final_sequence {
        Ok(DepthFrontierDisposition::Straddle {
            expected,
            first,
            final_sequence,
        })
    } else {
        Ok(DepthFrontierDisposition::Covered {
            expected,
            final_sequence,
        })
    }
}

/// Bounded pending-queue trimming that can never discard un-published data:
/// only entries at or below the canonical position (duplicates) are dropped.
pub fn trim_pending_depth(
    pending: &mut std::collections::VecDeque<CanonicalObservationV1>,
    canonical_final: u64,
) {
    while pending
        .front()
        .is_some_and(|observation| observation.final_sequence <= canonical_final)
    {
        pending.pop_front();
    }
}

/// Geometric coverage of the canonical next-expected depth update ID by a
/// candidate sibling frame window `[U, u]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepthWindowCoverage {
    /// `U <= expected <= u`: the sibling holds the exact next update.
    Covers,
    /// `u < expected`: the sibling is behind the canonical position.
    Behind,
    /// `U > expected`: the sibling starts after the canonical position, so
    /// the canonical update is missing from the sibling too.
    Missing,
}

pub fn evaluate_depth_window_coverage(
    canonical_next_expected: u64,
    sibling_first_sequence: u64,
    sibling_final_sequence: u64,
) -> Result<DepthWindowCoverage> {
    if sibling_first_sequence == 0
        || sibling_final_sequence < sibling_first_sequence
        || sibling_final_sequence == 0
    {
        return Err("sibling depth window carries an invalid update-ID range".to_owned());
    }
    if canonical_next_expected == 0 {
        return Err("canonical next-expected update ID is not initialized".to_owned());
    }
    if sibling_final_sequence < canonical_next_expected {
        return Ok(DepthWindowCoverage::Behind);
    }
    if sibling_first_sequence > canonical_next_expected {
        return Ok(DepthWindowCoverage::Missing);
    }
    Ok(DepthWindowCoverage::Covers)
}

/// Final depth lane-switch decision.  A proven switch requires BOTH geometric
/// coverage and exact reconstructed-book convergence; anything less is a
/// typed gap (the dual-loss boundary) and never a silent bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DepthSwitchOutcome {
    ProvenSwitch,
    GapRequired,
}

pub fn decide_depth_switch(
    coverage: DepthWindowCoverage,
    digests_converge: bool,
) -> DepthSwitchOutcome {
    match (coverage, digests_converge) {
        (DepthWindowCoverage::Covers, true) => DepthSwitchOutcome::ProvenSwitch,
        _ => DepthSwitchOutcome::GapRequired,
    }
}

/// Canonical live journal record body (hash-chained, fsynced JSONL).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveArbitrationJournalBodyV1 {
    pub schema: String,
    pub record_index: u64,
    pub wall_ns: u64,
    pub mono_ns: u64,
    pub channel: String,
    pub payload: Value,
    pub previous_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveArbitrationJournalEnvelopeV1 {
    pub body: LiveArbitrationJournalBodyV1,
    pub record_sha256: String,
}

const JOURNAL_SCHEMA: &str = "LiveArbitrationJournalRecordV1";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn unix_ns() -> Result<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| format!("system time before epoch: {error}"))?
            .as_nanos(),
    )
    .map_err(|_| "wall time overflow".to_owned())
}

/// Append-only canonical live journal with the project's exact durability
/// discipline: create-only, full write + flush + `sync_all`, chained SHA-256.
pub struct LiveArbitrationJournalWriter {
    file: File,
    next_index: u64,
    previous: String,
}

impl LiveArbitrationJournalWriter {
    pub fn create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create arbitration output parent: {error}"))?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        Ok(Self {
            file,
            next_index: 0,
            previous: ZERO_DIGEST.to_owned(),
        })
    }

    pub fn append(&mut self, mono_ns: u64, channel: &str, payload: Value) -> Result<String> {
        let body = LiveArbitrationJournalBodyV1 {
            schema: JOURNAL_SCHEMA.to_owned(),
            record_index: self.next_index,
            wall_ns: unix_ns()?,
            mono_ns,
            channel: channel.to_owned(),
            payload,
            previous_record_sha256: self.previous.clone(),
        };
        let digest = sha256_hex(
            &serde_json::to_vec(&body)
                .map_err(|error| format!("serialize arbitration journal body: {error}"))?,
        );
        let envelope = LiveArbitrationJournalEnvelopeV1 {
            body,
            record_sha256: digest.clone(),
        };
        let mut bytes = serde_json::to_vec(&envelope)
            .map_err(|error| format!("serialize arbitration journal record: {error}"))?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_all())
            .map_err(|error| format!("sync arbitration journal: {error}"))?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| "arbitration journal index overflow".to_owned())?;
        self.previous = digest.clone();
        Ok(digest)
    }

    pub fn records(&self) -> u64 {
        self.next_index
    }

    pub fn digest(&self) -> &str {
        &self.previous
    }
}

/// Independent scan of a canonical live journal: exact hash chain, schemas
/// and a strict sequence/dedup audit over the published observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LiveArbitrationScanV1 {
    pub records: u64,
    pub observations: u64,
    pub trades: u64,
    pub depth_frames: u64,
    pub gaps: u64,
    pub late_corrections: u64,
    pub rebootstrap: u64,
    pub status_records: u64,
    pub last_record_sha256: String,
    pub last_trade_id: Option<u64>,
    pub last_depth_sequence: Option<u64>,
    /// Distinct published trade identities retained by the audit.
    pub published_trades: u64,
    /// Declared canonical trade floor (fast-forward prefix head); `None`
    /// when the journal did not declare one (legacy/replay journals).
    pub trade_floor: Option<u64>,
    pub symbol: Option<String>,
    /// Number of journal segment files walked (1 for a single file).
    pub segments: u64,
    /// True only when an actual terminal record was validated in this prefix.
    pub terminal_seen: bool,
}

/// Shared audit state carried across a whole journal walk (one file or a
/// resume-chained set of files).
#[derive(Default)]
struct JournalAuditState {
    previous: String,
    observations: u64,
    trades: u64,
    depth_frames: u64,
    gaps: u64,
    late_corrections: u64,
    rebootstrap: u64,
    status_records: u64,
    records: u64,
    last_trade_id: Option<u64>,
    last_depth_sequence: Option<u64>,
    exact_next_depth: Option<u64>,
    published: std::collections::BTreeMap<u64, String>,
    corrected: std::collections::BTreeMap<u64, String>,
    started_seen: bool,
    terminal_seen: bool,
    trade_floor: Option<u64>,
    symbol: Option<String>,
    segments: u64,
    /// Last record SHA-256 of the previous segment (resume chaining).
    last_segment_sha: Option<String>,
    /// Torn tail bytes of the previous segment (crash recovery evidence:
    /// tolerated only when the next segment's ARBITRATION_RESUMED declares
    /// exactly those bytes).
    last_segment_tail: u64,
    /// A tail audit supplies the chain context up front: the RESUMED
    /// record's own declarations are taken as the context instead of being
    /// compared against a measured previous segment.
    preset_context: bool,
    /// A tail audit accepts the first depth frame of the segment without a
    /// cross-segment continuity check (the full set audit enforces it at
    /// the terminal); later frames keep the in-segment checks.
    tail_depth_seeded: bool,
}

fn payload_hex64<'a>(payload: &'a Value, field: &str, record: &str) -> Result<&'a str> {
    let value = payload
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{record} lacks {field}"))?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{record} carries a non-hex-SHA-256 {field}"));
    }
    Ok(value)
}

/// Processes one parsed envelope against the audit state.
/// `first_of_file` is true for record index 0 of the current file.
fn apply_audit_record(
    state: &mut JournalAuditState,
    envelope: &LiveArbitrationJournalEnvelopeV1,
    file_index: u64,
    first_of_file: bool,
) -> Result<()> {
    let body_bytes = serde_json::to_vec(&envelope.body)
        .map_err(|error| format!("serialize scanned arbitration journal body: {error}"))?;
    let digest = sha256_hex(&body_bytes);
    if envelope.body.schema != JOURNAL_SCHEMA
        || envelope.body.record_index != file_index
        || envelope.body.channel != "LIVE"
        || envelope.body.previous_record_sha256 != state.previous
        || envelope.record_sha256 != digest
    {
        return Err("arbitration journal hash chain is invalid".to_owned());
    }
    if state.terminal_seen {
        return Err("arbitration journal carries records after its terminal".to_owned());
    }
    let event = envelope
        .body
        .payload
        .get("event")
        .and_then(Value::as_str)
        .ok_or_else(|| "arbitration journal record lacks an event".to_owned())?;
    match event {
        "ARBITRATION_STARTED" => {
            if !first_of_file || state.segments != 0 {
                return Err(
                    "arbitration journal does not begin with ARBITRATION_STARTED".to_owned(),
                );
            }
            let symbol = envelope
                .body
                .payload
                .get("symbol")
                .and_then(Value::as_str)
                .ok_or_else(|| "ARBITRATION_STARTED lacks its symbol".to_owned())?;
            state.symbol = Some(symbol.to_owned());
            // The declared canonical trade floor (fast-forward prefix head)
            // bounds the verifier's oracle window on the raw union; legacy
            // journals without the field default to floor 0.
            state.trade_floor = envelope
                .body
                .payload
                .get("trade_floor")
                .and_then(Value::as_u64);
            state.started_seen = true;
        }
        "ARBITRATION_RESUMED" => {
            if !first_of_file || state.segments == 0 {
                return Err("ARBITRATION_RESUMED must open a later journal segment".to_owned());
            }
            if !state.started_seen {
                return Err("ARBITRATION_RESUMED lacks its ARBITRATION_STARTED segment".to_owned());
            }
            let symbol = envelope
                .body
                .payload
                .get("symbol")
                .and_then(Value::as_str)
                .ok_or_else(|| "ARBITRATION_RESUMED lacks its symbol".to_owned())?;
            if state.preset_context {
                // Tail audit: the record's own declarations are the context.
                state.symbol = Some(symbol.to_owned());
            } else if state.symbol.as_deref() != Some(symbol) {
                return Err("ARBITRATION_RESUMED changes the journal symbol".to_owned());
            }
            let previous_journal_sha256 = payload_hex64(
                &envelope.body.payload,
                "previous_journal_sha256",
                "ARBITRATION_RESUMED",
            )?;
            let chained = state
                .last_segment_sha
                .as_deref()
                .ok_or_else(|| "ARBITRATION_RESUMED has no previous segment to chain".to_owned())?;
            if previous_journal_sha256 != chained {
                return Err(format!(
                    "ARBITRATION_RESUMED does not chain the previous journal segment: declared {previous_journal_sha256}, previous {chained}"
                ));
            }
            let floor = envelope
                .body
                .payload
                .get("trade_floor")
                .and_then(Value::as_u64)
                .ok_or_else(|| "ARBITRATION_RESUMED lacks its trade_floor".to_owned())?;
            // The previous segment's effective trade floor is the maximum of
            // its declared bind floor and its last published trade: a crash
            // before the first trade publication must not drop the STARTED
            // fast-forward boundary (fault-gate defect hrs-7c9c792ca38c).
            let expected_floor = state
                .trade_floor
                .unwrap_or(0)
                .max(state.last_trade_id.unwrap_or(0));
            if floor != expected_floor {
                return Err(format!(
                    "ARBITRATION_RESUMED trade floor {floor} does not equal the previous segment's effective trade floor {expected_floor}"
                ));
            }
            if envelope
                .body
                .payload
                .get("mode")
                .and_then(Value::as_str)
                .is_none()
            {
                return Err("ARBITRATION_RESUMED lacks its mode".to_owned());
            }
            // Crash recovery evidence: a previous segment that ended with a
            // torn tail must declare exactly those bytes; a clean previous
            // segment must declare none.  A tail audit takes the record's
            // own declaration as its context.
            let declared_tail = envelope
                .body
                .payload
                .get("previous_tail_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if !state.preset_context && declared_tail != state.last_segment_tail {
                return Err(format!(
                    "ARBITRATION_RESUMED previous_tail_bytes {declared_tail} does not match the measured torn tail {}",
                    state.last_segment_tail
                ));
            }
            if state.preset_context {
                state.last_segment_tail = declared_tail;
            }
        }
        "ARBITRATION_TERMINAL" => {
            if !state.started_seen {
                return Err("arbitration journal has no ARBITRATION_STARTED".to_owned());
            }
            let status = envelope
                .body
                .payload
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| "ARBITRATION_TERMINAL lacks its status".to_owned())?;
            if status != "COMPLETE" {
                return Err(format!(
                    "arbitration journal terminal status is not COMPLETE: {status}"
                ));
            }
            let declared = (
                envelope.body.payload.get("trades").and_then(Value::as_u64),
                envelope
                    .body
                    .payload
                    .get("depth_frames")
                    .and_then(Value::as_u64),
                envelope.body.payload.get("gaps").and_then(Value::as_u64),
                envelope
                    .body
                    .payload
                    .get("late_corrections")
                    .and_then(Value::as_u64),
            );
            if !state.preset_context
                && declared
                    != (
                        Some(state.trades),
                        Some(state.depth_frames),
                        Some(state.gaps),
                        Some(state.late_corrections),
                    )
            {
                return Err(format!(
                    "arbitration journal terminal counters do not match the audit: declared {declared:?}, audited trades={} depth={} gaps={} late_corrections={}",
                    state.trades, state.depth_frames, state.gaps, state.late_corrections
                ));
            }
            // Tail audits carry the segment-local counters while the
            // terminal declares the CUMULATIVE chain counters: the equality
            // is enforced by the full-set audit at the service terminal.
            state.terminal_seen = true;
        }
        "TRADE_OBSERVATION" => {
            let id = envelope
                .body
                .payload
                .get("trade_id")
                .and_then(Value::as_u64)
                .ok_or_else(|| "trade observation lacks an exact trade ID".to_owned())?;
            let observation_sha256 = payload_hex64(
                &envelope.body.payload,
                "observation_sha256",
                "trade observation",
            )?;
            let _record_sha256 =
                payload_hex64(&envelope.body.payload, "record_sha256", "trade observation")?;
            if state.last_trade_id.is_some_and(|last| id <= last) {
                return Err("arbitration journal trade IDs are not strictly increasing".to_owned());
            }
            if state.trade_floor.is_some_and(|floor| id <= floor) {
                return Err(
                    "arbitration journal publishes a trade at or below its declared floor"
                        .to_owned(),
                );
            }
            state.last_trade_id = Some(id);
            state.published.insert(id, observation_sha256.to_owned());
            state.trades += 1;
            state.observations += 1;
        }
        "TRADE_LATE_CORRECTION" => {
            let id = envelope
                .body
                .payload
                .get("trade_id")
                .and_then(Value::as_u64)
                .ok_or_else(|| "trade late correction lacks an exact trade ID".to_owned())?;
            // A correction is the arbiter's typed claim that this ID was
            // already published: it must be at or below the canonical
            // position (an equal ID is the sibling's duplicate of the
            // most recent publication) and must carry its classification.
            if state.last_trade_id.is_none_or(|last| id > last) {
                return Err("trade late correction is not below the canonical position".to_owned());
            }
            if !state.preset_context && state.trade_floor.is_some_and(|floor| id <= floor) {
                return Err("trade late correction is at or below the startup floor".to_owned());
            }
            let kind = envelope.body.payload.get("kind").and_then(Value::as_str);
            let observation_sha256 = payload_hex64(
                &envelope.body.payload,
                "observation_sha256",
                "trade late correction",
            )?;
            match kind {
                Some("duplicate") => {
                    // The identical duplicate must match the published
                    // identity of the same ID (ADR-17 B5: corrections are
                    // materialized against the retained identity, never
                    // accepted by an ID bound alone).
                    match state
                        .published
                        .get(&id)
                        .or_else(|| state.corrected.get(&id))
                    {
                        Some(published_digest) if published_digest == observation_sha256 => {}
                        Some(_) => {
                            return Err(
                                "trade late correction kind=duplicate contradicts the published identity"
                                    .to_owned(),
                            );
                        }
                        None => {
                            return Err(
                                "trade late correction kind=duplicate references an unpublished identity"
                                    .to_owned(),
                            );
                        }
                    }
                }
                Some("unknown") => {
                    // `unknown` is the honest claim that the ID was never
                    // published: it must not exist in the published set (a
                    // retained identity would have classified it as
                    // duplicate or conflict).
                    if state.published.contains_key(&id) || state.corrected.contains_key(&id) {
                        return Err(
                            "trade late correction kind=unknown contradicts the published identity"
                                .to_owned(),
                        );
                    }
                    state.corrected.insert(id, observation_sha256.to_owned());
                }
                _ => {
                    // Schema compatibility policy (ADR-17 B5): corrections
                    // without a known classification are REJECTED, never
                    // silently reinterpreted; legacy journals lacking the
                    // field fail closed the same way.
                    return Err("trade late correction lacks its classification".to_owned());
                }
            }
            state.late_corrections += 1;
        }
        "TRADE_LAG" => {
            if envelope
                .body
                .payload
                .get("buffered")
                .and_then(Value::as_u64)
                .is_none()
            {
                return Err("TRADE_LAG lacks its buffered count".to_owned());
            }
            state.status_records += 1;
        }
        "TRADE_CONFLICT" => {
            if envelope
                .body
                .payload
                .get("trade_id")
                .and_then(Value::as_u64)
                .is_none()
            {
                return Err("TRADE_CONFLICT lacks its trade ID".to_owned());
            }
            state.status_records += 1;
        }
        "DEPTH_OBSERVATION" => {
            let first = envelope
                .body
                .payload
                .get("first_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| "depth observation lacks first_sequence".to_owned())?;
            let final_sequence = envelope
                .body
                .payload
                .get("final_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| "depth observation lacks final_sequence".to_owned())?;
            if first == 0 || final_sequence < first {
                return Err("arbitration journal depth range is invalid".to_owned());
            }
            let _lane = envelope
                .body
                .payload
                .get("lane")
                .and_then(Value::as_str)
                .ok_or_else(|| "depth observation lacks its lane".to_owned())?;
            let _observation_sha256 = payload_hex64(
                &envelope.body.payload,
                "observation_sha256",
                "depth observation",
            )?;
            let _record_sha256 =
                payload_hex64(&envelope.body.payload, "record_sha256", "depth observation")?;
            match state.exact_next_depth {
                Some(expected) if first != expected => {
                    return Err(
                        "arbitration journal depth ranges are not exactly contiguous".to_owned(),
                    );
                }
                None if (!state.preset_context || state.tail_depth_seeded)
                    && state.last_depth_sequence.is_some_and(|last| first <= last) =>
                {
                    return Err(
                        "arbitration journal depth ranges regress outside a typed gap".to_owned(),
                    );
                }
                _ => {}
            }
            state.tail_depth_seeded = true;
            state.exact_next_depth = Some(final_sequence.saturating_add(1));
            state.last_depth_sequence = Some(final_sequence);
            state.depth_frames += 1;
            state.observations += 1;
        }
        "GAP" => {
            let declared_last = envelope
                .body
                .payload
                .get("canonical_last_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| "arbitration gap lacks its canonical boundary".to_owned())?;
            if state.preset_context {
                // The boundary references the previous segment's cursor,
                // which the tail audit does not carry: the record's own
                // declaration is the context (the full set audit enforces
                // the cross-segment equality at the terminal).
                state.last_depth_sequence = Some(declared_last);
                state.tail_depth_seeded = false;
            } else if declared_last != state.last_depth_sequence.unwrap_or(0) {
                return Err(format!(
                    "arbitration gap boundary {declared_last} does not equal the canonical cursor {}",
                    state.last_depth_sequence.unwrap_or(0)
                ));
            }
            state.exact_next_depth = None;
            state.gaps += 1;
        }
        "DEPTH_REBOOTSTRAP" => {
            if state.gaps == 0 || state.exact_next_depth.is_some() {
                return Err("DEPTH_REBOOTSTRAP must follow a typed gap".to_owned());
            }
            for field in [
                "generation",
                "snapshot_record_sha256",
                "snapshot_last_update_id",
            ] {
                if envelope.body.payload.get(field).is_none() {
                    return Err(format!("DEPTH_REBOOTSTRAP lacks {field}"));
                }
            }
            state.rebootstrap += 1;
            state.status_records += 1;
        }
        "DEPTH_SWITCH_PROVEN" => {
            state.status_records += 1;
        }
        other => {
            return Err(format!(
                "arbitration journal carries an unknown event: {other}"
            ));
        }
    }
    state.previous = digest;
    state.records += 1;
    Ok(())
}

/// Walks one journal segment file, carrying the shared audit state across
/// resume-chained segments.  Returns `(clean_eof, tail_bytes)`.
/// Walks one journal segment file against the shared audit state.
/// `tolerate_tail` accepts a torn final line on a NON-final segment of a
/// resume-chained set (crash recovery evidence: the next segment's
/// ARBITRATION_RESUMED must declare exactly those bytes).
fn walk_audit_file(
    path: &Path,
    incremental: bool,
    state: &mut JournalAuditState,
    tolerate_tail: bool,
) -> Result<(bool, u64)> {
    walk_audit_file_with_context(path, incremental, state, tolerate_tail, false)
}

/// `preserve_context`: a tail audit supplies the previous-segment chain
/// context up front (bounded per-epoch verification); the walk must not
/// overwrite it with the empty in-process state.
fn walk_audit_file_with_context(
    path: &Path,
    incremental: bool,
    state: &mut JournalAuditState,
    tolerate_tail: bool,
    preserve_context: bool,
) -> Result<(bool, u64)> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    // Every segment file is its own record hash chain rooted at the zero
    // digest; resume-chained segments link through ARBITRATION_RESUMED.
    if state.segments > 0 && !preserve_context {
        state.last_segment_sha = Some(state.previous.clone());
    }
    state.previous = ZERO_DIGEST.to_owned();
    // A terminal closes its own segment file (it must be the last record of
    // that file); a resumed continuation segment opens a fresh one.
    state.terminal_seen = false;
    let mut lines = BufReader::new(file);
    let mut buf: Vec<u8> = Vec::new();
    let mut file_index = 0_u64;
    let mut tail_bytes = 0_u64;
    let mut clean_eof = true;
    loop {
        buf.clear();
        let read = lines
            .read_until(b'\n', &mut buf)
            .map_err(|error| format!("read arbitration journal: {error}"))?;
        if read == 0 {
            break;
        }
        let has_newline = buf.last() == Some(&b'\n');
        let line = if has_newline {
            &buf[..read - 1]
        } else {
            &buf[..read]
        };
        if !has_newline {
            // Partial final line (no trailing newline): tolerated by the
            // incremental auditor and by resume-chained NON-final segments;
            // it must not parse as a record.
            if incremental || tolerate_tail {
                tail_bytes = line.len() as u64;
                clean_eof = false;
                break;
            }
            return Err("arbitration journal ends with a partial tail".to_owned());
        }
        if line.is_empty() {
            continue;
        }
        if line.len() as u64 > MAX_RECORD_BYTES {
            return Err("arbitration journal record exceeds its bound".to_owned());
        }
        let envelope: LiveArbitrationJournalEnvelopeV1 = serde_json::from_slice(line)
            .map_err(|error| format!("invalid arbitration journal JSON: {error}"))?;
        apply_audit_record(state, &envelope, file_index, file_index == 0)?;
        file_index += 1;
    }
    if file_index == 0 {
        return Err("arbitration journal is empty".to_owned());
    }
    state.segments += 1;
    state.last_segment_tail = tail_bytes;
    Ok((clean_eof, tail_bytes))
}

fn finish_audit(state: &JournalAuditState, incremental: bool) -> Result<LiveArbitrationScanV1> {
    if !state.started_seen {
        return Err("arbitration journal lacks ARBITRATION_STARTED".to_owned());
    }
    if !incremental && !state.terminal_seen {
        return Err("arbitration journal lacks a terminal record".to_owned());
    }
    Ok(LiveArbitrationScanV1 {
        records: state.records,
        observations: state.observations,
        trades: state.trades,
        depth_frames: state.depth_frames,
        gaps: state.gaps,
        late_corrections: state.late_corrections,
        rebootstrap: state.rebootstrap,
        status_records: state.status_records,
        last_record_sha256: state.previous.clone(),
        last_trade_id: state.last_trade_id,
        last_depth_sequence: state.last_depth_sequence,
        published_trades: state.published.len() as u64,
        trade_floor: state.trade_floor,
        symbol: state.symbol.clone(),
        segments: state.segments,
        terminal_seen: state.terminal_seen,
    })
}

/// Strict closed-journal audit (ADR-16 verification fix, ADR-17 B5 rules): a
/// unique `ARBITRATION_STARTED` must open the journal, a unique
/// `ARBITRATION_TERMINAL` must close it as the very last record with
/// counters exactly equal to the recalculated ones (including
/// `late_corrections`), a `GAP` must declare the actual canonical cursor,
/// every trade observation must carry its raw lineage digests, corrections
/// are validated against the retained published identity, and no observation
/// may follow the terminal.
pub fn scan_live_arbitration_journal(path: &Path) -> Result<LiveArbitrationScanV1> {
    let mut state = JournalAuditState::default();
    let (clean_eof, tail_bytes) = walk_audit_file(path, false, &mut state, false)?;
    if !clean_eof {
        return Err(format!(
            "arbitration journal ends with a partial tail ({tail_bytes} bytes)"
        ));
    }
    finish_audit(&state, false)
}

/// Live prefix audit: the same walk without requiring the terminal record.
/// A partial final line is reported, not rejected: the prefix through the
/// last complete record is hash-chain verified.
pub fn scan_live_arbitration_journal_incremental(
    path: &Path,
) -> Result<(LiveArbitrationScanV1, bool, u64)> {
    let mut state = JournalAuditState::default();
    let (clean_eof, tail_bytes) = walk_audit_file(path, true, &mut state, true)?;
    let scan = finish_audit(&state, true)?;
    Ok((scan, clean_eof, tail_bytes))
}

/// Closed audit of a resume-chained journal SET (ADR-17 continuous
/// operation): the first segment opens with `ARBITRATION_STARTED`, every
/// later segment opens with `ARBITRATION_RESUMED` chaining the previous
/// segment's last record SHA-256 and declaring the exact trade floor, trade
/// IDs increase strictly across segments, the depth sequence continues
/// contiguously across segment boundaries unless a typed GAP follows, and
/// every segment's terminal counters equal the cumulative audit at that
/// point.  The final segment must carry the terminal and a clean tail;
/// non-final segments may end with a torn tail (crash recovery) ONLY when
/// the next segment's ARBITRATION_RESUMED declares exactly those bytes.
pub fn scan_live_arbitration_journal_set(paths: &[PathBuf]) -> Result<LiveArbitrationScanV1> {
    if paths.is_empty() {
        return Err("arbitration journal set is empty".to_owned());
    }
    let mut state = JournalAuditState::default();
    let last = paths.len() - 1;
    for (index, path) in paths.iter().enumerate() {
        let tolerate_tail = index < last;
        let (clean_eof, tail_bytes) = walk_audit_file(path, false, &mut state, tolerate_tail)?;
        if !clean_eof && !tolerate_tail {
            return Err(format!(
                "arbitration journal segment {} ends with a partial tail ({tail_bytes} bytes)",
                path.display()
            ));
        }
    }
    finish_audit(&state, false)
}

/// Audits a live resume-chained prefix from STARTED, preserving publication
/// and correction identities across segments. Torn predecessor tails are
/// accepted only when the next RESUMED declares the exact measured bytes.
/// The returned clean/tail values describe the final segment; they do not
/// imply a terminal, an immutable input set or exhaustive raw coverage.
pub fn scan_live_arbitration_journal_set_incremental(
    paths: &[PathBuf],
) -> Result<(LiveArbitrationScanV1, bool, u64)> {
    if paths.is_empty() {
        return Err("arbitration journal set is empty".to_owned());
    }
    let mut state = JournalAuditState::default();
    let mut final_tail = (true, 0);
    for path in paths {
        final_tail = walk_audit_file(path, true, &mut state, true)?;
    }
    Ok((finish_audit(&state, true)?, final_tail.0, final_tail.1))
}

/// Closed audit of ONE resume-chained tail segment with a supplied chain
/// context (ADR-17 bounded per-epoch verification): the segment must open
/// with `ARBITRATION_RESUMED` chaining `previous_segment_sha256` and
/// declaring the exact `trade_floor`; its counters and sequences are
/// audited cumulatively from that context without re-reading the previous
/// segments (the structural set audit runs once at the service terminal).
pub fn scan_live_arbitration_journal_tail(
    path: &Path,
    previous_segment_sha256: &str,
    trade_floor: u64,
) -> Result<LiveArbitrationScanV1> {
    let mut state = JournalAuditState {
        segments: 1,
        started_seen: true,
        preset_context: true,
        last_segment_sha: Some(previous_segment_sha256.to_owned()),
        last_trade_id: Some(trade_floor),
        trade_floor: Some(trade_floor),
        ..JournalAuditState::default()
    };
    let (clean_eof, tail_bytes) =
        walk_audit_file_with_context(path, false, &mut state, false, true)?;
    if !clean_eof {
        return Err(format!(
            "arbitration journal tail segment ends with a partial tail ({tail_bytes} bytes)"
        ));
    }
    finish_audit(&state, false)
}

/// Live-prefix audit of ONE active resume-chained tail segment with a
/// supplied chain context (ADR-17 bounded in-operation audits): the terminal
/// is not required and a torn final line is reported instead of rejected.
pub fn scan_live_arbitration_journal_tail_incremental(
    path: &Path,
    previous_segment_sha256: &str,
    trade_floor: u64,
) -> Result<(LiveArbitrationScanV1, bool, u64)> {
    let mut state = JournalAuditState {
        segments: 1,
        started_seen: true,
        preset_context: true,
        last_segment_sha: Some(previous_segment_sha256.to_owned()),
        last_trade_id: Some(trade_floor),
        trade_floor: Some(trade_floor),
        ..JournalAuditState::default()
    };
    let (clean_eof, tail_bytes) = walk_audit_file_with_context(path, true, &mut state, true, true)?;
    let scan = finish_audit(&state, true)?;
    Ok((scan, clean_eof, tail_bytes))
}

/// Resume recovery scan (ADR-17 B3): the shared set walk with the LAST
/// segment allowed to end with a torn tail (a crash mid-publication).  The
/// arbiter declares the measured torn bytes in the next segment's
/// ARBITRATION_RESUMED; every earlier segment keeps the strict chained
/// contract.
pub fn scan_live_arbitration_journal_set_recovery(
    paths: &[PathBuf],
) -> Result<LiveArbitrationScanV1> {
    if paths.is_empty() {
        return Err("arbitration journal set is empty".to_owned());
    }
    let mut state = JournalAuditState::default();
    let last = paths.len() - 1;
    for (index, path) in paths.iter().enumerate() {
        // The final segment may be torn (crash): tolerated, measured and
        // declared by the resumed generation.  Non-final segments keep the
        // strict declared-tail contract.
        let tolerate_tail = index == last;
        let (_clean_eof, _tail_bytes) =
            walk_audit_file_with_context(path, true, &mut state, tolerate_tail, false)?;
    }
    finish_audit(&state, true)
}

/// Exact event-identity comparison used by the failover oracle: the
/// canonical journal's published trade IDs must equal the untouched lane's
/// materialized trade IDs (zero missing, zero duplicate).
pub fn verify_trade_identity(canonical_ids: &[u64], oracle_ids: &[u64]) -> Result<()> {
    if canonical_ids != oracle_ids {
        return Err(format!(
            "canonical trade stream differs from the sibling oracle: canonical={} oracle={}",
            canonical_ids.len(),
            oracle_ids.len()
        ));
    }
    Ok(())
}

/// Selects the lane label payload value shared by all journal records.
pub fn lane_payload(lane: CaptureLane) -> Value {
    Value::String(lane.as_str().to_owned())
}

/// Portability helper reused by the sidecar and by tests.
pub fn safe_relative_path(root: &Path, full: &Path) -> Result<PathBuf> {
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("resolve arbitration root {}: {error}", root.display()))?;
    let canonical_full = full
        .canonicalize()
        .map_err(|error| format!("resolve arbitration path {}: {error}", full.display()))?;
    canonical_full
        .strip_prefix(&canonical_root)
        .map(PathBuf::from)
        .map_err(|error| format!("arbitration path escapes its root: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trade_observation(id: u64, epoch: &str, frame: u64, digest: &str) -> CanonicalObservationV1 {
        CanonicalObservationV1 {
            symbol: "BTCUSDT".to_owned(),
            stream_kind: BoundaryStreamKind::Trade,
            stream: "btcusdt@trade".to_owned(),
            connection_epoch: epoch.to_owned(),
            frame_index: frame,
            first_sequence: id,
            final_sequence: id,
            record_sha256: format!("r{id:0>63}"),
            observation_sha256: digest.to_owned(),
        }
    }

    fn depth_observation(first: u64, last: u64, epoch: &str, frame: u64) -> CanonicalObservationV1 {
        CanonicalObservationV1 {
            symbol: "BTCUSDT".to_owned(),
            stream_kind: BoundaryStreamKind::Depth,
            stream: "btcusdt@depth@100ms".to_owned(),
            connection_epoch: epoch.to_owned(),
            frame_index: frame,
            first_sequence: first,
            final_sequence: last,
            record_sha256: "c".repeat(64),
            observation_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn trade_union_never_confuses_a_lower_id_with_a_duplicate_t1() {
        // PRIMARY=[100,102], SHADOW=[101,102]: 101 must be published exactly
        // once (the previous arbiter classified it as stale and lost it).
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        assert_eq!(
            union
                .observe(
                    CaptureLane::Primary,
                    &trade_observation(100, "p", 0, "digest-100")
                )
                .unwrap(),
            TradeUnionDisposition::Buffered
        );
        assert_eq!(
            union
                .observe(
                    CaptureLane::Primary,
                    &trade_observation(102, "p", 1, "digest-102")
                )
                .unwrap(),
            TradeUnionDisposition::Buffered
        );
        // Shadow delivers 101: the watermark is now min(103, 102) = 102, so
        // 100 and 101 publish together in order.
        match union
            .observe(
                CaptureLane::Shadow,
                &trade_observation(101, "s", 0, "digest-101"),
            )
            .unwrap()
        {
            TradeUnionDisposition::Publishable(batch) => {
                assert_eq!(batch.len(), 2);
                assert_eq!(batch[0].1.final_sequence, 100);
                assert_eq!(batch[1].1.final_sequence, 101);
            }
            other => panic!("expected Publishable, got {other:?}"),
        }
        assert_eq!(union.last_published_id(), Some(101));
        // The shadow's 102 merges with the primary's buffered copy and, since
        // both lanes have now passed 102, it publishes exactly once.
        match union
            .observe(
                CaptureLane::Shadow,
                &trade_observation(102, "s", 1, "digest-102"),
            )
            .unwrap()
        {
            TradeUnionDisposition::Publishable(batch) => {
                assert_eq!(batch.len(), 1);
                assert_eq!(batch[0].1.final_sequence, 102);
            }
            other => panic!("expected Publishable, got {other:?}"),
        }
        assert_eq!(union.last_published_id(), Some(102));
    }

    #[test]
    fn trade_union_fast_forward_never_publishes_precanonical_history() {
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        union
            .fast_forward(
                CaptureLane::Primary,
                &trade_observation(100, "p", 0, "d100"),
            )
            .unwrap();
        union
            .fast_forward(
                CaptureLane::Primary,
                &trade_observation(102, "p", 1, "d102"),
            )
            .unwrap();
        union
            .fast_forward(CaptureLane::Shadow, &trade_observation(101, "s", 0, "d101"))
            .unwrap();
        assert_eq!(union.watermark(), Some(102));
        // History re-delivered later is silently outside the canonical window.
        assert_eq!(
            union
                .observe(CaptureLane::Shadow, &trade_observation(101, "s", 1, "d101"))
                .unwrap(),
            TradeUnionDisposition::Buffered
        );
        assert_eq!(union.last_published_id(), None);
        // New trades flow normally.
        assert_eq!(
            union
                .observe(
                    CaptureLane::Primary,
                    &trade_observation(103, "p", 2, "d103")
                )
                .unwrap(),
            TradeUnionDisposition::Buffered
        );
        match union
            .observe(CaptureLane::Shadow, &trade_observation(103, "s", 2, "d103"))
            .unwrap()
        {
            TradeUnionDisposition::Publishable(batch) => {
                assert_eq!(batch.len(), 1);
                assert_eq!(batch[0].1.final_sequence, 103);
            }
            other => panic!("expected Publishable, got {other:?}"),
        }
    }

    #[test]
    fn trade_union_excluded_lane_surfaces_late_deliveries_as_corrections_t2() {
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        union
            .observe(
                CaptureLane::Primary,
                &trade_observation(100, "p", 0, "d100"),
            )
            .unwrap();
        union
            .observe(CaptureLane::Shadow, &trade_observation(100, "s", 0, "d100"))
            .unwrap();
        union
            .observe(
                CaptureLane::Primary,
                &trade_observation(101, "p", 1, "d101"),
            )
            .unwrap();
        union
            .observe(CaptureLane::Shadow, &trade_observation(101, "s", 1, "d101"))
            .unwrap();
        assert_eq!(union.last_published_id(), Some(101));
        // Shadow exceeds the lag bound: excluded from the watermark.
        union.exclude_lane(CaptureLane::Shadow);
        // Primary continues alone.
        match union
            .observe(
                CaptureLane::Primary,
                &trade_observation(102, "p", 2, "d102"),
            )
            .unwrap()
        {
            TradeUnionDisposition::Publishable(batch) => {
                assert_eq!(batch.len(), 1);
                assert_eq!(batch[0].1.final_sequence, 102);
            }
            other => panic!("expected Publishable, got {other:?}"),
        }
        // The excluded lane later delivers 101 again: typed late correction
        // classified as the sibling's identical duplicate.
        assert_eq!(
            union
                .observe(CaptureLane::Shadow, &trade_observation(101, "s", 2, "d101"))
                .unwrap(),
            TradeUnionDisposition::Late {
                observation: trade_observation(101, "s", 2, "d101"),
                kind: LateCorrectionKind::Duplicate,
            }
        );
    }

    #[test]
    fn corrected_identity_is_unique_and_conflicts_after_recovery() {
        let mut union = TradeUnionState::new();
        union.restore_published_floor(450).unwrap();
        union.restore_startup_floor(100);
        let observation = trade_observation(150, "p", 0, "digest150");
        assert!(matches!(
            union.observe(CaptureLane::Primary, &observation).unwrap(),
            TradeUnionDisposition::Late {
                kind: LateCorrectionKind::Unknown,
                ..
            }
        ));
        assert!(matches!(
            union.observe(CaptureLane::Shadow, &observation).unwrap(),
            TradeUnionDisposition::Late {
                kind: LateCorrectionKind::Duplicate,
                ..
            }
        ));
        let mut resumed = TradeUnionState::new();
        resumed.restore_published_floor(450).unwrap();
        resumed.restore_startup_floor(100);
        resumed
            .restore_corrected_identity(150, "digest150".to_owned())
            .unwrap();
        assert!(matches!(
            resumed.observe(CaptureLane::Shadow, &observation).unwrap(),
            TradeUnionDisposition::Late {
                kind: LateCorrectionKind::Duplicate,
                ..
            }
        ));
        assert!(matches!(
            resumed
                .observe(
                    CaptureLane::Shadow,
                    &trade_observation(150, "s", 1, "changed")
                )
                .unwrap(),
            TradeUnionDisposition::Conflict { trade_id: 150, .. }
        ));
        assert_eq!(
            resumed
                .observe(
                    CaptureLane::Primary,
                    &trade_observation(90, "p", 2, "outside")
                )
                .unwrap(),
            TradeUnionDisposition::Buffered
        );
    }

    #[test]
    fn trade_union_detects_post_publish_conflicts_against_retained_identity_b4() {
        // Codex B4 probe: the ID 100 is published after BOTH lanes delivered
        // it with digest-A; a later delivery of the SAME ID with digest-B must
        // be a typed conflict, never a Late/duplicate acceptance.
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        match union
            .observe(
                CaptureLane::Primary,
                &trade_observation(100, "p", 0, "digest-A"),
            )
            .unwrap()
        {
            TradeUnionDisposition::Buffered => {}
            other => panic!("expected Buffered, got {other:?}"),
        }
        match union
            .observe(
                CaptureLane::Shadow,
                &trade_observation(100, "s", 0, "digest-A"),
            )
            .unwrap()
        {
            TradeUnionDisposition::Publishable(batch) => {
                assert_eq!(batch.len(), 1);
                assert_eq!(batch[0].1.final_sequence, 100);
            }
            other => panic!("expected Publishable, got {other:?}"),
        }
        assert_eq!(union.last_published_id(), Some(100));
        // Same ID, contradictory content, AFTER the commit: conflict.
        match union
            .observe(
                CaptureLane::Primary,
                &trade_observation(100, "p", 1, "digest-B"),
            )
            .unwrap()
        {
            TradeUnionDisposition::Conflict {
                trade_id,
                first_digest,
                second_digest,
            } => {
                assert_eq!(trade_id, 100);
                assert_eq!(first_digest, "digest-A");
                assert_eq!(second_digest, "digest-B");
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
        // And the identical duplicate still classifies as a duplicate.
        assert_eq!(
            union
                .observe(
                    CaptureLane::Shadow,
                    &trade_observation(100, "s", 1, "digest-A")
                )
                .unwrap(),
            TradeUnionDisposition::Late {
                observation: trade_observation(100, "s", 1, "digest-A"),
                kind: LateCorrectionKind::Duplicate,
            }
        );
    }

    #[test]
    fn trade_union_rejects_divergent_payloads_for_the_same_id_t3() {
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        union
            .observe(
                CaptureLane::Primary,
                &trade_observation(100, "p", 0, "digest-A"),
            )
            .unwrap();
        match union
            .observe(
                CaptureLane::Shadow,
                &trade_observation(100, "s", 0, "digest-B"),
            )
            .unwrap()
        {
            TradeUnionDisposition::Conflict { trade_id, .. } => assert_eq!(trade_id, 100),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn trade_union_rejects_non_trade_and_range_inputs() {
        let mut union = TradeUnionState::new();
        assert!(
            union
                .observe(CaptureLane::Primary, &depth_observation(1, 2, "p", 0))
                .is_err()
        );
        let mut ranged = trade_observation(5, "p", 0, "d5");
        ranged.final_sequence = 6;
        assert!(union.observe(CaptureLane::Primary, &ranged).is_err());
    }

    #[test]
    fn depth_frontier_classification_is_exact() {
        assert_eq!(
            classify_depth_frontier(Some(5001), 5001, 5010).unwrap(),
            DepthFrontierDisposition::Contiguous
        );
        assert_eq!(
            classify_depth_frontier(Some(5001), 5002, 5010).unwrap(),
            DepthFrontierDisposition::Missing {
                expected: 5001,
                first: 5002
            }
        );
        assert_eq!(
            classify_depth_frontier(Some(5001), 4999, 5010).unwrap(),
            DepthFrontierDisposition::Straddle {
                expected: 5001,
                first: 4999,
                final_sequence: 5010
            }
        );
        assert_eq!(
            classify_depth_frontier(Some(5001), 4999, 5000).unwrap(),
            DepthFrontierDisposition::Covered {
                expected: 5001,
                final_sequence: 5000
            }
        );
        assert_eq!(
            classify_depth_frontier(None, 4999, 5010).unwrap(),
            DepthFrontierDisposition::Straddle {
                expected: 0,
                first: 4999,
                final_sequence: 5010
            }
        );
        assert!(classify_depth_frontier(Some(5001), 0, 5010).is_err());
        assert!(classify_depth_frontier(Some(5001), 5010, 4999).is_err());
    }

    #[test]
    fn pending_trim_never_discards_unpublished_data() {
        let mut pending = std::collections::VecDeque::new();
        for id in 1..=5 {
            pending.push_back(depth_observation(id, id, "p", id));
        }
        trim_pending_depth(&mut pending, 3);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending.front().unwrap().final_sequence, 4);
        trim_pending_depth(&mut pending, 100);
        assert!(pending.is_empty());
    }

    #[test]
    fn depth_window_coverage_is_exact() {
        assert_eq!(
            evaluate_depth_window_coverage(5001, 4999, 5010).unwrap(),
            DepthWindowCoverage::Covers
        );
        assert_eq!(
            evaluate_depth_window_coverage(5001, 5001, 5001).unwrap(),
            DepthWindowCoverage::Covers
        );
        assert_eq!(
            evaluate_depth_window_coverage(5011, 4999, 5010).unwrap(),
            DepthWindowCoverage::Behind
        );
        assert_eq!(
            evaluate_depth_window_coverage(5001, 5002, 5010).unwrap(),
            DepthWindowCoverage::Missing
        );
        assert!(evaluate_depth_window_coverage(5001, 0, 5010).is_err());
        assert!(evaluate_depth_window_coverage(5001, 5010, 4999).is_err());
        assert!(evaluate_depth_window_coverage(0, 5000, 5010).is_err());
    }

    #[test]
    fn depth_switch_requires_coverage_and_convergence() {
        assert_eq!(
            decide_depth_switch(DepthWindowCoverage::Covers, true),
            DepthSwitchOutcome::ProvenSwitch
        );
        // gap-free is not the same as correct: coverage without exact
        // book convergence is a typed gap, never a bridge.
        assert_eq!(
            decide_depth_switch(DepthWindowCoverage::Covers, false),
            DepthSwitchOutcome::GapRequired
        );
        assert_eq!(
            decide_depth_switch(DepthWindowCoverage::Behind, true),
            DepthSwitchOutcome::GapRequired
        );
        assert_eq!(
            decide_depth_switch(DepthWindowCoverage::Missing, true),
            DepthSwitchOutcome::GapRequired
        );
    }

    #[test]
    fn journal_scan_audits_chain_and_strict_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canonical-live.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":10,"lane":"PRIMARY",
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                3,
                "LIVE",
                serde_json::json!({
                    "event":"DEPTH_OBSERVATION","first_sequence":5001,"final_sequence":5010,
                    "lane":"PRIMARY","record_sha256":"c".repeat(64),
                    "observation_sha256":"d".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                4,
                "LIVE",
                serde_json::json!({
                    "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                    "trades":1,"depth_frames":1,"gaps":0,"late_corrections":0
                }),
            )
            .unwrap();
        drop(writer);
        let scan = scan_live_arbitration_journal(&path).unwrap();
        assert_eq!(scan.records, 4);
        assert_eq!(scan.trades, 1);
        assert_eq!(scan.depth_frames, 1);
        assert_eq!(scan.observations, 2);
        assert_eq!(scan.gaps, 0);
        assert_eq!(scan.late_corrections, 0);
        assert_eq!(scan.last_trade_id, Some(10));
        assert_eq!(scan.last_depth_sequence, Some(5010));
        assert_eq!(scan.segments, 1);
    }

    #[test]
    fn journal_scan_rejects_duplicate_and_reordered_observations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canonical-live.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":10,
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                3,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":10,
                    "record_sha256":"c".repeat(64),"observation_sha256":"d".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                4,
                "LIVE",
                serde_json::json!({
                    "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                    "trades":1,"depth_frames":0,"gaps":0,"late_corrections":0
                }),
            )
            .unwrap();
        drop(writer);
        assert!(scan_live_arbitration_journal(&path).is_err());
    }

    #[test]
    fn journal_scan_rejects_lifecycle_mutants_v1() {
        // terminal_only: no ARBITRATION_STARTED.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("terminal-only.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(1, "LIVE", serde_json::json!({"event":"ARBITRATION_TERMINAL","status":"COMPLETE","trades":0,"depth_frames":0,"gaps":0,"late_corrections":0}))
            .unwrap();
        drop(writer);
        assert!(scan_live_arbitration_journal(&path).is_err());

        // data after terminal.
        let path = dir.path().join("data-after.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer.append(2, "LIVE", serde_json::json!({"event":"ARBITRATION_TERMINAL","status":"FAILED","trades":999,"depth_frames":0,"gaps":0,"late_corrections":0})).unwrap();
        writer
            .append(
                3,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":10,
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        drop(writer);
        assert!(scan_live_arbitration_journal(&path).is_err());

        // false gap boundary: declared cursor does not equal the real one.
        let path = dir.path().join("false-gap.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"DEPTH_OBSERVATION","first_sequence":10,"final_sequence":10,
                    "lane":"PRIMARY","record_sha256":"a".repeat(64),
                    "observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                3,
                "LIVE",
                serde_json::json!({"event":"GAP","canonical_last_sequence":999999}),
            )
            .unwrap();
        writer
            .append(
                4,
                "LIVE",
                serde_json::json!({
                    "event":"DEPTH_OBSERVATION","first_sequence":12,"final_sequence":12,
                    "lane":"PRIMARY","record_sha256":"c".repeat(64),
                    "observation_sha256":"d".repeat(64)
                }),
            )
            .unwrap();
        writer.append(5, "LIVE", serde_json::json!({"event":"ARBITRATION_TERMINAL","status":"COMPLETE","trades":0,"depth_frames":2,"gaps":1,"late_corrections":0})).unwrap();
        drop(writer);
        assert!(scan_live_arbitration_journal(&path).is_err());
    }

    #[test]
    fn journal_scan_rejects_terminal_counter_forgeries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forged.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer.append(2, "LIVE", serde_json::json!({"event":"ARBITRATION_TERMINAL","status":"COMPLETE","trades":5,"depth_frames":0,"gaps":0,"late_corrections":0})).unwrap();
        drop(writer);
        assert!(scan_live_arbitration_journal(&path).is_err());
    }

    #[test]
    fn journal_scan_rejects_late_correction_counter_forgeries_b5() {
        // The Codex late-count-forgery scenario: one published trade, one
        // valid duplicate correction, but the terminal declares 999
        // corrections.  The recalculated counter must win (ADR-17 B5).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forged-late.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":100,"lane":"PRIMARY",
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                3,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_LATE_CORRECTION","trade_id":100,"lane":"SHADOW",
                    "record_sha256":"c".repeat(64),"observation_sha256":"b".repeat(64),
                    "kind":"duplicate"
                }),
            )
            .unwrap();
        writer
            .append(
                4,
                "LIVE",
                serde_json::json!({
                    "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                    "trades":1,"depth_frames":0,"gaps":0,"late_corrections":999
                }),
            )
            .unwrap();
        drop(writer);
        assert!(scan_live_arbitration_journal(&path).is_err());
    }

    #[test]
    fn journal_scan_rejects_corrections_that_contradict_the_published_identity_b5() {
        // kind=duplicate with a digest that differs from the published one.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dup-lie.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":100,"lane":"PRIMARY",
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                3,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_LATE_CORRECTION","trade_id":100,"lane":"SHADOW",
                    "record_sha256":"c".repeat(64),"observation_sha256":"d".repeat(64),
                    "kind":"duplicate"
                }),
            )
            .unwrap();
        writer
            .append(
                4,
                "LIVE",
                serde_json::json!({
                    "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                    "trades":1,"depth_frames":0,"gaps":0,"late_corrections":1
                }),
            )
            .unwrap();
        drop(writer);
        assert!(scan_live_arbitration_journal(&path).is_err());

        // kind=unknown for a trade the journal published: contradictory.
        let path = dir.path().join("unknown-lie.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":100,"lane":"PRIMARY",
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                3,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_LATE_CORRECTION","trade_id":100,"lane":"SHADOW",
                    "record_sha256":"c".repeat(64),"observation_sha256":"d".repeat(64),
                    "kind":"unknown"
                }),
            )
            .unwrap();
        writer
            .append(
                4,
                "LIVE",
                serde_json::json!({
                    "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                    "trades":1,"depth_frames":0,"gaps":0,"late_corrections":1
                }),
            )
            .unwrap();
        drop(writer);
        assert!(scan_live_arbitration_journal(&path).is_err());
    }

    #[test]
    fn journal_scan_accepts_repeated_identical_corrections_and_genuine_unknown_b5() {
        // Repeated identical duplicates of the same published trade are
        // legitimate; a genuinely never-published late ID classifies as
        // unknown honestly.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("repeated.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":100,"lane":"PRIMARY",
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        for index in 0..3 {
            writer
                .append(
                    3 + index,
                    "LIVE",
                    serde_json::json!({
                        "event":"TRADE_LATE_CORRECTION","trade_id":100,"lane":"SHADOW",
                        "record_sha256":format!("r{index:0>63}"),
                        "observation_sha256":"b".repeat(64),
                        "kind":"duplicate"
                    }),
                )
                .unwrap();
        }
        // 99 was never published (pre-canonical history): unknown is honest.
        writer
            .append(
                6,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_LATE_CORRECTION","trade_id":99,"lane":"SHADOW",
                    "record_sha256":"z".repeat(64),"observation_sha256":"e".repeat(64),
                    "kind":"unknown"
                }),
            )
            .unwrap();
        writer
            .append(
                7,
                "LIVE",
                serde_json::json!({
                    "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                    "trades":1,"depth_frames":0,"gaps":0,"late_corrections":4
                }),
            )
            .unwrap();
        drop(writer);
        let scan = scan_live_arbitration_journal(&path).unwrap();
        assert_eq!(scan.late_corrections, 4);
        assert_eq!(scan.trades, 1);
    }

    #[test]
    fn incremental_scan_tolerates_a_partial_tail_without_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":10,"lane":"PRIMARY",
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        drop(writer);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b"{\"partial");
        std::fs::write(&path, &bytes).unwrap();
        let (scan, complete, tail) = scan_live_arbitration_journal_incremental(&path).unwrap();
        assert_eq!(scan.trades, 1);
        assert!(!complete);
        assert_eq!(tail, 9);
    }

    #[test]
    fn trade_identity_oracle_demands_exact_event_equality() {
        assert!(verify_trade_identity(&[1, 2, 3], &[1, 2, 3]).is_ok());
        assert!(verify_trade_identity(&[1, 2], &[1, 2, 3]).is_err());
        assert!(verify_trade_identity(&[1, 2, 3], &[1, 2]).is_err());
        assert!(verify_trade_identity(&[1, 2, 3], &[1, 3, 2]).is_err());
    }

    #[test]
    fn lane_payload_uses_the_stable_lane_label() {
        assert_eq!(
            lane_payload(CaptureLane::Primary),
            Value::String("PRIMARY".to_owned())
        );
        assert_eq!(
            lane_payload(CaptureLane::Shadow),
            Value::String("SHADOW".to_owned())
        );
    }

    #[test]
    fn trade_identity_log_persists_and_looks_up_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trade-identity.bin");
        {
            let mut log = TradeIdentityLog::create(&path).unwrap();
            assert_eq!(log.records(), 0);
            log.insert(100, &"b".repeat(64)).unwrap();
            log.insert(65537, &"c".repeat(64)).unwrap();
            assert_eq!(log.lookup(100).unwrap(), Some("b".repeat(64)));
            assert_eq!(log.lookup(65537).unwrap(), Some("c".repeat(64)));
            assert_eq!(log.lookup(101).unwrap(), None);
            log.sync().unwrap();
            log.validate().unwrap();
        }
        // Reopen (restart): the durable identity survives the process.
        let mut reopened = TradeIdentityLog::open(&path).unwrap();
        reopened.validate().unwrap();
        assert_eq!(reopened.records(), 2);
        assert_eq!(reopened.last_id(), Some(65537));
        assert_eq!(reopened.lookup(100).unwrap(), Some("b".repeat(64)));
        assert_eq!(reopened.lookup(65537).unwrap(), Some("c".repeat(64)));
        // Create-only discipline: a second create at the same path must fail.
        assert!(TradeIdentityLog::create(&path).is_err());
    }

    #[test]
    fn trade_identity_log_rejects_regression_and_malformed_digests() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trade-identity.bin");
        let mut log = TradeIdentityLog::create(&path).unwrap();
        log.insert(10, &"a".repeat(64)).unwrap();
        assert!(log.insert(10, &"a".repeat(64)).is_err());
        assert!(log.insert(9, &"a".repeat(64)).is_err());
        assert!(log.insert(11, "not-hex").is_err());
        assert!(log.insert(11, &"a".repeat(63)).is_err());
        assert_eq!(log.records(), 1);
        assert_eq!(log.last_id(), Some(10));
        log.sync().unwrap();
        log.validate().unwrap();
    }

    #[test]
    fn trade_union_resolves_conflict_after_eviction_via_durable_identity_b4() {
        // Codex identity_retention_probe scenario with the durable resolver:
        // publish 100 with digest-A from both lanes; contradict with digest-B
        // -> Conflict; publish 65,536 newer IDs so the in-memory set evicts
        // 100; the durable log (attached after the bulk, pre-populated with
        // 100) must still classify the contradiction as Conflict, and the
        // identical duplicate as Duplicate.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("trade-identity.bin");
        let digest_a = "aa".repeat(32);
        let digest_b = "bb".repeat(32);
        let mut log = TradeIdentityLog::create(&log_path).unwrap();
        log.insert(100, &digest_a).unwrap();
        log.sync().unwrap();
        drop(log);
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        match union
            .observe(
                CaptureLane::Primary,
                &trade_observation(100, "p", 0, &digest_a),
            )
            .unwrap()
        {
            TradeUnionDisposition::Buffered => {}
            other => panic!("expected Buffered, got {other:?}"),
        }
        match union
            .observe(
                CaptureLane::Shadow,
                &trade_observation(100, "s", 0, &digest_a),
            )
            .unwrap()
        {
            TradeUnionDisposition::Publishable(batch) => assert_eq!(batch.len(), 1),
            other => panic!("expected Publishable, got {other:?}"),
        }
        assert!(matches!(
            union
                .observe(
                    CaptureLane::Primary,
                    &trade_observation(100, "p", 1, &digest_b)
                )
                .unwrap(),
            TradeUnionDisposition::Conflict { trade_id: 100, .. }
        ));
        for id in 101..=65_636 {
            let good = trade_observation(id, "p", id, "digest-good");
            union.observe(CaptureLane::Primary, &good).unwrap();
            match union.observe(CaptureLane::Shadow, &good).unwrap() {
                TradeUnionDisposition::Publishable(_) => {}
                other => panic!("expected Publishable for {id}, got {other:?}"),
            }
        }
        // The bounded cache evicted 100; the durable log still answers.
        assert!(!union.published.contains_key(&100));
        union.set_identity_log(TradeIdentityLog::open(&log_path).unwrap());
        assert!(matches!(
            union
                .observe(
                    CaptureLane::Shadow,
                    &trade_observation(100, "s", 1, &digest_b)
                )
                .unwrap(),
            TradeUnionDisposition::Conflict { trade_id: 100, .. }
        ));
        assert!(matches!(
            union
                .observe(
                    CaptureLane::Shadow,
                    &trade_observation(100, "s", 2, &digest_a)
                )
                .unwrap(),
            TradeUnionDisposition::Late {
                kind: LateCorrectionKind::Duplicate,
                ..
            }
        ));
    }

    #[test]
    fn trade_union_resolves_conflict_after_restart_via_durable_identity_b4() {
        // Restart scenario: a fresh union over the same durable log and the
        // restored published floor must still classify the contradiction as
        // a typed conflict, and must never re-publish the restored prefix.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("trade-identity.bin");
        let digest_a = "aa".repeat(32);
        let digest_b = "bb".repeat(32);
        let digest_c = "cc".repeat(32);
        let digest_102 = "dd".repeat(32);
        let mut log = TradeIdentityLog::create(&log_path).unwrap();
        log.insert(100, &digest_a).unwrap();
        log.insert(101, &digest_b).unwrap();
        log.sync().unwrap();
        drop(log);
        let mut union = TradeUnionState::new();
        union.set_identity_log(TradeIdentityLog::open(&log_path).unwrap());
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        union.restore_published_identity(100, &digest_a);
        union.restore_published_identity(101, &digest_b);
        union.restore_published_floor(101).unwrap();
        // Contradiction on the restored prefix: conflict, not re-publication.
        assert!(matches!(
            union
                .observe(
                    CaptureLane::Shadow,
                    &trade_observation(100, "s", 0, &digest_c)
                )
                .unwrap(),
            TradeUnionDisposition::Conflict { trade_id: 100, .. }
        ));
        // New trades flow normally from the floor.
        union
            .observe(
                CaptureLane::Primary,
                &trade_observation(102, "p", 0, &digest_102),
            )
            .unwrap();
        match union
            .observe(
                CaptureLane::Shadow,
                &trade_observation(102, "s", 0, &digest_102),
            )
            .unwrap()
        {
            TradeUnionDisposition::Publishable(batch) => {
                assert_eq!(batch.len(), 1);
                assert_eq!(batch[0].1.final_sequence, 102);
            }
            other => panic!("expected Publishable, got {other:?}"),
        }
    }

    #[test]
    fn journal_set_audits_resume_chained_segments_across_restarts() {
        // Segment 1: STARTED, trade 100, depth 5001..5010, terminal.
        // Segment 2: RESUMED chaining segment 1, trade 101, depth 5011..5020,
        // terminal with cumulative counters.  The set audit verifies the
        // cross-segment chain, the exact trade floor and cumulative counters.
        let dir = tempfile::tempdir().unwrap();
        let segment_one = dir.path().join("canonical-0.jsonl");
        let segment_two = dir.path().join("canonical-1.jsonl");
        {
            let mut writer = LiveArbitrationJournalWriter::create(&segment_one).unwrap();
            writer
                .append(
                    1,
                    "LIVE",
                    serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT","trade_floor":0}),
                )
                .unwrap();
            writer
                .append(
                    2,
                    "LIVE",
                    serde_json::json!({
                        "event":"TRADE_OBSERVATION","trade_id":100,"lane":"PRIMARY",
                        "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                    }),
                )
                .unwrap();
            writer
                .append(
                    3,
                    "LIVE",
                    serde_json::json!({
                        "event":"DEPTH_OBSERVATION","first_sequence":5001,"final_sequence":5010,
                        "lane":"PRIMARY","record_sha256":"c".repeat(64),
                        "observation_sha256":"d".repeat(64)
                    }),
                )
                .unwrap();
            writer
                .append(
                    4,
                    "LIVE",
                    serde_json::json!({
                        "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                        "trades":1,"depth_frames":1,"gaps":0,"late_corrections":0
                    }),
                )
                .unwrap();
        }
        let previous_sha = std::fs::read_to_string(&segment_one)
            .unwrap()
            .lines()
            .last()
            .and_then(|line| serde_json::from_str::<LiveArbitrationJournalEnvelopeV1>(line).ok())
            .map(|envelope| envelope.record_sha256)
            .unwrap();
        {
            let mut writer = LiveArbitrationJournalWriter::create(&segment_two).unwrap();
            writer
                .append(
                    1,
                    "LIVE",
                    serde_json::json!({
                        "event":"ARBITRATION_RESUMED","symbol":"BTCUSDT","mode":"CONTINUOUS",
                        "previous_journal_sha256":previous_sha,"trade_floor":100
                    }),
                )
                .unwrap();
            writer
                .append(
                    2,
                    "LIVE",
                    serde_json::json!({
                        "event":"TRADE_OBSERVATION","trade_id":101,"lane":"PRIMARY",
                        "record_sha256":"e".repeat(64),"observation_sha256":"f".repeat(64)
                    }),
                )
                .unwrap();
            writer
                .append(
                    3,
                    "LIVE",
                    serde_json::json!({
                        "event":"TRADE_LATE_CORRECTION","trade_id":100,"lane":"SHADOW",
                        "record_sha256":"c".repeat(64),"observation_sha256":"b".repeat(64),
                        "kind":"duplicate"
                    }),
                )
                .unwrap();
            writer
                .append(
                    4,
                    "LIVE",
                    serde_json::json!({
                        "event":"DEPTH_OBSERVATION","first_sequence":5011,"final_sequence":5020,
                        "lane":"PRIMARY","record_sha256":"d".repeat(64),
                        "observation_sha256":"e".repeat(64)
                    }),
                )
                .unwrap();
            writer
                .append(
                    5,
                    "LIVE",
                    serde_json::json!({
                        "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                        "trades":2,"depth_frames":2,"gaps":0,"late_corrections":1
                    }),
                )
                .unwrap();
        }
        let scan =
            scan_live_arbitration_journal_set(&[segment_one.clone(), segment_two.clone()]).unwrap();
        assert_eq!(scan.segments, 2);
        assert_eq!(scan.trades, 2);
        assert_eq!(scan.depth_frames, 2);
        assert_eq!(scan.late_corrections, 1);
        assert_eq!(scan.last_trade_id, Some(101));
        assert_eq!(scan.last_depth_sequence, Some(5020));
        assert_eq!(scan.published_trades, 2);

        // A broken resume chain (previous sha mismatch) must be rejected.
        let corrupt_two = dir.path().join("canonical-1-broken.jsonl");
        let bytes = std::fs::read_to_string(&segment_two).unwrap();
        let broken = bytes.replacen(&previous_sha, &"0".repeat(64), 1);
        std::fs::write(&corrupt_two, broken).unwrap();
        assert!(scan_live_arbitration_journal_set(&[segment_one.clone(), corrupt_two]).is_err());

        // A resumed segment whose trade floor does not equal the previous
        // last published trade must be rejected.
        let wrong_floor = dir.path().join("canonical-1-wrong-floor.jsonl");
        let bytes = std::fs::read_to_string(&segment_two).unwrap();
        let broken = bytes.replacen("\"trade_floor\":100", "\"trade_floor\":99", 1);
        std::fs::write(&wrong_floor, broken).unwrap();
        assert!(scan_live_arbitration_journal_set(&[segment_one.clone(), wrong_floor]).is_err());
    }

    #[test]
    fn live_journal_set_preserves_identity_and_checks_predecessor_tail() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("0.jsonl");
        let second = dir.path().join("1.jsonl");
        let wrong = dir.path().join("wrong.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&first).unwrap();
        writer.append(0, "LIVE", serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT","trade_floor":10})).unwrap();
        writer.append(1, "LIVE", serde_json::json!({"event":"TRADE_OBSERVATION","trade_id":20,"lane":"PRIMARY","record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)})).unwrap();
        writer.append(2, "LIVE", serde_json::json!({"event":"TRADE_LATE_CORRECTION","trade_id":15,"kind":"unknown","lane":"SHADOW","record_sha256":"c".repeat(64),"observation_sha256":"d".repeat(64)})).unwrap();
        drop(writer);
        let (scan, _, _) = scan_live_arbitration_journal_incremental(&first).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&first)
            .unwrap()
            .write_all(b"torn1")
            .unwrap();
        for (path, previous_tail_bytes) in [(&second, 5), (&wrong, 4)] {
            let mut writer = LiveArbitrationJournalWriter::create(path).unwrap();
            writer.append(0, "LIVE", serde_json::json!({"event":"ARBITRATION_RESUMED","symbol":"BTCUSDT","mode":"CONTINUOUS","trade_floor":20,"previous_journal_sha256":scan.last_record_sha256,"previous_tail_bytes":previous_tail_bytes})).unwrap();
            writer.append(1, "LIVE", serde_json::json!({"event":"TRADE_LATE_CORRECTION","trade_id":15,"kind":"duplicate","lane":"PRIMARY","record_sha256":"e".repeat(64),"observation_sha256":"d".repeat(64)})).unwrap();
            drop(writer);
            std::fs::OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(b"tail")
                .unwrap();
        }
        let (scan, clean, tail) =
            scan_live_arbitration_journal_set_incremental(&[first.clone(), second]).unwrap();
        assert!(!clean);
        assert_eq!(tail, 4);
        assert!(!scan.terminal_seen);
        assert_eq!(scan.trade_floor, Some(10));
        assert_eq!(scan.late_corrections, 2);
        assert!(scan_live_arbitration_journal_set_incremental(&[first, wrong]).is_err());
    }

    #[test]
    fn identity_rebuild_materializes_missing_records_from_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("canonical.jsonl");
        let mut writer = LiveArbitrationJournalWriter::create(&journal_path).unwrap();
        writer
            .append(
                1,
                "LIVE",
                serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT"}),
            )
            .unwrap();
        writer
            .append(
                2,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":100,"lane":"PRIMARY",
                    "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                }),
            )
            .unwrap();
        writer
            .append(
                3,
                "LIVE",
                serde_json::json!({
                    "event":"TRADE_OBSERVATION","trade_id":101,"lane":"SHADOW",
                    "record_sha256":"c".repeat(64),"observation_sha256":"d".repeat(64)
                }),
            )
            .unwrap();
        drop(writer);
        let log_path = dir.path().join("trade-identity.bin");
        let mut log = TradeIdentityLog::create(&log_path).unwrap();
        let rebuilt = rebuild_trade_identity_from_journal(&journal_path, &mut log).unwrap();
        assert_eq!(rebuilt, 2);
        assert_eq!(log.lookup(100).unwrap(), Some("b".repeat(64)));
        assert_eq!(log.lookup(101).unwrap(), Some("d".repeat(64)));
        // Idempotent: a second rebuild inserts nothing.
        let rebuilt_again = rebuild_trade_identity_from_journal(&journal_path, &mut log).unwrap();
        assert_eq!(rebuilt_again, 0);
        assert_eq!(log.records(), 2);
    }
}
