//! Neutral validated observations derived from immutable BNRAW evidence.

use crate::boundary::{BoundaryStreamKind, CanonicalObservationV1};
use crate::{
    ApplyOutcome, FixedDecimal, LocalOrderBook, RawRecordEnvelopeV1, Result, hex, read_raw_records,
    read_raw_records_through_offset, scan_raw_log,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ObservationMaterializationV1 {
    pub schema: &'static str,
    pub symbol: String,
    pub stream_kind: BoundaryStreamKind,
    pub stream: String,
    pub connection_epoch: String,
    pub raw_path: String,
    pub raw_last_record_sha256: String,
    pub snapshot_path: Option<String>,
    pub snapshot_record_sha256: Option<String>,
    pub snapshot_last_update_id: Option<u64>,
    pub raw_records: u64,
    pub skipped_initial_old_records: u64,
    pub observations: Vec<CanonicalObservationV1>,
    pub first_sequence: u64,
    pub final_sequence: u64,
    pub materialization_sha256: String,
}

#[derive(Serialize)]
struct ObservationDigestItem<'a> {
    connection_epoch: &'a str,
    final_sequence: u64,
    first_sequence: u64,
    frame_index: u64,
    observation_sha256: &'a str,
    record_sha256: &'a str,
    stream: &'a str,
    stream_kind: BoundaryStreamKind,
    symbol: &'a str,
}

#[derive(Serialize)]
struct MaterializationDigest<'a> {
    observations: Vec<ObservationDigestItem<'a>>,
    raw_last_record_sha256: &'a str,
    schema: &'static str,
    skipped_initial_old_records: u64,
    snapshot_last_update_id: Option<u64>,
    snapshot_record_sha256: Option<&'a str>,
    stream_kind: BoundaryStreamKind,
}

#[derive(Serialize)]
struct CanonicalTradeEvent<'a> {
    best_match: bool,
    buyer_is_maker: bool,
    price: &'a str,
    quantity: &'a str,
    schema: &'static str,
    symbol: &'a str,
    trade_id: u64,
    trade_time: u64,
}

pub struct DepthObservationCursor {
    symbol: String,
    stream: String,
    connection_epoch: String,
    book: LocalOrderBook,
    live_started: bool,
}

impl DepthObservationCursor {
    pub fn from_durable_prefix(
        snapshot_path: &Path,
        depth_path: &Path,
        durable_through_offset: u64,
    ) -> Result<Self> {
        let snapshots = read_raw_records(snapshot_path)?;
        if snapshots.len() != 1 {
            return Err("depth cursor requires one snapshot".to_owned());
        }
        let records = read_raw_records_through_offset(depth_path, durable_through_offset)?;
        let (symbol, stream, connection_epoch) = identity(&records)?;
        if !stream.contains("@depth") || snapshots[0].frame.symbol != symbol {
            return Err("depth cursor snapshot/stream identity mismatch".to_owned());
        }
        let mut cursor = Self {
            book: LocalOrderBook::new(&symbol)?,
            symbol,
            stream,
            connection_epoch,
            live_started: false,
        };
        cursor.book.load_snapshot(&snapshots[0].frame.payload)?;
        for record in &records {
            cursor.apply_record(record)?;
        }
        if !cursor.live_started {
            return Err("depth cursor prefix never reached LIVE observations".to_owned());
        }
        Ok(cursor)
    }

    pub fn apply_record(
        &mut self,
        record: &RawRecordEnvelopeV1,
    ) -> Result<Option<CanonicalObservationV1>> {
        if record.frame.symbol != self.symbol
            || record.frame.stream != self.stream
            || record.frame.connection_epoch != self.connection_epoch
        {
            return Err("depth cursor record identity mismatch".to_owned());
        }
        let (first_sequence, final_sequence) = depth_ids(&record.frame.payload)?;
        match self.book.apply_depth(&record.frame.payload)? {
            ApplyOutcome::Old => {
                if self.live_started {
                    return Err("stale depth record appeared after cursor became LIVE".to_owned());
                }
                Ok(None)
            }
            ApplyOutcome::Applied => {
                self.live_started = true;
                Ok(Some(CanonicalObservationV1 {
                    symbol: self.symbol.clone(),
                    stream_kind: BoundaryStreamKind::Depth,
                    stream: self.stream.clone(),
                    connection_epoch: self.connection_epoch.clone(),
                    frame_index: record.frame.frame_index,
                    first_sequence,
                    final_sequence,
                    record_sha256: record.record_sha256.clone(),
                    observation_sha256: self.book.state_digest(),
                }))
            }
        }
    }
}

fn strict_object(payload: &[u8], label: &str) -> Result<Value> {
    let value: Value = serde_json::from_slice(payload)
        .map_err(|error| format!("{label} payload is not valid JSON: {error}"))?;
    if !value.is_object() {
        return Err(format!("{label} payload root must be object"));
    }
    Ok(value)
}

fn field_u64(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("invalid non-negative integer field {field}"))
}

fn field_bool(value: &Value, field: &str) -> Result<bool> {
    value[field]
        .as_bool()
        .ok_or_else(|| format!("invalid boolean field {field}"))
}

fn identity(records: &[RawRecordEnvelopeV1]) -> Result<(String, String, String)> {
    let first = records
        .first()
        .ok_or_else(|| "raw source has no records".to_owned())?;
    let identity = (
        first.frame.symbol.clone(),
        first.frame.stream.clone(),
        first.frame.connection_epoch.clone(),
    );
    if records.iter().any(|record| {
        record.frame.symbol != identity.0
            || record.frame.stream != identity.1
            || record.frame.connection_epoch != identity.2
    }) {
        return Err("raw source mixes symbol/stream/epoch identity".to_owned());
    }
    Ok(identity)
}

fn require_contiguous_frames(records: &[RawRecordEnvelopeV1]) -> Result<()> {
    for pair in records.windows(2) {
        if pair[1].frame.frame_index
            != pair[0]
                .frame
                .frame_index
                .checked_add(1)
                .ok_or_else(|| "raw frame index overflow".to_owned())?
        {
            return Err("raw observation window has a frame gap or duplicate".to_owned());
        }
    }
    Ok(())
}

fn depth_ids(payload: &[u8]) -> Result<(u64, u64)> {
    let value = strict_object(payload, "depth")?;
    if value["e"].as_str() != Some("depthUpdate") {
        return Err("unexpected depth event type".to_owned());
    }
    Ok((field_u64(&value, "U")?, field_u64(&value, "u")?))
}

fn server_shutdown_payload(payload: &[u8]) -> Result<bool> {
    let value = strict_object(payload, "serverShutdown/control")?;
    if value["e"].as_str() != Some("serverShutdown") {
        return Ok(false);
    }
    field_u64(&value, "E")?;
    Ok(true)
}

fn trade_observation_digest(payload: &[u8], symbol: &str) -> Result<(u64, String)> {
    let value = strict_object(payload, "trade")?;
    trade_observation_digest_value(&value, symbol)
}

fn trade_observation_digest_value(value: &Value, symbol: &str) -> Result<(u64, String)> {
    if value["e"].as_str() != Some("trade") || value["s"].as_str() != Some(symbol) {
        return Err("unexpected trade event type or symbol".to_owned());
    }
    let trade_id = field_u64(value, "t")?;
    // E remains validated raw evidence, but simultaneous public connections
    // can receive a different stream-dispatch timestamp for the same trade ID.
    // It therefore cannot define the logical trade identity digest.
    field_u64(value, "E")?;
    let trade_time = field_u64(value, "T")?;
    let raw_price = value["p"]
        .as_str()
        .ok_or_else(|| "trade price must be a string".to_owned())?;
    let raw_quantity = value["q"]
        .as_str()
        .ok_or_else(|| "trade quantity must be a string".to_owned())?;
    let price = FixedDecimal::parse(raw_price)?;
    let quantity = FixedDecimal::parse(raw_quantity)?;
    if price.is_zero() || price.is_negative() || quantity.is_zero() || quantity.is_negative() {
        return Err("trade price/quantity must be positive".to_owned());
    }
    let price = price.to_string();
    let quantity = quantity.to_string();
    let material = CanonicalTradeEvent {
        best_match: field_bool(value, "M")?,
        buyer_is_maker: field_bool(value, "m")?,
        price: &price,
        quantity: &quantity,
        schema: "CanonicalTradeEventV1",
        symbol,
        trade_id,
        trade_time,
    };
    let encoded = serde_json::to_vec(&material)
        .map_err(|error| format!("serialize canonical trade event: {error}"))?;
    Ok((trade_id, hex(&Sha256::digest(encoded))))
}

pub(crate) fn validated_trade_id(value: &Value, symbol: &str) -> Result<u64> {
    trade_observation_digest_value(value, symbol).map(|(trade_id, _)| trade_id)
}

pub fn materialize_trade_record(record: &RawRecordEnvelopeV1) -> Result<CanonicalObservationV1> {
    let symbol = &record.frame.symbol;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") || !record.frame.stream.ends_with("@trade")
    {
        return Err("trade record identity outside canonical scope".to_owned());
    }
    let (trade_id, event_digest) = trade_observation_digest(&record.frame.payload, symbol)?;
    Ok(CanonicalObservationV1 {
        symbol: symbol.clone(),
        stream_kind: BoundaryStreamKind::Trade,
        stream: record.frame.stream.clone(),
        connection_epoch: record.frame.connection_epoch.clone(),
        frame_index: record.frame.frame_index,
        first_sequence: trade_id,
        final_sequence: trade_id,
        record_sha256: record.record_sha256.clone(),
        observation_sha256: event_digest,
    })
}

/// Materialize an arbitrary contiguous depth window against one explicitly
/// chosen snapshot. This is used for bounded A/B convergence checks; it never
/// rewrites raw evidence and does not require the window to begin at frame 0.
pub fn materialize_depth_record_window(
    snapshot: &RawRecordEnvelopeV1,
    records: &[RawRecordEnvelopeV1],
) -> Result<Vec<CanonicalObservationV1>> {
    let (symbol, stream, epoch) = identity(records)?;
    require_contiguous_frames(records)?;
    if !stream.contains("@depth") || snapshot.frame.symbol != symbol {
        return Err("depth window snapshot/stream identity mismatch".to_owned());
    }
    let mut book = LocalOrderBook::new(&symbol)?;
    book.load_snapshot(&snapshot.frame.payload)?;
    let mut observations = Vec::new();
    for record in records {
        if server_shutdown_payload(&record.frame.payload)? {
            continue;
        }
        let (first_sequence, final_sequence) = depth_ids(&record.frame.payload)?;
        match book.apply_depth(&record.frame.payload)? {
            ApplyOutcome::Old => {
                if !observations.is_empty() {
                    return Err("stale depth record appeared after window became LIVE".to_owned());
                }
            }
            ApplyOutcome::Applied => observations.push(CanonicalObservationV1 {
                symbol: symbol.clone(),
                stream_kind: BoundaryStreamKind::Depth,
                stream: stream.clone(),
                connection_epoch: epoch.clone(),
                frame_index: record.frame.frame_index,
                first_sequence,
                final_sequence,
                record_sha256: record.record_sha256.clone(),
                observation_sha256: book.state_digest(),
            }),
        }
    }
    if observations.is_empty() {
        return Err("depth window never reached LIVE".to_owned());
    }
    Ok(observations)
}

#[derive(Clone, Copy)]
struct DepthWindowEvent {
    record_index: usize,
    first_sequence: u64,
    final_sequence: u64,
}

#[derive(Clone, Copy)]
struct AppliedDepthWindowEvent {
    event_index: usize,
    first_sequence: u64,
    final_sequence: u64,
}

#[derive(Clone, Copy)]
struct DepthConvergenceCandidate {
    predecessor: AppliedDepthWindowEvent,
    successor: AppliedDepthWindowEvent,
    continuation: DepthWindowEvent,
}

#[derive(Debug)]
pub struct LatestDepthWindowConvergenceV1 {
    pub predecessor_boundary: CanonicalObservationV1,
    pub successor_boundary: CanonicalObservationV1,
    pub successor_continuation: CanonicalObservationV1,
}

fn prepare_depth_window(
    snapshot: &RawRecordEnvelopeV1,
    records: &[RawRecordEnvelopeV1],
) -> Result<((String, String, String), Vec<DepthWindowEvent>)> {
    let identity = identity(records)?;
    require_contiguous_frames(records)?;
    if !identity.1.contains("@depth") || snapshot.frame.symbol != identity.0 {
        return Err("depth window snapshot/stream identity mismatch".to_owned());
    }
    let mut events = Vec::with_capacity(records.len());
    for (record_index, record) in records.iter().enumerate() {
        if server_shutdown_payload(&record.frame.payload)? {
            continue;
        }
        let (first_sequence, final_sequence) = depth_ids(&record.frame.payload)?;
        events.push(DepthWindowEvent {
            record_index,
            first_sequence,
            final_sequence,
        });
    }
    Ok((identity, events))
}

fn advance_depth_window(
    book: &mut LocalOrderBook,
    records: &[RawRecordEnvelopeV1],
    events: &[DepthWindowEvent],
    next_event: &mut usize,
    live_started: &mut bool,
) -> Result<Option<AppliedDepthWindowEvent>> {
    while let Some(event) = events.get(*next_event).copied() {
        let event_index = *next_event;
        *next_event += 1;
        match book.apply_depth(&records[event.record_index].frame.payload)? {
            ApplyOutcome::Old => {
                if *live_started {
                    return Err("stale depth record appeared after window became LIVE".to_owned());
                }
            }
            ApplyOutcome::Applied => {
                *live_started = true;
                return Ok(Some(AppliedDepthWindowEvent {
                    event_index,
                    first_sequence: event.first_sequence,
                    final_sequence: event.final_sequence,
                }));
            }
        }
    }
    Ok(None)
}

fn replay_depth_window_through(
    snapshot: &RawRecordEnvelopeV1,
    records: &[RawRecordEnvelopeV1],
    events: &[DepthWindowEvent],
    through_event: usize,
) -> Result<LocalOrderBook> {
    let mut book = LocalOrderBook::new(&snapshot.frame.symbol)?;
    book.load_snapshot(&snapshot.frame.payload)?;
    let mut live_started = false;
    for event in events.iter().take(through_event + 1) {
        match book.apply_depth(&records[event.record_index].frame.payload)? {
            ApplyOutcome::Old => {
                if live_started {
                    return Err("stale depth record appeared after window became LIVE".to_owned());
                }
            }
            ApplyOutcome::Applied => live_started = true,
        }
    }
    if !live_started {
        return Err("depth window never reached LIVE".to_owned());
    }
    Ok(book)
}

fn depth_window_observation(
    identity: &(String, String, String),
    record: &RawRecordEnvelopeV1,
    first_sequence: u64,
    final_sequence: u64,
    observation_sha256: String,
) -> CanonicalObservationV1 {
    CanonicalObservationV1 {
        symbol: identity.0.clone(),
        stream_kind: BoundaryStreamKind::Depth,
        stream: identity.1.clone(),
        connection_epoch: identity.2.clone(),
        frame_index: record.frame.frame_index,
        first_sequence,
        final_sequence,
        record_sha256: record.record_sha256.clone(),
        observation_sha256,
    }
}

/// Finds the latest exact A/B depth convergence without hashing the complete
/// order book after every update. Structural equality is authoritative; the
/// canonical SHA-256 state digest is computed only for an exact candidate.
pub fn latest_depth_window_convergence(
    snapshot: &RawRecordEnvelopeV1,
    predecessor_records: &[RawRecordEnvelopeV1],
    successor_records: &[RawRecordEnvelopeV1],
) -> Result<LatestDepthWindowConvergenceV1> {
    let (predecessor_identity, predecessor_events) =
        prepare_depth_window(snapshot, predecessor_records)?;
    let (successor_identity, successor_events) = prepare_depth_window(snapshot, successor_records)?;
    if predecessor_identity.0 != successor_identity.0 {
        return Err("depth overlap symbols differ".to_owned());
    }
    let mut predecessor_book = LocalOrderBook::new(&predecessor_identity.0)?;
    predecessor_book.load_snapshot(&snapshot.frame.payload)?;
    let mut successor_book = LocalOrderBook::new(&successor_identity.0)?;
    successor_book.load_snapshot(&snapshot.frame.payload)?;
    let mut predecessor_next = 0_usize;
    let mut successor_next = 0_usize;
    let mut predecessor_live = false;
    let mut successor_live = false;
    let mut predecessor_current = advance_depth_window(
        &mut predecessor_book,
        predecessor_records,
        &predecessor_events,
        &mut predecessor_next,
        &mut predecessor_live,
    )?;
    let mut successor_current = advance_depth_window(
        &mut successor_book,
        successor_records,
        &successor_events,
        &mut successor_next,
        &mut successor_live,
    )?;
    let mut candidates = Vec::new();
    while let (Some(predecessor), Some(successor)) = (predecessor_current, successor_current) {
        match predecessor.final_sequence.cmp(&successor.final_sequence) {
            std::cmp::Ordering::Less => {
                predecessor_current = advance_depth_window(
                    &mut predecessor_book,
                    predecessor_records,
                    &predecessor_events,
                    &mut predecessor_next,
                    &mut predecessor_live,
                )?;
            }
            std::cmp::Ordering::Greater => {
                successor_current = advance_depth_window(
                    &mut successor_book,
                    successor_records,
                    &successor_events,
                    &mut successor_next,
                    &mut successor_live,
                )?;
            }
            std::cmp::Ordering::Equal => {
                let continuation = successor_events.get(successor.event_index + 1).copied();
                if predecessor_book.same_state_fingerprint(&successor_book)
                    && let Some(continuation) = continuation
                {
                    let next = successor
                        .final_sequence
                        .checked_add(1)
                        .ok_or_else(|| "depth boundary sequence overflow".to_owned())?;
                    if continuation.first_sequence <= next && continuation.final_sequence >= next {
                        candidates.push(DepthConvergenceCandidate {
                            predecessor,
                            successor,
                            continuation,
                        });
                    }
                }
                predecessor_current = advance_depth_window(
                    &mut predecessor_book,
                    predecessor_records,
                    &predecessor_events,
                    &mut predecessor_next,
                    &mut predecessor_live,
                )?;
                successor_current = advance_depth_window(
                    &mut successor_book,
                    successor_records,
                    &successor_events,
                    &mut successor_next,
                    &mut successor_live,
                )?;
            }
        }
    }
    while predecessor_current.is_some() {
        predecessor_current = advance_depth_window(
            &mut predecessor_book,
            predecessor_records,
            &predecessor_events,
            &mut predecessor_next,
            &mut predecessor_live,
        )?;
    }
    while successor_current.is_some() {
        successor_current = advance_depth_window(
            &mut successor_book,
            successor_records,
            &successor_events,
            &mut successor_next,
            &mut successor_live,
        )?;
    }
    for candidate in candidates.into_iter().rev() {
        let predecessor_book = replay_depth_window_through(
            snapshot,
            predecessor_records,
            &predecessor_events,
            candidate.predecessor.event_index,
        )?;
        let successor_book = replay_depth_window_through(
            snapshot,
            successor_records,
            &successor_events,
            candidate.successor.event_index,
        )?;
        if !predecessor_book.same_state(&successor_book) {
            continue;
        }
        let state_sha256 = predecessor_book.state_digest();
        let predecessor_record = &predecessor_records
            [predecessor_events[candidate.predecessor.event_index].record_index];
        let successor_record =
            &successor_records[successor_events[candidate.successor.event_index].record_index];
        let continuation_record = &successor_records[candidate.continuation.record_index];
        return Ok(LatestDepthWindowConvergenceV1 {
            predecessor_boundary: depth_window_observation(
                &predecessor_identity,
                predecessor_record,
                candidate.predecessor.first_sequence,
                candidate.predecessor.final_sequence,
                state_sha256.clone(),
            ),
            successor_boundary: depth_window_observation(
                &successor_identity,
                successor_record,
                candidate.successor.first_sequence,
                candidate.successor.final_sequence,
                state_sha256,
            ),
            successor_continuation: depth_window_observation(
                &successor_identity,
                continuation_record,
                candidate.continuation.first_sequence,
                candidate.continuation.final_sequence,
                String::new(),
            ),
        });
    }
    Err("no exact depth convergence with documented B continuation".to_owned())
}

/// Materialize an arbitrary contiguous individual-trade window. Frame and
/// trade identity remain exact even when the first frame index is non-zero.
pub fn materialize_trade_record_window(
    records: &[RawRecordEnvelopeV1],
) -> Result<Vec<CanonicalObservationV1>> {
    let (symbol, stream, epoch) = identity(records)?;
    require_contiguous_frames(records)?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") || !stream.ends_with("@trade") {
        return Err("trade window identity outside canonical scope".to_owned());
    }
    let mut observations = Vec::with_capacity(records.len());
    let mut previous_trade_id: Option<u64> = None;
    for record in records {
        if server_shutdown_payload(&record.frame.payload)? {
            continue;
        }
        let (trade_id, event_digest) = trade_observation_digest(&record.frame.payload, &symbol)?;
        if let Some(previous) = previous_trade_id
            && trade_id <= previous
        {
            return Err(format!(
                "trade ID duplicated or regressed: previous {previous}, got {trade_id}"
            ));
        }
        observations.push(CanonicalObservationV1 {
            symbol: symbol.clone(),
            stream_kind: BoundaryStreamKind::Trade,
            stream: stream.clone(),
            connection_epoch: epoch.clone(),
            frame_index: record.frame.frame_index,
            first_sequence: trade_id,
            final_sequence: trade_id,
            record_sha256: record.record_sha256.clone(),
            observation_sha256: event_digest,
        });
        previous_trade_id = Some(trade_id);
    }
    Ok(observations)
}

#[allow(clippy::too_many_arguments)]
fn finalize(
    raw_path: &Path,
    stream_kind: BoundaryStreamKind,
    records: &[RawRecordEnvelopeV1],
    observations: Vec<CanonicalObservationV1>,
    skipped_initial_old_records: u64,
    snapshot_path: Option<&Path>,
    snapshot_record_sha256: Option<String>,
    snapshot_last_update_id: Option<u64>,
) -> Result<ObservationMaterializationV1> {
    let first = observations
        .first()
        .ok_or_else(|| "materialization produced no observations".to_owned())?;
    let first_sequence = first.first_sequence;
    let final_sequence = observations
        .last()
        .expect("observations checked nonempty")
        .final_sequence;
    let (symbol, stream, connection_epoch) = identity(records)?;
    let scan = scan_raw_log(raw_path)?;
    if !scan.clean_eof {
        return Err(format!(
            "raw source is corrupt/incomplete: {:?}",
            scan.reason
        ));
    }
    let digest_items = observations
        .iter()
        .map(|item| ObservationDigestItem {
            connection_epoch: &item.connection_epoch,
            final_sequence: item.final_sequence,
            first_sequence: item.first_sequence,
            frame_index: item.frame_index,
            observation_sha256: &item.observation_sha256,
            record_sha256: &item.record_sha256,
            stream: &item.stream,
            stream_kind: item.stream_kind,
            symbol: &item.symbol,
        })
        .collect();
    let digest_material = MaterializationDigest {
        observations: digest_items,
        raw_last_record_sha256: &scan.last_record_sha256,
        schema: "ObservationMaterializationDigestV1",
        skipped_initial_old_records,
        snapshot_last_update_id,
        snapshot_record_sha256: snapshot_record_sha256.as_deref(),
        stream_kind,
    };
    let encoded = serde_json::to_vec(&digest_material)
        .map_err(|error| format!("serialize observation materialization digest: {error}"))?;
    Ok(ObservationMaterializationV1 {
        schema: "ObservationMaterializationV1",
        symbol,
        stream_kind,
        stream,
        connection_epoch,
        raw_path: raw_path.display().to_string(),
        raw_last_record_sha256: scan.last_record_sha256,
        snapshot_path: snapshot_path.map(|path| path.display().to_string()),
        snapshot_record_sha256,
        snapshot_last_update_id,
        raw_records: records.len() as u64,
        skipped_initial_old_records,
        observations,
        first_sequence,
        final_sequence,
        materialization_sha256: hex(&Sha256::digest(encoded)),
    })
}

pub fn materialize_depth_observations(
    snapshot_path: &Path,
    depth_path: &Path,
) -> Result<ObservationMaterializationV1> {
    let snapshots = read_raw_records(snapshot_path)?;
    if snapshots.len() != 1 {
        return Err("depth materialization requires one snapshot".to_owned());
    }
    let records = read_raw_records(depth_path)?;
    let (symbol, stream, epoch) = identity(&records)?;
    if !stream.contains("@depth") {
        return Err("depth source stream is not a depth stream".to_owned());
    }
    if snapshots[0].frame.symbol != symbol {
        return Err("snapshot/depth symbol mismatch".to_owned());
    }
    let mut book = LocalOrderBook::new(&symbol)?;
    let snapshot_last_update_id = book.load_snapshot(&snapshots[0].frame.payload)?;
    let mut observations = Vec::new();
    let mut skipped = 0_u64;
    for record in &records {
        let (first_sequence, final_sequence) = depth_ids(&record.frame.payload)?;
        match book.apply_depth(&record.frame.payload)? {
            ApplyOutcome::Old => {
                if !observations.is_empty() {
                    return Err(
                        "stale depth record appeared after canonical LIVE observations".to_owned(),
                    );
                }
                skipped += 1;
            }
            ApplyOutcome::Applied => observations.push(CanonicalObservationV1 {
                symbol: symbol.clone(),
                stream_kind: BoundaryStreamKind::Depth,
                stream: stream.clone(),
                connection_epoch: epoch.clone(),
                frame_index: record.frame.frame_index,
                first_sequence,
                final_sequence,
                record_sha256: record.record_sha256.clone(),
                observation_sha256: book.state_digest(),
            }),
        }
    }
    finalize(
        depth_path,
        BoundaryStreamKind::Depth,
        &records,
        observations,
        skipped,
        Some(snapshot_path),
        Some(snapshots[0].record_sha256.clone()),
        Some(snapshot_last_update_id),
    )
}

pub fn materialize_trade_observations(trade_path: &Path) -> Result<ObservationMaterializationV1> {
    let records = read_raw_records(trade_path)?;
    let (symbol, stream, epoch) = identity(&records)?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err(format!("symbol outside scope: {symbol}"));
    }
    if !stream.ends_with("@trade") {
        return Err("trade source stream is not an individual trade stream".to_owned());
    }
    let mut observations = Vec::new();
    let mut previous_trade_id = None;
    for record in &records {
        let (trade_id, event_digest) = trade_observation_digest(&record.frame.payload, &symbol)?;
        if let Some(previous) = previous_trade_id
            && trade_id <= previous
        {
            return Err(format!(
                "trade ID duplicated or regressed: previous {previous}, got {trade_id}"
            ));
        }
        observations.push(CanonicalObservationV1 {
            symbol: symbol.clone(),
            stream_kind: BoundaryStreamKind::Trade,
            stream: stream.clone(),
            connection_epoch: epoch.clone(),
            frame_index: record.frame.frame_index,
            first_sequence: trade_id,
            final_sequence: trade_id,
            record_sha256: record.record_sha256.clone(),
            observation_sha256: event_digest,
        });
        previous_trade_id = Some(trade_id);
    }
    finalize(
        trade_path,
        BoundaryStreamKind::Trade,
        &records,
        observations,
        0,
        None,
        None,
        None,
    )
}
