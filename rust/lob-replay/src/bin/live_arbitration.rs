//! Live cross-lane arbitration sidecar (ADR-16, corrected contract).
//!
//! Consumes only the durable, BNACK-authorized prefixes of both redundant
//! lanes' active generations; materializes neutral observations with the
//! existing verified machinery; publishes one hash-chained canonical live
//! journal.  Trades are the exact union of both lanes: an ID publishes only
//! once EVERY live lane's durable prefix has passed it (per-connection
//! venue order makes that a final decision), so a lower ID from the other
//! lane is never confused with a duplicate; a lane excluded by the lag bound
//! surfaces its late deliveries as typed corrections.  Depth follows one
//! serving lane with every publication frontier-validated against the
//! canonical cursor; a proven switch requires geometric coverage AND exact
//! book convergence (gap-free is not the same as correct), a dual loss is a
//! typed GAP followed by an explicitly evidenced DEPTH_REBOOTSTRAP, and the
//! serving lane is never replaced before its predecessor drains to its
//! durable boundary.  Fail-closed: any materialization or arbitration error
//! stops publication and exits non-zero without ever touching BNRAW/BNACK.

use lob_replay::boundary::CanonicalObservationV1;
use lob_replay::durability_follower::SegmentDurabilityFollower;
use lob_replay::hot_redundancy::CaptureLane;
use lob_replay::live_arbitration::{
    DepthFrontierDisposition, LiveArbitrationJournalWriter, TradeIdentityLog,
    TradeUnionDisposition, TradeUnionState, classify_depth_frontier, lane_payload,
    rebuild_trade_identity_from_journal, safe_relative_path,
    scan_live_arbitration_journal_set_recovery, trim_pending_depth,
};
use lob_replay::observations::{
    DepthObservationCursor, materialize_depth_record_window, materialize_trade_record,
};
use lob_replay::segment_chain::{
    root_segment_genesis, scan_segment_manifest, successor_segment_genesis,
};
use lob_replay::{
    RawRecordEnvelopeV1, RawSegmentGenesisV1, Result, read_raw_record_range, read_raw_records,
    read_raw_segment_records,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";
const POLL: Duration = Duration::from_millis(250);
const SWITCH_HORIZON: Duration = Duration::from_secs(10);
const RENEW_BIND_DEADLINE: Duration = Duration::from_secs(60);
/// Hard trade-buffer bound: a live lane that lags more than this many IDs is
/// excluded from the watermark with a typed TRADE_LAG record; its later
/// deliveries become typed late corrections, never silent drops.
const TRADE_LAG_CAP: usize = 65_536;
/// A live lane without any trade advance for this long is excluded from the
/// watermark (the venue freshness deadline bounds a genuine stall to ~30 s).
const TRADE_LAG_HORIZON: Duration = Duration::from_secs(60);

fn parse_positive(value: Option<String>, name: &str, maximum: u64) -> Result<u64> {
    let parsed = value
        .ok_or_else(|| format!("missing {name}"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid {name}: {error}"))?;
    if parsed == 0 || parsed > maximum {
        return Err(format!("{name} must be within 1..={maximum}"));
    }
    Ok(parsed)
}

fn lane_leaf(lane: CaptureLane) -> &'static str {
    match lane {
        CaptureLane::Primary => "p",
        CaptureLane::Shadow => "s",
    }
}

fn lane_index(lane: CaptureLane) -> usize {
    match lane {
        CaptureLane::Primary => 0,
        CaptureLane::Shadow => 1,
    }
}

fn other_lane(lane: CaptureLane) -> CaptureLane {
    match lane {
        CaptureLane::Primary => CaptureLane::Shadow,
        CaptureLane::Shadow => CaptureLane::Primary,
    }
}

fn sorted_directories(root: &Path) -> Result<Vec<PathBuf>> {
    let mut directories: Vec<PathBuf> = fs::read_dir(root)
        .map_err(|error| format!("read {}: {error}", root.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    directories.sort();
    Ok(directories)
}

/// Chronological list of one lane's generations across every campaign:
/// `(campaign_dir, generation_dir, start_ns)` sorted by their timestamped
/// directory names (replay mode walks this list instead of only the latest).
fn all_generations(lane_root: &Path) -> Result<Vec<(PathBuf, PathBuf, u64)>> {
    let mut out = Vec::new();
    for campaign in sorted_directories(lane_root)? {
        for generation in sorted_directories(&campaign.join("generations"))? {
            let start_ns = generation
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.split('-').next())
                .and_then(|prefix| prefix.parse::<u64>().ok())
                .unwrap_or(0);
            out.push((campaign.clone(), generation, start_ns));
        }
    }
    out.sort_by_key(|(_, _, start_ns)| *start_ns);
    Ok(out)
}

/// Materializes one generation's full depth observation list (replay).
fn materialize_binding_observations(binding: &LaneBinding) -> Result<Vec<CanonicalObservationV1>> {
    let snapshots = read_raw_records(&binding.snapshot_path)?;
    if snapshots.len() != 1 {
        return Err("replay depth snapshot must contain exactly one record".to_owned());
    }
    let records = binding.depth.records().to_vec();
    materialize_depth_record_window(&snapshots[0], &records)
}

/// State recovered from a previous arbiter generation's journal segments
/// (ADR-17 B3 resume): cumulative counters, the exact published trade floor,
/// the canonical depth cursor and the serving lane.
struct RecoveredArbitrationState {
    trades: u64,
    depth_frames: u64,
    gaps: u64,
    late_corrections: u64,
    last_trade_id: Option<u64>,
    startup_trade_floor: u64,
    corrected_identities: BTreeMap<u64, String>,
    /// Duplicate corrections already durable in the recovered journal.
    /// A later resume must not append the same (trade, lane, digest) again.
    journaled_duplicate_corrections: BTreeSet<(u64, String, String)>,
    excluded_tail_origins: BTreeSet<String>,
    canonical_position: CanonicalDepthPosition,
    serving_lane: CaptureLane,
    /// Last complete record SHA-256 of the previous segment (resume chain).
    previous_segment_sha: String,
    /// Torn tail bytes of the previous segment (0 when it ended cleanly).
    previous_tail_bytes: u64,
}

/// The capture's durable terminal declaration: `generation.json` carries
/// `status: COMPLETE` only after the capture finished every stream and
/// sealed them (segmented_capture.rs writes it exactly once, create-only,
/// at the terminal).  Its ABSENCE means the writer may still be alive (or
/// was killed): absence is never proof that the stream ended.
/// ADR-17 boundary authority (review 2026-09-11 risk 1): between
/// `finalize_segment` and the creation of the next segment file there is a
/// legitimate execution window with the next file absent and the producer
/// still running — file absence alone must never be read as "the stream
/// can never deliver again".
fn generation_terminal_complete(generation_dir: &Path) -> Result<bool> {
    let path = generation_dir.join("generation.json");
    if !path.is_file() {
        return Ok(false);
    }
    let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        // The capture writes the terminal declaration once with
        // write+sync: a reader racing the write may see a partial body.
        // No proof of COMPLETE means the stream must stay unsealed
        // (conservative: the next poll retries).
        Err(_) => return Ok(false),
    };
    Ok(value["status"].as_str() == Some("COMPLETE") && value["failure"].is_null())
}

/// A capture generation that already committed `status: FAILED` with
/// `snapshot: null` will never gain `snapshot.bnraw`. That is a finished
/// declaration, not the race where a live writer has not created the file
/// yet. Absence of `generation.json`, a partial body, or any other status
/// stays unproven and must keep failing closed.
fn generation_terminal_failed_without_snapshot(generation_dir: &Path) -> Result<bool> {
    let path = generation_dir.join("generation.json");
    if !path.is_file() {
        return Ok(false);
    }
    let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    Ok(value["status"].as_str() == Some("FAILED")
        && value
            .get("snapshot")
            .is_some_and(|snapshot| snapshot.is_null()))
}

/// True when a lane stream directory is fully sealed (no in-flight
/// segment), i.e. the stream can never deliver again.  This requires the
/// generation's durable terminal declaration (COMPLETE) AND the segment
/// manifest's sealed chain leaving no successor file: a live rotation
/// window can never be misread as the definitive end.
fn stream_fully_sealed(stream_dir: &Path) -> Result<bool> {
    let generation_dir = stream_dir.parent().ok_or_else(|| {
        format!(
            "stream dir {} has no generation parent",
            stream_dir.display()
        )
    })?;
    if !generation_terminal_complete(generation_dir)? {
        return Ok(false);
    }
    let manifest_scan = scan_segment_manifest(&stream_dir.join("segments.bnseg"))?;
    let next_index = manifest_scan
        .entries
        .last()
        .map(|entry| entry.seal.segment_index.saturating_add(1))
        .unwrap_or(0);
    Ok(!stream_dir.join(segment_file_name(next_index)).is_file())
}

/// Both durable streams of a lane generation are sealed: the lane exhausted.
fn binding_streams_sealed(binding: &LaneBinding) -> Result<bool> {
    Ok(stream_fully_sealed(&binding.generation_dir.join("trade"))?
        && stream_fully_sealed(&binding.generation_dir.join("depth"))?)
}

/// Measures a journal segment's torn final line (0 when it ends cleanly).
fn measure_torn_tail(path: &Path) -> Result<u64> {
    let file = fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let read = reader
            .read_until(b'\n', &mut buf)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            return Ok(0);
        }
        if buf.last() != Some(&b'\n') {
            return Ok(buf.len() as u64);
        }
    }
}

/// Recovers the arbitration state from every previous journal segment below
/// `resume_dir` (sorted by name): chain-verifies each segment, validates the
/// resume links, rebuilds the durable trade identity when it lags the
/// journal, and extracts the canonical depth cursor plus the serving lane
/// from the last segment.  Returns `Ok(None)` when the directory holds no
/// previous segments yet (first generation of the service: fresh start).
fn recover_arbitration_state_opt(
    resume_dir: &Path,
    identity_path: &Path,
    new_journal_path: &Path,
) -> Result<Option<RecoveredArbitrationState>> {
    let mut segments: Vec<PathBuf> = fs::read_dir(resume_dir)
        .map_err(|error| format!("read {}: {error}", resume_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        // The new segment being created is not part of the recovered chain.
        .filter(|path| path.as_path() != new_journal_path)
        .collect();
    segments.sort();
    if segments.is_empty() {
        return Ok(None);
    }
    // Torn creations from crashed generations: a zero-byte segment carries
    // no records and no hash chain, so it can never be a valid chain member
    // and must not poison the resume scan ("arbitration journal is empty",
    // fault-gate defect hrs-68826803c27b).  Removing it loses nothing.
    let mut cleaned: Vec<PathBuf> = Vec::with_capacity(segments.len());
    for segment in segments {
        match fs::metadata(&segment) {
            Ok(metadata) if metadata.len() == 0 => {
                fs::remove_file(&segment).map_err(|error| {
                    format!("remove torn empty segment {}: {error}", segment.display())
                })?;
            }
            Ok(_) => cleaned.push(segment),
            Err(error) => {
                return Err(format!(
                    "stat journal segment {}: {error}",
                    segment.display()
                ));
            }
        }
    }
    let segments = cleaned;
    if segments.is_empty() {
        return Ok(None);
    }
    // The shared-state recovery walk: cumulative counters, strict chained
    // contract for every non-final segment, torn-tail tolerance on the
    // last (crash mid-publication).
    let scan = scan_live_arbitration_journal_set_recovery(&segments)?;
    let mut recovered = RecoveredArbitrationState {
        trades: scan.trades,
        depth_frames: scan.depth_frames,
        gaps: scan.gaps,
        late_corrections: scan.late_corrections,
        last_trade_id: scan.last_trade_id,
        startup_trade_floor: scan.trade_floor.unwrap_or(0),
        corrected_identities: BTreeMap::new(),
        journaled_duplicate_corrections: BTreeSet::new(),
        excluded_tail_origins: BTreeSet::new(),
        canonical_position: CanonicalDepthPosition {
            final_sequence: None,
            digest: None,
            gap_floor: None,
        },
        serving_lane: CaptureLane::Primary,
        previous_segment_sha: scan.last_record_sha256.clone(),
        previous_tail_bytes: 0,
    };
    let last_segment = segments.last().expect("segments checked non-empty");
    // Measure the last segment's torn tail (0 when it ended cleanly): the
    // resumed generation declares exactly these bytes.
    recovered.previous_tail_bytes = measure_torn_tail(last_segment)?;
    // Identity, exclusion decisions and the depth cursor belong to the
    // whole validated chain. Read complete byte lines only: a crash may
    // leave an incomplete UTF-8 code point, not merely incomplete JSON.
    for segment in &segments {
        let file = fs::File::open(segment)
            .map_err(|error| format!("open {}: {error}", segment.display()))?;
        let mut reader = std::io::BufReader::new(file);
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader
                .read_until(b'\n', &mut line)
                .map_err(|error| format!("read journal: {error}"))?
                == 0
            {
                break;
            }
            if line.last() != Some(&b'\n') {
                break;
            }
            line.pop();
            if line.is_empty() {
                continue;
            }
            let envelope: serde_json::Value =
                serde_json::from_slice(&line).map_err(|error| format!("journal JSON: {error}"))?;
            let payload = &envelope["body"]["payload"];
            if payload["event"] == "TRADE_LATE_CORRECTION" && payload["kind"] == "unknown" {
                let id = payload["trade_id"]
                    .as_u64()
                    .ok_or("correction identity missing ID")?;
                let digest = payload["observation_sha256"]
                    .as_str()
                    .ok_or("correction identity missing digest")?;
                recovered.corrected_identities.insert(id, digest.to_owned());
            }
            if payload["event"] == "TRADE_LATE_CORRECTION" && payload["kind"] == "duplicate" {
                let id = payload["trade_id"]
                    .as_u64()
                    .ok_or("duplicate correction missing ID")?;
                let lane = payload["lane"]
                    .as_str()
                    .ok_or("duplicate correction missing lane")?;
                let digest = payload["observation_sha256"]
                    .as_str()
                    .ok_or("duplicate correction missing digest")?;
                recovered.journaled_duplicate_corrections.insert((
                    id,
                    lane.to_owned(),
                    digest.to_owned(),
                ));
            }
            if payload["event"] == "TRADE_LAG" && payload["reason"] == "predecessor_lag" {
                if !payload["origin"].is_object() {
                    return Err("predecessor lag missing origin identity".to_owned());
                }
                recovered
                    .excluded_tail_origins
                    .insert(payload["origin"].to_string());
            }
            match payload.get("event").and_then(serde_json::Value::as_str) {
                Some("DEPTH_OBSERVATION") => {
                    recovered.canonical_position.final_sequence = payload
                        .get("final_sequence")
                        .and_then(serde_json::Value::as_u64);
                    recovered.canonical_position.digest = payload
                        .get("observation_sha256")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                }
                Some("GAP") => {
                    recovered.canonical_position = CanonicalDepthPosition {
                        final_sequence: None,
                        digest: None,
                        gap_floor: payload
                            .get("canonical_last_sequence")
                            .and_then(serde_json::Value::as_u64),
                    };
                }
                Some("DEPTH_SWITCH_PROVEN") => {
                    if payload.get("to_lane").and_then(serde_json::Value::as_str) == Some("SHADOW")
                    {
                        recovered.serving_lane = CaptureLane::Shadow;
                    } else {
                        recovered.serving_lane = CaptureLane::Primary;
                    }
                }
                Some("DEPTH_REBOOTSTRAP") => {
                    if payload.get("lane").and_then(serde_json::Value::as_str) == Some("SHADOW") {
                        recovered.serving_lane = CaptureLane::Shadow;
                    } else {
                        recovered.serving_lane = CaptureLane::Primary;
                    }
                }
                _ => {}
            }
        }
    }
    // The recovered trade floor is the cumulative maximum from the
    // shared-state recovery walk above (all segments), not a re-derivation
    // from the last segment alone: the last segment may legitimately hold no
    // TRADE_OBSERVATION records (crash right after a GAP or a correction-only
    // segment), and resetting the floor there would corrupt the resume chain.
    // It is also floored by the declared bind boundary: a crash BEFORE the
    // first trade publication must not drop the STARTED segment's declared
    // trade_floor (fault-gate defect hrs-7c9c792ca38c: the resumed generation
    // re-published the pre-bind region and the closed-set oracle rejected
    // "a trade at or below its declared floor").
    let floor = scan
        .last_trade_id
        .unwrap_or(0)
        .max(scan.trade_floor.unwrap_or(0));
    recovered.last_trade_id = (floor != 0).then_some(floor);
    // Durable identity: open (or create) the log and rebuild any identity
    // the log lost to a crash between the journal and identity writes.
    let mut identity = if identity_path.is_file() {
        TradeIdentityLog::open(identity_path)
    } else {
        TradeIdentityLog::create(identity_path)
    }?;
    if identity.last_id().is_some_and(|last| last > floor) {
        // The durable identity advanced PAST the journal (a crash landed
        // between the identity sync and the journal append): the journal is
        // the source of truth — recreate the log and rebuild it from the
        // journal chain, so the resumed walk can never regress an insert.
        drop(identity);
        fs::remove_file(identity_path).map_err(|error| {
            format!(
                "remove identity log ahead of the journal {}: {error}",
                identity_path.display()
            )
        })?;
        identity = TradeIdentityLog::create(identity_path)?;
    }
    if identity.last_id().is_none_or(|last| last < floor) {
        for segment in &segments {
            rebuild_trade_identity_from_journal(segment, &mut identity)?;
        }
    }
    identity.validate()?;
    drop(identity);
    Ok(Some(recovered))
}

/// Replay mode (ADR-16 integration gate 2): re-derives the canonical live
/// journal over a FINISHED campaign from its chronological generation list —
/// zero omissions by construction (no startup fast-forward, no queue cap),
/// with every depth boundary either contiguity-validated, proven through the
/// sibling's own observations, or typed as a GAP + evidenced
/// DEPTH_REBOOTSTRAP.  The result is independently auditable with the same
/// closed-journal and oracle verifiers.
fn run_replay(symbol: &str, artifact_root: &Path, output_journal: &Path) -> Result<PathBuf> {
    let origin = Instant::now();
    let mut journal = LiveArbitrationJournalWriter::create(output_journal)?;
    let mut union = TradeUnionState::new();
    union.register_lane(CaptureLane::Primary);
    union.register_lane(CaptureLane::Shadow);
    let mut trades_published = 0_u64;
    let mut depth_published = 0_u64;
    let mut gaps_published = 0_u64;
    let mut late_corrections = 0_u64;

    let primary_gens = all_generations(&artifact_root.join("p"))?;
    let shadow_gens = all_generations(&artifact_root.join("s"))?;
    if primary_gens.is_empty() || shadow_gens.is_empty() {
        return Err("replay requires generations on both lanes".to_owned());
    }
    let mut events: Vec<(u64, CaptureLane, usize)> = Vec::new();
    for (index, (_, _, start_ns)) in primary_gens.iter().enumerate() {
        events.push((*start_ns, CaptureLane::Primary, index));
    }
    for (index, (_, _, start_ns)) in shadow_gens.iter().enumerate() {
        events.push((*start_ns, CaptureLane::Shadow, index));
    }
    events.sort_by_key(|(start_ns, _, _)| *start_ns);

    journal.append(
        origin.elapsed().as_nanos() as u64,
        "LIVE",
        serde_json::json!({
            "event": "ARBITRATION_STARTED",
            "symbol": symbol,
            "mode": "REPLAY",
            "primary_generations": primary_gens.len(),
            "shadow_generations": shadow_gens.len(),
            "spec_revision": SPEC_REVISION,
        }),
    )?;

    let mut canonical = CanonicalDepthPosition {
        final_sequence: None,
        digest: None,
        gap_floor: None,
    };
    let mut serving_lane = CaptureLane::Primary;
    // The sibling's FULL observation history across generations: replay is
    // offline, so the convergence evidence is never bounded away.
    let mut history: [Vec<CanonicalObservationV1>; 2] = [Vec::new(), Vec::new()];

    for (_, lane, index) in events {
        let (campaign, generation, _) = if lane == CaptureLane::Primary {
            &primary_gens[index]
        } else {
            &shadow_gens[index]
        };
        let binding = LaneBinding::bind_generation(campaign, generation)?;
        // Trades: exact union, no fast-forward.
        for record in binding.trade.records() {
            let observation = materialize_trade_record(record)?;
            match union.observe(lane, &observation)? {
                TradeUnionDisposition::Publishable(batch) => {
                    for (source_lane, item) in batch {
                        journal.append(
                            origin.elapsed().as_nanos() as u64,
                            "LIVE",
                            serde_json::json!({
                                "event": "TRADE_OBSERVATION",
                                "trade_id": item.final_sequence,
                                "lane": lane_payload(source_lane),
                                "record_sha256": item.record_sha256,
                                "observation_sha256": item.observation_sha256,
                            }),
                        )?;
                        trades_published += 1;
                    }
                }
                TradeUnionDisposition::Late {
                    observation: item,
                    kind,
                } => {
                    journal.append(
                        origin.elapsed().as_nanos() as u64,
                        "LIVE",
                        serde_json::json!({
                            "event": "TRADE_LATE_CORRECTION",
                            "trade_id": item.final_sequence,
                            "lane": lane_payload(lane),
                            "record_sha256": item.record_sha256,
                            "observation_sha256": item.observation_sha256,
                            "kind": match kind {
                                lob_replay::live_arbitration::LateCorrectionKind::Duplicate => "duplicate",
                                lob_replay::live_arbitration::LateCorrectionKind::Unknown => "unknown",
                            },
                        }),
                    )?;
                    late_corrections += 1;
                }
                TradeUnionDisposition::Conflict { trade_id, .. } => {
                    return Err(format!(
                        "redundant lanes delivered conflicting payloads for trade {trade_id}; replay stopped fail-closed"
                    ));
                }
                TradeUnionDisposition::Buffered => {}
            }
        }
        // Depth: only the serving lane publishes; its boundaries are
        // validated, and a gap is bridged exclusively through the sibling's
        // own observations (exact convergence), never invented.
        let observations = materialize_binding_observations(&binding)?;
        history[lane_index(lane)].extend(observations.iter().cloned());
        if lane == serving_lane {
            let mut boundary: Option<(u64, u64)> = None;
            for observation in &observations {
                let expected = canonical.final_sequence.map(|f| f.saturating_add(1));
                match classify_depth_frontier(
                    expected,
                    observation.first_sequence,
                    observation.final_sequence,
                )? {
                    DepthFrontierDisposition::Contiguous
                    | DepthFrontierDisposition::Straddle { .. } => {
                        journal.append(
                            origin.elapsed().as_nanos() as u64,
                            "LIVE",
                            serde_json::json!({
                                "event": "DEPTH_OBSERVATION",
                                "first_sequence": observation.first_sequence,
                                "final_sequence": observation.final_sequence,
                                "lane": lane_payload(serving_lane),
                                "record_sha256": observation.record_sha256,
                                "observation_sha256": observation.observation_sha256,
                            }),
                        )?;
                        canonical.final_sequence = Some(observation.final_sequence);
                        canonical.digest = Some(observation.observation_sha256.clone());
                        depth_published += 1;
                    }
                    DepthFrontierDisposition::Covered { .. } => {}
                    DepthFrontierDisposition::Missing { expected, first } => {
                        boundary = Some((expected, first));
                        break;
                    }
                }
            }
            if let Some((expected, first)) = boundary {
                let sibling = other_lane(serving_lane);
                let sibling_observations = &history[lane_index(sibling)];
                let converged = sibling_observations.iter().any(|observation| {
                    observation.final_sequence == canonical.final_sequence.unwrap_or(0)
                        && observation.observation_sha256
                            == canonical.digest.clone().unwrap_or_default()
                });
                let covered: Vec<&CanonicalObservationV1> = sibling_observations
                    .iter()
                    .filter(|observation| {
                        observation.final_sequence >= expected
                            && observation.first_sequence <= expected
                    })
                    .collect();
                let contiguous = covered
                    .windows(2)
                    .all(|pair| pair[1].first_sequence == pair[0].final_sequence + 1);
                let reaches = covered
                    .last()
                    .is_some_and(|observation| observation.final_sequence >= first);
                // The first bridged frame must begin exactly at the expected
                // update ID: an overlap would duplicate an already-published
                // range and violate the canonical contiguity contract.
                let exact_start = covered
                    .first()
                    .is_some_and(|observation| observation.first_sequence == expected);
                if converged && !covered.is_empty() && contiguous && reaches && exact_start {
                    for observation in &covered {
                        journal.append(
                            origin.elapsed().as_nanos() as u64,
                            "LIVE",
                            serde_json::json!({
                                "event": "DEPTH_OBSERVATION",
                                "first_sequence": observation.first_sequence,
                                "final_sequence": observation.final_sequence,
                                "lane": lane_payload(sibling),
                                "record_sha256": observation.record_sha256,
                                "observation_sha256": observation.observation_sha256,
                            }),
                        )?;
                        canonical.final_sequence = Some(observation.final_sequence);
                        canonical.digest = Some(observation.observation_sha256.clone());
                        depth_published += 1;
                    }
                    journal.append(
                        origin.elapsed().as_nanos() as u64,
                        "LIVE",
                        serde_json::json!({
                            "event": "DEPTH_SWITCH_PROVEN",
                            "from_lane": lane_payload(serving_lane),
                            "to_lane": lane_payload(sibling),
                            "boundary_final_sequence": canonical.final_sequence,
                        }),
                    )?;
                    serving_lane = sibling;
                } else {
                    // Dual-loss boundary: type the gap and re-bootstrap from
                    // this generation's fresh snapshot with explicit evidence.
                    // The reason distinguishes a real dual loss (the sibling
                    // lacks the interval) from a sibling book that exists but
                    // cannot prove convergence (gap-free is not the same as
                    // correct) and from a boundary whose first sibling frame
                    // overlaps the already-published cursor (bridging would
                    // duplicate the boundary range).
                    let reason = if covered.is_empty() || !contiguous || !reaches {
                        "dual_loss"
                    } else if !exact_start {
                        "unprovable_continuation"
                    } else {
                        "sibling_book_diverges"
                    };
                    journal.append(
                        origin.elapsed().as_nanos() as u64,
                        "LIVE",
                        serde_json::json!({
                            "event": "GAP",
                            "stream_kind": "DEPTH",
                            "canonical_last_sequence": canonical.final_sequence.unwrap_or(0),
                            "renewed_lane": lane_payload(serving_lane),
                            "reason": reason,
                        }),
                    )?;
                    gaps_published += 1;
                    let snapshot_last = binding.snapshot_last_update_id()?;
                    journal.append(
                        origin.elapsed().as_nanos() as u64,
                        "LIVE",
                        serde_json::json!({
                            "event": "DEPTH_REBOOTSTRAP",
                            "lane": lane_payload(serving_lane),
                            "generation": binding.generation_id(),
                            "snapshot_last_update_id": snapshot_last,
                            "snapshot_record_sha256": binding
                                .snapshot_path
                                .file_name()
                                .map(|name| name.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                        }),
                    )?;
                    canonical.final_sequence = None;
                    canonical.digest = None;
                    for observation in &observations {
                        journal.append(
                            origin.elapsed().as_nanos() as u64,
                            "LIVE",
                            serde_json::json!({
                                "event": "DEPTH_OBSERVATION",
                                "first_sequence": observation.first_sequence,
                                "final_sequence": observation.final_sequence,
                                "lane": lane_payload(serving_lane),
                                "record_sha256": observation.record_sha256,
                                "observation_sha256": observation.observation_sha256,
                            }),
                        )?;
                        canonical.final_sequence = Some(observation.final_sequence);
                        canonical.digest = Some(observation.observation_sha256.clone());
                        depth_published += 1;
                    }
                }
            }
        }
    }
    // Terminal drain: every lane stream is exhausted, so excluding both
    // lanes releases the watermark and flushes every buffered trade.
    union.exclude_lane(CaptureLane::Primary);
    union.exclude_lane(CaptureLane::Shadow);
    match union.flush()? {
        TradeUnionDisposition::Publishable(batch) => {
            for (source_lane, item) in batch {
                journal.append(
                    origin.elapsed().as_nanos() as u64,
                    "LIVE",
                    serde_json::json!({
                        "event": "TRADE_OBSERVATION",
                        "trade_id": item.final_sequence,
                        "lane": lane_payload(source_lane),
                        "record_sha256": item.record_sha256,
                        "observation_sha256": item.observation_sha256,
                    }),
                )?;
                trades_published += 1;
            }
        }
        TradeUnionDisposition::Buffered => {}
        other => {
            return Err(format!(
                "replay terminal trade drain produced an unexpected disposition: {other:?}"
            ));
        }
    }
    if union.buffered() != 0 {
        return Err("replay trade union retains buffered trades at terminal".to_owned());
    }

    journal.append(
        origin.elapsed().as_nanos() as u64,
        "LIVE",
        serde_json::json!({
            "event": "ARBITRATION_TERMINAL",
            "status": "COMPLETE",
            "trades": trades_published,
            "depth_frames": depth_published,
            "gaps": gaps_published,
            "late_corrections": late_corrections,
            "serving_lane_at_terminal": lane_payload(serving_lane),
        }),
    )?;
    Ok(output_journal.to_path_buf())
}

fn latest_directory(root: &Path) -> Result<PathBuf> {
    latest_directory_opt(root)?.ok_or_else(|| format!("no directory below {}", root.display()))
}

/// Like `latest_directory` but returns `Ok(None)` when the directory has no
/// subdirectories (yet).  A restarted lane publishes its campaign and
/// generation directories in stages, so the arbiter must wait instead of
/// treating a not-yet-created directory as corruption.
fn latest_directory_opt(root: &Path) -> Result<Option<PathBuf>> {
    let mut entries: Vec<PathBuf> = fs::read_dir(root)
        .map_err(|error| format!("read {}: {error}", root.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    entries.sort();
    Ok(entries.pop())
}

fn segment_file_name(index: u64) -> String {
    format!("segment-{index:06}.bnraw")
}

fn progress_file_name(index: u64) -> String {
    format!("segment-{index:06}.bnack")
}

/// Incremental follower for one stream (depth or trade) inside one
/// generation: sealed segments are read once from the manifest authority;
/// the in-flight segment's BNACK-authorized tail is appended through the
/// durability follower without re-reading bytes from zero.  When the manifest
/// seals the in-flight segment, the follower verifies convergence on the seal
/// (exact terminal digest, record count and frame bounds) and advances to the
/// successor segment.  A fresh stream with no sealed segments yet starts from
/// the root segment whose identity is taken from its own verified record
/// chain (ZERO_DIGEST predecessor, frame 0), never invented.
struct StreamFollowState {
    stream_dir: PathBuf,
    stream_suffix: &'static str,
    records: Vec<RawRecordEnvelopeV1>,
    follower: Option<SegmentDurabilityFollower>,
    /// Genesis of the in-flight segment we are currently following.
    genesis: Option<RawSegmentGenesisV1>,
    /// Index of the in-flight segment (equals the manifest's sealed count).
    segment_index: u64,
    /// `records.len()` at the moment the current in-flight segment bound.
    segment_record_start: usize,
    last_durable_offset: u64,
    poisoned: bool,
}

impl StreamFollowState {
    fn open(stream_dir: &Path, stream_suffix: &'static str) -> Result<Self> {
        let manifest_scan = scan_segment_manifest(&stream_dir.join("segments.bnseg"))?;
        let mut state = Self {
            stream_dir: stream_dir.to_path_buf(),
            stream_suffix,
            records: Vec::new(),
            follower: None,
            genesis: None,
            segment_index: 0,
            segment_record_start: 0,
            last_durable_offset: 8,
            poisoned: false,
        };
        let mut previous_seal: Option<lob_replay::RawSegmentSealV1> = None;
        for entry in &manifest_scan.entries {
            let seal = &entry.seal;
            if seal.segment_index != state.segment_index {
                return Err("segment manifest seal index discontinuity".to_owned());
            }
            let read_genesis = match &previous_seal {
                None => root_segment_genesis(&seal.connection_epoch, &seal.stream)?,
                Some(previous) => {
                    let genesis = successor_segment_genesis(previous)?;
                    if genesis.previous_segment_terminal_sha256
                        != seal.previous_segment_terminal_sha256
                    {
                        return Err("segment manifest seal chain is discontinuous".to_owned());
                    }
                    genesis
                }
            };
            let raw_path = stream_dir.join(&seal.raw_file);
            state.records.extend(
                read_raw_segment_records(&raw_path, &read_genesis)
                    .map_err(|error| format!("sealed segment {}: {error}", seal.raw_file))?,
            );
            state.genesis = Some(successor_segment_genesis(seal)?);
            state.segment_index = seal.segment_index.saturating_add(1);
            state.segment_record_start = state.records.len();
            previous_seal = Some(seal.clone());
        }
        // The in-flight segment is exactly `segment_index`; bind it when its
        // raw file and durability journal already exist.
        state.try_bind_follower()?;
        Ok(state)
    }

    /// Depth follower with no records. Used only when a terminal FAILED
    /// generation has no snapshot and its depth stream cannot be bound;
    /// trade records of that generation stay readable.
    fn unbound(stream_dir: &Path, stream_suffix: &'static str) -> Self {
        Self {
            stream_dir: stream_dir.to_path_buf(),
            stream_suffix,
            records: Vec::new(),
            follower: None,
            genesis: None,
            segment_index: 0,
            segment_record_start: 0,
            last_durable_offset: 8,
            poisoned: false,
        }
    }

    /// Appends newly BNACK-authorized records and follows segment seals.
    /// Returns the number of new durable records.  Any corruption poisons
    /// this follower.
    fn refresh(&mut self) -> Result<usize> {
        if self.poisoned {
            return Err("stream follower is poisoned".to_owned());
        }
        let mut appended_total = 0_usize;
        loop {
            if self.follower.is_none() && !self.try_bind_follower()? {
                return Ok(appended_total);
            }
            let durable_offset = {
                let follower = self
                    .follower
                    .as_mut()
                    .ok_or_else(|| "stream follower is missing".to_owned())?;
                let poll = match follower.poll() {
                    Ok(poll) => poll,
                    Err(error) => {
                        self.poisoned = true;
                        return Err(error);
                    }
                };
                poll.cursor.raw_offset
            };
            if durable_offset < self.last_durable_offset {
                self.poisoned = true;
                return Err("in-flight durable offset regressed".to_owned());
            }
            if durable_offset > self.last_durable_offset {
                appended_total += self.extend_in_flight(durable_offset)?;
            }
            // Rotation: when the manifest seals the segment we are
            // following, verify convergence on the seal and advance to the
            // successor.  An unclean manifest tail (torn mid-append read) is
            // retried on the next poll, exactly like the BNACK durability
            // model reads only the verified prefix.
            let manifest = scan_segment_manifest(&self.stream_dir.join("segments.bnseg"))?;
            if !manifest.clean_eof {
                return Ok(appended_total);
            }
            let sealed_count = manifest.entries.len() as u64;
            if sealed_count <= self.segment_index {
                return Ok(appended_total);
            }
            let mut advanced = false;
            while self.segment_index < sealed_count {
                let entry = &manifest.entries[self.segment_index as usize];
                let seal = &entry.seal;
                if seal.segment_index != self.segment_index {
                    self.poisoned = true;
                    return Err("segment manifest seal index discontinuity".to_owned());
                }
                let genesis = match &self.genesis {
                    Some(genesis) => genesis.clone(),
                    None => {
                        let root = root_segment_genesis(&seal.connection_epoch, &seal.stream)?;
                        self.genesis = Some(root.clone());
                        root
                    }
                };
                if seal.previous_segment_terminal_sha256 != genesis.previous_segment_terminal_sha256
                    || seal.connection_epoch != genesis.connection_epoch
                    || seal.stream != genesis.stream
                {
                    self.poisoned = true;
                    return Err("segment manifest seal diverges from the followed chain".to_owned());
                }
                if seal.durable_through_offset < self.last_durable_offset {
                    self.poisoned = true;
                    return Err("segment seal durable offset regressed".to_owned());
                }
                if seal.durable_through_offset > self.last_durable_offset {
                    appended_total += self.extend_in_flight(seal.durable_through_offset)?;
                }
                // Exact convergence: the finished segment must equal the
                // manifest seal byte for byte at the durable boundary.
                let terminal = if self.records.len() == self.segment_record_start {
                    genesis.previous_segment_terminal_sha256.clone()
                } else {
                    self.records
                        .last()
                        .map(|record| record.record_sha256.clone())
                        .unwrap_or_default()
                };
                let segment_records = (self.records.len() - self.segment_record_start) as u64;
                let first_frame = self
                    .records
                    .get(self.segment_record_start)
                    .map(|record| record.frame.frame_index);
                let last_frame = self.records.last().map(|record| record.frame.frame_index);
                if terminal != seal.terminal_record_sha256
                    || segment_records != seal.records
                    || first_frame != Some(seal.first_frame_index)
                    || last_frame != Some(seal.last_frame_index)
                {
                    self.poisoned = true;
                    return Err("sealed segment does not converge on the manifest seal".to_owned());
                }
                self.genesis = Some(successor_segment_genesis(seal)?);
                self.segment_index = seal.segment_index.saturating_add(1);
                self.segment_record_start = self.records.len();
                self.follower = None;
                self.last_durable_offset = 8;
                advanced = true;
            }
            if advanced {
                continue;
            }
            return Ok(appended_total);
        }
    }

    /// Binds the durability follower to the in-flight segment when its raw
    /// file and BNACK journal both exist.  The root segment derives its
    /// identity from its own verified record chain; successors use the
    /// manifest-derived genesis.
    fn try_bind_follower(&mut self) -> Result<bool> {
        let raw_path = self.stream_dir.join(segment_file_name(self.segment_index));
        let progress_path = self.stream_dir.join(progress_file_name(self.segment_index));
        if !raw_path.is_file() || !progress_path.is_file() {
            return Ok(false);
        }
        if self.genesis.is_none() {
            let probe = read_raw_records(&raw_path)
                .map_err(|error| format!("probe root segment identity: {error}"))?;
            let first = probe
                .first()
                .ok_or_else(|| "root segment has no records yet".to_owned())?;
            if !first.frame.stream.contains(self.stream_suffix) {
                return Err("root segment stream suffix mismatch".to_owned());
            }
            self.genesis = Some(root_segment_genesis(
                &first.frame.connection_epoch,
                &first.frame.stream,
            )?);
        }
        let genesis = self
            .genesis
            .as_ref()
            .ok_or_else(|| "in-flight follower lost its genesis".to_owned())?
            .clone();
        // The BNACK journal stores the raw file as its portable bare name;
        // bind the follower to that exact reference.
        let raw_name = segment_file_name(self.segment_index);
        let mut opened = SegmentDurabilityFollower::open_with_reference(
            &progress_path,
            &raw_path,
            &genesis,
            &raw_name,
        )?;
        let poll = opened.poll()?;
        let durable_offset = poll.cursor.raw_offset;
        if durable_offset < 8 {
            return Err("in-flight durable offset before magic".to_owned());
        }
        self.follower = Some(opened);
        self.last_durable_offset = 8;
        self.segment_record_start = self.records.len();
        if durable_offset > 8 {
            self.extend_in_flight(durable_offset)?;
        }
        Ok(true)
    }

    /// Chain-verifies and appends the durable range
    /// `[last_durable_offset, end_offset)` of the in-flight segment.
    fn extend_in_flight(&mut self, end_offset: u64) -> Result<usize> {
        let genesis = self
            .genesis
            .as_ref()
            .ok_or_else(|| "in-flight follower lost its genesis".to_owned())?;
        let previous = self
            .records
            .last()
            .map(|record| record.record_sha256.clone())
            .unwrap_or_else(|| genesis.previous_segment_terminal_sha256.clone());
        let next_frame_index = self
            .records
            .last()
            .map(|record| record.frame.frame_index.saturating_add(1))
            .unwrap_or(genesis.next_frame_index);
        let raw_path = self.stream_dir.join(segment_file_name(self.segment_index));
        let appended = read_raw_record_range(
            &raw_path,
            self.last_durable_offset,
            end_offset,
            &previous,
            &genesis.connection_epoch,
            &genesis.stream,
            next_frame_index,
        )
        .inspect_err(|_| self.poisoned = true)?;
        let count = appended.len();
        self.records.extend(appended);
        self.last_durable_offset = end_offset;
        Ok(count)
    }

    fn records(&self) -> &[RawRecordEnvelopeV1] {
        &self.records
    }

    /// True when this follow state has converged on the stream's SEALED
    /// TERMINAL evidence (ADR-17 boundary authority, review 2026-09-11
    /// risk 2): the generation declared COMPLETE, the follower processed
    /// the final manifest seal (segment_index advanced past it), and the
    /// in-memory chain equals that same terminal cut — count, terminal
    /// digest and last frame index.  A consumer comparing a stale snapshot
    /// length against a seal that grew in between would retire the stream
    /// early and lose the final records; only this exact-terminal test
    /// authorizes "nothing more can ever arrive".
    fn consumed_sealed_terminal(&self) -> Result<bool> {
        let generation_dir = self.stream_dir.parent().ok_or_else(|| {
            format!(
                "stream dir {} has no generation parent",
                self.stream_dir.display()
            )
        })?;
        if !generation_terminal_complete(generation_dir)? {
            return Ok(false);
        }
        let manifest = scan_segment_manifest(&self.stream_dir.join("segments.bnseg"))?;
        let Some(last) = manifest.entries.last() else {
            return Ok(false);
        };
        if self.segment_index <= last.seal.segment_index {
            // The final seal has not been processed yet.
            return Ok(false);
        }
        let total: u64 = manifest
            .entries
            .iter()
            .map(|entry| entry.seal.records)
            .sum();
        if self.records.is_empty() {
            // A genuinely empty sealed stream has nothing left to consume:
            // the seal chain was processed and proves the emptiness.
            return Ok(total == 0);
        }
        if self.records.len() as u64 != total {
            return Ok(false);
        }
        if self
            .records
            .last()
            .map(|record| record.record_sha256.clone())
            != Some(last.seal.terminal_record_sha256.clone())
            || self.records.last().map(|record| record.frame.frame_index)
                != Some(last.seal.last_frame_index)
        {
            return Ok(false);
        }
        Ok(true)
    }
}

struct LaneBinding {
    generation_dir: PathBuf,
    snapshot_path: PathBuf,
    depth: StreamFollowState,
    trade: StreamFollowState,
    depth_consumed: usize,
    trade_consumed: usize,
    /// This lane's own verified incremental depth cursor.
    depth_cursor: Option<DepthObservationCursor>,
    /// Observations applied to this lane's cursor but not yet published by
    /// the canonical view (bounded; the overflow drops only frames that are
    /// duplicates of already-published ones or precede any provable switch).
    pending_depth: VecDeque<CanonicalObservationV1>,
    /// Exact consumed boundary evidence, independent of unpublished work.
    /// A binding owns one generation, so replacement invalidates the witness.
    depth_convergence_witness: Option<CanonicalObservationV1>,
    depth_switch_replay: Option<DepthSwitchReplay>,
    depth_switch_pending: bool,
}

impl LaneBinding {
    fn bind(lane_root: &Path) -> Result<Self> {
        let campaign = latest_directory(lane_root)?;
        let generation = latest_directory(&campaign.join("generations"))?;
        let mut binding = Self::bind_generation(&campaign, &generation)?;
        binding.bootstrap_depth()?;
        Ok(binding)
    }

    /// Binds one EXPLICIT generation (replay mode walks the chronological
    /// generation list instead of always taking the latest).  The replay
    /// only materializes whole generations, so it skips the incremental
    /// depth-cursor bootstrap (O(prefix) digest work that the live path
    /// needs but the replay does not).
    fn bind_generation(_campaign: &Path, generation: &Path) -> Result<Self> {
        let snapshot_path = generation.join("snapshot.bnraw");
        let failed_without_snapshot =
            !snapshot_path.is_file() && generation_terminal_failed_without_snapshot(generation)?;
        if !snapshot_path.is_file() && !failed_without_snapshot {
            return Err("lane generation lacks a snapshot".to_owned());
        }
        let depth = match StreamFollowState::open(&generation.join("depth"), "@depth") {
            Ok(depth) => depth,
            Err(_) if failed_without_snapshot => {
                StreamFollowState::unbound(&generation.join("depth"), "@depth")
            }
            Err(error) => return Err(error),
        };
        let trade = StreamFollowState::open(&generation.join("trade"), "@trade")?;
        Ok(Self {
            generation_dir: generation.to_path_buf(),
            snapshot_path,
            depth,
            trade,
            depth_consumed: 0,
            trade_consumed: 0,
            depth_cursor: None,
            pending_depth: VecDeque::new(),
            depth_convergence_witness: None,
            depth_switch_replay: None,
            depth_switch_pending: false,
        })
    }

    /// Builds this lane's verified depth cursor over its current durable
    /// prefix; the prefix itself is silently consumed (it precedes the
    /// arbiter's own start and is never republished).
    fn bootstrap_depth(&mut self) -> Result<()> {
        self.depth_switch_replay = None;
        self.depth_switch_pending = false;
        self.depth_convergence_witness = None;
        let snapshots = read_raw_records(&self.snapshot_path)?;
        if snapshots.len() != 1 {
            return Err("depth snapshot must contain exactly one record".to_owned());
        }
        // ADR-17 B3 fix (full-gate defect hrs-04e9f268cc0c): a segment
        // rotation can land between the follower's last poll and this call,
        // so the in-memory record vector may lag the manifest.  The manifest
        // is the authority for sealed segments: synchronize the follow state
        // (processing every completed rotation) BEFORE the cursor is derived
        // and the trail is sliced, so a freshly sealed root can never appear
        // shorter than the manifest declares.  A torn manifest (writer
        // mid-append) is retried briefly; the raw file behind a completed
        // seal is fully durable by contract, so the refresh that follows a
        // clean scan always covers the sealed root.  When the manifest never
        // stabilizes — the writer DIED mid-append (a killed lane at the
        // epoch boundary) — the VERIFIED PREFIX is accepted after the
        // bounded deadline instead of failing the bind forever: the prefix
        // is exactly the sealed evidence the closed oracle reads, and a
        // later seal (a live writer) is picked up by the incremental
        // refresh/cursor apply anyway (fault-gate defect hrs-1d4b237ce864:
        // the successor generation could never bind because its depth
        // manifest stayed torn, and the canonical depth ended one update
        // short of the trusted end).
        let sync_deadline = Instant::now() + Duration::from_secs(10);
        let mut sync_attempts = 0_u32;
        loop {
            sync_attempts = sync_attempts.saturating_add(1);
            if sync_attempts > 512 {
                return Err("depth segment manifest never synchronized".to_owned());
            }
            let scan =
                scan_segment_manifest(&self.generation_dir.join("depth").join("segments.bnseg"))?;
            if !scan.clean_eof {
                if Instant::now() < sync_deadline {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                // The writer died mid-append: the VERIFIED PREFIX is the
                // complete sealed evidence (the closed oracle reads the same
                // prefix); a live writer's later seals are picked up by the
                // incremental refresh/apply in the main loop.
                break;
            }
            if (scan.entries.len() as u64) <= self.depth.segment_index {
                break;
            }
            self.depth.refresh()?;
        }
        let manifest =
            scan_segment_manifest(&self.generation_dir.join("depth").join("segments.bnseg"))?;
        let (cursor, trail) = match manifest.entries.first() {
            Some(root) => {
                let root_records = root.seal.records as usize;
                let all_records = self.depth.records().to_vec();
                if all_records.len() < root_records {
                    return Err("depth durable prefix is shorter than the sealed root".to_owned());
                }
                let mut cursor = DepthObservationCursor::from_durable_prefix(
                    &self.snapshot_path,
                    &self.generation_dir.join("depth").join(&root.seal.raw_file),
                    root.seal.durable_through_offset,
                )?;
                let mut trail = VecDeque::new();
                for record in &all_records[root_records..] {
                    if let Some(observation) = cursor.apply_record(record)? {
                        trail.push_back(observation);
                    }
                }
                self.depth_consumed = all_records.len();
                (cursor, trail)
            }
            None => {
                // No sealed root yet: the whole durable prefix is the
                // in-flight root segment, whose own verified record chain
                // starts at ZERO_DIGEST with frame 0.
                let root_path = self.generation_dir.join("depth").join(segment_file_name(0));
                let cursor = DepthObservationCursor::from_durable_prefix(
                    &self.snapshot_path,
                    &root_path,
                    self.depth.last_durable_offset,
                )?;
                self.depth_consumed = self.depth.records().len();
                (cursor, VecDeque::new())
            }
        };
        self.depth_cursor = Some(cursor);
        // Keep only the bounded digest trail as pending history; these
        // frames precede the canonical start and must not be published.
        self.pending_depth = trail;
        Ok(())
    }

    fn refresh(&mut self) -> Result<()> {
        self.depth.refresh()?;
        self.trade.refresh()?;
        Ok(())
    }

    /// Applies this lane's new durable depth records to its own cursor,
    /// appending the observations to the pending queue.  NEVER trims here:
    /// trimming is a caller decision made with the canonical position in
    /// hand (`trim_pending_depth`), so no un-published observation can be
    /// discarded by a queue limit.
    fn apply_new_depth(&mut self) -> Result<usize> {
        let mut applied = 0;
        let started = Instant::now();
        let mut processed = 0;
        while self.depth_consumed < self.depth.records().len()
            && processed < DEPTH_SWITCH_RECORD_BUDGET
            && (processed == 0 || started.elapsed() < DEPTH_SWITCH_TIME_BUDGET)
        {
            let record = self.depth.records()[self.depth_consumed].clone();
            self.depth_consumed += 1;
            let cursor = self
                .depth_cursor
                .as_mut()
                .ok_or_else(|| "lane depth cursor is uninitialized".to_owned())?;
            if let Some(observation) = cursor.apply_record(&record)? {
                self.pending_depth.push_back(observation);
                applied += 1;
            }
            processed += 1;
        }
        Ok(applied)
    }

    fn trim_depth_history(&mut self, canonical_final: u64, gap_floor: Option<u64>) {
        if let Some(witness) = self
            .pending_depth
            .iter()
            .find(|observation| observation.final_sequence == canonical_final)
        {
            self.depth_convergence_witness = Some(witness.clone());
        } else if self
            .depth_convergence_witness
            .as_ref()
            .is_some_and(|witness| witness.final_sequence != canonical_final)
        {
            self.depth_convergence_witness = None;
        }
        if self
            .depth_convergence_witness
            .as_ref()
            .is_some_and(|witness| gap_floor.is_some_and(|floor| witness.final_sequence <= floor))
        {
            self.depth_convergence_witness = None;
        }
        trim_pending_depth(&mut self.pending_depth, canonical_final);
        trim_pending_depth_floor(&mut self.pending_depth, gap_floor);
    }

    /// The snapshot's `lastUpdateId` (the book state this generation starts
    /// from), used as journal evidence for bootstrapping records.
    fn snapshot_last_update_id(&self) -> Result<u64> {
        let snapshots = read_raw_records(&self.snapshot_path)?;
        if snapshots.len() != 1 {
            return Err("depth snapshot must contain exactly one record".to_owned());
        }
        let value: serde_json::Value = serde_json::from_slice(&snapshots[0].frame.payload)
            .map_err(|error| format!("parse depth snapshot payload: {error}"))?;
        value["lastUpdateId"]
            .as_u64()
            .ok_or_else(|| "depth snapshot lacks lastUpdateId".to_owned())
    }

    fn generation_id(&self) -> String {
        self.generation_dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

struct CanonicalDepthPosition {
    final_sequence: Option<u64>,
    digest: Option<String>,
    /// The last typed GAP cursor: after a gap no frame may publish at or
    /// below this boundary (even when a fresh generation's stream starts
    /// before it), so the post-gap publication can never regress.
    gap_floor: Option<u64>,
}

/// Drops every pending frame whose range starts at or below the typed gap
/// floor: those update IDs are covered by the GAP declaration and must
/// never be republished.
fn trim_pending_depth_floor(
    pending: &mut VecDeque<CanonicalObservationV1>,
    gap_floor: Option<u64>,
) {
    if let Some(floor) = gap_floor {
        while pending
            .front()
            .is_some_and(|observation| observation.first_sequence <= floor)
        {
            pending.pop_front();
        }
    }
}

// Scheduling quotas for exact depth application and switch proof. They do
// not bound snapshot/raw I/O, one book digest or journal sync latency.
const DEPTH_SWITCH_RECORD_BUDGET: usize = 128;
const DEPTH_SWITCH_TIME_BUDGET: Duration = Duration::from_millis(10);

/// One binding owns one snapshot and generation. The replay cursor survives
/// polls; exhausting a quota is PENDING, never evidence of divergence.
struct DepthSwitchReplay {
    cursor: DepthObservationCursor,
    consumed: usize,
    target: u64,
    witness: Option<CanonicalObservationV1>,
    tail: VecDeque<CanonicalObservationV1>,
}

fn replay_sibling_slice(
    binding: &mut LaneBinding,
    canonical_final: u64,
    canonical_digest: &str,
    record_budget: usize,
) -> Result<Option<Vec<CanonicalObservationV1>>> {
    binding.depth_switch_pending = false;
    if binding
        .depth_switch_replay
        .as_ref()
        .is_some_and(|replay| replay.target > canonical_final)
    {
        binding.depth_switch_replay = None;
    }
    if binding.depth_switch_replay.is_none() {
        let snapshots = read_raw_records(&binding.snapshot_path)?;
        if snapshots.len() != 1 {
            return Err("sibling depth snapshot must contain exactly one record".to_owned());
        }
        let Some(first) = binding.depth.records().first() else {
            return Ok(None);
        };
        binding.depth_switch_replay = Some(DepthSwitchReplay {
            cursor: DepthObservationCursor::from_snapshot(&snapshots[0], first)?,
            consumed: 0,
            target: canonical_final,
            witness: None,
            tail: VecDeque::new(),
        });
    }
    let replay = binding
        .depth_switch_replay
        .as_mut()
        .expect("replay initialized");
    // At most one previous slice is retained. A new canonical position may
    // consume it but never silently discards work above the new position.
    replay.target = canonical_final;
    if replay
        .witness
        .as_ref()
        .is_some_and(|obs| obs.final_sequence != canonical_final)
    {
        replay.witness = None;
    }
    while replay
        .tail
        .front()
        .is_some_and(|obs| obs.final_sequence <= canonical_final)
    {
        let observation = replay.tail.pop_front().expect("front just checked");
        if observation.final_sequence == canonical_final {
            replay.witness = Some(observation);
        }
    }
    let started = Instant::now();
    let mut processed = 0;
    while replay.consumed < binding.depth.records().len()
        && processed < record_budget
        && (processed == 0 || started.elapsed() < DEPTH_SWITCH_TIME_BUDGET)
        && replay.tail.len() < DEPTH_SWITCH_RECORD_BUDGET
    {
        let record = &binding.depth.records()[replay.consumed];
        if replay.consumed > 0
            && binding.depth.records()[replay.consumed - 1]
                .frame
                .frame_index
                .checked_add(1)
                != Some(record.frame.frame_index)
        {
            return Err("sibling replay frame gap or duplicate".to_owned());
        }
        if let Some(observation) = replay.cursor.apply_record(record)? {
            if observation.final_sequence == canonical_final {
                replay.witness = Some(observation);
            } else if observation.final_sequence > canonical_final {
                replay.tail.push_back(observation);
            }
        }
        replay.consumed += 1;
        processed += 1;
    }
    let converged = replay
        .witness
        .as_ref()
        .is_some_and(|obs| obs.observation_sha256 == canonical_digest);
    if converged && !replay.tail.is_empty() {
        // Transfer the exact replay cursor to the binding. Unprocessed raw
        // records remain owned and apply_new_depth resumes them in slices;
        // a truncated returned tail must never skip the historical remainder.
        let replay = binding
            .depth_switch_replay
            .take()
            .expect("replay initialized");
        let tail = replay.tail.iter().cloned().collect();
        binding.depth_consumed = replay.consumed;
        binding.depth_cursor = Some(replay.cursor);
        binding.depth_convergence_witness = replay.witness;
        binding.pending_depth = replay.tail;
        return Ok(Some(tail));
    }
    // Once an observation passed the target, no later monotone observation
    // can establish an exact boundary that was absent or had another digest.
    binding.depth_switch_pending =
        replay.tail.is_empty() && replay.consumed < binding.depth.records().len();
    Ok(None)
}

/// Dual-loss boundary: publishes the typed gap with the REAL canonical
/// cursor and re-bootstraps the canonical depth from the renewed lane
/// generation's fresh snapshot, recording the bootstrap activation with its
/// exact snapshot/generation evidence.
#[allow(clippy::too_many_arguments)]
fn gap_and_bootstrap_depth(
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    lane: CaptureLane,
    binding: &mut LaneBinding,
    canonical_position: &mut CanonicalDepthPosition,
    depth_published: &mut u64,
    gaps_published: &mut u64,
) -> Result<()> {
    let canonical_last = canonical_position.final_sequence.unwrap_or(0);
    binding.bootstrap_depth()?;
    // Drop every trail frame that starts at or before the gap boundary: its
    // coverage overlaps the already-published range and must never be
    // republished (the typed GAP declares the unexposed interval; the fresh
    // publication starts at the first whole frame strictly after the
    // cursor).  The floor persists on the canonical position: later-arriving
    // stale frames are dropped by the publisher for the rest of the segment.
    trim_pending_depth_floor(&mut binding.pending_depth, Some(canonical_last));
    // ADR-17 B5 honest-empty bootstrap: a typed GAP + DEPTH_REBOOTSTRAP with
    // nothing publishable after it is NOT a boundary when the fresh
    // generation's stream is FINAL and holds no frame beyond the canonical
    // cursor — the canonical position already IS the trusted end of the
    // window.  Skip the boundary records instead of emitting a rebootstrap
    // the closed verifier would (correctly) reject for lacking a following
    // frame (fault-gate defect hrs-a69b916cd0ea resume probe).  A LIVE
    // stream still types the boundary: its frames arrive later and publish
    // after the rebootstrap, so the journal never ends mid-boundary.
    let publishable = binding
        .pending_depth
        .iter()
        .any(|observation| observation.first_sequence > canonical_last);
    if !publishable && stream_fully_sealed(&binding.generation_dir.join("depth"))? {
        return Ok(());
    }
    journal.append(
        origin.elapsed().as_nanos() as u64,
        "LIVE",
        serde_json::json!({
            "event": "GAP",
            "stream_kind": "DEPTH",
            "canonical_last_sequence": canonical_last,
            "renewed_lane": lane_payload(lane),
            "reason": "unprovable_continuation",
        }),
    )?;
    *gaps_published += 1;
    let snapshot_last = binding.snapshot_last_update_id()?;
    journal.append(
        origin.elapsed().as_nanos() as u64,
        "LIVE",
        serde_json::json!({
            "event": "DEPTH_REBOOTSTRAP",
            "lane": lane_payload(lane),
            "generation": binding.generation_id(),
            "snapshot_last_update_id": snapshot_last,
            "snapshot_record_sha256": binding
                .snapshot_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
        }),
    )?;
    // The typed GAP already recorded the real boundary; the fresh bootstrap
    // starts a NEW book from the generation's snapshot, so the canonical
    // position resets here (the first frame is a legal post-bootstrap
    // straddle, never a continuation of the previous cursor) while the gap
    // floor persists so no later frame can regress below the boundary.
    canonical_position.final_sequence = None;
    canonical_position.digest = None;
    canonical_position.gap_floor = Some(canonical_last);
    match publish_pending_depth(
        journal,
        origin,
        lane,
        binding,
        canonical_position,
        depth_published,
    )? {
        DepthPublishOutcome::Published(_) => Ok(()),
        DepthPublishOutcome::GapDetected { expected, first } => Err(format!(
            "post-bootstrap publication cannot continue: expected update {expected}, lane held {first}"
        )),
    }
}

/// Outcome of a frontier-validated pending publication.
enum DepthPublishOutcome {
    Published(u64),
    /// The lane's next frame jumps over the canonical cursor: updates are
    /// missing from this lane and the caller must switch or type a gap.
    GapDetected {
        expected: u64,
        first: u64,
    },
}

/// Publishes every pending observation of one lane that lies beyond the
/// canonical position, validating each frontier BEFORE anything persists
/// (zero loss, zero duplication, zero unproven jumps).
fn publish_pending_depth(
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    lane: CaptureLane,
    binding: &mut LaneBinding,
    canonical_position: &mut CanonicalDepthPosition,
    depth_published: &mut u64,
) -> Result<DepthPublishOutcome> {
    let mut published = 0_u64;
    let started = Instant::now();
    let mut processed = 0;
    while let Some(front) = binding.pending_depth.front() {
        if processed >= DEPTH_SWITCH_RECORD_BUDGET
            || (processed > 0 && started.elapsed() >= DEPTH_SWITCH_TIME_BUDGET)
        {
            break;
        }
        processed += 1;
        let expected = canonical_position
            .final_sequence
            .map(|sequence| sequence.saturating_add(1));
        if let Some(floor) = canonical_position.gap_floor {
            // After a typed GAP, every frame at or below the boundary is
            // covered by the GAP declaration: drop it (never republish), so
            // the post-gap stream can never regress.
            if front.first_sequence <= floor {
                binding.pending_depth.pop_front();
                continue;
            }
        }
        match classify_depth_frontier(expected, front.first_sequence, front.final_sequence)? {
            DepthFrontierDisposition::Contiguous | DepthFrontierDisposition::Straddle { .. } => {
                let observation = binding.pending_depth.pop_front().expect("front just seen");
                journal.append(
                    origin.elapsed().as_nanos() as u64,
                    "LIVE",
                    serde_json::json!({
                        "event": "DEPTH_OBSERVATION",
                        "first_sequence": observation.first_sequence,
                        "final_sequence": observation.final_sequence,
                        "lane": lane_payload(lane),
                        "record_sha256": observation.record_sha256,
                        "observation_sha256": observation.observation_sha256,
                    }),
                )?;
                canonical_position.final_sequence = Some(observation.final_sequence);
                canonical_position.digest = Some(observation.observation_sha256);
                published += 1;
            }
            DepthFrontierDisposition::Covered { .. } => {
                // Already covered by the canonical position: a duplicate of
                // already-published coverage (never of un-published data).
                binding.pending_depth.pop_front();
            }
            DepthFrontierDisposition::Missing { expected, first } => {
                // Updates are missing from this lane: do NOT publish, do NOT
                // drop anything; the caller resolves via a proven switch or a
                // typed gap.
                *depth_published += published;
                return Ok(DepthPublishOutcome::GapDetected { expected, first });
            }
        }
    }
    *depth_published += published;
    Ok(DepthPublishOutcome::Published(published))
}

/// Bounded startup retry: a freshly launched campaign publishes its snapshot,
/// segment files and BNACK journals in stages, so the initial bind retries
/// transient mid-write states instead of failing closed on a legal prefix.
fn bind_with_retry(lane_root: &Path, deadline: Instant) -> Result<LaneBinding> {
    let mut attempts = 0_u32;
    loop {
        match LaneBinding::bind(lane_root) {
            Ok(binding) => return Ok(binding),
            Err(error) => {
                attempts += 1;
                if attempts >= 120 || Instant::now() >= deadline {
                    return Err(format!("initial lane bind never succeeded: {error}"));
                }
            }
        }
        std::thread::sleep(POLL);
    }
}

/// Feeds one lane's new durable trade records (predecessor first, then a
/// bound candidate's fresh-generation records) through the exact union and
/// writes every publication disposition to the canonical journal.  The
/// tail walkers feed even earlier (in `sync_tail_walkers`, the
/// generation-resolution section) so the lane's union cursor advances in
/// raw order across generation handovers.
#[allow(clippy::too_many_arguments)]
fn feed_lane_trades(
    lane: CaptureLane,
    binding: &mut LaneBinding,
    candidate: &mut Option<LaneBinding>,
    union: &mut TradeUnionState,
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    trades_published: &mut u64,
    late_corrections: &mut u64,
    advance: &mut bool,
) -> Result<()> {
    for source in [Some(binding), candidate.as_mut()].into_iter().flatten() {
        while source.trade_consumed < source.trade.records().len() {
            let record = source.trade.records()[source.trade_consumed].clone();
            source.trade_consumed += 1;
            let observation = materialize_trade_record(&record)?;
            observe_trade(
                lane,
                observation,
                union,
                journal,
                origin,
                trades_published,
                late_corrections,
                None,
            )?;
            *advance = true;
        }
    }
    Ok(())
}

/// Writes one drained publication batch into the canonical journal (shared
/// by the live observation path, the post-clamp drain and the terminal
/// flush).
fn publish_trade_batch(
    batch: Vec<(CaptureLane, CanonicalObservationV1)>,
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    trades_published: &mut u64,
) -> Result<()> {
    for (source_lane, item) in batch {
        journal.append(
            origin.elapsed().as_nanos() as u64,
            "LIVE",
            serde_json::json!({
                "event": "TRADE_OBSERVATION",
                "trade_id": item.final_sequence,
                "lane": lane_payload(source_lane),
                "record_sha256": item.record_sha256,
                "observation_sha256": item.observation_sha256,
            }),
        )?;
        *trades_published += 1;
    }
    Ok(())
}

/// A duplicate already durable in the recovered journal is not new evidence.
/// Returns true only the first time this trade, lane and digest are seen.
fn duplicate_correction_is_new(
    known: &mut BTreeSet<(u64, String, String)>,
    trade_id: u64,
    lane: &str,
    digest: &str,
) -> bool {
    known.insert((trade_id, lane.to_owned(), digest.to_owned()))
}

/// Observes one materialized trade through the union and journals every
/// disposition (publication, typed late correction, or a fail-closed
/// conflict).  Shared by the live feed and the resume historical walk so
/// both paths emit identical records.  The historical walk passes the
/// duplicates already recovered from the journal; the live feed passes
/// `None` and still records the first corroboration.
#[allow(clippy::too_many_arguments)]
fn observe_trade(
    lane: CaptureLane,
    observation: CanonicalObservationV1,
    union: &mut TradeUnionState,
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    trades_published: &mut u64,
    late_corrections: &mut u64,
    known_duplicates: Option<&mut BTreeSet<(u64, String, String)>>,
) -> Result<()> {
    match union.observe(lane, &observation)? {
        TradeUnionDisposition::Publishable(batch) => {
            publish_trade_batch(batch, journal, origin, trades_published)?;
        }
        TradeUnionDisposition::Late {
            observation: item,
            kind,
        } => {
            let journal_correction = match kind {
                lob_replay::live_arbitration::LateCorrectionKind::Duplicate => {
                    match known_duplicates {
                        Some(known) => duplicate_correction_is_new(
                            known,
                            item.final_sequence,
                            lane.as_str(),
                            &item.observation_sha256,
                        ),
                        None => true,
                    }
                }
                lob_replay::live_arbitration::LateCorrectionKind::Unknown => true,
            };
            if !journal_correction {
                return Ok(());
            }
            journal.append(
                origin.elapsed().as_nanos() as u64,
                "LIVE",
                serde_json::json!({
                    "event": "TRADE_LATE_CORRECTION",
                    "trade_id": item.final_sequence,
                    "lane": lane_payload(lane),
                    "record_sha256": item.record_sha256,
                    "observation_sha256": item.observation_sha256,
                    "kind": match kind {
                        lob_replay::live_arbitration::LateCorrectionKind::Duplicate => "duplicate",
                        lob_replay::live_arbitration::LateCorrectionKind::Unknown => "unknown",
                    },
                }),
            )?;
            *late_corrections += 1;
        }
        TradeUnionDisposition::Conflict { trade_id, .. } => {
            journal.append(
                origin.elapsed().as_nanos() as u64,
                "LIVE",
                serde_json::json!({
                    "event": "TRADE_CONFLICT",
                    "trade_id": trade_id,
                    "lane": lane_payload(lane),
                }),
            )?;
            return Err(format!(
                "redundant lanes delivered conflicting payloads for trade {trade_id}; publication stopped fail-closed"
            ));
        }
        TradeUnionDisposition::Buffered => {}
    }
    Ok(())
}

/// The generation directory's embedded start timestamp (nanoseconds), the
/// chronology authority used by the resume historical walk.
fn generation_start_ns(generation_dir: &Path) -> Option<u64> {
    generation_dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.split('-').next())
        .and_then(|prefix| prefix.parse::<u64>().ok())
}

/// Walks ONE binding's full durable trade prefix on resume: records at or
/// below the published floor advance the union coverage without publication
/// (already published); records above it flow through the normal union
/// machinery (buffer, drain, publish), so the resumed canonical continues
/// the raw union exactly where the previous generation left off.
#[allow(clippy::too_many_arguments)]
fn walk_generation_trades(
    lane: CaptureLane,
    binding: &mut LaneBinding,
    union: &mut TradeUnionState,
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    trades_published: &mut u64,
    late_corrections: &mut u64,
    floor: u64,
    mut known_duplicates: Option<&mut BTreeSet<(u64, String, String)>>,
) -> Result<()> {
    while binding.trade_consumed < binding.trade.records().len() {
        let record = binding.trade.records()[binding.trade_consumed].clone();
        binding.trade_consumed += 1;
        let observation = materialize_trade_record(&record)?;
        if observation.final_sequence <= floor {
            union.fast_forward(lane, &observation)?;
        } else {
            observe_trade(
                lane,
                observation,
                union,
                journal,
                origin,
                trades_published,
                late_corrections,
                known_duplicates.as_deref_mut(),
            )?;
        }
    }
    Ok(())
}

/// One persistent handover tail walker (ADR-17 B3/B5): keeps consuming a
/// predecessor generation's trade stream until it is sealed AND fully
/// consumed.  The former one-shot snapshot walk dropped every record that
/// became durable after the successor generation appeared (fault-gate
/// defect hrs-438af564df4d: the ETHUSDT canonical missed 100 union trades
/// that only predecessor tails held — 4344063810..4344063812 and
/// 4344066244..4344066340 — because the consumed snapshot ended mid-flight
/// and the successor's records advanced the union cursor past the
/// un-consumed tail).  Records at or below `floor` fast-forward the union
/// coverage (already published); records above it flow through the normal
/// union machinery.
struct GenerationTailWalker {
    generation: PathBuf,
    binding: LaneBinding,
    floor: u64,
    last_durable_advance: Instant,
    lag_excluded: bool,
}

impl GenerationTailWalker {
    fn new(generation: PathBuf, binding: LaneBinding, floor: u64) -> Self {
        Self {
            generation,
            binding,
            floor,
            last_durable_advance: Instant::now(),
            lag_excluded: false,
        }
    }

    fn origin_identity(&self, lane: CaptureLane) -> Result<serde_json::Value> {
        let record = self
            .binding
            .trade
            .records()
            .first()
            .ok_or("tail origin has no trade identity")?;
        let artifact = self
            .generation
            .ancestors()
            .nth(4)
            .and_then(Path::file_name)
            .ok_or("tail origin lacks artifact identity")?;
        Ok(serde_json::json!({
            "artifact": artifact.to_string_lossy(),
            "generation": self.binding.generation_id(),
            "lane": lane_payload(lane),
            "connection_epoch": record.frame.connection_epoch,
            "stream": record.frame.stream,
        }))
    }
}

fn exclude_lagging_tail_origins(
    lane: CaptureLane,
    tails: &mut [GenerationTailWalker],
    union: &TradeUnionState,
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    horizon: Duration,
) -> Result<()> {
    if union.buffered() == 0 {
        return Ok(());
    }
    for walker in tails {
        if walker.lag_excluded
            || walker.binding.trade_consumed != walker.binding.trade.records().len()
            || (walker.last_durable_advance.elapsed() < horizon
                && union.buffered() <= TRADE_LAG_CAP)
        {
            continue;
        }
        let Some(bound) = stream_head_bound(&walker.binding)? else {
            continue;
        };
        let record = walker
            .binding
            .trade
            .records()
            .last()
            .expect("bound requires a record");
        // Persist the exclusion before changing the emission policy. This is
        // a lag decision, never a claim that the producer or stream ended.
        journal.append(origin.elapsed().as_nanos() as u64, "LIVE", serde_json::json!({
            "event":"TRADE_LAG", "reason":"predecessor_lag", "excluded_lane":lane_payload(lane),
            "origin":walker.origin_identity(lane)?, "buffered":union.buffered(),
            "previous_emission_bound":bound, "pending_retained":true,
            "durable_cut":{"records":walker.binding.trade.records().len(),"last_frame_index":record.frame.frame_index,"last_record_sha256":record.record_sha256,"segment_index":walker.binding.trade.segment_index,"segment_durable_offset":walker.binding.trade.last_durable_offset}
        }))?;
        walker.lag_excluded = true;
    }
    Ok(())
}

/// Feeds every tail walker's newly durable records FAIL-CLOSED and drops
/// the walkers whose generation was consumed through its SEALED TERMINAL
/// cut.  Used by the cooperative stop drain so a fully drained walker can
/// never hold the drain open for the whole deadline (the retain previously
/// ran only while a generation change rebuilt the scopes).
#[allow(clippy::too_many_arguments)]
fn refresh_and_retire_tail_walkers(
    lane: CaptureLane,
    tails: &mut Vec<GenerationTailWalker>,
    union: &mut TradeUnionState,
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    trades_published: &mut u64,
    late_corrections: &mut u64,
) -> Result<()> {
    for walker in tails.iter_mut() {
        if walker.binding.trade.refresh()? > 0 {
            walker.last_durable_advance = Instant::now();
        }
        walk_generation_trades(
            lane,
            &mut walker.binding,
            union,
            journal,
            origin,
            trades_published,
            late_corrections,
            walker.floor,
            None,
        )?;
    }
    retire_consumed_tail_walkers(tails);
    Ok(())
}

/// Drops every walker that consumed its sealed terminal cut (identity,
/// count, terminal digest — never a stale snapshot length).
fn retire_consumed_tail_walkers(tails: &mut Vec<GenerationTailWalker>) {
    tails.retain(|walker| {
        !(walker
            .binding
            .trade
            .consumed_sealed_terminal()
            .unwrap_or(false)
            && walker.binding.trade_consumed == walker.binding.trade.records().len())
    });
}

/// A stopped lane releases its final trade watermark only after every
/// known origin reached its exact sealed cut. A non-serving depth candidate
/// need not become authoritative, but its trades still must be consumed.
fn lane_trade_drain_complete(
    binding: &LaneBinding,
    candidate: Option<&LaneBinding>,
    tails: &[GenerationTailWalker],
    latest_generation: Option<&Path>,
) -> Result<bool> {
    let head = candidate.unwrap_or(binding);
    if !tails.is_empty() || latest_generation != Some(head.generation_dir.as_path()) {
        return Ok(false);
    }
    for source in std::iter::once(binding).chain(candidate) {
        if source.trade_consumed != source.trade.records().len()
            || !source.trade.consumed_sealed_terminal()?
            || !binding_streams_sealed(source)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The serving generation's depth stream must be consumed exactly through
/// its SEALED TERMINAL before the stop drain may commit the terminal
/// (ADR-17 B5, fault-gate defect hrs-fa053dbc4a86): a COMPLETE generation
/// whose final seal holds records the binding never loaded keeps the drain
/// open; a killed generation has no terminal declaration and nothing to
/// demand (its BNACK prefix is the oracle the follower already follows).
fn serving_depth_converged(binding: &LaneBinding) -> Result<bool> {
    if !generation_terminal_complete(&binding.generation_dir)? {
        return Ok(true);
    }
    if !binding.depth.consumed_sealed_terminal()? {
        return Ok(false);
    }
    Ok(binding.depth_consumed == binding.depth.records().len() && binding.pending_depth.is_empty())
}

/// One generation-enumeration scope for the tail walkers: the live artifact
/// root (generations strictly between the current binding and the live head,
/// the candidate's own generation skipped) or a PRIOR artifact root passed
/// across an epoch rebind (every generation — the whole prior root is a
/// predecessor set whose tail must be consumed through its final seal).
struct WalkerScope {
    lane_root: PathBuf,
    /// Generations with a start at or above this are owned by the live
    /// binding/candidate machinery; `None` consumes every generation (prior
    /// artifacts have no live head of their own).
    latest_start: Option<u64>,
    /// The candidate's own generation (skipped: it feeds via the candidate).
    skip_generation: Option<PathBuf>,
    /// Records at or below this floor fast-forward (already published).
    floor: u64,
    /// Monotonic marker: the newest consumed generation start (each
    /// generation is consumed by exactly one walker).
    walked_through: Option<u64>,
}

/// The first trade ID the follower has not consumed yet (`None` when the
/// snapshot holds no records): emission must not pass it while the stream
/// may still deliver records below or at it in raw order.
fn stream_head_bound(binding: &LaneBinding) -> Result<Option<u64>> {
    let records = binding.trade.records();
    if records.is_empty() {
        return Ok(None);
    }
    if binding.trade_consumed >= records.len() {
        // Fully consumed snapshot on an unsealed stream: records arriving
        // later continue in raw order after the last consumed ID.
        let last = records.last().expect("records non-empty");
        let observation = materialize_trade_record(last)?;
        return Ok(Some(observation.final_sequence.saturating_add(1)));
    }
    let first = &records[binding.trade_consumed];
    let observation = materialize_trade_record(first)?;
    Ok(Some(observation.final_sequence))
}

/// Synchronizes one lane's persistent handover tail walkers (ADR-17
/// B3/B5): feeds every walker's newly durable records FAIL-CLOSED (a
/// poisoned follower must never freeze silently — the swallowed
/// `let _ = refresh()` was what let a stuck candidate stop consuming at
/// trade 3809/6243), drops walkers whose generation is sealed and fully
/// consumed, and adds walkers for the generations each scope still owns.
/// Walkers feed oldest-first so the lane's union cursor advances in raw
/// order; the emission clamp (see `lane_emission_clamp`) holds the
/// watermark back while any un-consumed tail may still deliver.
#[allow(clippy::too_many_arguments)]
fn sync_tail_walkers(
    lane: CaptureLane,
    binding_start: u64,
    scopes: &mut [WalkerScope],
    tails: &mut Vec<GenerationTailWalker>,
    union: &mut TradeUnionState,
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    trades_published: &mut u64,
    late_corrections: &mut u64,
) -> Result<()> {
    let debug_trace = std::env::var("BINANCE_LOB_DEBUG_TRACE").is_ok();
    // 1. Feed existing walkers (oldest first): refresh FAIL-CLOSED and walk
    //    every newly durable record through the union.
    for walker in tails.iter_mut() {
        if debug_trace {
            eprintln!(
                "[trace] sync {lane:?} walker refresh {}",
                walker.generation.display()
            );
        }
        if walker.binding.trade.refresh()? > 0 {
            walker.last_durable_advance = Instant::now();
        }
        if debug_trace {
            eprintln!(
                "[trace] sync {lane:?} walker walk {}",
                walker.generation.display()
            );
        }
        walk_generation_trades(
            lane,
            &mut walker.binding,
            union,
            journal,
            origin,
            trades_published,
            late_corrections,
            walker.floor,
            None,
        )?;
    }
    // 2. Drop walkers whose generation sealed and drained completely (the
    //    stream can never deliver again).  The retirement test is the
    //    SEALED TERMINAL CUT ITSELF (identity, count, terminal digest),
    //    never the length of a snapshot consumed earlier: an append + seal
    //    landing between the walk above and this check must keep the walker
    //    alive so the next refresh consumes the final records (ADR-17
    //    boundary authority, review 2026-09-11 risk 2 — fault-gate defect
    //    hrs-fa053dbc4a86 class: a terminal committed while sealed evidence
    //    still held unconsumed records).
    retire_consumed_tail_walkers(tails);
    // 3. Add walkers for the generations each scope still owns.
    for scope in scopes.iter_mut() {
        let lower = scope
            .walked_through
            .unwrap_or(binding_start)
            .max(binding_start);
        let deadline = Instant::now() + Duration::from_secs(15);
        for (campaign, generation, start_ns) in all_generations(&scope.lane_root)? {
            if start_ns <= lower {
                continue;
            }
            if scope
                .latest_start
                .is_some_and(|latest_start| start_ns >= latest_start)
            {
                continue;
            }
            if scope
                .skip_generation
                .as_ref()
                .is_some_and(|skip| skip == &generation)
            {
                continue;
            }
            if tails.iter().any(|walker| walker.generation == generation) {
                continue;
            }
            let mut intermediate = loop {
                match LaneBinding::bind_generation(&campaign, &generation) {
                    Ok(bound) => break bound,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(error) => {
                        return Err(format!(
                            "sealed intermediate trade walk could not bind generation {}: {error}",
                            generation.display()
                        ));
                    }
                }
            };
            walk_generation_trades(
                lane,
                &mut intermediate,
                union,
                journal,
                origin,
                trades_published,
                late_corrections,
                scope.floor,
                None,
            )?;
            tails.push(GenerationTailWalker::new(
                generation.clone(),
                intermediate,
                scope.floor,
            ));
            scope.walked_through = Some(start_ns);
        }
    }
    Ok(())
}

/// One lane's emission clamp: the smallest unfinished predecessor head —
/// the first un-consumed ID of every tail walker, plus the predecessor
/// binding's own un-consumed head while a successor candidate exists and
/// the binding's trade stream is not yet fully sealed.  While set, the
/// union's emission watermark cannot pass the bound, so a successor
/// generation can never skip records that a predecessor tail may still
/// deliver (ADR-17 B3/B5 exact union at handovers).
fn lane_emission_clamp(
    tails: &[GenerationTailWalker],
    binding: &LaneBinding,
    candidate_exists: bool,
) -> Result<Option<u64>> {
    let mut clamp: Option<u64> = None;
    for walker in tails {
        if walker.lag_excluded {
            continue;
        }
        if let Some(bound) = stream_head_bound(&walker.binding)? {
            clamp = Some(clamp.map_or(bound, |current: u64| current.min(bound)));
        }
    }
    if candidate_exists
        && !stream_fully_sealed(&binding.generation_dir.join("trade"))?
        && let Some(bound) = stream_head_bound(binding)?
    {
        clamp = Some(clamp.map_or(bound, |current: u64| current.min(bound)));
    }
    Ok(clamp)
}

/// Checks the retained exact witness, then advances a resumable replay.
/// `depth_switch_pending` distinguishes an unfinished proof from a negative
/// one. A work quota never authorizes a gap, retirement or completion.
fn evaluate_depth_switch_with_fallback(
    canonical: &CanonicalDepthPosition,
    sibling: &mut LaneBinding,
    use_fallback: bool,
) -> Result<Option<Vec<CanonicalObservationV1>>> {
    sibling.depth_switch_pending = false;
    let canonical_final = canonical
        .final_sequence
        .ok_or_else(|| "canonical depth position is uninitialized".to_owned())?;
    let canonical_digest = canonical
        .digest
        .clone()
        .ok_or_else(|| "canonical depth digest is unavailable".to_owned())?;
    let converged_at = sibling
        .depth_convergence_witness
        .iter()
        .chain(sibling.pending_depth.iter())
        .any(|observation| {
            observation.final_sequence == canonical_final
                && observation.observation_sha256 == canonical_digest
        });
    if converged_at {
        let tail: Vec<CanonicalObservationV1> = sibling
            .pending_depth
            .iter()
            .filter(|observation| observation.final_sequence > canonical_final)
            .take(DEPTH_SWITCH_RECORD_BUDGET)
            .cloned()
            .collect();
        if tail.is_empty() {
            return Ok(None);
        }
        return Ok(Some(tail));
    }
    if !use_fallback {
        return Ok(None);
    }
    replay_sibling_slice(
        sibling,
        canonical_final,
        &canonical_digest,
        DEPTH_SWITCH_RECORD_BUDGET,
    )
}

/// Resume depth transition (ADR-17 B3): after a restart the canonical depth
/// cursor must either continue exactly from the current bindings, switch to
/// the sibling with proven geometric coverage AND exact book convergence, or
/// be typed as a GAP + DEPTH_REBOOTSTRAP from the fresh serving generation.
/// Never a silent bridge, never a duplicated range.
#[allow(clippy::too_many_arguments)]
fn resume_depth_transition(
    journal: &mut LiveArbitrationJournalWriter,
    origin: &Instant,
    serving_lane: &mut CaptureLane,
    primary_binding: &mut LaneBinding,
    shadow_binding: &mut LaneBinding,
    canonical_position: &mut CanonicalDepthPosition,
    depth_published: &mut u64,
    gaps_published: &mut u64,
) -> Result<()> {
    let Some(canonical_final) = canonical_position.final_sequence else {
        // The previous segment ended right after a typed gap/bootstrap with
        // no further data: nothing to bridge; the first publish of the new
        // segment starts the fresh book (its DEPTH_REBOOTSTRAP evidence
        // lives in the previous segment).
        return Ok(());
    };
    let expected = canonical_final.saturating_add(1);
    let (serving_binding, sibling_binding) = if *serving_lane == CaptureLane::Primary {
        (primary_binding, &mut *shadow_binding)
    } else {
        (shadow_binding, &mut *primary_binding)
    };
    // Case 1: the serving binding continues exactly.
    let serving_continues = serving_binding
        .pending_depth
        .front()
        .is_some_and(|observation| observation.first_sequence == expected);
    if serving_continues {
        return Ok(());
    }
    // Case 2: proven sibling switch (coverage + exact convergence).
    if let Some(tail) =
        evaluate_depth_switch_with_fallback(canonical_position, sibling_binding, true)?
    {
        let new_serving_lane = other_lane(*serving_lane);
        let mut bridgeable = true;
        for observation in tail {
            let expected = canonical_position
                .final_sequence
                .map(|final_sequence| final_sequence.saturating_add(1));
            match classify_depth_frontier(
                expected,
                observation.first_sequence,
                observation.final_sequence,
            )? {
                DepthFrontierDisposition::Contiguous
                | DepthFrontierDisposition::Straddle { .. } => {
                    journal.append(
                        origin.elapsed().as_nanos() as u64,
                        "LIVE",
                        serde_json::json!({
                            "event": "DEPTH_OBSERVATION",
                            "first_sequence": observation.first_sequence,
                            "final_sequence": observation.final_sequence,
                            "lane": lane_payload(new_serving_lane),
                            "record_sha256": observation.record_sha256,
                            "observation_sha256": observation.observation_sha256,
                        }),
                    )?;
                    canonical_position.final_sequence = Some(observation.final_sequence);
                    canonical_position.digest = Some(observation.observation_sha256);
                    *depth_published += 1;
                }
                DepthFrontierDisposition::Covered { .. } => {}
                DepthFrontierDisposition::Missing { .. } => {
                    bridgeable = false;
                    break;
                }
            }
        }
        if bridgeable {
            journal.append(
                origin.elapsed().as_nanos() as u64,
                "LIVE",
                serde_json::json!({
                    "event": "DEPTH_SWITCH_PROVEN",
                    "from_lane": lane_payload(*serving_lane),
                    "to_lane": lane_payload(new_serving_lane),
                    "boundary_final_sequence": canonical_position.final_sequence,
                }),
            )?;
            *serving_lane = new_serving_lane;
            return Ok(());
        }
    }
    if sibling_binding.depth_switch_pending {
        // Resume the proof in the normal loop; a scheduling quota is not
        // evidence that the sibling cannot bridge the boundary.
        return Ok(());
    }
    // Case 3: typed gap + evidenced rebootstrap from the fresh serving
    // generation (its snapshot/generation evidence is recorded).
    gap_and_bootstrap_depth(
        journal,
        origin,
        *serving_lane,
        serving_binding,
        canonical_position,
        depth_published,
        gaps_published,
    )?;
    Ok(())
}

fn run() -> Result<PathBuf> {
    run_with_args(env::args())
}

fn run_with_args(mut args: impl Iterator<Item = String>) -> Result<PathBuf> {
    run_with_tail_lag_horizon(&mut args, TRADE_LAG_HORIZON)
}

fn run_with_tail_lag_horizon(
    mut args: impl Iterator<Item = String>,
    tail_lag_horizon: Duration,
) -> Result<PathBuf> {
    let executable = args.next().unwrap_or_else(|| "live_arbitration".to_owned());
    let symbol = args.next().ok_or_else(|| {
        format!(
            "usage: {executable} <BTCUSDT|ETHUSDT> <supervisor-artifact-root> <output-journal> <duration-s|--continuous> [--replay] [--identity <path>] [--stop-file <path>] [--rebind-file <path>] [--prior-artifact <root>]... [--resume-dir <dir>]"
        )
    })?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err("symbol outside fixed scope".to_owned());
    }
    let artifact_root = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing supervisor artifact root".to_owned())?,
    );
    let output_journal = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing output journal path".to_owned())?,
    );
    let duration_arg = args.next().ok_or_else(|| "missing duration".to_owned())?;
    let continuous = duration_arg == "--continuous";
    let duration_s = if continuous {
        0
    } else {
        parse_positive(Some(duration_arg), "duration-s", 7 * 24 * 3_600)?
    };
    let mut replay = false;
    let mut identity_path: Option<PathBuf> = None;
    let mut stop_file: Option<PathBuf> = None;
    let mut resume_dir: Option<PathBuf> = None;
    let mut prior_artifacts: Vec<PathBuf> = Vec::new();
    let mut rebind_file: Option<PathBuf> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--replay" => replay = true,
            "--identity" => {
                identity_path = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--identity expects a path".to_owned())?,
                ));
            }
            "--stop-file" => {
                stop_file = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--stop-file expects a path".to_owned())?,
                ));
            }
            "--rebind-file" => {
                rebind_file = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--rebind-file expects a path".to_owned())?,
                ));
            }
            "--prior-artifact" => {
                prior_artifacts
                    .push(PathBuf::from(args.next().ok_or_else(|| {
                        "--prior-artifact expects a path".to_owned()
                    })?));
            }
            "--resume-dir" => {
                resume_dir = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| "--resume-dir expects a path".to_owned())?,
                ));
            }
            _ => return Err("unknown trailing argument".to_owned()),
        }
    }
    if continuous && stop_file.is_none() {
        return Err("--continuous requires --stop-file".to_owned());
    }
    if continuous && resume_dir.is_none() && identity_path.is_none() {
        return Err("--continuous requires --identity and --resume-dir".to_owned());
    }
    if !prior_artifacts.is_empty() && resume_dir.is_none() {
        return Err("--prior-artifact requires --resume-dir".to_owned());
    }
    for prior in &prior_artifacts {
        if !prior.is_dir() {
            return Err(format!(
                "--prior-artifact is not an existing directory: {}",
                prior.display()
            ));
        }
    }

    let primary_root = artifact_root.join(lane_leaf(CaptureLane::Primary));
    let shadow_root = artifact_root.join(lane_leaf(CaptureLane::Shadow));
    if !primary_root.is_dir() || !shadow_root.is_dir() {
        return Err("supervisor artifact lacks both lane roots".to_owned());
    }
    if replay {
        return run_replay(&symbol, &artifact_root, &output_journal);
    }

    let origin = Instant::now();
    let deadline = if continuous {
        None
    } else {
        Some(origin + Duration::from_secs(duration_s))
    };
    if resume_dir.is_some()
        && output_journal.is_file()
        && fs::metadata(&output_journal)
            .map(|metadata| metadata.len() == 0)
            .unwrap_or(false)
    {
        // Torn creation from a crashed generation: an empty file carries no
        // records and no hash chain, so removing it loses nothing.
        fs::remove_file(&output_journal).map_err(|error| {
            format!(
                "remove torn empty journal {}: {error}",
                output_journal.display()
            )
        })?;
    }
    let mut trade_union = TradeUnionState::new();
    trade_union.register_lane(CaptureLane::Primary);
    trade_union.register_lane(CaptureLane::Shadow);
    let mut trades_published = 0_u64;
    let mut depth_published = 0_u64;
    let mut gaps_published = 0_u64;
    let mut late_corrections = 0_u64;
    let mut serving_lane = CaptureLane::Primary;
    let mut canonical_position = CanonicalDepthPosition {
        final_sequence: None,
        digest: None,
        gap_floor: None,
    };
    let mut last_serving_progress = Instant::now();
    let mut last_lag_report = Instant::now();
    let mut lane_trade_advance: [Option<Instant>; 2] = [None, None];

    // Bind the lanes BEFORE the journal is created.  A resumed arbiter binds
    // the CURRENT artifact root (possibly a new supervisor epoch) and pins
    // the published floor so the continuation can never duplicate or roll
    // back the canonical stream.  Both modes retry the initial bind: a
    // freshly launched campaign publishes its snapshot/segments in stages
    // (legal mid-write prefixes).  In CONTINUOUS mode a bindable race is
    // NEVER fatal: the bind retries every poll until it succeeds or the
    // cooperative stop-file appears (fault-gate defect: a slow-starting
    // generation emptied a whole segment chain and lost union trade
    // 6669312440 — an empty journal segment must never be created, so the
    // writer opens only after both bindings exist).  A stop during the bind
    // exits cleanly with NO journal segment at all.
    let mut primary_binding = match deadline {
        Some(deadline) => bind_with_retry(&primary_root, deadline)?,
        None => {
            let stop_file = stop_file.as_ref().expect("continuous requires --stop-file");
            loop {
                match LaneBinding::bind(&primary_root) {
                    Ok(binding) => break binding,
                    Err(_) if stop_file.is_file() => return Ok(output_journal),
                    Err(_) => std::thread::sleep(POLL),
                }
            }
        }
    };
    let mut shadow_binding = match deadline {
        Some(deadline) => bind_with_retry(&shadow_root, deadline)?,
        None => {
            let stop_file = stop_file.as_ref().expect("continuous requires --stop-file");
            loop {
                match LaneBinding::bind(&shadow_root) {
                    Ok(binding) => break binding,
                    Err(_) if stop_file.is_file() => return Ok(output_journal),
                    Err(_) => std::thread::sleep(POLL),
                }
            }
        }
    };
    let mut journal = LiveArbitrationJournalWriter::create(&output_journal)?;
    let mut primary_candidate: Option<LaneBinding> = None;
    let mut shadow_candidate: Option<LaneBinding> = None;
    let mut primary_rebind_since: Option<Instant> = None;
    let mut shadow_rebind_since: Option<Instant> = None;
    // Live completeness (ADR-17 B3): the newest-generation walk positions
    // per lane — the start timestamp of the last sealed intermediate
    // generation already consumed between the binding and the live head
    // (fault-gate defect hrs-e834f9740a96: a frozen pending candidate
    // skipped intermediate generations and dropped the shadow-exclusive
    // union trades at campaign handovers).
    let mut primary_walked_through: Option<u64> = None;
    let mut shadow_walked_through: Option<u64> = None;
    // Persistent handover tail walkers (ADR-17 B3/B5): predecessor
    // generations are consumed through their FINAL seal, never via a
    // one-shot mid-flight snapshot (fault-gate defect hrs-438af564df4d).
    let mut primary_tails: Vec<GenerationTailWalker> = Vec::new();
    let mut shadow_tails: Vec<GenerationTailWalker> = Vec::new();
    // Prior-artifact scopes (ADR-17 B3 LIVE rebind): generations of the
    // artifact left behind by an epoch rebind keep feeding the same
    // logical lane until they seal.
    let mut primary_prior_scopes: Vec<WalkerScope> = Vec::new();
    let mut shadow_prior_scopes: Vec<WalkerScope> = Vec::new();
    for prior in &prior_artifacts {
        let primary_lane_root = prior.join(lane_leaf(CaptureLane::Primary));
        if primary_lane_root.is_dir() {
            primary_prior_scopes.push(WalkerScope {
                lane_root: primary_lane_root,
                latest_start: None,
                skip_generation: None,
                floor: 0,
                walked_through: None,
            });
        }
        let shadow_lane_root = prior.join(lane_leaf(CaptureLane::Shadow));
        if shadow_lane_root.is_dir() {
            shadow_prior_scopes.push(WalkerScope {
                lane_root: shadow_lane_root,
                latest_start: None,
                skip_generation: None,
                floor: 0,
                walked_through: None,
            });
        }
    }

    // Resume (ADR-17 B3/B4): recover the previous journal chain, the exact
    // published trade floor, the durable identity and the canonical depth
    // cursor; then re-derive the union's lane positions from the CURRENT
    // durable prefixes up to the floor.  A resume directory without previous
    // segments is a FRESH start (first generation of the service).
    let mut resumed_state: Option<RecoveredArbitrationState> = None;
    if let Some(resume_dir) = &resume_dir {
        resumed_state = recover_arbitration_state_opt(
            resume_dir,
            identity_path
                .as_ref()
                .expect("continuous requires --identity"),
            &output_journal,
        )?;
    }
    if let Some(mut recovered) = resumed_state {
        trades_published = recovered.trades;
        depth_published = recovered.depth_frames;
        gaps_published = recovered.gaps;
        late_corrections = recovered.late_corrections;
        serving_lane = recovered.serving_lane;
        canonical_position = recovered.canonical_position;
        let mut resumed = serde_json::json!({
            "event": "ARBITRATION_RESUMED",
            "symbol": symbol,
            "mode": if continuous { "CONTINUOUS" } else { "RESUMED" },
            "previous_journal_sha256": recovered.previous_segment_sha,
            "trade_floor": recovered.last_trade_id.unwrap_or(0),
            "artifact_root": artifact_root
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
        });
        if !prior_artifacts.is_empty() {
            resumed["prior_artifacts"] = serde_json::json!(
                prior_artifacts
                    .iter()
                    .filter_map(|prior| prior
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned()))
                    .collect::<Vec<String>>()
            );
        }
        if recovered.previous_tail_bytes > 0 {
            resumed["previous_tail_bytes"] = serde_json::json!(recovered.previous_tail_bytes);
        }
        journal.append(origin.elapsed().as_nanos() as u64, "LIVE", resumed)?;
        trade_union.set_identity_log(TradeIdentityLog::open(
            identity_path
                .as_ref()
                .expect("continuous requires --identity"),
        )?);
        trade_union.restore_published_floor(recovered.last_trade_id.unwrap_or(0))?;
        let floor = recovered.startup_trade_floor;
        trade_union.restore_startup_floor(floor);
        for (id, digest) in recovered.corrected_identities {
            trade_union.restore_corrected_identity(id, digest)?;
        }
        for scope in primary_prior_scopes
            .iter_mut()
            .chain(shadow_prior_scopes.iter_mut())
        {
            scope.floor = floor;
        }
        // Resume completeness (ADR-17 B3): a rebind to a NEW artifact must
        // publish the artifact's FULL trade history above the published
        // floor, not only the newest generation's tail.  Fault-gate defect
        // hrs-9d4da4d02a1a: the terminal rebind bound the final campaign's
        // live generation only and dropped 17,683 union trades captured by
        // the previous campaigns while the sidecar was down (canonical 1226
        // vs union window 18909).  Every sealed generation OLDER than the
        // live binding is walked with a fresh binding, both lanes merged in
        // chronological order so the union's watermark only releases an ID
        // once each live lane has passed it (no spurious late corrections).
        // Generations NEWER than the live binding are owned by the live
        // candidate machinery (single consumer, monotonic cursor — never a
        // double feed).  A just-sealed generation's manifest may still be
        // stabilizing, so the bind retries against one shared bounded
        // deadline and then fails closed (an unverifiable raw prefix is
        // never invented away).
        let historical_deadline = Instant::now() + Duration::from_secs(15);
        let mut historical_events: Vec<(CaptureLane, PathBuf, PathBuf, u64)> = Vec::new();
        for (lane, lane_root, live_generation) in [
            (
                CaptureLane::Primary,
                primary_root.as_path(),
                primary_binding.generation_dir.as_path(),
            ),
            (
                CaptureLane::Shadow,
                shadow_root.as_path(),
                shadow_binding.generation_dir.as_path(),
            ),
        ] {
            let live_start = generation_start_ns(live_generation);
            for (campaign, generation, start_ns) in all_generations(lane_root)? {
                if generation == live_generation
                    || live_start.is_some_and(|live_start| start_ns >= live_start)
                {
                    continue;
                }
                historical_events.push((lane, campaign, generation, start_ns));
            }
        }
        // Prior artifacts (ADR-17 B3 LIVE rebind): every generation of the
        // artifact left behind by the epoch rebind is a predecessor tail of
        // the SAME logical lane.  They seal progressively after the old
        // epoch's lanes stop, so they are consumed as persistent walkers
        // too — the rebind recovers every recoverable record without
        // waiting for the old capture's stop.
        for prior in &prior_artifacts {
            for lane in [CaptureLane::Primary, CaptureLane::Shadow] {
                let lane_root = prior.join(lane_leaf(lane));
                if !lane_root.is_dir() {
                    continue;
                }
                for (campaign, generation, start_ns) in all_generations(&lane_root)? {
                    historical_events.push((lane, campaign, generation, start_ns));
                }
            }
        }
        historical_events.sort_by_key(|(_, _, _, start_ns)| *start_ns);
        for (lane, campaign, generation, _start_ns) in historical_events {
            if std::env::var("BINANCE_LOB_DEBUG_TRACE").is_ok() {
                eprintln!("[trace] resume walk bind {lane:?} {}", generation.display());
            }
            let mut historical = loop {
                match LaneBinding::bind_generation(&campaign, &generation) {
                    Ok(bound) => break bound,
                    Err(_) if Instant::now() < historical_deadline => {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(error) => {
                        return Err(format!(
                            "historical trade walk could not bind sealed generation {}: {error}",
                            generation.display()
                        ));
                    }
                }
            };
            walk_generation_trades(
                lane,
                &mut historical,
                &mut trade_union,
                &mut journal,
                &origin,
                &mut trades_published,
                &mut late_corrections,
                floor,
                Some(&mut recovered.journaled_duplicate_corrections),
            )?;
            // Keep the walker alive: the generation may still be mid-flight
            // (a rebind during the epoch overlap).  Its tail is consumed
            // through the final seal by sync_tail_walkers — never dropped
            // (ADR-17 B3/B5).
            let mut walker = GenerationTailWalker::new(generation.clone(), historical, floor);
            if !walker.binding.trade.records().is_empty() {
                walker.lag_excluded = recovered
                    .excluded_tail_origins
                    .contains(&walker.origin_identity(lane)?.to_string());
            }
            match lane {
                CaptureLane::Primary => primary_tails.push(walker),
                CaptureLane::Shadow => shadow_tails.push(walker),
            }
        }
        // Re-derive the union lane positions on the LIVE bindings: consume
        // every durable trade at or below the floor without publishing
        // (already published), leaving the follower exactly at the first
        // un-published durable record for the live feed.
        for (lane, binding) in [
            (CaptureLane::Primary, &mut primary_binding),
            (CaptureLane::Shadow, &mut shadow_binding),
        ] {
            while binding.trade_consumed < binding.trade.records().len() {
                let record = binding.trade.records()[binding.trade_consumed].clone();
                let observation = materialize_trade_record(&record)?;
                if observation.final_sequence > floor {
                    break;
                }
                binding.trade_consumed += 1;
                trade_union.fast_forward(lane, &observation)?;
            }
        }
        // The canonical depth cursor must continue exactly, switch to the
        // sibling with proven convergence, or be typed as a GAP +
        // DEPTH_REBOOTSTRAP from the fresh generation — never bridged.
        if std::env::var("BINANCE_LOB_DEBUG_TRACE").is_ok() {
            eprintln!("[trace] resume depth transition start");
        }
        resume_depth_transition(
            &mut journal,
            &origin,
            &mut serving_lane,
            &mut primary_binding,
            &mut shadow_binding,
            &mut canonical_position,
            &mut depth_published,
            &mut gaps_published,
        )?;
        last_serving_progress = Instant::now();
    } else {
        if let Some(identity) = &identity_path {
            trade_union.set_identity_log(TradeIdentityLog::create(identity)?);
        }
        // Fast-forward the historical prefixes: trades establish the coverage
        // floor (declared in ARBITRATION_STARTED so the oracle window is
        // external, never trimmed to the output); the canonical depth
        // position adopts the serving lane's prefix head.
        for (lane, binding) in [
            (CaptureLane::Primary, &mut primary_binding),
            (CaptureLane::Shadow, &mut shadow_binding),
        ] {
            while binding.trade_consumed < binding.trade.records().len() {
                let record = binding.trade.records()[binding.trade_consumed].clone();
                binding.trade_consumed += 1;
                let observation = materialize_trade_record(&record)?;
                trade_union.fast_forward(lane, &observation)?;
            }
        }
        if let Some(last) = primary_binding.pending_depth.back() {
            canonical_position.final_sequence = Some(last.final_sequence);
            canonical_position.digest = Some(last.observation_sha256.clone());
        }
        primary_binding.pending_depth.clear();
        shadow_binding.pending_depth.clear();
        journal.append(
            origin.elapsed().as_nanos() as u64,
            "LIVE",
            serde_json::json!({
                "event": "ARBITRATION_STARTED",
                "symbol": symbol,
                "primary_root": safe_relative_path(&artifact_root, &primary_root)?,
                "shadow_root": safe_relative_path(&artifact_root, &shadow_root)?,
                "spec_revision": SPEC_REVISION,
                "trade_floor": trade_union.consumed_floor(),
                "artifact_root": artifact_root
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            }),
        )?;
    }

    let mut drain_deadline: Option<Instant> = None;
    // ADR-17 B5 terminal cut: bounded fail-closed deadline for the serving
    // stream's convergence on its sealed terminal evidence (a drain that
    // can never converge must not commit a COMPLETE terminal).
    let mut convergence_deadline: Option<Instant> = None;
    let mut primary_clamp: Option<u64> = None;
    let mut shadow_clamp: Option<u64> = None;
    let debug_trace = std::env::var("BINANCE_LOB_DEBUG_TRACE").is_ok();
    let trace_file = std::env::var("BINANCE_LOB_TRACE_FILE").ok();
    let mut trace_handle: Option<std::fs::File> = match &trace_file {
        Some(path) => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok(),
        None => None,
    };
    macro_rules! trace {
        ($($arg:tt)*) => {
            if let Some(handle) = trace_handle.as_mut() {
                use std::io::Write;
                let _ = writeln!(handle, $($arg)*);
            }
        };
    }
    let mut iteration: u64 = 0;
    // One evidenced gap on a sealed serving generation during stop. Repeating
    // it would emit a second boundary for the same cursor.
    let mut stop_gap_bootstrapped = false;
    let handoff_terminal = loop {
        iteration += 1;
        if debug_trace {
            eprintln!(
                "[trace] iteration {iteration} start (buffered={}, tails p={} s={}, published={})",
                trade_union.buffered(),
                primary_tails.len(),
                shadow_tails.len(),
                trades_published
            );
        }
        trace!(
            "iter {iteration} buffered={} published={} p_next={:?} s_next={:?} pclamp={:?} sclamp={:?} pbind={} pcand={:?} pconsumed={}/{} sbind={} scand={:?} sconsumed={}/{} pdepth={}/{} sdepth={}/{} pwalkers=[{}] swalkers=[{}] stop_requested_flag=false",
            trade_union.buffered(),
            trades_published,
            trade_union.lane_next(CaptureLane::Primary),
            trade_union.lane_next(CaptureLane::Shadow),
            primary_clamp,
            shadow_clamp,
            primary_binding.generation_id(),
            primary_candidate.as_ref().map(|c| c.generation_id()),
            primary_binding.trade_consumed,
            primary_binding.trade.records().len(),
            shadow_binding.generation_id(),
            shadow_candidate.as_ref().map(|c| c.generation_id()),
            shadow_binding.trade_consumed,
            shadow_binding.trade.records().len(),
            primary_binding.depth_consumed,
            primary_binding.depth.records().len(),
            shadow_binding.depth_consumed,
            shadow_binding.depth.records().len(),
            primary_tails
                .iter()
                .map(|w| format!(
                    "{}:{}/{}",
                    w.generation
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    w.binding.trade_consumed,
                    w.binding.trade.records().len()
                ))
                .collect::<Vec<_>>()
                .join(","),
            shadow_tails
                .iter()
                .map(|w| format!(
                    "{}:{}/{}",
                    w.generation
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    w.binding.trade_consumed,
                    w.binding.trade.records().len()
                ))
                .collect::<Vec<_>>()
                .join(","),
        );
        // Termination request (ADR-17 B2/B3): a bounded run ends at its
        // deadline; a continuous service ends on the cooperative stop-file
        // OR the rebind file (LIVE rebind: both files are always passed and
        // each must stop the sidecar independently — fault-gate defect
        // hrs-e703a7fc69e4: the rebind file was ignored while the stop file
        // existed, the old sidecar was killed after 60 s and the successor
        // chained to a torn tail).  `rebind_stop` drains only what is
        // already durable: the successor owns the predecessor artifact's
        // sealing tails via --prior-artifact.
        let stop_requested = match (&deadline, &stop_file, &rebind_file) {
            (Some(deadline), _, _) => Instant::now() >= *deadline,
            (None, Some(stop), Some(rebind)) => stop.is_file() || rebind.is_file(),
            (None, Some(stop), None) => stop.is_file(),
            (None, None, Some(rebind)) => rebind.is_file(),
            (None, None, None) => unreachable!("--continuous requires --stop-file"),
        };
        let rebind_stop = deadline.is_none()
            && rebind_file.as_ref().is_some_and(|file| file.is_file())
            && !stop_file.as_ref().is_some_and(|file| file.is_file());
        let serving_generation_changed;
        let mut serving_gap_detected = false;
        let primary_generation;
        let shadow_generation;
        {
            // Resolve generations and manage predecessor/candidate pairs.
            primary_generation =
                latest_directory_opt(&latest_directory(&primary_root)?.join("generations"))?;
            shadow_generation =
                latest_directory_opt(&latest_directory(&shadow_root)?.join("generations"))?;
            if debug_trace {
                eprintln!("[trace] {iteration} generation resolution (bindings loaded)");
            }
            serving_generation_changed = if serving_lane == CaptureLane::Primary {
                primary_generation.as_deref() != Some(primary_binding.generation_dir.as_path())
            } else {
                shadow_generation.as_deref() != Some(shadow_binding.generation_dir.as_path())
            };
            // ADR-17 B3/B5 publication order (review 2026-09-11 risk 3):
            // the handover emission clamps must govern BEFORE any walker
            // publication this iteration can advance the union cursor.
            // The tails' heads from the previous iteration bound the
            // emission while the sync below walks them further — a stale
            // (lower) bound only blocks, it can never skip — and the
            // post-sync recompute raises the bound to the advanced heads
            // and flushes the released records.  The predecessor condition
            // is the EXISTENCE of a successor generation (latest !=
            // binding), never the presence of a bound candidate object
            // (fault-gate defect hrs-64a42e7a0850).
            match lane_emission_clamp(
                &primary_tails,
                &primary_binding,
                primary_generation.as_deref() != Some(primary_binding.generation_dir.as_path()),
            )? {
                Some(bound) => {
                    trade_union.set_emission_clamp(CaptureLane::Primary, bound);
                }
                None => {
                    trade_union.clear_emission_clamp(CaptureLane::Primary);
                }
            }
            match lane_emission_clamp(
                &shadow_tails,
                &shadow_binding,
                shadow_generation.as_deref() != Some(shadow_binding.generation_dir.as_path()),
            )? {
                Some(bound) => {
                    trade_union.set_emission_clamp(CaptureLane::Shadow, bound);
                }
                None => {
                    trade_union.clear_emission_clamp(CaptureLane::Shadow);
                }
            }
            // Prior-artifact tails progress independently of the current
            // generation. A stable live binding must not pin a fully sealed
            // predecessor forever. The pre-refresh clamps above still guard
            // publication until every newly durable tail record is consumed.
            refresh_and_retire_tail_walkers(
                CaptureLane::Primary,
                &mut primary_tails,
                &mut trade_union,
                &mut journal,
                &origin,
                &mut trades_published,
                &mut late_corrections,
            )?;
            refresh_and_retire_tail_walkers(
                CaptureLane::Shadow,
                &mut shadow_tails,
                &mut trade_union,
                &mut journal,
                &origin,
                &mut trades_published,
                &mut late_corrections,
            )?;
            exclude_lagging_tail_origins(
                CaptureLane::Primary,
                &mut primary_tails,
                &trade_union,
                &mut journal,
                &origin,
                tail_lag_horizon,
            )?;
            exclude_lagging_tail_origins(
                CaptureLane::Shadow,
                &mut shadow_tails,
                &trade_union,
                &mut journal,
                &origin,
                tail_lag_horizon,
            )?;
            // PRIMARY: keep the predecessor authoritative until its records
            // drain; the candidate binds separately and is activated only by
            // an explicit, evidenced transition.  Every generation between
            // the binding and the live head is consumed through its FINAL
            // seal by a persistent tail walker (never a one-shot mid-flight
            // snapshot) so a pending candidate can never skip an
            // intermediate generation's trades; walkers feed before the
            // candidate so the lane's union cursor advances in raw order.
            if primary_generation.as_deref() != Some(primary_binding.generation_dir.as_path()) {
                // FAIL-CLOSED refresh (ADR-17 B3/B5): a poisoned follower
                // must stop publication instead of freezing silently
                // (fault-gate defect hrs-438af564df4d: a swallowed refresh
                // error left the shadow lane's consumption parked at trade
                // 3809/6243 forever).
                primary_binding.refresh()?;
                // Candidate freshness (ADR-17 B3/B5): the candidate must
                // ALWAYS be the newest generation.  A candidate bound once
                // and never re-bound went stale forever (the non-serving
                // lane's binding never activates), leaving the live head's
                // trades with NO consumer (fault-gate defect
                // hrs-a69b916cd0ea: the shadow candidate stayed on campaign
                // 1 g001 for the whole run and 4346058346..4346058350 of
                // the last campaign's g002 were lost).  The rebind runs
                // BEFORE the walker scopes are built: the dropped
                // candidate's generation stops being the skip target and
                // its un-consumed tail is preserved by a tail walker.
                match primary_candidate.as_mut() {
                    Some(candidate)
                        if primary_generation.as_deref()
                            != Some(candidate.generation_dir.as_path()) =>
                    {
                        match LaneBinding::bind(&primary_root) {
                            Ok(fresh) => *candidate = fresh,
                            Err(_) => {
                                let _ = candidate.refresh();
                            }
                        }
                    }
                    Some(candidate) => {
                        candidate.refresh()?;
                    }
                    None => match LaneBinding::bind(&primary_root) {
                        Ok(candidate) => primary_candidate = Some(candidate),
                        Err(error) => {
                            // A renewed generation publishes its snapshot and
                            // segments in stages: the bind failure is a legal
                            // transient prefix.  Keep the predecessor
                            // authoritative and retry every poll — never
                            // abort the canonical view over a bindable race
                            // (ADR-17 B3: raw stays untouched either way).
                            primary_rebind_since.get_or_insert_with(Instant::now);
                            if primary_rebind_since
                                .expect("rebind deadline armed")
                                .elapsed()
                                > RENEW_BIND_DEADLINE
                            {
                                primary_rebind_since = None;
                            }
                            let _ = error;
                        }
                    },
                }
                let binding_start =
                    generation_start_ns(&primary_binding.generation_dir).unwrap_or(0);
                let latest_start = primary_generation
                    .as_ref()
                    .and_then(|generation| generation_start_ns(generation));
                let mut primary_scopes: Vec<WalkerScope> = primary_prior_scopes
                    .iter()
                    .map(|scope| WalkerScope {
                        lane_root: scope.lane_root.clone(),
                        latest_start: None,
                        skip_generation: None,
                        floor: scope.floor,
                        walked_through: scope.walked_through,
                    })
                    .collect();
                primary_scopes.push(WalkerScope {
                    lane_root: primary_root.clone(),
                    latest_start,
                    skip_generation: primary_candidate
                        .as_ref()
                        .map(|candidate| candidate.generation_dir.clone()),
                    floor: 0,
                    walked_through: primary_walked_through,
                });
                sync_tail_walkers(
                    CaptureLane::Primary,
                    binding_start,
                    &mut primary_scopes,
                    &mut primary_tails,
                    &mut trade_union,
                    &mut journal,
                    &origin,
                    &mut trades_published,
                    &mut late_corrections,
                )?;
                primary_walked_through =
                    primary_scopes.last().and_then(|scope| scope.walked_through);
            } else {
                primary_binding.refresh()?;
                primary_candidate = None;
                primary_rebind_since = None;
                primary_walked_through = None;
            }
            // SHADOW: same discipline.
            if shadow_generation.as_deref() != Some(shadow_binding.generation_dir.as_path()) {
                shadow_binding.refresh()?;
                // Candidate freshness (ADR-17 B3/B5, same discipline as
                // PRIMARY — fault-gate defect hrs-a69b916cd0ea): rebind
                // BEFORE building the walker scopes so the dropped
                // candidate's tail becomes a walker target.
                match shadow_candidate.as_mut() {
                    Some(candidate)
                        if shadow_generation.as_deref()
                            != Some(candidate.generation_dir.as_path()) =>
                    {
                        match LaneBinding::bind(&shadow_root) {
                            Ok(fresh) => *candidate = fresh,
                            Err(_) => {
                                let _ = candidate.refresh();
                            }
                        }
                    }
                    Some(candidate) => {
                        candidate.refresh()?;
                    }
                    None => match LaneBinding::bind(&shadow_root) {
                        Ok(candidate) => shadow_candidate = Some(candidate),
                        Err(error) => {
                            // Same discipline as PRIMARY: transient bindable
                            // prefixes are retried, never fatal.
                            shadow_rebind_since.get_or_insert_with(Instant::now);
                            if shadow_rebind_since
                                .expect("rebind deadline armed")
                                .elapsed()
                                > RENEW_BIND_DEADLINE
                            {
                                shadow_rebind_since = None;
                            }
                            let _ = error;
                        }
                    },
                }
                let binding_start =
                    generation_start_ns(&shadow_binding.generation_dir).unwrap_or(0);
                let latest_start = shadow_generation
                    .as_ref()
                    .and_then(|generation| generation_start_ns(generation));
                let mut shadow_scopes: Vec<WalkerScope> = shadow_prior_scopes
                    .iter()
                    .map(|scope| WalkerScope {
                        lane_root: scope.lane_root.clone(),
                        latest_start: None,
                        skip_generation: None,
                        floor: scope.floor,
                        walked_through: scope.walked_through,
                    })
                    .collect();
                shadow_scopes.push(WalkerScope {
                    lane_root: shadow_root.clone(),
                    latest_start,
                    skip_generation: shadow_candidate
                        .as_ref()
                        .map(|candidate| candidate.generation_dir.clone()),
                    floor: 0,
                    walked_through: shadow_walked_through,
                });
                sync_tail_walkers(
                    CaptureLane::Shadow,
                    binding_start,
                    &mut shadow_scopes,
                    &mut shadow_tails,
                    &mut trade_union,
                    &mut journal,
                    &origin,
                    &mut trades_published,
                    &mut late_corrections,
                )?;
                shadow_walked_through = shadow_scopes.last().and_then(|scope| scope.walked_through);
            } else {
                shadow_binding.refresh()?;
                shadow_candidate = None;
                shadow_rebind_since = None;
                shadow_walked_through = None;
            }
            // Handover emission clamps (ADR-17 B3/B5): while any
            // predecessor tail may still deliver, the union's emission
            // watermark must not pass the tail's consumed head — the
            // successor's records then wait in the buffer and publish in
            // ID order as the tail seals.  The predecessor condition is
            // the EXISTENCE of a successor generation (latest != binding),
            // never the presence of a bound candidate object: a transient
            // candidate bind failure (a legal mid-write prefix) must not
            // disarm the clamp — fault-gate defect hrs-64a42e7a0850: the
            // primary delivered 4345964645..4345964665 as `unknown`
            // corrections because the successor's records had already
            // released the watermark past them while the candidate object
            // was momentarily unbound.
            match lane_emission_clamp(
                &primary_tails,
                &primary_binding,
                primary_generation.as_deref() != Some(primary_binding.generation_dir.as_path()),
            )? {
                Some(bound) => {
                    trade_union.set_emission_clamp(CaptureLane::Primary, bound);
                    primary_clamp = Some(bound);
                }
                None => {
                    trade_union.clear_emission_clamp(CaptureLane::Primary);
                    primary_clamp = None;
                }
            }
            match lane_emission_clamp(
                &shadow_tails,
                &shadow_binding,
                shadow_generation.as_deref() != Some(shadow_binding.generation_dir.as_path()),
            )? {
                Some(bound) => {
                    trade_union.set_emission_clamp(CaptureLane::Shadow, bound);
                    shadow_clamp = Some(bound);
                }
                None => {
                    trade_union.clear_emission_clamp(CaptureLane::Shadow);
                    shadow_clamp = None;
                }
            }
            // A raised/cleared clamp can release buffered records without
            // any new observation arriving (the tail walkers consumed
            // records in this iteration): drain immediately so publication
            // follows the seal, never the next venue trade.
            match trade_union.flush()? {
                TradeUnionDisposition::Publishable(batch) => {
                    publish_trade_batch(batch, &mut journal, &origin, &mut trades_published)?;
                }
                TradeUnionDisposition::Buffered => {}
                other => {
                    return Err(format!(
                        "unexpected union disposition after handover clamp update: {other:?}"
                    ));
                }
            }
        }

        if debug_trace {
            eprintln!("[trace] {iteration} trades feed start");
        }
        // Trades: exact union of both lanes' durable records.
        {
            let mut advance_primary = false;
            feed_lane_trades(
                CaptureLane::Primary,
                &mut primary_binding,
                &mut primary_candidate,
                &mut trade_union,
                &mut journal,
                &origin,
                &mut trades_published,
                &mut late_corrections,
                &mut advance_primary,
            )?;
            let mut advance_shadow = false;
            feed_lane_trades(
                CaptureLane::Shadow,
                &mut shadow_binding,
                &mut shadow_candidate,
                &mut trade_union,
                &mut journal,
                &origin,
                &mut trades_published,
                &mut late_corrections,
                &mut advance_shadow,
            )?;
            if advance_primary {
                lane_trade_advance[lane_index(CaptureLane::Primary)] = Some(Instant::now());
            }
            if advance_shadow {
                lane_trade_advance[lane_index(CaptureLane::Shadow)] = Some(Instant::now());
            }
            // Once a predecessor is FULLY SEALED and drained (every durable
            // record it ever wrote has been consumed — the seal is the
            // terminal signal: the old stream can never deliver again) and
            // no tail walker remains for the lane, release the watermark.
            // Excluding on a mid-flight snapshot would let the successor
            // skip the predecessor's not-yet-durable tail (ADR-17 B3/B5).
            if primary_binding.trade_consumed == primary_binding.trade.records().len()
                && stream_fully_sealed(&primary_binding.generation_dir.join("trade"))?
                && primary_tails.is_empty()
                && primary_candidate.is_some()
            {
                trade_union.exclude_lane(CaptureLane::Primary);
            }
            if shadow_binding.trade_consumed == shadow_binding.trade.records().len()
                && stream_fully_sealed(&shadow_binding.generation_dir.join("trade"))?
                && shadow_tails.is_empty()
                && shadow_candidate.is_some()
            {
                trade_union.exclude_lane(CaptureLane::Shadow);
            }
        }

        if debug_trace {
            eprintln!("[trace] {iteration} lag policy");
        }
        // Lag policy: a live lane that stalls beyond the bound is excluded
        // from the watermark with a typed status; its late deliveries become
        // typed corrections, never silent drops.
        if trade_union.buffered() > 0 {
            let over_budget = trade_union.buffered() > TRADE_LAG_CAP;
            let stale = match lane_trade_advance[lane_index(serving_lane)] {
                Some(advanced) => advanced.elapsed() > TRADE_LAG_HORIZON,
                None => false,
            };
            if (over_budget || stale) && last_lag_report.elapsed() >= Duration::from_secs(10) {
                // Exclude the lane that holds the watermark (it is the one
                // blocking emission).
                let watermark_holder = match trade_union.watermark() {
                    Some(watermark) => {
                        let primary_next = trade_union.lane_next(CaptureLane::Primary);
                        let shadow_next = trade_union.lane_next(CaptureLane::Shadow);
                        match (primary_next, shadow_next) {
                            (Some(p), _) if p == watermark => Some(CaptureLane::Primary),
                            (_, Some(s)) if s == watermark => Some(CaptureLane::Shadow),
                            _ => None,
                        }
                    }
                    None => None,
                };
                if let Some(holder) = watermark_holder {
                    trade_union.exclude_lane(holder);
                    journal.append(
                        origin.elapsed().as_nanos() as u64,
                        "LIVE",
                        serde_json::json!({
                            "event": "TRADE_LAG",
                            "excluded_lane": lane_payload(holder),
                            "buffered": trade_union.buffered(),
                            "watermark": trade_union.watermark(),
                        }),
                    )?;
                }
                last_lag_report = Instant::now();
            }
        }

        if debug_trace {
            eprintln!("[trace] {iteration} depth section");
        }
        // Depth: the serving lane publishes its pending observations with
        // every frontier validated; the sibling accumulates for convergence.
        {
            let serving_outcome = {
                let serving_binding = if serving_lane == CaptureLane::Primary {
                    &mut primary_binding
                } else {
                    &mut shadow_binding
                };
                let applied = serving_binding.apply_new_depth()?;
                let canonical_final = canonical_position.final_sequence.unwrap_or(0);
                serving_binding.trim_depth_history(canonical_final, canonical_position.gap_floor);
                let outcome = publish_pending_depth(
                    &mut journal,
                    &origin,
                    serving_lane,
                    serving_binding,
                    &mut canonical_position,
                    &mut depth_published,
                )?;
                (applied, outcome)
            };
            match serving_outcome {
                (applied, DepthPublishOutcome::Published(published)) => {
                    if applied > 0 || published > 0 {
                        last_serving_progress = Instant::now();
                    }
                }
                (_, DepthPublishOutcome::GapDetected { .. }) => {
                    serving_gap_detected = true;
                }
            }
            let sibling_binding = if serving_lane == CaptureLane::Primary {
                &mut shadow_binding
            } else {
                &mut primary_binding
            };
            sibling_binding.apply_new_depth()?;
            let canonical_final = canonical_position.final_sequence.unwrap_or(0);
            sibling_binding.trim_depth_history(canonical_final, canonical_position.gap_floor);
        }

        if debug_trace {
            eprintln!("[trace] {iteration} switch resolution");
        }
        // Resume switch proof on every poll, including cooperative drain.
        // Exhausting the replay quota is never evidence authorizing a gap.
        if canonical_position.final_sequence.is_some()
            && (serving_generation_changed
                || serving_gap_detected
                || primary_binding.depth_switch_pending
                || shadow_binding.depth_switch_pending
                || last_serving_progress.elapsed() >= SWITCH_HORIZON)
        {
            let sibling_binding = if serving_lane == CaptureLane::Primary {
                &mut shadow_binding
            } else {
                &mut primary_binding
            };
            let sibling_tail =
                evaluate_depth_switch_with_fallback(&canonical_position, sibling_binding, true)?;
            let proof_pending = sibling_binding.depth_switch_pending;
            let mut switched = false;
            if let Some(tail) = sibling_tail {
                let new_serving_lane = match serving_lane {
                    CaptureLane::Primary => CaptureLane::Shadow,
                    CaptureLane::Shadow => CaptureLane::Primary,
                };
                // Every switched frame is frontier-validated too: a venue drop
                // inside the sibling's own tail stops the switch (the caller
                // then falls through to the typed gap below).
                let mut bridgeable = true;
                for observation in tail {
                    let expected = canonical_position
                        .final_sequence
                        .map(|final_sequence| final_sequence.saturating_add(1));
                    match classify_depth_frontier(
                        expected,
                        observation.first_sequence,
                        observation.final_sequence,
                    )? {
                        DepthFrontierDisposition::Contiguous
                        | DepthFrontierDisposition::Straddle { .. } => {
                            journal.append(
                                origin.elapsed().as_nanos() as u64,
                                "LIVE",
                                serde_json::json!({
                                    "event": "DEPTH_OBSERVATION",
                                    "first_sequence": observation.first_sequence,
                                    "final_sequence": observation.final_sequence,
                                    "lane": lane_payload(new_serving_lane),
                                    "record_sha256": observation.record_sha256,
                                    "observation_sha256": observation.observation_sha256,
                                }),
                            )?;
                            canonical_position.final_sequence = Some(observation.final_sequence);
                            canonical_position.digest = Some(observation.observation_sha256);
                            depth_published += 1;
                        }
                        DepthFrontierDisposition::Covered { .. } => {}
                        DepthFrontierDisposition::Missing { .. } => {
                            bridgeable = false;
                            break;
                        }
                    }
                }
                if bridgeable {
                    journal.append(
                        origin.elapsed().as_nanos() as u64,
                        "LIVE",
                        serde_json::json!({
                            "event": "DEPTH_SWITCH_PROVEN",
                            "from_lane": lane_payload(serving_lane),
                            "to_lane": lane_payload(new_serving_lane),
                            "boundary_final_sequence": canonical_position.final_sequence,
                        }),
                    )?;
                    serving_lane = new_serving_lane;
                    last_serving_progress = Instant::now();
                    switched = true;
                }
            }
            if !switched && !proof_pending && (serving_generation_changed || serving_gap_detected) {
                // Dual-loss boundary: the renewed serving lane cannot be
                // bridged from the sibling — either no sibling tail exists
                // or the tail itself carries an unprovable jump (a
                // present-but-unbridgeable tail must NEVER leave the
                // serving lane parked silently: the typed gap + evidenced
                // bootstrap of the successor is the honest resolution,
                // fault-gate defect hrs-0b2308e2099c: the canonical depth
                // ended one update short of the sealed evidence's trusted
                // end at the terminal).  Publish the typed gap and activate
                // the candidate with explicit bootstrap evidence.
                // Activation only after the predecessor's trade stream is
                // FULLY drained and sealed: its sealed tail can land a poll
                // or two after the renewal, and replacing the binding any
                // earlier abandons every record the follower had not yet
                // appended (fault-gate defect hrs-5addeeea3763: ETHUSDT
                // dropped 79 shadow-exclusive trades of a generation
                // consumed only up to its penultimate durable prefix).
                let (candidate_pending, predecessor_drained) =
                    if serving_lane == CaptureLane::Primary {
                        (
                            primary_candidate.is_some(),
                            primary_binding.trade_consumed == primary_binding.trade.records().len()
                                && binding_streams_sealed(&primary_binding)?,
                        )
                    } else {
                        (
                            shadow_candidate.is_some(),
                            shadow_binding.trade_consumed == shadow_binding.trade.records().len()
                                && binding_streams_sealed(&shadow_binding)?,
                        )
                    };
                if candidate_pending && predecessor_drained {
                    let binding_slot = if serving_lane == CaptureLane::Primary {
                        &mut primary_binding
                    } else {
                        &mut shadow_binding
                    };
                    let candidate_slot = if serving_lane == CaptureLane::Primary {
                        &mut primary_candidate
                    } else {
                        &mut shadow_candidate
                    };
                    let mut candidate = candidate_slot.take().expect("candidate just checked");
                    // The predecessor's remaining depth tail (already
                    // frontier-validated by the publisher) is everything the
                    // old generation can still prove; the gap boundary is the
                    // real cursor.
                    gap_and_bootstrap_depth(
                        &mut journal,
                        &origin,
                        serving_lane,
                        &mut candidate,
                        &mut canonical_position,
                        &mut depth_published,
                        &mut gaps_published,
                    )?;
                    *binding_slot = candidate;
                    if serving_lane == CaptureLane::Primary {
                        primary_rebind_since = None;
                    } else {
                        shadow_rebind_since = None;
                    }
                }
                last_serving_progress = Instant::now();
            }
        }

        if debug_trace {
            eprintln!("[trace] {iteration} stop check");
        }
        // Termination (ADR-17 B2): the request was computed at the top of
        // the iteration; the final iteration drains everything already
        // durable before the terminal record commits, so the failover
        // oracle can demand exact event identity against the redundant
        // evidence.
        if stop_requested {
            // Final drain (ADR-17 B5 closed-window completeness): the
            // canonical view must reach the sealed evidence's trusted end
            // before the terminal commits, or the closed oracle would
            // (correctly) reject the window as a final omission.  Pending
            // states that keep the loop draining:
            //   1. a pending SERVING-lane generation transition (the
            //      successor's bind resolves deterministically now that the
            //      captures are sealing; the exclusion of a drained
            //      predecessor with a bound candidate then releases the
            //      trade watermark — a buffered union trade must never be
            //      lost to a rebind, fault-gate defect 6669312440).  The
            //      NON-serving lane's generation change is NOT a drain
            //      condition: its binding legitimately stays on the old
            //      generation until a proven switch (the change persists
            //      for the rest of the run and would stall the stop);
            //   2. buffered union trades: each continued iteration feeds
            //      both lanes and drains below the watermark;
            //   3. unfinished handover tail walkers (ADR-17 B3/B5): a
            //      predecessor tail must be consumed through its final seal
            //      before the terminal commits;
            //   4. late durable records: the captures' final sync can land
            //      between this iteration's sections and the stop check.
            // Bounded by WALL TIME (~30 s, inside the launcher's 60 s
            // cooperative stop deadline): a successor that can never bind
            // leaves the window short and the closed audit fails closed
            // instead of fabricating continuity.  A REBIND stop skips the
            // seal/candidate waits: the successor owns them (the rebind
            // must never stall the canonical chain for the old epoch's
            // drain, ADR-17 B3 LIVE rebind).
            // A REBIND stop skips every seal/walker/buffer wait: the
            // successor owns the predecessor tails via --prior-artifact and
            // the un-published buffered trades are still above the floor in
            // the raw union (never duplicated, never lost).
            let (primary_trade_complete, shadow_trade_complete) = if !rebind_stop {
                // Feed and retire the tail walkers BEFORE the pending test:
                // a walker that consumed its sealed terminal cut must stop
                // holding the drain open (the retain requires the exact
                // sealed terminal — risk 2, never a stale snapshot length).
                refresh_and_retire_tail_walkers(
                    CaptureLane::Primary,
                    &mut primary_tails,
                    &mut trade_union,
                    &mut journal,
                    &origin,
                    &mut trades_published,
                    &mut late_corrections,
                )?;
                refresh_and_retire_tail_walkers(
                    CaptureLane::Shadow,
                    &mut shadow_tails,
                    &mut trade_union,
                    &mut journal,
                    &origin,
                    &mut trades_published,
                    &mut late_corrections,
                )?;
                let primary_complete = lane_trade_drain_complete(
                    &primary_binding,
                    primary_candidate.as_ref(),
                    &primary_tails,
                    primary_generation.as_deref(),
                )?;
                let shadow_complete = lane_trade_drain_complete(
                    &shadow_binding,
                    shadow_candidate.as_ref(),
                    &shadow_tails,
                    shadow_generation.as_deref(),
                )?;
                // An exhausted sealed lane cannot hold the other's final
                // union records behind its last ID. This must precede the
                // buffered-work pending check, not follow loop termination.
                for (lane, complete) in [
                    (CaptureLane::Primary, primary_complete),
                    (CaptureLane::Shadow, shadow_complete),
                ] {
                    if complete {
                        trade_union.clear_emission_clamp(lane);
                        trade_union.exclude_lane(lane);
                    }
                }
                // A raised/cleared clamp can release buffered records
                // without a new observation arriving.
                match trade_union.flush()? {
                    TradeUnionDisposition::Publishable(batch) => {
                        publish_trade_batch(batch, &mut journal, &origin, &mut trades_published)?;
                    }
                    TradeUnionDisposition::Buffered => {}
                    other => {
                        return Err(format!(
                            "unexpected union disposition during stop drain: {other:?}"
                        ));
                    }
                }
                (primary_complete, shadow_complete)
            } else {
                (true, true)
            };
            let mut pending = if rebind_stop {
                false
            } else {
                serving_generation_changed
                    || primary_binding.depth_switch_pending
                    || shadow_binding.depth_switch_pending
                    || trade_union.buffered() > 0
                    || !primary_trade_complete
                    || !shadow_trade_complete
            };
            if !pending {
                let primary_new =
                    primary_binding.depth.refresh()? + primary_binding.trade.refresh()?;
                let shadow_new =
                    shadow_binding.depth.refresh()? + shadow_binding.trade.refresh()?;
                pending = primary_new > 0 || shadow_new > 0;
            }
            // ADR-17 B5 terminal cut (fault-gate defect hrs-fa053dbc4a86):
            // "the refresh found no new records" is NOT proof that the
            // serving stream's sealed terminal evidence was consumed.  A
            // COMPLETE generation (generation.json) whose final seal holds
            // records the binding never loaded must keep draining; the
            // terminal commits only on the PROVEN sealed cut.  A killed
            // generation has no terminal declaration: nothing to demand
            // (the closed oracle uses its BNACK prefix, which the follower
            // follows by construction).  A REBIND stop is EXEMPT: the
            // successor owns the predecessor tails via --prior-artifact
            // (the rebind must never stall the canonical chain for the old
            // epoch's drain — ADR-17 B3 LIVE rebind; service-gate defect
            // hrs-04751fbe8d87: demanding convergence here failed the
            // rebind drain fail-closed mid-epoch).
            let serving_depth_converged = if rebind_stop {
                true
            } else if serving_lane == CaptureLane::Primary {
                serving_depth_converged(&primary_binding)?
            } else {
                serving_depth_converged(&shadow_binding)?
            };
            drain_deadline.get_or_insert_with(|| Instant::now() + Duration::from_secs(20));
            trace!(
                "drain iter {iteration} pending={} deadline={:?} converged={} pdepth={}/{} sdepth={}/{}",
                pending,
                drain_deadline.map(|d| d.elapsed().as_millis()),
                serving_depth_converged,
                primary_binding.depth_consumed,
                primary_binding.depth.records().len(),
                shadow_binding.depth_consumed,
                shadow_binding.depth.records().len(),
            );
            if pending && Instant::now() < drain_deadline.expect("drain deadline armed") {
                std::thread::sleep(POLL);
                continue;
            }
            if !pending {
                if serving_depth_converged {
                    break rebind_stop;
                }
                // The sealed generation is fully loaded, but its frames do
                // not continue the resumed cursor and there is no successor
                // candidate. The live path only types that gap when it
                // activates a candidate, so the pending queue never empties
                // and the stop fails closed on evidence it already holds.
                // A frame that continues the cursor is the normal tail: the
                // next iteration publishes it. Typing a gap there rewrites a
                // contiguous drain.
                if !stop_gap_bootstrapped {
                    let binding = if serving_lane == CaptureLane::Primary {
                        &mut primary_binding
                    } else {
                        &mut shadow_binding
                    };
                    let expected = canonical_position
                        .final_sequence
                        .map(|sequence| sequence.saturating_add(1));
                    let front_continues =
                        binding.pending_depth.front().is_some_and(|observation| {
                            expected.is_some_and(|expected| observation.first_sequence == expected)
                        });
                    let ready = generation_terminal_complete(&binding.generation_dir)?
                        && binding_streams_sealed(binding)?
                        && binding.depth_consumed == binding.depth.records().len()
                        && binding.depth.consumed_sealed_terminal()?
                        && !binding.pending_depth.is_empty()
                        && !front_continues;
                    if ready {
                        stop_gap_bootstrapped = true;
                        gap_and_bootstrap_depth(
                            &mut journal,
                            &origin,
                            serving_lane,
                            binding,
                            &mut canonical_position,
                            &mut depth_published,
                            &mut gaps_published,
                        )?;
                        continue;
                    }
                }
                // The refresh delivered nothing yet the sealed terminal cut
                // is unconsumed: keep polling (the follower converges on the
                // next poll), bounded — a serving stream that never
                // converges fails closed instead of committing a COMPLETE
                // the closed oracle would reject as a final omission.
                let convergence_deadline = convergence_deadline
                    .get_or_insert_with(|| Instant::now() + Duration::from_secs(30));
                if Instant::now() >= *convergence_deadline {
                    return Err(
                        "cooperative stop drain: the serving stream never converged on its sealed terminal evidence"
                            .to_owned(),
                    );
                }
                std::thread::sleep(POLL);
                continue;
            }
            // A timeout is not evidence that unpublished work disappeared.
            // Preserve the durable resumable prefix without a terminal.
            return Err(
                "cooperative stop drain timed out with pending work; journal remains incomplete"
                    .to_owned(),
            );
        }
        std::thread::sleep(POLL);
    };

    // Clean-stop drain (ADR-17 B3): when the service was stopped with its
    // lanes sealed (the supervisor epochs ended first), every buffered
    // trade below the released watermark is published exactly once, so the
    // closed oracle over the union can demand exact event identity.
    if continuous || resume_dir.is_some() {
        let lanes_sealed =
            binding_streams_sealed(&primary_binding)? && binding_streams_sealed(&shadow_binding)?;
        if lanes_sealed {
            trade_union.exclude_lane(CaptureLane::Primary);
            trade_union.exclude_lane(CaptureLane::Shadow);
            match trade_union.flush()? {
                TradeUnionDisposition::Publishable(batch) => {
                    publish_trade_batch(batch, &mut journal, &origin, &mut trades_published)?;
                }
                TradeUnionDisposition::Buffered => {}
                other => {
                    return Err(format!(
                        "terminal trade drain produced an unexpected disposition: {other:?}"
                    ));
                }
            }
        }
    }

    journal.append(
        origin.elapsed().as_nanos() as u64,
        "LIVE",
        serde_json::json!({
            "event": "ARBITRATION_TERMINAL",
            "status": "COMPLETE",
            "completion_scope": if handoff_terminal { "HANDOFF" } else { "SEALED_DRAIN" },
            "trades": trades_published,
            "depth_frames": depth_published,
            "gaps": gaps_published,
            "late_corrections": late_corrections,
            "serving_lane_at_terminal": lane_payload(serving_lane),
        }),
    )?;
    Ok(output_journal)
}

fn main() {
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            eprintln!("live-arbitration: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lob_replay::live_arbitration::{
        LiveArbitrationJournalEnvelopeV1, LiveArbitrationJournalWriter,
    };

    fn regression_20260922_fixture_dir(name: &str) -> PathBuf {
        let root = env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join("canonical-fault-fixtures");
        fs::create_dir_all(&root).unwrap();
        let path = tempfile::Builder::new()
            .prefix(name)
            .tempdir_in(root)
            .unwrap()
            .keep();
        eprintln!("retained fault fixture: {}", path.display());
        path
    }

    fn regression_20260922_generation(
        artifact: &Path,
        lane: &str,
        stamp: u64,
        ids: &[u64],
        complete: bool,
    ) -> (
        PathBuf,
        lob_replay::segment_chain::RawSegmentManifestWriter,
        lob_replay::segment_chain::RawSegmentManifestWriter,
    ) {
        use lob_replay::segment_chain::RawSegmentManifestWriter;
        let campaign = artifact.join(lane).join("campaign");
        let epoch = format!("{stamp}-{lane}");
        let generation = lob_reply_helpers::make_generation(
            &campaign,
            &format!("{stamp}-BTCUSDT-g000-fixture"),
            "BTCUSDT",
            &epoch,
        );
        // The fixture helper wrote only the empty manifest header; replace
        // that owned fixture header with the sealed depth fixture below.
        let mut depth_manifest = RawSegmentManifestWriter::from_sink(
            fs::File::create(generation.join("depth/segments.bnseg")).unwrap(),
        )
        .unwrap();
        let depth_frames = [
            lob_reply_helpers::fixture_frame(
                "BTCUSDT", "btcusdt@depth", &epoch, 0, 10,
                br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":101,"u":101,"b":[],"a":[]}"#,
            ),
            lob_reply_helpers::fixture_frame(
                "BTCUSDT", "btcusdt@depth", &epoch, 1, 11,
                br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":102,"u":105,"b":[["100","4"]],"a":[]}"#,
            ),
        ];
        lob_reply_helpers::append_segment_fixture(
            &generation.join("depth"),
            &mut depth_manifest,
            &root_segment_genesis(&epoch, "btcusdt@depth").unwrap(),
            &depth_frames,
        );
        let mut trade_manifest =
            RawSegmentManifestWriter::create(&generation.join("trade/segments.bnseg")).unwrap();
        let frames: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                lob_reply_helpers::trade_frame(
                    "BTCUSDT",
                    &epoch,
                    index as u64,
                    20 + index as u64,
                    *id,
                )
            })
            .collect();
        lob_reply_helpers::append_segment_fixture(
            &generation.join("trade"),
            &mut trade_manifest,
            &root_segment_genesis(&epoch, "btcusdt@trade").unwrap(),
            &frames,
        );
        if complete {
            lob_reply_helpers::mark_generation_complete(&generation);
        }
        (generation, trade_manifest, depth_manifest)
    }

    fn regression_20260922_seed_resume(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let journals = root.join("journals");
        let identity = root.join("identity.bin");
        let first = journals.join("BTCUSDT-seg-0000.jsonl");
        let next = journals.join("BTCUSDT-seg-0001.jsonl");
        let mut journal = LiveArbitrationJournalWriter::create(&first).unwrap();
        journal
            .append(
                0,
                "LIVE",
                serde_json::json!({
                    "event":"ARBITRATION_STARTED","symbol":"BTCUSDT","trade_floor":0
                }),
            )
            .unwrap();
        journal
            .append(
                1,
                "LIVE",
                serde_json::json!({
                    "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                    "trades":0,"depth_frames":0,"gaps":0,"late_corrections":0
                }),
            )
            .unwrap();
        (journals, identity, next)
    }

    fn regression_20260922_start(
        root: &Path,
        artifact: &Path,
        prior: &Path,
    ) -> (PathBuf, std::thread::JoinHandle<Result<PathBuf>>) {
        let (journals, identity, next) = regression_20260922_seed_resume(root);
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            artifact.to_string_lossy().into_owned(),
            next.to_string_lossy().into_owned(),
            "3".to_owned(),
            "--identity".to_owned(),
            identity.to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            journals.to_string_lossy().into_owned(),
            "--prior-artifact".to_owned(),
            prior.to_string_lossy().into_owned(),
        ];
        let child = std::thread::spawn(move || run_with_args(args.into_iter()));
        (next, child)
    }

    fn regression_20260922_ids_if_complete(path: &Path) -> Vec<u64> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|record| {
                        let payload = &record["body"]["payload"];
                        (payload["event"] == "TRADE_OBSERVATION")
                            .then(|| payload["trade_id"].as_u64())
                            .flatten()
                    })
            })
            .collect()
    }

    #[test]
    fn regression_20260922_failed_generation_without_snapshot_still_binds_trades() {
        let artifact = regression_20260922_fixture_dir("failed-no-snapshot-");
        let (generation, _, _) =
            regression_20260922_generation(&artifact, "p", 10, &[6704116076, 6704116077], false);
        fs::remove_file(generation.join("snapshot.bnraw")).unwrap();
        let failed = serde_json::json!({
            "schema": "RawGenerationManifestV1",
            "status": "FAILED",
            "snapshot": null,
            "failure": "transport watchdog pong deadline exceeded"
        });
        fs::write(
            generation.join("generation.json"),
            serde_json::to_vec(&failed).unwrap(),
        )
        .unwrap();
        let bound = LaneBinding::bind_generation(generation.parent().unwrap(), &generation)
            .expect("terminal FAILED generation must keep its durable trades bindable");
        assert_eq!(bound.trade.records().len(), 2);

        let (empty_depth, _, _) =
            regression_20260922_generation(&artifact, "s", 11, &[6704116616], false);
        fs::remove_file(empty_depth.join("snapshot.bnraw")).unwrap();
        fs::write(
            empty_depth.join("generation.json"),
            serde_json::to_vec(&failed).unwrap(),
        )
        .unwrap();
        fs::write(empty_depth.join("depth/segment-000000.bnraw"), [0_u8; 8]).unwrap();
        let bound = LaneBinding::bind_generation(empty_depth.parent().unwrap(), &empty_depth)
            .expect("empty depth on a FAILED generation must not discard its trades");
        assert_eq!(bound.trade.records().len(), 1);
        assert!(bound.depth.records().is_empty());

        let (open_generation, _, _) =
            regression_20260922_generation(&artifact, "p", 12, &[3], false);
        fs::remove_file(open_generation.join("snapshot.bnraw")).unwrap();
        let error =
            match LaneBinding::bind_generation(open_generation.parent().unwrap(), &open_generation)
            {
                Ok(_) => {
                    panic!("a generation without a terminal FAILED declaration stays fail-closed")
                }
                Err(error) => error,
            };
        assert!(error.contains("lacks a snapshot"), "{error}");

        let (complete_generation, _, _) =
            regression_20260922_generation(&artifact, "s", 13, &[4], true);
        fs::remove_file(complete_generation.join("snapshot.bnraw")).unwrap();
        let error = match LaneBinding::bind_generation(
            complete_generation.parent().unwrap(),
            &complete_generation,
        ) {
            Ok(_) => panic!("COMPLETE without a snapshot stays fail-closed"),
            Err(error) => error,
        };
        assert!(error.contains("lacks a snapshot"), "{error}");
    }

    #[test]
    fn regression_20260922_sealed_prior_progresses_without_generation_change() {
        let root = regression_20260922_fixture_dir("sealed-prior-");
        let prior = root.join("prior");
        let live = root.join("live");
        for lane in ["p", "s"] {
            regression_20260922_generation(&prior, lane, 1000, &[101, 111], true);
            regression_20260922_generation(&live, lane, 2000, &[300, 450], true);
        }
        let (journal, child) = regression_20260922_start(&root, &live, &prior);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut ids = Vec::new();
        while Instant::now() < deadline {
            ids = regression_20260922_ids_if_complete(&journal);
            if ids.contains(&450) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // Join and preserve final output before asserting. The stop drain
        // must not conceal that no progress occurred during normal capture.
        let result = child.join().unwrap();
        assert!(result.is_ok(), "main failed: {result:?}");
        assert_eq!(
            ids,
            vec![101, 111, 300, 450],
            "sealed prior clamp prevented live progress before stop"
        );
    }

    #[test]
    fn regression_20260922_late_prior_seal_progresses_without_generation_change() {
        use lob_replay::segment_chain::successor_segment_genesis;
        let root = regression_20260922_fixture_dir("late-prior-seal-");
        let prior = root.join("prior");
        let live = root.join("live");
        let mut held = Vec::new();
        for lane in ["p", "s"] {
            let (generation, manifest, _) =
                regression_20260922_generation(&prior, lane, 1000, &[101, 111], false);
            let trade = generation.join("trade");
            let scan = scan_segment_manifest(&trade.join("segments.bnseg")).unwrap();
            let next = successor_segment_genesis(&scan.entries[0].seal).unwrap();
            let frames = [lob_reply_helpers::trade_frame(
                "BTCUSDT",
                &format!("1000-{lane}"),
                2,
                30,
                150,
            )];
            let (raw_file, ack, progress) =
                lob_reply_helpers::write_in_flight_segment(&trade, &next, &frames);
            held.push((generation, manifest, next, raw_file, ack, progress));
            regression_20260922_generation(&live, lane, 2000, &[300, 450], true);
        }
        let (journal, child) = regression_20260922_start(&root, &live, &prior);
        let ready_deadline = Instant::now() + Duration::from_secs(1);
        while regression_20260922_ids_if_complete(&journal).is_empty()
            && Instant::now() < ready_deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        for (generation, mut manifest, next, raw_file, ack, mut progress) in held {
            progress.append(ack.clone()).unwrap();
            lob_reply_helpers::seal_in_flight(
                &generation.join("trade"),
                &mut manifest,
                &next,
                &raw_file,
                &ack,
            );
            lob_reply_helpers::mark_generation_complete(&generation);
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut ids = Vec::new();
        while Instant::now() < deadline {
            ids = regression_20260922_ids_if_complete(&journal);
            if ids.contains(&450) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let result = child.join().unwrap();
        assert!(result.is_ok(), "main failed: {result:?}");
        assert_eq!(
            ids,
            vec![101, 111, 150, 300, 450],
            "late ACK+seal must be consumed without a new live generation"
        );
    }

    #[test]
    fn regression_20260922_depth_pruning_preserves_exact_switch_witness() {
        let root = regression_20260922_fixture_dir("depth-witness-");
        let (generation, _, _) =
            regression_20260922_generation(&root.join("live"), "s", 2000, &[300, 450], true);
        let campaign = generation.parent().unwrap().parent().unwrap();
        let mut sibling = LaneBinding::bind_generation(campaign, &generation).unwrap();
        let observations = materialize_binding_observations(&sibling).unwrap();
        let boundary = observations[0].clone();
        sibling.pending_depth = VecDeque::from(observations);
        let canonical = CanonicalDepthPosition {
            final_sequence: Some(101),
            digest: Some(boundary.observation_sha256),
            gap_floor: None,
        };
        sibling.trim_depth_history(101, None);
        let tail = evaluate_depth_switch_with_fallback(&canonical, &mut sibling, false).unwrap();
        assert_eq!(
            tail.map(|tail| tail
                .iter()
                .map(|obs| obs.final_sequence)
                .collect::<Vec<_>>()),
            Some(vec![105]),
            "pruning consumed observations must retain the exact convergence witness"
        );
    }

    #[test]
    fn regression_20260922_each_published_depth_uses_the_new_frontier() {
        let root = regression_20260922_fixture_dir("depth-frontier-");
        let (generation, _, _) =
            regression_20260922_generation(&root.join("live"), "p", 2000, &[300, 450], true);
        let mut binding = LaneBinding::bind_generation(
            generation.parent().unwrap().parent().unwrap(),
            &generation,
        )
        .unwrap();
        binding.pending_depth = materialize_binding_observations(&binding).unwrap().into();
        let mut canonical = CanonicalDepthPosition {
            final_sequence: Some(100),
            digest: Some("snapshot".to_owned()),
            gap_floor: None,
        };
        let mut journal =
            LiveArbitrationJournalWriter::create(&root.join("frontier.jsonl")).unwrap();
        let mut published = 0;
        let result = publish_pending_depth(
            &mut journal,
            &Instant::now(),
            CaptureLane::Primary,
            &mut binding,
            &mut canonical,
            &mut published,
        )
        .unwrap();
        assert!(
            matches!(result, DepthPublishOutcome::Published(2)),
            "second contiguous frame must not be classified as a gap"
        );
        assert_eq!(canonical.final_sequence, Some(105));
        assert_eq!(published, 2);
    }

    #[test]
    fn regression_20260922_stale_wrong_and_gap_witness_never_switch() {
        let root = regression_20260922_fixture_dir("negative-witness-");
        let (generation, _, _) =
            regression_20260922_generation(&root.join("live"), "s", 2000, &[300, 450], true);
        let mut binding = LaneBinding::bind_generation(
            generation.parent().unwrap().parent().unwrap(),
            &generation,
        )
        .unwrap();
        let observations = materialize_binding_observations(&binding).unwrap();
        let digest = observations[0].observation_sha256.clone();
        binding.pending_depth = observations.into();
        binding.trim_depth_history(101, None);
        let wrong = CanonicalDepthPosition {
            final_sequence: Some(101),
            digest: Some("wrong".to_owned()),
            gap_floor: None,
        };
        assert!(
            evaluate_depth_switch_with_fallback(&wrong, &mut binding, false)
                .unwrap()
                .is_none()
        );
        let advanced = CanonicalDepthPosition {
            final_sequence: Some(102),
            digest: Some(digest.clone()),
            gap_floor: None,
        };
        binding.trim_depth_history(102, None);
        assert!(binding.depth_convergence_witness.is_none());
        assert!(
            evaluate_depth_switch_with_fallback(&advanced, &mut binding, false)
                .unwrap()
                .is_none()
        );
        binding.depth_convergence_witness =
            Some(materialize_binding_observations(&binding).unwrap()[0].clone());
        binding.trim_depth_history(101, Some(101));
        assert!(binding.depth_convergence_witness.is_none());
        let rebound = LaneBinding::bind_generation(
            generation.parent().unwrap().parent().unwrap(),
            &generation,
        )
        .unwrap();
        assert!(rebound.depth_convergence_witness.is_none());
    }

    fn regression_20260922_long_generation(artifact: &Path, lane: &str) -> PathBuf {
        use lob_replay::segment_chain::successor_segment_genesis;
        let (generation, _, mut manifest) =
            regression_20260922_generation(artifact, lane, 2000, &[300, 450], false);
        let path = generation.join("depth/segments.bnseg");
        let scan = scan_segment_manifest(&path).unwrap();
        let genesis = successor_segment_genesis(&scan.entries[0].seal).unwrap();
        let frames: Vec<_> = (0..600).map(|index| {
            let sequence = 106 + index;
            let payload = serde_json::json!({"e":"depthUpdate","E":sequence,"s":"BTCUSDT","U":sequence,"u":sequence,"b":[],"a":[]});
            lob_reply_helpers::fixture_frame("BTCUSDT", "btcusdt@depth", &format!("2000-{lane}"), index+2, index+30, &serde_json::to_vec(&payload).unwrap())
        }).collect();
        lob_reply_helpers::append_segment_fixture(
            &generation.join("depth"),
            &mut manifest,
            &genesis,
            &frames,
        );
        lob_reply_helpers::mark_generation_complete(&generation);
        generation
    }

    #[test]
    fn regression_20260922_fallback_slices_preserve_exact_historical_tail() {
        let root = regression_20260922_fixture_dir("fallback-slices-");
        let generation = regression_20260922_long_generation(&root.join("live"), "s");
        let mut binding = LaneBinding::bind_generation(
            generation.parent().unwrap().parent().unwrap(),
            &generation,
        )
        .unwrap();
        let oracle = materialize_binding_observations(&binding).unwrap();
        let boundary = &oracle[200];
        let mut previous = 0;
        let mut polls = 0;
        loop {
            let result = replay_sibling_slice(
                &mut binding,
                boundary.final_sequence,
                &boundary.observation_sha256,
                7,
            )
            .unwrap();
            polls += 1;
            if result.is_some() {
                break;
            }
            assert!(
                binding.depth_switch_pending,
                "budget exhaustion is pending, not negative proof"
            );
            let consumed = binding.depth_switch_replay.as_ref().unwrap().consumed;
            assert!(consumed > previous && consumed - previous <= 7);
            previous = consumed;
            assert!(polls < 100);
        }
        assert!(polls > 1);
        let mut actual: Vec<_> = binding.pending_depth.drain(..).collect();
        while binding.depth_consumed < binding.depth.records().len() {
            let before = binding.depth_consumed;
            binding.apply_new_depth().unwrap();
            assert!(binding.depth_consumed - before <= DEPTH_SWITCH_RECORD_BUDGET);
            actual.extend(binding.pending_depth.drain(..));
        }
        let expected: Vec<_> = oracle
            .iter()
            .skip(201)
            .map(|obs| {
                (
                    &obs.record_sha256,
                    &obs.observation_sha256,
                    obs.final_sequence,
                )
            })
            .collect();
        let actual: Vec<_> = actual
            .iter()
            .map(|obs| {
                (
                    &obs.record_sha256,
                    &obs.observation_sha256,
                    obs.final_sequence,
                )
            })
            .collect();
        assert_eq!(
            actual, expected,
            "cursor transfer must retain every historical observation and exact digest"
        );
    }

    #[test]
    fn regression_20260922_stop_during_resume_fallback_drains_exact_tail() {
        let root = regression_20260922_fixture_dir("stop-during-fallback-");
        let artifact = root.join("live");
        let primary = regression_20260922_long_generation(&artifact, "p");
        regression_20260922_long_generation(&artifact, "s");
        let binding =
            LaneBinding::bind_generation(primary.parent().unwrap().parent().unwrap(), &primary)
                .unwrap();
        let oracle = materialize_binding_observations(&binding).unwrap();
        let boundary = &oracle[400];
        let journals = root.join("journals");
        let mut seed =
            LiveArbitrationJournalWriter::create(&journals.join("BTCUSDT-seg-0000.jsonl")).unwrap();
        seed.append(
            0,
            "LIVE",
            serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT","trade_floor":0}),
        )
        .unwrap();
        seed.append(1, "LIVE", serde_json::json!({"event":"DEPTH_OBSERVATION","lane":"PRIMARY","first_sequence":boundary.first_sequence,"final_sequence":boundary.final_sequence,"record_sha256":boundary.record_sha256,"observation_sha256":boundary.observation_sha256})).unwrap();
        seed.append(2, "LIVE", serde_json::json!({"event":"ARBITRATION_TERMINAL","status":"COMPLETE","trades":0,"depth_frames":1,"gaps":0,"late_corrections":0})).unwrap();
        drop(seed);
        let output = journals.join("BTCUSDT-seg-0001.jsonl");
        let stop = root.join("stop.flag");
        fs::write(&stop, "stop fixture").unwrap();
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            artifact.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
            "--continuous".to_owned(),
            "--identity".to_owned(),
            root.join("identity.bin").to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            journals.to_string_lossy().into_owned(),
            "--stop-file".to_owned(),
            stop.to_string_lossy().into_owned(),
        ];
        let started = Instant::now();
        run_with_args(args.into_iter()).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "small sealed fixture must drain cooperatively across quotas"
        );
        let values: Vec<serde_json::Value> = fs::read_to_string(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let actual: Vec<_> = values
            .iter()
            .filter_map(|record| {
                let payload = &record["body"]["payload"];
                (payload["event"] == "DEPTH_OBSERVATION").then(|| {
                    (
                        payload["final_sequence"].as_u64().unwrap(),
                        payload["observation_sha256"].as_str().unwrap(),
                    )
                })
            })
            .collect();
        let expected: Vec<_> = oracle
            .iter()
            .skip(401)
            .map(|obs| (obs.final_sequence, obs.observation_sha256.as_str()))
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            values.last().unwrap()["body"]["payload"]["completion_scope"],
            "SEALED_DRAIN"
        );
        assert!(
            !values
                .iter()
                .any(|record| record["body"]["payload"]["event"] == "GAP")
        );
    }

    #[test]
    fn regression_20260922_incremental_cursor_rejects_identity_changes() {
        let root = regression_20260922_fixture_dir("cursor-identity-");
        let (generation, _, _) =
            regression_20260922_generation(&root.join("live"), "p", 2000, &[300, 450], true);
        let binding = LaneBinding::bind_generation(
            generation.parent().unwrap().parent().unwrap(),
            &generation,
        )
        .unwrap();
        let snapshots = read_raw_records(&binding.snapshot_path).unwrap();
        let first = &binding.depth.records()[0];
        let mut wrong = first.clone();
        wrong.frame.symbol = "ETHUSDT".to_owned();
        assert!(DepthObservationCursor::from_snapshot(&snapshots[0], &wrong).is_err());
        let mut cursor = DepthObservationCursor::from_snapshot(&snapshots[0], first).unwrap();
        wrong = first.clone();
        wrong.frame.connection_epoch = "another-epoch".to_owned();
        assert!(cursor.apply_record(&wrong).is_err());
        let observation = cursor.apply_record(first).unwrap().unwrap();
        assert_eq!(
            observation.observation_sha256,
            materialize_binding_observations(&binding).unwrap()[0].observation_sha256
        );
    }

    #[test]
    fn regression_20260922_unsealed_pending_timeout_never_completes() {
        let root = regression_20260922_fixture_dir("pending-timeout-");
        let prior = root.join("prior");
        let live = root.join("live");
        for lane in ["p", "s"] {
            regression_20260922_generation(&prior, lane, 1000, &[101, 111], false);
            regression_20260922_generation(&live, lane, 2000, &[300, 450], true);
        }
        let (journal, child) = regression_20260922_start(&root, &live, &prior);
        let result = child.join().unwrap();
        assert!(
            result.is_err(),
            "pending predecessor timed out but claimed completion: {result:?}"
        );
        let contents = fs::read_to_string(journal).unwrap();
        assert!(
            !contents.contains("ARBITRATION_TERMINAL"),
            "timeout must preserve an incomplete resumable prefix"
        );
    }

    #[test]
    fn regression_p0_unsealed_prior_lag_preserves_late_and_live_progress() {
        use lob_replay::segment_chain::successor_segment_genesis;
        let root = regression_20260922_fixture_dir("p0-unsealed-lag-");
        let prior = root.join("prior");
        let live = root.join("live");
        let mut held = Vec::new();
        let mut current = Vec::new();
        for lane in ["p", "s"] {
            let (generation, _, _) =
                regression_20260922_generation(&prior, lane, 1000, &[101, 111], false);
            let trade = generation.join("trade");
            let scan = scan_segment_manifest(&trade.join("segments.bnseg")).unwrap();
            let genesis = successor_segment_genesis(&scan.entries[0].seal).unwrap();
            let frames = [lob_reply_helpers::trade_frame(
                "BTCUSDT",
                &format!("1000-{lane}"),
                2,
                40,
                150,
            )];
            let (_, ack, progress) =
                lob_reply_helpers::write_in_flight_segment(&trade, &genesis, &frames);
            held.push((ack, progress));
            let (generation, manifest, _) =
                regression_20260922_generation(&live, lane, 2000, &[300, 450], false);
            current.push((generation, manifest, lane));
        }
        let (journals, identity, journal) = regression_20260922_seed_resume(&root);
        let stop = root.join("stop.flag");
        let rebind = root.join("rebind.flag");
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            live.to_string_lossy().into_owned(),
            journal.to_string_lossy().into_owned(),
            "--continuous".to_owned(),
            "--identity".to_owned(),
            identity.to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            journals.to_string_lossy().into_owned(),
            "--prior-artifact".to_owned(),
            prior.to_string_lossy().into_owned(),
            "--stop-file".to_owned(),
            stop.to_string_lossy().into_owned(),
            "--rebind-file".to_owned(),
            rebind.to_string_lossy().into_owned(),
        ];
        let child = std::thread::spawn(move || {
            run_with_tail_lag_horizon(args.into_iter(), Duration::from_millis(100))
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut step = 0;
        let mut progressed = false;
        while Instant::now() < deadline {
            for (generation, manifest, lane) in &mut current {
                let trade = generation.join("trade");
                let scan = scan_segment_manifest(&trade.join("segments.bnseg")).unwrap();
                let genesis =
                    successor_segment_genesis(&scan.entries.last().unwrap().seal).unwrap();
                let frames = [lob_reply_helpers::trade_frame(
                    "BTCUSDT",
                    &format!("2000-{lane}"),
                    step + 2,
                    step + 50,
                    600 + step * 100,
                )];
                lob_reply_helpers::append_segment_fixture(&trade, manifest, &genesis, &frames);
            }
            step += 1;
            if regression_20260922_ids_if_complete(&journal).contains(&450) {
                progressed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        for (ack, mut progress) in held {
            progress.append(ack).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if fs::read_to_string(&journal)
                .unwrap_or_default()
                .contains("TRADE_LATE_CORRECTION")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        fs::write(rebind, "transfer pending fixture").unwrap();
        let result = child.join().unwrap();
        assert!(result.is_ok(), "main failed: {result:?}");
        assert!(
            progressed,
            "current lanes kept advancing but interrupted prior clamped live publication forever"
        );
        let rows: Vec<serde_json::Value> = fs::read_to_string(journal)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(
            rows.iter()
                .any(|row| row["body"]["payload"]["event"] == "TRADE_LAG"
                    && row["body"]["payload"]["reason"] == "predecessor_lag")
        );
        let corrections: Vec<_> = rows
            .iter()
            .filter(|row| {
                row["body"]["payload"]["event"] == "TRADE_LATE_CORRECTION"
                    && row["body"]["payload"]["trade_id"] == 150
            })
            .collect();
        assert_eq!(
            corrections.len(),
            2,
            "both genuine late raw lineages must survive origin exclusion"
        );
        assert_eq!(corrections[0]["body"]["payload"]["kind"], "unknown");
        assert_eq!(corrections[1]["body"]["payload"]["kind"], "duplicate");
        assert_eq!(
            rows.last().unwrap()["body"]["payload"]["completion_scope"],
            "HANDOFF"
        );
        let recovered = recover_arbitration_state_opt(
            &root.join("journals"),
            &root.join("identity.bin"),
            &root.join("journals/BTCUSDT-seg-0002.jsonl"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            recovered.excluded_tail_origins.len(),
            2,
            "origin lag exclusions must survive a restart"
        );
        assert_eq!(recovered.corrected_identities.len(), 1);
        assert!(recovered.corrected_identities.contains_key(&150));
        // A lag exclusion restores publication, never fabricates source
        // closure. Even with both current generations now COMPLETE, the
        // unsealed prior prevents a SEALED_DRAIN terminal on normal stop.
        for (generation, _, _) in &current {
            lob_reply_helpers::mark_generation_complete(generation);
        }
        fs::write(root.join("stop.flag"), "normal stop fixture").unwrap();
        let next = root.join("journals/BTCUSDT-seg-0002.jsonl");
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            live.to_string_lossy().into_owned(),
            next.to_string_lossy().into_owned(),
            "--continuous".to_owned(),
            "--identity".to_owned(),
            root.join("identity.bin").to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            root.join("journals").to_string_lossy().into_owned(),
            "--prior-artifact".to_owned(),
            prior.to_string_lossy().into_owned(),
            "--stop-file".to_owned(),
            root.join("stop.flag").to_string_lossy().into_owned(),
        ];
        let result = run_with_tail_lag_horizon(args.into_iter(), Duration::from_millis(100));
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.contains("pending work")),
            "unclosed predecessor must fail normal close: {result:?}"
        );
        assert!(
            !fs::read_to_string(next)
                .unwrap()
                .contains("ARBITRATION_TERMINAL")
        );
    }

    #[test]
    fn regression_p0_new_prior_below_resume_floor_emits_unknown() {
        let root = regression_20260922_fixture_dir("p0-resume-floor-");
        let prior = root.join("prior");
        let live = root.join("live");
        let mut primary = None;
        for lane in ["p", "s"] {
            regression_20260922_generation(&prior, lane, 1000, &[90, 150], true);
            let (generation, _, _) =
                regression_20260922_generation(&live, lane, 2000, &[300, 450, 600], true);
            if lane == "p" {
                primary = Some(generation);
            }
        }
        let generation = primary.unwrap();
        let binding = LaneBinding::bind_generation(
            generation.parent().unwrap().parent().unwrap(),
            &generation,
        )
        .unwrap();
        let journals = root.join("journals");
        let mut seed =
            LiveArbitrationJournalWriter::create(&journals.join("BTCUSDT-seg-0000.jsonl")).unwrap();
        seed.append(
            0,
            "LIVE",
            serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT","trade_floor":100}),
        )
        .unwrap();
        for (index, raw) in binding.trade.records()[..2].iter().enumerate() {
            let obs = materialize_trade_record(raw).unwrap();
            seed.append(index as u64 + 1, "LIVE", serde_json::json!({"event":"TRADE_OBSERVATION","trade_id":obs.final_sequence,"lane":"PRIMARY","record_sha256":obs.record_sha256,"observation_sha256":obs.observation_sha256})).unwrap();
        }
        for (index, obs) in materialize_binding_observations(&binding)
            .unwrap()
            .iter()
            .enumerate()
        {
            seed.append(index as u64 + 3, "LIVE", serde_json::json!({"event":"DEPTH_OBSERVATION","lane":"PRIMARY","first_sequence":obs.first_sequence,"final_sequence":obs.final_sequence,"record_sha256":obs.record_sha256,"observation_sha256":obs.observation_sha256})).unwrap();
        }
        seed.append(5, "LIVE", serde_json::json!({"event":"ARBITRATION_TERMINAL","status":"COMPLETE","trades":2,"depth_frames":2,"gaps":0,"late_corrections":0})).unwrap();
        drop(seed);
        let journal = journals.join("BTCUSDT-seg-0001.jsonl");
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            live.to_string_lossy().into_owned(),
            journal.to_string_lossy().into_owned(),
            "1".to_owned(),
            "--identity".to_owned(),
            root.join("identity.bin").to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            journals.to_string_lossy().into_owned(),
            "--prior-artifact".to_owned(),
            prior.to_string_lossy().into_owned(),
        ];
        run_with_args(args.into_iter()).unwrap();
        let rows: Vec<serde_json::Value> = fs::read_to_string(journal)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let unknown: Vec<_> = rows
            .iter()
            .filter_map(|row| {
                let payload = &row["body"]["payload"];
                (payload["event"] == "TRADE_LATE_CORRECTION" && payload["kind"] == "unknown")
                    .then(|| payload["trade_id"].as_u64().unwrap())
            })
            .collect();
        assert_eq!(
            unknown,
            vec![150],
            "startup floor100 cannot silently suppress an unknown ID150 below resume cursor450"
        );
        assert!(rows.iter().any(
            |row| row["body"]["payload"]["event"] == "ARBITRATION_RESUMED"
                && row["body"]["payload"]["trade_floor"] == 450
        ));
        let next = journals.join("BTCUSDT-seg-0002.jsonl");
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            live.to_string_lossy().into_owned(),
            next.to_string_lossy().into_owned(),
            "1".to_owned(),
            "--identity".to_owned(),
            root.join("identity.bin").to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            journals.to_string_lossy().into_owned(),
            "--prior-artifact".to_owned(),
            prior.to_string_lossy().into_owned(),
        ];
        run_with_args(args.into_iter()).unwrap();
        let rows: Vec<serde_json::Value> = fs::read_to_string(next)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let repeated: Vec<_> = rows
            .iter()
            .filter(|row| {
                row["body"]["payload"]["event"] == "TRADE_LATE_CORRECTION"
                    && row["body"]["payload"]["trade_id"] == 150
            })
            .collect();
        assert_eq!(
            repeated.len(),
            1,
            "only the lane not already stored as a duplicate is new evidence"
        );
        assert!(
            repeated
                .iter()
                .all(|row| row["body"]["payload"]["kind"] == "duplicate"),
            "recovery must restore correction identity, not emit UNKNOWN again"
        );
        let third = journals.join("BTCUSDT-seg-0003.jsonl");
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            live.to_string_lossy().into_owned(),
            third.to_string_lossy().into_owned(),
            "1".to_owned(),
            "--identity".to_owned(),
            root.join("identity.bin").to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            journals.to_string_lossy().into_owned(),
            "--prior-artifact".to_owned(),
            prior.to_string_lossy().into_owned(),
        ];
        run_with_args(args.into_iter()).unwrap();
        let rows: Vec<serde_json::Value> = fs::read_to_string(third)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(
            rows.iter().all(|row| {
                let payload = &row["body"]["payload"];
                !(payload["event"] == "TRADE_LATE_CORRECTION" && payload["trade_id"] == 150)
            }),
            "a later resume must not append the same duplicate correction again"
        );
    }

    fn regression_smoke03_sealed_stop_fixture(renew_shadow: bool) {
        let root = regression_20260922_fixture_dir("smoke03-sealed-stop-");
        let live = root.join("live");
        regression_20260922_generation(&live, "p", 2000, &[101, 111], true);
        regression_20260922_generation(
            &live,
            "s",
            2000,
            if renew_shadow {
                &[101, 111]
            } else {
                &[101, 111, 150]
            },
            true,
        );
        let (journals, identity, output) = regression_20260922_seed_resume(&root);
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            live.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
            "1".to_owned(),
            "--identity".to_owned(),
            identity.to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            journals.to_string_lossy().into_owned(),
        ];
        let started = Instant::now();
        let child = std::thread::spawn(move || run_with_args(args.into_iter()));
        if renew_shadow {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !regression_20260922_ids_if_complete(&output).contains(&111)
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                regression_20260922_ids_if_complete(&output).contains(&111),
                "initial lane binding must precede successor creation"
            );
            regression_20260922_generation(&live, "s", 3000, &[111, 150], true);
        }
        let result = child.join().unwrap();
        assert!(
            result.is_ok(),
            "sealed unequal lane heads must release final union before pending check: {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "sealed drain must not wait for lag/timeout policy"
        );
        assert_eq!(
            regression_20260922_ids_if_complete(&output),
            vec![101, 111, 150]
        );
        let rows: Vec<serde_json::Value> = fs::read_to_string(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            rows.last().unwrap()["body"]["payload"]["completion_scope"],
            "SEALED_DRAIN"
        );
    }

    #[test]
    fn regression_smoke03_unequal_sealed_heads_release_final_union() {
        regression_smoke03_sealed_stop_fixture(false);
    }

    #[test]
    fn regression_smoke03_nonserving_sealed_candidate_does_not_hold_stop() {
        regression_smoke03_sealed_stop_fixture(true);
    }

    #[test]
    fn regression_smoke03_closure_requires_latest_consumed_seal() {
        let root = regression_20260922_fixture_dir("smoke03-seal-proof-");
        let (generation, _, _) =
            regression_20260922_generation(&root, "p", 2000, &[101, 111], true);
        let campaign = generation.parent().unwrap().parent().unwrap();
        let mut binding = LaneBinding::bind_generation(campaign, &generation).unwrap();
        assert!(
            !lane_trade_drain_complete(&binding, None, &[], Some(&generation)).unwrap(),
            "loaded but not observed trades are pending"
        );
        binding.trade_consumed = binding.trade.records().len();
        assert!(lane_trade_drain_complete(&binding, None, &[], Some(&generation)).unwrap());
        let (successor, _, _) = regression_20260922_generation(&root, "p", 3000, &[150], true);
        assert!(
            !lane_trade_drain_complete(&binding, None, &[], Some(&successor)).unwrap(),
            "a newer unbound origin is pending"
        );
        let mut candidate = LaneBinding::bind_generation(campaign, &successor).unwrap();
        assert!(
            !lane_trade_drain_complete(&binding, Some(&candidate), &[], Some(&successor)).unwrap(),
            "candidate records must be observed too"
        );
        candidate.trade_consumed = candidate.trade.records().len();
        assert!(
            lane_trade_drain_complete(&binding, Some(&candidate), &[], Some(&successor)).unwrap()
        );
        fs::write(
            successor.join("generation.json"),
            br#"{"schema":"RawGenerationManifestV1","status":"RUNNING","failure":null}"#,
        )
        .unwrap();
        assert!(
            !lane_trade_drain_complete(&binding, Some(&candidate), &[], Some(&successor)).unwrap(),
            "sealed segments without generation terminal never prove closure"
        );
    }

    #[test]
    fn regression_smoke03_missing_explicit_prior_is_rejected_before_output() {
        let root = regression_20260922_fixture_dir("smoke03-missing-prior-");
        let live = root.join("live");
        for lane in ["p", "s"] {
            regression_20260922_generation(&live, lane, 2000, &[101, 111], true);
        }
        let (journals, identity, output) = regression_20260922_seed_resume(&root);
        let missing = root.join("absent-explicit-prior");
        let args = vec![
            "live_arbitration".to_owned(),
            "BTCUSDT".to_owned(),
            live.to_string_lossy().into_owned(),
            output.to_string_lossy().into_owned(),
            "1".to_owned(),
            "--identity".to_owned(),
            identity.to_string_lossy().into_owned(),
            "--resume-dir".to_owned(),
            journals.to_string_lossy().into_owned(),
            "--prior-artifact".to_owned(),
            missing.to_string_lossy().into_owned(),
        ];
        let result = run_with_args(args.into_iter());
        assert!(
            result.as_ref().is_err_and(
                |reason| reason.contains("--prior-artifact is not an existing directory")
            ),
            "an explicitly requested missing origin must not disappear silently: {result:?}"
        );
        assert!(
            !output.exists(),
            "invalid inventory must be rejected before canonical output"
        );
    }

    fn regression_p1_restart_fixture(tail: &[u8], reject: bool) {
        use std::io::Write;
        let root = regression_20260922_fixture_dir("p1-torn-restarts-");
        let live = root.join("live");
        let (generation, _, _) =
            regression_20260922_generation(&live, "p", 2000, &[300, 450, 600], true);
        regression_20260922_generation(&live, "s", 2000, &[300, 450, 600], true);
        let binding = LaneBinding::bind_generation(
            generation.parent().unwrap().parent().unwrap(),
            &generation,
        )
        .unwrap();
        let depth = materialize_binding_observations(&binding).unwrap();
        let trade = materialize_trade_record(&binding.trade.records()[0]).unwrap();
        let journals = root.join("journals");
        let first = journals.join("BTCUSDT-seg-0000.jsonl");
        let mut seed = LiveArbitrationJournalWriter::create(&first).unwrap();
        seed.append(
            0,
            "LIVE",
            serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"BTCUSDT","trade_floor":100}),
        )
        .unwrap();
        seed.append(1,"LIVE",serde_json::json!({"event":"TRADE_OBSERVATION","trade_id":300,"lane":"PRIMARY","record_sha256":trade.record_sha256,"observation_sha256":trade.observation_sha256})).unwrap();
        for (index, obs) in depth.iter().enumerate() {
            seed.append(index as u64+2,"LIVE",serde_json::json!({"event":"DEPTH_OBSERVATION","lane":"PRIMARY","first_sequence":obs.first_sequence,"final_sequence":obs.final_sequence,"record_sha256":obs.record_sha256,"observation_sha256":obs.observation_sha256})).unwrap();
        }
        drop(seed);
        fs::OpenOptions::new()
            .append(true)
            .open(&first)
            .unwrap()
            .write_all(tail)
            .unwrap();
        let identity = root.join("identity.bin");
        for index in 1..=2 {
            let output = journals.join(format!("BTCUSDT-seg-{index:04}.jsonl"));
            let args = vec![
                "live_arbitration".to_owned(),
                "BTCUSDT".to_owned(),
                live.to_string_lossy().into_owned(),
                output.to_string_lossy().into_owned(),
                "1".to_owned(),
                "--identity".to_owned(),
                identity.to_string_lossy().into_owned(),
                "--resume-dir".to_owned(),
                journals.to_string_lossy().into_owned(),
            ];
            let result = run_with_args(args.into_iter());
            if reject {
                assert!(
                    result.is_err(),
                    "newline-terminated corrupt record must fail closed"
                );
                return;
            }
            assert!(
                result.is_ok(),
                "restart{index} must recover exact complete prefix despite torn bytes: {result:?}"
            );
            let rows: Vec<serde_json::Value> = fs::read_to_string(&output)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(
                rows[0]["body"]["payload"]["previous_tail_bytes"]
                    .as_u64()
                    .unwrap_or(0),
                if index == 1 { tail.len() as u64 } else { 3 }
            );
            assert!(
                !rows
                    .iter()
                    .any(|row| row["body"]["payload"]["event"] == "DEPTH_OBSERVATION"),
                "fixture continuation must exercise inherited depth without fresh depth records"
            );
            let next = journals.join(format!("BTCUSDT-seg-{:04}.jsonl", index + 1));
            let recovered = recover_arbitration_state_opt(&journals, &identity, &next)
                .unwrap()
                .unwrap();
            assert_eq!(
                recovered.canonical_position.final_sequence,
                Some(105),
                "depth state belongs to the entire chain, not only its last file"
            );
            assert_eq!(
                recovered.canonical_position.digest.as_ref(),
                Some(&depth[1].observation_sha256)
            );
            if index == 1 {
                // Retain the real main output's complete prefix, simulating
                // interruption immediately before its terminal was written.
                let bytes = fs::read(&output).unwrap();
                let terminal_start = bytes[..bytes.len() - 1]
                    .iter()
                    .rposition(|byte| *byte == b'\n')
                    .unwrap()
                    + 1;
                let mut interrupted = bytes[..terminal_start].to_vec();
                interrupted.extend_from_slice(&[0xf0, 0x9f, 0x92]);
                fs::write(&output, interrupted).unwrap();
            }
        }
    }

    #[test]
    fn regression_p1_ascii_torn_survives_two_real_restarts() {
        regression_p1_restart_fixture(b"{\"unfinished\":", false);
    }
    #[test]
    fn regression_p1_utf8_torn_survives_two_real_restarts() {
        regression_p1_restart_fixture(&[0xf0, 0x9f, 0x92], false);
    }
    #[test]
    fn regression_p1_depth_cursor_survives_segment_without_depth() {
        regression_p1_restart_fixture(b"", false);
    }
    #[test]
    fn regression_p1_newline_terminated_corruption_is_rejected() {
        regression_p1_restart_fixture(b"{bad}\n", true);
        regression_p1_restart_fixture(&[0xf0, 0x9f, 0x92, b'\n'], true);
    }

    /// ADR-17 B3 regression (full-gate defect hr-04e9f268cc0c): the last
    /// journal segment legitimately carried NO trade records (RESUMED + GAP
    /// right before a crash), and the recovery dropped the accumulated trade
    /// floor to 0, corrupting every later ARBITRATION_RESUMED.  The recovered
    /// floor must be the cumulative maximum across ALL segments.
    #[test]
    fn recovery_keeps_trade_floor_when_last_segment_has_no_trades() {
        let dir = tempfile::tempdir().unwrap();
        let segment_zero = dir.path().join("ETHUSDT-seg-0000.jsonl");
        let segment_one = dir.path().join("ETHUSDT-seg-0001.jsonl");
        let next_segment = dir.path().join("ETHUSDT-seg-0002.jsonl");
        let identity = dir.path().join("trade-identity.log");
        let floor: u64 = 4_340_361_667;
        {
            let mut writer = LiveArbitrationJournalWriter::create(&segment_zero).unwrap();
            writer
                .append(
                    1,
                    "LIVE",
                    serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"ETHUSDT","trade_floor":0}),
                )
                .unwrap();
            writer
                .append(
                    2,
                    "LIVE",
                    serde_json::json!({
                        "event":"TRADE_OBSERVATION","trade_id":floor,"lane":"PRIMARY",
                        "record_sha256":"a".repeat(64),"observation_sha256":"b".repeat(64)
                    }),
                )
                .unwrap();
            writer
                .append(
                    3,
                    "LIVE",
                    serde_json::json!({
                        "event":"ARBITRATION_TERMINAL","status":"COMPLETE",
                        "trades":1,"depth_frames":0,"gaps":0,"late_corrections":0
                    }),
                )
                .unwrap();
        }
        let previous_sha = std::fs::read_to_string(&segment_zero)
            .unwrap()
            .lines()
            .last()
            .and_then(|line| serde_json::from_str::<LiveArbitrationJournalEnvelopeV1>(line).ok())
            .map(|envelope| envelope.record_sha256)
            .unwrap();
        {
            // Crash survivor: RESUMED chaining segment zero, then a typed GAP,
            // then the process dies before any trade or depth publishes.
            let mut writer = LiveArbitrationJournalWriter::create(&segment_one).unwrap();
            writer
                .append(
                    1,
                    "LIVE",
                    serde_json::json!({
                        "event":"ARBITRATION_RESUMED","symbol":"ETHUSDT","mode":"CONTINUOUS",
                        "previous_journal_sha256":previous_sha,"trade_floor":floor
                    }),
                )
                .unwrap();
            writer
                .append(
                    2,
                    "LIVE",
                    serde_json::json!({
                        "event":"GAP","reason":"unprovable_continuation",
                        "renewed_lane":"SHADOW","stream_kind":"DEPTH","canonical_last_sequence":0
                    }),
                )
                .unwrap();
        }
        let recovered = recover_arbitration_state_opt(dir.path(), &identity, &next_segment)
            .unwrap()
            .expect("recovery must find the previous chain");
        assert_eq!(recovered.trades, 1);
        assert_eq!(
            recovered.last_trade_id,
            Some(floor),
            "the trade floor must survive a trade-less final segment"
        );
    }

    #[test]
    fn duplicate_correction_already_in_the_journal_is_not_new() {
        let mut known = BTreeSet::new();
        assert!(duplicate_correction_is_new(&mut known, 7, "PRIMARY", "abc"));
        assert!(!duplicate_correction_is_new(
            &mut known, 7, "PRIMARY", "abc"
        ));
        assert!(duplicate_correction_is_new(&mut known, 7, "SHADOW", "abc"));
    }

    #[test]
    fn recovery_remembers_journaled_duplicate_corrections() {
        let dir = tempfile::tempdir().unwrap();
        let segment = dir.path().join("BTCUSDT-seg-0000.jsonl");
        let next = dir.path().join("BTCUSDT-seg-0001.jsonl");
        let identity = dir.path().join("trade-identity.log");
        let digest = "b".repeat(64);
        {
            let mut writer = LiveArbitrationJournalWriter::create(&segment).unwrap();
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
                        "event":"TRADE_OBSERVATION","trade_id":40,"lane":"PRIMARY",
                        "record_sha256":"a".repeat(64),"observation_sha256":digest
                    }),
                )
                .unwrap();
            writer
                .append(
                    3,
                    "LIVE",
                    serde_json::json!({
                        "event":"TRADE_LATE_CORRECTION","trade_id":40,"lane":"SHADOW",
                        "kind":"duplicate","record_sha256":"c".repeat(64),
                        "observation_sha256":digest
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
        }
        let recovered = recover_arbitration_state_opt(dir.path(), &identity, &next)
            .unwrap()
            .expect("recovery must find the previous chain");
        assert!(recovered.journaled_duplicate_corrections.contains(&(
            40,
            "SHADOW".to_owned(),
            digest
        )));
        assert_eq!(recovered.journaled_duplicate_corrections.len(), 1);
    }

    /// Fault-gate defect 2026-09-17 (closure run hrs-7c9c792ca38c): the
    /// arbiter crashed BEFORE its first trade publication.  The STARTED
    /// segment declared a non-zero bind floor (the union fast-forward
    /// boundary) but the resumed generation recovered floor 0 and
    /// re-published the pre-bind region, failing the closed-set oracle
    /// ("arbitration journal publishes a trade at or below its declared
    /// floor").  The recovered floor must be the maximum of the published
    /// trades AND the declared bind floor.
    #[test]
    fn recovery_preserves_bind_floor_when_crash_precedes_first_trade() {
        let dir = tempfile::tempdir().unwrap();
        let segment_zero = dir.path().join("ETHUSDT-seg-0000.jsonl");
        let next_segment = dir.path().join("ETHUSDT-seg-0001.jsonl");
        let identity = dir.path().join("trade-identity.log");
        let bind_floor: u64 = 4_364_395_512;
        {
            let mut writer = LiveArbitrationJournalWriter::create(&segment_zero).unwrap();
            writer
                .append(
                    1,
                    "LIVE",
                    serde_json::json!({"event":"ARBITRATION_STARTED","symbol":"ETHUSDT","trade_floor":bind_floor}),
                )
                .unwrap();
            for index in 0..3_u64 {
                writer
                    .append(
                        2 + index,
                        "LIVE",
                        serde_json::json!({
                            "event":"DEPTH_OBSERVATION","lane":"PRIMARY",
                            "first_sequence":100 + index * 21,"final_sequence":120 + index * 21,
                            "record_sha256":"c".repeat(64),"observation_sha256":"d".repeat(64)
                        }),
                    )
                    .unwrap();
            }
            // Crash before the first trade: no TRADE_OBSERVATION, no terminal.
        }
        let recovered = recover_arbitration_state_opt(dir.path(), &identity, &next_segment)
            .unwrap()
            .expect("recovery must find the previous chain");
        assert_eq!(recovered.trades, 0);
        assert_eq!(
            recovered.last_trade_id,
            Some(bind_floor),
            "the declared bind floor must survive a crash that precedes the first trade"
        );
    }

    /// ADR-17 B3 regression (full-gate defect hrs-04e9f268cc0c): a depth
    /// segment rotation landing between the binding's `open` (which saw the
    /// empty manifest and bound the in-flight root) and `bootstrap_depth`
    /// (which re-scans the manifest and now sees the sealed root) used to
    /// fail with "depth durable prefix is shorter than the sealed root" and
    /// killed the arbiter exactly inside the post-gap bootstrap.  The
    /// bootstrap must synchronize the follow state to the manifest authority
    /// first and derive the cursor over the freshly sealed root.
    #[test]
    fn bootstrap_depth_accepts_a_rotation_landing_after_open() {
        use lob_reply_helpers::{append_segment_fixture, fixture_frame};
        let dir = tempfile::tempdir().unwrap();
        let campaign = dir.path().join("hr-fixture");
        let generation = campaign.join("generations").join("fixture-g000");
        let depth_dir = generation.join("depth");
        let trade_dir = generation.join("trade");
        std::fs::create_dir_all(&depth_dir).unwrap();
        std::fs::create_dir_all(&trade_dir).unwrap();
        let symbol = "BTCUSDT";
        let depth_stream = "btcusdt@depth@100ms";
        let depth_epoch = "depth-fixture";
        let snapshot_payload =
            br#"{"lastUpdateId":100,"bids":[["100","2"],["99","1"]],"asks":[["101","3"],["102","1"]]}"#;
        let snapshot_path = generation.join("snapshot.bnraw");
        {
            let mut snapshot_writer =
                lob_replay::RawLogWriter::create(&snapshot_path, 100).unwrap();
            snapshot_writer
                .append(&fixture_frame(
                    symbol,
                    "btcusdt@rest-depth-snapshot",
                    "snapshot-fixture",
                    0,
                    5,
                    snapshot_payload,
                ))
                .unwrap();
            snapshot_writer.sync().unwrap();
        }
        // Both stream manifests exist but carry NO seal entries yet: this is
        // the state the failing binding observed in its `open`.
        let mut depth_manifest = lob_replay::segment_chain::RawSegmentManifestWriter::create(
            &depth_dir.join("segments.bnseg"),
        )
        .unwrap();
        let trade_manifest = lob_replay::segment_chain::RawSegmentManifestWriter::create(
            &trade_dir.join("segments.bnseg"),
        )
        .unwrap();
        drop(trade_manifest);
        let mut binding =
            LaneBinding::bind_generation(&campaign, &generation).expect("bind_generation");
        assert!(
            binding.depth.records().is_empty(),
            "the fixture must open with no sealed depth records"
        );
        // The rotation lands NOW: segment 0 completes, its ACK is durable and
        // the manifest seals it — without any refresh in between.
        let depth_root =
            lob_replay::segment_chain::root_segment_genesis(depth_epoch, depth_stream).unwrap();
        let frames = [
            fixture_frame(symbol, depth_stream, depth_epoch, 0, 10, br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":99,"u":100,"b":[],"a":[]}"#),
            fixture_frame(symbol, depth_stream, depth_epoch, 1, 20, br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":101,"u":101,"b":[["100","0"]],"a":[]}"#),
        ];
        append_segment_fixture(&depth_dir, &mut depth_manifest, &depth_root, &frames);
        drop(depth_manifest);
        binding
            .bootstrap_depth()
            .expect("bootstrap must synchronize to the freshly sealed root instead of failing");
        assert_eq!(
            binding.depth_consumed, 2,
            "the sealed root's records must be consumed exactly once"
        );
        assert!(binding.depth_cursor.is_some());
        assert!(binding.pending_depth.is_empty());
    }

    /// ADR-17 B3/B5 boundary regression (fault-gate defect hrs-fa053dbc4a86):
    /// the live drain committed the terminal while the serving stream still
    /// held ACKed, sealed records the canonical never published (ETH ended at
    /// 80854734742 while the p seal continued at 80854734743).  The
    /// follower must converge EXACTLY on the seal across progressive
    /// durability ACKs: every ACKed batch is consumed on the next refresh,
    /// and after the final sync + seal the in-memory chain equals the
    /// manifest seal (count, terminal digest, frame bounds).
    #[test]
    fn follower_converges_across_progressive_acks_and_final_seal() {
        use lob_replay::RawLogWriter;
        use lob_replay::durability_progress::DurabilityProgressWriter;
        use lob_replay::segment_chain::{
            RawSegmentManifestWriter, root_segment_genesis, scan_segment_manifest,
            successor_segment_genesis, verify_and_seal_raw_segment,
        };
        use lob_reply_helpers::{append_segment_fixture, fixture_frame};
        let dir = tempfile::tempdir().unwrap();
        let campaign = dir.path().join("hr-fixture");
        let generation = campaign.join("generations").join("1000-BTCUSDT-g000-g");
        let depth_dir = generation.join("depth");
        let trade_dir = generation.join("trade");
        std::fs::create_dir_all(&depth_dir).unwrap();
        std::fs::create_dir_all(&trade_dir).unwrap();
        // Snapshot with lastUpdateId 100; the sealed root carries one Old
        // prefix frame and two applied frames.
        let snapshot_path = generation.join("snapshot.bnraw");
        {
            let mut snapshot_writer = RawLogWriter::create(&snapshot_path, 100).unwrap();
            snapshot_writer
                .append(&fixture_frame(
                    "BTCUSDT",
                    "btcusdt@rest-depth-snapshot",
                    "g0",
                    0,
                    5,
                    br#"{"lastUpdateId":100,"bids":[["100","2"]],"asks":[["101","3"]]}"#,
                ))
                .unwrap();
            snapshot_writer.sync().unwrap();
        }
        let stream = "btcusdt@depth@100ms";
        let epoch = "g0";
        // Sealed root segment: frames 0..2 (one Old prefix frame, two applied).
        let mut manifest =
            RawSegmentManifestWriter::create(&depth_dir.join("segments.bnseg")).unwrap();
        let trade_manifest =
            RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
        drop(trade_manifest);
        let root = root_segment_genesis(epoch, stream).unwrap();
        let root_frames = [
            fixture_frame(
                "BTCUSDT",
                stream,
                epoch,
                0,
                10,
                br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":99,"u":100,"b":[],"a":[]}"#,
            ),
            fixture_frame(
                "BTCUSDT",
                stream,
                epoch,
                1,
                20,
                br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":101,"u":101,"b":[],"a":[]}"#,
            ),
            fixture_frame(
                "BTCUSDT",
                stream,
                epoch,
                2,
                30,
                br#"{"e":"depthUpdate","E":3,"s":"BTCUSDT","U":102,"u":102,"b":[],"a":[]}"#,
            ),
        ];
        append_segment_fixture(&depth_dir, &mut manifest, &root, &root_frames);
        let second = successor_segment_genesis(
            &scan_segment_manifest(&depth_dir.join("segments.bnseg"))
                .unwrap()
                .entries[0]
                .seal,
        )
        .unwrap();
        let mut binding =
            LaneBinding::bind_generation(&campaign, &generation).expect("bind_generation");
        binding
            .bootstrap_depth()
            .expect("bootstrap the sealed root");
        assert_eq!(binding.depth.records().len(), 3);
        assert_eq!(binding.depth_consumed, 3);
        // In-flight successor segment with a LIVE writer: durability ACKs
        // land progressively (group sync every 3 records), exactly the
        // cadence the failing live drain observed.
        let raw_path = depth_dir.join("segment-000001.bnraw");
        let mut writer = RawLogWriter::create_segment(&raw_path, 3, &second).unwrap();
        let mut progress = DurabilityProgressWriter::create_with_reference(
            &depth_dir.join("segment-000001.bnack"),
            &raw_path,
            "segment-000001.bnraw",
        )
        .unwrap();
        let mut acks: Vec<lob_replay::DurabilityAckV1> = Vec::new();
        for i in 0..7 {
            let payload = format!(
                r#"{{"e":"depthUpdate","E":{},"s":"BTCUSDT","U":{},"u":{},"b":[],"a":[]}}"#,
                100 + i,
                103 + i,
                103 + i
            );
            let receipt = writer
                .append(&fixture_frame(
                    "BTCUSDT",
                    stream,
                    epoch,
                    3 + i,
                    100 + i * 10,
                    payload.as_bytes(),
                ))
                .unwrap();
            if let Some(ack) = receipt.durability_ack {
                progress.append(ack.clone()).unwrap();
                acks.push(ack);
                binding.refresh().expect("refresh after progressive ACK");
                let consumed = binding.depth.records().len() - 3;
                assert_eq!(
                    consumed,
                    acks.len() * 3,
                    "the follower must consume every ACKed batch exactly"
                );
            }
        }
        assert_eq!(acks.len(), 2, "two group-sync ACKs for seven records");
        // Final sync + seal: the capture's terminal rotation.
        let final_ack = writer.sync().unwrap();
        drop(writer);
        progress.append(final_ack.clone()).unwrap();
        drop(progress);
        let raw_file = "segment-000001.bnraw";
        let verified = verify_and_seal_raw_segment(&raw_path, raw_file, &second, &final_ack)
            .expect("verify final segment");
        let seal = verified.seal().clone();
        manifest.append_verified(&verified).unwrap();
        drop(manifest);
        binding.refresh().expect("refresh after final seal");
        // Exact convergence on the seal: all 10 records, terminal digest,
        // frame bounds; the follow state advanced past the seal.
        assert_eq!(binding.depth.records().len(), 10);
        assert_eq!(
            binding.depth.records().last().unwrap().record_sha256,
            seal.terminal_record_sha256,
            "the follower must converge on the seal's terminal digest"
        );
        assert_eq!(
            binding.depth.records().last().unwrap().frame.frame_index,
            seal.last_frame_index
        );
        assert_eq!(binding.depth.segment_index, 2, "advanced past the seal");
        // The sealed records materialize into publishable observations.
        let applied = binding.apply_new_depth().expect("apply final records");
        assert_eq!(applied, 7);
        assert!(binding.pending_depth.len() >= 7);
        assert_eq!(
            binding
                .pending_depth
                .back()
                .expect("final pending observation")
                .final_sequence,
            109,
            "the sealed continuation must reach the trusted end"
        );
    }

    /// ADR-17 boundary regression (review 2026-09-11 risk 1): the capture
    /// finalizes the current segment BEFORE creating the next one — a
    /// legitimate execution window with the next file absent and the
    /// producer still alive.  `stream_fully_sealed` must NOT read that
    /// window as the definitive end: only the generation's durable
    /// terminal declaration (generation.json COMPLETE) authorizes
    /// "the stream can never deliver again".
    #[test]
    fn live_rotation_window_is_not_misread_as_terminal() {
        use lob_replay::segment_chain::RawSegmentManifestWriter;
        use lob_reply_helpers::{append_segment_fixture, fixture_frame};
        let dir = tempfile::tempdir().unwrap();
        let campaign = dir.path().join("hr-fixture");
        let generation = campaign.join("generations").join("1000-BTCUSDT-g000-g");
        let depth_dir = generation.join("depth");
        std::fs::create_dir_all(&depth_dir).unwrap();
        let stream = "btcusdt@depth@100ms";
        let epoch = "g0";
        let mut manifest =
            RawSegmentManifestWriter::create(&depth_dir.join("segments.bnseg")).unwrap();
        let genesis = lob_replay::segment_chain::root_segment_genesis(epoch, stream).unwrap();
        let frames = [fixture_frame(
            "BTCUSDT",
            stream,
            epoch,
            0,
            10,
            br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":101,"u":101,"b":[],"a":[]}"#,
        )];
        append_segment_fixture(&depth_dir, &mut manifest, &genesis, &frames);
        drop(manifest);
        // The rotation window: segment 0 sealed and announced, the writer
        // paused before creating segment-000001 — and NO terminal
        // declaration exists yet.
        assert!(!depth_dir.join("segment-000001.bnraw").is_file());
        assert!(!generation.join("generation.json").is_file());
        assert!(
            !stream_fully_sealed(&depth_dir).unwrap(),
            "a live rotation window (next file absent, no COMPLETE declaration) must not be misread as the definitive end"
        );
        // A live producer creating the successor file still is not terminal.
        std::fs::write(depth_dir.join("segment-000001.bnraw"), b"BNRAW\0\x01\n").unwrap();
        assert!(!stream_fully_sealed(&depth_dir).unwrap());
        std::fs::remove_file(depth_dir.join("segment-000001.bnraw")).unwrap();
        // The capture's durable terminal declaration is the authority.
        lob_reply_helpers::mark_generation_complete(&generation);
        assert!(
            stream_fully_sealed(&depth_dir).unwrap(),
            "COMPLETE generation without a successor file IS the definitive end"
        );
    }

    /// ADR-17 boundary regression (review 2026-09-11 risk 2): a tail
    /// walker consumes a prefix; the writer appends the final records AND
    /// seals BETWEEN that consumption and the retirement check.  The
    /// retirement must require consumption of the SAME sealed terminal cut
    /// (identity, count, terminal digest) — never the length of a stale
    /// snapshot — or the final records would be lost forever.
    #[test]
    fn walker_retire_requires_the_sealed_terminal_cut() {
        use lob_replay::RawLogWriter;
        use lob_replay::durability_progress::DurabilityProgressWriter;
        use lob_replay::segment_chain::{
            RawSegmentManifestWriter, root_segment_genesis, scan_segment_manifest,
            successor_segment_genesis, verify_and_seal_raw_segment,
        };
        use lob_reply_helpers::{append_segment_fixture, fixture_frame, mark_generation_complete};
        let dir = tempfile::tempdir().unwrap();
        let campaign = dir.path().join("hr-fixture");
        let generation = campaign.join("generations").join("1000-BTCUSDT-g000-g");
        let trade_dir = generation.join("trade");
        let depth_dir = generation.join("depth");
        std::fs::create_dir_all(&trade_dir).unwrap();
        std::fs::create_dir_all(&depth_dir).unwrap();
        let snapshot_path = generation.join("snapshot.bnraw");
        {
            let mut snapshot_writer = RawLogWriter::create(&snapshot_path, 100).unwrap();
            snapshot_writer
                .append(&fixture_frame(
                    "BTCUSDT",
                    "btcusdt@rest-depth-snapshot",
                    "g0",
                    0,
                    5,
                    br#"{"lastUpdateId":100,"bids":[["100","2"]],"asks":[["101","3"]]}"#,
                ))
                .unwrap();
            snapshot_writer.sync().unwrap();
        }
        let depth_manifest =
            RawSegmentManifestWriter::create(&depth_dir.join("segments.bnseg")).unwrap();
        drop(depth_manifest);
        let trade_stream = "btcusdt@trade";
        let epoch = "g0";
        // Segment 0 sealed: trades 100..102.
        let mut manifest =
            RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
        let root = root_segment_genesis(epoch, trade_stream).unwrap();
        let root_frames: Vec<_> = (0..3)
            .map(|i| lob_reply_helpers::trade_frame("BTCUSDT", epoch, i, 100 + i * 10, 100 + i))
            .collect();
        append_segment_fixture(&trade_dir, &mut manifest, &root, &root_frames);
        let second = successor_segment_genesis(
            &scan_segment_manifest(&trade_dir.join("segments.bnseg"))
                .unwrap()
                .entries[0]
                .seal,
        )
        .unwrap();
        // Segment 1 in-flight: batch A (103..105) written and ACKed.
        let raw_path = trade_dir.join("segment-000001.bnraw");
        let mut writer = RawLogWriter::create_segment(&raw_path, 3, &second).unwrap();
        let mut progress = DurabilityProgressWriter::create_with_reference(
            &trade_dir.join("segment-000001.bnack"),
            &raw_path,
            "segment-000001.bnraw",
        )
        .unwrap();
        for i in 0..3 {
            let receipt = writer
                .append(&lob_reply_helpers::trade_frame(
                    "BTCUSDT",
                    epoch,
                    3 + i,
                    300 + i * 10,
                    103 + i,
                ))
                .unwrap();
            if let Some(ack) = receipt.durability_ack {
                progress.append(ack.clone()).unwrap();
            }
        }
        let binding =
            LaneBinding::bind_generation(&campaign, &generation).expect("bind_generation");
        let walker_binding =
            LaneBinding::bind_generation(&campaign, &generation).expect("walker bind");
        let mut tails = vec![GenerationTailWalker {
            generation: generation.clone(),
            binding: walker_binding,
            floor: 102,
            last_durable_advance: Instant::now(),
            lag_excluded: false,
        }];
        let journal_path = dir.path().join("journal.jsonl");
        let mut journal = LiveArbitrationJournalWriter::create(&journal_path).unwrap();
        let origin = Instant::now();
        let mut trades_published = 0_u64;
        let mut late_corrections = 0_u64;
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        union.restore_published_floor(102).unwrap();
        // The sibling lane's stream is exhausted: it stops bounding the
        // watermark, so the tail's records publish as soon as they are
        // walked (the exact drain/terminal shape).
        union.exclude_lane(CaptureLane::Primary);
        let _ = &binding;
        // 1. The walker consumes the ACKed prefix (103..105) — a stale
        //    snapshot: consumed == records().len() == 3.
        refresh_and_retire_tail_walkers(
            CaptureLane::Shadow,
            &mut tails,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
        )
        .unwrap();
        assert_eq!(tails.len(), 1, "the unsealed walker must stay");
        // 2. THE INJECTION: the writer appends the FINAL batch (106..108)
        //    and seals the segment BETWEEN the consumption above and the
        //    retirement check below.
        for i in 0..3 {
            writer
                .append(&lob_reply_helpers::trade_frame(
                    "BTCUSDT",
                    epoch,
                    6 + i,
                    600 + i * 10,
                    106 + i,
                ))
                .unwrap();
        }
        let final_ack = writer.sync().unwrap();
        drop(writer);
        progress.append(final_ack.clone()).unwrap();
        drop(progress);
        let verified =
            verify_and_seal_raw_segment(&raw_path, "segment-000001.bnraw", &second, &final_ack)
                .unwrap();
        manifest.append_verified(&verified).unwrap();
        drop(manifest);
        mark_generation_complete(&generation);
        // 3. The retirement test compares against the SEALED TERMINAL CUT:
        //    the in-memory chain (3 records) does not converge on the seal
        //    (6 records) — the walker must NOT retire on the stale length.
        retire_consumed_tail_walkers(&mut tails);
        assert_eq!(
            tails.len(),
            1,
            "an append+seal landing after consumption must keep the walker alive"
        );
        // 4. The next refresh consumes the final records through the seal
        //    and the walker retires only then.
        refresh_and_retire_tail_walkers(
            CaptureLane::Shadow,
            &mut tails,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
        )
        .unwrap();
        assert_eq!(
            tails.len(),
            0,
            "the converged walker retires on the sealed cut"
        );
        match union.flush().unwrap() {
            TradeUnionDisposition::Publishable(batch) => {
                publish_trade_batch(batch, &mut journal, &origin, &mut trades_published).unwrap();
            }
            TradeUnionDisposition::Buffered => {
                // The observe path already drained below the watermark.
            }
            other => panic!("unexpected union disposition: {other:?}"),
        }
        assert_eq!(
            journal_trade_ids(&journal_path),
            vec![103, 104, 105, 106, 107, 108],
            "the final records must reach the canonical in ID order"
        );
    }

    /// ADR-17 B5 terminal-cut regression (fault-gate defect
    /// hrs-fa053dbc4a86): the cooperative drain must NOT commit the
    /// terminal while the serving generation's sealed evidence still holds
    /// records the binding never consumed.  `serving_depth_converged` is
    /// false until the follow state converges on the final seal and every
    /// sealed record is applied and published.
    #[test]
    fn drain_terminal_requires_serving_stream_convergence() {
        use lob_replay::RawLogWriter;
        use lob_replay::durability_progress::DurabilityProgressWriter;
        use lob_replay::segment_chain::{
            RawSegmentManifestWriter, root_segment_genesis, scan_segment_manifest,
            successor_segment_genesis, verify_and_seal_raw_segment,
        };
        use lob_reply_helpers::{append_segment_fixture, fixture_frame, mark_generation_complete};
        let dir = tempfile::tempdir().unwrap();
        let campaign = dir.path().join("hr-fixture");
        let generation = campaign.join("generations").join("1000-BTCUSDT-g000-g");
        let depth_dir = generation.join("depth");
        let trade_dir = generation.join("trade");
        std::fs::create_dir_all(&depth_dir).unwrap();
        std::fs::create_dir_all(&trade_dir).unwrap();
        let snapshot_path = generation.join("snapshot.bnraw");
        {
            let mut snapshot_writer = RawLogWriter::create(&snapshot_path, 100).unwrap();
            snapshot_writer
                .append(&fixture_frame(
                    "BTCUSDT",
                    "btcusdt@rest-depth-snapshot",
                    "g0",
                    0,
                    5,
                    br#"{"lastUpdateId":100,"bids":[["100","2"]],"asks":[["101","3"]]}"#,
                ))
                .unwrap();
            snapshot_writer.sync().unwrap();
        }
        let trade_manifest =
            RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
        drop(trade_manifest);
        let stream = "btcusdt@depth@100ms";
        let epoch = "g0";
        let mut manifest =
            RawSegmentManifestWriter::create(&depth_dir.join("segments.bnseg")).unwrap();
        let root = root_segment_genesis(epoch, stream).unwrap();
        let root_frames = [fixture_frame(
            "BTCUSDT",
            stream,
            epoch,
            0,
            10,
            br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":101,"u":101,"b":[],"a":[]}"#,
        )];
        append_segment_fixture(&depth_dir, &mut manifest, &root, &root_frames);
        let second = successor_segment_genesis(
            &scan_segment_manifest(&depth_dir.join("segments.bnseg"))
                .unwrap()
                .entries[0]
                .seal,
        )
        .unwrap();
        // In-flight successor with ONE ACKed record; the final records land
        // and seal only after the binding already consumed the prefix.
        let raw_path = depth_dir.join("segment-000001.bnraw");
        let mut writer = RawLogWriter::create_segment(&raw_path, 1, &second).unwrap();
        let mut progress = DurabilityProgressWriter::create_with_reference(
            &depth_dir.join("segment-000001.bnack"),
            &raw_path,
            "segment-000001.bnraw",
        )
        .unwrap();
        let receipt = writer
            .append(&fixture_frame(
                "BTCUSDT",
                stream,
                epoch,
                1,
                20,
                br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":102,"u":102,"b":[],"a":[]}"#,
            ))
            .unwrap();
        progress
            .append(receipt.durability_ack.clone().unwrap())
            .unwrap();
        let mut binding =
            LaneBinding::bind_generation(&campaign, &generation).expect("bind_generation");
        binding.bootstrap_depth().expect("bootstrap");
        binding.refresh().expect("consume the ACKed prefix");
        assert_eq!(binding.depth.records().len(), 2);
        // The generation declares COMPLETE only now — with the final record
        // sealed: the binding (1 consumed record) does NOT converge yet.
        let _receipt = writer
            .append(&fixture_frame(
                "BTCUSDT",
                stream,
                epoch,
                2,
                30,
                br#"{"e":"depthUpdate","E":3,"s":"BTCUSDT","U":103,"u":103,"b":[],"a":[]}"#,
            ))
            .unwrap();
        let final_ack = writer.sync().unwrap();
        drop(writer);
        progress.append(final_ack.clone()).unwrap();
        drop(progress);
        let verified =
            verify_and_seal_raw_segment(&raw_path, "segment-000001.bnraw", &second, &final_ack)
                .unwrap();
        manifest.append_verified(&verified).unwrap();
        drop(manifest);
        mark_generation_complete(&generation);
        assert!(
            !serving_depth_converged(&binding).unwrap(),
            "a COMPLETE generation whose final sealed record is unconsumed must not converge"
        );
        // One more poll consumes the sealed terminal and the guard clears.
        binding.refresh().expect("refresh the final seal");
        binding.apply_new_depth().expect("apply the final record");
        assert_eq!(binding.depth.records().len(), 3);
        assert!(
            binding.depth.consumed_sealed_terminal().unwrap(),
            "the follow state converged on the final seal"
        );
        assert_eq!(binding.depth_consumed, 3);
        // After the serving publisher drains its pending queue the drain may
        // commit (the guard's pending_empty condition).
        binding.pending_depth.clear();
        assert!(serving_depth_converged(&binding).unwrap());
    }

    /// ADR-17 B3/B5 publication-order regression (review 2026-09-11 risk
    /// 3): the emission clamp must govern BEFORE any walker publication
    /// can advance the cursor — first successor appearance, a replaced
    /// candidate, a transient bind failure (the clamp follows the
    /// generation's EXISTENCE, never the candidate object), a predecessor
    /// without records, and both arrival orders.
    #[test]
    fn emission_clamp_governs_before_any_walker_publication() {
        use lob_replay::segment_chain::RawSegmentManifestWriter;
        use lob_reply_helpers::{append_segment_fixture, mark_generation_complete, trade_frame};
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("hr-fixture");
        let s_root = artifact.join("s");
        let symbol = "BTCUSDT";
        let trade_stream = "btcusdt@trade";
        let s_campaign = s_root.join("0001-BTCUSDT-raw-s");
        let predecessor =
            lob_reply_helpers::make_generation(&s_campaign, "1000-BTCUSDT-g000-s", symbol, "s0");
        mark_generation_complete(&predecessor);
        {
            let trade_dir = predecessor.join("trade");
            let mut manifest =
                RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
            let genesis =
                lob_replay::segment_chain::root_segment_genesis("s0", trade_stream).unwrap();
            let frames: Vec<_> = (0..2)
                .map(|i| trade_frame(symbol, "s0", i, 100 + i * 10, 100 + i))
                .collect();
            append_segment_fixture(&trade_dir, &mut manifest, &genesis, &frames);
        }
        // A walker over an intermediate generation with NO durable records
        // yet (the writer is alive, only the manifests exist): an empty
        // stream contributes no bound.
        let intermediate =
            lob_reply_helpers::make_generation(&s_campaign, "2000-BTCUSDT-g001-s", symbol, "s1");
        {
            let trade_manifest = RawSegmentManifestWriter::create(
                &intermediate.join("trade").join("segments.bnseg"),
            )
            .unwrap();
            drop(trade_manifest);
        }
        let empty_walker = GenerationTailWalker {
            generation: intermediate.clone(),
            binding: LaneBinding::bind_generation(&s_campaign, &intermediate).unwrap(),
            floor: 0,
            last_durable_advance: Instant::now(),
            lag_excluded: false,
        };
        let binding = LaneBinding::bind_generation(&s_campaign, &predecessor).unwrap();
        let mut tails = vec![empty_walker];
        // First successor appearance + predecessor without records: no
        // clamp bound (empty walker, sealed binding) — the successor may
        // publish immediately.
        let clamp = lane_emission_clamp(&tails, &binding, true).unwrap();
        assert!(
            clamp.is_none(),
            "an empty predecessor contributes no emission bound"
        );
        // Transient bind failure: the successor generation EXISTS (latest !=
        // binding) while the candidate object is absent — the clamp must
        // still hold the walker's head once the walker has records.
        // Simulate one durable record arriving at the walker (in-flight
        // ROOT segment + ACK) so its head bounds the emission.
        {
            use lob_replay::RawLogWriter;
            use lob_replay::durability_progress::DurabilityProgressWriter;
            let trade_dir = intermediate.join("trade");
            let raw_path = trade_dir.join("segment-000000.bnraw");
            let root = lob_replay::segment_chain::root_segment_genesis("s1", trade_stream).unwrap();
            let mut writer = RawLogWriter::create_segment(&raw_path, 1, &root).unwrap();
            let receipt = writer
                .append(&trade_frame(symbol, "s1", 0, 300, 103))
                .unwrap();
            let mut progress = DurabilityProgressWriter::create_with_reference(
                &trade_dir.join("segment-000000.bnack"),
                &raw_path,
                "segment-000000.bnraw",
            )
            .unwrap();
            progress.append(receipt.durability_ack.unwrap()).unwrap();
            let _ = writer;
        }
        tails[0].binding.refresh().unwrap();
        // The successor exists (candidate_exists=true) even with NO bound
        // candidate object: the clamp must hold the walker's head 103.
        let clamp = lane_emission_clamp(&tails, &binding, true).unwrap();
        assert_eq!(
            clamp,
            Some(103),
            "the clamp must hold the tail's head while a successor generation exists (transient bind failure)"
        );
        // Both arrival orders: with the clamp armed FIRST, walking the tail
        // buffers its records — nothing may publish past the clamped head —
        // and the post-walk recompute raises the bound to the advanced head
        // (104) before the flush releases exactly the walked records.
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Shadow);
        union.set_emission_clamp(CaptureLane::Shadow, 103);
        let journal_path = dir.path().join("journal.jsonl");
        let mut journal = LiveArbitrationJournalWriter::create(&journal_path).unwrap();
        let origin = Instant::now();
        let mut trades_published = 0_u64;
        let mut late_corrections = 0_u64;
        walk_generation_trades(
            CaptureLane::Shadow,
            &mut tails[0].binding,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
            0,
            None,
        )
        .unwrap();
        match union.flush().unwrap() {
            TradeUnionDisposition::Publishable(batch) => {
                publish_trade_batch(batch, &mut journal, &origin, &mut trades_published).unwrap();
            }
            TradeUnionDisposition::Buffered => {}
            other => panic!("unexpected disposition: {other:?}"),
        }
        assert!(
            journal_trade_ids(&journal_path).is_empty(),
            "the clamped head must govern BEFORE the walker publishes"
        );
        // The post-walk recompute: the walker consumed 103, its head is 104.
        let clamp = lane_emission_clamp(&tails, &binding, true)
            .unwrap()
            .expect("the walker still holds the emission bound");
        assert_eq!(clamp, 104, "the clamp follows the consumed head");
        union.set_emission_clamp(CaptureLane::Shadow, clamp);
        match union.flush().unwrap() {
            TradeUnionDisposition::Publishable(batch) => {
                publish_trade_batch(batch, &mut journal, &origin, &mut trades_published).unwrap();
            }
            TradeUnionDisposition::Buffered => {}
            other => panic!("unexpected disposition: {other:?}"),
        }
        assert_eq!(
            journal_trade_ids(&journal_path),
            vec![103],
            "the walked record publishes exactly once the head advanced past it"
        );
    }

    /// ADR-17 B3/B5 regression (full-gate defect hrs-438af564df4d): at a
    /// lane-generation handover the OLD path consumed a mid-flight snapshot
    /// of the predecessor (one-shot walk, then a candidate whose swallowed
    /// refresh error froze it) and the successor's records advanced the
    /// union cursor past the predecessor's not-yet-durable tail — the
    /// ETHUSDT canonical dropped 100 union trades that only the predecessor
    /// tails held (4344063810..4344063812, 4344066244..4344066340).  The
    /// persistent tail walker must consume the predecessor through its
    /// FINAL seal and the emission clamp must hold the watermark back until
    /// the tail is durable: no skip, no loss, exact ID order.
    #[test]
    fn tail_walkers_consume_predecessor_tail_without_skipping() {
        use lob_replay::segment_chain::RawSegmentManifestWriter;
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("hr-fixture");
        let p_root = artifact.join("p");
        let s_root = artifact.join("s");
        let symbol = "BTCUSDT";
        let trade_stream = "btcusdt@trade";

        // PRIMARY lane: campaign1 g000 (100..102, sealed, pre-floor) and
        // g001 (106..108, sealed): the primary cursor advances to 109.
        // Every finished capture carries its terminal declaration.
        let p_campaign = p_root.join("0001-BTCUSDT-raw-p0");
        let p_g000 =
            lob_reply_helpers::make_generation(&p_campaign, "1000-BTCUSDT-g000-p0", symbol, "p0");
        let p_g001 =
            lob_reply_helpers::make_generation(&p_campaign, "3000-BTCUSDT-g001-p1", symbol, "p1");
        lob_reply_helpers::mark_generation_complete(&p_g000);
        lob_reply_helpers::mark_generation_complete(&p_g001);
        {
            let trade_dir = p_g000.join("trade");
            let mut manifest =
                RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
            let genesis =
                lob_replay::segment_chain::root_segment_genesis("p0", trade_stream).unwrap();
            let frames: Vec<_> = (0..3)
                .map(|i| lob_reply_helpers::trade_frame(symbol, "p0", i, 100 + i * 10, 100 + i))
                .collect();
            lob_reply_helpers::append_segment_fixture(&trade_dir, &mut manifest, &genesis, &frames);
        }
        {
            let trade_dir = p_g001.join("trade");
            let mut manifest =
                RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
            let genesis =
                lob_replay::segment_chain::root_segment_genesis("p1", trade_stream).unwrap();
            let frames: Vec<_> = (0..3)
                .map(|i| lob_reply_helpers::trade_frame(symbol, "p1", i, 1000 + i * 10, 106 + i))
                .collect();
            lob_reply_helpers::append_segment_fixture(&trade_dir, &mut manifest, &genesis, &frames);
        }

        // SHADOW lane: campaign1 g000 (100..102, sealed) = the drained
        // predecessor binding; campaign2 g000 = the intermediate generation
        // whose tail (103..105) is captured but NOT yet durable (in-flight
        // segment without an ACK); campaign2 g001 (106..108, sealed) = the
        // candidate whose records would skip the tail without the clamp.
        let s_campaign_1 = s_root.join("0001-BTCUSDT-raw-s0");
        let s_campaign_2 = s_root.join("0002-BTCUSDT-raw-s1");
        let s_bind_gen =
            lob_reply_helpers::make_generation(&s_campaign_1, "1000-BTCUSDT-g000-s0", symbol, "s0");
        let s_mid_gen =
            lob_reply_helpers::make_generation(&s_campaign_2, "2000-BTCUSDT-g000-s1", symbol, "s1");
        let s_candidate_gen =
            lob_reply_helpers::make_generation(&s_campaign_2, "3000-BTCUSDT-g001-s2", symbol, "s2");
        lob_reply_helpers::mark_generation_complete(&s_bind_gen);
        lob_reply_helpers::mark_generation_complete(&s_candidate_gen);
        {
            let trade_dir = s_bind_gen.join("trade");
            let mut manifest =
                RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
            let genesis =
                lob_replay::segment_chain::root_segment_genesis("s0", trade_stream).unwrap();
            let frames: Vec<_> = (0..3)
                .map(|i| lob_reply_helpers::trade_frame(symbol, "s0", i, 200 + i * 10, 100 + i))
                .collect();
            lob_reply_helpers::append_segment_fixture(&trade_dir, &mut manifest, &genesis, &frames);
        }
        let mut mid_manifest = {
            let trade_dir = s_mid_gen.join("trade");
            RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap()
        };
        let mid_root = lob_replay::segment_chain::root_segment_genesis("s1", trade_stream).unwrap();
        {
            let trade_dir = s_mid_gen.join("trade");
            let frames: Vec<_> = (0..3)
                .map(|i| lob_reply_helpers::trade_frame(symbol, "s1", i, 300 + i * 10, 100 + i))
                .collect();
            lob_reply_helpers::append_segment_fixture(
                &trade_dir,
                &mut mid_manifest,
                &mid_root,
                &frames,
            );
        }
        let mid_second = lob_replay::segment_chain::successor_segment_genesis(
            &lob_replay::segment_chain::scan_segment_manifest(
                &s_mid_gen.join("trade").join("segments.bnseg"),
            )
            .unwrap()
            .entries[0]
                .seal,
        )
        .unwrap();
        let (mid_tail_file, mid_tail_ack, mut mid_progress) = {
            let frames: Vec<_> = (0..3)
                .map(|i| lob_reply_helpers::trade_frame(symbol, "s1", 3 + i, 400 + i * 10, 103 + i))
                .collect();
            lob_reply_helpers::write_in_flight_segment(
                &s_mid_gen.join("trade"),
                &mid_second,
                &frames,
            )
        };
        {
            let trade_dir = s_candidate_gen.join("trade");
            let mut manifest =
                RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
            let genesis =
                lob_replay::segment_chain::root_segment_genesis("s2", trade_stream).unwrap();
            let frames: Vec<_> = (0..3)
                .map(|i| lob_reply_helpers::trade_frame(symbol, "s2", i, 500 + i * 10, 106 + i))
                .collect();
            lob_reply_helpers::append_segment_fixture(&trade_dir, &mut manifest, &genesis, &frames);
        }

        // --- Union state: the published floor is 102 (already-published
        // history); both lanes are registered.
        let floor: u64 = 102;
        let mut union = TradeUnionState::new();
        union.register_lane(CaptureLane::Primary);
        union.register_lane(CaptureLane::Shadow);
        union.restore_published_floor(floor).unwrap();

        let journal_path = dir.path().join("ETHUSDT-seg-0000.jsonl");
        let mut journal = LiveArbitrationJournalWriter::create(&journal_path).unwrap();
        let origin = Instant::now();
        let mut trades_published = 0_u64;
        let mut late_corrections = 0_u64;

        // PRIMARY: bind the successor generation and feed 106..108.
        let mut primary_binding =
            LaneBinding::bind_generation(&p_campaign, &p_g001).expect("primary bind");
        let mut primary_candidate: Option<LaneBinding> = None;
        let mut advance = false;
        feed_lane_trades(
            CaptureLane::Primary,
            &mut primary_binding,
            &mut primary_candidate,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
            &mut advance,
        )
        .unwrap();

        // SHADOW: the drained predecessor binding, the intermediate
        // generation walked by a persistent tail walker, and the candidate.
        let mut shadow_binding =
            LaneBinding::bind_generation(&s_campaign_1, &s_bind_gen).expect("shadow bind");
        walk_generation_trades(
            CaptureLane::Shadow,
            &mut shadow_binding,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
            floor,
            None,
        )
        .unwrap();
        let mut shadow_tails: Vec<GenerationTailWalker> = Vec::new();
        let mut scope = WalkerScope {
            lane_root: s_root.clone(),
            latest_start: Some(3000),
            skip_generation: Some(s_candidate_gen.clone()),
            floor,
            walked_through: None,
        };
        sync_tail_walkers(
            CaptureLane::Shadow,
            1000,
            std::slice::from_mut(&mut scope),
            &mut shadow_tails,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
        )
        .unwrap();
        assert_eq!(
            shadow_tails.len(),
            1,
            "the intermediate generation must be walked"
        );
        let mut shadow_candidate = Some(
            LaneBinding::bind_generation(&s_campaign_2, &s_candidate_gen).expect("candidate bind"),
        );
        // Handover clamp: the tail walker's un-consumed head (103) bounds
        // the shadow lane's emission.
        let clamp = lane_emission_clamp(&shadow_tails, &shadow_binding, shadow_candidate.is_some())
            .unwrap()
            .expect("the unfinished tail walker must clamp emission");
        assert_eq!(clamp, 103);
        union.set_emission_clamp(CaptureLane::Shadow, clamp);
        let mut advance_shadow = false;
        feed_lane_trades(
            CaptureLane::Shadow,
            &mut shadow_binding,
            &mut shadow_candidate,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
            &mut advance_shadow,
        )
        .unwrap();
        // The candidate delivered 106..108 but the clamp must have held the
        // watermark at 103: NOTHING may publish yet (the old path would
        // have published 106..108 here and skipped 103..105 forever).
        {
            let ids = journal_trade_ids(&journal_path);
            assert!(
                ids.is_empty(),
                "the successor's records must wait for the predecessor tail: published {ids:?}"
            );
        }

        // The capture ACKs the tail: 103..105 become durable.
        mid_progress.append(mid_tail_ack.clone()).unwrap();
        drop(mid_progress);
        sync_tail_walkers(
            CaptureLane::Shadow,
            1000,
            std::slice::from_mut(&mut scope),
            &mut shadow_tails,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
        )
        .unwrap();
        let clamp = lane_emission_clamp(&shadow_tails, &shadow_binding, shadow_candidate.is_some())
            .unwrap()
            .expect("the tail walker is unsealed: clamp persists");
        assert_eq!(clamp, 106, "the clamp must follow the tail's consumed head");
        union.set_emission_clamp(CaptureLane::Shadow, clamp);
        match union.flush().unwrap() {
            TradeUnionDisposition::Publishable(batch) => {
                publish_trade_batch(batch, &mut journal, &origin, &mut trades_published).unwrap();
            }
            other => panic!("expected the released tail to publish: {other:?}"),
        }
        {
            let ids = journal_trade_ids(&journal_path);
            assert_eq!(
                ids,
                vec![103, 104, 105],
                "the durable tail must publish before the successor's records"
            );
        }

        // The generation's terminal seal lands: the walker finishes and the
        // clamp clears, releasing the successor's records in ID order.
        lob_reply_helpers::seal_in_flight(
            &s_mid_gen.join("trade"),
            &mut mid_manifest,
            &mid_second,
            &mid_tail_file,
            &mid_tail_ack,
        );
        lob_reply_helpers::mark_generation_complete(&s_mid_gen);
        sync_tail_walkers(
            CaptureLane::Shadow,
            1000,
            std::slice::from_mut(&mut scope),
            &mut shadow_tails,
            &mut union,
            &mut journal,
            &origin,
            &mut trades_published,
            &mut late_corrections,
        )
        .unwrap();
        assert!(
            shadow_tails.is_empty(),
            "the sealed and drained walker must retire"
        );
        let clamp = lane_emission_clamp(&shadow_tails, &shadow_binding, shadow_candidate.is_some())
            .unwrap();
        assert!(
            clamp.is_none(),
            "a sealed predecessor must not clamp emission"
        );
        union.clear_emission_clamp(CaptureLane::Shadow);
        match union.flush().unwrap() {
            TradeUnionDisposition::Publishable(batch) => {
                publish_trade_batch(batch, &mut journal, &origin, &mut trades_published).unwrap();
            }
            other => panic!("expected the successor's records to publish: {other:?}"),
        }
        let ids = journal_trade_ids(&journal_path);
        assert_eq!(
            ids,
            vec![103, 104, 105, 106, 107, 108],
            "the canonical stream must equal the union in exact ID order"
        );
        assert_eq!(
            late_corrections, 0,
            "no honest correction may mask a lost trade"
        );
    }

    /// ADR-17 B5 regression (fault-gate defect hrs-a69b916cd0ea resume
    /// probe): a typed GAP + DEPTH_REBOOTSTRAP with NOTHING publishable
    /// after it is not a boundary when the fresh generation's stream is
    /// FINAL and holds no frame beyond the canonical cursor — the canonical
    /// position already is the trusted end.  The boundary records must be
    /// skipped (the closed verifier rejects a rebootstrap without a
    /// following frame).
    #[test]
    fn empty_final_successor_skips_the_vacuous_depth_boundary() {
        use lob_replay::segment_chain::RawSegmentManifestWriter;
        let dir = tempfile::tempdir().unwrap();
        let campaign = dir.path().join("0001-BTCUSDT-raw-g");
        let generation =
            lob_reply_helpers::make_generation(&campaign, "1000-BTCUSDT-g000-g", "BTCUSDT", "g0");
        {
            // Depth stream: snapshot at lastUpdateId=100 plus ONE sealed
            // root segment with frames 101..110 — everything ends at or
            // before the canonical cursor 110.
            let depth_dir = generation.join("depth");
            std::fs::remove_file(depth_dir.join("segments.bnseg"))
                .expect("remove the helper's empty manifest");
            let mut manifest =
                RawSegmentManifestWriter::create(&depth_dir.join("segments.bnseg")).unwrap();
            let genesis =
                lob_replay::segment_chain::root_segment_genesis("g0", "btcusdt@depth").unwrap();
            let frames: Vec<_> = (0..5)
                .map(|i| {
                    lob_reply_helpers::fixture_frame(
                        "BTCUSDT",
                        "btcusdt@depth",
                        "g0",
                        i,
                        200 + i * 10,
                        format!(
                            r#"{{"e":"depthUpdate","E":{},"s":"BTCUSDT","U":{},"u":{},"b":[["100","1"]],"a":[]}}"#,
                            200 + i * 10,
                            101 + i * 2,
                            101 + i * 2 + 1,
                        )
                        .as_bytes(),
                    )
                })
                .collect();
            lob_reply_helpers::append_segment_fixture(&depth_dir, &mut manifest, &genesis, &frames);
        }
        {
            // The trade stream needs only an (empty) manifest for the bind.
            let trade_manifest =
                RawSegmentManifestWriter::create(&generation.join("trade").join("segments.bnseg"))
                    .unwrap();
            drop(trade_manifest);
        }
        // The FINAL successor's capture finished: its terminal declaration
        // is what authorizes "the stream can never deliver again".
        lob_reply_helpers::mark_generation_complete(&generation);
        let mut binding =
            LaneBinding::bind_generation(&campaign, &generation).expect("bind_generation");
        binding.bootstrap_depth().expect("bootstrap");
        let journal_path = dir.path().join("journal.jsonl");
        let mut journal = LiveArbitrationJournalWriter::create(&journal_path).unwrap();
        let origin = Instant::now();
        let mut canonical_position = CanonicalDepthPosition {
            final_sequence: Some(110),
            digest: Some("d".to_owned()),
            gap_floor: None,
        };
        let mut depth_published = 0_u64;
        let mut gaps_published = 0_u64;
        gap_and_bootstrap_depth(
            &mut journal,
            &origin,
            CaptureLane::Primary,
            &mut binding,
            &mut canonical_position,
            &mut depth_published,
            &mut gaps_published,
        )
        .expect("the vacuous boundary must be skipped, not fail");
        assert_eq!(
            gaps_published, 0,
            "no GAP may be typed without a following frame"
        );
        let content = std::fs::read_to_string(&journal_path).unwrap();
        assert!(
            !content.contains("\"event\":\"GAP\"")
                && !content.contains("\"event\":\"DEPTH_REBOOTSTRAP\""),
            "the journal must carry no vacuous boundary records"
        );
    }

    /// Reads the canonical journal's TRADE_OBSERVATION IDs in order.
    fn journal_trade_ids(path: &Path) -> Vec<u64> {
        let content = std::fs::read_to_string(path).unwrap();
        let mut ids = Vec::new();
        for line in content.lines() {
            let envelope: LiveArbitrationJournalEnvelopeV1 =
                serde_json::from_str(line).expect("journal JSON");
            let payload = &envelope.body.payload;
            if payload.get("event").and_then(serde_json::Value::as_str) == Some("TRADE_OBSERVATION")
            {
                ids.push(
                    payload
                        .get("trade_id")
                        .and_then(serde_json::Value::as_u64)
                        .expect("trade id"),
                );
            }
        }
        ids
    }

    mod lob_reply_helpers {
        use super::*;
        use lob_replay::durability_progress::DurabilityProgressWriter;
        use lob_replay::segment_chain::RawSegmentManifestWriter;
        use lob_replay::{CapturedFrame, DurabilityAckV1, RawLogWriter};

        pub(super) fn fixture_frame(
            symbol: &str,
            stream: &str,
            epoch: &str,
            index: u64,
            mono: u64,
            payload: &[u8],
        ) -> CapturedFrame {
            CapturedFrame {
                venue: "binance-spot".to_owned(),
                environment: "production-public-market-data".to_owned(),
                endpoint: "wss://data-stream.binance.vision:443/ws/fixture".to_owned(),
                stream: stream.to_owned(),
                symbol: symbol.to_owned(),
                connection_epoch: epoch.to_owned(),
                frame_index: index,
                receive_wall_ns: 1_000_000 + mono,
                receive_mono_ns: mono,
                clock_quality: "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND".to_owned(),
                clock_source: "fixture".to_owned(),
                payload: payload.to_vec(),
                spec_revision: SPEC_REVISION.to_owned(),
            }
        }

        /// One venue trade frame with an exact ID and a canonical payload
        /// (the sibling lane must deliver the SAME payload so the union
        /// merges the two lineages instead of typing a conflict).
        pub(super) fn trade_frame(
            symbol: &str,
            epoch: &str,
            index: u64,
            mono: u64,
            trade_id: u64,
        ) -> CapturedFrame {
            let payload = format!(
                r#"{{"e":"trade","E":{mono},"s":"{symbol}","t":{trade_id},"T":{trade_id},"p":"1.00000000","q":"0.00100000","M":true,"m":false}}"#
            );
            fixture_frame(
                symbol,
                "btcusdt@trade",
                epoch,
                index,
                mono,
                payload.as_bytes(),
            )
        }

        /// Creates one generation directory (snapshot + empty depth
        /// manifest + trade/depth stream dirs) ready for segment fixtures.
        pub(super) fn make_generation(
            campaign: &Path,
            name: &str,
            symbol: &str,
            epoch: &str,
        ) -> PathBuf {
            let generation = campaign.join("generations").join(name);
            std::fs::create_dir_all(generation.join("trade")).unwrap();
            std::fs::create_dir_all(generation.join("depth")).unwrap();
            let snapshot_path = generation.join("snapshot.bnraw");
            let mut snapshot_writer = RawLogWriter::create(&snapshot_path, 100).unwrap();
            snapshot_writer
                .append(&fixture_frame(
                    symbol,
                    "btcusdt@rest-depth-snapshot",
                    epoch,
                    0,
                    5,
                    br#"{"lastUpdateId":100,"bids":[["100","2"]],"asks":[["101","3"]]}"#,
                ))
                .unwrap();
            snapshot_writer.sync().unwrap();
            drop(snapshot_writer);
            let depth_manifest =
                RawSegmentManifestWriter::create(&generation.join("depth").join("segments.bnseg"))
                    .unwrap();
            drop(depth_manifest);
            generation
        }

        pub(super) fn append_segment_fixture(
            directory: &Path,
            manifest: &mut RawSegmentManifestWriter,
            genesis: &lob_replay::RawSegmentGenesisV1,
            frames: &[CapturedFrame],
        ) -> lob_replay::RawSegmentSealV1 {
            use lob_replay::segment_chain::verify_and_seal_raw_segment;
            let raw_file = format!("segment-{:06}.bnraw", genesis.segment_index);
            let raw_path = directory.join(&raw_file);
            let mut writer = RawLogWriter::create_segment(&raw_path, 100, genesis).unwrap();
            for item in frames {
                writer.append(item).unwrap();
            }
            let ack = writer.sync().unwrap();
            // The capture publishes the durable ACK (BNACK) before sealing:
            // the arbiter's follower binds the in-flight segment through it.
            let progress_path =
                directory.join(format!("segment-{:06}.bnack", genesis.segment_index));
            let mut progress = DurabilityProgressWriter::create_with_reference(
                &progress_path,
                &raw_path,
                &raw_file,
            )
            .unwrap();
            progress.append(ack.clone()).unwrap();
            drop(progress);
            drop(writer);
            let verified =
                verify_and_seal_raw_segment(&raw_path, &raw_file, genesis, &ack).unwrap();
            let seal = verified.seal().clone();
            manifest.append_verified(&verified).unwrap();
            seal
        }

        /// Writes one in-flight segment: the raw file holds every frame, the
        /// BNACK journal EXISTS but carries NO durability ACK yet (the
        /// capture captured the records but has not acknowledged them).
        /// Returns the raw file name, the held-back ACK and the live
        /// progress writer (the caller publishes the ACK later — exactly
        /// the durability cadence that hid the predecessor tail in
        /// fault-gate defect hrs-438af564df4d).
        pub(super) fn write_in_flight_segment(
            directory: &Path,
            genesis: &lob_replay::RawSegmentGenesisV1,
            frames: &[CapturedFrame],
        ) -> (String, DurabilityAckV1, DurabilityProgressWriter) {
            let raw_file = format!("segment-{:06}.bnraw", genesis.segment_index);
            let raw_path = directory.join(&raw_file);
            let mut writer = RawLogWriter::create_segment(&raw_path, 100, genesis).unwrap();
            for item in frames {
                writer.append(item).unwrap();
            }
            let ack = writer.sync().unwrap();
            drop(writer);
            let progress_path =
                directory.join(format!("segment-{:06}.bnack", genesis.segment_index));
            let progress = DurabilityProgressWriter::create_with_reference(
                &progress_path,
                &raw_path,
                &raw_file,
            )
            .unwrap();
            (raw_file, ack, progress)
        }

        /// Seals a previously in-flight segment into the manifest (the
        /// generation's terminal rotation).
        pub(super) fn seal_in_flight(
            directory: &Path,
            manifest: &mut RawSegmentManifestWriter,
            genesis: &lob_replay::RawSegmentGenesisV1,
            raw_file: &str,
            ack: &DurabilityAckV1,
        ) -> lob_replay::RawSegmentSealV1 {
            use lob_replay::segment_chain::verify_and_seal_raw_segment;
            let verified =
                verify_and_seal_raw_segment(&directory.join(raw_file), raw_file, genesis, ack)
                    .unwrap();
            let seal = verified.seal().clone();
            manifest.append_verified(&verified).unwrap();
            seal
        }

        /// Writes the capture's durable terminal declaration
        /// (`generation.json`, status COMPLETE) — the boundary authority the
        /// arbiter now requires before a stream may be treated as
        /// "can never deliver again" (ADR-17 review 2026-09-11 risk 1).
        pub(super) fn mark_generation_complete(generation: &Path) {
            let manifest = serde_json::json!({
                "schema": "RawGenerationManifestV1",
                "status": "COMPLETE",
                "failure": null,
            });
            let bytes = serde_json::to_vec(&manifest).unwrap();
            std::fs::write(generation.join("generation.json"), bytes).unwrap();
        }
    }
}
