//! Deterministic replay of an explicitly selected, sealed RawCampaign segment prefix.
//!
//! This module is deliberately neutral: it reconstructs L2 state and validates
//! the independent trade stream, but emits no economic features, labels or
//! cross-stream ordering claim. A failed campaign prefix is development
//! evidence only and can never become a qualified dataset through this API.

use crate::segment_chain::{
    RawSegmentManifestEntryV1, scan_segment_manifest, verify_segment_manifest_prefix_files,
};
use crate::{
    ApplyOutcome, FixedDecimal, LocalOrderBook, RawFrame, Result, read_raw_records,
    read_raw_segment_records,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const DEVELOPMENT_USAGE: &str = "DEVELOPMENT_ONLY_FAILED_PREFIX_NOT_PROMOTABLE";
const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayPrefixSelectionV1 {
    pub schema: String,
    pub usage: String,
    pub generation_directory: PathBuf,
    pub through_segment_index: u64,
    pub exclusion_reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplaySourceBindingV1 {
    pub source_run_id: String,
    pub source_run_status: String,
    pub source_campaign_id: String,
    pub session_id: String,
    pub symbol: String,
    pub spec_revision: String,
    pub launcher_terminal_sha256: String,
    pub campaign_bindings_sha256: String,
    pub startup_sha256: String,
    pub snapshot_raw_sha256: String,
    pub snapshot_record_sha256: String,
    pub snapshot_last_update_id: u64,
    pub depth_manifest_sha256: String,
    pub depth_selected_manifest_record_sha256: String,
    pub trade_manifest_sha256: String,
    pub trade_selected_manifest_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DepthReplayCheckpointV1 {
    pub segment_index: u64,
    pub terminal_record_sha256: String,
    pub last_frame_index: u64,
    pub last_update_id: u64,
    pub state_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TradeReplayCheckpointV1 {
    pub segment_index: u64,
    pub terminal_record_sha256: String,
    pub last_frame_index: u64,
    pub last_trade_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DepthReplayV1 {
    pub connection_epoch: String,
    pub stream: String,
    pub selected_segments: u64,
    pub excluded_manifest_segments: u64,
    pub raw_records: u64,
    pub control_records: u64,
    pub old_records: u64,
    pub applied_records: u64,
    pub first_frame_index: u64,
    pub last_frame_index: u64,
    pub first_applied_frame_index: u64,
    pub final_update_id: u64,
    pub bid_levels: u64,
    pub ask_levels: u64,
    pub state_sha256: String,
    pub checkpoints: Vec<DepthReplayCheckpointV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TradeReplayV1 {
    pub connection_epoch: String,
    pub stream: String,
    pub selected_segments: u64,
    pub excluded_manifest_segments: u64,
    pub raw_records: u64,
    pub control_records: u64,
    pub first_frame_index: u64,
    pub last_frame_index: u64,
    pub first_trade_id: u64,
    pub last_trade_id: u64,
    pub trade_ids_strictly_increasing: bool,
    pub checkpoints: Vec<TradeReplayCheckpointV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketReplayReportV1 {
    pub schema: String,
    pub usage: String,
    pub qualification_claim: bool,
    pub exclusion_reason: String,
    pub selected_through_segment_index: u64,
    pub source: ReplaySourceBindingV1,
    pub depth: DepthReplayV1,
    pub trades: TradeReplayV1,
    pub cross_stream_total_order_available: bool,
    pub economic_features: Vec<String>,
    pub report_sha256: String,
}

#[derive(Clone)]
pub(crate) struct TransportIdentity {
    pub(crate) symbol: String,
    pub(crate) stream: String,
    pub(crate) connection_epoch: String,
    pub(crate) endpoint: String,
    pub(crate) spec_revision: String,
}

struct FailedSourceIdentity {
    run_id: String,
    campaign_id: String,
    launcher_terminal_sha256: String,
    campaign_bindings_sha256: String,
}

pub(crate) fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} is not a regular non-link file"));
    }
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    require_regular_file(path, "hashed source")?;
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(crate::hex(&hasher.finalize()))
}

pub(crate) fn load_json(path: &Path, label: &str) -> Result<Value> {
    require_regular_file(path, label)?;
    let bytes = std::fs::read(path).map_err(|error| format!("read {label}: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
}

fn validate_failed_source(generation: &Path, symbol: &str) -> Result<FailedSourceIdentity> {
    let generations = generation
        .parent()
        .ok_or_else(|| "generation has no parent directory".to_owned())?;
    if generations.file_name().and_then(|value| value.to_str()) != Some("generations") {
        return Err("generation is not below an exact generations directory".to_owned());
    }
    let campaign = generations
        .parent()
        .ok_or_else(|| "generation has no campaign directory".to_owned())?;
    let run = campaign
        .parent()
        .ok_or_else(|| "generation has no qualification run directory".to_owned())?;
    let terminal_path = run.join("launcher-terminal.json");
    let terminal = load_json(&terminal_path, "launcher terminal")?;
    let run_id = text(&terminal, "run_id", "launcher terminal")?;
    let campaign_id = campaign
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "campaign directory name is not UTF-8".to_owned())?;
    if text(&terminal, "schema", "launcher terminal")? != "RawQualificationLauncherTerminalV2"
        || text(&terminal, "status", "launcher terminal")? != "FAILED"
        || text(&terminal, "mode", "launcher terminal")? != "Production"
        || text(&terminal, "credentials", "launcher terminal")? != "NONE"
        || text(&terminal, "order_entry", "launcher terminal")? != "ABSENT"
        || run.file_name().and_then(|value| value.to_str()) != Some(run_id)
    {
        return Err("source qualification is not an exact failed production run".to_owned());
    }
    let terminal_run_root = PathBuf::from(text(&terminal, "run_root", "launcher terminal")?)
        .canonicalize()
        .map_err(|error| format!("resolve launcher terminal run_root: {error}"))?;
    if terminal_run_root != run {
        return Err("launcher terminal run_root differs from selected source".to_owned());
    }
    let bindings_path = run.join("campaign-bindings.json");
    let bindings_sha256 = sha256_file(&bindings_path)?;
    if text(&terminal, "campaign_bindings_sha256", "launcher terminal")? != bindings_sha256 {
        return Err("launcher terminal does not bind campaign-bindings.json".to_owned());
    }
    let bindings = load_json(&bindings_path, "campaign bindings")?;
    if text(&bindings, "schema", "campaign bindings")? != "RawQualificationCampaignBindingsV1"
        || text(&bindings, "run_id", "campaign bindings")? != run_id
    {
        return Err("campaign bindings identity differs from failed run".to_owned());
    }
    let rows = bindings["campaigns"]
        .as_array()
        .ok_or_else(|| "campaign bindings.campaigns must be an array".to_owned())?;
    let mut matches = 0_u64;
    for row in rows {
        let row_campaign = text(row, "campaign_id", "campaign binding")?;
        let row_symbol = text(row, "symbol", "campaign binding")?;
        let row_path = PathBuf::from(text(row, "campaign_directory", "campaign binding")?)
            .canonicalize()
            .map_err(|error| format!("resolve campaign binding directory: {error}"))?;
        if row_campaign == campaign_id && row_symbol == symbol && row_path == campaign {
            matches += 1;
        }
    }
    if matches != 1 {
        return Err("selected generation is not bound exactly once by the failed run".to_owned());
    }
    Ok(FailedSourceIdentity {
        run_id: run_id.to_owned(),
        campaign_id: campaign_id.to_owned(),
        launcher_terminal_sha256: sha256_file(&terminal_path)?,
        campaign_bindings_sha256: bindings_sha256,
    })
}

pub(crate) fn text<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .filter(|item| !item.is_empty())
        .ok_or_else(|| format!("{label}.{field} must be non-empty text"))
}

pub(crate) fn u64_field(value: &Value, field: &str, label: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("{label}.{field} must be a non-negative integer"))
}

pub(crate) fn load_transport(
    path: &Path,
    expected_kind: &str,
    startup: &Value,
) -> Result<TransportIdentity> {
    let value = load_json(path, "transport metadata")?;
    if text(&value, "schema", "transport")? != "TransportMetadataV1"
        || text(&value, "session_id", "transport")? != text(startup, "session_id", "startup")?
        || u64_field(&value, "generation_index", "transport")?
            != u64_field(startup, "generation_index", "startup")?
        || text(&value, "symbol", "transport")? != text(startup, "symbol", "startup")?
        || text(&value, "spec_revision", "transport")? != text(startup, "spec_revision", "startup")?
    {
        return Err("transport metadata differs from startup identity".to_owned());
    }
    let connection = &value["connection"];
    if text(connection, "stream", "transport.connection")? != expected_kind
        || u64_field(connection, "websocket_http_status", "transport.connection")? != 101
    {
        return Err("transport metadata does not describe the expected WebSocket".to_owned());
    }
    let symbol = text(&value, "symbol", "transport")?.to_owned();
    let stream = if expected_kind == "depth" {
        format!("{}@depth@100ms", symbol.to_ascii_lowercase())
    } else {
        format!("{}@trade", symbol.to_ascii_lowercase())
    };
    Ok(TransportIdentity {
        symbol,
        stream,
        connection_epoch: text(connection, "connection_epoch", "transport.connection")?.to_owned(),
        endpoint: text(connection, "uri", "transport.connection")?.to_owned(),
        spec_revision: text(&value, "spec_revision", "transport")?.to_owned(),
    })
}

pub(crate) fn validate_frame(frame: &RawFrame, expected: &TransportIdentity) -> Result<()> {
    if frame.venue != "binance-spot"
        || frame.environment != "production-public-market-data"
        || frame.symbol != expected.symbol
        || frame.stream != expected.stream
        || frame.connection_epoch != expected.connection_epoch
        || frame.endpoint != expected.endpoint
        || frame.spec_revision != expected.spec_revision
    {
        return Err("raw frame identity differs from the selected transport".to_owned());
    }
    Ok(())
}

pub(crate) fn is_server_shutdown(value: &Value) -> Result<bool> {
    if value["e"].as_str() != Some("serverShutdown") {
        return Ok(false);
    }
    u64_field(value, "E", "serverShutdown")?;
    Ok(true)
}

fn selected_entries<'a>(
    entries: &'a [RawSegmentManifestEntryV1],
    through: u64,
    label: &str,
) -> Result<&'a [RawSegmentManifestEntryV1]> {
    let count = through
        .checked_add(1)
        .ok_or_else(|| "selected segment index overflow".to_owned())?;
    let count = usize::try_from(count).map_err(|_| "selected segment count overflow".to_owned())?;
    if count > entries.len() {
        return Err(format!(
            "{label} manifest has {} records, cannot select through segment {through}",
            entries.len()
        ));
    }
    Ok(&entries[..count])
}

fn replay_depth(
    generation: &Path,
    through: u64,
    snapshot_payload: &[u8],
    expected: &TransportIdentity,
) -> Result<(DepthReplayV1, String, String)> {
    let directory = generation.join("depth");
    let manifest_path = directory.join("segments.bnseg");
    require_regular_file(&manifest_path, "depth segment manifest")?;
    let scan = scan_segment_manifest(&manifest_path)?;
    if !scan.clean_eof {
        return Err(format!("depth manifest is incomplete: {:?}", scan.reason));
    }
    let entries = selected_entries(&scan.entries, through, "depth")?;
    let verified = verify_segment_manifest_prefix_files(&scan, &directory, through)?;
    let mut book = LocalOrderBook::new(&expected.symbol)?;
    book.load_snapshot(snapshot_payload)?;
    let mut raw_records = 0_u64;
    let mut control_records = 0_u64;
    let mut old_records = 0_u64;
    let mut applied_records = 0_u64;
    let mut first_applied = None;
    let mut previous_mono = None;
    let mut checkpoints = Vec::with_capacity(verified.len());
    for artifact in &verified {
        require_regular_file(artifact.raw_path(), "selected depth segment")?;
        let records = read_raw_segment_records(artifact.raw_path(), artifact.genesis())?;
        if records.len() as u64 != artifact.seal().records
            || records.last().map(|item| item.end_offset)
                != Some(artifact.seal().durable_through_offset)
            || records.last().map(|item| item.record_sha256.as_str())
                != Some(artifact.seal().terminal_record_sha256.as_str())
        {
            return Err("depth segment changed after seal verification".to_owned());
        }
        for record in &records {
            validate_frame(&record.frame, expected)?;
            if previous_mono.is_some_and(|old| record.frame.receive_mono_ns < old) {
                return Err("depth receive monotonic time regressed".to_owned());
            }
            previous_mono = Some(record.frame.receive_mono_ns);
            raw_records = raw_records
                .checked_add(1)
                .ok_or_else(|| "depth record count overflow".to_owned())?;
            let value: Value = serde_json::from_slice(&record.frame.payload)
                .map_err(|error| format!("invalid depth payload JSON: {error}"))?;
            if is_server_shutdown(&value)? {
                control_records += 1;
                continue;
            }
            match book.apply_depth(&record.frame.payload)? {
                ApplyOutcome::Old => old_records += 1,
                ApplyOutcome::Applied => {
                    first_applied.get_or_insert(record.frame.frame_index);
                    applied_records += 1;
                }
            }
        }
        checkpoints.push(DepthReplayCheckpointV1 {
            segment_index: artifact.seal().segment_index,
            terminal_record_sha256: artifact.seal().terminal_record_sha256.clone(),
            last_frame_index: artifact.seal().last_frame_index,
            last_update_id: book
                .last_update_id()
                .ok_or_else(|| "depth replay lost its update ID".to_owned())?,
            state_sha256: book.state_digest(),
        });
    }
    if !book.is_live() {
        return Err("selected depth prefix never reached LIVE".to_owned());
    }
    let (bid_levels, ask_levels) = book.level_counts();
    let first = entries.first().expect("selected entries are nonempty");
    let last = entries.last().expect("selected entries are nonempty");
    Ok((
        DepthReplayV1 {
            connection_epoch: expected.connection_epoch.clone(),
            stream: expected.stream.clone(),
            selected_segments: entries.len() as u64,
            excluded_manifest_segments: scan.records - entries.len() as u64,
            raw_records,
            control_records,
            old_records,
            applied_records,
            first_frame_index: first.seal.first_frame_index,
            last_frame_index: last.seal.last_frame_index,
            first_applied_frame_index: first_applied
                .ok_or_else(|| "selected depth prefix applied no record".to_owned())?,
            final_update_id: book
                .last_update_id()
                .ok_or_else(|| "depth replay has no final update ID".to_owned())?,
            bid_levels: bid_levels as u64,
            ask_levels: ask_levels as u64,
            state_sha256: book.state_digest(),
            checkpoints,
        },
        sha256_file(&manifest_path)?,
        last.manifest_record_sha256.clone(),
    ))
}

fn replay_trades(
    generation: &Path,
    through: u64,
    expected: &TransportIdentity,
) -> Result<(TradeReplayV1, String, String)> {
    let directory = generation.join("trade");
    let manifest_path = directory.join("segments.bnseg");
    require_regular_file(&manifest_path, "trade segment manifest")?;
    let scan = scan_segment_manifest(&manifest_path)?;
    if !scan.clean_eof {
        return Err(format!("trade manifest is incomplete: {:?}", scan.reason));
    }
    let entries = selected_entries(&scan.entries, through, "trade")?;
    let verified = verify_segment_manifest_prefix_files(&scan, &directory, through)?;
    let mut raw_records = 0_u64;
    let mut control_records = 0_u64;
    let mut first_trade_id = None;
    let mut previous_trade_id = None;
    let mut previous_mono = None;
    let mut checkpoints = Vec::with_capacity(verified.len());
    for artifact in &verified {
        require_regular_file(artifact.raw_path(), "selected trade segment")?;
        let records = read_raw_segment_records(artifact.raw_path(), artifact.genesis())?;
        if records.len() as u64 != artifact.seal().records
            || records.last().map(|item| item.end_offset)
                != Some(artifact.seal().durable_through_offset)
            || records.last().map(|item| item.record_sha256.as_str())
                != Some(artifact.seal().terminal_record_sha256.as_str())
        {
            return Err("trade segment changed after seal verification".to_owned());
        }
        for record in &records {
            validate_frame(&record.frame, expected)?;
            if previous_mono.is_some_and(|old| record.frame.receive_mono_ns < old) {
                return Err("trade receive monotonic time regressed".to_owned());
            }
            previous_mono = Some(record.frame.receive_mono_ns);
            raw_records = raw_records
                .checked_add(1)
                .ok_or_else(|| "trade record count overflow".to_owned())?;
            let value: Value = serde_json::from_slice(&record.frame.payload)
                .map_err(|error| format!("invalid trade payload JSON: {error}"))?;
            if is_server_shutdown(&value)? {
                control_records += 1;
                continue;
            }
            if value["e"].as_str() != Some("trade")
                || value["s"].as_str() != Some(expected.symbol.as_str())
            {
                return Err("unexpected trade event type or symbol".to_owned());
            }
            u64_field(&value, "E", "trade")?;
            u64_field(&value, "T", "trade")?;
            let trade_id = u64_field(&value, "t", "trade")?;
            for field in ["p", "q"] {
                let decimal = FixedDecimal::parse(text(&value, field, "trade")?)?;
                if decimal.is_zero() || decimal.is_negative() {
                    return Err(format!("trade.{field} must be positive"));
                }
            }
            for field in ["m", "M"] {
                if !value[field].is_boolean() {
                    return Err(format!("trade.{field} must be boolean"));
                }
            }
            if previous_trade_id.is_some_and(|old| trade_id <= old) {
                return Err(format!(
                    "trade ID duplicated or regressed: previous {}, got {trade_id}",
                    previous_trade_id.expect("checked some")
                ));
            }
            first_trade_id.get_or_insert(trade_id);
            previous_trade_id = Some(trade_id);
        }
        checkpoints.push(TradeReplayCheckpointV1 {
            segment_index: artifact.seal().segment_index,
            terminal_record_sha256: artifact.seal().terminal_record_sha256.clone(),
            last_frame_index: artifact.seal().last_frame_index,
            last_trade_id: previous_trade_id
                .ok_or_else(|| "selected trade prefix contains no trade event".to_owned())?,
        });
    }
    let first = entries.first().expect("selected entries are nonempty");
    let last = entries.last().expect("selected entries are nonempty");
    Ok((
        TradeReplayV1 {
            connection_epoch: expected.connection_epoch.clone(),
            stream: expected.stream.clone(),
            selected_segments: entries.len() as u64,
            excluded_manifest_segments: scan.records - entries.len() as u64,
            raw_records,
            control_records,
            first_frame_index: first.seal.first_frame_index,
            last_frame_index: last.seal.last_frame_index,
            first_trade_id: first_trade_id
                .ok_or_else(|| "selected trade prefix contains no trade event".to_owned())?,
            last_trade_id: previous_trade_id
                .ok_or_else(|| "selected trade prefix contains no trade event".to_owned())?,
            trade_ids_strictly_increasing: true,
            checkpoints,
        },
        sha256_file(&manifest_path)?,
        last.manifest_record_sha256.clone(),
    ))
}

pub fn replay_failed_generation_prefix(
    selection: &ReplayPrefixSelectionV1,
) -> Result<MarketReplayReportV1> {
    if selection.schema != "ReplayPrefixSelectionV1"
        || selection.usage != DEVELOPMENT_USAGE
        || selection.exclusion_reason.trim().is_empty()
    {
        return Err("invalid development-only replay prefix selection".to_owned());
    }
    let generation = selection
        .generation_directory
        .canonicalize()
        .map_err(|error| format!("resolve generation directory: {error}"))?;
    if !generation.is_dir() {
        return Err("generation path is not a directory".to_owned());
    }
    let startup_path = generation.join("startup.json");
    let startup = load_json(&startup_path, "generation startup")?;
    if text(&startup, "schema", "startup")? != "RawGenerationStartupV1"
        || text(&startup, "implementation", "startup")? != "rust-segmented"
        || text(&startup, "spec_revision", "startup")? != SPEC_REVISION
        || text(&startup, "credentials", "startup")? != "NONE"
        || text(&startup, "order_entry", "startup")? != "ABSENT"
    {
        return Err("generation startup is outside replay scope".to_owned());
    }
    let symbol = text(&startup, "symbol", "startup")?.to_owned();
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err("generation symbol is outside replay scope".to_owned());
    }
    let failed_source = validate_failed_source(&generation, &symbol)?;
    let depth_identity =
        load_transport(&generation.join("transport-depth.json"), "depth", &startup)?;
    let trade_identity =
        load_transport(&generation.join("transport-trade.json"), "trade", &startup)?;

    let snapshot_path = generation.join("snapshot.bnraw");
    let snapshots = read_raw_records(&snapshot_path)?;
    if snapshots.len() != 1 {
        return Err("replay requires exactly one durable snapshot record".to_owned());
    }
    let snapshot = &snapshots[0];
    let snapshot_meta = load_json(
        &generation.join("snapshot-http.json"),
        "snapshot HTTP metadata",
    )?;
    let snapshot_endpoint = text(&snapshot_meta, "endpoint", "snapshot metadata")?;
    if text(&snapshot_meta, "schema", "snapshot metadata")? != "SnapshotHttpMetadataV1"
        || u64_field(&snapshot_meta, "http_status", "snapshot metadata")? != 200
        || snapshot_meta["body_complete"].as_bool() != Some(true)
        || text(&snapshot_meta, "raw_file", "snapshot metadata")? != "snapshot.bnraw"
        || text(&snapshot_meta, "raw_record_sha256", "snapshot metadata")? != snapshot.record_sha256
        || snapshot.frame.symbol != symbol
        || snapshot.frame.stream != format!("{}@rest-depth-snapshot", symbol.to_ascii_lowercase())
        || snapshot.frame.endpoint != snapshot_endpoint
        || snapshot.frame.spec_revision != SPEC_REVISION
        || snapshot.frame.payload.len() as u64
            != u64_field(&snapshot_meta, "body_length", "snapshot metadata")?
        || crate::hex(&Sha256::digest(&snapshot.frame.payload))
            != text(&snapshot_meta, "body_sha256", "snapshot metadata")?
    {
        return Err("snapshot evidence is not bound to the selected generation".to_owned());
    }
    let snapshot_value: Value = serde_json::from_slice(&snapshot.frame.payload)
        .map_err(|error| format!("invalid snapshot payload JSON: {error}"))?;
    let snapshot_last_update_id = u64_field(&snapshot_value, "lastUpdateId", "snapshot")?;

    let (depth, depth_manifest_sha256, depth_selected_manifest_record_sha256) = replay_depth(
        &generation,
        selection.through_segment_index,
        &snapshot.frame.payload,
        &depth_identity,
    )?;
    let (trades, trade_manifest_sha256, trade_selected_manifest_record_sha256) = replay_trades(
        &generation,
        selection.through_segment_index,
        &trade_identity,
    )?;
    let source = ReplaySourceBindingV1 {
        source_run_id: failed_source.run_id,
        source_run_status: "FAILED".to_owned(),
        source_campaign_id: failed_source.campaign_id,
        session_id: text(&startup, "session_id", "startup")?.to_owned(),
        symbol,
        spec_revision: SPEC_REVISION.to_owned(),
        launcher_terminal_sha256: failed_source.launcher_terminal_sha256,
        campaign_bindings_sha256: failed_source.campaign_bindings_sha256,
        startup_sha256: sha256_file(&startup_path)?,
        snapshot_raw_sha256: sha256_file(&snapshot_path)?,
        snapshot_record_sha256: snapshot.record_sha256.clone(),
        snapshot_last_update_id,
        depth_manifest_sha256,
        depth_selected_manifest_record_sha256,
        trade_manifest_sha256,
        trade_selected_manifest_record_sha256,
    };
    let mut report = MarketReplayReportV1 {
        schema: "MarketReplayReportV1".to_owned(),
        usage: DEVELOPMENT_USAGE.to_owned(),
        qualification_claim: false,
        exclusion_reason: selection.exclusion_reason.clone(),
        selected_through_segment_index: selection.through_segment_index,
        source,
        depth,
        trades,
        cross_stream_total_order_available: false,
        economic_features: Vec::new(),
        report_sha256: String::new(),
    };
    let bytes = serde_json::to_vec(&report)
        .map_err(|error| format!("serialize replay report digest material: {error}"))?;
    report.report_sha256 = crate::hex(&Sha256::digest(bytes));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment_chain::{
        RawSegmentManifestWriter, root_segment_genesis, successor_segment_genesis,
        verify_and_seal_raw_segment,
    };
    use crate::{CapturedFrame, RawLogWriter};
    use serde_json::json;
    use tempfile::TempDir;

    fn frame(
        symbol: &str,
        stream: &str,
        epoch: &str,
        endpoint: &str,
        index: u64,
        mono: u64,
        payload: &[u8],
    ) -> CapturedFrame {
        CapturedFrame {
            venue: "binance-spot".to_owned(),
            environment: "production-public-market-data".to_owned(),
            endpoint: endpoint.to_owned(),
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

    fn write_json(path: &Path, value: &Value) {
        std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }

    fn append_segment(
        directory: &Path,
        manifest: &mut RawSegmentManifestWriter,
        genesis: &crate::RawSegmentGenesisV1,
        frames: &[CapturedFrame],
    ) -> crate::RawSegmentSealV1 {
        let raw_file = format!("segment-{:06}.bnraw", genesis.segment_index);
        let raw_path = directory.join(&raw_file);
        let mut writer = RawLogWriter::create_segment(&raw_path, 100, genesis).unwrap();
        for item in frames {
            writer.append(item).unwrap();
        }
        let ack = writer.sync().unwrap();
        drop(writer);
        let verified = verify_and_seal_raw_segment(&raw_path, &raw_file, genesis, &ack).unwrap();
        let seal = verified.seal().clone();
        manifest.append_verified(&verified).unwrap();
        seal
    }

    fn fixture() -> (TempDir, ReplayPrefixSelectionV1) {
        let temp = TempDir::new().unwrap();
        let run = temp.path().join("fixture-run");
        let campaign = run.join("fixture-campaign");
        let generation = campaign.join("generations").join("fixture-generation");
        let depth_dir = generation.join("depth");
        let trade_dir = generation.join("trade");
        std::fs::create_dir_all(&depth_dir).unwrap();
        std::fs::create_dir_all(&trade_dir).unwrap();
        let symbol = "BTCUSDT";
        let session = "fixture-BTCUSDT-g000";
        let depth_stream = "btcusdt@depth@100ms";
        let trade_stream = "btcusdt@trade";
        let depth_epoch = "depth-fixture";
        let trade_epoch = "trade-fixture";
        let depth_endpoint =
            "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms?timeUnit=MICROSECOND";
        let trade_endpoint =
            "wss://data-stream.binance.vision:443/ws/btcusdt@trade?timeUnit=MICROSECOND";
        let snapshot_endpoint =
            "https://data-api.binance.vision/api/v3/depth?symbol=BTCUSDT&limit=5000";
        let bindings_path = run.join("campaign-bindings.json");
        write_json(
            &bindings_path,
            &json!({
                "schema":"RawQualificationCampaignBindingsV1","run_id":"fixture-run",
                "campaigns":[{"symbol":symbol,"campaign_id":"fixture-campaign",
                "campaign_directory":campaign.canonicalize().unwrap().to_string_lossy()}]
            }),
        );
        write_json(
            &run.join("launcher-terminal.json"),
            &json!({
                "schema":"RawQualificationLauncherTerminalV2","status":"FAILED",
                "run_id":"fixture-run","mode":"Production",
                "run_root":run.canonicalize().unwrap().to_string_lossy(),
                "campaign_bindings_sha256":sha256_file(&bindings_path).unwrap(),
                "credentials":"NONE","order_entry":"ABSENT"
            }),
        );
        write_json(
            &generation.join("startup.json"),
            &json!({
                "schema":"RawGenerationStartupV1","implementation":"rust-segmented",
                "session_id":session,"generation_index":0,"symbol":symbol,
                "segment_duration_s":900,"spec_revision":SPEC_REVISION,
                "credentials":"NONE","order_entry":"ABSENT"
            }),
        );
        for (kind, epoch, uri) in [
            ("depth", depth_epoch, depth_endpoint),
            ("trade", trade_epoch, trade_endpoint),
        ] {
            write_json(
                &generation.join(format!("transport-{kind}.json")),
                &json!({
                    "schema":"TransportMetadataV1","session_id":session,
                    "generation_index":0,"symbol":symbol,"spec_revision":SPEC_REVISION,
                    "connection":{"stream":kind,"connection_epoch":epoch,"uri":uri,
                    "websocket_http_status":101}
                }),
            );
        }
        let snapshot_payload =
            br#"{"lastUpdateId":100,"bids":[["100","2"],["99","1"]],"asks":[["101","3"],["102","1"]]}"#;
        let snapshot_path = generation.join("snapshot.bnraw");
        let mut snapshot_writer = RawLogWriter::create(&snapshot_path, 100).unwrap();
        let snapshot_receipt = snapshot_writer
            .append(&frame(
                symbol,
                "btcusdt@rest-depth-snapshot",
                "snapshot-fixture",
                snapshot_endpoint,
                0,
                5,
                snapshot_payload,
            ))
            .unwrap();
        snapshot_writer.sync().unwrap();
        drop(snapshot_writer);
        write_json(
            &generation.join("snapshot-http.json"),
            &json!({
                "schema":"SnapshotHttpMetadataV1","endpoint":snapshot_endpoint,
                "http_status":200,"body_complete":true,"body_length":snapshot_payload.len(),
                "body_sha256":crate::hex(&Sha256::digest(snapshot_payload)),
                "raw_file":"snapshot.bnraw","raw_record_sha256":snapshot_receipt.record_sha256
            }),
        );

        let mut depth_manifest =
            RawSegmentManifestWriter::create(&depth_dir.join("segments.bnseg")).unwrap();
        let depth_root = root_segment_genesis(depth_epoch, depth_stream).unwrap();
        let depth_seal0 = append_segment(
            &depth_dir,
            &mut depth_manifest,
            &depth_root,
            &[
                frame(symbol, depth_stream, depth_epoch, depth_endpoint, 0, 10, br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":99,"u":100,"b":[],"a":[]}"#),
                frame(symbol, depth_stream, depth_epoch, depth_endpoint, 1, 20, br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":101,"u":101,"b":[["100","0"]],"a":[]}"#),
            ],
        );
        let depth_next = successor_segment_genesis(&depth_seal0).unwrap();
        append_segment(
            &depth_dir,
            &mut depth_manifest,
            &depth_next,
            &[frame(symbol, depth_stream, depth_epoch, depth_endpoint, 2, 900_000_000_010, br#"{"e":"depthUpdate","E":3,"s":"BTCUSDT","U":102,"u":102,"b":[["99","4"]],"a":[["102","0"]]}"#)],
        );
        drop(depth_manifest);

        let mut trade_manifest =
            RawSegmentManifestWriter::create(&trade_dir.join("segments.bnseg")).unwrap();
        let trade_root = root_segment_genesis(trade_epoch, trade_stream).unwrap();
        let trade_seal0 = append_segment(
            &trade_dir,
            &mut trade_manifest,
            &trade_root,
            &[
                frame(symbol, trade_stream, trade_epoch, trade_endpoint, 0, 11, br#"{"e":"trade","E":1,"s":"BTCUSDT","t":10,"p":"100","q":"0.1","T":1,"m":false,"M":true}"#),
                frame(symbol, trade_stream, trade_epoch, trade_endpoint, 1, 21, br#"{"e":"trade","E":2,"s":"BTCUSDT","t":12,"p":"101","q":"0.2","T":2,"m":true,"M":true}"#),
            ],
        );
        let trade_next = successor_segment_genesis(&trade_seal0).unwrap();
        append_segment(
            &trade_dir,
            &mut trade_manifest,
            &trade_next,
            &[frame(symbol, trade_stream, trade_epoch, trade_endpoint, 2, 900_000_000_011, br#"{"e":"trade","E":3,"s":"BTCUSDT","t":13,"p":"99","q":"0.3","T":3,"m":false,"M":true}"#)],
        );
        drop(trade_manifest);

        let selection = ReplayPrefixSelectionV1 {
            schema: "ReplayPrefixSelectionV1".to_owned(),
            usage: DEVELOPMENT_USAGE.to_owned(),
            generation_directory: generation,
            through_segment_index: 0,
            exclusion_reason: "fixture failed-source prefix".to_owned(),
        };
        (temp, selection)
    }

    #[test]
    fn failed_prefix_replay_is_neutral_deterministic_and_explicitly_bounded() {
        let (_temp, mut selection) = fixture();
        let first = replay_failed_generation_prefix(&selection).unwrap();
        assert!(!first.qualification_claim);
        assert!(first.economic_features.is_empty());
        assert!(!first.cross_stream_total_order_available);
        assert_eq!(first.depth.selected_segments, 1);
        assert_eq!(first.depth.excluded_manifest_segments, 1);
        assert_eq!(first.depth.old_records, 1);
        assert_eq!(first.depth.applied_records, 1);
        assert_eq!(first.depth.final_update_id, 101);
        assert_eq!(first.trades.first_trade_id, 10);
        assert_eq!(first.trades.last_trade_id, 12);

        let repeated = replay_failed_generation_prefix(&selection).unwrap();
        assert_eq!(first, repeated);

        selection.through_segment_index = 1;
        let second = replay_failed_generation_prefix(&selection).unwrap();
        assert_eq!(second.depth.final_update_id, 102);
        assert_eq!(second.trades.last_trade_id, 13);
        assert_eq!(second.depth.checkpoints.len(), 2);
        assert_eq!(second.trades.checkpoints.len(), 2);
        assert_ne!(first.report_sha256, second.report_sha256);
    }

    #[test]
    fn failed_prefix_replay_refuses_unmanifested_range() {
        let (_temp, mut selection) = fixture();
        selection.through_segment_index = 2;
        let error = replay_failed_generation_prefix(&selection).unwrap_err();
        assert!(error.contains("cannot select through segment 2"));
    }

    #[test]
    fn failed_prefix_replay_refuses_a_nonfailed_source_terminal() {
        let (_temp, selection) = fixture();
        let run = selection
            .generation_directory
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .expect("fixture generation has run ancestor");
        let terminal_path = run.join("launcher-terminal.json");
        let mut terminal = load_json(&terminal_path, "launcher terminal fixture").unwrap();
        terminal["status"] = Value::String("COMPLETE".to_owned());
        write_json(&terminal_path, &terminal);

        let error = replay_failed_generation_prefix(&selection).unwrap_err();
        assert!(error.contains("not an exact failed production run"));
    }
}
