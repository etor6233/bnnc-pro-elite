//! Independent terminal verification of one immutable segmented raw generation.
//!
//! This module computes no market feature.  It validates only artifact lineage,
//! durable publication, source identity, official payload shape and sequence
//! continuity.  Raw files are selected exclusively by their hash-bound BNSEG
//! manifests; directory glob order is never authority.

use crate::durability_follower::SegmentDurabilityFollower;
use crate::durability_progress::scan_durability_progress;
use crate::segment_chain::{
    RawSegmentManifestEntryV1, scan_segment_manifest, verify_segment_manifest_files,
};
use crate::transport_journal::{TransportJournalSealV1, verify_sealed_transport_journal};
use crate::{
    DurabilityAckV1, RawRecordEnvelopeV1, RawSegmentGenesisV1, Result, StreamDurabilityWatermarkV1,
    read_raw_records, read_raw_segment_records, scan_raw_log,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

pub const SEGMENTED_SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";
const MARKET_FRESHNESS_STARTUP_GRACE_S: u64 = 30;
const MARKET_FRESHNESS_DEADLINE_S: u64 = 30;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotManifestV1 {
    endpoint: String,
    http_status: u16,
    last_update_id: u64,
    bid_levels: usize,
    ask_levels: usize,
    raw_file: String,
    durability_ack: DurabilityAckV1,
    http_metadata_file: String,
    http_metadata_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StreamManifestV1 {
    name: String,
    uri: String,
    connection_epoch: String,
    transport_metadata_file: Option<String>,
    transport_metadata_sha256: Option<String>,
    transport_journal: Option<TransportJournalSealV1>,
    received: u64,
    written: u64,
    durable_records: u64,
    segments: u64,
    last_socket_activity_mono_ns: u64,
    last_market_message_mono_ns: u64,
    server_shutdown_events: u64,
    segment_manifest: String,
    segment_manifest_sha256: String,
    terminal_raw_sha256: String,
    error: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetryManifestV1 {
    schema: String,
    file: String,
    records: u64,
    durable_through_offset: u64,
    terminal_record_sha256: String,
    terminal_mono_ns: u64,
    file_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectedInfoV1 {
    stream: String,
    connection_epoch: String,
    uri: String,
    websocket_http_status: u16,
    local_endpoint: String,
    remote_endpoint: String,
    response_headers: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportMetadataV1 {
    schema: String,
    session_id: String,
    generation_index: u64,
    symbol: String,
    spec_revision: String,
    connection: ConnectedInfoV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationManifestV1 {
    schema: String,
    implementation: String,
    session_id: String,
    generation_index: u64,
    status: String,
    symbol: String,
    duration_requested_s: u64,
    segment_duration_s: u64,
    started_wall_ns: u64,
    finished_wall_ns: u64,
    collector_executable_sha256: String,
    public_config_sha256: String,
    market_freshness_startup_grace_s: u64,
    market_freshness_deadline_s: u64,
    credentials: String,
    order_entry: String,
    raw_boundary: String,
    spec_revision: String,
    startup_file: String,
    startup_sha256: String,
    failure: Option<String>,
    snapshot: Option<SnapshotManifestV1>,
    telemetry: TelemetryManifestV1,
    streams: Vec<StreamManifestV1>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetryClockV1 {
    quality: String,
    source: String,
    leap_indicator: Option<u8>,
    stratum: Option<u8>,
    last_successful_sync: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetryRecordV1 {
    schema: String,
    record_index: u64,
    wall_ns: u64,
    mono_ns: u64,
    clock: TelemetryClockV1,
    depth_received: u64,
    depth_written: u64,
    depth_durable: u64,
    depth_segment: u64,
    depth_last_socket_activity_mono_ns: u64,
    depth_last_market_message_mono_ns: u64,
    depth_last_durable_mono_ns: u64,
    depth_queue_records: u64,
    depth_queue_bytes: u64,
    depth_max_queue_records: u64,
    depth_max_queue_bytes: u64,
    depth_max_queue_age_ns: u64,
    depth_last_sync_duration_ns: u64,
    depth_max_sync_duration_ns: u64,
    trade_received: u64,
    trade_written: u64,
    trade_durable: u64,
    trade_segment: u64,
    trade_last_socket_activity_mono_ns: u64,
    trade_last_market_message_mono_ns: u64,
    trade_last_durable_mono_ns: u64,
    trade_queue_records: u64,
    trade_queue_bytes: u64,
    trade_max_queue_records: u64,
    trade_max_queue_bytes: u64,
    trade_max_queue_age_ns: u64,
    trade_last_sync_duration_ns: u64,
    trade_max_sync_duration_ns: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupManifestV1 {
    schema: String,
    implementation: String,
    session_id: String,
    generation_index: u64,
    symbol: String,
    duration_requested_s: u64,
    segment_duration_s: u64,
    started_wall_ns: u64,
    collector_executable_sha256: String,
    public_config_sha256: String,
    market_freshness_startup_grace_s: u64,
    market_freshness_deadline_s: u64,
    credentials: String,
    order_entry: String,
    raw_boundary: String,
    spec_revision: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotHttpMetadataV1 {
    schema: String,
    endpoint: String,
    http_status: u16,
    headers: BTreeMap<String, Vec<String>>,
    receive_wall_ns: u64,
    receive_mono_ns: u64,
    body_complete: bool,
    body_length: usize,
    body_sha256: String,
    raw_file: String,
    raw_record_sha256: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct VerifiedServerShutdownV1 {
    pub stream: String,
    pub connection_epoch: String,
    pub segment_index: u64,
    pub raw_file: String,
    pub frame_index: u64,
    pub receive_mono_ns: u64,
    pub durable_record_count: u64,
    pub durable_through_offset: u64,
    pub last_record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedGenerationStreamV1 {
    pub schema: &'static str,
    pub name: String,
    pub connection_epoch: String,
    pub records: u64,
    pub segments: u64,
    pub first_frame_index: u64,
    pub last_frame_index: u64,
    pub first_sequence: u64,
    pub final_sequence: u64,
    pub last_socket_activity_mono_ns: u64,
    pub last_market_message_mono_ns: u64,
    pub server_shutdown_events: u64,
    // Runtime-only evidence used by the campaign verifier.  The established
    // on-disk evaluation schema stays stable; every item is reconstructed
    // independently from the exact BNRAW record and its byte boundary.
    #[serde(skip_serializing)]
    pub server_shutdowns: Vec<VerifiedServerShutdownV1>,
    pub manifest_sha256: String,
    pub terminal_raw_sha256: String,
    pub entries: Vec<RawSegmentManifestEntryV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedGenerationV1 {
    pub schema: &'static str,
    pub status: &'static str,
    pub session_id: String,
    pub session_dir: PathBuf,
    pub generation_index: u64,
    pub symbol: String,
    pub duration_requested_s: u64,
    pub segment_duration_s: u64,
    pub started_wall_ns: u64,
    pub finished_wall_ns: u64,
    pub collector_executable_sha256: String,
    pub public_config_sha256: String,
    pub generation_manifest_sha256: String,
    pub snapshot_sha256: String,
    pub snapshot_record_sha256: String,
    pub snapshot_last_update_id: u64,
    pub telemetry_sha256: String,
    pub telemetry_records: u64,
    pub streams: Vec<VerifiedGenerationStreamV1>,
    pub verification_sha256: String,
}

#[derive(Serialize)]
struct VerificationDigestMaterial<'a> {
    schema: &'static str,
    session_id: &'a str,
    generation_index: u64,
    symbol: &'a str,
    duration_requested_s: u64,
    segment_duration_s: u64,
    collector_executable_sha256: &'a str,
    public_config_sha256: &'a str,
    generation_manifest_sha256: &'a str,
    snapshot_sha256: &'a str,
    snapshot_record_sha256: &'a str,
    snapshot_last_update_id: u64,
    telemetry_sha256: &'a str,
    telemetry_records: u64,
    streams: &'a [VerifiedGenerationStreamV1],
}

#[derive(Default)]
struct SequenceState {
    started: bool,
    first: Option<u64>,
    previous_final: Option<u64>,
    last_market_mono_ns: u64,
    server_shutdown_events: u64,
}

/// Freshness reconstructed from the immutable BNRAW application messages.
///
/// Telemetry remains useful evidence, but it is not authority for this gate:
/// a later telemetry sample could otherwise hide a market-data outage that
/// recovered between samples.  Messages received after the requested active
/// window are deliberately ignored here because they belong to shutdown/drain.
#[derive(Default)]
struct RawMarketFreshness {
    first_active_mono_ns: Option<u64>,
    previous_active_mono_ns: Option<u64>,
}

#[derive(Clone, Copy)]
struct GenerationTiming {
    duration_requested_s: u64,
    segment_duration_s: u64,
}

impl RawMarketFreshness {
    fn observe(&mut self, stream: &str, mono_ns: u64, active_end_ns: u64) -> Result<()> {
        if mono_ns > active_end_ns {
            return Ok(());
        }
        if let Some(previous) = self.previous_active_mono_ns
            && mono_ns.saturating_sub(previous)
                > MARKET_FRESHNESS_DEADLINE_S.saturating_mul(1_000_000_000)
        {
            return Err(format!(
                "{stream} BNRAW market-message gap exceeds the freshness deadline"
            ));
        }
        self.first_active_mono_ns.get_or_insert(mono_ns);
        self.previous_active_mono_ns = Some(mono_ns);
        Ok(())
    }

    fn finish(&self, stream: &str, active_end_ns: u64) -> Result<()> {
        let startup_grace_ns = MARKET_FRESHNESS_STARTUP_GRACE_S
            .checked_mul(1_000_000_000)
            .ok_or_else(|| "market freshness startup grace overflow".to_owned())?;
        let deadline_ns = MARKET_FRESHNESS_DEADLINE_S
            .checked_mul(1_000_000_000)
            .ok_or_else(|| "market freshness deadline overflow".to_owned())?;

        let first_deadline_ns = active_end_ns.min(startup_grace_ns);
        if self
            .first_active_mono_ns
            .is_none_or(|first| first > first_deadline_ns)
        {
            return Err(format!(
                "{stream} BNRAW lacks a market message inside its active startup window"
            ));
        }
        if let Some(last) = self.previous_active_mono_ns
            && active_end_ns.saturating_sub(last) > deadline_ns
        {
            return Err(format!(
                "{stream} BNRAW market-message tail exceeds the freshness deadline"
            ));
        }
        Ok(())
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    crate::hex(&Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_file(path: &Path) -> Result<String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| format!("read {} for SHA-256: {error}", path.display()))
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "artifact path is not a safe relative path: {value}"
        ));
    }
    Ok(path.to_path_buf())
}

fn reject_symlink(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("metadata {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "artifact path must not be a symlink: {}",
            path.display()
        ));
    }
    Ok(())
}

fn exact_directory_entries(path: &Path, expected: &BTreeSet<String>) -> Result<()> {
    reject_symlink(path)?;
    let actual = fs::read_dir(path)
        .map_err(|error| format!("read directory {}: {error}", path.display()))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
            reject_symlink(&entry.path())?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| "artifact filename is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if &actual != expected {
        return Err(format!(
            "artifact inventory mismatch at {}: expected {expected:?}, got {actual:?}",
            path.display()
        ));
    }
    Ok(())
}

fn required_u64(value: &Value, field: &str, label: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("{label} field {field} is not an unsigned integer"))
}

fn required_array<'a>(value: &'a Value, field: &str, label: &str) -> Result<&'a Vec<Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("{label} field {field} is not an array"))
}

fn validate_levels(levels: &[Value], label: &str) -> Result<()> {
    for level in levels {
        let fields = level
            .as_array()
            .ok_or_else(|| format!("{label} level is not an array"))?;
        if fields.len() != 2 || fields[0].as_str().is_none() || fields[1].as_str().is_none() {
            return Err(format!("{label} level is not an exact price/quantity pair"));
        }
    }
    Ok(())
}

fn validate_snapshot(
    session: &Path,
    symbol: &str,
    snapshot: &SnapshotManifestV1,
) -> Result<(String, String)> {
    if snapshot.http_status != 200
        || snapshot.raw_file != "snapshot.bnraw"
        || snapshot.http_metadata_file != "snapshot-http.json"
        || snapshot.endpoint
            != format!("https://data-api.binance.vision/api/v3/depth?symbol={symbol}&limit=5000")
    {
        return Err("snapshot manifest identity/status is invalid".to_owned());
    }
    let path = session.join(&snapshot.raw_file);
    let scan = scan_raw_log(&path)?;
    let records = read_raw_records(&path)?;
    if !scan.clean_eof
        || scan.records != 1
        || records.len() != 1
        || snapshot.durability_ack.schema != "DurabilityAckV1"
        || snapshot.durability_ack.durable_record_count != 1
        || snapshot.durability_ack.durable_through_offset != scan.last_good_offset
        || snapshot.durability_ack.last_record_sha256 != scan.last_record_sha256
        || snapshot.durability_ack.streams.len() != 1
    {
        return Err("snapshot durability ACK does not match exact BNRAW".to_owned());
    }
    let record = &records[0];
    let watermark = &snapshot.durability_ack.streams[0];
    if record.frame.symbol != symbol
        || record.frame.venue != "binance-spot"
        || record.frame.environment != "production-public-market-data"
        || record.frame.stream != format!("{}@rest-depth-snapshot", symbol.to_ascii_lowercase())
        || record.frame.endpoint != snapshot.endpoint
        || record.frame.spec_revision != SEGMENTED_SPEC_REVISION
        || record.frame.recorder_state != "PENDING"
        || watermark.connection_epoch != record.frame.connection_epoch
        || watermark.stream != record.frame.stream
        || watermark.durable_through_frame_index != 0
    {
        return Err("snapshot raw identity differs from manifest/contract".to_owned());
    }
    let payload: Value = serde_json::from_slice(&record.frame.payload)
        .map_err(|error| format!("snapshot payload is invalid JSON: {error}"))?;
    let bids = required_array(&payload, "bids", "snapshot")?;
    let asks = required_array(&payload, "asks", "snapshot")?;
    validate_levels(bids, "snapshot bid")?;
    validate_levels(asks, "snapshot ask")?;
    if required_u64(&payload, "lastUpdateId", "snapshot")? != snapshot.last_update_id
        || bids.len() != snapshot.bid_levels
        || asks.len() != snapshot.ask_levels
    {
        return Err("snapshot payload summary differs from manifest".to_owned());
    }
    let metadata_path = session.join(&snapshot.http_metadata_file);
    let metadata_bytes = fs::read(&metadata_path)
        .map_err(|error| format!("read {}: {error}", metadata_path.display()))?;
    if sha256_bytes(&metadata_bytes) != snapshot.http_metadata_sha256 {
        return Err("snapshot HTTP metadata digest differs from manifest".to_owned());
    }
    let metadata: SnapshotHttpMetadataV1 = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| format!("invalid snapshot HTTP metadata: {error}"))?;
    if metadata.schema != "SnapshotHttpMetadataV1"
        || metadata.endpoint != snapshot.endpoint
        || metadata.http_status != snapshot.http_status
        || metadata.headers.is_empty()
        || !metadata.body_complete
        || metadata.body_length != record.frame.payload.len()
        || metadata.body_sha256 != sha256_bytes(&record.frame.payload)
        || metadata.raw_file != snapshot.raw_file
        || metadata.raw_record_sha256 != record.record_sha256
        || metadata.receive_wall_ns != record.frame.receive_wall_ns
        || metadata.receive_mono_ns != record.frame.receive_mono_ns
    {
        return Err("snapshot HTTP metadata is not bound to exact raw body".to_owned());
    }
    Ok((sha256_file(&path)?, record.record_sha256.clone()))
}

fn validate_frame_identity(
    record: &RawRecordEnvelopeV1,
    symbol: &str,
    name: &str,
    epoch: &str,
    uri: &str,
) -> Result<Value> {
    let expected_stream = if name == "depth" {
        format!("{}@depth@100ms", symbol.to_ascii_lowercase())
    } else {
        format!("{}@trade", symbol.to_ascii_lowercase())
    };
    if record.frame.symbol != symbol
        || record.frame.venue != "binance-spot"
        || record.frame.environment != "production-public-market-data"
        || record.frame.stream != expected_stream
        || record.frame.connection_epoch != epoch
        || record.frame.endpoint != uri
        || record.frame.spec_revision != SEGMENTED_SPEC_REVISION
        || record.frame.recorder_state != "PENDING"
        || record.frame.clock_quality.trim().is_empty()
        || record.frame.clock_source.trim().is_empty()
    {
        return Err(format!("{name} raw frame identity/metadata drift"));
    }
    let value: Value = serde_json::from_slice(&record.frame.payload)
        .map_err(|error| format!("{name} payload is invalid JSON: {error}"))?;
    if !value.is_object() {
        return Err(format!("{name} payload root is not an object"));
    }
    Ok(value)
}

fn validate_depth_payload(
    value: &Value,
    symbol: &str,
    snapshot_sequence: u64,
    sequence: &mut SequenceState,
) -> Result<()> {
    if value["e"].as_str() != Some("depthUpdate") || value["s"].as_str() != Some(symbol) {
        return Err("depth event identity is invalid".to_owned());
    }
    required_u64(value, "E", "depth")?;
    let first = required_u64(value, "U", "depth")?;
    let final_id = required_u64(value, "u", "depth")?;
    if first > final_id {
        return Err("depth update range is inverted".to_owned());
    }
    validate_levels(required_array(value, "b", "depth")?, "depth bid")?;
    validate_levels(required_array(value, "a", "depth")?, "depth ask")?;
    if !sequence.started {
        if final_id <= snapshot_sequence {
            return Ok(());
        }
        let bridge = snapshot_sequence
            .checked_add(1)
            .ok_or_else(|| "snapshot sequence overflow".to_owned())?;
        if first > bridge || final_id < bridge {
            return Err("depth stream cannot bridge its durable snapshot".to_owned());
        }
        sequence.started = true;
        sequence.first = Some(first);
        sequence.previous_final = Some(final_id);
        return Ok(());
    }
    let next = sequence
        .previous_final
        .expect("started depth sequence has a terminal ID")
        .checked_add(1)
        .ok_or_else(|| "depth sequence overflow".to_owned())?;
    if first > next || final_id < next {
        return Err(format!(
            "depth update discontinuity: expected coverage of {next}, got {first}..{final_id}"
        ));
    }
    sequence.previous_final = Some(final_id);
    Ok(())
}

fn validate_trade_payload(value: &Value, symbol: &str, sequence: &mut SequenceState) -> Result<()> {
    if value["e"].as_str() != Some("trade") || value["s"].as_str() != Some(symbol) {
        return Err("trade event identity is invalid".to_owned());
    }
    required_u64(value, "E", "trade")?;
    let trade_id = required_u64(value, "t", "trade")?;
    required_u64(value, "T", "trade")?;
    for field in ["p", "q"] {
        if value[field].as_str().is_none() {
            return Err(format!("trade field {field} is not a decimal string"));
        }
    }
    for field in ["m", "M"] {
        if value[field].as_bool().is_none() {
            return Err(format!("trade field {field} is not boolean"));
        }
    }
    if let Some(previous) = sequence.previous_final {
        if trade_id <= previous {
            return Err(format!(
                "trade ID duplicated or regressed: previous {previous}, got {trade_id}"
            ));
        }
    } else {
        sequence.started = true;
        sequence.first = Some(trade_id);
    }
    sequence.previous_final = Some(trade_id);
    Ok(())
}

fn validate_server_shutdown_payload(value: &Value, sequence: &mut SequenceState) -> Result<bool> {
    if value["e"].as_str() != Some("serverShutdown") {
        return Ok(false);
    }
    required_u64(value, "E", "serverShutdown")?;
    sequence.server_shutdown_events = sequence
        .server_shutdown_events
        .checked_add(1)
        .ok_or_else(|| "serverShutdown event count overflow".to_owned())?;
    Ok(true)
}

fn seal_ack(entry: &RawSegmentManifestEntryV1) -> DurabilityAckV1 {
    let seal = &entry.seal;
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

fn validate_transport_metadata(
    session: &Path,
    session_id: &str,
    generation_index: u64,
    symbol: &str,
    stream: &StreamManifestV1,
    expected_uri: &str,
) -> Result<()> {
    let file = stream
        .transport_metadata_file
        .as_deref()
        .ok_or_else(|| format!("{} stream lacks transport metadata file", stream.name))?;
    let expected_file = format!("transport-{}.json", stream.name);
    let digest = stream
        .transport_metadata_sha256
        .as_deref()
        .ok_or_else(|| format!("{} stream lacks transport metadata digest", stream.name))?;
    if file != expected_file || !valid_sha256(digest) {
        return Err(format!(
            "{} transport metadata reference is invalid",
            stream.name
        ));
    }
    let relative = safe_relative(file)?;
    let path = session.join(relative);
    reject_symlink(&path)?;
    let bytes = fs::read(&path)
        .map_err(|error| format!("read transport metadata {}: {error}", path.display()))?;
    if sha256_bytes(&bytes) != digest {
        return Err(format!("{} transport metadata digest drift", stream.name));
    }
    let metadata: TransportMetadataV1 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid {} transport metadata: {error}", stream.name))?;
    let connection = &metadata.connection;
    let local = connection
        .local_endpoint
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid {} local endpoint: {error}", stream.name))?;
    let remote = connection
        .remote_endpoint
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid {} remote endpoint: {error}", stream.name))?;
    let headers_valid = !connection.response_headers.is_empty()
        && connection.response_headers.iter().all(|(name, values)| {
            !name.trim().is_empty()
                && !values.is_empty()
                && values.iter().all(|value| !value.contains(['\r', '\n']))
        });
    if metadata.schema != "TransportMetadataV1"
        || metadata.session_id != session_id
        || metadata.generation_index != generation_index
        || metadata.symbol != symbol
        || metadata.spec_revision != SEGMENTED_SPEC_REVISION
        || connection.stream != stream.name
        || connection.connection_epoch != stream.connection_epoch
        || connection.uri != expected_uri
        || connection.uri != stream.uri
        || connection.websocket_http_status != 101
        || local.port() == 0
        || local.ip().is_unspecified()
        || remote.port() != 443
        || remote.ip().is_unspecified()
        || !headers_valid
    {
        return Err(format!(
            "{} transport metadata identity/handshake drift",
            stream.name
        ));
    }
    Ok(())
}

fn validate_transport_journal(session: &Path, stream: &StreamManifestV1) -> Result<()> {
    let seal = stream
        .transport_journal
        .as_ref()
        .ok_or_else(|| format!("{} stream lacks a sealed transport journal", stream.name))?;
    let expected_file = format!("transport-{}-events.jsonl", stream.name);
    if seal.schema != "TransportJournalSealV1"
        || seal.file != expected_file
        || seal.records == 0
        || !valid_sha256(&seal.terminal_record_sha256)
        || seal.file_bytes == 0
        || !valid_sha256(&seal.file_sha256)
    {
        return Err(format!("{} transport journal seal is invalid", stream.name));
    }
    let relative = safe_relative(&seal.file)?;
    let path = session.join(relative);
    reject_symlink(&path)?;
    let scanned = verify_sealed_transport_journal(
        &path,
        &stream.name,
        &stream.connection_epoch,
        &stream.uri,
        stream.received,
    )?;
    if &scanned != seal {
        return Err(format!("{} transport journal seal drift", stream.name));
    }
    Ok(())
}

fn validate_stream(
    session: &Path,
    session_id: &str,
    generation_index: u64,
    symbol: &str,
    snapshot_sequence: u64,
    timing: GenerationTiming,
    stream: &StreamManifestV1,
) -> Result<VerifiedGenerationStreamV1> {
    if !matches!(stream.name.as_str(), "depth" | "trade")
        || stream.error.is_some()
        || stream.received == 0
        || stream.received != stream.written
        || stream.written != stream.durable_records
        || stream.segments == 0
    {
        return Err("generation stream terminal status/count is invalid".to_owned());
    }
    let expected_uri = if stream.name == "depth" {
        format!(
            "wss://data-stream.binance.vision:443/ws/{}@depth@100ms?timeUnit=MICROSECOND",
            symbol.to_ascii_lowercase()
        )
    } else {
        format!(
            "wss://data-stream.binance.vision:443/ws/{}@trade?timeUnit=MICROSECOND",
            symbol.to_ascii_lowercase()
        )
    };
    let expected_manifest = format!("{}/segments.bnseg", stream.name);
    if stream.uri != expected_uri || stream.segment_manifest != expected_manifest {
        return Err(format!("{} stream endpoint/manifest drift", stream.name));
    }
    validate_transport_metadata(
        session,
        session_id,
        generation_index,
        symbol,
        stream,
        &expected_uri,
    )?;
    validate_transport_journal(session, stream)?;
    let manifest_relative = safe_relative(&stream.segment_manifest)?;
    let manifest_path = session.join(manifest_relative);
    let scan = scan_segment_manifest(&manifest_path)?;
    if !scan.clean_eof
        || scan.records != stream.segments
        || scan.entries.len() as u64 != stream.segments
        || scan.last_record_sha256 != stream.segment_manifest_sha256
    {
        return Err(format!("{} BNSEG terminal state mismatch", stream.name));
    }
    let stream_directory = session.join(&stream.name);
    let segment_ns = timing
        .segment_duration_s
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "segment duration nanoseconds overflow".to_owned())?;
    let active_end_ns = timing
        .duration_requested_s
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "generation duration nanoseconds overflow".to_owned())?;
    let mut expected_files = BTreeSet::from(["segments.bnseg".to_owned()]);
    for entry in &scan.entries {
        expected_files.insert(entry.seal.raw_file.clone());
        expected_files.insert(format!("segment-{:06}.bnack", entry.seal.segment_index));
    }
    exact_directory_entries(&stream_directory, &expected_files)?;
    verify_segment_manifest_files(&scan, &stream_directory)?;
    let mut records_total = 0_u64;
    let mut previous_mono = None;
    let mut sequence = SequenceState::default();
    let mut freshness = RawMarketFreshness::default();
    let mut server_shutdowns = Vec::new();
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
        let raw_path = stream_directory.join(&seal.raw_file);
        let progress_path =
            stream_directory.join(format!("segment-{:06}.bnack", seal.segment_index));
        let progress_scan = scan_durability_progress(&progress_path)?;
        let mut follower = SegmentDurabilityFollower::open_with_reference(
            &progress_path,
            &raw_path,
            &genesis,
            &seal.raw_file,
        )?;
        let cursor = follower.require_clean_eof()?;
        if cursor.latest_ack.as_ref() != Some(&seal_ack(entry))
            || cursor.raw_record_count != seal.records
            || cursor.raw_offset != seal.durable_through_offset
            || cursor.raw_previous_record_sha256 != seal.terminal_record_sha256
            || cursor.raw_next_frame_index
                != seal
                    .last_frame_index
                    .checked_add(1)
                    .ok_or_else(|| "raw frame index overflow".to_owned())?
        {
            return Err(format!(
                "{} BNACK differs from exact sealed BNRAW",
                stream.name
            ));
        }
        let records = read_raw_segment_records(&raw_path, &genesis)?;
        if records.len() as u64 != seal.records {
            return Err(format!("{} segment record count drift", stream.name));
        }
        for record in &records {
            if record.frame.receive_mono_ns / segment_ns != seal.segment_index {
                return Err(format!(
                    "{} record is outside its declared monotonic segment",
                    stream.name
                ));
            }
            if let Some(old) = previous_mono
                && record.frame.receive_mono_ns < old
            {
                return Err(format!("{} receive monotonic time regressed", stream.name));
            }
            previous_mono = Some(record.frame.receive_mono_ns);
            let value = validate_frame_identity(
                record,
                symbol,
                &stream.name,
                &stream.connection_epoch,
                &stream.uri,
            )?;
            if validate_server_shutdown_payload(&value, &mut sequence)? {
                let exact_ack = DurabilityAckV1 {
                    schema: "DurabilityAckV1".to_owned(),
                    durable_record_count: record
                        .record_index
                        .checked_add(1)
                        .ok_or_else(|| "serverShutdown durable count overflow".to_owned())?,
                    durable_through_offset: record.end_offset,
                    last_record_sha256: record.record_sha256.clone(),
                    streams: vec![StreamDurabilityWatermarkV1 {
                        connection_epoch: stream.connection_epoch.clone(),
                        stream: seal.stream.clone(),
                        durable_through_frame_index: record.frame.frame_index,
                    }],
                };
                if !progress_scan.acknowledgements.contains(&exact_ack) {
                    return Err(format!(
                        "{} serverShutdown record lacks its exact durable BNACK",
                        stream.name
                    ));
                }
                server_shutdowns.push(VerifiedServerShutdownV1 {
                    stream: stream.name.clone(),
                    connection_epoch: stream.connection_epoch.clone(),
                    segment_index: seal.segment_index,
                    raw_file: seal.raw_file.clone(),
                    frame_index: record.frame.frame_index,
                    receive_mono_ns: record.frame.receive_mono_ns,
                    durable_record_count: exact_ack.durable_record_count,
                    durable_through_offset: record.end_offset,
                    last_record_sha256: record.record_sha256.clone(),
                });
                continue;
            }
            if stream.name == "depth" {
                validate_depth_payload(&value, symbol, snapshot_sequence, &mut sequence)?;
            } else {
                validate_trade_payload(&value, symbol, &mut sequence)?;
            }
            freshness.observe(&stream.name, record.frame.receive_mono_ns, active_end_ns)?;
            sequence.last_market_mono_ns = record.frame.receive_mono_ns;
        }
        records_total = records_total
            .checked_add(records.len() as u64)
            .ok_or_else(|| "generation record count overflow".to_owned())?;
    }
    let first = scan
        .entries
        .first()
        .ok_or_else(|| "verified stream manifest is empty".to_owned())?;
    let last = scan.entries.last().expect("entries checked nonempty");
    freshness.finish(&stream.name, active_end_ns)?;
    if records_total != stream.received
        || first.seal.first_frame_index != 0
        || last.seal.last_frame_index
            != stream
                .received
                .checked_sub(1)
                .ok_or_else(|| "empty stream record count".to_owned())?
        || last.seal.terminal_record_sha256 != stream.terminal_raw_sha256
        || sequence.last_market_mono_ns != stream.last_market_message_mono_ns
        || stream.last_socket_activity_mono_ns < stream.last_market_message_mono_ns
        || sequence.server_shutdown_events != stream.server_shutdown_events
        || !sequence.started
    {
        return Err(format!(
            "{} terminal lineage/continuity mismatch",
            stream.name
        ));
    }
    Ok(VerifiedGenerationStreamV1 {
        schema: "VerifiedGenerationStreamV1",
        name: stream.name.clone(),
        connection_epoch: stream.connection_epoch.clone(),
        records: records_total,
        segments: stream.segments,
        first_frame_index: first.seal.first_frame_index,
        last_frame_index: last.seal.last_frame_index,
        first_sequence: sequence.first.expect("started sequence has first ID"),
        final_sequence: sequence
            .previous_final
            .expect("started sequence has final ID"),
        last_socket_activity_mono_ns: stream.last_socket_activity_mono_ns,
        last_market_message_mono_ns: stream.last_market_message_mono_ns,
        server_shutdown_events: stream.server_shutdown_events,
        server_shutdowns,
        manifest_sha256: scan.last_record_sha256,
        terminal_raw_sha256: last.seal.terminal_record_sha256.clone(),
        entries: scan.entries,
    })
}

fn validate_telemetry(
    path: &Path,
    manifest: &TelemetryManifestV1,
    streams: &[VerifiedGenerationStreamV1],
    duration_requested_s: u64,
) -> Result<(String, u64)> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let file_sha256 = sha256_bytes(&bytes);
    if manifest.schema != "TelemetryArtifactV1"
        || manifest.file != "telemetry.jsonl"
        || manifest.records == 0
        || manifest.durable_through_offset == 0
        || !valid_sha256(&manifest.terminal_record_sha256)
        || manifest.terminal_mono_ns == 0
        || manifest.file_sha256 != file_sha256
        || bytes.is_empty()
        || !bytes.ends_with(b"\n")
        || u64::try_from(bytes.len()).map_err(|_| "telemetry size overflow".to_owned())?
            != manifest.durable_through_offset
    {
        return Err("telemetry has an empty or partial terminal record".to_owned());
    }
    let expected: BTreeMap<&str, &VerifiedGenerationStreamV1> = streams
        .iter()
        .map(|stream| (stream.name.as_str(), stream))
        .collect();
    let mut previous: Option<TelemetryRecordV1> = None;
    let mut count = 0_u64;
    let mut terminal_record_sha256 = None;
    let mut parsed_offset = 0_u64;
    for line_with_newline in bytes.split_inclusive(|byte| *byte == b'\n') {
        if line_with_newline.len() <= 1 || !line_with_newline.ends_with(b"\n") {
            return Err("telemetry contains an empty or partial record".to_owned());
        }
        parsed_offset = parsed_offset
            .checked_add(
                u64::try_from(line_with_newline.len())
                    .map_err(|_| "telemetry record size overflow".to_owned())?,
            )
            .ok_or_else(|| "telemetry offset overflow".to_owned())?;
        let line = &line_with_newline[..line_with_newline.len() - 1];
        let record: TelemetryRecordV1 = serde_json::from_slice(line)
            .map_err(|error| format!("invalid telemetry JSON: {error}"))?;
        if record.schema != "CaptureTelemetryV1"
            || record.record_index != count
            || record.wall_ns == 0
            || record.clock.quality.trim().is_empty()
            || record.clock.source.trim().is_empty()
            || !matches!(
                record.clock.quality.as_str(),
                "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND" | "UNKNOWN"
            )
            || (record.clock.quality == "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND"
                && (record.clock.leap_indicator != Some(0)
                    || !matches!(record.clock.stratum, Some(1..=15))
                    || record.clock.last_successful_sync.is_none()))
            || record.depth_written > record.depth_received
            || record.depth_durable > record.depth_written
            || record.trade_written > record.trade_received
            || record.trade_durable > record.trade_written
            || record.depth_last_socket_activity_mono_ns > record.mono_ns
            || record.depth_last_market_message_mono_ns > record.mono_ns
            || record.depth_last_durable_mono_ns > record.mono_ns
            || record.trade_last_socket_activity_mono_ns > record.mono_ns
            || record.trade_last_market_message_mono_ns > record.mono_ns
            || record.trade_last_durable_mono_ns > record.mono_ns
            || record.depth_last_market_message_mono_ns > record.depth_last_socket_activity_mono_ns
            || record.trade_last_market_message_mono_ns > record.trade_last_socket_activity_mono_ns
            || record.depth_queue_records > record.depth_max_queue_records
            || record.depth_queue_bytes > record.depth_max_queue_bytes
            || record.depth_last_sync_duration_ns > record.depth_max_sync_duration_ns
            || record.trade_queue_records > record.trade_max_queue_records
            || record.trade_queue_bytes > record.trade_max_queue_bytes
            || record.trade_last_sync_duration_ns > record.trade_max_sync_duration_ns
        {
            return Err("telemetry record shape/counters are invalid".to_owned());
        }
        let active_end_ns = duration_requested_s.saturating_mul(1_000_000_000);
        let freshness_grace_ns = MARKET_FRESHNESS_STARTUP_GRACE_S * 1_000_000_000;
        let freshness_deadline_ns = MARKET_FRESHNESS_DEADLINE_S * 1_000_000_000;
        if record.mono_ns >= freshness_grace_ns
            && record.mono_ns < active_end_ns
            && (record.depth_last_market_message_mono_ns == 0
                || record.trade_last_market_message_mono_ns == 0
                || record
                    .mono_ns
                    .saturating_sub(record.depth_last_market_message_mono_ns)
                    > freshness_deadline_ns
                || record
                    .mono_ns
                    .saturating_sub(record.trade_last_market_message_mono_ns)
                    > freshness_deadline_ns)
        {
            return Err(
                "telemetry records stale market data despite fresh socket/control activity"
                    .to_owned(),
            );
        }
        if let Some(old) = &previous
            && (record.mono_ns < old.mono_ns
                || record.depth_received < old.depth_received
                || record.depth_written < old.depth_written
                || record.depth_durable < old.depth_durable
                || record.depth_segment < old.depth_segment
                || record.depth_last_socket_activity_mono_ns
                    < old.depth_last_socket_activity_mono_ns
                || record.depth_last_market_message_mono_ns < old.depth_last_market_message_mono_ns
                || record.depth_max_queue_records < old.depth_max_queue_records
                || record.depth_max_queue_bytes < old.depth_max_queue_bytes
                || record.depth_max_queue_age_ns < old.depth_max_queue_age_ns
                || record.depth_max_sync_duration_ns < old.depth_max_sync_duration_ns
                || record.trade_received < old.trade_received
                || record.trade_written < old.trade_written
                || record.trade_durable < old.trade_durable
                || record.trade_segment < old.trade_segment
                || record.trade_last_socket_activity_mono_ns
                    < old.trade_last_socket_activity_mono_ns
                || record.trade_last_market_message_mono_ns < old.trade_last_market_message_mono_ns
                || record.trade_max_queue_records < old.trade_max_queue_records
                || record.trade_max_queue_bytes < old.trade_max_queue_bytes
                || record.trade_max_queue_age_ns < old.trade_max_queue_age_ns
                || record.trade_max_sync_duration_ns < old.trade_max_sync_duration_ns)
        {
            return Err("telemetry monotonic lineage regressed".to_owned());
        }
        terminal_record_sha256 = Some(sha256_bytes(line_with_newline));
        previous = Some(record);
        count = count
            .checked_add(1)
            .ok_or_else(|| "telemetry record count overflow".to_owned())?;
    }
    let terminal = previous.ok_or_else(|| "telemetry has no records".to_owned())?;
    let depth = expected
        .get("depth")
        .ok_or_else(|| "verified generation lacks depth stream".to_owned())?;
    let trade = expected
        .get("trade")
        .ok_or_else(|| "verified generation lacks trade stream".to_owned())?;
    if terminal.depth_received != depth.records
        || terminal.depth_written != depth.records
        || terminal.depth_durable != depth.records
        || terminal.depth_segment != depth.segments - 1
        || terminal.depth_queue_records != 0
        || terminal.depth_queue_bytes != 0
        || terminal.depth_last_socket_activity_mono_ns != depth.last_socket_activity_mono_ns
        || terminal.depth_last_market_message_mono_ns != depth.last_market_message_mono_ns
        || terminal.trade_received != trade.records
        || terminal.trade_written != trade.records
        || terminal.trade_durable != trade.records
        || terminal.trade_segment != trade.segments - 1
        || terminal.trade_queue_records != 0
        || terminal.trade_queue_bytes != 0
        || terminal.trade_last_socket_activity_mono_ns != trade.last_socket_activity_mono_ns
        || terminal.trade_last_market_message_mono_ns != trade.last_market_message_mono_ns
        || terminal.depth_max_sync_duration_ns == 0
        || terminal.trade_max_sync_duration_ns == 0
        || count != manifest.records
        || parsed_offset != manifest.durable_through_offset
        || terminal_record_sha256.as_deref() != Some(&manifest.terminal_record_sha256)
        || terminal.mono_ns != manifest.terminal_mono_ns
        || terminal.mono_ns < duration_requested_s.saturating_mul(1_000_000_000)
    {
        return Err("telemetry terminal counters differ from sealed raw streams".to_owned());
    }
    Ok((file_sha256, count))
}

pub fn verify_segmented_generation(session: &Path) -> Result<VerifiedGenerationV1> {
    let generation_path = session.join("generation.json");
    let generation_bytes = fs::read(&generation_path)
        .map_err(|error| format!("read {}: {error}", generation_path.display()))?;
    let manifest: GenerationManifestV1 = serde_json::from_slice(&generation_bytes)
        .map_err(|error| format!("invalid generation manifest JSON: {error}"))?;
    if manifest.schema != "RawGenerationManifestV1"
        || manifest.implementation != "rust-segmented"
        || manifest.status != "COMPLETE"
        || manifest.failure.is_some()
        || !matches!(manifest.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
        || manifest.duration_requested_s == 0
        || manifest.segment_duration_s == 0
        || manifest.segment_duration_s > manifest.duration_requested_s
        || manifest.started_wall_ns == 0
        || manifest.finished_wall_ns < manifest.started_wall_ns
        || !valid_sha256(&manifest.collector_executable_sha256)
        || !valid_sha256(&manifest.public_config_sha256)
        || manifest.market_freshness_startup_grace_s != MARKET_FRESHNESS_STARTUP_GRACE_S
        || manifest.market_freshness_deadline_s != MARKET_FRESHNESS_DEADLINE_S
        || manifest.credentials != "NONE"
        || manifest.order_entry != "ABSENT"
        || manifest.raw_boundary
            != "WebSocket application messages after TLS/framing and before JSON interpretation"
        || manifest.spec_revision != SEGMENTED_SPEC_REVISION
        || manifest.startup_file != "startup.json"
        || manifest.telemetry.file != "telemetry.jsonl"
        || session.file_name().and_then(|name| name.to_str()) != Some(&manifest.session_id)
    {
        return Err("generation manifest contract/status is invalid".to_owned());
    }
    let startup_path = session.join(&manifest.startup_file);
    let startup_bytes = fs::read(&startup_path)
        .map_err(|error| format!("read {}: {error}", startup_path.display()))?;
    if sha256_bytes(&startup_bytes) != manifest.startup_sha256 {
        return Err("startup manifest digest differs from terminal generation".to_owned());
    }
    let startup: StartupManifestV1 = serde_json::from_slice(&startup_bytes)
        .map_err(|error| format!("invalid generation startup JSON: {error}"))?;
    if startup.schema != "RawGenerationStartupV1"
        || startup.implementation != manifest.implementation
        || startup.session_id != manifest.session_id
        || startup.generation_index != manifest.generation_index
        || startup.symbol != manifest.symbol
        || startup.duration_requested_s != manifest.duration_requested_s
        || startup.segment_duration_s != manifest.segment_duration_s
        || startup.started_wall_ns != manifest.started_wall_ns
        || startup.collector_executable_sha256 != manifest.collector_executable_sha256
        || startup.public_config_sha256 != manifest.public_config_sha256
        || startup.market_freshness_startup_grace_s != manifest.market_freshness_startup_grace_s
        || startup.market_freshness_deadline_s != manifest.market_freshness_deadline_s
        || startup.credentials != manifest.credentials
        || startup.order_entry != manifest.order_entry
        || startup.raw_boundary != manifest.raw_boundary
        || startup.spec_revision != manifest.spec_revision
    {
        return Err("startup manifest differs from terminal generation identity".to_owned());
    }
    let snapshot = manifest
        .snapshot
        .as_ref()
        .ok_or_else(|| "complete generation lacks durable snapshot".to_owned())?;
    let (snapshot_sha256, snapshot_record_sha256) =
        validate_snapshot(session, &manifest.symbol, snapshot)?;
    if manifest.streams.len() != 2 {
        return Err("generation must contain exactly depth and trade".to_owned());
    }
    let mut seen = BTreeMap::new();
    let mut streams = Vec::with_capacity(2);
    for stream in &manifest.streams {
        if seen.insert(stream.name.as_str(), ()).is_some() {
            return Err("generation contains a duplicate stream".to_owned());
        }
        streams.push(validate_stream(
            session,
            &manifest.session_id,
            manifest.generation_index,
            &manifest.symbol,
            snapshot.last_update_id,
            GenerationTiming {
                duration_requested_s: manifest.duration_requested_s,
                segment_duration_s: manifest.segment_duration_s,
            },
            stream,
        )?);
    }
    streams.sort_by(|left, right| left.name.cmp(&right.name));
    if streams
        .iter()
        .map(|stream| stream.name.as_str())
        .collect::<Vec<_>>()
        != ["depth", "trade"]
    {
        return Err("generation stream set differs from depth/trade".to_owned());
    }
    let (telemetry_sha256, telemetry_records) = validate_telemetry(
        &session.join("telemetry.jsonl"),
        &manifest.telemetry,
        &streams,
        manifest.duration_requested_s,
    )?;
    exact_directory_entries(
        session,
        &BTreeSet::from([
            "depth".to_owned(),
            "generation.json".to_owned(),
            "snapshot-http.json".to_owned(),
            "snapshot.bnraw".to_owned(),
            "startup.json".to_owned(),
            "telemetry.jsonl".to_owned(),
            "transport-depth-events.jsonl".to_owned(),
            "transport-depth.json".to_owned(),
            "transport-trade-events.jsonl".to_owned(),
            "transport-trade.json".to_owned(),
            "trade".to_owned(),
        ]),
    )?;
    let generation_manifest_sha256 = sha256_bytes(&generation_bytes);
    let material = VerificationDigestMaterial {
        schema: "VerifiedGenerationDigestV1",
        session_id: &manifest.session_id,
        generation_index: manifest.generation_index,
        symbol: &manifest.symbol,
        duration_requested_s: manifest.duration_requested_s,
        segment_duration_s: manifest.segment_duration_s,
        collector_executable_sha256: &manifest.collector_executable_sha256,
        public_config_sha256: &manifest.public_config_sha256,
        generation_manifest_sha256: &generation_manifest_sha256,
        snapshot_sha256: &snapshot_sha256,
        snapshot_record_sha256: &snapshot_record_sha256,
        snapshot_last_update_id: snapshot.last_update_id,
        telemetry_sha256: &telemetry_sha256,
        telemetry_records,
        streams: &streams,
    };
    let verification_sha256 = sha256_bytes(
        &serde_json::to_vec(&material)
            .map_err(|error| format!("serialize generation verification digest: {error}"))?,
    );
    Ok(VerifiedGenerationV1 {
        schema: "VerifiedGenerationV1",
        status: "PASS",
        session_id: manifest.session_id,
        session_dir: session.to_path_buf(),
        generation_index: manifest.generation_index,
        symbol: manifest.symbol,
        duration_requested_s: manifest.duration_requested_s,
        segment_duration_s: manifest.segment_duration_s,
        started_wall_ns: manifest.started_wall_ns,
        finished_wall_ns: manifest.finished_wall_ns,
        collector_executable_sha256: manifest.collector_executable_sha256,
        public_config_sha256: manifest.public_config_sha256,
        generation_manifest_sha256,
        snapshot_sha256,
        snapshot_record_sha256,
        snapshot_last_update_id: snapshot.last_update_id,
        telemetry_sha256,
        telemetry_records,
        streams,
        verification_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::{RawMarketFreshness, StreamManifestV1, sha256_bytes, validate_transport_metadata};
    use tempfile::tempdir;

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn raw_market_freshness_rejects_a_recovered_gap_between_telemetry_samples() {
        let mut freshness = RawMarketFreshness::default();
        freshness.observe("trade", SECOND, 90 * SECOND).unwrap();
        let error = freshness
            .observe("trade", 32 * SECOND, 90 * SECOND)
            .unwrap_err();
        assert!(error.contains("gap exceeds"));
    }

    #[test]
    fn raw_market_freshness_rejects_late_start_and_post_deadline_substitution() {
        let mut late_start = RawMarketFreshness::default();
        late_start
            .observe("depth", 31 * SECOND, 90 * SECOND)
            .unwrap();
        assert!(late_start.finish("depth", 90 * SECOND).is_err());

        let mut only_drain = RawMarketFreshness::default();
        only_drain
            .observe("depth", 21 * SECOND, 20 * SECOND)
            .unwrap();
        assert!(only_drain.finish("depth", 20 * SECOND).is_err());
    }

    #[test]
    fn raw_market_freshness_rejects_tail_even_after_drain_recovers() {
        let mut tail = RawMarketFreshness::default();
        for second in [9, 39, 69] {
            tail.observe("trade", second * SECOND, 100 * SECOND)
                .unwrap();
        }
        assert!(tail.finish("trade", 100 * SECOND).is_err());

        let mut recovered_after_deadline = RawMarketFreshness::default();
        for second in [9, 39, 69] {
            recovered_after_deadline
                .observe("trade", second * SECOND, 100 * SECOND)
                .unwrap();
        }
        recovered_after_deadline
            .observe("trade", 101 * SECOND, 100 * SECOND)
            .unwrap();
        assert!(
            recovered_after_deadline
                .finish("trade", 100 * SECOND)
                .is_err()
        );
    }

    #[test]
    fn raw_market_freshness_accepts_exact_deadlines_and_short_active_window() {
        let mut exact = RawMarketFreshness::default();
        for second in [30, 60, 90, 120] {
            exact
                .observe("depth", second * SECOND, 120 * SECOND)
                .unwrap();
        }
        exact.finish("depth", 120 * SECOND).unwrap();

        let mut short = RawMarketFreshness::default();
        short.observe("trade", 20 * SECOND, 20 * SECOND).unwrap();
        short.finish("trade", 20 * SECOND).unwrap();
    }

    #[test]
    fn transport_metadata_is_exactly_bound_to_stream_identity() {
        let directory = tempdir().unwrap();
        let uri = "wss://data-stream.binance.vision:443/ws/btcusdt@trade?timeUnit=MICROSECOND";
        let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "TransportMetadataV1",
            "session_id": "session",
            "generation_index": 4,
            "symbol": "BTCUSDT",
            "spec_revision": super::SEGMENTED_SPEC_REVISION,
            "connection": {
                "stream": "trade",
                "connection_epoch": "trade-epoch",
                "uri": uri,
                "websocket_http_status": 101,
                "local_endpoint": "127.0.0.1:50000",
                "remote_endpoint": "127.0.0.2:443",
                "response_headers": {"upgrade": ["websocket"]}
            }
        }))
        .unwrap();
        bytes.push(b'\n');
        std::fs::write(directory.path().join("transport-trade.json"), &bytes).unwrap();
        let stream = StreamManifestV1 {
            name: "trade".to_owned(),
            uri: uri.to_owned(),
            connection_epoch: "trade-epoch".to_owned(),
            transport_metadata_file: Some("transport-trade.json".to_owned()),
            transport_metadata_sha256: Some(sha256_bytes(&bytes)),
            transport_journal: None,
            received: 1,
            written: 1,
            durable_records: 1,
            segments: 1,
            last_socket_activity_mono_ns: 1,
            last_market_message_mono_ns: 1,
            server_shutdown_events: 0,
            segment_manifest: "trade/segments.bnseg".to_owned(),
            segment_manifest_sha256: "0".repeat(64),
            terminal_raw_sha256: "0".repeat(64),
            error: None,
        };
        validate_transport_metadata(directory.path(), "session", 4, "BTCUSDT", &stream, uri)
            .unwrap();

        let mut tampered = bytes.clone();
        tampered.push(b' ');
        std::fs::write(directory.path().join("transport-trade.json"), tampered).unwrap();
        assert!(
            validate_transport_metadata(directory.path(), "session", 4, "BTCUSDT", &stream, uri,)
                .is_err()
        );
    }
}
