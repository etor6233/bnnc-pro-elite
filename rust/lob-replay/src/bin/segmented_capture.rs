use lob_replay::capture_config::validate_public_capture_config;
use lob_replay::durability_progress::DurabilityProgressWriter;
use lob_replay::segment_chain::{
    RawSegmentManifestWriter, root_segment_genesis, scan_segment_manifest,
    successor_segment_genesis, verify_and_seal_raw_segment,
};
use lob_replay::transport_journal::{TransportJournalSealV1, TransportJournalWriter};
#[cfg(windows)]
use lob_replay::windows_tcp::sample_tcp_info_v0;
#[cfg(windows)]
use lob_replay::windows_time::TrustedWindowsTimeProbe;
use lob_replay::{CapturedFrame, DurabilityAckV1, RawLogWriter, RawSegmentGenesisV1, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Error as WebSocketError, Message, WebSocket, connect};
use uuid::Uuid;

const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";
const WS_BASE: &str = "wss://data-stream.binance.vision:443";
const REST_BASE: &str = "https://data-api.binance.vision";
const SOCKET_POLL_TIMEOUT: Duration = Duration::from_secs(5);
const TRANSPORT_DEAD_AFTER: Duration = Duration::from_secs(60);
// Watchdog ping→pong (port of tetsuo SocketWS.c ws_auto_ping_callback): a
// proactive PING every 30 s keeps transport liveness honest; a missing PONG
// within 5 s types the transport as DEAD, while a ponging-but-silent exchange
// is typed exchange-silent by the market-freshness layer.
const WS_PING_INTERVAL: Duration = Duration::from_secs(30);
const WS_PONG_DEADLINE: Duration = Duration::from_secs(5);
const WRITER_SYNC_MAX_AGE: Duration = Duration::from_secs(1);
const SUPERVISOR_POLL: Duration = Duration::from_millis(50);
const TELEMETRY_PERIOD: Duration = Duration::from_secs(5);
const CLOCK_PROBE_PERIOD: Duration = Duration::from_secs(30);
const MARKET_FRESHNESS_STARTUP_GRACE_S: u64 = 30;
const MARKET_FRESHNESS_DEADLINE_S: u64 = 30;
const GROUP_SYNC_RECORDS: u64 = 64;
const MAX_WS_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
struct ClockMetadata {
    quality: String,
    source: String,
    leap_indicator: Option<u8>,
    stratum: Option<u8>,
    last_successful_sync: Option<String>,
}

#[cfg(not(windows))]
struct TrustedWindowsTimeProbe;

#[cfg(not(windows))]
impl TrustedWindowsTimeProbe {
    fn resolve() -> Result<Self> {
        Ok(Self)
    }
}

#[derive(Default)]
struct StreamHealth {
    received: AtomicU64,
    written: AtomicU64,
    durable: AtomicU64,
    segment_index: AtomicU64,
    last_socket_activity_mono_ns: AtomicU64,
    last_market_message_mono_ns: AtomicU64,
    server_shutdown_events: AtomicU64,
    last_durable_mono_ns: AtomicU64,
    queue_records: AtomicU64,
    queue_bytes: AtomicU64,
    max_queue_records: AtomicU64,
    max_queue_bytes: AtomicU64,
    max_queue_age_ns: AtomicU64,
    last_sync_duration_ns: AtomicU64,
    max_sync_duration_ns: AtomicU64,
}

#[derive(Clone, Copy, Debug)]
struct StreamHealthSnapshot {
    received: u64,
    written: u64,
    durable: u64,
    segment_index: u64,
    last_socket_activity_mono_ns: u64,
    last_market_message_mono_ns: u64,
    last_durable_mono_ns: u64,
    queue_records: u64,
    queue_bytes: u64,
    max_queue_records: u64,
    max_queue_bytes: u64,
    max_queue_age_ns: u64,
    last_sync_duration_ns: u64,
    max_sync_duration_ns: u64,
}

impl StreamHealthSnapshot {
    fn load(health: &StreamHealth) -> Self {
        // These are observational counters updated by the producer and writer.
        // Load causally later facts first, then the facts that must cover them:
        // durable -> written -> received and market -> socket -> received. This
        // produces a conservative, invariant-preserving observation without a
        // mutex on the market-data hot path.
        let last_durable_mono_ns = health.last_durable_mono_ns.load(Ordering::Acquire);
        let durable = health.durable.load(Ordering::Acquire);
        let last_market_message_mono_ns =
            health.last_market_message_mono_ns.load(Ordering::Acquire);
        let written = health.written.load(Ordering::Acquire);
        let last_socket_activity_mono_ns =
            health.last_socket_activity_mono_ns.load(Ordering::Acquire);
        let received = health.received.load(Ordering::Acquire);
        Self {
            received,
            written,
            durable,
            segment_index: health.segment_index.load(Ordering::Acquire),
            last_socket_activity_mono_ns,
            last_market_message_mono_ns,
            last_durable_mono_ns,
            queue_records: health.queue_records.load(Ordering::Acquire),
            queue_bytes: health.queue_bytes.load(Ordering::Acquire),
            max_queue_records: health.max_queue_records.load(Ordering::Acquire),
            max_queue_bytes: health.max_queue_bytes.load(Ordering::Acquire),
            max_queue_age_ns: health.max_queue_age_ns.load(Ordering::Acquire),
            last_sync_duration_ns: health.last_sync_duration_ns.load(Ordering::Acquire),
            max_sync_duration_ns: health.max_sync_duration_ns.load(Ordering::Acquire),
        }
    }
}

#[derive(Debug, Serialize)]
struct StartupManifest {
    schema: &'static str,
    implementation: &'static str,
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
    credentials: &'static str,
    order_entry: &'static str,
    raw_boundary: &'static str,
    spec_revision: &'static str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaptureStopRequestV1 {
    schema: String,
    session_id: String,
    reason: String,
    campaign_failure_record_sha256: String,
}

#[derive(Clone, Debug)]
struct SupervisorStopCause {
    source: &'static str,
    reason: String,
    campaign_failure_record_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
struct StreamResult {
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

#[derive(Debug, Serialize)]
struct SnapshotResult {
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

#[derive(Serialize)]
struct SnapshotHttpMetadata<'a> {
    schema: &'static str,
    endpoint: &'a str,
    http_status: u16,
    headers: BTreeMap<String, Vec<String>>,
    receive_wall_ns: u64,
    receive_mono_ns: u64,
    body_complete: bool,
    body_length: usize,
    body_sha256: String,
    raw_file: &'static str,
    raw_record_sha256: &'a str,
}

#[derive(Debug, Serialize)]
struct TelemetryResult {
    schema: &'static str,
    file: &'static str,
    records: u64,
    durable_through_offset: u64,
    terminal_record_sha256: String,
    terminal_mono_ns: u64,
    file_sha256: String,
}

#[derive(Debug, Serialize)]
struct GenerationManifest {
    schema: &'static str,
    implementation: &'static str,
    session_id: String,
    generation_index: u64,
    status: &'static str,
    symbol: String,
    duration_requested_s: u64,
    segment_duration_s: u64,
    started_wall_ns: u64,
    finished_wall_ns: u64,
    collector_executable_sha256: String,
    public_config_sha256: String,
    market_freshness_startup_grace_s: u64,
    market_freshness_deadline_s: u64,
    credentials: &'static str,
    order_entry: &'static str,
    raw_boundary: &'static str,
    spec_revision: &'static str,
    startup_file: &'static str,
    startup_sha256: String,
    failure: Option<String>,
    snapshot: Option<SnapshotResult>,
    telemetry: TelemetryResult,
    streams: Vec<StreamResult>,
}

#[derive(Debug, Serialize)]
struct TelemetryRecord {
    schema: &'static str,
    record_index: u64,
    wall_ns: u64,
    mono_ns: u64,
    clock: ClockMetadata,
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

fn validate_telemetry_record(record: &TelemetryRecord) -> Result<()> {
    for (stream, received, written, durable, socket, market, last_durable) in [
        (
            "depth",
            record.depth_received,
            record.depth_written,
            record.depth_durable,
            record.depth_last_socket_activity_mono_ns,
            record.depth_last_market_message_mono_ns,
            record.depth_last_durable_mono_ns,
        ),
        (
            "trade",
            record.trade_received,
            record.trade_written,
            record.trade_durable,
            record.trade_last_socket_activity_mono_ns,
            record.trade_last_market_message_mono_ns,
            record.trade_last_durable_mono_ns,
        ),
    ] {
        if durable > written || written > received {
            return Err(format!(
                "telemetry {stream} causal count invariant failed: durable={durable}, written={written}, received={received}"
            ));
        }
        if market > socket || socket > record.mono_ns || last_durable > record.mono_ns {
            return Err(format!(
                "telemetry {stream} causal time invariant failed: market={market}, socket={socket}, last_durable={last_durable}, observation={}",
                record.mono_ns
            ));
        }
    }
    Ok(())
}

struct WriterResult {
    name: String,
    written: u64,
    durable_records: u64,
    segments: u64,
    manifest_digest: String,
    terminal_raw_digest: String,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct DurableSegmentEvent {
    schema: &'static str,
    stream: String,
    connection_epoch: String,
    segment_index: u64,
    raw_file: String,
    first_frame_index: u64,
    last_frame_index: u64,
    records: u64,
    durable_through_offset: u64,
    previous_segment_terminal_sha256: String,
    terminal_record_sha256: String,
    manifest_record_index: u64,
    manifest_durable_through_offset: u64,
    manifest_record_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
struct DurableServerShutdownEvent {
    schema: &'static str,
    stream: String,
    connection_epoch: String,
    segment_index: u64,
    raw_file: String,
    frame_index: u64,
    receive_mono_ns: u64,
    durable_record_count: u64,
    durable_through_offset: u64,
    last_record_sha256: String,
}

#[derive(Clone, Debug)]
enum DurableWriterEvent {
    Segment(DurableSegmentEvent),
    ServerShutdown(DurableServerShutdownEvent),
}

#[derive(Serialize)]
struct CaptureProcessEvent<'a> {
    schema: &'static str,
    event: &'static str,
    session_id: &'a str,
    session_dir: &'a str,
    generation_index: u64,
    symbol: &'a str,
    process_id: u32,
    spec_revision: &'static str,
    startup_manifest_sha256: &'a str,
}

#[derive(Serialize)]
struct SnapshotDurableEvent<'a> {
    schema: &'static str,
    event: &'static str,
    session_id: &'a str,
    raw_file: &'a str,
    durable_through_offset: u64,
    last_record_sha256: &'a str,
    http_metadata_file: &'a str,
    http_metadata_sha256: &'a str,
}

#[derive(Serialize)]
struct SegmentDurableProcessEvent<'a> {
    schema: &'static str,
    event: &'static str,
    session_id: &'a str,
    segment: &'a DurableSegmentEvent,
}

#[derive(Serialize)]
struct ServerShutdownDurableProcessEvent<'a> {
    schema: &'static str,
    event: &'static str,
    session_id: &'a str,
    shutdown: &'a DurableServerShutdownEvent,
}

#[derive(Serialize)]
struct CaptureTerminalEvent<'a> {
    schema: &'static str,
    event: &'static str,
    session_id: &'a str,
    status: &'static str,
    generation_manifest: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ConnectedInfo {
    stream: String,
    connection_epoch: String,
    uri: String,
    websocket_http_status: u16,
    local_endpoint: String,
    remote_endpoint: String,
    response_headers: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize)]
struct TransportMetadata<'a> {
    schema: &'static str,
    session_id: &'a str,
    generation_index: u64,
    symbol: &'a str,
    spec_revision: &'static str,
    connection: &'a ConnectedInfo,
}

#[derive(Clone, Debug)]
struct TransportArtifactReference {
    file: String,
    sha256: String,
}

#[derive(Serialize)]
struct TransportConnectedProcessEvent<'a> {
    schema: &'static str,
    event: &'static str,
    session_id: &'a str,
    metadata_file: &'a str,
    metadata_sha256: &'a str,
    connection: &'a ConnectedInfo,
}

#[derive(Serialize)]
struct HeartbeatProcessEvent<'a> {
    schema: &'static str,
    event: &'static str,
    session_id: &'a str,
    telemetry_record_index: u64,
    telemetry_record_sha256: &'a str,
    telemetry_durable_through_offset: u64,
    telemetry_mono_ns: u64,
    depth_received: u64,
    depth_durable: u64,
    depth_queue_records: u64,
    depth_last_socket_activity_mono_ns: u64,
    depth_last_market_message_mono_ns: u64,
    depth_last_durable_mono_ns: u64,
    trade_received: u64,
    trade_durable: u64,
    trade_queue_records: u64,
    trade_last_socket_activity_mono_ns: u64,
    trade_last_market_message_mono_ns: u64,
    trade_last_durable_mono_ns: u64,
}

struct DurableTelemetryPublication {
    record: TelemetryRecord,
    durable_through_offset: u64,
    record_sha256: String,
}

struct ProducerResult {
    name: String,
    uri: String,
    epoch: String,
    received: u64,
    transport_journal: Option<TransportJournalSealV1>,
    error: Option<String>,
}

fn unix_ns() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system time before epoch: {error}"))?
            .as_nanos(),
    )
    .map_err(|_| "wall clock nanoseconds overflow u64".to_owned())
}

fn elapsed_ns(origin: Instant) -> Result<u64> {
    u64::try_from(origin.elapsed().as_nanos())
        .map_err(|_| "monotonic nanoseconds overflow u64".to_owned())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    let digest = hash.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(output)
}

fn emit_event(value: &impl Serialize) -> Result<()> {
    if env::var_os("BINANCE_LOB_EVENT_STREAM").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return Ok(());
    }
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)
        .map_err(|error| format!("serialize process event: {error}"))?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|error| format!("flush process event: {error}"))
}

fn detect_clock_metadata(probe: &TrustedWindowsTimeProbe) -> Result<ClockMetadata> {
    #[cfg(windows)]
    {
        let output = probe.query_status()?;
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let source = text.lines().find_map(|line| {
                let (key, value) = line.trim().split_once(':')?;
                key.eq_ignore_ascii_case("Source")
                    .then(|| value.trim().to_owned())
            });
            let stratum = text.lines().find_map(|line| {
                let (key, value) = line.trim().split_once(':')?;
                key.eq_ignore_ascii_case("Stratum")
                    .then(|| value.split_whitespace().next()?.parse::<u8>().ok())?
            });
            let leap_indicator = text.lines().find_map(|line| {
                let (key, value) = line.trim().split_once(':')?;
                key.eq_ignore_ascii_case("Leap Indicator")
                    .then(|| value.split('(').next()?.trim().parse::<u8>().ok())?
            });
            let last_successful_sync = text.lines().find_map(|line| {
                let (key, value) = line.trim().split_once(':')?;
                key.eq_ignore_ascii_case("Last Successful Sync Time")
                    .then(|| value.trim().to_owned())
            });
            if let (Some(source), Some(1..=15), Some(0)) = (source, stratum, leap_indicator)
                && !source.to_ascii_lowercase().contains("local cmos")
            {
                return Ok(ClockMetadata {
                    quality: "HOST_CLOCK_SERVICE_LEAP0_NO_ONE_WAY_BOUND".to_owned(),
                    source: format!(
                        "Windows-w32time:{source};w32tm_sha256={}",
                        probe.executable_sha256()
                    ),
                    leap_indicator,
                    stratum,
                    last_successful_sync,
                });
            }
        }
        Ok(ClockMetadata {
            quality: "UNSYNCHRONIZED".to_owned(),
            source: format!(
                "Windows-w32time-unavailable-or-unsynchronized;w32tm_sha256={}",
                probe.executable_sha256()
            ),
            leap_indicator: None,
            stratum: None,
            last_successful_sync: None,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = probe;
        Ok(ClockMetadata {
            quality: "UNKNOWN".to_owned(),
            source: "system-clock-status-not-probed".to_owned(),
            leap_indicator: None,
            stratum: None,
            last_successful_sync: None,
        })
    }
}

fn update_max(target: &AtomicU64, value: u64) {
    let mut current = target.load(Ordering::Acquire);
    while value > current {
        match target.compare_exchange_weak(current, value, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

fn stream_uri(symbol: &str, stream: &str) -> String {
    let name = match stream {
        "depth" => format!("{}@depth@100ms", symbol.to_ascii_lowercase()),
        "trade" => format!("{}@trade", symbol.to_ascii_lowercase()),
        _ => unreachable!("validated stream"),
    };
    format!("{WS_BASE}/ws/{name}?timeUnit=MICROSECOND")
}

fn stream_name(symbol: &str, stream: &str) -> String {
    if stream == "depth" {
        format!("{}@depth@100ms", symbol.to_ascii_lowercase())
    } else {
        format!("{}@trade", symbol.to_ascii_lowercase())
    }
}

fn configure_socket(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) -> Result<(String, String)> {
    let tcp = match socket.get_mut() {
        MaybeTlsStream::Plain(tcp) => tcp,
        MaybeTlsStream::Rustls(tls) => &mut tls.sock,
        _ => return Err("unsupported WebSocket TLS stream".to_owned()),
    };
    tcp.set_nodelay(true)
        .and_then(|_| tcp.set_read_timeout(Some(SOCKET_POLL_TIMEOUT)))
        .and_then(|_| tcp.set_write_timeout(Some(SOCKET_POLL_TIMEOUT)))
        .map_err(|error| format!("configure WebSocket TCP deadlines: {error}"))?;
    let local = tcp
        .local_addr()
        .map_err(|error| format!("query WebSocket local endpoint: {error}"))?;
    let remote = tcp
        .peer_addr()
        .map_err(|error| format!("query WebSocket remote endpoint: {error}"))?;
    Ok((local.to_string(), remote.to_string()))
}

fn socket_tcp_stream(socket: &WebSocket<MaybeTlsStream<TcpStream>>) -> Result<&TcpStream> {
    match socket.get_ref() {
        MaybeTlsStream::Plain(tcp) => Ok(tcp),
        MaybeTlsStream::Rustls(tls) => Ok(&tls.sock),
        _ => Err("unsupported WebSocket TLS stream".to_owned()),
    }
}

#[cfg(windows)]
fn tcp_sample(socket: &WebSocket<MaybeTlsStream<TcpStream>>) -> Value {
    match socket_tcp_stream(socket).and_then(sample_tcp_info_v0) {
        Ok(sample) => serde_json::json!({"status":"AVAILABLE","sample":sample}),
        Err(error) => serde_json::json!({"status":"UNAVAILABLE","error":error}),
    }
}

#[cfg(not(windows))]
fn tcp_sample(socket: &WebSocket<MaybeTlsStream<TcpStream>>) -> Value {
    let _ = socket_tcp_stream(socket);
    serde_json::json!({"status":"UNSUPPORTED_PLATFORM"})
}

fn diagnostic_dns_addresses() -> Result<Vec<String>> {
    let mut addresses = ("data-stream.binance.vision", 443)
        .to_socket_addrs()
        .map_err(|error| format!("diagnostic DNS resolution failed: {error}"))?
        .map(|address| address.to_string())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err("diagnostic DNS resolution returned no addresses".to_owned());
    }
    Ok(addresses)
}

fn append_transport_event(
    journal: &mut TransportJournalWriter,
    origin: Instant,
    event: &str,
    payload: Value,
) -> Result<String> {
    journal.append(unix_ns()?, elapsed_ns(origin)?, event, payload)
}

fn websocket_error_evidence(error: &WebSocketError) -> Value {
    match error {
        WebSocketError::Io(io) => serde_json::json!({
            "category":"IO",
            "io_kind":format!("{:?}", io.kind()),
            "native_os_error":io.raw_os_error(),
            "message":io.to_string()
        }),
        other => serde_json::json!({
            "category":format!("{:?}", other),
            "message":other.to_string()
        }),
    }
}

fn parse_capture_stop_request(
    bytes: &[u8],
    expected_session_id: &str,
) -> Result<SupervisorStopCause> {
    let request: CaptureStopRequestV1 = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid capture stop request JSON: {error}"))?;
    if request.schema != "CaptureStopRequestV1"
        || request.session_id != expected_session_id
        || request.reason.trim().is_empty()
        || request.campaign_failure_record_sha256.len() != 64
        || !request
            .campaign_failure_record_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("malformed or wrong-session stop request".to_owned());
    }
    let mut canonical = serde_json::to_vec(&request)
        .map_err(|error| format!("reserialize capture stop request: {error}"))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err("capture stop request is not exact canonical JSONL".to_owned());
    }
    Ok(SupervisorStopCause {
        source: "CAMPAIGN_STOP_REQUEST",
        reason: request.reason,
        campaign_failure_record_sha256: Some(request.campaign_failure_record_sha256),
    })
}

fn server_shutdown(payload: &[u8]) -> bool {
    serde_json::from_slice::<Value>(payload)
        .ok()
        .and_then(|value| value["e"].as_str().map(|event| event == "serverShutdown"))
        .unwrap_or(false)
}

fn valid_market_message(payload: &[u8], symbol: &str, stream: &str) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(payload) else {
        return false;
    };
    if value["s"].as_str() != Some(symbol) || value["E"].as_u64().is_none() {
        return false;
    }
    match stream {
        "depth" => {
            value["e"].as_str() == Some("depthUpdate")
                && value["U"].as_u64().is_some()
                && value["u"].as_u64().is_some()
                && value["b"].as_array().is_some()
                && value["a"].as_array().is_some()
        }
        "trade" => {
            value["e"].as_str() == Some("trade")
                && value["t"].as_u64().is_some()
                && value["T"].as_u64().is_some()
                && value["p"].as_str().is_some()
                && value["q"].as_str().is_some()
                && value["m"].as_bool().is_some()
                && value["M"].as_bool().is_some()
        }
        _ => false,
    }
}

/// Test-only fault directive that reproduces the observed silent market-data
/// black-hole: a remote flow stops delivering application traffic without any
/// FIN/RST, while the local process, its heartbeats and its socket-read loop
/// remain alive.  Absent from every non-injected environment.
///
/// `stream` is `depth` or `trade`; `after_mono_ns` is the generation-monotonic
/// instant from which that stream's receipts stop advancing every application
/// counter (received/queued/socket-activity/market-activity) exactly as if the
/// bytes had never arrived.  Control frames keep the read loop alive, which is
/// the faithful local approximation of a peer that went dark upstream while
/// TCP still appears established.
#[derive(Clone, Debug)]
struct FaultSilentStallSpec {
    stream: String,
    after_mono_ns: u64,
}

fn parse_fault_silent_stall(value: Option<&str>) -> Result<Option<FaultSilentStallSpec>> {
    let Some(value) = value else { return Ok(None) };
    let parts: Vec<&str> = value.split(':').map(str::trim).collect();
    if parts.len() != 2 {
        return Err(format!(
            "BINANCE_LOB_FAULT_SILENT_STALL must be <stream>:<after-s>; got {value:?}"
        ));
    }
    if !matches!(parts[0], "depth" | "trade") {
        return Err(format!(
            "BINANCE_LOB_FAULT_SILENT_STALL names an unknown stream: {:?}",
            parts[0]
        ));
    }
    let after_s = parts[1].parse::<u64>().map_err(|error| {
        format!("BINANCE_LOB_FAULT_SILENT_STALL after-s is not a bounded integer: {error}")
    })?;
    Ok(Some(FaultSilentStallSpec {
        stream: parts[0].to_owned(),
        after_mono_ns: after_s.saturating_mul(1_000_000_000),
    }))
}

#[allow(clippy::too_many_arguments)]
fn producer_loop(
    journal_root: PathBuf,
    symbol: String,
    stream: String,
    epoch: String,
    sender: SyncSender<CapturedFrame>,
    connected: mpsc::Sender<Result<ConnectedInfo>>,
    stop: Arc<AtomicBool>,
    supervisor_stop: Arc<RwLock<Option<SupervisorStopCause>>>,
    mono_origin: Instant,
    clock: Arc<RwLock<ClockMetadata>>,
    health: Arc<StreamHealth>,
    fault: Option<FaultSilentStallSpec>,
) -> ProducerResult {
    let uri = stream_uri(&symbol, &stream);
    let journal_path = journal_root.join(format!("transport-{stream}-events.jsonl"));
    let mut journal = match TransportJournalWriter::create(&journal_path, &stream, &epoch) {
        Ok(journal) => journal,
        Err(error) => {
            let _ = connected.send(Err(error.clone()));
            stop.store(true, Ordering::Release);
            return ProducerResult {
                name: stream,
                uri,
                epoch,
                received: health.received.load(Ordering::Acquire),
                transport_journal: None,
                error: Some(error),
            };
        }
    };
    let mut result: Result<()> = append_transport_event(
        &mut journal,
        mono_origin,
        "CONNECT_ATTEMPT",
        serde_json::json!({"uri":uri}),
    )
    .map(|_| ());
    if result.is_ok() {
        result = match diagnostic_dns_addresses() {
            Ok(addresses) => append_transport_event(
                &mut journal,
                mono_origin,
                "DNS_OBSERVED",
                serde_json::json!({
                    "host":"data-stream.binance.vision",
                    "port":443,
                    "addresses":addresses,
                    "role":"DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION"
                }),
            )
            .map(|_| ()),
            Err(error) => append_transport_event(
                &mut journal,
                mono_origin,
                "DNS_FAILED",
                serde_json::json!({
                    "host":"data-stream.binance.vision",
                    "port":443,
                    "error":error,
                    "role":"DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION"
                }),
            )
            .map(|_| ()),
        };
    }
    if result.is_ok() {
        result = (|| -> Result<()> {
            let (mut socket, response) = match connect(&uri) {
                Ok(connected_socket) => connected_socket,
                Err(error) => {
                    append_transport_event(
                        &mut journal,
                        mono_origin,
                        "CONNECT_FAILED",
                        serde_json::json!({"error":websocket_error_evidence(&error)}),
                    )?;
                    return Err(format!("connect {uri}: {error}"));
                }
            };
            if response.status().as_u16() != 101 {
                append_transport_event(
                    &mut journal,
                    mono_origin,
                    "WEBSOCKET_UPGRADE_REJECTED",
                    serde_json::json!({"http_status":response.status().as_u16()}),
                )?;
                return Err(format!(
                    "unexpected WebSocket HTTP status {}",
                    response.status()
                ));
            }
            let (local_endpoint, remote_endpoint) = configure_socket(&mut socket)?;
            let response_headers = response.headers().iter().fold(
                BTreeMap::<String, Vec<String>>::new(),
                |mut output, (name, value)| {
                    output
                        .entry(name.as_str().to_owned())
                        .or_default()
                        .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
                    output
                },
            );
            let supervisor_cause = supervisor_stop
                .read()
                .map_err(|_| "supervisor stop cause lock poisoned".to_owned())?
                .clone();
            if let Some(cause) = supervisor_cause {
                append_transport_event(
                    &mut journal,
                    mono_origin,
                    "SUPERVISOR_FAILURE_STOP",
                    serde_json::json!({
                        "campaign_failure_record_sha256":cause.campaign_failure_record_sha256,
                        "reason":cause.reason.clone(),
                        "source":cause.source,
                        "tcp_info":tcp_sample(&socket)
                    }),
                )?;
                return Err(format!("supervisor failure stop: {}", cause.reason));
            }
            append_transport_event(
                &mut journal,
                mono_origin,
                "WEBSOCKET_CONNECTED",
                serde_json::json!({
                    "websocket_http_status":response.status().as_u16(),
                    "local_endpoint":local_endpoint,
                    "remote_endpoint":remote_endpoint,
                    "tcp_info":tcp_sample(&socket)
                }),
            )?;
            connected
                .send(Ok(ConnectedInfo {
                    stream: stream.clone(),
                    connection_epoch: epoch.clone(),
                    uri: uri.clone(),
                    websocket_http_status: response.status().as_u16(),
                    local_endpoint,
                    remote_endpoint,
                    response_headers,
                }))
                .map_err(|error| format!("signal connected: {error}"))?;
            let mut last_transport = Instant::now();
            let mut stall_announced = false;
            let mut last_ping_sent: Option<Instant> = None;
            let mut awaiting_pong = false;
            while !stop.load(Ordering::Acquire) {
                let message = match socket.read() {
                    Ok(message) => {
                        last_transport = Instant::now();
                        message
                    }
                    Err(WebSocketError::Io(error))
                        if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                    {
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                        // Watchdog: a PING awaiting its PONG past the deadline
                        // means the transport is dead even though the socket is
                        // nominally open — type it precisely.
                        if awaiting_pong
                            && last_ping_sent.is_some_and(|sent| sent.elapsed() >= WS_PONG_DEADLINE)
                        {
                            append_transport_event(
                                &mut journal,
                                mono_origin,
                                "WATCHDOG_PONG_DEADLINE",
                                serde_json::json!({
                                    "deadline_ms":u64::try_from(WS_PONG_DEADLINE.as_millis()).unwrap_or(u64::MAX),
                                    "inactive_ms":u64::try_from(last_transport.elapsed().as_millis()).unwrap_or(u64::MAX),
                                    "tcp_info":tcp_sample(&socket)
                                }),
                            )?;
                            return Err(format!(
                                "transport watchdog pong deadline exceeded for {stream}: transport is dead"
                            ));
                        }
                        // Watchdog: schedule the next proactive PING.  Each
                        // PONG answer counts as transport activity, so a
                        // ponging-but-silent exchange is typed by the market-
                        // freshness layer instead of this deadline.
                        if !awaiting_pong
                            && last_ping_sent.is_none_or(|sent| sent.elapsed() >= WS_PING_INTERVAL)
                        {
                            socket
                                .send(Message::Ping(Vec::new().into()))
                                .map_err(|error| {
                                    format!("send watchdog ping for {stream}: {error}")
                                })?;
                            socket.flush().map_err(|error| {
                                format!("flush watchdog ping for {stream}: {error}")
                            })?;
                            append_transport_event(
                                &mut journal,
                                mono_origin,
                                "WATCHDOG_PING_SENT",
                                serde_json::json!({
                                    "interval_ms":u64::try_from(WS_PING_INTERVAL.as_millis()).unwrap_or(u64::MAX),
                                    "deadline_ms":u64::try_from(WS_PONG_DEADLINE.as_millis()).unwrap_or(u64::MAX)
                                }),
                            )?;
                            last_ping_sent = Some(Instant::now());
                            awaiting_pong = true;
                            continue;
                        }
                        let inactive_ms =
                            u64::try_from(last_transport.elapsed().as_millis()).unwrap_or(u64::MAX);
                        append_transport_event(
                            &mut journal,
                            mono_origin,
                            "READ_TIMEOUT",
                            serde_json::json!({
                                "inactive_ms":inactive_ms,
                                "io_kind":format!("{:?}", error.kind()),
                                "native_os_error":error.raw_os_error(),
                                "tcp_info":tcp_sample(&socket)
                            }),
                        )?;
                        if last_transport.elapsed() >= TRANSPORT_DEAD_AFTER {
                            append_transport_event(
                                &mut journal,
                                mono_origin,
                                "TRANSPORT_DEADLINE",
                                serde_json::json!({
                                    "deadline_ms":u64::try_from(TRANSPORT_DEAD_AFTER.as_millis()).unwrap_or(u64::MAX),
                                    "inactive_ms":inactive_ms,
                                    "tcp_info":tcp_sample(&socket)
                                }),
                            )?;
                            return Err(format!(
                                "transport liveness deadline exceeded for {stream}"
                            ));
                        }
                        continue;
                    }
                    Err(error) => {
                        append_transport_event(
                            &mut journal,
                            mono_origin,
                            "SOCKET_READ_ERROR",
                            serde_json::json!({
                                "error":websocket_error_evidence(&error),
                                "tcp_info":tcp_sample(&socket)
                            }),
                        )?;
                        return Err(format!("read {stream}: {error}"));
                    }
                };
                let receive_wall_ns = unix_ns()?;
                let receive_mono_ns = elapsed_ns(mono_origin)?;
                if stop.load(Ordering::Acquire) {
                    break;
                }
                if let Some(fault) = &fault
                    && elapsed_ns(mono_origin)? >= fault.after_mono_ns
                {
                    // Injected silent stall: the bytes are treated as never
                    // received. No counter advances and nothing is enqueued,
                    // reproducing the observed frozen
                    // last_market == last_socket signature with a live process.
                    if !stall_announced {
                        append_transport_event(
                            &mut journal,
                            mono_origin,
                            "FAULT_INJECTED_SILENT_STALL",
                            serde_json::json!({
                                "stream":fault.stream,
                                "after_mono_ns":fault.after_mono_ns
                            }),
                        )?;
                        stall_announced = true;
                    }
                    continue;
                }
                // One receipt timestamp is authoritative for a data message and
                // its enclosing socket activity. Control frames use the same
                // socket timestamp but never advance market freshness.
                health
                    .last_socket_activity_mono_ns
                    .store(receive_mono_ns, Ordering::Release);
                let payload = match message {
                    Message::Text(text) => text.as_str().as_bytes().to_vec(),
                    Message::Binary(binary) => binary.to_vec(),
                    Message::Close(close) => {
                        append_transport_event(
                            &mut journal,
                            mono_origin,
                            "WEBSOCKET_CLOSE",
                            serde_json::json!({
                                "close":close.as_ref().map(|frame| serde_json::json!({
                                    "code":format!("{:?}", frame.code),
                                    "reason":frame.reason.to_string()
                                })),
                                "tcp_info":tcp_sample(&socket)
                            }),
                        )?;
                        return Err(format!("server closed {stream}: {close:?}"));
                    }
                    Message::Ping(payload) => {
                        socket.flush().map_err(|error| {
                            format!("flush automatic pong for {stream}: {error}")
                        })?;
                        append_transport_event(
                            &mut journal,
                            mono_origin,
                            "WS_PING_PONG_FLUSHED",
                            serde_json::json!({
                                "payload_bytes":payload.len(),
                                "payload_sha256":sha256_hex(payload.as_ref())
                            }),
                        )?;
                        continue;
                    }
                    Message::Pong(payload) => {
                        let watchdog_rtt_ms = if awaiting_pong {
                            awaiting_pong = false;
                            last_ping_sent.map(|sent| {
                                u64::try_from(sent.elapsed().as_millis()).unwrap_or(u64::MAX)
                            })
                        } else {
                            None
                        };
                        append_transport_event(
                            &mut journal,
                            mono_origin,
                            "WS_PONG_RECEIVED",
                            serde_json::json!({
                                "payload_bytes":payload.len(),
                                "payload_sha256":sha256_hex(payload.as_ref()),
                                "watchdog_rtt_ms":watchdog_rtt_ms
                            }),
                        )?;
                        continue;
                    }
                    Message::Frame(_) => {
                        append_transport_event(
                            &mut journal,
                            mono_origin,
                            "UNEXPECTED_RAW_FRAME",
                            serde_json::json!({}),
                        )?;
                        continue;
                    }
                };
                if payload.len() > MAX_WS_PAYLOAD_BYTES {
                    return Err(format!(
                        "WebSocket payload exceeds bounded raw limit for {stream}"
                    ));
                }
                // Receipt is a fact before enqueue. Publishing it before the queue
                // handoff also guarantees that the writer cannot make written or
                // durable visible ahead of received.
                let frame_index = health.received.fetch_add(1, Ordering::AcqRel);
                let payload_bytes = payload.len() as u64;
                let clock_sample = clock
                    .read()
                    .map_err(|_| "clock metadata lock poisoned".to_owned())?
                    .clone();
                let frame = CapturedFrame {
                    venue: "binance-spot".to_owned(),
                    environment: "production-public-market-data".to_owned(),
                    endpoint: uri.clone(),
                    stream: stream_name(&symbol, &stream),
                    symbol: symbol.clone(),
                    connection_epoch: epoch.clone(),
                    frame_index,
                    receive_wall_ns,
                    receive_mono_ns,
                    clock_quality: clock_sample.quality,
                    clock_source: clock_sample.source,
                    payload,
                    spec_revision: SPEC_REVISION.to_owned(),
                };
                let queued_records = health.queue_records.fetch_add(1, Ordering::AcqRel) + 1;
                let queued_bytes = health
                    .queue_bytes
                    .fetch_add(payload_bytes, Ordering::AcqRel)
                    + payload_bytes;
                update_max(&health.max_queue_records, queued_records);
                update_max(&health.max_queue_bytes, queued_bytes);
                match sender.try_send(frame) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        health.queue_records.fetch_sub(1, Ordering::AcqRel);
                        health
                            .queue_bytes
                            .fetch_sub(payload_bytes, Ordering::AcqRel);
                        return Err(format!("bounded queue overflow: {stream}"));
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        health.queue_records.fetch_sub(1, Ordering::AcqRel);
                        health
                            .queue_bytes
                            .fetch_sub(payload_bytes, Ordering::AcqRel);
                        return Err(format!("writer disconnected: {stream}"));
                    }
                }
            }
            let supervisor_cause = supervisor_stop
                .read()
                .map_err(|_| "supervisor stop cause lock poisoned".to_owned())?
                .clone();
            if let Some(cause) = supervisor_cause {
                append_transport_event(
                    &mut journal,
                    mono_origin,
                    "SUPERVISOR_FAILURE_STOP",
                    serde_json::json!({
                        "campaign_failure_record_sha256":cause.campaign_failure_record_sha256,
                        "reason":cause.reason.clone(),
                        "source":cause.source,
                        "tcp_info":tcp_sample(&socket)
                    }),
                )?;
                return Err(format!("supervisor failure stop: {}", cause.reason));
            }
            append_transport_event(
                &mut journal,
                mono_origin,
                "CLIENT_STOP_OBSERVED",
                serde_json::json!({"tcp_info":tcp_sample(&socket)}),
            )?;
            if let Err(error) = socket.close(None)
                && !stop.load(Ordering::Acquire)
            {
                return Err(format!("close {stream}: {error}"));
            }
            Ok(())
        })();
    }
    let initial_error = result.as_ref().err().cloned();
    if let Some(error) = initial_error.as_ref()
        && let Err(journal_error) = append_transport_event(
            &mut journal,
            mono_origin,
            "PRODUCER_FAILURE",
            serde_json::json!({"error":error,"stage":"PRODUCER_LOOP"}),
        )
    {
        result = Err(format!(
            "{error}; persist exact producer failure: {journal_error}"
        ));
    }
    let terminal_error = result.as_ref().err().cloned();
    if let Err(journal_error) = append_transport_event(
        &mut journal,
        mono_origin,
        "TRANSPORT_TERMINAL",
        serde_json::json!({
            "status":if result.is_ok() { "STOPPED" } else { "FAILED" },
            "error":terminal_error,
            "received":health.received.load(Ordering::Acquire)
        }),
    ) {
        result = Err(match result {
            Ok(()) => format!("persist transport terminal: {journal_error}"),
            Err(error) => format!("{error}; persist transport terminal: {journal_error}"),
        });
    }
    let transport_journal = match journal.seal() {
        Ok(seal) => Some(seal),
        Err(journal_error) => {
            result = Err(match result {
                Ok(()) => format!("seal transport journal: {journal_error}"),
                Err(error) => format!("{error}; seal transport journal: {journal_error}"),
            });
            None
        }
    };
    if let Err(error) = &result {
        let _ = connected.send(Err(error.clone()));
        stop.store(true, Ordering::Release);
    }
    ProducerResult {
        name: stream,
        uri,
        epoch,
        received: health.received.load(Ordering::Acquire),
        transport_journal,
        error: result.err(),
    }
}

fn append_progress(
    progress: &mut DurabilityProgressWriter,
    latest: &mut Option<DurabilityAckV1>,
    ack: DurabilityAckV1,
    health: &StreamHealth,
    mono_origin: Instant,
) -> Result<()> {
    if latest.as_ref() != Some(&ack) {
        progress.append(ack.clone())?;
        health.durable.store(
            ack.streams[0].durable_through_frame_index + 1,
            Ordering::Release,
        );
        health
            .last_durable_mono_ns
            .store(elapsed_ns(mono_origin)?, Ordering::Release);
        *latest = Some(ack);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finalize_segment(
    raw_path: &Path,
    raw_file: &str,
    genesis: &RawSegmentGenesisV1,
    mut writer: RawLogWriter,
    mut progress: DurabilityProgressWriter,
    latest: &mut Option<DurabilityAckV1>,
    manifest: &mut RawSegmentManifestWriter,
    health: &StreamHealth,
    mono_origin: Instant,
) -> Result<(
    lob_replay::RawSegmentSealV1,
    lob_replay::segment_chain::RawSegmentManifestAckV1,
)> {
    let sync_started = Instant::now();
    let ack = writer.sync()?;
    let sync_duration = u64::try_from(sync_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    health
        .last_sync_duration_ns
        .store(sync_duration, Ordering::Release);
    update_max(&health.max_sync_duration_ns, sync_duration);
    append_progress(&mut progress, latest, ack.clone(), health, mono_origin)?;
    drop(writer);
    drop(progress);
    let verified = verify_and_seal_raw_segment(raw_path, raw_file, genesis, &ack)?;
    let manifest_ack = manifest.append_verified(&verified)?;
    Ok((verified.seal().clone(), manifest_ack))
}

#[allow(clippy::too_many_arguments)]
fn writer_loop(
    root: PathBuf,
    symbol: String,
    stream: String,
    epoch: String,
    segment_duration: Duration,
    receiver: Receiver<CapturedFrame>,
    stop: Arc<AtomicBool>,
    health: Arc<StreamHealth>,
    mono_origin: Instant,
    event_sender: mpsc::Sender<DurableWriterEvent>,
) -> WriterResult {
    let result = (|| -> Result<(u64, u64, String, String, Option<String>)> {
        let directory = root.join(&stream);
        fs::create_dir(&directory)
            .map_err(|error| format!("create stream directory {}: {error}", directory.display()))?;
        let manifest_path = directory.join("segments.bnseg");
        let mut manifest = RawSegmentManifestWriter::create(&manifest_path)?;
        let mut genesis = root_segment_genesis(&epoch, &stream_name(&symbol, &stream))?;
        let segment_ns = u64::try_from(segment_duration.as_nanos())
            .map_err(|_| "segment duration nanoseconds overflow".to_owned())?;
        let mut segment_index = 0_u64;
        let mut raw_file = segment_file(segment_index);
        let mut raw_path = directory.join(&raw_file);
        let mut writer = RawLogWriter::create_segment(&raw_path, GROUP_SYNC_RECORDS, &genesis)?;
        let mut progress = DurabilityProgressWriter::create_with_reference(
            &directory.join(progress_file(segment_index)),
            &raw_path,
            &raw_file,
        )?;
        let mut latest_ack = None;
        let mut pending = false;
        let mut last_sync = Instant::now();
        let mut segments = 0_u64;
        let mut written = 0_u64;
        let terminal_error = None;
        loop {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(frame) => {
                    health.queue_records.fetch_sub(1, Ordering::AcqRel);
                    health
                        .queue_bytes
                        .fetch_sub(frame.payload.len() as u64, Ordering::AcqRel);
                    let queue_age = elapsed_ns(mono_origin)?.saturating_sub(frame.receive_mono_ns);
                    update_max(&health.max_queue_age_ns, queue_age);
                    let desired = frame.receive_mono_ns / segment_ns;
                    if desired > segment_index {
                        if desired != segment_index + 1 || !pending && latest_ack.is_none() {
                            return Err(
                                "segment boundary skipped or empty segment observed".to_owned()
                            );
                        }
                        let (seal, manifest_ack) = finalize_segment(
                            &raw_path,
                            &raw_file,
                            &genesis,
                            writer,
                            progress,
                            &mut latest_ack,
                            &mut manifest,
                            &health,
                            mono_origin,
                        )?;
                        event_sender
                            .send(DurableWriterEvent::Segment(DurableSegmentEvent {
                                schema: "DurableSegmentEventV1",
                                stream: stream.clone(),
                                connection_epoch: seal.connection_epoch.clone(),
                                segment_index: seal.segment_index,
                                raw_file: seal.raw_file.clone(),
                                first_frame_index: seal.first_frame_index,
                                last_frame_index: seal.last_frame_index,
                                records: seal.records,
                                durable_through_offset: seal.durable_through_offset,
                                previous_segment_terminal_sha256: seal
                                    .previous_segment_terminal_sha256
                                    .clone(),
                                terminal_record_sha256: seal.terminal_record_sha256.clone(),
                                manifest_record_index: manifest_ack.record_index,
                                manifest_durable_through_offset: manifest_ack
                                    .durable_through_offset,
                                manifest_record_sha256: manifest_ack.record_sha256,
                            }))
                            .map_err(|error| format!("publish durable segment event: {error}"))?;
                        segments += 1;
                        genesis = successor_segment_genesis(&seal)?;
                        segment_index = genesis.segment_index;
                        health.segment_index.store(segment_index, Ordering::Release);
                        raw_file = segment_file(segment_index);
                        raw_path = directory.join(&raw_file);
                        writer =
                            RawLogWriter::create_segment(&raw_path, GROUP_SYNC_RECORDS, &genesis)?;
                        progress = DurabilityProgressWriter::create_with_reference(
                            &directory.join(progress_file(segment_index)),
                            &raw_path,
                            &raw_file,
                        )?;
                        latest_ack = None;
                        last_sync = Instant::now();
                    }
                    let append_started = Instant::now();
                    let receipt = writer.append(&frame)?;
                    // Interpret only after the immutable raw record write has
                    // completed. A shutdown event then forces an immediate
                    // durability ACK before it can be published to the parent.
                    let shutdown = server_shutdown(&frame.payload);
                    let market_message = valid_market_message(&frame.payload, &symbol, &stream);
                    let append_duration =
                        u64::try_from(append_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                    pending = true;
                    written += 1;
                    health.written.store(written, Ordering::Release);
                    if market_message {
                        health
                            .last_market_message_mono_ns
                            .store(frame.receive_mono_ns, Ordering::Release);
                    }
                    if let Some(ack) = receipt.durability_ack {
                        append_progress(&mut progress, &mut latest_ack, ack, &health, mono_origin)?;
                        health
                            .last_sync_duration_ns
                            .store(append_duration, Ordering::Release);
                        update_max(&health.max_sync_duration_ns, append_duration);
                        pending = false;
                        last_sync = Instant::now();
                    }
                    if shutdown {
                        if pending {
                            let sync_started = Instant::now();
                            let ack = writer.sync()?;
                            let sync_duration = u64::try_from(sync_started.elapsed().as_nanos())
                                .unwrap_or(u64::MAX);
                            append_progress(
                                &mut progress,
                                &mut latest_ack,
                                ack,
                                &health,
                                mono_origin,
                            )?;
                            health
                                .last_sync_duration_ns
                                .store(sync_duration, Ordering::Release);
                            update_max(&health.max_sync_duration_ns, sync_duration);
                            pending = false;
                            last_sync = Instant::now();
                        }
                        let ack = latest_ack.as_ref().ok_or_else(|| {
                            "serverShutdown lacks an exact durable ACK after forced sync".to_owned()
                        })?;
                        if ack.streams.len() != 1
                            || ack.streams[0].durable_through_frame_index != frame.frame_index
                        {
                            return Err("serverShutdown durable ACK does not end at its raw frame"
                                .to_owned());
                        }
                        event_sender
                            .send(DurableWriterEvent::ServerShutdown(
                                DurableServerShutdownEvent {
                                    schema: "DurableServerShutdownEventV1",
                                    stream: stream.clone(),
                                    connection_epoch: epoch.clone(),
                                    segment_index,
                                    raw_file: raw_file.clone(),
                                    frame_index: frame.frame_index,
                                    receive_mono_ns: frame.receive_mono_ns,
                                    durable_record_count: ack.durable_record_count,
                                    durable_through_offset: ack.durable_through_offset,
                                    last_record_sha256: ack.last_record_sha256.clone(),
                                },
                            ))
                            .map_err(|error| {
                                format!("publish durable serverShutdown event: {error}")
                            })?;
                        health.server_shutdown_events.fetch_add(1, Ordering::AcqRel);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if pending && last_sync.elapsed() >= WRITER_SYNC_MAX_AGE {
                        let sync_started = Instant::now();
                        let ack = writer.sync()?;
                        let sync_duration =
                            u64::try_from(sync_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                        append_progress(&mut progress, &mut latest_ack, ack, &health, mono_origin)?;
                        health
                            .last_sync_duration_ns
                            .store(sync_duration, Ordering::Release);
                        update_max(&health.max_sync_duration_ns, sync_duration);
                        pending = false;
                        last_sync = Instant::now();
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let terminal_digest = if pending || latest_ack.is_some() {
            let (seal, manifest_ack) = finalize_segment(
                &raw_path,
                &raw_file,
                &genesis,
                writer,
                progress,
                &mut latest_ack,
                &mut manifest,
                &health,
                mono_origin,
            )?;
            event_sender
                .send(DurableWriterEvent::Segment(DurableSegmentEvent {
                    schema: "DurableSegmentEventV1",
                    stream: stream.clone(),
                    connection_epoch: seal.connection_epoch.clone(),
                    segment_index: seal.segment_index,
                    raw_file: seal.raw_file.clone(),
                    first_frame_index: seal.first_frame_index,
                    last_frame_index: seal.last_frame_index,
                    records: seal.records,
                    durable_through_offset: seal.durable_through_offset,
                    previous_segment_terminal_sha256: seal.previous_segment_terminal_sha256.clone(),
                    terminal_record_sha256: seal.terminal_record_sha256.clone(),
                    manifest_record_index: manifest_ack.record_index,
                    manifest_durable_through_offset: manifest_ack.durable_through_offset,
                    manifest_record_sha256: manifest_ack.record_sha256,
                }))
                .map_err(|error| format!("publish terminal durable segment event: {error}"))?;
            segments += 1;
            seal.terminal_record_sha256
        } else {
            return Err("stream ended without a raw record".to_owned());
        };
        drop(manifest);
        let scan = scan_segment_manifest(&manifest_path)?;
        if !scan.clean_eof || scan.records != segments {
            return Err("terminal segment manifest verification failed".to_owned());
        }
        Ok((
            written,
            segments,
            scan.last_record_sha256,
            terminal_digest,
            terminal_error,
        ))
    })();
    if result.is_err() {
        stop.store(true, Ordering::Release);
    }
    match result {
        Ok((written, segments, manifest_digest, terminal_raw_digest, terminal_error)) => {
            WriterResult {
                name: stream,
                written,
                durable_records: health.durable.load(Ordering::Acquire),
                segments,
                manifest_digest,
                terminal_raw_digest,
                error: terminal_error,
            }
        }
        Err(error) => WriterResult {
            name: stream,
            written: health.written.load(Ordering::Acquire),
            durable_records: health.durable.load(Ordering::Acquire),
            segments: health.segment_index.load(Ordering::Acquire),
            manifest_digest: String::new(),
            terminal_raw_digest: String::new(),
            error: Some(error),
        },
    }
}

fn segment_file(index: u64) -> String {
    format!("segment-{index:06}.bnraw")
}

fn progress_file(index: u64) -> String {
    format!("segment-{index:06}.bnack")
}

fn write_synced_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

fn transport_metadata_file(stream: &str) -> Result<&'static str> {
    match stream {
        "depth" => Ok("transport-depth.json"),
        "trade" => Ok("transport-trade.json"),
        _ => Err(format!("transport metadata has invalid stream {stream}")),
    }
}

fn persist_transport_metadata(
    session: &Path,
    session_id: &str,
    generation_index: u64,
    symbol: &str,
    connection: &ConnectedInfo,
) -> Result<TransportArtifactReference> {
    let file = transport_metadata_file(&connection.stream)?;
    let metadata = TransportMetadata {
        schema: "TransportMetadataV1",
        session_id,
        generation_index,
        symbol,
        spec_revision: SPEC_REVISION,
        connection,
    };
    let mut bytes = serde_json::to_vec_pretty(&metadata)
        .map_err(|error| format!("serialize {file}: {error}"))?;
    bytes.push(b'\n');
    write_synced_new(&session.join(file), &bytes)?;
    Ok(TransportArtifactReference {
        file: file.to_owned(),
        sha256: sha256_hex(&bytes),
    })
}

fn fetch_snapshot(
    symbol: &str,
    session: &Path,
    mono_origin: Instant,
    clock: &ClockMetadata,
) -> Result<SnapshotResult> {
    let endpoint = format!("{REST_BASE}/api/v3/depth?symbol={symbol}&limit=5000");
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .user_agent("binance-lob-rust-segmented/0.1")
        .build()
        .map_err(|error| format!("build REST client: {error}"))?;
    let mut response = client
        .get(&endpoint)
        .send()
        .map_err(|error| format!("snapshot request: {error}"))?;
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SNAPSHOT_BYTES)
    {
        return Err("snapshot Content-Length exceeds bounded raw limit".to_owned());
    }
    let headers = response.headers().iter().fold(
        BTreeMap::<String, Vec<String>>::new(),
        |mut output, (name, value)| {
            output
                .entry(name.as_str().to_owned())
                .or_default()
                .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
            output
        },
    );
    let mut payload = Vec::new();
    Read::by_ref(&mut response)
        .take(MAX_SNAPSHOT_BYTES + 1)
        .read_to_end(&mut payload)
        .map_err(|error| format!("read snapshot body: {error}"))?;
    let receive_wall_ns = unix_ns()?;
    let receive_mono_ns = elapsed_ns(mono_origin)?;
    if payload.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err("snapshot body exceeds bounded raw limit".to_owned());
    }
    let path = session.join("snapshot.bnraw");
    let mut writer = RawLogWriter::create(&path, 1)?;
    writer.append(&CapturedFrame {
        venue: "binance-spot".to_owned(),
        environment: "production-public-market-data".to_owned(),
        endpoint: endpoint.clone(),
        stream: format!("{}@rest-depth-snapshot", symbol.to_ascii_lowercase()),
        symbol: symbol.to_owned(),
        connection_epoch: format!("snapshot-{}", Uuid::new_v4()),
        frame_index: 0,
        receive_wall_ns,
        receive_mono_ns,
        clock_quality: clock.quality.clone(),
        clock_source: clock.source.clone(),
        payload: payload.clone(),
        spec_revision: SPEC_REVISION.to_owned(),
    })?;
    let durability_ack = writer.sync()?;
    drop(writer);
    let body_sha256 = sha256_hex(&payload);
    let http_metadata = SnapshotHttpMetadata {
        schema: "SnapshotHttpMetadataV1",
        endpoint: &endpoint,
        http_status: status,
        headers,
        receive_wall_ns,
        receive_mono_ns,
        body_complete: true,
        body_length: payload.len(),
        body_sha256,
        raw_file: "snapshot.bnraw",
        raw_record_sha256: &durability_ack.last_record_sha256,
    };
    let http_metadata_bytes = serde_json::to_vec(&http_metadata)
        .map_err(|error| format!("serialize snapshot HTTP metadata: {error}"))?;
    write_synced_new(&session.join("snapshot-http.json"), &http_metadata_bytes)?;
    let http_metadata_sha256 = sha256_hex(&http_metadata_bytes);
    // Raw body and HTTP context are durable before any semantic JSON check.
    if status != 200 {
        return Err(format!("snapshot HTTP status {status}"));
    }
    let value: Value = serde_json::from_slice(&payload)
        .map_err(|error| format!("invalid snapshot JSON: {error}"))?;
    let last_update_id = value["lastUpdateId"]
        .as_u64()
        .ok_or_else(|| "invalid snapshot lastUpdateId".to_owned())?;
    let bids = value["bids"]
        .as_array()
        .ok_or_else(|| "invalid snapshot bids".to_owned())?;
    let asks = value["asks"]
        .as_array()
        .ok_or_else(|| "invalid snapshot asks".to_owned())?;
    Ok(SnapshotResult {
        endpoint,
        http_status: status,
        last_update_id,
        bid_levels: bids.len(),
        ask_levels: asks.len(),
        raw_file: "snapshot.bnraw".to_owned(),
        durability_ack,
        http_metadata_file: "snapshot-http.json".to_owned(),
        http_metadata_sha256,
    })
}

fn append_telemetry(
    file: &mut File,
    record_index: u64,
    origin: Instant,
    clock: &ClockMetadata,
    depth: &StreamHealth,
    trade: &StreamHealth,
) -> Result<DurableTelemetryPublication> {
    let depth = StreamHealthSnapshot::load(depth);
    let trade = StreamHealthSnapshot::load(trade);
    // `mono_ns` is the completion bound of this observation. Sampling it only
    // after every atomic field prevents a concurrent socket update from being
    // published as occurring in the future relative to its own heartbeat.
    let wall_ns = unix_ns()?;
    let mono_ns = elapsed_ns(origin)?;
    let record = TelemetryRecord {
        schema: "CaptureTelemetryV1",
        record_index,
        wall_ns,
        mono_ns,
        clock: clock.clone(),
        depth_received: depth.received,
        depth_written: depth.written,
        depth_durable: depth.durable,
        depth_segment: depth.segment_index,
        depth_last_socket_activity_mono_ns: depth.last_socket_activity_mono_ns,
        depth_last_market_message_mono_ns: depth.last_market_message_mono_ns,
        depth_last_durable_mono_ns: depth.last_durable_mono_ns,
        depth_queue_records: depth.queue_records,
        depth_queue_bytes: depth.queue_bytes,
        depth_max_queue_records: depth.max_queue_records,
        depth_max_queue_bytes: depth.max_queue_bytes,
        depth_max_queue_age_ns: depth.max_queue_age_ns,
        depth_last_sync_duration_ns: depth.last_sync_duration_ns,
        depth_max_sync_duration_ns: depth.max_sync_duration_ns,
        trade_received: trade.received,
        trade_written: trade.written,
        trade_durable: trade.durable,
        trade_segment: trade.segment_index,
        trade_last_socket_activity_mono_ns: trade.last_socket_activity_mono_ns,
        trade_last_market_message_mono_ns: trade.last_market_message_mono_ns,
        trade_last_durable_mono_ns: trade.last_durable_mono_ns,
        trade_queue_records: trade.queue_records,
        trade_queue_bytes: trade.queue_bytes,
        trade_max_queue_records: trade.max_queue_records,
        trade_max_queue_bytes: trade.max_queue_bytes,
        trade_max_queue_age_ns: trade.max_queue_age_ns,
        trade_last_sync_duration_ns: trade.last_sync_duration_ns,
        trade_max_sync_duration_ns: trade.max_sync_duration_ns,
    };
    validate_telemetry_record(&record)?;
    let mut bytes = serde_json::to_vec(&record)
        .map_err(|error| format!("serialize capture telemetry: {error}"))?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_data())
        .map_err(|error| format!("sync capture telemetry: {error}"))?;
    let durable_through_offset = file
        .stream_position()
        .map_err(|error| format!("query durable telemetry offset: {error}"))?;
    Ok(DurableTelemetryPublication {
        record,
        durable_through_offset,
        record_sha256: sha256_hex(&bytes),
    })
}

fn heartbeat_event<'a>(
    session_id: &'a str,
    publication: &'a DurableTelemetryPublication,
) -> HeartbeatProcessEvent<'a> {
    let record = &publication.record;
    HeartbeatProcessEvent {
        schema: "HeartbeatProcessEventV1",
        event: "HEARTBEAT_DURABLE",
        session_id,
        telemetry_record_index: record.record_index,
        telemetry_record_sha256: &publication.record_sha256,
        telemetry_durable_through_offset: publication.durable_through_offset,
        telemetry_mono_ns: record.mono_ns,
        depth_received: record.depth_received,
        depth_durable: record.depth_durable,
        depth_queue_records: record.depth_queue_records,
        depth_last_socket_activity_mono_ns: record.depth_last_socket_activity_mono_ns,
        depth_last_market_message_mono_ns: record.depth_last_market_message_mono_ns,
        depth_last_durable_mono_ns: record.depth_last_durable_mono_ns,
        trade_received: record.trade_received,
        trade_durable: record.trade_durable,
        trade_queue_records: record.trade_queue_records,
        trade_last_socket_activity_mono_ns: record.trade_last_socket_activity_mono_ns,
        trade_last_market_message_mono_ns: record.trade_last_market_message_mono_ns,
        trade_last_durable_mono_ns: record.trade_last_durable_mono_ns,
    }
}

fn emit_heartbeat(session_id: &str, publication: &DurableTelemetryPublication) -> Result<()> {
    emit_event(&heartbeat_event(session_id, publication))
}

fn drain_writer_events(receiver: &Receiver<DurableWriterEvent>, session_id: &str) -> Result<()> {
    for event in receiver.try_iter() {
        match event {
            DurableWriterEvent::Segment(segment) => {
                emit_event(&SegmentDurableProcessEvent {
                    schema: "SegmentDurableProcessEventV1",
                    event: "SEGMENT_DURABLE",
                    session_id,
                    segment: &segment,
                })?;
            }
            DurableWriterEvent::ServerShutdown(shutdown) => {
                emit_event(&ServerShutdownDurableProcessEvent {
                    schema: "ServerShutdownDurableProcessEventV1",
                    event: "SERVER_SHUTDOWN_DURABLE",
                    session_id,
                    shutdown: &shutdown,
                })?;
            }
        }
    }
    Ok(())
}

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

fn run() -> Result<PathBuf> {
    let mut args = env::args();
    let executable = args
        .next()
        .unwrap_or_else(|| "segmented_capture".to_owned());
    let symbol = args.next().ok_or_else(|| {
        format!(
            "usage: {executable} <BTCUSDT|ETHUSDT> <generation-index> <duration-s> <segment-s> [output]"
        )
    })?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err("symbol outside fixed scope".to_owned());
    }
    let generation_index = args
        .next()
        .ok_or_else(|| "missing generation-index".to_owned())?
        .parse::<u64>()
        .map_err(|error| format!("invalid generation-index: {error}"))?;
    let duration_s = parse_positive(args.next(), "duration-s", 86_300)?;
    let segment_s = parse_positive(args.next(), "segment-s", 3_600)?;
    if segment_s > duration_s {
        return Err("segment-s cannot exceed duration-s".to_owned());
    }
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/segmented-captures"));
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let current_executable =
        env::current_exe().map_err(|error| format!("resolve collector executable: {error}"))?;
    let collector_executable_sha256 = sha256_file(&current_executable)?;
    let public_config_path = Path::new("config/public.json");
    validate_public_capture_config(public_config_path)?;
    let public_config_sha256 = sha256_file(public_config_path)?;
    if let Some(expected) = env::var_os("BINANCE_LOB_EXPECTED_CAPTURE_SHA256")
        && expected.to_string_lossy() != collector_executable_sha256
    {
        return Err("collector executable differs from campaign source lock".to_owned());
    }
    if let Some(expected) = env::var_os("BINANCE_LOB_EXPECTED_PUBLIC_CONFIG_SHA256")
        && expected.to_string_lossy() != public_config_sha256
    {
        return Err("public config differs from campaign source lock".to_owned());
    }
    let clock_probe = TrustedWindowsTimeProbe::resolve()?;
    let stop_file = env::var_os("BINANCE_LOB_STOP_FILE").map(PathBuf::from);
    let fault_stall =
        parse_fault_silent_stall(env::var("BINANCE_LOB_FAULT_SILENT_STALL").ok().as_deref())?;
    let session_id = format!(
        "{}-{}-g{:03}-{}",
        unix_ns()?,
        symbol,
        generation_index,
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let session = output.join(&session_id);
    fs::create_dir_all(&session)
        .map_err(|error| format!("create session {}: {error}", session.display()))?;
    let session_display = session.display().to_string();
    let started_wall_ns = unix_ns()?;
    let origin = Instant::now();
    let startup = StartupManifest {
        schema: "RawGenerationStartupV1",
        implementation: "rust-segmented",
        session_id: session_id.clone(),
        generation_index,
        symbol: symbol.clone(),
        duration_requested_s: duration_s,
        segment_duration_s: segment_s,
        started_wall_ns,
        collector_executable_sha256: collector_executable_sha256.clone(),
        public_config_sha256: public_config_sha256.clone(),
        market_freshness_startup_grace_s: MARKET_FRESHNESS_STARTUP_GRACE_S,
        market_freshness_deadline_s: MARKET_FRESHNESS_DEADLINE_S,
        credentials: "NONE",
        order_entry: "ABSENT",
        raw_boundary: "WebSocket application messages after TLS/framing and before JSON interpretation",
        spec_revision: SPEC_REVISION,
    };
    let mut startup_bytes = serde_json::to_vec_pretty(&startup)
        .map_err(|error| format!("serialize generation startup: {error}"))?;
    startup_bytes.push(b'\n');
    write_synced_new(&session.join("startup.json"), &startup_bytes)?;
    let startup_manifest_sha256 = sha256_hex(&startup_bytes);
    emit_event(&CaptureProcessEvent {
        schema: "CaptureProcessEventV1",
        event: "PROCESS_STARTED",
        session_id: &session_id,
        session_dir: &session_display,
        generation_index,
        symbol: &symbol,
        process_id: std::process::id(),
        spec_revision: SPEC_REVISION,
        startup_manifest_sha256: &startup_manifest_sha256,
    })?;
    let initial_clock = detect_clock_metadata(&clock_probe)?;
    let shared_clock = Arc::new(RwLock::new(initial_clock.clone()));
    let stop = Arc::new(AtomicBool::new(false));
    let supervisor_stop = Arc::new(RwLock::new(None::<SupervisorStopCause>));
    let depth_health = Arc::new(StreamHealth::default());
    let trade_health = Arc::new(StreamHealth::default());
    let mut producers = Vec::new();
    let mut writers = Vec::new();
    let (connected_tx, connected_rx) = mpsc::channel();
    let (segment_event_tx, segment_event_rx) = mpsc::channel();
    for stream in ["depth", "trade"] {
        let epoch = format!("{}-{}", stream, Uuid::new_v4());
        let health = if stream == "depth" {
            Arc::clone(&depth_health)
        } else {
            Arc::clone(&trade_health)
        };
        let (tx, rx) = sync_channel(4096);
        let writer_root = session.clone();
        let writer_symbol = symbol.clone();
        let writer_stream = stream.to_owned();
        let writer_epoch = epoch.clone();
        let writer_stop = Arc::clone(&stop);
        let writer_health = Arc::clone(&health);
        let writer_events = segment_event_tx.clone();
        writers.push(thread::spawn(move || {
            writer_loop(
                writer_root,
                writer_symbol,
                writer_stream,
                writer_epoch,
                Duration::from_secs(segment_s),
                rx,
                writer_stop,
                writer_health,
                origin,
                writer_events,
            )
        }));
        let producer_symbol = symbol.clone();
        let producer_stream = stream.to_owned();
        let producer_journal_root = session.clone();
        let producer_stop = Arc::clone(&stop);
        let producer_supervisor_stop = Arc::clone(&supervisor_stop);
        let producer_health = Arc::clone(&health);
        let producer_connected = connected_tx.clone();
        let producer_clock = Arc::clone(&shared_clock);
        let producer_fault = fault_stall
            .as_ref()
            .filter(|spec| spec.stream == stream)
            .cloned();
        producers.push(thread::spawn(move || {
            producer_loop(
                producer_journal_root,
                producer_symbol,
                producer_stream,
                epoch,
                tx,
                producer_connected,
                producer_stop,
                producer_supervisor_stop,
                origin,
                producer_clock,
                producer_health,
                producer_fault,
            )
        }));
    }
    drop(connected_tx);
    drop(segment_event_tx);
    let mut startup_failure = None;
    let mut transport_artifacts = BTreeMap::<String, TransportArtifactReference>::new();
    for _ in 0..2 {
        match connected_rx.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok(connection)) => {
                if transport_artifacts.contains_key(&connection.stream) {
                    startup_failure = Some(format!(
                        "duplicate transport connection for {}",
                        connection.stream
                    ));
                    continue;
                }
                match persist_transport_metadata(
                    &session,
                    &session_id,
                    generation_index,
                    &symbol,
                    &connection,
                ) {
                    Ok(artifact) => {
                        emit_event(&TransportConnectedProcessEvent {
                            schema: "TransportConnectedProcessEventV1",
                            event: "TRANSPORT_CONNECTED",
                            session_id: &session_id,
                            metadata_file: &artifact.file,
                            metadata_sha256: &artifact.sha256,
                            connection: &connection,
                        })?;
                        transport_artifacts.insert(connection.stream.clone(), artifact);
                    }
                    Err(error) => startup_failure = Some(error),
                }
            }
            Ok(Err(error)) => startup_failure = Some(error),
            Err(error) => startup_failure = Some(format!("WebSocket connect timeout: {error}")),
        }
    }
    let snapshot = if startup_failure.is_none() {
        match fetch_snapshot(&symbol, &session, origin, &initial_clock) {
            Ok(snapshot) => {
                emit_event(&SnapshotDurableEvent {
                    schema: "SnapshotDurableProcessEventV1",
                    event: "SNAPSHOT_DURABLE",
                    session_id: &session_id,
                    raw_file: &snapshot.raw_file,
                    durable_through_offset: snapshot.durability_ack.durable_through_offset,
                    last_record_sha256: &snapshot.durability_ack.last_record_sha256,
                    http_metadata_file: &snapshot.http_metadata_file,
                    http_metadata_sha256: &snapshot.http_metadata_sha256,
                })?;
                Some(snapshot)
            }
            Err(error) => {
                startup_failure = Some(error);
                None
            }
        }
    } else {
        None
    };
    if startup_failure.is_some() {
        *supervisor_stop
            .write()
            .map_err(|_| "supervisor stop cause lock poisoned".to_owned())? =
            startup_failure.as_ref().map(|reason| SupervisorStopCause {
                source: "LOCAL_GENERATION_SUPERVISOR",
                reason: reason.clone(),
                campaign_failure_record_sha256: None,
            });
        stop.store(true, Ordering::Release);
    }
    let mut telemetry = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(session.join("telemetry.jsonl"))
        .map_err(|error| format!("create telemetry: {error}"))?;
    let deadline = origin + Duration::from_secs(duration_s);
    let mut telemetry_index = 0_u64;
    let mut next_telemetry = Instant::now();
    let mut next_clock_probe = Instant::now();
    let mut clock = initial_clock.clone();
    let mut runtime_failure = None;
    while Instant::now() < deadline && !stop.load(Ordering::Acquire) {
        let now = Instant::now();
        if let Some(path) = &stop_file
            && path.exists()
        {
            let request_bytes = fs::read(path)
                .map_err(|error| format!("read stop request {}: {error}", path.display()))?;
            match parse_capture_stop_request(&request_bytes, &session_id) {
                Err(error) => runtime_failure = Some(error),
                Ok(cause) => {
                    let reason = cause.reason.clone();
                    let failure_digest =
                        cause
                            .campaign_failure_record_sha256
                            .clone()
                            .ok_or_else(|| {
                                "campaign stop request lost its durable digest".to_owned()
                            })?;
                    *supervisor_stop
                        .write()
                        .map_err(|_| "supervisor stop cause lock poisoned".to_owned())? =
                        Some(cause);
                    runtime_failure = Some(format!(
                        "campaign failure stop: {} [journal {}]",
                        reason, failure_digest
                    ));
                }
            }
            break;
        }
        if now >= next_clock_probe {
            clock = match detect_clock_metadata(&clock_probe) {
                Ok(clock) => clock,
                Err(error) => {
                    runtime_failure = Some(format!("trusted Windows clock probe failed: {error}"));
                    *supervisor_stop
                        .write()
                        .map_err(|_| "supervisor stop cause lock poisoned".to_owned())? =
                        runtime_failure.as_ref().map(|reason| SupervisorStopCause {
                            source: "LOCAL_GENERATION_SUPERVISOR",
                            reason: reason.clone(),
                            campaign_failure_record_sha256: None,
                        });
                    break;
                }
            };
            *shared_clock
                .write()
                .map_err(|_| "clock metadata lock poisoned".to_owned())? = clock.clone();
            next_clock_probe = now + CLOCK_PROBE_PERIOD;
        }
        drain_writer_events(&segment_event_rx, &session_id)?;
        if now >= next_telemetry {
            let publication = append_telemetry(
                &mut telemetry,
                telemetry_index,
                origin,
                &clock,
                &depth_health,
                &trade_health,
            )?;
            emit_heartbeat(&session_id, &publication)?;
            telemetry_index = telemetry_index
                .checked_add(1)
                .ok_or_else(|| "telemetry record index overflow".to_owned())?;
            next_telemetry = now + TELEMETRY_PERIOD;
        }
        thread::sleep(SUPERVISOR_POLL.min(deadline.saturating_duration_since(now)));
    }
    if let Some(reason) = runtime_failure.as_ref() {
        let mut cause = supervisor_stop
            .write()
            .map_err(|_| "supervisor stop cause lock poisoned".to_owned())?;
        if cause.is_none() {
            *cause = Some(SupervisorStopCause {
                source: "LOCAL_GENERATION_SUPERVISOR",
                reason: reason.clone(),
                campaign_failure_record_sha256: None,
            });
        }
    }
    stop.store(true, Ordering::Release);
    let producer_results = producers
        .into_iter()
        .map(|handle| handle.join().map_err(|_| "producer panicked".to_owned()))
        .collect::<Result<Vec<_>>>()?;
    let writer_results = writers
        .into_iter()
        .map(|handle| handle.join().map_err(|_| "writer panicked".to_owned()))
        .collect::<Result<Vec<_>>>()?;
    drain_writer_events(&segment_event_rx, &session_id)?;
    let terminal_telemetry = append_telemetry(
        &mut telemetry,
        telemetry_index,
        origin,
        &clock,
        &depth_health,
        &trade_health,
    )?;
    emit_heartbeat(&session_id, &terminal_telemetry)?;
    let telemetry_records = terminal_telemetry
        .record
        .record_index
        .checked_add(1)
        .ok_or_else(|| "telemetry record count overflow".to_owned())?;
    drop(telemetry);
    let telemetry_bytes = fs::read(session.join("telemetry.jsonl"))
        .map_err(|error| format!("read terminal telemetry: {error}"))?;
    if u64::try_from(telemetry_bytes.len()).map_err(|_| "telemetry size overflow".to_owned())?
        != terminal_telemetry.durable_through_offset
    {
        return Err("terminal telemetry offset differs from file size".to_owned());
    }
    let telemetry_result = TelemetryResult {
        schema: "TelemetryArtifactV1",
        file: "telemetry.jsonl",
        records: telemetry_records,
        durable_through_offset: terminal_telemetry.durable_through_offset,
        terminal_record_sha256: terminal_telemetry.record_sha256.clone(),
        terminal_mono_ns: terminal_telemetry.record.mono_ns,
        file_sha256: sha256_hex(&telemetry_bytes),
    };
    let mut streams = Vec::new();
    let mut failure = startup_failure.or(runtime_failure);
    if failure.is_none()
        && (depth_health.queue_records.load(Ordering::Acquire) != 0
            || depth_health.queue_bytes.load(Ordering::Acquire) != 0
            || trade_health.queue_records.load(Ordering::Acquire) != 0
            || trade_health.queue_bytes.load(Ordering::Acquire) != 0)
    {
        failure = Some("terminal bounded queues are not empty".to_owned());
    }
    for producer in producer_results {
        let writer = writer_results
            .iter()
            .find(|writer| writer.name == producer.name)
            .ok_or_else(|| "missing stream writer result".to_owned())?;
        let transport = transport_artifacts.get(&producer.name);
        let stream_error = producer
            .error
            .clone()
            .or_else(|| writer.error.clone())
            .or_else(|| {
                transport
                    .is_none()
                    .then(|| format!("{} transport metadata is absent", producer.name))
            });
        if failure.is_none() {
            failure = stream_error.clone().or_else(|| {
                (producer.received != writer.written
                    || writer.written != writer.durable_records
                    || writer.segments == 0
                    || if producer.name == "depth" {
                        depth_health
                            .last_market_message_mono_ns
                            .load(Ordering::Acquire)
                            == 0
                    } else {
                        trade_health
                            .last_market_message_mono_ns
                            .load(Ordering::Acquire)
                            == 0
                    })
                .then(|| format!("{} terminal count/segment mismatch", producer.name))
            });
        }
        streams.push(StreamResult {
            name: producer.name.clone(),
            uri: producer.uri,
            connection_epoch: producer.epoch,
            transport_metadata_file: transport.map(|artifact| artifact.file.clone()),
            transport_metadata_sha256: transport.map(|artifact| artifact.sha256.clone()),
            transport_journal: producer.transport_journal.clone(),
            received: producer.received,
            written: writer.written,
            durable_records: writer.durable_records,
            segments: writer.segments,
            last_socket_activity_mono_ns: if producer.name == "depth" {
                depth_health
                    .last_socket_activity_mono_ns
                    .load(Ordering::Acquire)
            } else {
                trade_health
                    .last_socket_activity_mono_ns
                    .load(Ordering::Acquire)
            },
            last_market_message_mono_ns: if producer.name == "depth" {
                depth_health
                    .last_market_message_mono_ns
                    .load(Ordering::Acquire)
            } else {
                trade_health
                    .last_market_message_mono_ns
                    .load(Ordering::Acquire)
            },
            server_shutdown_events: if producer.name == "depth" {
                depth_health.server_shutdown_events.load(Ordering::Acquire)
            } else {
                trade_health.server_shutdown_events.load(Ordering::Acquire)
            },
            segment_manifest: format!("{}/segments.bnseg", producer.name),
            segment_manifest_sha256: writer.manifest_digest.clone(),
            terminal_raw_sha256: writer.terminal_raw_digest.clone(),
            error: stream_error,
        });
    }
    let manifest = GenerationManifest {
        schema: "RawGenerationManifestV1",
        implementation: "rust-segmented",
        session_id: session_id.clone(),
        generation_index,
        status: if failure.is_none() {
            "COMPLETE"
        } else {
            "FAILED"
        },
        symbol,
        duration_requested_s: duration_s,
        segment_duration_s: segment_s,
        started_wall_ns,
        finished_wall_ns: unix_ns()?,
        collector_executable_sha256,
        public_config_sha256,
        market_freshness_startup_grace_s: MARKET_FRESHNESS_STARTUP_GRACE_S,
        market_freshness_deadline_s: MARKET_FRESHNESS_DEADLINE_S,
        credentials: "NONE",
        order_entry: "ABSENT",
        raw_boundary: "WebSocket application messages after TLS/framing and before JSON interpretation",
        spec_revision: SPEC_REVISION,
        startup_file: "startup.json",
        startup_sha256: startup_manifest_sha256,
        failure: failure.clone(),
        snapshot,
        telemetry: telemetry_result,
        streams,
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize generation manifest: {error}"))?;
    bytes.push(b'\n');
    write_synced_new(&session.join("generation.json"), &bytes)?;
    emit_event(&CaptureTerminalEvent {
        schema: "CaptureTerminalProcessEventV1",
        event: "PROCESS_TERMINAL",
        session_id: &session_id,
        status: if failure.is_none() {
            "COMPLETE"
        } else {
            "FAILED"
        },
        generation_manifest: "generation.json",
    })?;
    if let Some(error) = failure {
        return Err(format!(
            "segmented capture failed: {error}; evidence at {}",
            session.display()
        ));
    }
    Ok(session)
}

fn main() {
    match run() {
        Ok(session) => {
            // Under the campaign protocol stdout is a machine-only JSONL
            // event stream.  The terminal PROCESS_TERMINAL event emitted by
            // `run` is the final record; a human-readable path here would be
            // an untyped extra message and make the evidence ambiguous.
            if env::var_os("BINANCE_LOB_EVENT_STREAM").as_deref() != Some(std::ffi::OsStr::new("1"))
            {
                println!("{}", session.display());
            }
        }
        Err(error) => {
            if env::var_os("BINANCE_LOB_EVENT_STREAM").as_deref() != Some(std::ffi::OsStr::new("1"))
            {
                eprintln!("segmented-capture: {error}");
            }
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClockMetadata, ConnectedInfo, DurableWriterEvent, StreamHealth, StreamHealthSnapshot,
        append_telemetry, elapsed_ns, heartbeat_event, parse_capture_stop_request,
        parse_fault_silent_stall, parse_positive, persist_transport_metadata, progress_file,
        segment_file, server_shutdown, sha256_hex, transport_metadata_file, valid_market_message,
        writer_loop,
    };
    use lob_replay::CapturedFrame;
    use lob_replay::durability_progress::scan_durability_progress;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    #[test]
    fn fault_silent_stall_directive_is_exact_and_bounded() {
        assert!(parse_fault_silent_stall(None).unwrap().is_none());
        let trade = parse_fault_silent_stall(Some("trade:20")).unwrap().unwrap();
        assert_eq!(trade.stream, "trade");
        assert_eq!(trade.after_mono_ns, 20_000_000_000);
        let depth = parse_fault_silent_stall(Some("depth:0")).unwrap().unwrap();
        assert_eq!(depth.stream, "depth");
        assert_eq!(depth.after_mono_ns, 0);
        assert!(parse_fault_silent_stall(Some("")).is_err());
        assert!(parse_fault_silent_stall(Some("unknown:5")).is_err());
        assert!(parse_fault_silent_stall(Some("trade:abc")).is_err());
        assert!(parse_fault_silent_stall(Some("trade")).is_err());
        assert!(parse_fault_silent_stall(Some("trade:1:2")).is_err());
    }

    #[test]
    fn arguments_and_names_are_bounded() {
        assert_eq!(
            parse_positive(Some("900".to_owned()), "segment", 3600),
            Ok(900)
        );
        assert!(parse_positive(Some("0".to_owned()), "segment", 3600).is_err());
        assert_eq!(segment_file(12), "segment-000012.bnraw");
        assert_eq!(progress_file(12), "segment-000012.bnack");
    }

    #[test]
    fn campaign_stop_request_is_exact_and_session_bound() {
        let digest = "a".repeat(64);
        let bytes = format!(
            "{{\"schema\":\"CaptureStopRequestV1\",\"session_id\":\"session\",\"reason\":\"market silence\",\"campaign_failure_record_sha256\":\"{digest}\"}}\n"
        );
        let cause = parse_capture_stop_request(bytes.as_bytes(), "session").unwrap();
        assert_eq!(cause.source, "CAMPAIGN_STOP_REQUEST");
        assert_eq!(cause.reason, "market silence");
        assert_eq!(
            cause.campaign_failure_record_sha256.as_deref(),
            Some(digest.as_str())
        );
        assert!(parse_capture_stop_request(bytes.as_bytes(), "other").is_err());
        let noncanonical = bytes.replace("\n", " \n");
        assert!(parse_capture_stop_request(noncanonical.as_bytes(), "session").is_err());
    }

    #[test]
    fn server_shutdown_detection_is_strict() {
        assert!(server_shutdown(br#"{"e":"serverShutdown","E":1}"#));
        assert!(!server_shutdown(br#"{"e":"depthUpdate"}"#));
        assert!(!server_shutdown(b"not-json"));
    }

    #[test]
    fn market_validation_never_treats_ping_or_server_shutdown_as_fresh_data() {
        assert!(valid_market_message(
            br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":1,"u":1,"b":[],"a":[]}"#,
            "BTCUSDT",
            "depth"
        ));
        assert!(!valid_market_message(
            br#"{"e":"serverShutdown","E":1}"#,
            "BTCUSDT",
            "depth"
        ));
        assert!(!valid_market_message(b"ping", "BTCUSDT", "depth"));
    }

    #[test]
    fn server_shutdown_is_acknowledged_before_action_and_does_not_stop_writer() {
        let directory = tempdir().unwrap();
        let (sender, receiver) = mpsc::sync_channel(8);
        let (events_tx, events_rx) = mpsc::channel();
        let health = Arc::new(StreamHealth::default());
        health
            .last_socket_activity_mono_ns
            .store(2, Ordering::Release);
        let common = |frame_index, receive_mono_ns, payload: &[u8]| CapturedFrame {
            venue: "binance-spot".to_owned(),
            environment: "production-public-market-data".to_owned(),
            endpoint:
                "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms?timeUnit=MICROSECOND"
                    .to_owned(),
            stream: "btcusdt@depth@100ms".to_owned(),
            symbol: "BTCUSDT".to_owned(),
            connection_epoch: "depth-epoch".to_owned(),
            frame_index,
            receive_wall_ns: 1 + frame_index,
            receive_mono_ns,
            clock_quality: "UNKNOWN".to_owned(),
            clock_source: "test".to_owned(),
            payload: payload.to_vec(),
            spec_revision: super::SPEC_REVISION.to_owned(),
        };
        sender
            .send(common(
                0,
                1,
                br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":1,"u":1,"b":[],"a":[]}"#,
            ))
            .unwrap();
        sender
            .send(common(1, 2, br#"{"e":"serverShutdown","E":2}"#))
            .unwrap();
        drop(sender);
        let result = writer_loop(
            directory.path().to_path_buf(),
            "BTCUSDT".to_owned(),
            "depth".to_owned(),
            "depth-epoch".to_owned(),
            Duration::from_secs(60),
            receiver,
            Arc::new(AtomicBool::new(false)),
            Arc::clone(&health),
            Instant::now(),
            events_tx,
        );
        assert!(result.error.is_none(), "{:?}", result.error);
        let events = events_rx.try_iter().collect::<Vec<_>>();
        let shutdown = match &events[0] {
            DurableWriterEvent::ServerShutdown(event) => event,
            other => panic!("first action was not durable serverShutdown: {other:?}"),
        };
        assert_eq!(shutdown.frame_index, 1);
        assert_eq!(shutdown.durable_record_count, 2);
        assert!(matches!(events[1], DurableWriterEvent::Segment(_)));
        let progress =
            scan_durability_progress(&directory.path().join("depth").join("segment-000000.bnack"))
                .unwrap();
        let ack = progress.latest_ack.unwrap();
        assert_eq!(ack.durable_through_offset, shutdown.durable_through_offset);
        assert_eq!(ack.last_record_sha256, shutdown.last_record_sha256);
        assert_eq!(health.server_shutdown_events.load(Ordering::Acquire), 1);
        assert_eq!(
            health.last_market_message_mono_ns.load(Ordering::Acquire),
            1
        );
        assert!(
            health.last_market_message_mono_ns.load(Ordering::Acquire)
                <= health.last_socket_activity_mono_ns.load(Ordering::Acquire)
        );
    }

    #[test]
    fn transport_metadata_is_durable_and_hash_bound_before_publication() {
        let directory = tempdir().unwrap();
        let connection = ConnectedInfo {
            stream: "depth".to_owned(),
            connection_epoch: "depth-epoch".to_owned(),
            uri: "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms?timeUnit=MICROSECOND"
                .to_owned(),
            websocket_http_status: 101,
            local_endpoint: "127.0.0.1:50000".to_owned(),
            remote_endpoint: "127.0.0.2:443".to_owned(),
            response_headers: BTreeMap::from([(
                "upgrade".to_owned(),
                vec!["websocket".to_owned()],
            )]),
        };
        let artifact =
            persist_transport_metadata(directory.path(), "session", 7, "BTCUSDT", &connection)
                .unwrap();
        assert_eq!(artifact.file, "transport-depth.json");
        let bytes = std::fs::read(directory.path().join(&artifact.file)).unwrap();
        assert_eq!(artifact.sha256, sha256_hex(&bytes));
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema"], "TransportMetadataV1");
        assert_eq!(value["connection"]["connection_epoch"], "depth-epoch");
        assert!(transport_metadata_file("unknown").is_err());
    }

    #[test]
    fn heartbeat_is_the_exact_synced_telemetry_record() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("telemetry.jsonl");
        let mut file = File::create(&path).unwrap();
        let depth = StreamHealth::default();
        let trade = StreamHealth::default();
        depth.received.store(11, Ordering::Release);
        depth.written.store(10, Ordering::Release);
        depth.durable.store(9, Ordering::Release);
        depth.queue_records.store(2, Ordering::Release);
        trade.received.store(5, Ordering::Release);
        trade.written.store(5, Ordering::Release);
        trade.durable.store(4, Ordering::Release);
        let publication = append_telemetry(
            &mut file,
            3,
            Instant::now(),
            &ClockMetadata {
                quality: "UNKNOWN".to_owned(),
                source: "test".to_owned(),
                leap_indicator: None,
                stratum: None,
                last_successful_sync: None,
            },
            &depth,
            &trade,
        )
        .unwrap();
        depth.received.store(99, Ordering::Release);
        let event = serde_json::to_value(heartbeat_event("session", &publication)).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(publication.durable_through_offset, bytes.len() as u64);
        assert_eq!(publication.record_sha256, sha256_hex(&bytes));
        assert_eq!(event["telemetry_record_index"], 3);
        assert_eq!(
            event["telemetry_durable_through_offset"],
            bytes.len() as u64
        );
        assert_eq!(event["telemetry_mono_ns"], publication.record.mono_ns);
        assert_eq!(event["depth_received"], 11);
        assert_eq!(event["depth_durable"], 9);
        assert_eq!(event["trade_received"], 5);
        assert_eq!(event["trade_durable"], 4);
    }

    #[test]
    fn impossible_concurrent_observation_is_never_persisted() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("telemetry.jsonl");
        let mut file = File::create(&path).unwrap();
        let depth = StreamHealth::default();
        let trade = StreamHealth::default();
        depth.received.store(1, Ordering::Release);
        depth.written.store(2, Ordering::Release);
        let error = append_telemetry(
            &mut file,
            0,
            Instant::now(),
            &ClockMetadata {
                quality: "UNKNOWN".to_owned(),
                source: "test".to_owned(),
                leap_indicator: None,
                stratum: None,
                last_successful_sync: None,
            },
            &depth,
            &trade,
        )
        .err()
        .expect("impossible telemetry must be rejected");
        assert!(error.contains("depth causal count invariant failed"));
        assert_eq!(std::fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn concurrent_health_snapshot_preserves_causal_bounds() {
        let origin = Instant::now();
        let health = Arc::new(StreamHealth::default());
        let stop = Arc::new(AtomicBool::new(false));

        let producer_health = Arc::clone(&health);
        let producer_stop = Arc::clone(&stop);
        let producer = std::thread::spawn(move || {
            while !producer_stop.load(Ordering::Acquire) {
                let receive_mono_ns = elapsed_ns(origin).unwrap();
                producer_health
                    .last_socket_activity_mono_ns
                    .store(receive_mono_ns, Ordering::Release);
                producer_health.received.fetch_add(1, Ordering::AcqRel);
            }
        });

        let writer_health = Arc::clone(&health);
        let writer_stop = Arc::clone(&stop);
        let writer = std::thread::spawn(move || {
            while !writer_stop.load(Ordering::Acquire) {
                let received = writer_health.received.load(Ordering::Acquire);
                writer_health.written.store(received, Ordering::Release);
                let socket = writer_health
                    .last_socket_activity_mono_ns
                    .load(Ordering::Acquire);
                writer_health
                    .last_market_message_mono_ns
                    .store(socket, Ordering::Release);
                writer_health.durable.store(received, Ordering::Release);
            }
        });

        for _ in 0..100_000 {
            let snapshot = StreamHealthSnapshot::load(&health);
            let completion_mono_ns = elapsed_ns(origin).unwrap();
            assert!(snapshot.durable <= snapshot.written);
            assert!(snapshot.written <= snapshot.received);
            assert!(snapshot.last_market_message_mono_ns <= snapshot.last_socket_activity_mono_ns);
            assert!(snapshot.last_socket_activity_mono_ns <= completion_mono_ns);
        }

        stop.store(true, Ordering::Release);
        producer.join().unwrap();
        writer.join().unwrap();
    }
}
