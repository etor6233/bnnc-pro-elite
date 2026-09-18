use lob_replay::durability_progress::{
    DurabilityProgressWriter, scan_durability_progress, verify_progress_against_raw,
};
#[cfg(windows)]
use lob_replay::windows_time::TrustedWindowsTimeProbe;
use lob_replay::{CapturedFrame, DurabilityAckV1, RawLogWriter, read_raw_log};
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, mpsc};
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
// proactive PING every 30 s keeps transport liveness honest — a server that
// answers PONGs but sends no market data is typed exchange-silent by the
// market-freshness layer, while a missing PONG within 5 s types the transport
// as DEAD.
const WS_PING_INTERVAL: Duration = Duration::from_secs(30);
const WS_PONG_DEADLINE: Duration = Duration::from_secs(5);
const SUPERVISOR_POLL: Duration = Duration::from_millis(50);

type Result<T> = std::result::Result<T, String>;

#[cfg(not(windows))]
struct TrustedWindowsTimeProbe;

#[cfg(not(windows))]
impl TrustedWindowsTimeProbe {
    fn resolve() -> Result<Self> {
        Ok(Self)
    }
}

#[derive(Serialize)]
struct StreamResult {
    name: String,
    uri: String,
    received: u64,
    written: u64,
    connection_epoch: String,
    raw_file: String,
    durability_progress_file: String,
    durability_ack: Option<DurabilityAckV1>,
    error: Option<String>,
}

#[derive(Serialize)]
struct SnapshotResult {
    endpoint: String,
    http_status: u16,
    last_update_id: u64,
    bid_levels: usize,
    ask_levels: usize,
    raw_file: &'static str,
    durability_ack: DurabilityAckV1,
}

#[derive(Serialize)]
struct Manifest {
    schema: &'static str,
    implementation: &'static str,
    session_id: String,
    status: &'static str,
    symbol: String,
    duration_requested_s: u64,
    credentials: &'static str,
    order_entry: &'static str,
    clock_quality: String,
    clock_source: String,
    spec_revision: &'static str,
    failure: Option<String>,
    snapshot: SnapshotResult,
    streams: Vec<StreamResult>,
}

#[derive(Clone, Debug)]
struct ClockMetadata {
    quality: String,
    source: String,
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
                if !key.eq_ignore_ascii_case("Stratum") {
                    return None;
                }
                value.split_whitespace().next()?.parse::<u8>().ok()
            });
            if let (Some(source), Some(1..=15)) = (source, stratum)
                && !source.to_ascii_lowercase().contains("local cmos")
            {
                return Ok(ClockMetadata {
                    quality: "SYNCHRONIZED".to_owned(),
                    source: format!(
                        "Windows-w32time:{source};w32tm_sha256={}",
                        probe.executable_sha256()
                    ),
                });
            }
        }
        Ok(ClockMetadata {
            quality: "UNSYNCHRONIZED".to_owned(),
            source: format!(
                "Windows-w32time-unavailable-or-unsynchronized;w32tm_sha256={}",
                probe.executable_sha256()
            ),
        })
    }
    #[cfg(not(windows))]
    {
        let _ = probe;
        Ok(ClockMetadata {
            quality: "UNKNOWN".to_owned(),
            source: "system-clock-status-not-probed".to_owned(),
        })
    }
}

struct WriterResult {
    written: u64,
    durability_ack: Option<DurabilityAckV1>,
    error: Option<String>,
    durability_progress_file: String,
}

struct ProducerResult {
    name: String,
    uri: String,
    received: u64,
    epoch: String,
    raw_file: String,
    error: Option<String>,
}

fn unix_ns() -> Result<u64> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system time before epoch: {error}"))?
        .as_nanos();
    u64::try_from(nanos).map_err(|_| "wall clock nanoseconds overflow u64".to_owned())
}

fn stream_uri(symbol: &str, stream: &str) -> String {
    let name = match stream {
        "depth" => format!("{}@depth@100ms", symbol.to_ascii_lowercase()),
        "trade" => format!("{}@trade", symbol.to_ascii_lowercase()),
        _ => unreachable!("validated stream"),
    };
    format!("{WS_BASE}/ws/{name}?timeUnit=MICROSECOND")
}

fn configure_socket(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) -> Result<()> {
    let tcp = match socket.get_mut() {
        MaybeTlsStream::Plain(tcp) => tcp,
        MaybeTlsStream::Rustls(tls) => &mut tls.sock,
        _ => return Err("unsupported WebSocket TLS stream".to_owned()),
    };
    tcp.set_nodelay(true)
        .and_then(|_| tcp.set_read_timeout(Some(SOCKET_POLL_TIMEOUT)))
        .and_then(|_| tcp.set_write_timeout(Some(SOCKET_POLL_TIMEOUT)))
        .map_err(|error| format!("configure WebSocket TCP deadlines: {error}"))
}

fn supervise_until(stop: &AtomicBool, deadline: Instant) {
    while Instant::now() < deadline && !stop.load(Ordering::Acquire) {
        thread::sleep(SUPERVISOR_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn writer_loop(
    path: PathBuf,
    progress_path: PathBuf,
    receiver: Receiver<CapturedFrame>,
    stop: Arc<AtomicBool>,
) -> WriterResult {
    let mut written = 0_u64;
    let mut durability_ack = None;
    let durability_progress_file = progress_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| progress_path.display().to_string());
    let result = (|| -> Result<()> {
        let mut writer = RawLogWriter::create(&path, 64)?;
        let mut progress = DurabilityProgressWriter::create(&progress_path, &path)?;
        for frame in receiver {
            let receipt = writer.append(&frame)?;
            if let Some(ack) = receipt.durability_ack {
                progress.append(ack)?;
            }
            written += 1;
        }
        let final_ack = writer.sync()?;
        if progress.latest_ack() != Some(&final_ack) {
            progress.append(final_ack.clone())?;
        }
        let scan = scan_durability_progress(&progress_path)?;
        let verified = verify_progress_against_raw(&scan, &path)?;
        if !scan.clean_eof || verified != final_ack {
            return Err("final durability progress does not match raw ACK".to_owned());
        }
        durability_ack = Some(final_ack);
        Ok(())
    })();
    if result.is_err() {
        stop.store(true, Ordering::Release);
    }
    WriterResult {
        written,
        durability_ack,
        error: result.err(),
        durability_progress_file,
    }
}

fn producer_loop(
    symbol: String,
    stream: String,
    sender: SyncSender<CapturedFrame>,
    connected: mpsc::Sender<Result<String>>,
    stop: Arc<AtomicBool>,
    mono_origin: Instant,
    clock: Arc<ClockMetadata>,
) -> ProducerResult {
    let uri = stream_uri(&symbol, &stream);
    let epoch = Uuid::new_v4().to_string();
    let raw_file = format!("{stream}.bnraw");
    let mut received = 0_u64;
    let result = (|| -> Result<()> {
        let (mut socket, response) =
            connect(&uri).map_err(|error| format!("connect {uri}: {error}"))?;
        if response.status().as_u16() != 101 {
            return Err(format!(
                "unexpected WebSocket HTTP status {}",
                response.status()
            ));
        }
        configure_socket(&mut socket)?;
        connected
            .send(Ok(stream.clone()))
            .map_err(|error| format!("signal connected: {error}"))?;
        let mut last_transport_activity = Instant::now();
        let mut last_ping_sent: Option<Instant> = None;
        let mut awaiting_pong = false;
        while !stop.load(Ordering::Acquire) {
            let message = match socket.read() {
                Ok(message) => {
                    last_transport_activity = Instant::now();
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
                        return Err(format!(
                            "transport watchdog pong deadline exceeded for {stream}: no PONG within {} seconds after ping — transport is dead",
                            WS_PONG_DEADLINE.as_secs()
                        ));
                    }
                    // Watchdog: schedule the next proactive PING.  Each PONG
                    // answer counts as transport activity, so a ponging-but-
                    // silent exchange is typed by the market-freshness layer
                    // instead of this deadline.
                    if !awaiting_pong
                        && last_ping_sent.is_none_or(|sent| sent.elapsed() >= WS_PING_INTERVAL)
                    {
                        socket
                            .send(Message::Ping(Vec::new().into()))
                            .map_err(|error| format!("send watchdog ping for {stream}: {error}"))?;
                        socket.flush().map_err(|error| {
                            format!("flush watchdog ping for {stream}: {error}")
                        })?;
                        last_ping_sent = Some(Instant::now());
                        awaiting_pong = true;
                        continue;
                    }
                    if last_transport_activity.elapsed() >= TRANSPORT_DEAD_AFTER {
                        return Err(format!(
                            "transport liveness deadline exceeded for {stream}: no WebSocket frame within {} seconds",
                            TRANSPORT_DEAD_AFTER.as_secs()
                        ));
                    }
                    continue;
                }
                Err(error) => return Err(format!("read {stream}: {error}")),
            };
            let payload = match message {
                Message::Text(text) => text.as_str().as_bytes().to_vec(),
                Message::Binary(binary) => binary.to_vec(),
                Message::Close(_) => return Err(format!("server closed {stream}")),
                Message::Ping(_) => {
                    // tungstenite queues the matching automatic pong on read;
                    // flush immediately instead of constructing a second pong.
                    socket
                        .flush()
                        .map_err(|error| format!("flush automatic pong for {stream}: {error}"))?;
                    continue;
                }
                Message::Pong(_) => {
                    if awaiting_pong {
                        awaiting_pong = false;
                    }
                    continue;
                }
                Message::Frame(_) => continue,
            };
            let frame = CapturedFrame {
                venue: "binance-spot".to_owned(),
                environment: "production-public-market-data".to_owned(),
                endpoint: uri.clone(),
                stream: if stream == "depth" {
                    format!("{}@depth@100ms", symbol.to_ascii_lowercase())
                } else {
                    format!("{}@trade", symbol.to_ascii_lowercase())
                },
                symbol: symbol.clone(),
                connection_epoch: epoch.clone(),
                frame_index: received,
                receive_wall_ns: unix_ns()?,
                receive_mono_ns: u64::try_from(mono_origin.elapsed().as_nanos())
                    .map_err(|_| "monotonic nanoseconds overflow u64".to_owned())?,
                clock_quality: clock.quality.clone(),
                clock_source: clock.source.clone(),
                payload,
                spec_revision: SPEC_REVISION.to_owned(),
            };
            match sender.try_send(frame) {
                Ok(()) => received += 1,
                Err(TrySendError::Full(_)) => {
                    return Err(format!("bounded queue overflow: {stream}"));
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(format!("writer disconnected: {stream}"));
                }
            }
        }
        if let Err(error) = socket.close(None)
            && !stop.load(Ordering::Acquire)
        {
            return Err(format!("close {stream}: {error}"));
        }
        Ok(())
    })();
    if let Err(error) = &result {
        let _ = connected.send(Err(error.clone()));
        stop.store(true, Ordering::Release);
    }
    ProducerResult {
        name: stream,
        uri,
        received,
        epoch,
        raw_file,
        error: result.err(),
    }
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
        .user_agent("binance-lob-rust/0.1")
        .build()
        .map_err(|error| format!("build REST client: {error}"))?;
    let response = client
        .get(&endpoint)
        .send()
        .map_err(|error| format!("snapshot request: {error}"))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(format!("snapshot HTTP status {status}"));
    }
    let payload = response
        .bytes()
        .map_err(|error| format!("read snapshot body: {error}"))?;
    if payload.len() > 16 * 1024 * 1024 {
        return Err("snapshot exceeds 16 MiB".to_owned());
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
    let mut writer = RawLogWriter::create(&session.join("snapshot.bnraw"), 1)?;
    writer.append(&CapturedFrame {
        venue: "binance-spot".to_owned(),
        environment: "production-public-market-data".to_owned(),
        endpoint: endpoint.clone(),
        stream: format!("{}@rest-depth-snapshot", symbol.to_ascii_lowercase()),
        symbol: symbol.to_owned(),
        connection_epoch: format!("snapshot-{}", Uuid::new_v4()),
        frame_index: 0,
        receive_wall_ns: unix_ns()?,
        receive_mono_ns: u64::try_from(mono_origin.elapsed().as_nanos())
            .map_err(|_| "monotonic nanoseconds overflow u64".to_owned())?,
        clock_quality: clock.quality.clone(),
        clock_source: clock.source.clone(),
        payload: payload.to_vec(),
        spec_revision: SPEC_REVISION.to_owned(),
    })?;
    let durability_ack = writer.sync()?;
    Ok(SnapshotResult {
        endpoint,
        http_status: status,
        last_update_id,
        bid_levels: bids.len(),
        ask_levels: asks.len(),
        raw_file: "snapshot.bnraw",
        durability_ack,
    })
}

fn run() -> Result<PathBuf> {
    let mut args = env::args();
    let executable = args.next().unwrap_or_else(|| "capture".to_owned());
    let symbol = args.next().ok_or_else(|| {
        format!("usage: {executable} <BTCUSDT|ETHUSDT> <duration-seconds> [output]")
    })?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err("symbol outside fixed scope".to_owned());
    }
    let duration_s: u64 = args
        .next()
        .ok_or_else(|| "missing duration".to_owned())?
        .parse()
        .map_err(|error| format!("invalid duration: {error}"))?;
    if duration_s == 0 || duration_s > 86_400 {
        return Err("duration must be within 1..=86400".to_owned());
    }
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/rust-captures"));
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system time: {error}"))?;
    let session_id = format!(
        "{}.{:09}Z-{}-rust-{}",
        now.as_secs(),
        now.subsec_nanos(),
        symbol,
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let session = output.join(&session_id);
    fs::create_dir_all(&session)
        .map_err(|error| format!("create session {}: {error}", session.display()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let clock_probe = TrustedWindowsTimeProbe::resolve()?;
    let clock = Arc::new(detect_clock_metadata(&clock_probe)?);
    let mono_origin = Instant::now();
    let (connected_tx, connected_rx) = mpsc::channel();
    let mut producer_handles = Vec::new();
    let mut writer_handles = Vec::new();
    for stream in ["depth", "trade"] {
        let raw_file = format!("{stream}.bnraw");
        let (tx, rx) = sync_channel(4096);
        let path = session.join(&raw_file);
        let progress_path = session.join(format!("{stream}.bnack"));
        let writer_stop = Arc::clone(&stop);
        writer_handles.push((
            stream.to_owned(),
            thread::spawn(move || writer_loop(path, progress_path, rx, writer_stop)),
        ));
        let producer_symbol = symbol.clone();
        let producer_stream = stream.to_owned();
        let producer_connected = connected_tx.clone();
        let producer_stop = Arc::clone(&stop);
        let producer_clock = Arc::clone(&clock);
        producer_handles.push(thread::spawn(move || {
            producer_loop(
                producer_symbol,
                producer_stream,
                tx,
                producer_connected,
                producer_stop,
                mono_origin,
                producer_clock,
            )
        }));
    }
    drop(connected_tx);
    for _ in 0..2 {
        connected_rx
            .recv_timeout(Duration::from_secs(20))
            .map_err(|error| format!("WebSocket connect timeout: {error}"))??;
    }
    let snapshot = fetch_snapshot(&symbol, &session, mono_origin, &clock)?;
    let deadline = Instant::now() + Duration::from_secs(duration_s);
    supervise_until(&stop, deadline);
    stop.store(true, Ordering::Release);
    let producers = producer_handles
        .into_iter()
        .map(|handle| handle.join().map_err(|_| "producer panicked".to_owned()))
        .collect::<Result<Vec<_>>>()?;
    let writers = writer_handles
        .into_iter()
        .map(|(name, handle)| {
            handle
                .join()
                .map(|result| (name, result))
                .map_err(|_| "writer panicked".to_owned())
        })
        .collect::<Result<Vec<_>>>()?;
    let mut streams = Vec::new();
    for producer in producers {
        let writer = writers
            .iter()
            .find(|(name, _)| name == &producer.name)
            .ok_or_else(|| "missing writer result".to_owned())?;
        let error = producer.error.or_else(|| writer.1.error.clone());
        streams.push(StreamResult {
            name: producer.name,
            uri: producer.uri,
            received: producer.received,
            written: writer.1.written,
            connection_epoch: producer.epoch,
            raw_file: producer.raw_file,
            durability_progress_file: writer.1.durability_progress_file.clone(),
            durability_ack: writer.1.durability_ack.clone(),
            error,
        });
    }
    let raw_failure = ["depth.bnraw", "trade.bnraw", "snapshot.bnraw"]
        .into_iter()
        .find_map(|file| {
            read_raw_log(&session.join(file))
                .err()
                .map(|error| format!("verify {file}: {error}"))
        });
    let stream_failure = streams.iter().find_map(|stream| {
        stream
            .error
            .clone()
            .or_else(|| {
                (stream.received != stream.written).then(|| {
                    format!(
                        "{} received/written mismatch: {}/{}",
                        stream.name, stream.received, stream.written
                    )
                })
            })
            .or_else(|| {
                stream
                    .durability_ack
                    .as_ref()
                    .is_none_or(|ack| ack.durable_record_count != stream.written)
                    .then(|| format!("{} terminal durability ACK mismatch", stream.name))
            })
    });
    let failure = stream_failure.or(raw_failure);
    let manifest = Manifest {
        schema: "CaptureManifestV1",
        implementation: "rust",
        session_id,
        status: if failure.is_none() {
            "COMPLETE"
        } else {
            "FAILED"
        },
        symbol,
        duration_requested_s: duration_s,
        credentials: "NONE",
        order_entry: "ABSENT",
        clock_quality: clock.quality.clone(),
        clock_source: clock.source.clone(),
        spec_revision: SPEC_REVISION,
        failure: failure.clone(),
        snapshot,
        streams,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize manifest: {error}"))?;
    fs::write(session.join("manifest.json"), manifest_bytes)
        .map_err(|error| format!("write manifest: {error}"))?;
    if let Some(error) = failure {
        return Err(format!(
            "capture stream failed: {error}; evidence at {}",
            session.display()
        ));
    }
    Ok(session)
}

fn main() {
    match run() {
        Ok(session) => println!("{}", session.display()),
        Err(error) => {
            eprintln!("lob-capture: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::supervise_until;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    #[test]
    fn supervisor_returns_immediately_after_worker_failure_signal() {
        let stop = AtomicBool::new(true);
        let started = Instant::now();
        supervise_until(&stop, started + Duration::from_secs(5));
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
