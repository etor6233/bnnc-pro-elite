use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportJournalBodyV1 {
    pub schema: String,
    pub record_index: u64,
    pub wall_ns: u64,
    pub mono_ns: u64,
    pub stream: String,
    pub connection_epoch: String,
    pub event: String,
    pub payload: Value,
    pub previous_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportJournalEnvelopeV1 {
    pub body: TransportJournalBodyV1,
    pub record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportJournalSealV1 {
    pub schema: String,
    pub file: String,
    pub records: u64,
    pub terminal_record_sha256: String,
    pub file_bytes: u64,
    pub file_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransportJournalDiagnosisV1 {
    pub schema: &'static str,
    pub stream: String,
    pub connection_epoch: String,
    pub records: u64,
    pub terminal_record_sha256: String,
    pub terminal_status: String,
    pub terminal_error: Option<String>,
    pub terminal_received: u64,
    pub websocket_remote_endpoint: Option<String>,
    pub read_timeouts: u64,
    pub last_tcp_info: Option<Value>,
    pub event_counts: BTreeMap<String, u64>,
    pub classification: String,
    pub attribution_scope: &'static str,
}

pub struct TransportJournalWriter {
    path: PathBuf,
    file_name: String,
    file: File,
    stream: String,
    connection_epoch: String,
    next_index: u64,
    previous_record_sha256: String,
}

fn sha256_bytes(bytes: &[u8]) -> String {
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

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    object
        .keys()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

fn valid_tcp_observation(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    match object.get("status").and_then(Value::as_str) {
        Some("AVAILABLE") => {
            exact_keys(object, &["sample", "status"])
                && object.get("sample").is_some_and(valid_windows_tcp_sample)
        }
        Some("UNAVAILABLE") => {
            exact_keys(object, &["error", "status"])
                && object
                    .get("error")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
        }
        Some("UNSUPPORTED_PLATFORM") => exact_keys(object, &["status"]),
        _ => false,
    }
}

fn valid_windows_tcp_sample(value: &Value) -> bool {
    let Some(sample) = value.as_object() else {
        return false;
    };
    let keys = [
        "api",
        "api_version",
        "bytes_in",
        "bytes_in_flight",
        "bytes_out",
        "bytes_reordered",
        "bytes_retransmitted",
        "congestion_window_bytes",
        "connection_time_ms",
        "duplicate_acks_in",
        "fast_retransmits",
        "min_rtt_us",
        "mss",
        "receive_buffer_bytes",
        "receive_window_bytes",
        "rtt_us",
        "schema",
        "send_window_bytes",
        "state",
        "state_name",
        "syn_retransmits",
        "timeout_episodes",
        "timestamps_enabled",
    ];
    let u32_fields = [
        "bytes_in_flight",
        "bytes_reordered",
        "bytes_retransmitted",
        "congestion_window_bytes",
        "connection_time_ms",
        "duplicate_acks_in",
        "fast_retransmits",
        "min_rtt_us",
        "mss",
        "receive_buffer_bytes",
        "receive_window_bytes",
        "rtt_us",
        "send_window_bytes",
        "timeout_episodes",
    ];
    let state = sample.get("state").and_then(Value::as_i64);
    let expected_state_name = match state {
        Some(0) => Some("CLOSED"),
        Some(1) => Some("LISTEN"),
        Some(2) => Some("SYN_SENT"),
        Some(3) => Some("SYN_RECEIVED"),
        Some(4) => Some("ESTABLISHED"),
        Some(5) => Some("FIN_WAIT_1"),
        Some(6) => Some("FIN_WAIT_2"),
        Some(7) => Some("CLOSE_WAIT"),
        Some(8) => Some("CLOSING"),
        Some(9) => Some("LAST_ACK"),
        Some(10) => Some("TIME_WAIT"),
        Some(_) => Some("UNKNOWN"),
        None => None,
    };
    exact_keys(sample, &keys)
        && sample.get("schema").and_then(Value::as_str) == Some("WindowsTcpInfoV0")
        && sample.get("api").and_then(Value::as_str) == Some("SIO_TCP_INFO")
        && sample.get("api_version").and_then(Value::as_u64) == Some(0)
        && u32_fields.iter().all(|field| {
            sample
                .get(*field)
                .and_then(Value::as_u64)
                .is_some_and(|value| value <= u32::MAX.into())
        })
        && ["bytes_in", "bytes_out", "connection_time_ms"]
            .iter()
            .all(|field| sample.get(*field).and_then(Value::as_u64).is_some())
        && sample
            .get("syn_retransmits")
            .and_then(Value::as_u64)
            .is_some_and(|value| value <= u8::MAX.into())
        && state.is_some_and(|value| i32::try_from(value).is_ok())
        && sample.get("state_name").and_then(Value::as_str) == expected_state_name
        && sample
            .get("timestamps_enabled")
            .is_some_and(Value::is_boolean)
}

fn valid_socket_endpoint(value: &Value, expected_port: Option<u16>) -> bool {
    value
        .as_str()
        .and_then(|text| text.parse::<SocketAddr>().ok())
        .is_some_and(|address| {
            !address.ip().is_unspecified()
                && address.port() != 0
                && expected_port.is_none_or(|port| address.port() == port)
        })
}

fn valid_websocket_error(value: &Value) -> bool {
    let Some(error) = value.as_object() else {
        return false;
    };
    match error.get("category").and_then(Value::as_str) {
        Some("IO") => {
            exact_keys(
                error,
                &["category", "io_kind", "message", "native_os_error"],
            ) && error
                .get("io_kind")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
                && error
                    .get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                && error
                    .get("native_os_error")
                    .is_some_and(|value| value.is_null() || value.as_i64().is_some())
        }
        Some(category) if !category.is_empty() => {
            exact_keys(error, &["category", "message"])
                && error
                    .get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
        }
        _ => false,
    }
}

fn valid_transport_payload(event: &str, payload: &Value) -> bool {
    let Some(object) = payload.as_object() else {
        return false;
    };
    let text = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    };
    let u64_field = |field: &str| object.get(field).and_then(Value::as_u64).is_some();
    match event {
        "CONNECT_ATTEMPT" => {
            exact_keys(object, &["uri"])
                && object
                    .get("uri")
                    .and_then(Value::as_str)
                    .is_some_and(|uri| uri.starts_with("wss://data-stream.binance.vision:443/ws/"))
        }
        "DNS_OBSERVED" => {
            exact_keys(object, &["addresses", "host", "port", "role"])
                && object.get("host").and_then(Value::as_str) == Some("data-stream.binance.vision")
                && object.get("port").and_then(Value::as_u64) == Some(443)
                && object.get("role").and_then(Value::as_str)
                    == Some("DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION")
                && object
                    .get("addresses")
                    .and_then(Value::as_array)
                    .is_some_and(|addresses| {
                        !addresses.is_empty()
                            && addresses
                                .iter()
                                .all(|address| valid_socket_endpoint(address, Some(443)))
                    })
        }
        "DNS_FAILED" => {
            exact_keys(object, &["error", "host", "port", "role"])
                && text("error")
                && object.get("host").and_then(Value::as_str) == Some("data-stream.binance.vision")
                && object.get("port").and_then(Value::as_u64) == Some(443)
                && object.get("role").and_then(Value::as_str)
                    == Some("DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION")
        }
        "CONNECT_FAILED" => {
            exact_keys(object, &["error"]) && object.get("error").is_some_and(valid_websocket_error)
        }
        "WEBSOCKET_UPGRADE_REJECTED" => {
            exact_keys(object, &["http_status"])
                && object
                    .get("http_status")
                    .and_then(Value::as_u64)
                    .is_some_and(|status| (100..=599).contains(&status) && status != 101)
        }
        "WEBSOCKET_CONNECTED" => {
            exact_keys(
                object,
                &[
                    "local_endpoint",
                    "remote_endpoint",
                    "tcp_info",
                    "websocket_http_status",
                ],
            ) && object
                .get("local_endpoint")
                .is_some_and(|value| valid_socket_endpoint(value, None))
                && object
                    .get("remote_endpoint")
                    .is_some_and(|value| valid_socket_endpoint(value, Some(443)))
                && object.get("websocket_http_status").and_then(Value::as_u64) == Some(101)
                && object.get("tcp_info").is_some_and(valid_tcp_observation)
        }
        "FAULT_INJECTED_SILENT_STALL" => {
            exact_keys(object, &["after_mono_ns", "stream"])
                && u64_field("after_mono_ns")
                && object
                    .get("stream")
                    .and_then(Value::as_str)
                    .is_some_and(|stream| matches!(stream, "depth" | "trade"))
        }
        "READ_TIMEOUT" => {
            exact_keys(
                object,
                &["inactive_ms", "io_kind", "native_os_error", "tcp_info"],
            ) && u64_field("inactive_ms")
                && text("io_kind")
                && object
                    .get("native_os_error")
                    .is_some_and(|value| value.is_null() || value.as_i64().is_some())
                && object.get("tcp_info").is_some_and(valid_tcp_observation)
        }
        "TRANSPORT_DEADLINE" => {
            exact_keys(object, &["deadline_ms", "inactive_ms", "tcp_info"])
                && u64_field("deadline_ms")
                && u64_field("inactive_ms")
                && object.get("tcp_info").is_some_and(valid_tcp_observation)
        }
        "SOCKET_READ_ERROR" => {
            exact_keys(object, &["error", "tcp_info"])
                && object.get("error").is_some_and(valid_websocket_error)
                && object.get("tcp_info").is_some_and(valid_tcp_observation)
        }
        "WEBSOCKET_CLOSE" => {
            exact_keys(object, &["close", "tcp_info"])
                && object.get("close").is_some_and(|value| {
                    value.is_null()
                        || value.as_object().is_some_and(|close| {
                            exact_keys(close, &["code", "reason"])
                                && close.get("code").and_then(Value::as_str).is_some()
                                && close.get("reason").and_then(Value::as_str).is_some()
                        })
                })
                && object.get("tcp_info").is_some_and(valid_tcp_observation)
        }
        "WS_PING_PONG_FLUSHED" => {
            exact_keys(object, &["payload_bytes", "payload_sha256"])
                && u64_field("payload_bytes")
                && object
                    .get("payload_sha256")
                    .and_then(Value::as_str)
                    .is_some_and(valid_sha256)
        }
        "WS_PONG_RECEIVED" => {
            // `watchdog_rtt_ms` is optional: historical journals predate the
            // watchdog and carry only the two base keys.
            (exact_keys(object, &["payload_bytes", "payload_sha256"])
                || exact_keys(
                    object,
                    &["payload_bytes", "payload_sha256", "watchdog_rtt_ms"],
                ))
                && u64_field("payload_bytes")
                && object
                    .get("payload_sha256")
                    .and_then(Value::as_str)
                    .is_some_and(valid_sha256)
                && object
                    .get("watchdog_rtt_ms")
                    .is_none_or(|value| value.is_null() || value.as_u64().is_some())
        }
        "WATCHDOG_PING_SENT" => {
            exact_keys(object, &["deadline_ms", "interval_ms"])
                && u64_field("deadline_ms")
                && u64_field("interval_ms")
        }
        "WATCHDOG_PONG_DEADLINE" => {
            exact_keys(object, &["deadline_ms", "inactive_ms", "tcp_info"])
                && u64_field("deadline_ms")
                && u64_field("inactive_ms")
                && object.get("tcp_info").is_some_and(valid_tcp_observation)
        }
        "UNEXPECTED_RAW_FRAME" => object.is_empty(),
        "CLIENT_STOP_OBSERVED" => {
            exact_keys(object, &["tcp_info"])
                && object.get("tcp_info").is_some_and(valid_tcp_observation)
        }
        "SUPERVISOR_FAILURE_STOP" => {
            exact_keys(
                object,
                &[
                    "campaign_failure_record_sha256",
                    "reason",
                    "source",
                    "tcp_info",
                ],
            ) && object
                .get("campaign_failure_record_sha256")
                .is_some_and(|value| value.is_null() || value.as_str().is_some_and(valid_sha256))
                && text("reason")
                && object
                    .get("source")
                    .and_then(Value::as_str)
                    .is_some_and(|source| {
                        matches!(
                            source,
                            "CAMPAIGN_STOP_REQUEST" | "LOCAL_GENERATION_SUPERVISOR"
                        )
                    })
                && object.get("tcp_info").is_some_and(valid_tcp_observation)
                && match object.get("source").and_then(Value::as_str) {
                    Some("CAMPAIGN_STOP_REQUEST") => object
                        .get("campaign_failure_record_sha256")
                        .and_then(Value::as_str)
                        .is_some_and(valid_sha256),
                    Some("LOCAL_GENERATION_SUPERVISOR") => object
                        .get("campaign_failure_record_sha256")
                        .is_some_and(Value::is_null),
                    _ => false,
                }
        }
        "PRODUCER_FAILURE" => {
            exact_keys(object, &["error", "stage"])
                && text("error")
                && object.get("stage").and_then(Value::as_str) == Some("PRODUCER_LOOP")
        }
        "TRANSPORT_TERMINAL" => {
            exact_keys(object, &["error", "received", "status"])
                && u64_field("received")
                && match object.get("status").and_then(Value::as_str) {
                    Some("STOPPED") => object.get("error").is_some_and(Value::is_null),
                    Some("FAILED") => object
                        .get("error")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.trim().is_empty()),
                    _ => false,
                }
        }
        _ => false,
    }
}

impl TransportJournalWriter {
    pub fn create(
        path: &Path,
        stream: &str,
        connection_epoch: &str,
    ) -> Result<TransportJournalWriter> {
        if !matches!(stream, "depth" | "trade") || connection_epoch.trim().is_empty() {
            return Err("transport journal stream/connection epoch is invalid".to_owned());
        }
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "transport journal path lacks a UTF-8 file name".to_owned())?
            .to_owned();
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        Ok(Self {
            path: path.to_owned(),
            file_name,
            file,
            stream: stream.to_owned(),
            connection_epoch: connection_epoch.to_owned(),
            next_index: 0,
            previous_record_sha256: ZERO_SHA256.to_owned(),
        })
    }

    pub fn append(
        &mut self,
        wall_ns: u64,
        mono_ns: u64,
        event: &str,
        payload: Value,
    ) -> Result<String> {
        if wall_ns == 0 || event.trim().is_empty() {
            return Err("transport journal timestamp/event is invalid".to_owned());
        }
        if !valid_transport_payload(event, &payload) {
            return Err(format!("transport journal {event} payload is invalid"));
        }
        let body = TransportJournalBodyV1 {
            schema: "TransportJournalRecordV1".to_owned(),
            record_index: self.next_index,
            wall_ns,
            mono_ns,
            stream: self.stream.clone(),
            connection_epoch: self.connection_epoch.clone(),
            event: event.to_owned(),
            payload,
            previous_record_sha256: self.previous_record_sha256.clone(),
        };
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|error| format!("serialize transport journal body: {error}"))?;
        let digest = sha256_bytes(&body_bytes);
        let envelope = TransportJournalEnvelopeV1 {
            body,
            record_sha256: digest.clone(),
        };
        let mut bytes = serde_json::to_vec(&envelope)
            .map_err(|error| format!("serialize transport journal envelope: {error}"))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err("transport journal record exceeds its bounded size".to_owned());
        }
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_all())
            .map_err(|error| format!("sync transport journal {}: {error}", self.path.display()))?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| "transport journal index overflow".to_owned())?;
        self.previous_record_sha256 = digest.clone();
        Ok(digest)
    }

    pub fn seal(mut self) -> Result<TransportJournalSealV1> {
        if self.next_index == 0 {
            return Err("cannot seal an empty transport journal".to_owned());
        }
        self.file
            .flush()
            .and_then(|_| self.file.sync_all())
            .map_err(|error| format!("seal transport journal {}: {error}", self.path.display()))?;
        drop(self.file);
        let file_bytes = std::fs::metadata(&self.path)
            .map_err(|error| format!("stat {}: {error}", self.path.display()))?
            .len();
        let seal = TransportJournalSealV1 {
            schema: "TransportJournalSealV1".to_owned(),
            file: self.file_name,
            records: self.next_index,
            terminal_record_sha256: self.previous_record_sha256,
            file_bytes,
            file_sha256: sha256_file(&self.path)?,
        };
        let scanned = scan_transport_journal(&self.path)?;
        if scanned != seal {
            return Err("transport journal seal differs from independent rescan".to_owned());
        }
        Ok(seal)
    }
}

fn scan_transport_journal_internal(
    path: &Path,
    expected_identity: Option<(&str, &str, &str)>,
    expected_terminal_received: Option<u64>,
) -> Result<TransportJournalSealV1> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_bytes = file
        .metadata()
        .map_err(|error| format!("stat {}: {error}", path.display()))?
        .len();
    if file_bytes == 0 || file_bytes > MAX_JOURNAL_BYTES {
        return Err("transport journal is empty or exceeds its total size bound".to_owned());
    }
    let mut reader = BufReader::new(file);
    let mut expected_index = 0_u64;
    let mut previous = ZERO_SHA256.to_owned();
    let mut expected_stream: Option<String> = None;
    let mut expected_epoch: Option<String> = None;
    let mut first_event: Option<String> = None;
    let mut last_event: Option<String> = None;
    let mut last_payload: Option<Value> = None;
    let mut websocket_connected = false;
    let mut client_stop_observed = false;
    let mut failure_reason: Option<String> = None;
    let mut terminal_seen = false;
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take(MAX_RECORD_BYTES + 1)
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        if read as u64 > MAX_RECORD_BYTES || line.last() != Some(&b'\n') {
            return Err("transport journal contains an oversized or partial record".to_owned());
        }
        line.pop();
        let envelope: TransportJournalEnvelopeV1 = serde_json::from_slice(&line)
            .map_err(|error| format!("invalid transport journal JSON: {error}"))?;
        let body_bytes = serde_json::to_vec(&envelope.body)
            .map_err(|error| format!("serialize scanned transport journal body: {error}"))?;
        let digest = sha256_bytes(&body_bytes);
        if envelope.body.schema != "TransportJournalRecordV1"
            || envelope.body.record_index != expected_index
            || envelope.body.wall_ns == 0
            || !matches!(envelope.body.stream.as_str(), "depth" | "trade")
            || envelope.body.connection_epoch.trim().is_empty()
            || envelope.body.event.trim().is_empty()
            || !valid_transport_payload(&envelope.body.event, &envelope.body.payload)
            || envelope.body.previous_record_sha256 != previous
            || envelope.record_sha256 != digest
            || !valid_sha256(&envelope.record_sha256)
        {
            return Err("transport journal identity/hash chain is invalid".to_owned());
        }
        if expected_stream
            .as_ref()
            .is_some_and(|value| value != &envelope.body.stream)
            || expected_epoch
                .as_ref()
                .is_some_and(|value| value != &envelope.body.connection_epoch)
        {
            return Err("transport journal changed stream or connection epoch".to_owned());
        }
        let event = envelope.body.event.as_str();
        if expected_index == 0
            && let Some((_, _, expected_uri)) = expected_identity
            && envelope.body.payload["uri"].as_str() != Some(expected_uri)
        {
            return Err("transport journal connect URI differs from its stream binding".to_owned());
        }
        if terminal_seen
            || (expected_index == 0 && event != "CONNECT_ATTEMPT")
            || (expected_index == 1 && !matches!(event, "DNS_OBSERVED" | "DNS_FAILED"))
            || (expected_index == 2
                && !matches!(
                    event,
                    "CONNECT_FAILED"
                        | "WEBSOCKET_UPGRADE_REJECTED"
                        | "WEBSOCKET_CONNECTED"
                        | "SUPERVISOR_FAILURE_STOP"
                        | "PRODUCER_FAILURE"
                ))
        {
            return Err("transport journal lifecycle sequence is invalid".to_owned());
        }
        if expected_index > 2
            && !websocket_connected
            && event != "PRODUCER_FAILURE"
            && !(event == "TRANSPORT_TERMINAL" && failure_reason.is_some())
        {
            return Err("transport journal advanced without a WebSocket connection".to_owned());
        }
        if client_stop_observed && event != "TRANSPORT_TERMINAL" {
            return Err("transport journal continued after client stop".to_owned());
        }
        if failure_reason.is_some() && event != "TRANSPORT_TERMINAL" {
            return Err("transport journal continued after producer failure".to_owned());
        }
        match event {
            "WEBSOCKET_CONNECTED" => {
                if websocket_connected {
                    return Err(
                        "transport journal contains duplicate WebSocket connection".to_owned()
                    );
                }
                websocket_connected = true;
            }
            "READ_TIMEOUT"
            | "TRANSPORT_DEADLINE"
            | "SOCKET_READ_ERROR"
            | "WEBSOCKET_CLOSE"
            | "WS_PING_PONG_FLUSHED"
            | "WS_PONG_RECEIVED"
            | "WATCHDOG_PING_SENT"
            | "WATCHDOG_PONG_DEADLINE"
            | "UNEXPECTED_RAW_FRAME"
            | "FAULT_INJECTED_SILENT_STALL"
            | "CLIENT_STOP_OBSERVED" => {
                if !websocket_connected {
                    return Err("transport event precedes WebSocket connection".to_owned());
                }
                if event == "CLIENT_STOP_OBSERVED" {
                    client_stop_observed = true;
                }
            }
            "SUPERVISOR_FAILURE_STOP" => {
                if expected_index > 2 && !websocket_connected {
                    return Err(
                        "supervisor failure stop has no observable socket boundary".to_owned()
                    );
                }
            }
            "PRODUCER_FAILURE" => {
                failure_reason = envelope.body.payload["error"].as_str().map(str::to_owned);
            }
            "TRANSPORT_TERMINAL" => {
                let status = envelope.body.payload["status"].as_str();
                let error = envelope.body.payload["error"].as_str();
                if (status == Some("STOPPED")
                    && (!client_stop_observed || failure_reason.is_some()))
                    || (status == Some("FAILED")
                        && (failure_reason.is_none() || error != failure_reason.as_deref()))
                {
                    return Err("transport terminal contradicts its observed lifecycle".to_owned());
                }
                terminal_seen = true;
            }
            _ => {}
        }
        expected_stream.get_or_insert(envelope.body.stream);
        expected_epoch.get_or_insert(envelope.body.connection_epoch);
        first_event.get_or_insert_with(|| envelope.body.event.clone());
        last_event = Some(envelope.body.event);
        last_payload = Some(envelope.body.payload);
        previous = digest;
        expected_index = expected_index
            .checked_add(1)
            .ok_or_else(|| "transport journal index overflow".to_owned())?;
    }
    if expected_index == 0 {
        return Err("transport journal is empty".to_owned());
    }
    if let Some((stream, epoch, _)) = expected_identity
        && (expected_stream.as_deref() != Some(stream) || expected_epoch.as_deref() != Some(epoch))
    {
        return Err("transport journal differs from its bound stream/epoch".to_owned());
    }
    if first_event.as_deref() != Some("CONNECT_ATTEMPT")
        || last_event.as_deref() != Some("TRANSPORT_TERMINAL")
        || !terminal_seen
    {
        return Err("transport journal lifecycle boundary is invalid".to_owned());
    }
    if let Some(expected_received) = expected_terminal_received {
        let payload = last_payload
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| "transport terminal payload is not an object".to_owned())?;
        let keys = payload.keys().map(String::as_str).collect::<Vec<_>>();
        if last_event.as_deref() != Some("TRANSPORT_TERMINAL")
            || keys != ["error", "received", "status"]
            || !payload["error"].is_null()
            || payload["received"].as_u64() != Some(expected_received)
            || payload["status"].as_str() != Some("STOPPED")
        {
            return Err("sealed transport journal terminal status/count is invalid".to_owned());
        }
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "transport journal path lacks a UTF-8 file name".to_owned())?;
    Ok(TransportJournalSealV1 {
        schema: "TransportJournalSealV1".to_owned(),
        file: file_name.to_owned(),
        records: expected_index,
        terminal_record_sha256: previous,
        file_bytes,
        file_sha256: sha256_file(path)?,
    })
}

pub fn scan_transport_journal(path: &Path) -> Result<TransportJournalSealV1> {
    scan_transport_journal_internal(path, None, None)
}

pub fn verify_sealed_transport_journal(
    path: &Path,
    stream: &str,
    connection_epoch: &str,
    expected_uri: &str,
    expected_received: u64,
) -> Result<TransportJournalSealV1> {
    if expected_uri.trim().is_empty() {
        return Err("transport journal expected URI is empty".to_owned());
    }
    scan_transport_journal_internal(
        path,
        Some((stream, connection_epoch, expected_uri)),
        Some(expected_received),
    )
}

pub fn diagnose_sealed_transport_journal(
    path: &Path,
    stream: &str,
    connection_epoch: &str,
    expected_uri: &str,
    expected_received: u64,
    expected_seal: &TransportJournalSealV1,
) -> Result<TransportJournalDiagnosisV1> {
    if expected_uri.trim().is_empty() {
        return Err("transport journal expected URI is empty".to_owned());
    }
    let scanned = scan_transport_journal_internal(
        path,
        Some((stream, connection_epoch, expected_uri)),
        None,
    )?;
    if &scanned != expected_seal {
        return Err("transport journal differs from its expected seal".to_owned());
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("read diagnostic journal {}: {error}", path.display()))?;
    if bytes.len() as u64 != scanned.file_bytes || sha256_bytes(&bytes) != scanned.file_sha256 {
        return Err("transport journal changed between validation and diagnosis".to_owned());
    }
    let mut event_counts = BTreeMap::<String, u64>::new();
    let mut websocket_remote_endpoint = None;
    let mut read_timeouts = 0_u64;
    let mut last_tcp_info = None;
    let mut terminal_status = None;
    let mut terminal_error = None;
    let mut terminal_received = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let envelope: TransportJournalEnvelopeV1 = serde_json::from_slice(line)
            .map_err(|error| format!("parse validated diagnostic journal: {error}"))?;
        let count = event_counts.entry(envelope.body.event.clone()).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| "transport diagnostic event count overflow".to_owned())?;
        if envelope.body.event == "WEBSOCKET_CONNECTED" {
            websocket_remote_endpoint = envelope.body.payload["remote_endpoint"]
                .as_str()
                .map(str::to_owned);
        }
        if envelope.body.event == "READ_TIMEOUT" {
            read_timeouts = read_timeouts
                .checked_add(1)
                .ok_or_else(|| "transport diagnostic timeout count overflow".to_owned())?;
        }
        if let Some(tcp_info) = envelope.body.payload.get("tcp_info") {
            last_tcp_info = Some(tcp_info.clone());
        }
        if envelope.body.event == "TRANSPORT_TERMINAL" {
            terminal_status = envelope.body.payload["status"].as_str().map(str::to_owned);
            terminal_error = envelope.body.payload["error"].as_str().map(str::to_owned);
            terminal_received = envelope.body.payload["received"].as_u64();
        }
    }
    let status =
        terminal_status.ok_or_else(|| "transport diagnosis lacks terminal status".to_owned())?;
    let received = terminal_received
        .ok_or_else(|| "transport diagnosis lacks terminal received count".to_owned())?;
    if received != expected_received {
        return Err("transport diagnosis received count differs from stream manifest".to_owned());
    }
    let contains = |event: &str| event_counts.get(event).copied().unwrap_or(0) != 0;
    let classification = if status == "STOPPED" {
        "CLEAN_CLIENT_STOP".to_owned()
    } else if contains("SUPERVISOR_FAILURE_STOP") {
        "SUPERVISOR_FAILURE_STOP_OBSERVED".to_owned()
    } else if contains("CONNECT_FAILED") {
        "CONNECT_FAILURE_OBSERVED".to_owned()
    } else if contains("WEBSOCKET_UPGRADE_REJECTED") {
        "WEBSOCKET_UPGRADE_REJECTION_OBSERVED".to_owned()
    } else if contains("WEBSOCKET_CLOSE") {
        "WEBSOCKET_CLOSE_FRAME_OBSERVED".to_owned()
    } else if contains("SOCKET_READ_ERROR") {
        "SOCKET_READ_ERROR_OBSERVED".to_owned()
    } else if contains("TRANSPORT_DEADLINE") {
        let state = last_tcp_info
            .as_ref()
            .and_then(|value| value.get("sample"))
            .and_then(|value| value.get("state_name"))
            .and_then(Value::as_str);
        if state == Some("ESTABLISHED") {
            "TRANSPORT_SILENCE_WITH_LOCAL_TCP_ESTABLISHED".to_owned()
        } else {
            "TRANSPORT_SILENCE_WITHOUT_LOCAL_ESTABLISHED_PROOF".to_owned()
        }
    } else {
        "LOCAL_PRODUCER_FAILURE_WITHOUT_TRANSPORT_SUBTYPE".to_owned()
    };
    Ok(TransportJournalDiagnosisV1 {
        schema: "TransportJournalDiagnosisV1",
        stream: stream.to_owned(),
        connection_epoch: connection_epoch.to_owned(),
        records: scanned.records,
        terminal_record_sha256: scanned.terminal_record_sha256,
        terminal_status: status,
        terminal_error,
        terminal_received: received,
        websocket_remote_endpoint,
        read_timeouts,
        last_tcp_info,
        event_counts,
        classification,
        attribution_scope: "OBSERVED_LOCAL_SOCKET_AND_WEBSOCKET_BOUNDARY_ONLY",
    })
}

#[cfg(test)]
mod tests {
    use super::{
        TransportJournalWriter, diagnose_sealed_transport_journal, scan_transport_journal,
        verify_sealed_transport_journal,
    };
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn durable_transport_chain_seals_and_rejects_tampering() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("transport-depth-events.jsonl");
        let mut writer = TransportJournalWriter::create(&path, "depth", "epoch").unwrap();
        writer
            .append(
                1,
                0,
                "CONNECT_ATTEMPT",
                json!({"uri":"wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms?timeUnit=MICROSECOND"}),
            )
            .unwrap();
        writer
            .append(
                2,
                1,
                "DNS_OBSERVED",
                json!({
                    "addresses":["127.0.0.1:443"],
                    "host":"data-stream.binance.vision",
                    "port":443,
                    "role":"DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION"
                }),
            )
            .unwrap();
        writer
            .append(
                3,
                2,
                "CONNECT_FAILED",
                json!({"error":{"category":"IO","io_kind":"ConnectionRefused","message":"refused","native_os_error":10061}}),
            )
            .unwrap();
        writer
            .append(
                4,
                3,
                "PRODUCER_FAILURE",
                json!({"error":"connect failed","stage":"PRODUCER_LOOP"}),
            )
            .unwrap();
        writer
            .append(
                5,
                4,
                "TRANSPORT_TERMINAL",
                json!({"error":"connect failed","received":0,"status":"FAILED"}),
            )
            .unwrap();
        let seal = writer.seal().unwrap();
        assert_eq!(seal.records, 5);
        assert_eq!(scan_transport_journal(&path).unwrap(), seal);
        let diagnosis = diagnose_sealed_transport_journal(
            &path,
            "depth",
            "epoch",
            "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms?timeUnit=MICROSECOND",
            0,
            &seal,
        )
        .unwrap();
        assert_eq!(diagnosis.classification, "CONNECT_FAILURE_OBSERVED");

        let mut bytes = std::fs::read(&path).unwrap();
        let position = bytes.iter().position(|byte| *byte == b'T').unwrap();
        bytes[position] = b'Z';
        std::fs::write(&path, bytes).unwrap();
        assert!(scan_transport_journal(&path).is_err());
    }

    #[test]
    fn partial_tail_is_never_accepted_as_a_seal() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("transport-trade-events.jsonl");
        let mut writer = TransportJournalWriter::create(&path, "trade", "epoch").unwrap();
        writer
            .append(
                1,
                0,
                "CONNECT_ATTEMPT",
                json!({"uri":"wss://data-stream.binance.vision:443/ws/btcusdt@trade?timeUnit=MICROSECOND"}),
            )
            .unwrap();
        drop(writer);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.pop();
        std::fs::write(&path, bytes).unwrap();
        assert!(scan_transport_journal(&path).is_err());
    }

    #[test]
    fn unknown_event_and_clean_terminal_without_client_stop_fail_closed() {
        let directory = tempdir().unwrap();
        let invalid_path = directory.path().join("invalid.jsonl");
        let mut invalid = TransportJournalWriter::create(&invalid_path, "depth", "epoch").unwrap();
        assert!(
            invalid
                .append(1, 0, "FUTURE_UNKNOWN_EVENT", json!({}))
                .is_err()
        );

        let path = directory.path().join("transport-depth-events.jsonl");
        let uri =
            "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms?timeUnit=MICROSECOND";
        let mut writer = TransportJournalWriter::create(&path, "depth", "epoch").unwrap();
        writer
            .append(1, 0, "CONNECT_ATTEMPT", json!({"uri":uri}))
            .unwrap();
        writer
            .append(
                2,
                1,
                "DNS_OBSERVED",
                json!({"addresses":["127.0.0.1:443"],"host":"data-stream.binance.vision","port":443,"role":"DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION"}),
            )
            .unwrap();
        writer
            .append(
                3,
                2,
                "WEBSOCKET_CONNECTED",
                json!({"local_endpoint":"127.0.0.1:40000","remote_endpoint":"127.0.0.1:443","tcp_info":{"status":"UNSUPPORTED_PLATFORM"},"websocket_http_status":101}),
            )
            .unwrap();
        writer
            .append(
                4,
                3,
                "TRANSPORT_TERMINAL",
                json!({"error":null,"received":0,"status":"STOPPED"}),
            )
            .unwrap();
        assert!(writer.seal().is_err());
    }

    #[test]
    fn successful_seal_is_bound_to_exact_uri_and_received_count() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("transport-trade-events.jsonl");
        let uri = "wss://data-stream.binance.vision:443/ws/btcusdt@trade?timeUnit=MICROSECOND";
        let mut writer = TransportJournalWriter::create(&path, "trade", "epoch").unwrap();
        writer
            .append(1, 0, "CONNECT_ATTEMPT", json!({"uri":uri}))
            .unwrap();
        writer
            .append(
                2,
                1,
                "DNS_OBSERVED",
                json!({"addresses":["127.0.0.1:443"],"host":"data-stream.binance.vision","port":443,"role":"DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION"}),
            )
            .unwrap();
        writer
            .append(
                3,
                2,
                "WEBSOCKET_CONNECTED",
                json!({"local_endpoint":"127.0.0.1:40000","remote_endpoint":"127.0.0.1:443","tcp_info":{"status":"UNSUPPORTED_PLATFORM"},"websocket_http_status":101}),
            )
            .unwrap();
        writer
            .append(
                4,
                3,
                "CLIENT_STOP_OBSERVED",
                json!({"tcp_info":{"status":"UNSUPPORTED_PLATFORM"}}),
            )
            .unwrap();
        writer
            .append(
                5,
                4,
                "TRANSPORT_TERMINAL",
                json!({"error":null,"received":7,"status":"STOPPED"}),
            )
            .unwrap();
        let seal = writer.seal().unwrap();
        assert!(verify_sealed_transport_journal(&path, "trade", "epoch", uri, 7).is_ok());
        assert!(
            verify_sealed_transport_journal(&path, "trade", "epoch", "wss://wrong", 7).is_err()
        );
        assert!(verify_sealed_transport_journal(&path, "trade", "epoch", uri, 8).is_err());
        let diagnosis =
            diagnose_sealed_transport_journal(&path, "trade", "epoch", uri, 7, &seal).unwrap();
        assert_eq!(diagnosis.classification, "CLEAN_CLIENT_STOP");
        assert_eq!(diagnosis.terminal_received, 7);
        assert_eq!(
            diagnosis.websocket_remote_endpoint.as_deref(),
            Some("127.0.0.1:443")
        );
    }

    #[test]
    fn transport_silence_is_classified_only_to_the_observed_socket_boundary() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("transport-depth-events.jsonl");
        let uri =
            "wss://data-stream.binance.vision:443/ws/btcusdt@depth@100ms?timeUnit=MICROSECOND";
        let mut writer = TransportJournalWriter::create(&path, "depth", "epoch").unwrap();
        writer
            .append(1, 0, "CONNECT_ATTEMPT", json!({"uri":uri}))
            .unwrap();
        writer
            .append(
                2,
                1,
                "DNS_OBSERVED",
                json!({"addresses":["127.0.0.1:443"],"host":"data-stream.binance.vision","port":443,"role":"DIAGNOSTIC_OBSERVATION_NOT_CONNECT_SELECTION"}),
            )
            .unwrap();
        writer
            .append(
                3,
                2,
                "WEBSOCKET_CONNECTED",
                json!({"local_endpoint":"127.0.0.1:40000","remote_endpoint":"127.0.0.1:443","tcp_info":{"status":"UNSUPPORTED_PLATFORM"},"websocket_http_status":101}),
            )
            .unwrap();
        writer
            .append(
                4,
                3,
                "READ_TIMEOUT",
                json!({"inactive_ms":5000,"io_kind":"TimedOut","native_os_error":null,"tcp_info":{"status":"UNSUPPORTED_PLATFORM"}}),
            )
            .unwrap();
        writer
            .append(
                5,
                4,
                "TRANSPORT_DEADLINE",
                json!({"deadline_ms":30000,"inactive_ms":30001,"tcp_info":{"status":"UNSUPPORTED_PLATFORM"}}),
            )
            .unwrap();
        let error = "transport liveness deadline exceeded for depth";
        writer
            .append(
                6,
                5,
                "PRODUCER_FAILURE",
                json!({"error":error,"stage":"PRODUCER_LOOP"}),
            )
            .unwrap();
        writer
            .append(
                7,
                6,
                "TRANSPORT_TERMINAL",
                json!({"error":error,"received":11,"status":"FAILED"}),
            )
            .unwrap();
        let seal = writer.seal().unwrap();
        let diagnosis =
            diagnose_sealed_transport_journal(&path, "depth", "epoch", uri, 11, &seal).unwrap();
        assert_eq!(
            diagnosis.classification,
            "TRANSPORT_SILENCE_WITHOUT_LOCAL_ESTABLISHED_PROOF"
        );
        assert_eq!(
            diagnosis.attribution_scope,
            "OBSERVED_LOCAL_SOCKET_AND_WEBSOCKET_BOUNDARY_ONLY"
        );
        assert_eq!(diagnosis.read_timeouts, 1);
    }
}
