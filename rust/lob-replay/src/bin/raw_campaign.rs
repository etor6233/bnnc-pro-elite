use lob_replay::Result;
use lob_replay::capture_config::validate_public_capture_config;
use lob_replay::generation_artifact::{VerifiedGenerationV1, verify_segmented_generation};
use lob_replay::generation_handover::{
    ExpectedSegmentPublicationV1, ExpectedSnapshotPublicationV1, RawGenerationHandoverProofV1,
    prove_raw_generation_handover, validate_raw_handover_proof_digest,
};
use lob_replay::generation_supervisor::{
    CandidateFact, GenerationIdentity, RawGenerationSupervisor, RawSupervisorConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";
const POLL: Duration = Duration::from_millis(100);
const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(30);
const STARTUP_DEADLINE: Duration = Duration::from_secs(30);
const FAILURE_STOP_GRACE: Duration = Duration::from_secs(5);
const PROOF_COMPLETION_DEADLINE: Duration = Duration::from_secs(30 * 60);
const MAX_TELEMETRY_RECORD_BYTES: u64 = 64 * 1024;
const PROOF_MARGIN_S: u64 = 3_600;
const MAX_HANDOVER_SEAL_GUARD_S: u64 = 30;
// The launcher grants 120 s for terminal publication after the requested
// campaign horizon.  Keep the final overlap generation alive for at most
// 90 s of that budget so its root segment can be proven while the candidate
// is still live, leaving 30 s for terminal publication and coordinator work.
const FINAL_HANDOVER_TAIL_S: u64 = 90;
const MARKET_FRESHNESS_STARTUP_GRACE_NS: u64 = 30_000_000_000;
const MARKET_FRESHNESS_DEADLINE_NS: u64 = 30_000_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ExpectedServerShutdownPublicationV1 {
    schema: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CampaignJournalBodyV1 {
    schema: String,
    record_index: u64,
    wall_ns: u64,
    campaign_mono_ns: u64,
    generation_index: Option<u64>,
    channel: String,
    payload: Value,
    previous_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CampaignJournalEnvelopeV1 {
    body: CampaignJournalBodyV1,
    record_sha256: String,
}

struct CampaignJournalWriter {
    file: File,
    next_index: u64,
    previous: String,
}

#[derive(Serialize)]
struct CampaignHeartbeatV1<'a> {
    event: &'static str,
    campaign_id: &'a str,
    elapsed_s: u64,
    generations: usize,
    active_processes: usize,
    handovers_proven: usize,
    failure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_record_sha256: Option<&'a str>,
}

#[derive(Serialize)]
struct CaptureStopRequestV1<'a> {
    schema: &'static str,
    session_id: &'a str,
    reason: &'a str,
    campaign_failure_record_sha256: &'a str,
}

impl CampaignJournalWriter {
    fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        Ok(Self {
            file,
            next_index: 0,
            previous: "0".repeat(64),
        })
    }

    fn append(
        &mut self,
        origin: Instant,
        generation_index: Option<u64>,
        channel: &str,
        payload: Value,
    ) -> Result<String> {
        let body = CampaignJournalBodyV1 {
            schema: "RawCampaignJournalRecordV1".to_owned(),
            record_index: self.next_index,
            wall_ns: unix_ns()?,
            campaign_mono_ns: elapsed_ns(origin)?,
            generation_index,
            channel: channel.to_owned(),
            payload,
            previous_record_sha256: self.previous.clone(),
        };
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|error| format!("serialize campaign journal body: {error}"))?;
        let digest = sha256_hex(&body_bytes);
        let envelope = CampaignJournalEnvelopeV1 {
            body,
            record_sha256: digest.clone(),
        };
        let mut bytes = serde_json::to_vec(&envelope)
            .map_err(|error| format!("serialize campaign journal envelope: {error}"))?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_all())
            .map_err(|error| format!("sync campaign journal: {error}"))?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| "campaign journal index overflow".to_owned())?;
        self.previous = digest.clone();
        Ok(digest)
    }

    fn records(&self) -> u64 {
        self.next_index
    }

    fn digest(&self) -> &str {
        &self.previous
    }
}

fn persist_runtime_failure_once(
    journal: &mut CampaignJournalWriter,
    origin: Instant,
    failure: Option<&str>,
    failure_record_sha256: &mut Option<String>,
) -> Result<()> {
    let Some(error) = failure else {
        return Ok(());
    };
    if failure_record_sha256.is_some() {
        return Ok(());
    }
    let digest = journal.append(
        origin,
        None,
        "CAMPAIGN",
        serde_json::json!({
            "event":"CAMPAIGN_FAILED",
            "stage":"RUNTIME",
            "error":error
        }),
    )?;
    *failure_record_sha256 = Some(digest);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn campaign_heartbeat_json(
    campaign_id: &str,
    elapsed_s: u64,
    generations: usize,
    active_processes: usize,
    handovers_proven: usize,
    failure: Option<&str>,
    failure_record_sha256: Option<&str>,
) -> Result<String> {
    if failure.is_some() != failure_record_sha256.is_some() {
        return Err("campaign heartbeat failure cause/digest presence differs".to_owned());
    }
    serde_json::to_string(&CampaignHeartbeatV1 {
        event: "CAMPAIGN_HEARTBEAT",
        campaign_id,
        elapsed_s,
        generations,
        active_processes,
        handovers_proven,
        failure: failure.is_some(),
        failure_reason: failure,
        failure_record_sha256,
    })
    .map_err(|error| format!("serialize campaign heartbeat: {error}"))
}

#[derive(Debug)]
enum ProcessOutput {
    Stdout { generation: u64, line: String },
    Stderr { generation: u64, line: String },
}

struct ChildState {
    generation_index: u64,
    symbol: String,
    launch_mono_ns: u64,
    duration_s: u64,
    child: Child,
    stop_file: PathBuf,
    session_id: Option<String>,
    session_dir: Option<PathBuf>,
    startup_sha256: Option<String>,
    connections: BTreeMap<String, String>,
    snapshot: Option<ExpectedSnapshotPublicationV1>,
    root_segments: BTreeMap<String, ExpectedSegmentPublicationV1>,
    last_segments: BTreeMap<String, ExpectedSegmentPublicationV1>,
    telemetry_durable_offset: u64,
    last_telemetry_index: Option<u64>,
    last_telemetry_mono_ns: u64,
    last_telemetry_sha256: Option<String>,
    last_heartbeat: Instant,
    last_depth_received: u64,
    last_depth_durable: u64,
    last_trade_received: u64,
    last_trade_durable: u64,
    last_depth_socket_activity_mono_ns: u64,
    last_trade_socket_activity_mono_ns: u64,
    last_depth_market_message_mono_ns: u64,
    last_trade_market_message_mono_ns: u64,
    pending_server_shutdown_epochs: Vec<String>,
    last_server_shutdown: BTreeMap<String, ExpectedServerShutdownPublicationV1>,
    terminal_status: Option<String>,
    exit_status: Option<ExitStatus>,
    exit_seen: Option<Instant>,
    exit_journaled: bool,
    supervisor_registered: bool,
    disconnect_reported: bool,
}

impl ChildState {
    fn identity(&self) -> Result<GenerationIdentity> {
        GenerationIdentity::new(
            self.session_id
                .as_deref()
                .ok_or_else(|| "generation lacks PROCESS_STARTED".to_owned())?,
            self.connections
                .get("depth")
                .ok_or_else(|| "generation lacks depth connection epoch".to_owned())?,
            self.connections
                .get("trade")
                .ok_or_else(|| "generation lacks trade connection epoch".to_owned())?,
        )
    }

    fn live_prefix_ready(&self) -> bool {
        self.session_dir.is_some()
            && self.startup_sha256.is_some()
            && self.connections.len() == 2
            && self.snapshot.is_some()
            && self.root_segments.contains_key("depth")
            && self.root_segments.contains_key("trade")
    }

    fn terminal_complete(&self) -> bool {
        self.exit_status.as_ref().is_some_and(ExitStatus::success)
            && self.terminal_status.as_deref() == Some("COMPLETE")
    }
}

impl Drop for ChildState {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[derive(Debug)]
struct ProofCompletion {
    predecessor_index: u64,
    successor_index: u64,
    result: Result<RawGenerationHandoverProofV1>,
}

#[derive(Serialize)]
struct CampaignStartupV1 {
    schema: &'static str,
    campaign_id: String,
    symbol: String,
    total_duration_s: u64,
    rotation_s: u64,
    overlap_s: u64,
    segment_s: u64,
    started_wall_ns: u64,
    process_id: u32,
    executable_sha256: String,
    capture_executable_sha256: String,
    public_config_sha256: String,
    spec_revision: &'static str,
    credentials: &'static str,
    order_entry: &'static str,
}

#[derive(Serialize)]
struct CampaignGenerationResultV1 {
    generation_index: u64,
    session_id: String,
    session_dir: String,
    verification_sha256: String,
    evaluation_file: String,
    evaluation_file_sha256: String,
    generation_manifest_sha256: String,
    depth_records: u64,
    trade_records: u64,
}

#[derive(Serialize)]
struct CampaignHandoverResultV1 {
    predecessor_generation_index: u64,
    successor_generation_index: u64,
    proof_sha256: String,
    proof_file: String,
    proof_file_sha256: String,
}

#[derive(Serialize)]
struct CampaignManifestV1 {
    schema: &'static str,
    status: &'static str,
    campaign_id: String,
    symbol: String,
    total_duration_s: u64,
    rotation_s: u64,
    overlap_s: u64,
    segment_s: u64,
    started_wall_ns: u64,
    finished_wall_ns: u64,
    spec_revision: &'static str,
    credentials: &'static str,
    order_entry: &'static str,
    executable_sha256: String,
    capture_executable_sha256: String,
    public_config_sha256: String,
    startup_file: &'static str,
    startup_sha256: String,
    journal_file: &'static str,
    journal_boundary: &'static str,
    journal_precommit_records: u64,
    journal_precommit_sha256: String,
    supervisor_gap_count: u64,
    generations: Vec<CampaignGenerationResultV1>,
    handovers: Vec<CampaignHandoverResultV1>,
}

fn unix_ns() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system time before epoch: {error}"))?
            .as_nanos(),
    )
    .map_err(|_| "wall time overflow".to_owned())
}

fn elapsed_ns(origin: Instant) -> Result<u64> {
    u64::try_from(origin.elapsed().as_nanos()).map_err(|_| "monotonic time overflow".to_owned())
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
    // Keep the large I/O buffer on the heap. Windows worker threads and the
    // executable entry point commonly have a 1 MiB stack, so a 1 MiB local
    // array can overflow before the campaign has written its startup record.
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

fn parse_event_stream_flag(value: Option<String>) -> Result<bool> {
    match value.as_deref() {
        None => Ok(false),
        Some("--event-stream") => Ok(true),
        Some(_) => Err("unknown trailing raw_campaign argument".to_owned()),
    }
}

/// Test-only silent-stall fault directive at the campaign layer.  The lane
/// filter is resolved by the hot-redundant supervisor before this campaign is
/// launched, so the variable must already be the lane-free
/// `<stream>:<after-s>` form.  Strict parsing fails closed.
fn parse_fault_silent_stall_env(value: Option<&str>) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
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
    Ok(Some(format!("{}:{}", parts[0], after_s)))
}

fn failure_for_observed_exit(generation_index: u64, success: bool) -> Option<String> {
    (!success)
        .then(|| format!("generation {generation_index} exited without COMPLETE terminal evidence"))
}

fn should_publish_campaign_heartbeat(failure_became_durable: bool, since_last: Duration) -> bool {
    failure_became_durable || since_last >= Duration::from_secs(5)
}

fn ceil_duration_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
}

/// Reserves a bounded monotonic interval between the predecessor deadline and
/// the successor root-segment boundary. Without this guard both events occur
/// at the same nominal instant, so independent socket delivery and final fsync
/// scheduling can leave B a few records behind A even when overlap is healthy.
/// The proof remains strict: the guard creates time; it never invents data.
fn handover_seal_guard_seconds(overlap_s: u64) -> Result<u64> {
    if overlap_s < 2 {
        return Err("overlap-s must leave at least one second for a handover guard".to_owned());
    }
    Ok((overlap_s / 10).clamp(1, MAX_HANDOVER_SEAL_GUARD_S))
}

fn maximum_generation_duration_seconds(rotation_s: u64, overlap_s: u64) -> Result<u64> {
    let guard_s = handover_seal_guard_seconds(overlap_s)?;
    rotation_s
        .checked_add(overlap_s)
        .and_then(|duration| duration.checked_sub(guard_s))
        .ok_or_else(|| "guarded generation duration overflow/underflow".to_owned())
}

fn candidate_duration_seconds(
    remaining: Duration,
    overlap_s: u64,
    maximum_generation_s: u64,
) -> Option<u64> {
    let rounded = ceil_duration_seconds(remaining);
    (rounded >= overlap_s).then_some(rounded.min(maximum_generation_s))
}

/// Returns the next candidate's absolute campaign slot and requested duration.
///
/// Planned rotation is anchored to `campaign origin + slot * rotation`; TLS,
/// snapshot and proof latency must not move later slots.  Duration is also
/// derived from that immutable slot, so a reasonably late process launch does
/// not silently delete the final qualification generation.  A caller must
/// still reject launch once `slot_start + overlap` has elapsed.
fn planned_candidate(
    total_s: u64,
    rotation_s: u64,
    overlap_s: u64,
    maximum_generation_s: u64,
    slot: u64,
) -> Result<Option<(u64, u64)>> {
    let start_s = slot
        .checked_mul(rotation_s)
        .ok_or_else(|| "planned rotation start overflow".to_owned())?;
    let Some(remaining_s) = total_s.checked_sub(start_s) else {
        return Ok(None);
    };
    if remaining_s < overlap_s {
        return Ok(None);
    }
    let next_start_s = start_s
        .checked_add(rotation_s)
        .ok_or_else(|| "planned next rotation start overflow".to_owned())?;
    let next_remaining_s = total_s.saturating_sub(next_start_s);
    let is_final_candidate = next_remaining_s < overlap_s;
    let requested_s = if is_final_candidate {
        remaining_s.max(overlap_s.saturating_add(FINAL_HANDOVER_TAIL_S))
    } else {
        remaining_s
    };
    Ok(Some((start_s, requested_s.min(maximum_generation_s))))
}

fn planned_launch_window_open(elapsed: Duration, start_s: u64, overlap_s: u64) -> Result<bool> {
    let end_s = start_s
        .checked_add(overlap_s)
        .ok_or_else(|| "planned rotation launch window overflow".to_owned())?;
    Ok(elapsed < Duration::from_secs(end_s))
}

fn require_empty_transport_warm_slot(unregistered_generations: usize) -> Result<()> {
    if unregistered_generations == 0 {
        Ok(())
    } else {
        Err(
            "planned transport slot arrived while one warm successor was still unregistered"
                .to_owned(),
        )
    }
}

fn validate_market_freshness(
    telemetry_mono_ns: u64,
    duration_s: u64,
    depth_last_socket_activity_mono_ns: u64,
    depth_last_market_message_mono_ns: u64,
    trade_last_socket_activity_mono_ns: u64,
    trade_last_market_message_mono_ns: u64,
) -> Result<()> {
    let active_end_ns = duration_s.saturating_mul(1_000_000_000);
    if telemetry_mono_ns < MARKET_FRESHNESS_STARTUP_GRACE_NS || telemetry_mono_ns >= active_end_ns {
        return Ok(());
    }
    for (stream, last_socket, last_market) in [
        (
            "depth",
            depth_last_socket_activity_mono_ns,
            depth_last_market_message_mono_ns,
        ),
        (
            "trade",
            trade_last_socket_activity_mono_ns,
            trade_last_market_message_mono_ns,
        ),
    ] {
        if last_market == 0
            || last_market > telemetry_mono_ns
            || last_market > last_socket
            || telemetry_mono_ns.saturating_sub(last_market) > MARKET_FRESHNESS_DEADLINE_NS
        {
            return Err(format!(
                "{stream} market-message freshness deadline exceeded while generation was active"
            ));
        }
    }
    Ok(())
}

fn register_server_shutdown_publication(
    publications: &mut BTreeMap<String, ExpectedServerShutdownPublicationV1>,
    publication: ExpectedServerShutdownPublicationV1,
) -> Result<bool> {
    if let Some(previous) = publications.get(&publication.stream) {
        if previous == &publication {
            return Ok(false);
        }
        if publication.frame_index <= previous.frame_index {
            return Err("durable serverShutdown publication conflicts or regresses".to_owned());
        }
    }
    publications.insert(publication.stream.clone(), publication);
    Ok(true)
}

fn spawn_reader<R: Read + Send + 'static>(
    reader: R,
    generation: u64,
    stdout: bool,
    sender: Sender<ProcessOutput>,
) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else { break };
            let message = if stdout {
                ProcessOutput::Stdout { generation, line }
            } else {
                ProcessOutput::Stderr { generation, line }
            };
            if sender.send(message).is_err() {
                break;
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn launch_generation(
    capture_executable: &Path,
    expected_capture_sha256: &str,
    expected_public_config_sha256: &str,
    generations_root: &Path,
    control_root: &Path,
    symbol: &str,
    generation_index: u64,
    duration_s: u64,
    segment_s: u64,
    origin: Instant,
    output_sender: &Sender<ProcessOutput>,
    fault_silent_stall: &Option<String>,
) -> Result<ChildState> {
    if sha256_file(capture_executable)? != expected_capture_sha256 {
        return Err(format!(
            "capture executable drift before generation {generation_index}"
        ));
    }
    if sha256_file(Path::new("config/public.json"))? != expected_public_config_sha256 {
        return Err(format!(
            "public config drift before generation {generation_index}"
        ));
    }
    let stop_file = control_root.join(format!("generation-{generation_index:03}.stop"));
    let mut command = Command::new(capture_executable);
    command
        .arg(symbol)
        .arg(generation_index.to_string())
        .arg(duration_s.to_string())
        .arg(segment_s.to_string())
        .arg(generations_root)
        .env("BINANCE_LOB_EVENT_STREAM", "1")
        .env("BINANCE_LOB_STOP_FILE", &stop_file)
        .env(
            "BINANCE_LOB_EXPECTED_CAPTURE_SHA256",
            expected_capture_sha256,
        )
        .env(
            "BINANCE_LOB_EXPECTED_PUBLIC_CONFIG_SHA256",
            expected_public_config_sha256,
        );
    if let Some(cleaned) = fault_silent_stall {
        command.env("BINANCE_LOB_FAULT_SILENT_STALL", cleaned);
    } else {
        command.env_remove("BINANCE_LOB_FAULT_SILENT_STALL");
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn generation {generation_index}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "capture child lacks stdout pipe".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "capture child lacks stderr pipe".to_owned())?;
    spawn_reader(stdout, generation_index, true, output_sender.clone());
    spawn_reader(stderr, generation_index, false, output_sender.clone());
    Ok(ChildState {
        generation_index,
        symbol: symbol.to_owned(),
        launch_mono_ns: elapsed_ns(origin)?,
        duration_s,
        child,
        stop_file,
        session_id: None,
        session_dir: None,
        startup_sha256: None,
        connections: BTreeMap::new(),
        snapshot: None,
        root_segments: BTreeMap::new(),
        last_segments: BTreeMap::new(),
        telemetry_durable_offset: 0,
        last_telemetry_index: None,
        last_telemetry_mono_ns: 0,
        last_telemetry_sha256: None,
        last_heartbeat: Instant::now(),
        last_depth_received: 0,
        last_depth_durable: 0,
        last_trade_received: 0,
        last_trade_durable: 0,
        last_depth_socket_activity_mono_ns: 0,
        last_trade_socket_activity_mono_ns: 0,
        last_depth_market_message_mono_ns: 0,
        last_trade_market_message_mono_ns: 0,
        pending_server_shutdown_epochs: Vec::new(),
        last_server_shutdown: BTreeMap::new(),
        terminal_status: None,
        exit_status: None,
        exit_seen: None,
        exit_journaled: false,
        supervisor_registered: generation_index == 0,
        disconnect_reported: false,
    })
}

fn value_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("process event lacks string {field}"))
}

fn value_u64(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("process event lacks integer {field}"))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_published_telemetry(value: &Value, child: &ChildState) -> Result<Value> {
    let expected_index = value_u64(value, "telemetry_record_index")?;
    let expected_previous = child
        .last_telemetry_index
        .map_or(0, |index| index.saturating_add(1));
    if expected_index != expected_previous {
        return Err("telemetry publication index is not exactly consecutive".to_owned());
    }
    let expected_hash = value_str(value, "telemetry_record_sha256")?;
    if !valid_sha256(expected_hash)
        || child
            .last_telemetry_sha256
            .as_deref()
            .is_some_and(|previous| previous == expected_hash)
    {
        return Err("telemetry publication digest is invalid or repeated".to_owned());
    }
    let durable_offset = value_u64(value, "telemetry_durable_through_offset")?;
    let delta = durable_offset
        .checked_sub(child.telemetry_durable_offset)
        .ok_or_else(|| "telemetry durable offset regressed".to_owned())?;
    if delta == 0 || delta > MAX_TELEMETRY_RECORD_BYTES {
        return Err("telemetry durable publication has an invalid record length".to_owned());
    }
    let session = child
        .session_dir
        .as_ref()
        .ok_or_else(|| "telemetry published before PROCESS_STARTED".to_owned())?;
    let path = session.join("telemetry.jsonl");
    let mut file = File::open(&path)
        .map_err(|error| format!("open published telemetry {}: {error}", path.display()))?;
    if file
        .metadata()
        .map_err(|error| format!("stat published telemetry {}: {error}", path.display()))?
        .len()
        < durable_offset
    {
        return Err("telemetry event points beyond the durable file length".to_owned());
    }
    file.seek(SeekFrom::Start(child.telemetry_durable_offset))
        .map_err(|error| format!("seek published telemetry: {error}"))?;
    let mut bytes = vec![0_u8; usize::try_from(delta).map_err(|_| "telemetry delta overflow")?];
    file.read_exact(&mut bytes)
        .map_err(|error| format!("read published telemetry: {error}"))?;
    if bytes.last() != Some(&b'\n')
        || bytes.iter().filter(|byte| **byte == b'\n').count() != 1
        || sha256_hex(&bytes) != expected_hash
    {
        return Err("telemetry event does not bind one exact durable JSONL record".to_owned());
    }
    let record: Value = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|error| format!("invalid published telemetry JSON: {error}"))?;
    if value_str(&record, "schema")? != "CaptureTelemetryV1"
        || value_u64(&record, "record_index")? != expected_index
        || value_u64(&record, "mono_ns")? != value_u64(value, "telemetry_mono_ns")?
    {
        return Err("telemetry event identity differs from its durable record".to_owned());
    }
    for field in [
        "depth_received",
        "depth_durable",
        "depth_queue_records",
        "depth_last_socket_activity_mono_ns",
        "depth_last_market_message_mono_ns",
        "depth_last_durable_mono_ns",
        "trade_received",
        "trade_durable",
        "trade_queue_records",
        "trade_last_socket_activity_mono_ns",
        "trade_last_market_message_mono_ns",
        "trade_last_durable_mono_ns",
    ] {
        if value_u64(&record, field)? != value_u64(value, field)? {
            return Err(format!(
                "telemetry event field {field} differs from durable record"
            ));
        }
    }
    Ok(record)
}

fn handle_stdout_event(
    value: &Value,
    child: &mut ChildState,
    generations_root: &Path,
) -> Result<()> {
    let event = value_str(value, "event")?;
    let expected_schema = match event {
        "PROCESS_STARTED" => "CaptureProcessEventV1",
        "TRANSPORT_CONNECTED" => "TransportConnectedProcessEventV1",
        "SNAPSHOT_DURABLE" => "SnapshotDurableProcessEventV1",
        "SEGMENT_DURABLE" => "SegmentDurableProcessEventV1",
        "SERVER_SHUTDOWN_DURABLE" => "ServerShutdownDurableProcessEventV1",
        "HEARTBEAT_DURABLE" => "HeartbeatProcessEventV1",
        "PROCESS_TERMINAL" => "CaptureTerminalProcessEventV1",
        other => return Err(format!("unknown child process event: {other}")),
    };
    if value_str(value, "schema")? != expected_schema {
        return Err(format!("{event} uses the wrong event schema"));
    }
    let published_session = value_str(value, "session_id")?;
    if event != "PROCESS_STARTED" && child.session_id.is_none() {
        return Err(format!("{event} arrived before PROCESS_STARTED"));
    }
    if child
        .session_id
        .as_deref()
        .is_some_and(|old| old != published_session)
    {
        return Err("child process event changed session ID".to_owned());
    }
    match event {
        "PROCESS_STARTED" => {
            if child.session_id.is_some()
                || value_u64(value, "generation_index")? != child.generation_index
                || value_str(value, "symbol")? != child.symbol
                || value_u64(value, "process_id")? == 0
                || value_str(value, "spec_revision")? != SPEC_REVISION
                || !valid_sha256(value_str(value, "startup_manifest_sha256")?)
            {
                return Err("duplicate or wrong PROCESS_STARTED".to_owned());
            }
            let session_id = value_str(value, "session_id")?.to_owned();
            let session_dir = PathBuf::from(value_str(value, "session_dir")?);
            if session_dir.parent() != Some(generations_root)
                || session_dir.file_name().and_then(|name| name.to_str()) != Some(&session_id)
            {
                return Err("child session directory escaped generation root".to_owned());
            }
            child.session_id = Some(session_id);
            child.session_dir = Some(session_dir);
            child.startup_sha256 = Some(value_str(value, "startup_manifest_sha256")?.to_owned());
        }
        "TRANSPORT_CONNECTED" => {
            let connection = &value["connection"];
            let stream = value_str(connection, "stream")?;
            if !matches!(stream, "depth" | "trade") {
                return Err("transport event uses an unknown stream".to_owned());
            }
            let expected_uri = match stream {
                "depth" => format!(
                    "wss://data-stream.binance.vision:443/ws/{}@depth@100ms?timeUnit=MICROSECOND",
                    child.symbol.to_ascii_lowercase()
                ),
                "trade" => format!(
                    "wss://data-stream.binance.vision:443/ws/{}@trade?timeUnit=MICROSECOND",
                    child.symbol.to_ascii_lowercase()
                ),
                _ => String::new(),
            };
            let epoch = value_str(connection, "connection_epoch")?;
            let metadata_file = value_str(value, "metadata_file")?;
            let expected_metadata_file = format!("transport-{stream}.json");
            let metadata_sha256 = value_str(value, "metadata_sha256")?;
            if metadata_file != expected_metadata_file || !valid_sha256(metadata_sha256) {
                return Err("transport metadata reference is invalid".to_owned());
            }
            let session = child
                .session_dir
                .as_ref()
                .ok_or_else(|| "transport published before PROCESS_STARTED".to_owned())?;
            let metadata_path = session.join(metadata_file);
            let metadata_file_state = fs::symlink_metadata(&metadata_path).map_err(|error| {
                format!(
                    "stat transport metadata {}: {error}",
                    metadata_path.display()
                )
            })?;
            let metadata_bytes = fs::read(&metadata_path).map_err(|error| {
                format!(
                    "read transport metadata {}: {error}",
                    metadata_path.display()
                )
            })?;
            let metadata: Value = serde_json::from_slice(&metadata_bytes)
                .map_err(|error| format!("invalid durable transport metadata: {error}"))?;
            if value_u64(connection, "websocket_http_status")? != 101
                || value_str(connection, "uri")? != expected_uri
                || value_str(connection, "local_endpoint")?.trim().is_empty()
                || value_str(connection, "remote_endpoint")?.trim().is_empty()
                || epoch.trim().is_empty()
                || metadata_file_state.file_type().is_symlink()
                || !metadata_file_state.is_file()
                || sha256_hex(&metadata_bytes) != metadata_sha256
                || value_str(&metadata, "schema")? != "TransportMetadataV1"
                || value_str(&metadata, "session_id")? != published_session
                || value_u64(&metadata, "generation_index")? != child.generation_index
                || value_str(&metadata, "symbol")? != child.symbol
                || value_str(&metadata, "spec_revision")? != SPEC_REVISION
                || metadata["connection"] != *connection
                || child.connections.values().any(|old| old == epoch)
                || child
                    .connections
                    .insert(stream.to_owned(), epoch.to_owned())
                    .is_some()
            {
                return Err("invalid or duplicate transport connection event".to_owned());
            }
        }
        "SNAPSHOT_DURABLE" => {
            if child.snapshot.is_some()
                || child.connections.len() != 2
                || value_str(value, "raw_file")? != "snapshot.bnraw"
                || value_str(value, "http_metadata_file")? != "snapshot-http.json"
                || value_u64(value, "durable_through_offset")? == 0
                || !valid_sha256(value_str(value, "last_record_sha256")?)
                || !valid_sha256(value_str(value, "http_metadata_sha256")?)
            {
                return Err("duplicate snapshot publication".to_owned());
            }
            child.snapshot = Some(ExpectedSnapshotPublicationV1 {
                raw_file: value_str(value, "raw_file")?.to_owned(),
                durable_through_offset: value_u64(value, "durable_through_offset")?,
                last_record_sha256: value_str(value, "last_record_sha256")?.to_owned(),
                http_metadata_file: value_str(value, "http_metadata_file")?.to_owned(),
                http_metadata_sha256: value_str(value, "http_metadata_sha256")?.to_owned(),
            });
        }
        "SEGMENT_DURABLE" => {
            let publication: ExpectedSegmentPublicationV1 =
                serde_json::from_value(value["segment"].clone())
                    .map_err(|error| format!("invalid segment publication event: {error}"))?;
            let stream = publication.stream.as_str();
            let expected_epoch = child
                .connections
                .get(stream)
                .ok_or_else(|| "segment published before its transport connection".to_owned())?;
            let expected_raw = format!("segment-{:06}.bnraw", publication.segment_index);
            let record_span = publication
                .last_frame_index
                .checked_sub(publication.first_frame_index)
                .and_then(|span| span.checked_add(1));
            if child.snapshot.is_none()
                || publication.schema != "DurableSegmentEventV1"
                || !matches!(stream, "depth" | "trade")
                || &publication.connection_epoch != expected_epoch
                || publication.raw_file != expected_raw
                || publication.records == 0
                || record_span != Some(publication.records)
                || publication.durable_through_offset == 0
                || publication.manifest_record_index != publication.segment_index
                || publication.manifest_durable_through_offset == 0
                || !valid_sha256(&publication.previous_segment_terminal_sha256)
                || !valid_sha256(&publication.terminal_record_sha256)
                || !valid_sha256(&publication.manifest_record_sha256)
            {
                return Err("invalid durable segment publication".to_owned());
            }
            if let Some(previous) = child.last_segments.get(stream) {
                if publication.segment_index != previous.segment_index + 1
                    || publication.first_frame_index != previous.last_frame_index + 1
                    || publication.previous_segment_terminal_sha256
                        != previous.terminal_record_sha256
                {
                    return Err("segment publication lineage is not exactly consecutive".to_owned());
                }
            } else if publication.segment_index != 0
                || publication.first_frame_index != 0
                || publication.previous_segment_terminal_sha256 != "0".repeat(64)
            {
                return Err("first segment publication is not a root".to_owned());
            }
            if publication.segment_index == 0 {
                child
                    .root_segments
                    .insert(stream.to_owned(), publication.clone());
            }
            child.last_segments.insert(stream.to_owned(), publication);
        }
        "SERVER_SHUTDOWN_DURABLE" => {
            let publication: ExpectedServerShutdownPublicationV1 =
                serde_json::from_value(value["shutdown"].clone())
                    .map_err(|error| format!("invalid durable serverShutdown event: {error}"))?;
            let expected_epoch = child
                .connections
                .get(&publication.stream)
                .ok_or_else(|| "serverShutdown published before transport connection".to_owned())?;
            let expected_raw = format!("segment-{:06}.bnraw", publication.segment_index);
            if publication.schema != "DurableServerShutdownEventV1"
                || !matches!(publication.stream.as_str(), "depth" | "trade")
                || &publication.connection_epoch != expected_epoch
                || publication.raw_file != expected_raw
                || publication.durable_record_count == 0
                || publication.durable_through_offset == 0
                || publication.receive_mono_ns == 0
                || !valid_sha256(&publication.last_record_sha256)
            {
                return Err("durable serverShutdown publication is invalid/regressed".to_owned());
            }
            let epoch = publication.connection_epoch.clone();
            if register_server_shutdown_publication(&mut child.last_server_shutdown, publication)? {
                child.pending_server_shutdown_epochs.push(epoch);
            }
        }
        "HEARTBEAT_DURABLE" => {
            let record = read_published_telemetry(value, child)?;
            let telemetry_index = value_u64(&record, "record_index")?;
            let telemetry_mono_ns = value_u64(&record, "mono_ns")?;
            let depth_received = value_u64(&record, "depth_received")?;
            let depth_durable = value_u64(&record, "depth_durable")?;
            let trade_received = value_u64(&record, "trade_received")?;
            let trade_durable = value_u64(&record, "trade_durable")?;
            let depth_socket = value_u64(&record, "depth_last_socket_activity_mono_ns")?;
            let trade_socket = value_u64(&record, "trade_last_socket_activity_mono_ns")?;
            let depth_market = value_u64(&record, "depth_last_market_message_mono_ns")?;
            let trade_market = value_u64(&record, "trade_last_market_message_mono_ns")?;
            if depth_received < child.last_depth_received
                || depth_durable < child.last_depth_durable
                || trade_received < child.last_trade_received
                || trade_durable < child.last_trade_durable
                || depth_durable > depth_received
                || trade_durable > trade_received
                || telemetry_mono_ns <= child.last_telemetry_mono_ns
                || depth_socket < child.last_depth_socket_activity_mono_ns
                || trade_socket < child.last_trade_socket_activity_mono_ns
                || depth_market < child.last_depth_market_message_mono_ns
                || trade_market < child.last_trade_market_message_mono_ns
                || depth_socket > telemetry_mono_ns
                || trade_socket > telemetry_mono_ns
                || depth_market > depth_socket
                || trade_market > trade_socket
                || telemetry_mono_ns.saturating_sub(depth_socket) > 60_000_000_000
                || telemetry_mono_ns.saturating_sub(trade_socket) > 60_000_000_000
            {
                return Err(
                    "child durable telemetry regressed, froze, or became impossible".to_owned(),
                );
            }
            validate_market_freshness(
                telemetry_mono_ns,
                child.duration_s,
                depth_socket,
                depth_market,
                trade_socket,
                trade_market,
            )?;
            child.telemetry_durable_offset = value_u64(value, "telemetry_durable_through_offset")?;
            child.last_telemetry_index = Some(telemetry_index);
            child.last_telemetry_mono_ns = telemetry_mono_ns;
            child.last_telemetry_sha256 =
                Some(value_str(value, "telemetry_record_sha256")?.to_owned());
            child.last_depth_received = depth_received;
            child.last_depth_durable = depth_durable;
            child.last_trade_received = trade_received;
            child.last_trade_durable = trade_durable;
            child.last_depth_socket_activity_mono_ns = depth_socket;
            child.last_trade_socket_activity_mono_ns = trade_socket;
            child.last_depth_market_message_mono_ns = depth_market;
            child.last_trade_market_message_mono_ns = trade_market;
            child.last_heartbeat = Instant::now();
        }
        "PROCESS_TERMINAL" => {
            let status = value_str(value, "status")?;
            if child.terminal_status.is_some()
                || !matches!(status, "COMPLETE" | "FAILED")
                || value_str(value, "generation_manifest")? != "generation.json"
                || (status == "COMPLETE"
                    && (child.snapshot.is_none()
                        || child.root_segments.len() != 2
                        || child.last_telemetry_index.is_none()))
            {
                return Err("duplicate child terminal event".to_owned());
            }
            child.terminal_status = Some(status.to_owned());
        }
        _ => unreachable!("event schema match exhaustively validated"),
    }
    Ok(())
}

fn observe_available_candidate_facts(
    supervisor: &mut RawGenerationSupervisor,
    child: &ChildState,
    now_ns: u64,
) -> Result<()> {
    supervisor.observe_candidate_fact(CandidateFact::DepthConnected, now_ns)?;
    supervisor.observe_candidate_fact(CandidateFact::TradeConnected, now_ns)?;
    if child.snapshot.is_some() {
        supervisor.observe_candidate_fact(CandidateFact::SnapshotPersisted, now_ns)?;
    }
    if child.root_segments.contains_key("depth") {
        supervisor.observe_candidate_fact(CandidateFact::DepthDurable, now_ns)?;
    }
    if child.root_segments.contains_key("trade") {
        supervisor.observe_candidate_fact(CandidateFact::TradeDurable, now_ns)?;
    }
    Ok(())
}

fn capture_stop_request_bytes(
    session_id: &str,
    reason: &str,
    campaign_failure_record_sha256: &str,
) -> Result<Vec<u8>> {
    if reason.trim().is_empty() || !valid_sha256(campaign_failure_record_sha256) {
        return Err("capture stop request lacks its exact durable failure cause".to_owned());
    }
    let request = CaptureStopRequestV1 {
        schema: "CaptureStopRequestV1",
        session_id,
        reason,
        campaign_failure_record_sha256,
    };
    let mut bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("serialize capture stop request: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn request_stop(
    child: &ChildState,
    reason: &str,
    campaign_failure_record_sha256: &str,
) -> Result<()> {
    let Some(session_id) = &child.session_id else {
        return Ok(());
    };
    if child.exit_status.is_some() || child.stop_file.exists() {
        return Ok(());
    }
    let bytes = capture_stop_request_bytes(session_id, reason, campaign_failure_record_sha256)?;
    write_synced_new(&child.stop_file, &bytes)
}

fn scan_campaign_journal(path: &Path) -> Result<(u64, String)> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut records = 0_u64;
    let mut previous = "0".repeat(64);
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| format!("read campaign journal: {error}"))?;
        let envelope: CampaignJournalEnvelopeV1 = serde_json::from_str(&line)
            .map_err(|error| format!("invalid campaign journal JSON: {error}"))?;
        let bytes = serde_json::to_vec(&envelope.body)
            .map_err(|error| format!("reserialize campaign journal body: {error}"))?;
        let digest = sha256_hex(&bytes);
        if envelope.body.schema != "RawCampaignJournalRecordV1"
            || envelope.body.record_index != records
            || envelope.body.previous_record_sha256 != previous
            || envelope.record_sha256 != digest
        {
            return Err("campaign journal hash chain is invalid".to_owned());
        }
        records += 1;
        previous = digest;
    }
    if records == 0 {
        return Err("campaign journal is empty".to_owned());
    }
    Ok((records, previous))
}

fn stream_records(verification: &VerifiedGenerationV1, name: &str) -> Result<u64> {
    verification
        .streams
        .iter()
        .find(|stream| stream.name == name)
        .map(|stream| stream.records)
        .ok_or_else(|| format!("verified generation lacks {name}"))
}

fn run() -> Result<PathBuf> {
    let mut args = env::args();
    let executable_arg = args.next().unwrap_or_else(|| "raw_campaign".to_owned());
    let symbol = args.next().ok_or_else(|| {
        format!(
            "usage: {executable_arg} <BTCUSDT|ETHUSDT> <total-s> <rotation-s> <overlap-s> <segment-s> [output-root] [--event-stream]"
        )
    })?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err("symbol outside fixed scope".to_owned());
    }
    let total_s = parse_positive(args.next(), "total-s", 7 * 24 * 3_600)?;
    let rotation_s = parse_positive(args.next(), "rotation-s", 86_000)?;
    let overlap_s = parse_positive(args.next(), "overlap-s", 3_600)?;
    let segment_s = parse_positive(args.next(), "segment-s", 3_600)?;
    if overlap_s != segment_s
        || rotation_s % segment_s != 0
        || rotation_s + overlap_s > 86_300
        || total_s < overlap_s
    {
        return Err(
            "require overlap-s == segment-s, rotation multiple of segment, and generation <= 86,300 s"
                .to_owned(),
        );
    }
    let maximum_generation_s = maximum_generation_duration_seconds(rotation_s, overlap_s)?;
    let output_root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/raw-campaigns"));
    let _managed_event_stream = parse_event_stream_flag(args.next())?;
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let fault_silent_stall =
        parse_fault_silent_stall_env(env::var("BINANCE_LOB_FAULT_SILENT_STALL").ok().as_deref())?;
    validate_public_capture_config(Path::new("config/public.json"))?;
    let executable = env::current_exe().map_err(|error| format!("current executable: {error}"))?;
    let capture_executable = executable.with_file_name(if cfg!(windows) {
        "segmented_capture.exe"
    } else {
        "segmented_capture"
    });
    if !capture_executable.is_file() {
        return Err(format!(
            "verified capture executable is absent: {}",
            capture_executable.display()
        ));
    }
    let campaign_id = format!(
        "{}-{}-raw-{}",
        unix_ns()?,
        symbol,
        &Uuid::new_v4().simple().to_string()[..12]
    );
    fs::create_dir_all(&output_root)
        .map_err(|error| format!("create {}: {error}", output_root.display()))?;
    let campaign_dir = output_root.join(&campaign_id);
    fs::create_dir(&campaign_dir)
        .map_err(|error| format!("create {}: {error}", campaign_dir.display()))?;
    let generations_root = campaign_dir.join("generations");
    let handovers_root = campaign_dir.join("handovers");
    let evaluations_root = campaign_dir.join("evaluations");
    let control_root = campaign_dir.join("control");
    for directory in [
        &generations_root,
        &handovers_root,
        &evaluations_root,
        &control_root,
    ] {
        fs::create_dir(directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
    }
    let executable_sha256 = sha256_file(&executable)?;
    let capture_executable_sha256 = sha256_file(&capture_executable)?;
    let public_config_sha256 = sha256_file(Path::new("config/public.json"))?;
    let started_wall_ns = unix_ns()?;
    let startup = CampaignStartupV1 {
        schema: "RawCampaignStartupV1",
        campaign_id: campaign_id.clone(),
        symbol: symbol.clone(),
        total_duration_s: total_s,
        rotation_s,
        overlap_s,
        segment_s,
        started_wall_ns,
        process_id: std::process::id(),
        executable_sha256: executable_sha256.clone(),
        capture_executable_sha256: capture_executable_sha256.clone(),
        public_config_sha256: public_config_sha256.clone(),
        spec_revision: SPEC_REVISION,
        credentials: "NONE",
        order_entry: "ABSENT",
    };
    let mut startup_bytes = serde_json::to_vec_pretty(&startup)
        .map_err(|error| format!("serialize campaign startup: {error}"))?;
    startup_bytes.push(b'\n');
    write_synced_new(&campaign_dir.join("campaign-startup.json"), &startup_bytes)?;
    let startup_sha256 = sha256_hex(&startup_bytes);
    let origin = Instant::now();
    let deadline = origin + Duration::from_secs(total_s);
    let journal_path = campaign_dir.join("campaign-events.jsonl");
    let mut journal = CampaignJournalWriter::create(&journal_path)?;
    journal.append(
        origin,
        None,
        "CAMPAIGN",
        serde_json::json!({
            "event": "CAMPAIGN_STARTED",
            "campaign_id": campaign_id,
            "startup_sha256": startup_sha256
        }),
    )?;
    if let Some(cleaned) = &fault_silent_stall {
        let parts: Vec<&str> = cleaned.split(':').collect();
        journal.append(
            origin,
            None,
            "CAMPAIGN",
            serde_json::json!({
                "event": "FAULT_INJECTED_SILENT_STALL",
                "stream": parts[0],
                "after_s": parts[1].parse::<u64>().map_err(|error| {
                    format!("fault after-s reparse failed: {error}")
                })?,
                "child_environment": cleaned
            }),
        )?;
    }
    let (output_tx, output_rx) = mpsc::channel();
    let (proof_tx, proof_rx): (Sender<ProofCompletion>, Receiver<ProofCompletion>) =
        mpsc::channel();
    let first_duration = total_s.min(maximum_generation_s);
    let first = launch_generation(
        &capture_executable,
        &capture_executable_sha256,
        &public_config_sha256,
        &generations_root,
        &control_root,
        &symbol,
        0,
        first_duration,
        segment_s,
        origin,
        &output_tx,
        &fault_silent_stall,
    )?;
    journal.append(
        origin,
        Some(0),
        "CAMPAIGN",
        serde_json::json!({"event":"GENERATION_LAUNCHED","duration_s":first_duration}),
    )?;
    let mut children = vec![first];
    let config = RawSupervisorConfig {
        segment_interval_ns: segment_s.saturating_mul(1_000_000_000),
        planned_rotation_age_ns: rotation_s.saturating_mul(1_000_000_000),
        active_max_age_ns: (maximum_generation_s + PROOF_MARGIN_S).saturating_mul(1_000_000_000),
        candidate_timeout_ns: (overlap_s + PROOF_MARGIN_S).saturating_mul(1_000_000_000),
        backoff_initial_ns: 1_000_000_000,
        backoff_max_ns: 60_000_000_000,
    };
    let mut supervisor: Option<RawGenerationSupervisor> = None;
    let mut pending_candidate = None;
    let mut pending_server_shutdown_epoch: Option<String> = None;
    let mut next_planned_slot = 1_u64;
    let mut proof_started = BTreeMap::<u64, Instant>::new();
    let mut handover_proofs = BTreeMap::<u64, RawGenerationHandoverProofV1>::new();
    let mut failure: Option<String> = None;
    let mut failure_record_sha256: Option<String> = None;
    let mut failure_started: Option<Instant> = None;
    let mut last_status_print = Instant::now() - Duration::from_secs(10);

    loop {
        while let Ok(output) = output_rx.try_recv() {
            match output {
                ProcessOutput::Stdout { generation, line } => {
                    let payload = match serde_json::from_str::<Value>(&line) {
                        Ok(payload) => payload,
                        Err(error) => {
                            let payload = serde_json::json!({"text":line});
                            journal.append(origin, Some(generation), "CHILD_STDOUT", payload)?;
                            failure.get_or_insert(format!(
                                "generation {generation} emitted non-JSON stdout: {error}"
                            ));
                            continue;
                        }
                    };
                    journal.append(origin, Some(generation), "CHILD_STDOUT", payload.clone())?;
                    let child = children
                        .iter_mut()
                        .find(|child| child.generation_index == generation)
                        .ok_or_else(|| "stdout references unknown generation".to_owned())?;
                    if let Err(error) = handle_stdout_event(&payload, child, &generations_root) {
                        failure.get_or_insert(error);
                    }
                }
                ProcessOutput::Stderr { generation, line } => {
                    journal.append(
                        origin,
                        Some(generation),
                        "CHILD_STDERR",
                        serde_json::json!({"text":line.clone()}),
                    )?;
                    failure
                        .get_or_insert(format!("generation {generation} emitted stderr: {line}"));
                }
            }
        }

        for child in &mut children {
            if child.exit_status.is_none()
                && let Some(status) = child
                    .child
                    .try_wait()
                    .map_err(|error| format!("poll generation process: {error}"))?
            {
                child.exit_status = Some(status);
                child.exit_seen = Some(Instant::now());
                let success = child.exit_status.as_ref().is_some_and(ExitStatus::success);
                if let Some(exit_failure) =
                    failure_for_observed_exit(child.generation_index, success)
                {
                    failure.get_or_insert(exit_failure);
                }
            }
            if !child.exit_journaled
                && let Some(status) = &child.exit_status
                && (child.terminal_status.is_some() || !status.success())
            {
                journal.append(
                    origin,
                    Some(child.generation_index),
                    "CAMPAIGN",
                    serde_json::json!({
                        "event":"GENERATION_EXITED",
                        "success":status.success(),
                        "code":status.code()
                    }),
                )?;
                child.exit_journaled = true;
            }
            if child.exit_status.is_none()
                && child.last_heartbeat.elapsed() > HEARTBEAT_DEADLINE
                && origin.elapsed() > STARTUP_DEADLINE
            {
                failure.get_or_insert_with(|| {
                    format!(
                        "generation {} durable heartbeat deadline exceeded",
                        child.generation_index
                    )
                });
            }
            if child.exit_status.is_some()
                && child
                    .exit_seen
                    .is_some_and(|seen| seen.elapsed() > Duration::from_secs(2))
                && !child.terminal_complete()
            {
                failure.get_or_insert_with(|| {
                    format!(
                        "generation {} exited without COMPLETE terminal evidence",
                        child.generation_index
                    )
                });
            }
        }

        let now_ns = elapsed_ns(origin)?;
        if supervisor.is_none()
            && let Some(initial) = children.first()
            && initial.connections.len() == 2
            && initial.session_id.is_some()
        {
            supervisor = Some(RawGenerationSupervisor::new(
                config.clone(),
                initial.identity()?,
                initial.launch_mono_ns,
            )?);
            journal.append(
                origin,
                Some(0),
                "SUPERVISOR",
                serde_json::json!({"event":"INITIAL_ACTIVE_REGISTERED"}),
            )?;
        }

        // Planned transport preparation follows the absolute campaign clock,
        // while ownership still admits exactly one candidate at a time.  A
        // generation launched at the next slot may therefore wait here until
        // the preceding proof promotes.  This prevents proof runtime from
        // accumulating into schedule drift without granting the warmed
        // generation any publication authority.
        if pending_candidate.is_none()
            && let Some(child) = children
                .iter()
                .find(|child| child.generation_index != 0 && !child.supervisor_registered)
        {
            pending_candidate = Some(child.generation_index);
        }

        let shutdown_requests = children
            .iter_mut()
            .flat_map(|child| {
                let generation = child.generation_index;
                child
                    .pending_server_shutdown_epochs
                    .drain(..)
                    .map(move |epoch| (generation, epoch))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for (source_generation, source_epoch) in shutdown_requests {
            let active_source = supervisor.as_ref().is_some_and(|supervisor| {
                supervisor.active().is_some_and(|active| {
                    active.identity.depth_epoch == source_epoch
                        || active.identity.trade_epoch == source_epoch
                })
            });
            if !active_source {
                journal.append(
                    origin,
                    Some(source_generation),
                    "SUPERVISOR",
                    serde_json::json!({
                        "event":"SERVER_SHUTDOWN_IGNORED_NON_ACTIVE",
                        "source_epoch":source_epoch
                    }),
                )?;
                continue;
            }
            if pending_candidate.is_some()
                || supervisor
                    .as_ref()
                    .is_some_and(|supervisor| supervisor.candidate().is_some())
            {
                journal.append(
                    origin,
                    Some(source_generation),
                    "SUPERVISOR",
                    serde_json::json!({
                        "event":"SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
                        "source_epoch":source_epoch
                    }),
                )?;
                continue;
            }
            if failure.is_none() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Some(duration_s) =
                    candidate_duration_seconds(remaining, overlap_s, maximum_generation_s)
                else {
                    failure.get_or_insert(
                        "serverShutdown arrived without enough campaign time for one proven overlap"
                            .to_owned(),
                    );
                    continue;
                };
                let index = children.len() as u64;
                let child = launch_generation(
                    &capture_executable,
                    &capture_executable_sha256,
                    &public_config_sha256,
                    &generations_root,
                    &control_root,
                    &symbol,
                    index,
                    duration_s,
                    segment_s,
                    origin,
                    &output_tx,
                    &fault_silent_stall,
                )?;
                children.push(child);
                pending_candidate = Some(index);
                pending_server_shutdown_epoch = Some(source_epoch.clone());
                journal.append(
                    origin,
                    Some(index),
                    "CAMPAIGN",
                    serde_json::json!({
                        "event":"GENERATION_LAUNCHED_SERVER_SHUTDOWN",
                        "duration_s":duration_s,
                        "source_generation":source_generation,
                        "source_epoch":source_epoch
                    }),
                )?;
            }
        }

        if let (Some(supervisor), Some(index)) = (&mut supervisor, pending_candidate)
            && let Some(child) = children
                .iter_mut()
                .find(|child| child.generation_index == index)
            && !child.supervisor_registered
            && child.connections.len() == 2
            && child.session_id.is_some()
            && (pending_server_shutdown_epoch.is_some()
                || supervisor.active().is_some_and(|active| {
                    now_ns.saturating_sub(active.opened_mono_ns) >= config.planned_rotation_age_ns
                }))
        {
            if let Some(source_epoch) = pending_server_shutdown_epoch.as_deref() {
                let outcome =
                    supervisor.on_server_shutdown(source_epoch, child.identity()?, now_ns)?;
                if !matches!(
                    outcome,
                    lob_replay::generation_supervisor::ServerShutdownOutcome::CandidateStarted
                ) {
                    return Err(
                        "serverShutdown candidate registration was not exactly one fresh start"
                            .to_owned(),
                    );
                }
            } else {
                supervisor.start_due_candidate(child.identity()?, now_ns)?;
            }
            child.supervisor_registered = true;
            observe_available_candidate_facts(supervisor, child, now_ns)?;
            journal.append(
                origin,
                Some(index),
                "SUPERVISOR",
                serde_json::json!({"event":"CANDIDATE_REGISTERED"}),
            )?;
        }

        if let (Some(supervisor), Some(index)) = (&mut supervisor, pending_candidate)
            && let Some(child) = children
                .iter()
                .find(|child| child.generation_index == index)
            && child.supervisor_registered
            && supervisor.candidate().is_some()
        {
            let readiness = &supervisor.candidate().expect("candidate checked").readiness;
            if child.snapshot.is_some() && !readiness.snapshot_persisted {
                supervisor.observe_candidate_fact(CandidateFact::SnapshotPersisted, now_ns)?;
            }
            let readiness = &supervisor.candidate().expect("candidate checked").readiness;
            if child.root_segments.contains_key("depth") && !readiness.depth_durable {
                supervisor.observe_candidate_fact(CandidateFact::DepthDurable, now_ns)?;
            }
            let readiness = &supervisor.candidate().expect("candidate checked").readiness;
            if child.root_segments.contains_key("trade") && !readiness.trade_durable {
                supervisor.observe_candidate_fact(CandidateFact::TradeDurable, now_ns)?;
            }
        }

        if let Some(supervisor) = &mut supervisor {
            for child in &mut children {
                if child.disconnect_reported
                    || child.exit_status.as_ref().is_none_or(ExitStatus::success)
                    || child.connections.is_empty()
                {
                    continue;
                }
                let epoch = child
                    .connections
                    .get("depth")
                    .or_else(|| child.connections.values().next())
                    .cloned()
                    .ok_or_else(|| "failed child has no connection epoch".to_owned())?;
                let outcome = supervisor.disconnect_epoch(
                    &epoch,
                    "capture process exited before a proven handover",
                    now_ns,
                )?;
                child.disconnect_reported = true;
                journal.append(
                    origin,
                    Some(child.generation_index),
                    "SUPERVISOR",
                    serde_json::json!({
                        "event":"GENERATION_DISCONNECT_FAIL_CLOSED",
                        "epoch":epoch,
                        "outcome":format!("{outcome:?}"),
                        "gap_count":supervisor.gap_count()
                    }),
                )?;
            }
        }

        if let Some(supervisor) = &mut supervisor {
            let advance = supervisor.advance_time(now_ns)?;
            if advance.candidate_timed_out || advance.entered_gap {
                failure.get_or_insert_with(|| {
                    "generation supervisor reached a candidate/active deadline".to_owned()
                });
            }
        }

        if failure.is_none()
            && let Some((planned_start_s, duration_s)) = planned_candidate(
                total_s,
                rotation_s,
                overlap_s,
                maximum_generation_s,
                next_planned_slot,
            )?
        {
            let elapsed = origin.elapsed();
            if !planned_launch_window_open(elapsed, planned_start_s, overlap_s)? {
                failure.get_or_insert_with(|| {
                    format!(
                        "planned rotation slot {next_planned_slot} lost its complete launch window"
                    )
                });
            } else if elapsed >= Duration::from_secs(planned_start_s) {
                let warm_count = children
                    .iter()
                    .filter(|child| child.generation_index != 0 && !child.supervisor_registered)
                    .count();
                if let Err(error) = require_empty_transport_warm_slot(warm_count) {
                    failure.get_or_insert(error);
                } else {
                    let index = children.len() as u64;
                    let child = launch_generation(
                        &capture_executable,
                        &capture_executable_sha256,
                        &public_config_sha256,
                        &generations_root,
                        &control_root,
                        &symbol,
                        index,
                        duration_s,
                        segment_s,
                        origin,
                        &output_tx,
                        &fault_silent_stall,
                    )?;
                    children.push(child);
                    if pending_candidate.is_none() {
                        pending_candidate = Some(index);
                    }
                    next_planned_slot = next_planned_slot
                        .checked_add(1)
                        .ok_or_else(|| "planned rotation slot overflow".to_owned())?;
                    journal.append(
                        origin,
                        Some(index),
                        "CAMPAIGN",
                        serde_json::json!({"event":"GENERATION_LAUNCHED","duration_s":duration_s}),
                    )?;
                }
            }
        }

        for predecessor_index in 0..children.len().saturating_sub(1) {
            let successor_index = predecessor_index + 1;
            if proof_started.contains_key(&(predecessor_index as u64))
                || !children[predecessor_index].terminal_complete()
                || !children[successor_index].live_prefix_ready()
            {
                continue;
            }
            let predecessor_session = children[predecessor_index]
                .session_dir
                .clone()
                .expect("terminal generation has session");
            let successor_session = children[successor_index]
                .session_dir
                .clone()
                .expect("ready generation has session");
            let startup_sha = children[successor_index]
                .startup_sha256
                .clone()
                .expect("ready generation has startup");
            let snapshot = children[successor_index]
                .snapshot
                .clone()
                .expect("ready generation has snapshot");
            let depth = children[successor_index].root_segments["depth"].clone();
            let output = handovers_root.join(format!(
                "handover-{predecessor_index:03}-to-{successor_index:03}"
            ));
            let sender = proof_tx.clone();
            thread::spawn(move || {
                let result = prove_raw_generation_handover(
                    &predecessor_session,
                    &successor_session,
                    &startup_sha,
                    &snapshot,
                    &depth,
                    &output,
                );
                let _ = sender.send(ProofCompletion {
                    predecessor_index: predecessor_index as u64,
                    successor_index: successor_index as u64,
                    result,
                });
            });
            proof_started.insert(predecessor_index as u64, Instant::now());
            journal.append(
                origin,
                Some(successor_index as u64),
                "CAMPAIGN",
                serde_json::json!({"event":"HANDOVER_PROOF_STARTED","predecessor":predecessor_index}),
            )?;
        }

        while let Ok(completion) = proof_rx.try_recv() {
            match completion.result {
                Ok(proof) => {
                    validate_raw_handover_proof_digest(&proof)?;
                    if let Some(supervisor) = &mut supervisor {
                        supervisor
                            .observe_candidate_fact(CandidateFact::DepthContinuityProven, now_ns)?;
                        supervisor
                            .observe_candidate_fact(CandidateFact::TradeContinuityProven, now_ns)?;
                        let promotion = supervisor.promote_candidate(now_ns)?;
                        if promotion.successor.generation_id != proof.successor_session_id {
                            return Err("supervisor promotion/proof identity mismatch".to_owned());
                        }
                        if let Some(predecessor) = promotion.predecessor {
                            supervisor.close_draining(&predecessor.generation_id, now_ns)?;
                        }
                    }
                    journal.append(
                        origin,
                        Some(completion.successor_index),
                        "SUPERVISOR",
                        serde_json::json!({
                            "event":"HANDOVER_PROVEN_AND_PROMOTED",
                            "predecessor":completion.predecessor_index,
                            "proof_sha256":proof.proof_sha256
                        }),
                    )?;
                    handover_proofs.insert(completion.predecessor_index, proof);
                    pending_candidate = None;
                    pending_server_shutdown_epoch = None;
                }
                Err(error) => {
                    failure.get_or_insert(format!(
                        "handover {}->{} failed: {error}",
                        completion.predecessor_index, completion.successor_index
                    ));
                }
            }
        }

        for (predecessor, started) in &proof_started {
            if !handover_proofs.contains_key(predecessor)
                && started.elapsed() > PROOF_COMPLETION_DEADLINE
            {
                failure.get_or_insert_with(|| {
                    format!("handover proof after generation {predecessor} exceeded its deadline")
                });
            }
        }

        persist_runtime_failure_once(
            &mut journal,
            origin,
            failure.as_deref(),
            &mut failure_record_sha256,
        )?;

        let publish_failure_now = failure.is_some() && failure_started.is_none();
        if failure.is_some() {
            let failed_at = *failure_started.get_or_insert_with(Instant::now);
            let reason = failure
                .as_deref()
                .ok_or_else(|| "failure stop lacks a reason".to_owned())?;
            let failure_digest = failure_record_sha256
                .as_deref()
                .ok_or_else(|| "failure stop precedes durable CAMPAIGN_FAILED".to_owned())?;
            for child in &mut children {
                request_stop(child, reason, failure_digest)?;
                if child.exit_status.is_none() && failed_at.elapsed() > FAILURE_STOP_GRACE {
                    let _ = child.child.kill();
                }
            }
        }

        if should_publish_campaign_heartbeat(publish_failure_now, last_status_print.elapsed()) {
            let active = children
                .iter()
                .filter(|child| child.exit_status.is_none())
                .count();
            println!(
                "{}",
                campaign_heartbeat_json(
                    &campaign_id,
                    origin.elapsed().as_secs(),
                    children.len(),
                    active,
                    handover_proofs.len(),
                    failure.as_deref(),
                    failure_record_sha256.as_deref(),
                )?
            );
            std::io::stdout()
                .flush()
                .map_err(|error| format!("flush campaign heartbeat: {error}"))?;
            last_status_print = Instant::now();
        }

        let all_exited = children.iter().all(|child| child.exit_status.is_some());
        let all_complete_and_journaled = children
            .iter()
            .all(|child| child.terminal_complete() && child.exit_journaled);
        let expected_handovers = children.len().saturating_sub(1);
        if all_complete_and_journaled
            && (failure.is_some() || handover_proofs.len() == expected_handovers)
            && Instant::now() >= deadline
        {
            break;
        }
        if failure.is_some() && all_exited {
            break;
        }
        thread::sleep(POLL);
    }

    if let Some(error) = failure {
        if failure_record_sha256.is_none() {
            return Err("runtime failure escaped its durable CAMPAIGN_FAILED record".to_owned());
        }
        return Err(format!(
            "raw campaign failed: {error}; evidence at {}",
            campaign_dir.display()
        ));
    }
    let terminal_evaluation = (|| -> Result<(
        Vec<CampaignGenerationResultV1>,
        Vec<CampaignHandoverResultV1>,
        u64,
    )> {
        let gap_count = supervisor
            .as_ref()
            .map_or(0, RawGenerationSupervisor::gap_count);
        if gap_count != 0 {
            return Err("campaign supervisor recorded a gap".to_owned());
        }
        if handover_proofs.len() != children.len().saturating_sub(1) {
            return Err("campaign handover proof cardinality is incomplete".to_owned());
        }
        let mut generation_results = Vec::new();
        for child in &children {
            let session = child
                .session_dir
                .as_ref()
                .ok_or_else(|| "completed child lacks session directory".to_owned())?;
            let verification = verify_segmented_generation(session)?;
            if verification.generation_index != child.generation_index
                || verification.symbol != symbol
                || child.session_id.as_deref() != Some(&verification.session_id)
                || verification.session_dir != *session
                || verification.collector_executable_sha256 != capture_executable_sha256
                || verification.public_config_sha256 != public_config_sha256
                || verification.streams.iter().any(|stream| {
                    child.connections.get(&stream.name) != Some(&stream.connection_epoch)
                })
                || stream_records(&verification, "depth")? != child.last_depth_durable
                || stream_records(&verification, "trade")? != child.last_trade_durable
            {
                return Err(format!(
                    "generation {} identity/source/durable state differs from campaign",
                    child.generation_index
                ));
            }
            let session_relative = format!("generations/{}", verification.session_id);
            let mut portable_verification = verification.clone();
            portable_verification.session_dir = PathBuf::from(&session_relative);
            let mut bytes = serde_json::to_vec_pretty(&portable_verification)
                .map_err(|error| format!("serialize generation verification: {error}"))?;
            bytes.push(b'\n');
            let evaluation_file = format!(
                "evaluations/generation-{:03}-rust.json",
                child.generation_index
            );
            write_synced_new(&campaign_dir.join(&evaluation_file), &bytes)?;
            generation_results.push(CampaignGenerationResultV1 {
                generation_index: child.generation_index,
                session_id: verification.session_id.clone(),
                session_dir: session_relative,
                verification_sha256: verification.verification_sha256.clone(),
                evaluation_file,
                evaluation_file_sha256: sha256_hex(&bytes),
                generation_manifest_sha256: verification.generation_manifest_sha256.clone(),
                depth_records: stream_records(&verification, "depth")?,
                trade_records: stream_records(&verification, "trade")?,
            });
        }
        let mut handover_results = Vec::new();
        for (predecessor, proof) in &handover_proofs {
            let successor = predecessor
                .checked_add(1)
                .ok_or_else(|| "handover successor index overflow".to_owned())?;
            if proof.predecessor_generation_index != *predecessor
                || proof.successor_generation_index != successor
                || proof.symbol != symbol
                || children[*predecessor as usize].session_id.as_deref()
                    != Some(&proof.predecessor_session_id)
                || children[successor as usize].session_id.as_deref()
                    != Some(&proof.successor_session_id)
            {
                return Err("handover proof identity differs from campaign generations".to_owned());
            }
            let proof_file = format!(
                "handovers/handover-{predecessor:03}-to-{successor:03}/handover.json"
            );
            let proof_bytes = fs::read(campaign_dir.join(&proof_file))
                .map_err(|error| format!("read terminal handover proof: {error}"))?;
            let mut expected_proof_bytes = serde_json::to_vec_pretty(proof)
                .map_err(|error| format!("serialize promoted handover proof: {error}"))?;
            expected_proof_bytes.push(b'\n');
            if proof_bytes != expected_proof_bytes {
                return Err("handover proof bytes differ from promoted proof".to_owned());
            }
            handover_results.push(CampaignHandoverResultV1 {
                predecessor_generation_index: *predecessor,
                successor_generation_index: successor,
                proof_sha256: proof.proof_sha256.clone(),
                proof_file,
                proof_file_sha256: sha256_hex(&proof_bytes),
            });
        }
        Ok((generation_results, handover_results, gap_count))
    })();
    let (generation_results, handover_results, gap_count) = match terminal_evaluation {
        Ok(result) => result,
        Err(error) => {
            journal.append(
                origin,
                None,
                "CAMPAIGN",
                serde_json::json!({
                    "event":"CAMPAIGN_FAILED",
                    "stage":"TERMINAL_EVALUATION",
                    "error":error
                }),
            )?;
            return Err(format!(
                "raw campaign terminal evaluation failed: {error}; evidence at {}",
                campaign_dir.display()
            ));
        }
    };
    journal.append(
        origin,
        None,
        "CAMPAIGN",
        serde_json::json!({"event":"CAMPAIGN_EVALUATION_PREPARED"}),
    )?;
    let journal_records = journal.records();
    let journal_digest = journal.digest().to_owned();
    if scan_campaign_journal(&journal_path)? != (journal_records, journal_digest.clone()) {
        return Err("precommit campaign journal rescan mismatch".to_owned());
    }
    let manifest = CampaignManifestV1 {
        schema: "RawCampaignManifestV1",
        status: "COMPLETE",
        campaign_id,
        symbol,
        total_duration_s: total_s,
        rotation_s,
        overlap_s,
        segment_s,
        started_wall_ns,
        finished_wall_ns: unix_ns()?,
        spec_revision: SPEC_REVISION,
        credentials: "NONE",
        order_entry: "ABSENT",
        executable_sha256,
        capture_executable_sha256,
        public_config_sha256,
        startup_file: "campaign-startup.json",
        startup_sha256,
        journal_file: "campaign-events.jsonl",
        journal_boundary: "PRECOMMIT_PREFIX",
        journal_precommit_records: journal_records,
        journal_precommit_sha256: journal_digest,
        supervisor_gap_count: gap_count,
        generations: generation_results,
        handovers: handover_results,
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize campaign manifest: {error}"))?;
    bytes.push(b'\n');
    write_synced_new(&campaign_dir.join("campaign.json"), &bytes)?;
    let manifest_sha256 = sha256_hex(&bytes);
    journal.append(
        origin,
        None,
        "CAMPAIGN",
        serde_json::json!({
            "event":"CAMPAIGN_COMMITTED",
            "manifest_file":"campaign.json",
            "manifest_sha256":manifest_sha256
        }),
    )?;
    let committed = (journal.records(), journal.digest().to_owned());
    drop(journal);
    if scan_campaign_journal(&journal_path)? != committed {
        return Err("committed campaign journal rescan mismatch".to_owned());
    }
    Ok(campaign_dir)
}

fn main() {
    let managed_event_stream = env::args_os()
        .last()
        .is_some_and(|value| value == std::ffi::OsStr::new("--event-stream"));
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            if !managed_event_stream
                && env::var_os("BINANCE_LOB_EVENT_STREAM").as_deref()
                    != Some(std::ffi::OsStr::new("1"))
            {
                eprintln!("raw-campaign: {error}");
            }
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ExpectedServerShutdownPublicationV1;
    use super::{
        CampaignJournalWriter, campaign_heartbeat_json, candidate_duration_seconds,
        capture_stop_request_bytes, failure_for_observed_exit, handover_seal_guard_seconds,
        maximum_generation_duration_seconds, parse_event_stream_flag, parse_fault_silent_stall_env,
        persist_runtime_failure_once, planned_candidate, planned_launch_window_open,
        register_server_shutdown_publication, require_empty_transport_warm_slot,
        scan_campaign_journal, sha256_file, should_publish_campaign_heartbeat,
        validate_market_freshness,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    #[test]
    fn silent_stall_environment_is_exact_and_strict() {
        assert!(parse_fault_silent_stall_env(None).unwrap().is_none());
        assert_eq!(
            parse_fault_silent_stall_env(Some("trade:20")).unwrap(),
            Some("trade:20".to_owned())
        );
        assert_eq!(
            parse_fault_silent_stall_env(Some(" depth : 0 ")).unwrap(),
            Some("depth:0".to_owned())
        );
        assert!(parse_fault_silent_stall_env(Some("")).is_err());
        assert!(parse_fault_silent_stall_env(Some("trade")).is_err());
        assert!(parse_fault_silent_stall_env(Some("unknown:1")).is_err());
        assert!(parse_fault_silent_stall_env(Some("trade:abc")).is_err());
        assert!(parse_fault_silent_stall_env(Some("trade:1:2")).is_err());
        assert!(parse_fault_silent_stall_env(Some("trade:1:p")).is_err());
    }

    #[test]
    fn capture_stop_request_binds_session_reason_and_durable_failure() {
        let digest = "a".repeat(64);
        let bytes = capture_stop_request_bytes("session", "market silence", &digest).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!(
                "{{\"schema\":\"CaptureStopRequestV1\",\"session_id\":\"session\",\"reason\":\"market silence\",\"campaign_failure_record_sha256\":\"{digest}\"}}\n"
            )
        );
        assert!(capture_stop_request_bytes("session", "", &digest).is_err());
        assert!(capture_stop_request_bytes("session", "reason", "bad").is_err());
    }

    #[test]
    fn managed_event_stream_flag_is_exact_and_optional() {
        assert_eq!(parse_event_stream_flag(None), Ok(false));
        assert_eq!(
            parse_event_stream_flag(Some("--event-stream".to_owned())),
            Ok(true)
        );
        assert!(parse_event_stream_flag(Some("--event-stream=true".to_owned())).is_err());
        assert!(parse_event_stream_flag(Some("--unknown".to_owned())).is_err());
    }

    #[test]
    fn failed_process_exit_is_immediately_actionable_but_success_can_drain_stdout() {
        assert_eq!(failure_for_observed_exit(7, true), None);
        assert_eq!(
            failure_for_observed_exit(7, false),
            Some("generation 7 exited without COMPLETE terminal evidence".to_owned())
        );
    }

    #[test]
    fn durable_failure_bypasses_the_periodic_heartbeat_interval() {
        assert!(should_publish_campaign_heartbeat(
            true,
            Duration::from_millis(1)
        ));
        assert!(!should_publish_campaign_heartbeat(
            false,
            Duration::from_millis(4_999)
        ));
        assert!(should_publish_campaign_heartbeat(
            false,
            Duration::from_secs(5)
        ));
    }

    #[test]
    fn campaign_journal_is_durable_hash_chain() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("events.jsonl");
        let origin = Instant::now();
        let mut writer = CampaignJournalWriter::create(&path).unwrap();
        writer
            .append(origin, Some(0), "TEST", json!({"event":"A"}))
            .unwrap();
        writer
            .append(origin, Some(1), "TEST", json!({"event":"B"}))
            .unwrap();
        let expected = (writer.records(), writer.digest().to_owned());
        drop(writer);
        assert_eq!(scan_campaign_journal(&path).unwrap(), expected);
    }

    #[test]
    fn campaign_journal_rejects_tampering() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("events.jsonl");
        let origin = Instant::now();
        let mut writer = CampaignJournalWriter::create(&path).unwrap();
        writer
            .append(origin, Some(0), "TEST", json!({"event":"A"}))
            .unwrap();
        drop(writer);
        let mut bytes = std::fs::read(&path).unwrap();
        let position = bytes.iter().position(|byte| *byte == b'A').unwrap();
        bytes[position] = b'Z';
        std::fs::write(&path, bytes).unwrap();
        assert!(scan_campaign_journal(&path).is_err());
    }

    #[test]
    fn runtime_failure_is_durable_exactly_once_before_publication() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("events.jsonl");
        let origin = Instant::now();
        let mut writer = CampaignJournalWriter::create(&path).unwrap();
        let mut failure_digest = None;
        persist_runtime_failure_once(
            &mut writer,
            origin,
            Some("trade market-message freshness deadline exceeded"),
            &mut failure_digest,
        )
        .unwrap();
        let first_digest = failure_digest.clone().unwrap();
        persist_runtime_failure_once(
            &mut writer,
            origin,
            Some("a later error cannot replace the first cause"),
            &mut failure_digest,
        )
        .unwrap();
        assert_eq!(writer.records(), 1);
        assert_eq!(writer.digest(), first_digest);
        drop(writer);

        let line = std::fs::read_to_string(&path).unwrap();
        assert_eq!(line.lines().count(), 1);
        let envelope: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(
            envelope["body"]["payload"],
            json!({
                "event":"CAMPAIGN_FAILED",
                "stage":"RUNTIME",
                "error":"trade market-message freshness deadline exceeded"
            })
        );
        assert_eq!(envelope["record_sha256"], first_digest);
    }

    #[test]
    fn failure_heartbeat_binds_exact_reason_and_durable_record() {
        let digest = "a".repeat(64);
        let heartbeat = campaign_heartbeat_json(
            "campaign",
            42,
            1,
            1,
            0,
            Some("depth market-message freshness deadline exceeded"),
            Some(&digest),
        )
        .unwrap();
        assert_eq!(
            heartbeat,
            format!(
                "{{\"event\":\"CAMPAIGN_HEARTBEAT\",\"campaign_id\":\"campaign\",\"elapsed_s\":42,\"generations\":1,\"active_processes\":1,\"handovers_proven\":0,\"failure\":true,\"failure_reason\":\"depth market-message freshness deadline exceeded\",\"failure_record_sha256\":\"{digest}\"}}"
            )
        );
        assert!(campaign_heartbeat_json("campaign", 42, 1, 1, 0, Some("x"), None).is_err());
        assert!(campaign_heartbeat_json("campaign", 42, 1, 1, 0, None, Some(&digest)).is_err());
    }

    #[test]
    fn executable_file_hash_is_single_sha256_without_stack_sized_buffer() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("fixture.bin");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn absolute_stress_schedule_keeps_exactly_seven_handover_launches() {
        let opening_delays_s = [2_u64, 5, 9, 14, 20, 27, 35];
        let maximum_generation_s = maximum_generation_duration_seconds(900, 900).unwrap();
        assert_eq!(maximum_generation_s, 1_770);
        let planned = (1_u64..)
            .map(|slot| planned_candidate(7_200, 900, 900, maximum_generation_s, slot).unwrap())
            .take_while(Option::is_some)
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(planned.len(), 7);
        assert_eq!(planned.last(), Some(&(6_300, 990)));
        for ((start_s, _), delay_s) in planned.iter().zip(opening_delays_s) {
            assert!(
                planned_launch_window_open(Duration::from_secs(start_s + delay_s), *start_s, 900,)
                    .unwrap()
            );
        }
        // Initial generation plus seven immutable absolute slots.
        assert_eq!(planned.len() + 1, 8);
    }

    #[test]
    fn a_second_transport_warm_slot_fails_closed_before_launch() {
        assert!(require_empty_transport_warm_slot(0).is_ok());
        assert!(require_empty_transport_warm_slot(1).is_err());
        assert!(require_empty_transport_warm_slot(2).is_err());
    }

    #[test]
    fn handover_guard_precedes_the_successor_root_segment_seal() {
        assert_eq!(handover_seal_guard_seconds(10).unwrap(), 1);
        assert_eq!(handover_seal_guard_seconds(900).unwrap(), 30);
        assert_eq!(maximum_generation_duration_seconds(60, 10).unwrap(), 69);
        assert_eq!(
            maximum_generation_duration_seconds(82_800, 900).unwrap(),
            83_670
        );
        assert!(handover_seal_guard_seconds(1).is_err());
    }

    #[test]
    fn planned_rotation_fails_closed_after_the_complete_window_is_lost() {
        assert!(planned_launch_window_open(Duration::from_secs(7_199), 6_300, 900).unwrap());
        assert!(!planned_launch_window_open(Duration::from_secs(7_200), 6_300, 900).unwrap());
        assert_eq!(planned_candidate(7_200, 900, 900, 1_800, 8).unwrap(), None);
        assert_eq!(
            planned_candidate(86_400, 82_800, 900, 83_670, 1).unwrap(),
            Some((82_800, 3_600))
        );
        assert_eq!(planned_candidate(40, 5, 5, 9, 7).unwrap(), Some((35, 9)));

        // The separate immediate-serverShutdown helper remains fail-closed
        // once actual remaining time cannot round to a complete overlap.
        assert_eq!(
            candidate_duration_seconds(Duration::from_millis(899_900), 900, 1_800),
            Some(900)
        );
        assert_eq!(
            candidate_duration_seconds(Duration::from_millis(898_999), 900, 1_800),
            None
        );
    }

    #[test]
    fn durable_server_shutdown_publication_is_idempotent_but_not_ambiguous() {
        let publication = ExpectedServerShutdownPublicationV1 {
            schema: "DurableServerShutdownEventV1".to_owned(),
            stream: "depth".to_owned(),
            connection_epoch: "depth-epoch".to_owned(),
            segment_index: 1,
            raw_file: "segment-000001.bnraw".to_owned(),
            frame_index: 50,
            receive_mono_ns: 10,
            durable_record_count: 3,
            durable_through_offset: 100,
            last_record_sha256: "a".repeat(64),
        };
        let mut seen = BTreeMap::new();
        assert!(register_server_shutdown_publication(&mut seen, publication.clone()).unwrap());
        assert!(!register_server_shutdown_publication(&mut seen, publication.clone()).unwrap());
        let mut conflicting = publication;
        conflicting.last_record_sha256 = "b".repeat(64);
        assert!(register_server_shutdown_publication(&mut seen, conflicting).is_err());
    }

    #[test]
    fn control_pings_cannot_mask_frozen_market_messages() {
        let second = 1_000_000_000;
        let now = 70 * second;
        let fresh_socket = 70 * second;
        let stale_market = 39 * second;
        assert!(
            validate_market_freshness(
                now,
                120,
                fresh_socket,
                stale_market,
                fresh_socket,
                stale_market,
            )
            .is_err()
        );
        assert!(
            validate_market_freshness(
                now,
                120,
                fresh_socket,
                69 * second,
                fresh_socket,
                69 * second,
            )
            .is_ok()
        );
    }

    #[test]
    fn market_freshness_has_startup_grace_and_ignores_post_deadline_drain() {
        let second = 1_000_000_000;
        assert!(validate_market_freshness(20 * second, 60, 0, 0, 0, 0).is_ok());
        assert!(validate_market_freshness(61 * second, 60, 0, 0, 0, 0).is_ok());
        assert!(
            validate_market_freshness(
                40 * second,
                60,
                40 * second,
                40 * second,
                40 * second,
                40 * second,
            )
            .is_ok()
        );
    }
}
