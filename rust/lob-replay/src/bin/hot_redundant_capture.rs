use lob_replay::Result;
use lob_replay::hot_redundancy::{
    CaptureLane, CoverageState, CoverageTransition, GapInterval, HotRedundancyConfig,
    HotRedundantSupervisor,
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
const CHILD_HEARTBEAT_DEADLINE: Duration = Duration::from_secs(30);
const CHILD_OUTPUT_DRAIN: Duration = Duration::from_secs(1);
const MAX_JOURNAL_RECORD_BYTES: usize = 1024 * 1024;
const MAX_CHILD_STDOUT_LINE_BYTES: usize = 64 * 1024;
const MAX_CHILD_WINDOW_S: u64 = 7 * 24 * 3_600;
const TERMINAL_COMPLETION_GRACE: Duration = Duration::from_secs(30 * 60);
const LEGACY_WINDOWS_MAX_PATH_CHARS: usize = 259;

#[derive(Debug)]
enum ChildOutput {
    Stdout {
        lane: CaptureLane,
        token: String,
        line: String,
    },
    Stderr {
        lane: CaptureLane,
        token: String,
        line: String,
    },
}

#[derive(Debug)]
struct LaneRuntime {
    token: String,
    child: Child,
    requested_s: u64,
    started_mono_ns: u64,
    last_heartbeat: Instant,
    campaign_id: Option<String>,
    campaign_dir: Option<PathBuf>,
    cursor: Option<CampaignJournalCursor>,
    ready: bool,
    failure_reason: Option<String>,
    failure_record_sha256: Option<String>,
    stderr_lines: Vec<String>,
    terminal_path_seen: bool,
    exit_status: Option<ExitStatus>,
    exit_seen: Option<Instant>,
}

impl Drop for LaneRuntime {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[derive(Debug, Default)]
struct ReadinessFacts {
    process_started: bool,
    depth_connected: bool,
    trade_connected: bool,
    snapshot_durable: bool,
    semantic_heartbeat: bool,
    failure_reason: Option<String>,
}

impl ReadinessFacts {
    fn ready(&self) -> bool {
        self.process_started
            && self.depth_connected
            && self.trade_connected
            && self.snapshot_durable
            && self.semantic_heartbeat
            && self.failure_reason.is_none()
    }
}

#[derive(Debug)]
struct CampaignJournalCursor {
    path: PathBuf,
    offset: u64,
    next_index: u64,
    previous: String,
    facts: ReadinessFacts,
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize)]
struct CampaignJournalEnvelopeV1 {
    body: CampaignJournalBodyV1,
    record_sha256: String,
}

impl CampaignJournalCursor {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            next_index: 0,
            previous: "0".repeat(64),
            facts: ReadinessFacts::default(),
        }
    }

    fn read_new(&mut self) -> Result<()> {
        if !self.path.is_file() {
            return Ok(());
        }
        let mut file = File::open(&self.path)
            .map_err(|error| format!("open {}: {error}", self.path.display()))?;
        let length = file
            .metadata()
            .map_err(|error| format!("stat {}: {error}", self.path.display()))?
            .len();
        if length < self.offset {
            return Err("child campaign journal truncated while live".to_owned());
        }
        file.seek(SeekFrom::Start(self.offset))
            .map_err(|error| format!("seek child campaign journal: {error}"))?;
        let mut reader = BufReader::new(file);
        loop {
            let mut bytes = Vec::new();
            let read = reader
                .read_until(b'\n', &mut bytes)
                .map_err(|error| format!("read child campaign journal: {error}"))?;
            if read == 0 {
                break;
            }
            if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
                return Err("child campaign journal record exceeds its bound".to_owned());
            }
            if bytes.last() != Some(&b'\n') {
                break;
            }
            let line = std::str::from_utf8(&bytes[..bytes.len() - 1])
                .map_err(|error| format!("child campaign journal is not UTF-8: {error}"))?;
            let envelope: CampaignJournalEnvelopeV1 = serde_json::from_str(line)
                .map_err(|error| format!("invalid child campaign journal JSON: {error}"))?;
            let body_bytes = serde_json::to_vec(&envelope.body)
                .map_err(|error| format!("reserialize child campaign journal: {error}"))?;
            let digest = sha256_hex(&body_bytes);
            if envelope.body.schema != "RawCampaignJournalRecordV1"
                || envelope.body.record_index != self.next_index
                || envelope.body.previous_record_sha256 != self.previous
                || envelope.record_sha256 != digest
            {
                return Err("child campaign journal hash chain is invalid".to_owned());
            }
            self.observe(&envelope.body)?;
            self.offset = self
                .offset
                .checked_add(u64::try_from(read).map_err(|_| "journal offset overflow")?)
                .ok_or_else(|| "journal offset overflow".to_owned())?;
            self.next_index = self
                .next_index
                .checked_add(1)
                .ok_or_else(|| "journal record-index overflow".to_owned())?;
            self.previous = digest;
        }
        Ok(())
    }

    fn observe(&mut self, body: &CampaignJournalBodyV1) -> Result<()> {
        let event = body
            .payload
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or("");
        if body.channel == "CAMPAIGN" && event == "CAMPAIGN_FAILED" {
            let reason = body
                .payload
                .get("error")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "child CAMPAIGN_FAILED lacks exact reason".to_owned())?;
            if self
                .facts
                .failure_reason
                .replace(reason.to_owned())
                .is_some()
            {
                return Err("child campaign published duplicate failure cause".to_owned());
            }
            return Ok(());
        }
        if body.channel != "CHILD_STDOUT" {
            return Ok(());
        }
        match event {
            "PROCESS_STARTED" => self.facts.process_started = true,
            "TRANSPORT_CONNECTED" => {
                let stream = body
                    .payload
                    .pointer("/connection/stream")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "TRANSPORT_CONNECTED lacks stream".to_owned())?;
                match stream {
                    "depth" => self.facts.depth_connected = true,
                    "trade" => self.facts.trade_connected = true,
                    _ => return Err("TRANSPORT_CONNECTED names unknown stream".to_owned()),
                }
            }
            "SNAPSHOT_DURABLE" => self.facts.snapshot_durable = true,
            "HEARTBEAT_DURABLE" => {
                let positive = |name: &str| {
                    body.payload
                        .get(name)
                        .and_then(Value::as_u64)
                        .is_some_and(|value| value != 0)
                };
                if positive("depth_durable")
                    && positive("trade_durable")
                    && positive("depth_last_market_message_mono_ns")
                    && positive("trade_last_market_message_mono_ns")
                {
                    self.facts.semantic_heartbeat = true;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCampaignHeartbeatV1 {
    event: String,
    campaign_id: String,
    elapsed_s: u64,
    generations: usize,
    active_processes: usize,
    handovers_proven: usize,
    failure: bool,
    #[serde(default)]
    failure_reason: Option<String>,
    #[serde(default)]
    failure_record_sha256: Option<String>,
}

impl RawCampaignHeartbeatV1 {
    fn validate(&self) -> Result<()> {
        if self.event != "CAMPAIGN_HEARTBEAT"
            || self.campaign_id.trim().is_empty()
            || self.generations == 0
            || self.active_processes > self.generations
            || self.handovers_proven >= self.generations
            || self.failure != self.failure_reason.is_some()
            || self.failure != self.failure_record_sha256.is_some()
            || self
                .failure_reason
                .as_deref()
                .is_some_and(|reason| reason.trim().is_empty())
            || self
                .failure_record_sha256
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err("raw campaign heartbeat violates its exact contract".to_owned());
        }
        let _ = self.elapsed_s;
        Ok(())
    }
}

#[derive(Serialize)]
struct SupervisorJournalBodyV1 {
    schema: &'static str,
    record_index: u64,
    wall_ns: u64,
    supervisor_mono_ns: u64,
    channel: String,
    payload: Value,
    previous_record_sha256: String,
}

#[derive(Serialize)]
struct SupervisorJournalEnvelopeV1 {
    body: SupervisorJournalBodyV1,
    record_sha256: String,
}

struct SupervisorJournalWriter {
    file: File,
    next_index: u64,
    previous: String,
}

impl SupervisorJournalWriter {
    fn create(path: &Path) -> Result<Self> {
        Ok(Self {
            file: OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .map_err(|error| format!("create {}: {error}", path.display()))?,
            next_index: 0,
            previous: "0".repeat(64),
        })
    }

    fn append(&mut self, origin: Instant, channel: &str, payload: Value) -> Result<String> {
        let body = SupervisorJournalBodyV1 {
            schema: "HotRedundantJournalRecordV1",
            record_index: self.next_index,
            wall_ns: unix_ns()?,
            supervisor_mono_ns: elapsed_ns(origin)?,
            channel: channel.to_owned(),
            payload,
            previous_record_sha256: self.previous.clone(),
        };
        let digest = sha256_hex(
            &serde_json::to_vec(&body)
                .map_err(|error| format!("serialize supervisor journal body: {error}"))?,
        );
        let envelope = SupervisorJournalEnvelopeV1 {
            body,
            record_sha256: digest.clone(),
        };
        let mut bytes = serde_json::to_vec(&envelope)
            .map_err(|error| format!("serialize supervisor journal record: {error}"))?;
        bytes.push(b'\n');
        self.file
            .write_all(&bytes)
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_all())
            .map_err(|error| format!("sync supervisor journal: {error}"))?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| "supervisor journal index overflow".to_owned())?;
        self.previous = digest.clone();
        Ok(digest)
    }
}

#[derive(Serialize)]
struct SupervisorStartupV1 {
    schema: &'static str,
    supervisor_id: String,
    artifact_id: String,
    symbol: String,
    total_duration_s: u64,
    primary_rotation_s: u64,
    shadow_rotation_s: u64,
    overlap_s: u64,
    segment_s: u64,
    primary_window_s: u64,
    shadow_window_s: u64,
    process_id: u32,
    started_wall_ns: u64,
    executable_sha256: String,
    raw_campaign_executable_sha256: String,
    public_config_sha256: String,
    spec_revision: &'static str,
    credentials: &'static str,
    order_entry: &'static str,
}

#[derive(Serialize)]
struct LaneRunResultV1 {
    lane: CaptureLane,
    token: String,
    requested_s: u64,
    started_mono_ns: u64,
    ready: bool,
    campaign_id: Option<String>,
    campaign_dir: Option<String>,
    exit_success: bool,
    exit_code: Option<i32>,
    failure_reason: Option<String>,
    failure_record_sha256: Option<String>,
    stderr_lines: Vec<String>,
}

#[derive(Serialize)]
struct SupervisorTerminalV1 {
    schema: &'static str,
    status: &'static str,
    supervisor_id: String,
    symbol: String,
    finished_wall_ns: u64,
    final_coverage: CoverageState,
    gaps: Vec<GapInterval>,
    lane_runs: Vec<LaneRunResultV1>,
    journal_boundary: &'static str,
    journal_precommit_records: u64,
    journal_precommit_sha256: String,
    credentials: &'static str,
    order_entry: &'static str,
}

#[derive(Clone, Debug)]
struct Arguments {
    symbol: String,
    total_s: u64,
    primary_rotation_s: u64,
    shadow_rotation_s: u64,
    overlap_s: u64,
    segment_s: u64,
    primary_window_s: u64,
    shadow_window_s: u64,
    output_root: PathBuf,
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

fn parse_arguments() -> Result<Arguments> {
    let mut args = env::args();
    let executable = args
        .next()
        .unwrap_or_else(|| "hot_redundant_capture".to_owned());
    let symbol = args.next().ok_or_else(|| {
        format!(
            "usage: {executable} <BTCUSDT|ETHUSDT> <total-s> <primary-rotation-s> <shadow-rotation-s> <overlap-s> <segment-s> <primary-window-s> <shadow-window-s> [output-root] [--event-stream]"
        )
    })?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err("symbol outside fixed scope".to_owned());
    }
    let total_s = parse_positive(args.next(), "total-s", 365 * 24 * 3_600)?;
    let primary_rotation_s = parse_positive(args.next(), "primary-rotation-s", 86_000)?;
    let shadow_rotation_s = parse_positive(args.next(), "shadow-rotation-s", 86_000)?;
    let overlap_s = parse_positive(args.next(), "overlap-s", 3_600)?;
    let segment_s = parse_positive(args.next(), "segment-s", 3_600)?;
    let primary_window_s = parse_positive(args.next(), "primary-window-s", MAX_CHILD_WINDOW_S)?;
    let shadow_window_s = parse_positive(args.next(), "shadow-window-s", MAX_CHILD_WINDOW_S)?;
    let trailing = args.collect::<Vec<_>>();
    let (output_root, _event_stream) = match trailing.as_slice() {
        [] => (PathBuf::from("artifacts/hr"), false),
        [flag] if flag == "--event-stream" => (PathBuf::from("artifacts/hr"), true),
        [output] => (PathBuf::from(output), false),
        [output, flag] if flag == "--event-stream" => (PathBuf::from(output), true),
        _ => return Err("invalid trailing hot_redundant_capture arguments".to_owned()),
    };
    if overlap_s != segment_s
        || primary_rotation_s == shadow_rotation_s
        || primary_rotation_s % segment_s != 0
        || shadow_rotation_s % segment_s != 0
        || primary_rotation_s.saturating_add(overlap_s) > 86_300
        || shadow_rotation_s.saturating_add(overlap_s) > 86_300
        || primary_window_s < overlap_s
        || shadow_window_s < overlap_s
        || primary_window_s == shadow_window_s
        || total_s < overlap_s
    {
        return Err(
            "invalid redundant topology: rotations and lane windows must be distinct, segment-aligned and Binance-lifetime bounded"
                .to_owned(),
        );
    }
    Ok(Arguments {
        symbol,
        total_s,
        primary_rotation_s,
        shadow_rotation_s,
        overlap_s,
        segment_s,
        primary_window_s,
        shadow_window_s,
        output_root,
    })
}

fn spawn_reader<R: Read + Send + 'static>(
    reader: R,
    lane: CaptureLane,
    token: String,
    stdout: bool,
    sender: Sender<ChildOutput>,
) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else { break };
            let event = if stdout {
                ChildOutput::Stdout {
                    lane,
                    token: token.clone(),
                    line,
                }
            } else {
                ChildOutput::Stderr {
                    lane,
                    token: token.clone(),
                    line,
                }
            };
            if sender.send(event).is_err() {
                break;
            }
        }
    });
}

/// Test-only one-shot silent-stall directive resolved at the supervisor.
///
/// Format: `<stream>:<after-s>[:<lane>]` with `lane` in `p|s`.  The directive
/// is consumed exactly once: it is passed as the lane-free `<stream>:<after-s>`
/// environment only to the FIRST launch of the targeted lane (both lanes when
/// the filter is absent); every later launch removes the variable, so a fresh
/// replacement window can complete and prove recovery.  Strict parsing fails
/// closed and an invalid value aborts the supervisor before capture.
#[derive(Clone, Debug)]
struct FaultSilentStallDirective {
    stream: String,
    after_s: u64,
    lane_leaf: Option<String>,
}

impl FaultSilentStallDirective {
    fn cleaned_for(&self, lane: CaptureLane) -> Option<String> {
        let matches_lane = self.lane_leaf.as_deref().is_none_or(|leaf| {
            matches!(
                (lane, leaf),
                (CaptureLane::Primary, "p") | (CaptureLane::Shadow, "s")
            )
        });
        matches_lane.then(|| format!("{}:{}", self.stream, self.after_s))
    }
}

fn parse_fault_silent_stall(value: Option<&str>) -> Result<Option<FaultSilentStallDirective>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parts: Vec<&str> = value.split(':').map(str::trim).collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(format!(
            "BINANCE_LOB_FAULT_SILENT_STALL must be <stream>:<after-s>[:<lane>]; got {value:?}"
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
    let lane_leaf = match parts.get(2).copied() {
        None | Some("") => None,
        Some(leaf) if matches!(leaf, "p" | "s") => Some(leaf.to_owned()),
        Some(other) => {
            return Err(format!(
                "BINANCE_LOB_FAULT_SILENT_STALL lane filter must be p or s; got {other:?}"
            ));
        }
    };
    Ok(Some(FaultSilentStallDirective {
        stream: parts[0].to_owned(),
        after_s,
        lane_leaf,
    }))
}

#[allow(clippy::too_many_arguments)]
fn launch_lane(
    lane: CaptureLane,
    token: String,
    requested_s: u64,
    args: &Arguments,
    raw_campaign: &Path,
    expected_raw_sha256: &str,
    run_dir: &Path,
    origin: Instant,
    output_tx: &Sender<ChildOutput>,
    fault_silent_stall: Option<&str>,
) -> Result<LaneRuntime> {
    if sha256_file(raw_campaign)? != expected_raw_sha256 {
        return Err("raw_campaign executable changed before lane launch".to_owned());
    }
    let lane_root = run_dir.join(lane_directory(lane));
    fs::create_dir_all(&lane_root)
        .map_err(|error| format!("create {}: {error}", lane_root.display()))?;
    let rotation_s = match lane {
        CaptureLane::Primary => args.primary_rotation_s,
        CaptureLane::Shadow => args.shadow_rotation_s,
    };
    let mut command = Command::new(raw_campaign);
    command
        .arg(&args.symbol)
        .arg(requested_s.to_string())
        .arg(rotation_s.to_string())
        .arg(args.overlap_s.to_string())
        .arg(args.segment_s.to_string())
        .arg(&lane_root)
        .arg("--event-stream")
        .env("BINANCE_LOB_EVENT_STREAM", "1");
    if let Some(cleaned) = fault_silent_stall {
        command.env("BINANCE_LOB_FAULT_SILENT_STALL", cleaned);
    } else {
        command.env_remove("BINANCE_LOB_FAULT_SILENT_STALL");
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("launch {} lane: {error}", lane.as_str()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "raw campaign stdout pipe is absent".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "raw campaign stderr pipe is absent".to_owned())?;
    spawn_reader(stdout, lane, token.clone(), true, output_tx.clone());
    spawn_reader(stderr, lane, token.clone(), false, output_tx.clone());
    Ok(LaneRuntime {
        token,
        child,
        requested_s,
        started_mono_ns: elapsed_ns(origin)?,
        last_heartbeat: Instant::now(),
        campaign_id: None,
        campaign_dir: None,
        cursor: None,
        ready: false,
        failure_reason: None,
        failure_record_sha256: None,
        stderr_lines: Vec::new(),
        terminal_path_seen: false,
        exit_status: None,
        exit_seen: None,
    })
}

fn record_transition(
    journal: &mut SupervisorJournalWriter,
    origin: Instant,
    transition: &CoverageTransition,
    gaps: &mut Vec<GapInterval>,
) -> Result<()> {
    if transition.previous != transition.current {
        journal.append(
            origin,
            "COVERAGE",
            serde_json::json!({
                "event":"COVERAGE_CHANGED",
                "previous":transition.previous,
                "current":transition.current
            }),
        )?;
    }
    if let Some(gap) = &transition.opened_gap {
        gaps.push(gap.clone());
        journal.append(
            origin,
            "COVERAGE",
            serde_json::json!({"event":"GAP_OPENED","gap":gap}),
        )?;
    }
    if let Some(gap) = &transition.closed_gap {
        let retained = gaps
            .iter_mut()
            .find(|candidate| candidate.gap_id == gap.gap_id)
            .ok_or_else(|| "closed gap was never durably opened".to_owned())?;
        *retained = gap.clone();
        journal.append(
            origin,
            "COVERAGE",
            serde_json::json!({"event":"GAP_CLOSED","gap":gap}),
        )?;
    }
    Ok(())
}

fn validate_campaign_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("child campaign ID is not a portable basename".to_owned());
    }
    Ok(())
}

fn process_output(
    event: ChildOutput,
    runtimes: &mut BTreeMap<CaptureLane, LaneRuntime>,
    run_dir: &Path,
    journal: &mut SupervisorJournalWriter,
    origin: Instant,
) -> Result<()> {
    let (lane, token, line, stdout) = match event {
        ChildOutput::Stdout { lane, token, line } => (lane, token, line, true),
        ChildOutput::Stderr { lane, token, line } => (lane, token, line, false),
    };
    let Some(runtime) = runtimes.get_mut(&lane) else {
        return Ok(());
    };
    if runtime.token != token {
        return Ok(());
    }
    if !stdout {
        if line.len() > MAX_CHILD_STDOUT_LINE_BYTES {
            return Err("raw campaign stderr line exceeds its bound".to_owned());
        }
        runtime.stderr_lines.push(line.clone());
        journal.append(
            origin,
            "LANE_STDERR",
            serde_json::json!({"event":"LANE_STDERR","lane":lane,"token":token,"text":line}),
        )?;
    } else {
        if line.len() > MAX_CHILD_STDOUT_LINE_BYTES {
            return Err("raw campaign stdout line exceeds its bound".to_owned());
        }
        let heartbeat: RawCampaignHeartbeatV1 = match serde_json::from_str(&line) {
            Ok(heartbeat) => heartbeat,
            Err(error) => {
                let Some(expected) = runtime.campaign_dir.as_ref() else {
                    return Err(format!(
                        "{} emitted non-JSON output before campaign identity: {error}",
                        lane.as_str()
                    ));
                };
                let observed = PathBuf::from(&line);
                let expected_absolute = fs::canonicalize(expected).map_err(|path_error| {
                    format!("resolve expected terminal campaign path: {path_error}")
                })?;
                let observed_absolute = fs::canonicalize(&observed).map_err(|path_error| {
                    format!("resolve reported terminal campaign path: {path_error}")
                })?;
                if observed_absolute != expected_absolute {
                    return Err(format!(
                        "{} emitted unexpected non-JSON output: {error}",
                        lane.as_str()
                    ));
                }
                runtime.terminal_path_seen = true;
                return Ok(());
            }
        };
        heartbeat.validate()?;
        if let Some(existing) = &runtime.campaign_id {
            if existing != &heartbeat.campaign_id {
                return Err("raw campaign changed identity during one lane run".to_owned());
            }
        } else {
            validate_campaign_id(&heartbeat.campaign_id)?;
            let lane_root = run_dir.join(lane_directory(lane));
            let campaign_dir = lane_root.join(&heartbeat.campaign_id);
            runtime.campaign_id = Some(heartbeat.campaign_id.clone());
            runtime.campaign_dir = Some(campaign_dir.clone());
            runtime.cursor = Some(CampaignJournalCursor::new(
                campaign_dir.join("campaign-events.jsonl"),
            ));
        }
        runtime.last_heartbeat = Instant::now();
        if heartbeat.failure {
            runtime.failure_reason = heartbeat.failure_reason;
            runtime.failure_record_sha256 = heartbeat.failure_record_sha256;
        }
    }
    Ok(())
}

fn run() -> Result<PathBuf> {
    let args = parse_arguments()?;
    let fault_directive =
        parse_fault_silent_stall(env::var("BINANCE_LOB_FAULT_SILENT_STALL").ok().as_deref())?;
    let executable = env::current_exe().map_err(|error| format!("current executable: {error}"))?;
    let raw_campaign = executable.with_file_name(if cfg!(windows) {
        "raw_campaign.exe"
    } else {
        "raw_campaign"
    });
    if !raw_campaign.is_file() {
        return Err(format!(
            "raw_campaign executable is absent: {}",
            raw_campaign.display()
        ));
    }
    let config_path = Path::new("config/public.json");
    if !config_path.is_file() {
        return Err("config/public.json is absent".to_owned());
    }
    let supervisor_id = format!(
        "{}-{}-redundant-{}",
        unix_ns()?,
        args.symbol,
        &Uuid::new_v4().simple().to_string()[..12]
    );
    fs::create_dir_all(&args.output_root)
        .map_err(|error| format!("create {}: {error}", args.output_root.display()))?;
    validate_path_budget(&args.output_root, &args.symbol)?;
    let artifact_id = format!("hr-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let run_dir = args.output_root.join(&artifact_id);
    fs::create_dir(&run_dir).map_err(|error| format!("create {}: {error}", run_dir.display()))?;
    for lane in CaptureLane::ALL {
        fs::create_dir(run_dir.join(lane_directory(lane)))
            .map_err(|error| format!("create lane directory: {error}"))?;
    }
    let raw_campaign_sha256 = sha256_file(&raw_campaign)?;
    let started_wall_ns = unix_ns()?;
    let startup = SupervisorStartupV1 {
        schema: "HotRedundantCaptureStartupV1",
        supervisor_id: supervisor_id.clone(),
        artifact_id,
        symbol: args.symbol.clone(),
        total_duration_s: args.total_s,
        primary_rotation_s: args.primary_rotation_s,
        shadow_rotation_s: args.shadow_rotation_s,
        overlap_s: args.overlap_s,
        segment_s: args.segment_s,
        primary_window_s: args.primary_window_s,
        shadow_window_s: args.shadow_window_s,
        process_id: std::process::id(),
        started_wall_ns,
        executable_sha256: sha256_file(&executable)?,
        raw_campaign_executable_sha256: raw_campaign_sha256.clone(),
        public_config_sha256: sha256_file(config_path)?,
        spec_revision: SPEC_REVISION,
        credentials: "NONE",
        order_entry: "ABSENT",
    };
    let startup_sha256 = write_synced_json_new(&run_dir.join("supervisor-startup.json"), &startup)?;

    let origin = Instant::now();
    let deadline = origin + Duration::from_secs(args.total_s);
    let terminal_deadline = deadline + TERMINAL_COMPLETION_GRACE;
    let mut journal = SupervisorJournalWriter::create(&run_dir.join("supervisor-events.jsonl"))?;
    journal.append(
        origin,
        "SUPERVISOR",
        serde_json::json!({
            "event":"SUPERVISOR_STARTED",
            "supervisor_id":supervisor_id,
            "startup_file":"supervisor-startup.json",
            "startup_sha256":startup_sha256
        }),
    )?;
    if let Some(directive) = &fault_directive {
        journal.append(
            origin,
            "SUPERVISOR",
            serde_json::json!({
                "event":"FAULT_INJECTED_SILENT_STALL",
                "stream":directive.stream,
                "after_s":directive.after_s,
                "lane_leaf":directive.lane_leaf,
                "scope":"FIRST_LAUNCH_OF_TARGETED_LANE_ONLY"
            }),
        )?;
    }
    let mut supervisor = HotRedundantSupervisor::new(
        HotRedundancyConfig {
            backoff_initial_ns: 1_000_000_000,
            backoff_max_ns: 60_000_000_000,
            jitter_max_ns: 1_000_000_000,
            backoff_reset_after_ns: 300_000_000_000,
            circuit_failure_threshold: 5,
            circuit_reset_cooldown_ns: 60_000_000_000,
        },
        0,
    )?;
    let (output_tx, output_rx): (Sender<ChildOutput>, Receiver<ChildOutput>) = mpsc::channel();
    let mut runtimes = BTreeMap::<CaptureLane, LaneRuntime>::new();
    let mut run_results = Vec::<LaneRunResultV1>::new();
    let mut gaps = Vec::<GapInterval>::new();
    let mut last_status = Instant::now() - Duration::from_secs(10);
    let mut horizon_closed = false;

    for lane in CaptureLane::ALL {
        let token = format!(
            "{}-{}-{}",
            lane.as_str().to_ascii_lowercase(),
            1,
            &Uuid::new_v4().simple().to_string()[..12]
        );
        let transition = supervisor.start_lane(lane, &token, elapsed_ns(origin)?)?;
        record_transition(&mut journal, origin, &transition, &mut gaps)?;
        let window = match lane {
            CaptureLane::Primary => args.primary_window_s,
            CaptureLane::Shadow => args.shadow_window_s,
        };
        let requested_s = args.total_s.min(window);
        let runtime = launch_lane(
            lane,
            token.clone(),
            requested_s,
            &args,
            &raw_campaign,
            &raw_campaign_sha256,
            &run_dir,
            origin,
            &output_tx,
            fault_directive
                .as_ref()
                .and_then(|directive| directive.cleaned_for(lane))
                .as_deref(),
        )?;
        journal.append(
            origin,
            "LANE",
            serde_json::json!({
                "event":"LANE_LAUNCHED","lane":lane,"token":token,
                "pid":runtime.child.id(),"requested_s":requested_s
            }),
        )?;
        runtimes.insert(lane, runtime);
    }

    loop {
        while let Ok(event) = output_rx.try_recv() {
            process_output(event, &mut runtimes, &run_dir, &mut journal, origin)?;
        }

        let now_ns = elapsed_ns(origin)?;
        if !horizon_closed && Instant::now() >= deadline {
            let transition = supervisor.terminate(args.total_s.saturating_mul(1_000_000_000))?;
            record_transition(&mut journal, origin, &transition, &mut gaps)?;
            journal.append(
                origin,
                "SUPERVISOR",
                serde_json::json!({
                    "event":"CAPTURE_HORIZON_CLOSED",
                    "capture_horizon_mono_ns":args.total_s.saturating_mul(1_000_000_000),
                    "terminal_drain_is_not_market_coverage":true
                }),
            )?;
            horizon_closed = true;
        }
        for lane in CaptureLane::ALL {
            let Some(runtime) = runtimes.get_mut(&lane) else {
                continue;
            };
            if let Some(cursor) = &mut runtime.cursor {
                cursor.read_new()?;
                if runtime.failure_reason.is_none() {
                    runtime.failure_reason = cursor.facts.failure_reason.clone();
                }
                if !runtime.ready && cursor.facts.ready() {
                    runtime.ready = true;
                    let token = runtime.token.clone();
                    let transition = supervisor.mark_ready(lane, &token, now_ns)?;
                    record_transition(&mut journal, origin, &transition, &mut gaps)?;
                    journal.append(
                        origin,
                        "LANE",
                        serde_json::json!({
                            "event":"LANE_READY","lane":lane,"token":token,
                            "campaign_id":runtime.campaign_id
                        }),
                    )?;
                }
            }
            if runtime.exit_status.is_none()
                && let Some(status) = runtime
                    .child
                    .try_wait()
                    .map_err(|error| format!("poll {} child: {error}", lane.as_str()))?
            {
                runtime.exit_status = Some(status);
                runtime.exit_seen = Some(Instant::now());
            }
            if runtime.exit_status.is_none()
                && runtime.last_heartbeat.elapsed() > CHILD_HEARTBEAT_DEADLINE
                && runtime.ready
            {
                journal.append(
                    origin,
                    "LANE",
                    serde_json::json!({
                        "event":"LANE_COORDINATOR_HEARTBEAT_STALE","lane":lane,
                        "token":runtime.token,"elapsed_ms":runtime.last_heartbeat.elapsed().as_millis()
                    }),
                )?;
                runtime.last_heartbeat = Instant::now();
            }
        }

        let completed = CaptureLane::ALL
            .into_iter()
            .filter(|lane| {
                runtimes.get(lane).is_some_and(|runtime| {
                    runtime.exit_status.is_some()
                        && runtime
                            .exit_seen
                            .is_some_and(|seen| seen.elapsed() >= CHILD_OUTPUT_DRAIN)
                })
            })
            .collect::<Vec<_>>();
        for lane in completed {
            while let Ok(event) = output_rx.try_recv() {
                process_output(event, &mut runtimes, &run_dir, &mut journal, origin)?;
            }
            let mut runtime = runtimes
                .remove(&lane)
                .ok_or_else(|| "completed lane runtime disappeared".to_owned())?;
            if let Some(cursor) = &mut runtime.cursor {
                cursor.read_new()?;
                if runtime.failure_reason.is_none() {
                    runtime.failure_reason = cursor.facts.failure_reason.clone();
                }
            }
            let status = runtime
                .exit_status
                .take()
                .ok_or_else(|| "completed lane lacks exit status".to_owned())?;
            let clean = status.success()
                && runtime.ready
                && runtime.failure_reason.is_none()
                && runtime.stderr_lines.is_empty()
                && runtime.terminal_path_seen
                && runtime
                    .campaign_dir
                    .as_ref()
                    .is_some_and(|directory| directory.join("campaign.json").is_file());
            let reason = if clean {
                None
            } else {
                Some(runtime.failure_reason.clone().unwrap_or_else(|| {
                    format!(
                        "raw_campaign exited without a complete verified lane window (code={:?})",
                        status.code()
                    )
                }))
            };
            if !horizon_closed {
                let transition = if clean {
                    supervisor.retire_lane(lane, &runtime.token, now_ns)?
                } else {
                    supervisor.fail_lane(
                        lane,
                        &runtime.token,
                        reason.as_deref().expect("unclean run has reason"),
                        now_ns,
                    )?
                };
                record_transition(&mut journal, origin, &transition, &mut gaps)?;
            }
            journal.append(
                origin,
                "LANE",
                serde_json::json!({
                    "event":if clean {"LANE_WINDOW_COMPLETED"} else {"LANE_FAILED"},
                    "lane":lane,"token":runtime.token,"code":status.code(),
                    "reason":reason,"campaign_id":runtime.campaign_id
                }),
            )?;
            run_results.push(LaneRunResultV1 {
                lane,
                token: runtime.token.clone(),
                requested_s: runtime.requested_s,
                started_mono_ns: runtime.started_mono_ns,
                ready: runtime.ready,
                campaign_id: runtime.campaign_id.clone(),
                campaign_dir: runtime
                    .campaign_id
                    .as_ref()
                    .map(|campaign_id| format!("{}/{campaign_id}", lane_directory(lane))),
                // This field is the supervisor's verified lane outcome.  The
                // raw OS result remains independently preserved in exit_code.
                exit_success: clean,
                exit_code: status.code(),
                failure_reason: reason,
                failure_record_sha256: runtime.failure_record_sha256.clone(),
                stderr_lines: runtime.stderr_lines.clone(),
            });
        }

        if Instant::now() < deadline {
            for request in supervisor.restart_requests(now_ns)? {
                if runtimes.contains_key(&request.lane) {
                    return Err("restart requested while lane runtime still exists".to_owned());
                }
                let remaining_s = ceil_seconds(deadline.saturating_duration_since(Instant::now()));
                if remaining_s < args.overlap_s {
                    continue;
                }
                let window = match request.lane {
                    CaptureLane::Primary => args.primary_window_s,
                    CaptureLane::Shadow => args.shadow_window_s,
                };
                let requested_s = remaining_s.min(window);
                let token = format!(
                    "{}-{}-{}",
                    request.lane.as_str().to_ascii_lowercase(),
                    request.next_launch_attempt,
                    &Uuid::new_v4().simple().to_string()[..12]
                );
                let transition = supervisor.start_lane(request.lane, &token, now_ns)?;
                record_transition(&mut journal, origin, &transition, &mut gaps)?;
                // The one-shot fault directive applies only to the first launch
                // of its targeted lane; every replacement window runs clean so
                // recovery can complete and be independently verified.
                let runtime = launch_lane(
                    request.lane,
                    token.clone(),
                    requested_s,
                    &args,
                    &raw_campaign,
                    &raw_campaign_sha256,
                    &run_dir,
                    origin,
                    &output_tx,
                    None,
                )?;
                journal.append(
                    origin,
                    "LANE",
                    serde_json::json!({
                        "event":"LANE_RESTARTED","lane":request.lane,"token":token,
                        "pid":runtime.child.id(),"requested_s":requested_s,
                        "attempt":request.next_launch_attempt
                    }),
                )?;
                runtimes.insert(request.lane, runtime);
            }
        }

        let transition = supervisor.advance_time(now_ns)?;
        record_transition(&mut journal, origin, &transition, &mut gaps)?;
        if last_status.elapsed() >= Duration::from_secs(5) {
            println!(
                "{}",
                serde_json::json!({
                    "event":"HOT_REDUNDANT_HEARTBEAT",
                    "supervisor_id":supervisor_id,
                    "elapsed_s":origin.elapsed().as_secs(),
                    "coverage":supervisor.coverage(),
                    "primary":supervisor.lane(CaptureLane::Primary).state,
                    "shadow":supervisor.lane(CaptureLane::Shadow).state,
                    "open_gap":supervisor.open_gap().map(|gap| gap.gap_id),
                    "completed_lane_runs":run_results.len()
                })
            );
            std::io::stdout()
                .flush()
                .map_err(|error| format!("flush supervisor heartbeat: {error}"))?;
            last_status = Instant::now();
        }
        if Instant::now() >= deadline && runtimes.is_empty() {
            break;
        }
        if Instant::now() > terminal_deadline {
            return Err("lane campaigns exceeded the terminal completion grace".to_owned());
        }
        thread::sleep(POLL);
    }

    if !horizon_closed {
        let transition = supervisor.terminate(elapsed_ns(origin)?)?;
        record_transition(&mut journal, origin, &transition, &mut gaps)?;
    }
    journal.append(
        origin,
        "SUPERVISOR",
        serde_json::json!({"event":"SUPERVISOR_TERMINAL_PREPARED"}),
    )?;
    let journal_precommit_records = journal.next_index;
    let journal_precommit_sha256 = journal.previous.clone();
    let status = if gaps.iter().any(|gap| gap.closed_mono_ns.is_none()) {
        "COMPLETE_WITH_OPEN_GAP"
    } else if gaps.is_empty() {
        "COMPLETE_NO_DUAL_OUTAGE"
    } else {
        "COMPLETE_WITH_EXPLICIT_GAPS"
    };
    let terminal = SupervisorTerminalV1 {
        schema: "HotRedundantCaptureTerminalV1",
        status,
        supervisor_id,
        symbol: args.symbol,
        finished_wall_ns: unix_ns()?,
        final_coverage: supervisor.coverage(),
        gaps,
        lane_runs: run_results,
        journal_boundary: "PRECOMMIT_PREFIX",
        journal_precommit_records,
        journal_precommit_sha256,
        credentials: "NONE",
        order_entry: "ABSENT",
    };
    let terminal_sha256 =
        write_synced_json_new(&run_dir.join("supervisor-terminal.json"), &terminal)?;
    journal.append(
        origin,
        "SUPERVISOR",
        serde_json::json!({
            "event":"SUPERVISOR_COMMITTED",
            "terminal_file":"supervisor-terminal.json",
            "terminal_sha256":terminal_sha256
        }),
    )?;
    Ok(run_dir)
}

fn ceil_seconds(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
}

fn lane_directory(lane: CaptureLane) -> &'static str {
    match lane {
        CaptureLane::Primary => "p",
        CaptureLane::Shadow => "s",
    }
}

fn validate_path_budget(output_root: &Path, symbol: &str) -> Result<()> {
    let root = if output_root.is_absolute() {
        output_root.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| format!("resolve current directory: {error}"))?
            .join(output_root)
    };
    let projected = root
        .join("hr-000000000000")
        .join("p")
        .join(format!("00000000000000000000-{symbol}-raw-000000000000"))
        .join("generations")
        .join(format!("00000000000000000000-{symbol}-g999-000000000000"))
        .join("transport-depth-events.jsonl");
    let characters = projected.to_string_lossy().chars().count();
    if characters > LEGACY_WINDOWS_MAX_PATH_CHARS {
        return Err(format!(
            "output root exceeds the Windows verifier path budget: projected={characters}, maximum={LEGACY_WINDOWS_MAX_PATH_CHARS}"
        ));
    }
    Ok(())
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    Ok(sha256_hex(&hash.finalize()))
}

fn write_synced_json_new<T: Serialize>(path: &Path, value: &T) -> Result<String> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(&bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("sync {}: {error}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn main() {
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            // Failure evidence is never discarded (ADR-17 B6): the launcher
            // captures stderr into the epoch's retained evidence file.
            eprintln!("hot-redundant-capture: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CampaignJournalCursor, FaultSilentStallDirective, ceil_seconds, parse_fault_silent_stall,
        validate_campaign_id, validate_path_budget,
    };
    use lob_replay::hot_redundancy::CaptureLane;
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn silent_stall_directive_is_strict_and_binds_exactly_one_lane() {
        assert!(parse_fault_silent_stall(None).unwrap().is_none());
        let both = parse_fault_silent_stall(Some("trade:20")).unwrap().unwrap();
        assert_eq!(both.stream, "trade");
        assert_eq!(both.after_s, 20);
        assert_eq!(
            both.cleaned_for(CaptureLane::Primary),
            Some("trade:20".to_owned())
        );
        assert_eq!(
            both.cleaned_for(CaptureLane::Shadow),
            Some("trade:20".to_owned())
        );
        let primary = parse_fault_silent_stall(Some("trade:20:p"))
            .unwrap()
            .unwrap();
        assert_eq!(
            primary.cleaned_for(CaptureLane::Primary),
            Some("trade:20".to_owned())
        );
        assert_eq!(primary.cleaned_for(CaptureLane::Shadow), None);
        let shadow = parse_fault_silent_stall(Some("depth:5:s"))
            .unwrap()
            .unwrap();
        assert_eq!(shadow.cleaned_for(CaptureLane::Primary), None);
        assert_eq!(
            shadow.cleaned_for(CaptureLane::Shadow),
            Some("depth:5".to_owned())
        );
        assert!(parse_fault_silent_stall(Some("")).is_err());
        assert!(parse_fault_silent_stall(Some("trade")).is_err());
        assert!(parse_fault_silent_stall(Some("unknown:1")).is_err());
        assert!(parse_fault_silent_stall(Some("trade:abc")).is_err());
        assert!(parse_fault_silent_stall(Some("trade:1:x")).is_err());
        assert!(parse_fault_silent_stall(Some("trade:1:p:s")).is_err());
        let _: FaultSilentStallDirective = both;
    }

    #[test]
    fn child_campaign_id_is_a_bounded_basename() {
        assert!(validate_campaign_id("123-BTCUSDT-raw-abcd").is_ok());
        assert!(validate_campaign_id("../escape").is_err());
        assert!(validate_campaign_id("contains\\separator").is_err());
        assert!(validate_campaign_id("").is_err());
    }

    #[test]
    fn remaining_duration_rounds_up_without_zero_window() {
        assert_eq!(ceil_seconds(Duration::from_nanos(1)), 1);
        assert_eq!(ceil_seconds(Duration::from_secs(7)), 7);
    }

    #[test]
    fn readiness_requires_every_independent_fact() {
        let cursor = CampaignJournalCursor::new("missing".into());
        assert!(!cursor.facts.ready());
    }

    #[test]
    fn legacy_windows_path_budget_rejects_excessive_output_roots() {
        assert!(validate_path_budget(Path::new("artifacts/hr"), "BTCUSDT").is_ok());
        assert!(
            validate_path_budget(
                Path::new("artifacts").join("x".repeat(240)).as_path(),
                "BTCUSDT"
            )
            .is_err()
        );
    }
}
