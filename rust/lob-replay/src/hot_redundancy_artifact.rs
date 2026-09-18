//! Independent verification for a committed hot-redundant capture artifact.

use crate::Result;
use crate::campaign_artifact::verify_raw_campaign;
use crate::hot_redundancy::{CaptureLane, CoverageState, GapInterval};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Component, Path, PathBuf};

const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";
const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorStartupV1 {
    schema: String,
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
    spec_revision: String,
    credentials: String,
    order_entry: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorTerminalV1 {
    schema: String,
    status: String,
    supervisor_id: String,
    symbol: String,
    finished_wall_ns: u64,
    final_coverage: CoverageState,
    gaps: Vec<GapInterval>,
    lane_runs: Vec<LaneRunResultV1>,
    journal_boundary: String,
    journal_precommit_records: u64,
    journal_precommit_sha256: String,
    credentials: String,
    order_entry: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SupervisorJournalBodyV1 {
    schema: String,
    record_index: u64,
    wall_ns: u64,
    supervisor_mono_ns: u64,
    channel: String,
    payload: Value,
    previous_record_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SupervisorJournalEnvelopeV1 {
    body: SupervisorJournalBodyV1,
    record_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCampaignJournalBodyV1 {
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
#[serde(deny_unknown_fields)]
struct RawCampaignJournalEnvelopeV1 {
    body: RawCampaignJournalBodyV1,
    record_sha256: String,
}

#[derive(Debug)]
struct LaunchEvidence {
    lane: CaptureLane,
    requested_s: u64,
    campaign_id: Option<String>,
    ready: bool,
    outcome_success: Option<bool>,
    failure_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedLaneCampaignV1 {
    pub lane: CaptureLane,
    pub token: String,
    pub campaign_id: String,
    pub status: String,
    pub campaign_verification_sha256: Option<String>,
    pub failure_record_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedHotRedundantCaptureV1 {
    pub schema: &'static str,
    pub status: &'static str,
    pub supervisor_id: String,
    pub artifact_id: String,
    pub symbol: String,
    pub terminal_status: String,
    pub terminal_file_sha256: String,
    pub journal_records: u64,
    pub journal_terminal_sha256: String,
    pub gaps: Vec<GapInterval>,
    pub lane_campaigns: Vec<VerifiedLaneCampaignV1>,
    pub verification_sha256: String,
}

pub fn verify_hot_redundant_capture(root: &Path) -> Result<VerifiedHotRedundantCaptureV1> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolve {}: {error}", root.display()))?;
    if !root.is_dir() {
        return Err("hot-redundant artifact is not a directory".to_owned());
    }
    let startup_bytes = fs::read(root.join("supervisor-startup.json"))
        .map_err(|error| format!("read supervisor startup: {error}"))?;
    let terminal_bytes = fs::read(root.join("supervisor-terminal.json"))
        .map_err(|error| format!("read supervisor terminal: {error}"))?;
    require_pretty_newline(&startup_bytes, "supervisor startup")?;
    require_pretty_newline(&terminal_bytes, "supervisor terminal")?;
    let startup: SupervisorStartupV1 = serde_json::from_slice(&startup_bytes)
        .map_err(|error| format!("parse supervisor startup: {error}"))?;
    let terminal: SupervisorTerminalV1 = serde_json::from_slice(&terminal_bytes)
        .map_err(|error| format!("parse supervisor terminal: {error}"))?;
    validate_startup_terminal(&root, &startup, &terminal)?;

    let journal = scan_supervisor_journal(&root.join("supervisor-events.jsonl"))?;
    let startup_digest = sha256_hex(&startup_bytes);
    let first = journal
        .first()
        .ok_or_else(|| "supervisor journal is empty".to_owned())?;
    if first.body.channel != "SUPERVISOR"
        || first.body.payload
            != serde_json::json!({
                "event":"SUPERVISOR_STARTED",
                "supervisor_id":startup.supervisor_id,
                "startup_file":"supervisor-startup.json",
                "startup_sha256":startup_digest
            })
    {
        return Err("supervisor startup lacks an exact durable binding".to_owned());
    }
    if terminal.journal_boundary != "PRECOMMIT_PREFIX"
        || terminal.journal_precommit_records == 0
        || terminal.journal_precommit_records.saturating_add(1) != journal.len() as u64
    {
        return Err("supervisor journal commit cardinality is invalid".to_owned());
    }
    let precommit = &journal[(terminal.journal_precommit_records - 1) as usize];
    if precommit.record_sha256 != terminal.journal_precommit_sha256
        || precommit.body.payload.get("event").and_then(Value::as_str)
            != Some("SUPERVISOR_TERMINAL_PREPARED")
    {
        return Err("supervisor terminal does not bind its exact journal prefix".to_owned());
    }
    let terminal_digest = sha256_hex(&terminal_bytes);
    let commit = journal
        .last()
        .ok_or_else(|| "supervisor journal is empty".to_owned())?;
    if commit.body.channel != "SUPERVISOR"
        || commit.body.payload
            != serde_json::json!({
                "event":"SUPERVISOR_COMMITTED",
                "terminal_file":"supervisor-terminal.json",
                "terminal_sha256":terminal_digest
            })
    {
        return Err("supervisor terminal lacks an exact durable commit".to_owned());
    }

    validate_gaps(&journal, &terminal)?;
    let launch_evidence = collect_lane_evidence(&journal)?;
    let mut observed_tokens = BTreeSet::new();
    let mut complete_by_lane =
        BTreeMap::from([(CaptureLane::Primary, 0_u64), (CaptureLane::Shadow, 0_u64)]);
    let mut verified_campaigns = Vec::new();
    for lane_run in &terminal.lane_runs {
        if lane_run.token.trim().is_empty() || !observed_tokens.insert(lane_run.token.clone()) {
            return Err("terminal lane run token is empty or reused".to_owned());
        }
        let evidence = launch_evidence
            .get(&lane_run.token)
            .ok_or_else(|| "terminal lane run was never launched".to_owned())?;
        if evidence.lane != lane_run.lane
            || evidence.requested_s != lane_run.requested_s
            || evidence.ready != lane_run.ready
            || evidence.outcome_success != Some(lane_run.exit_success)
            || evidence.campaign_id != lane_run.campaign_id
            || lane_run.started_mono_ns > startup.total_duration_s.saturating_mul(1_000_000_000)
            || (!lane_run.stderr_lines.is_empty() && lane_run.exit_success)
        {
            return Err("terminal lane run differs from its durable lifecycle".to_owned());
        }
        let campaign_id = lane_run
            .campaign_id
            .as_deref()
            .ok_or_else(|| "terminal lane run lacks campaign identity".to_owned())?;
        validate_component(campaign_id, "campaign ID")?;
        let relative = lane_run
            .campaign_dir
            .as_deref()
            .ok_or_else(|| "terminal lane run lacks campaign directory".to_owned())?;
        let expected_relative = format!("{}/{campaign_id}", lane_dir(lane_run.lane));
        if relative != expected_relative {
            return Err("terminal lane campaign path is not exact and portable".to_owned());
        }
        let campaign = safe_relative(&root, relative, "lane campaign")?;
        if lane_run.exit_success {
            if !lane_run.ready
                || lane_run.exit_code != Some(0)
                || lane_run.failure_reason.is_some()
                || lane_run.failure_record_sha256.is_some()
                || evidence.failure_reason.is_some()
            {
                return Err("successful lane run carries contradictory failure evidence".to_owned());
            }
            let verified = verify_raw_campaign(&campaign)?;
            if verified.symbol != terminal.symbol
                || verified.campaign_id != campaign_id
                || verified.total_duration_s != lane_run.requested_s
            {
                return Err(
                    "verified child campaign differs from supervisor lane result".to_owned(),
                );
            }
            *complete_by_lane
                .get_mut(&lane_run.lane)
                .expect("both lanes initialized") += 1;
            verified_campaigns.push(VerifiedLaneCampaignV1 {
                lane: lane_run.lane,
                token: lane_run.token.clone(),
                campaign_id: campaign_id.to_owned(),
                status: "VERIFIED_COMPLETE".to_owned(),
                campaign_verification_sha256: Some(verified.verification_sha256),
                failure_record_sha256: None,
            });
        } else {
            let reason = lane_run
                .failure_reason
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| "failed lane run lacks exact failure reason".to_owned())?;
            let digest = lane_run
                .failure_record_sha256
                .as_deref()
                .filter(|value| is_sha256(value))
                .ok_or_else(|| "failed lane run lacks durable failure digest".to_owned())?;
            if evidence.failure_reason.as_deref() != Some(reason)
                || campaign.join("campaign.json").exists()
            {
                return Err(
                    "failed lane run contradicts its preserved campaign evidence".to_owned(),
                );
            }
            verify_failed_campaign_journal(&campaign, reason, digest)?;
            verified_campaigns.push(VerifiedLaneCampaignV1 {
                lane: lane_run.lane,
                token: lane_run.token.clone(),
                campaign_id: campaign_id.to_owned(),
                status: "VERIFIED_FAILED_PRESERVED".to_owned(),
                campaign_verification_sha256: None,
                failure_record_sha256: Some(digest.to_owned()),
            });
        }
    }
    if observed_tokens.len() != launch_evidence.len()
        || complete_by_lane.values().any(|count| *count == 0)
    {
        return Err(
            "terminal omits a launched run or one lane never completed a verified window"
                .to_owned(),
        );
    }

    let mut report = VerifiedHotRedundantCaptureV1 {
        schema: "VerifiedHotRedundantCaptureV1",
        status: "PASS",
        supervisor_id: terminal.supervisor_id,
        artifact_id: startup.artifact_id,
        symbol: terminal.symbol,
        terminal_status: terminal.status,
        terminal_file_sha256: terminal_digest,
        journal_records: journal.len() as u64,
        journal_terminal_sha256: journal
            .last()
            .expect("journal is non-empty")
            .record_sha256
            .clone(),
        gaps: terminal.gaps,
        lane_campaigns: verified_campaigns,
        verification_sha256: String::new(),
    };
    report.verification_sha256 = verification_digest(&report)?;
    Ok(report)
}

fn validate_startup_terminal(
    root: &Path,
    startup: &SupervisorStartupV1,
    terminal: &SupervisorTerminalV1,
) -> Result<()> {
    let basename = root
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "artifact root lacks UTF-8 basename".to_owned())?;
    if startup.schema != "HotRedundantCaptureStartupV1"
        || terminal.schema != "HotRedundantCaptureTerminalV1"
        || startup.artifact_id != basename
        || startup.supervisor_id != terminal.supervisor_id
        || startup.symbol != terminal.symbol
        || !matches!(startup.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
        || startup.total_duration_s == 0
        || startup.total_duration_s > 365 * 24 * 60 * 60
        || startup.primary_rotation_s == startup.shadow_rotation_s
        || startup.overlap_s == 0
        || startup.overlap_s != startup.segment_s
        || !startup.primary_rotation_s.is_multiple_of(startup.segment_s)
        || !startup.shadow_rotation_s.is_multiple_of(startup.segment_s)
        || startup.primary_rotation_s.saturating_add(startup.overlap_s) > 86_300
        || startup.shadow_rotation_s.saturating_add(startup.overlap_s) > 86_300
        || startup.primary_window_s == startup.shadow_window_s
        || startup.primary_window_s < startup.overlap_s
        || startup.shadow_window_s < startup.overlap_s
        || startup.primary_window_s > 7 * 24 * 60 * 60
        || startup.shadow_window_s > 7 * 24 * 60 * 60
        || startup.process_id == 0
        || terminal.finished_wall_ns < startup.started_wall_ns
        || terminal.final_coverage != CoverageState::Terminal
        || startup.spec_revision != SPEC_REVISION
        || !is_sha256(&startup.executable_sha256)
        || !is_sha256(&startup.raw_campaign_executable_sha256)
        || !is_sha256(&startup.public_config_sha256)
        || startup.credentials != "NONE"
        || startup.order_entry != "ABSENT"
        || terminal.credentials != "NONE"
        || terminal.order_entry != "ABSENT"
    {
        return Err("supervisor startup and terminal contract is invalid".to_owned());
    }
    let expected_status = if terminal.gaps.iter().any(|gap| gap.closed_mono_ns.is_none()) {
        "COMPLETE_WITH_OPEN_GAP"
    } else if terminal.gaps.is_empty() {
        "COMPLETE_NO_DUAL_OUTAGE"
    } else {
        "COMPLETE_WITH_EXPLICIT_GAPS"
    };
    if terminal.status != expected_status {
        return Err("terminal status contradicts recorded gaps".to_owned());
    }
    Ok(())
}

fn scan_supervisor_journal(path: &Path) -> Result<Vec<SupervisorJournalEnvelopeV1>> {
    let file = File::open(path).map_err(|error| format!("open supervisor journal: {error}"))?;
    let mut records = Vec::new();
    let mut previous = "0".repeat(64);
    for line in BufReader::new(file).split(b'\n') {
        let line = line.map_err(|error| format!("read supervisor journal: {error}"))?;
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_RECORD_BYTES {
            return Err("supervisor journal record exceeds its bound".to_owned());
        }
        let envelope: SupervisorJournalEnvelopeV1 = serde_json::from_slice(&line)
            .map_err(|error| format!("parse supervisor journal: {error}"))?;
        let digest = sha256_hex(
            &serde_json::to_vec(&envelope.body)
                .map_err(|error| format!("reserialize supervisor journal: {error}"))?,
        );
        if envelope.body.schema != "HotRedundantJournalRecordV1"
            || envelope.body.record_index != records.len() as u64
            || envelope.body.previous_record_sha256 != previous
            || envelope.record_sha256 != digest
        {
            return Err("supervisor journal hash chain is invalid".to_owned());
        }
        previous = digest;
        records.push(envelope);
    }
    if records.is_empty() {
        return Err("supervisor journal is empty".to_owned());
    }
    Ok(records)
}

fn collect_lane_evidence(
    journal: &[SupervisorJournalEnvelopeV1],
) -> Result<BTreeMap<String, LaunchEvidence>> {
    let mut launches = BTreeMap::<String, LaunchEvidence>::new();
    for record in journal {
        let event = record.body.payload.get("event").and_then(Value::as_str);
        match event {
            Some("LANE_LAUNCHED" | "LANE_RESTARTED") => {
                let token = text(&record.body.payload, "token")?;
                let lane = serde_json::from_value(
                    record
                        .body
                        .payload
                        .get("lane")
                        .cloned()
                        .ok_or("lane absent")?,
                )
                .map_err(|error| format!("invalid lane: {error}"))?;
                let requested_s = record
                    .body
                    .payload
                    .get("requested_s")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "lane launch lacks requested duration".to_owned())?;
                if launches
                    .insert(
                        token.to_owned(),
                        LaunchEvidence {
                            lane,
                            requested_s,
                            campaign_id: None,
                            ready: false,
                            outcome_success: None,
                            failure_reason: None,
                        },
                    )
                    .is_some()
                {
                    return Err("lane token was launched more than once".to_owned());
                }
            }
            Some("LANE_READY") => {
                let token = text(&record.body.payload, "token")?;
                let launch = launches
                    .get_mut(token)
                    .ok_or_else(|| "lane became ready before launch".to_owned())?;
                if launch.ready {
                    return Err("lane published duplicate readiness".to_owned());
                }
                launch.ready = true;
                launch.campaign_id = Some(text(&record.body.payload, "campaign_id")?.to_owned());
            }
            Some("LANE_FAILED" | "LANE_WINDOW_COMPLETED") => {
                let token = text(&record.body.payload, "token")?;
                let launch = launches
                    .get_mut(token)
                    .ok_or_else(|| "lane outcome preceded launch".to_owned())?;
                if launch.outcome_success.is_some() {
                    return Err("lane published duplicate outcome".to_owned());
                }
                let success = event == Some("LANE_WINDOW_COMPLETED");
                launch.outcome_success = Some(success);
                if !success {
                    launch.failure_reason = Some(text(&record.body.payload, "reason")?.to_owned());
                }
            }
            _ => {}
        }
    }
    Ok(launches)
}

fn validate_gaps(
    journal: &[SupervisorJournalEnvelopeV1],
    terminal: &SupervisorTerminalV1,
) -> Result<()> {
    let mut gaps = BTreeMap::<u64, GapInterval>::new();
    for record in journal {
        match record.body.payload.get("event").and_then(Value::as_str) {
            Some("GAP_OPENED") => {
                let gap: GapInterval = serde_json::from_value(
                    record
                        .body
                        .payload
                        .get("gap")
                        .cloned()
                        .ok_or("gap absent")?,
                )
                .map_err(|error| format!("invalid opened gap: {error}"))?;
                if gap.gap_id != gaps.len() as u64
                    || gap.closed_mono_ns.is_some()
                    || gap.unavailable_ns.is_some()
                    || gaps.insert(gap.gap_id, gap).is_some()
                {
                    return Err("opened gap identity/state is invalid".to_owned());
                }
            }
            Some("GAP_CLOSED") => {
                let gap: GapInterval = serde_json::from_value(
                    record
                        .body
                        .payload
                        .get("gap")
                        .cloned()
                        .ok_or("gap absent")?,
                )
                .map_err(|error| format!("invalid closed gap: {error}"))?;
                let previous = gaps
                    .get_mut(&gap.gap_id)
                    .ok_or_else(|| "gap closed before opening".to_owned())?;
                if previous.closed_mono_ns.is_some()
                    || gap.closed_mono_ns.is_none()
                    || gap.unavailable_ns
                        != gap
                            .closed_mono_ns
                            .map(|closed| closed.saturating_sub(gap.opened_mono_ns))
                    || previous.opened_mono_ns != gap.opened_mono_ns
                {
                    return Err("closed gap duration/state is invalid".to_owned());
                }
                *previous = gap;
            }
            _ => {}
        }
    }
    if gaps.values().cloned().collect::<Vec<_>>() != terminal.gaps {
        return Err("terminal gaps differ from durable supervisor events".to_owned());
    }
    Ok(())
}

fn verify_failed_campaign_journal(campaign: &Path, reason: &str, digest: &str) -> Result<()> {
    let file = File::open(campaign.join("campaign-events.jsonl"))
        .map_err(|error| format!("open failed campaign journal: {error}"))?;
    let mut previous = "0".repeat(64);
    let mut index = 0_u64;
    let mut matched = false;
    for line in BufReader::new(file).split(b'\n') {
        let line = line.map_err(|error| format!("read failed campaign journal: {error}"))?;
        if line.is_empty() {
            continue;
        }
        let envelope: RawCampaignJournalEnvelopeV1 = serde_json::from_slice(&line)
            .map_err(|error| format!("parse failed campaign journal: {error}"))?;
        let actual = sha256_hex(
            &serde_json::to_vec(&envelope.body)
                .map_err(|error| format!("reserialize failed campaign journal: {error}"))?,
        );
        if envelope.body.schema != "RawCampaignJournalRecordV1"
            || envelope.body.record_index != index
            || envelope.body.previous_record_sha256 != previous
            || envelope.record_sha256 != actual
        {
            return Err("failed campaign journal hash chain is invalid".to_owned());
        }
        if envelope.body.channel == "CAMPAIGN"
            && envelope.body.payload.get("event").and_then(Value::as_str) == Some("CAMPAIGN_FAILED")
            && envelope.body.payload.get("error").and_then(Value::as_str) == Some(reason)
            && envelope.record_sha256 == digest
        {
            matched = true;
        }
        previous = actual;
        index = index
            .checked_add(1)
            .ok_or_else(|| "failed campaign journal index overflow".to_owned())?;
    }
    if !matched {
        return Err("failed lane result is not bound to CAMPAIGN_FAILED".to_owned());
    }
    Ok(())
}

fn safe_relative(root: &Path, relative: &str, label: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{label} path is not portable"));
    }
    let joined = root.join(path);
    let canonical = joined
        .canonicalize()
        .map_err(|error| format!("resolve {label}: {error}"))?;
    if !canonical.starts_with(root) {
        return Err(format!("{label} escaped artifact root"));
    }
    Ok(canonical)
}

fn validate_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(format!("{label} is not a safe component"));
    }
    Ok(())
}

fn lane_dir(lane: CaptureLane) -> &'static str {
    match lane {
        CaptureLane::Primary => "p",
        CaptureLane::Shadow => "s",
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("event lacks {key}"))
}

fn require_pretty_newline(bytes: &[u8], label: &str) -> Result<()> {
    if bytes.last() != Some(&b'\n') {
        return Err(format!("{label} lacks terminal newline"));
    }
    Ok(())
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

fn verification_digest(report: &VerifiedHotRedundantCaptureV1) -> Result<String> {
    #[derive(Serialize)]
    struct DigestView<'a> {
        schema: &'a str,
        status: &'a str,
        supervisor_id: &'a str,
        artifact_id: &'a str,
        symbol: &'a str,
        terminal_status: &'a str,
        terminal_file_sha256: &'a str,
        journal_records: u64,
        journal_terminal_sha256: &'a str,
        gaps: &'a [GapInterval],
        lane_campaigns: &'a [VerifiedLaneCampaignV1],
    }
    let view = DigestView {
        schema: report.schema,
        status: report.status,
        supervisor_id: &report.supervisor_id,
        artifact_id: &report.artifact_id,
        symbol: &report.symbol,
        terminal_status: &report.terminal_status,
        terminal_file_sha256: &report.terminal_file_sha256,
        journal_records: report.journal_records,
        journal_terminal_sha256: &report.journal_terminal_sha256,
        gaps: &report.gaps,
        lane_campaigns: &report.lane_campaigns,
    };
    Ok(sha256_hex(&serde_json::to_vec(&view).map_err(|error| {
        format!("serialize verification digest: {error}")
    })?))
}
