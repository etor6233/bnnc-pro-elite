//! Independent terminal verification of one committed raw campaign.
//!
//! The verifier trusts neither process exit nor the collector's in-memory
//! state. It reopens the campaign commit, journal, generation artifacts,
//! evaluation reports and handover proofs from exact manifest paths.

use crate::generation_artifact::{
    VerifiedGenerationV1, VerifiedServerShutdownV1, verify_segmented_generation,
};
use crate::generation_handover::{
    RawGenerationHandoverProofV1, validate_raw_handover_proof_digest,
    verify_terminal_raw_generation_handover_from_verified,
};
use crate::{Result, hex};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";
const CAMPAIGN_STARTUP_GRACE_NS: u64 = 30_000_000_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignStartupV1 {
    schema: String,
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
    spec_revision: String,
    credentials: String,
    order_entry: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignHandoverResultV1 {
    predecessor_generation_index: u64,
    successor_generation_index: u64,
    proof_sha256: String,
    proof_file: String,
    proof_file_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignManifestV1 {
    schema: String,
    status: String,
    campaign_id: String,
    symbol: String,
    total_duration_s: u64,
    rotation_s: u64,
    overlap_s: u64,
    segment_s: u64,
    started_wall_ns: u64,
    finished_wall_ns: u64,
    spec_revision: String,
    credentials: String,
    order_entry: String,
    executable_sha256: String,
    capture_executable_sha256: String,
    public_config_sha256: String,
    startup_file: String,
    startup_sha256: String,
    journal_file: String,
    journal_boundary: String,
    journal_precommit_records: u64,
    journal_precommit_sha256: String,
    supervisor_gap_count: u64,
    generations: Vec<CampaignGenerationResultV1>,
    handovers: Vec<CampaignHandoverResultV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CampaignJournalEnvelopeV1 {
    body: CampaignJournalBodyV1,
    record_sha256: String,
}

struct VerifiedJournal {
    records: Vec<CampaignJournalEnvelopeV1>,
    terminal_sha256: String,
}

#[derive(Clone, Debug)]
struct GenerationLifecycleExpectation {
    generation_index: u64,
    session_id: String,
    symbol: String,
    duration_requested_s: u64,
    startup_sha256: String,
    stream_epochs: BTreeMap<String, String>,
    server_shutdown_events: BTreeMap<String, u64>,
    server_shutdowns: BTreeSet<VerifiedServerShutdownV1>,
}

#[derive(Clone, Debug)]
struct HandoverLifecycleExpectation {
    predecessor_generation_index: u64,
    successor_generation_index: u64,
    proof_sha256: String,
}

#[derive(Default)]
struct GenerationLifecycleState {
    launch_record: Option<u64>,
    process_started_record: Option<u64>,
    process_started_mono_ns: Option<u64>,
    process_terminal_record: Option<u64>,
    process_terminal_mono_ns: Option<u64>,
    generation_exited_record: Option<u64>,
    generation_exited_mono_ns: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedRawCampaignGenerationV1 {
    pub generation_index: u64,
    pub session_id: String,
    pub verification_sha256: String,
    pub depth_records: u64,
    pub trade_records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedRawCampaignV1 {
    pub schema: &'static str,
    pub status: &'static str,
    pub campaign_id: String,
    pub symbol: String,
    pub total_duration_s: u64,
    pub rotation_s: u64,
    pub overlap_s: u64,
    pub segment_s: u64,
    pub campaign_manifest_sha256: String,
    pub journal_records: u64,
    pub journal_terminal_sha256: String,
    pub generations: Vec<VerifiedRawCampaignGenerationV1>,
    pub handovers: u64,
    pub verification_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RawCampaignVerificationPhaseTimingsV1 {
    pub clock: String,
    pub manifest_startup_journal_ns: u64,
    pub generation_reverification_ns: u64,
    pub handover_reverification_ns: u64,
    pub lifecycle_and_finalization_ns: u64,
    pub unattributed_ns: u64,
    pub total_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfiledRawCampaignVerificationV1 {
    pub schema: String,
    pub timings: RawCampaignVerificationPhaseTimingsV1,
    pub verification: VerifiedRawCampaignV1,
}

#[derive(Serialize)]
struct VerificationMaterial<'a> {
    schema: &'static str,
    campaign_id: &'a str,
    symbol: &'a str,
    total_duration_s: u64,
    rotation_s: u64,
    overlap_s: u64,
    segment_s: u64,
    campaign_manifest_sha256: &'a str,
    journal_records: u64,
    journal_terminal_sha256: &'a str,
    generations: &'a [VerifiedRawCampaignGenerationV1],
    handovers: u64,
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative(value: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!("unsafe campaign-relative path: {value}"));
    }
    Ok(path.to_path_buf())
}

fn exact_entries(path: &Path, expected: &BTreeSet<String>) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("stat {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a real directory", path.display()));
    }
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(path).map_err(|error| format!("read {}: {error}", path.display()))? {
        let entry = entry.map_err(|error| format!("read {} entry: {error}", path.display()))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("stat {}: {error}", entry.path().display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "symlink/reparse entry rejected: {}",
                entry.path().display()
            ));
        }
        actual.insert(entry.file_name().to_string_lossy().into_owned());
    }
    if &actual != expected {
        return Err(format!(
            "exact campaign inventory mismatch at {}",
            path.display()
        ));
    }
    Ok(())
}

fn scan_journal(path: &Path) -> Result<VerifiedJournal> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return Err("campaign journal is empty or has a partial tail".to_owned());
    }
    let mut previous = "0".repeat(64);
    let mut records = Vec::new();
    let mut previous_mono = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err("campaign journal contains an empty internal record".to_owned());
        }
        let envelope: CampaignJournalEnvelopeV1 = serde_json::from_slice(line)
            .map_err(|error| format!("invalid campaign journal record: {error}"))?;
        let body_bytes = serde_json::to_vec(&envelope.body)
            .map_err(|error| format!("serialize campaign journal body: {error}"))?;
        let digest = sha256_bytes(&body_bytes);
        if envelope.body.schema != "RawCampaignJournalRecordV1"
            || envelope.body.record_index != records.len() as u64
            || envelope.body.previous_record_sha256 != previous
            || envelope.record_sha256 != digest
            || previous_mono.is_some_and(|old| envelope.body.campaign_mono_ns < old)
        {
            return Err("campaign journal hash/index/time chain is invalid".to_owned());
        }
        previous_mono = Some(envelope.body.campaign_mono_ns);
        previous = digest;
        records.push(envelope);
    }
    if records.is_empty() {
        return Err("campaign journal has no records".to_owned());
    }
    Ok(VerifiedJournal {
        records,
        terminal_sha256: previous,
    })
}

fn stream_records(verification: &VerifiedGenerationV1, name: &str) -> Result<u64> {
    verification
        .streams
        .iter()
        .find(|stream| stream.name == name)
        .map(|stream| stream.records)
        .ok_or_else(|| format!("verified generation lacks {name}"))
}

fn campaign_generation_timing(
    generation_segment_s: u64,
    generation_duration_s: u64,
    campaign_segment_s: u64,
    campaign_rotation_s: u64,
    campaign_overlap_s: u64,
) -> Result<()> {
    let maximum_duration_s = campaign_rotation_s
        .checked_add(campaign_overlap_s)
        .ok_or_else(|| "campaign generation duration policy overflow".to_owned())?;
    if generation_segment_s != campaign_segment_s
        || generation_duration_s == 0
        || generation_duration_s > maximum_duration_s
    {
        return Err("generation timing differs from campaign policy".to_owned());
    }
    Ok(())
}

fn validate_precommit_elapsed(
    journal: &VerifiedJournal,
    precommit: usize,
    total_duration_s: u64,
) -> Result<()> {
    let required_mono_ns = total_duration_s
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "campaign duration nanoseconds overflow".to_owned())?;
    let prepared = precommit
        .checked_sub(1)
        .and_then(|index| journal.records.get(index))
        .ok_or_else(|| "campaign precommit boundary is empty".to_owned())?;
    if prepared.body.campaign_mono_ns < required_mono_ns {
        return Err("campaign precommit predates the requested duration".to_owned());
    }
    Ok(())
}

fn payload_u64(payload: &Value, field: &str, event: &str) -> Result<u64> {
    payload[field]
        .as_u64()
        .ok_or_else(|| format!("{event} lacks unsigned integer {field}"))
}

fn payload_text<'a>(payload: &'a Value, field: &str, event: &str) -> Result<&'a str> {
    payload[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{event} lacks nonempty string {field}"))
}

fn lifecycle_generation<'a>(
    generations: &'a [GenerationLifecycleExpectation],
    generation_index: Option<u64>,
    event: &str,
) -> Result<&'a GenerationLifecycleExpectation> {
    let index = generation_index.ok_or_else(|| format!("{event} is not generation-scoped"))?;
    generations
        .get(usize::try_from(index).map_err(|_| format!("{event} generation index overflow"))?)
        .filter(|generation| generation.generation_index == index)
        .ok_or_else(|| format!("{event} references a generation outside the campaign"))
}

fn validate_process_session_path(value: &str, expected_session_id: &str) -> Result<()> {
    let path = Path::new(value);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
        || path.file_name().and_then(|name| name.to_str()) != Some(expected_session_id)
        || path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("generations")
    {
        return Err("PROCESS_STARTED session path is not a generation path".to_owned());
    }
    Ok(())
}

fn validate_campaign_lifecycle(
    journal: &VerifiedJournal,
    campaign_id: &str,
    startup_sha256: &str,
    campaign_manifest_sha256: &str,
    total_duration_s: u64,
    generations: &[GenerationLifecycleExpectation],
    handovers: &[HandoverLifecycleExpectation],
) -> Result<()> {
    let mut identity_tokens = BTreeSet::new();
    for generation in generations {
        if generation.stream_epochs.len() != 2
            || !generation.stream_epochs.contains_key("depth")
            || !generation.stream_epochs.contains_key("trade")
            || !identity_tokens.insert(generation.session_id.as_str())
            || generation
                .stream_epochs
                .values()
                .any(|epoch| epoch.is_empty() || !identity_tokens.insert(epoch.as_str()))
        {
            return Err("campaign generation/session epoch identity was reused".to_owned());
        }
    }
    let mut states = (0..generations.len())
        .map(|index| (index as u64, GenerationLifecycleState::default()))
        .collect::<BTreeMap<_, _>>();
    let expected_handovers = handovers
        .iter()
        .map(|handover| {
            (
                (
                    handover.predecessor_generation_index,
                    handover.successor_generation_index,
                ),
                handover.proof_sha256.as_str(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut proof_started = BTreeSet::new();
    let mut promoted = BTreeMap::new();
    let mut observed_shutdowns = BTreeMap::<(u64, String), u64>::new();
    let mut available_shutdowns = BTreeMap::<(u64, String), u64>::new();
    let mut observed_shutdown_publications = BTreeSet::new();
    let mut campaign_started = 0_u64;
    let mut campaign_prepared = 0_u64;
    let mut campaign_committed = 0_u64;
    let mut campaign_prepared_boundary = None;
    let mut initial_active_registered = false;
    let mut candidate_registered = BTreeSet::new();
    let mut active_generation = None;
    // Mirror the supervisor's single-candidate invariant while allowing one
    // transport-only warm successor.  The warm child has no supervisor
    // authority until the preceding candidate promotes and an exact
    // CANDIDATE_REGISTERED event transfers it into `pending_candidate`.
    let mut pending_candidate = None;
    let mut warmed_generation = None;

    for record in &journal.records {
        if !matches!(
            record.body.channel.as_str(),
            "CAMPAIGN" | "CHILD_STDOUT" | "CHILD_STDERR" | "SUPERVISOR"
        ) || record.body.wall_ns == 0
        {
            return Err("campaign journal channel/wall timestamp is invalid".to_owned());
        }
        if record.body.channel == "CHILD_STDERR" {
            return Err("complete campaign journal contains child stderr".to_owned());
        }
        if let Some(index) = record.body.generation_index
            && generations
                .get(
                    usize::try_from(index)
                        .map_err(|_| "campaign journal generation index overflow".to_owned())?,
                )
                .is_none_or(|generation| generation.generation_index != index)
        {
            return Err("campaign journal references a generation outside the manifest".to_owned());
        }
        let event = record
            .body
            .payload
            .get("event")
            .ok_or_else(|| "campaign journal payload lacks event".to_owned())?
            .as_str()
            .ok_or_else(|| "campaign journal event is not a string".to_owned())?;
        let payload = &record.body.payload;
        let record_index = record.body.record_index;
        let channel_event_allowed = match record.body.channel.as_str() {
            "CHILD_STDOUT" => matches!(
                event,
                "PROCESS_STARTED"
                    | "TRANSPORT_CONNECTED"
                    | "SNAPSHOT_DURABLE"
                    | "SEGMENT_DURABLE"
                    | "SERVER_SHUTDOWN_DURABLE"
                    | "HEARTBEAT_DURABLE"
                    | "PROCESS_TERMINAL"
            ),
            "CAMPAIGN" => matches!(
                event,
                "CAMPAIGN_STARTED"
                    | "GENERATION_LAUNCHED"
                    | "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
                    | "GENERATION_EXITED"
                    | "HANDOVER_PROOF_STARTED"
                    | "CAMPAIGN_EVALUATION_PREPARED"
                    | "CAMPAIGN_COMMITTED"
                    | "CAMPAIGN_FAILED"
            ),
            "SUPERVISOR" => matches!(
                event,
                "INITIAL_ACTIVE_REGISTERED"
                    | "CANDIDATE_REGISTERED"
                    | "HANDOVER_PROVEN_AND_PROMOTED"
                    | "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE"
                    | "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING"
                    | "GENERATION_DISCONNECT_FAIL_CLOSED"
            ),
            _ => false,
        };
        if !channel_event_allowed {
            return Err(format!(
                "campaign journal event {event} is unknown or invalid for channel {}",
                record.body.channel
            ));
        }
        if record.body.channel == "CHILD_STDOUT" {
            let expected_schema = match event {
                "PROCESS_STARTED" => "CaptureProcessEventV1",
                "TRANSPORT_CONNECTED" => "TransportConnectedProcessEventV1",
                "SNAPSHOT_DURABLE" => "SnapshotDurableProcessEventV1",
                "SEGMENT_DURABLE" => "SegmentDurableProcessEventV1",
                "SERVER_SHUTDOWN_DURABLE" => "ServerShutdownDurableProcessEventV1",
                "HEARTBEAT_DURABLE" => "HeartbeatProcessEventV1",
                "PROCESS_TERMINAL" => "CaptureTerminalProcessEventV1",
                _ => unreachable!("child event allowlist is exhaustive"),
            };
            if payload["schema"].as_str() != Some(expected_schema) {
                return Err(format!("{event} uses the wrong child event schema"));
            }
            let generation =
                lifecycle_generation(generations, record.body.generation_index, event)?;
            let state = states
                .get(&generation.generation_index)
                .expect("child stdout lifecycle state exists");
            if payload["session_id"].as_str() != Some(generation.session_id.as_str())
                || (event != "PROCESS_STARTED"
                    && (state
                        .process_started_record
                        .is_none_or(|started| started >= record_index)
                        || state.process_terminal_record.is_some()))
            {
                return Err(format!("{event} child session/lifecycle is invalid"));
            }
        }
        match event {
            "CAMPAIGN_STARTED" => {
                campaign_started = campaign_started
                    .checked_add(1)
                    .ok_or_else(|| "CAMPAIGN_STARTED count overflow".to_owned())?;
                if record.body.channel != "CAMPAIGN"
                    || record.body.generation_index.is_some()
                    || payload
                        != &serde_json::json!({
                            "event":"CAMPAIGN_STARTED",
                            "campaign_id":campaign_id,
                            "startup_sha256":startup_sha256
                        })
                {
                    return Err("CAMPAIGN_STARTED identity is invalid".to_owned());
                }
            }
            "CAMPAIGN_EVALUATION_PREPARED" => {
                campaign_prepared = campaign_prepared
                    .checked_add(1)
                    .ok_or_else(|| "campaign prepared count overflow".to_owned())?;
                if record.body.channel != "CAMPAIGN"
                    || record.body.generation_index.is_some()
                    || payload != &serde_json::json!({"event":"CAMPAIGN_EVALUATION_PREPARED"})
                {
                    return Err("CAMPAIGN_EVALUATION_PREPARED scope is invalid".to_owned());
                }
                campaign_prepared_boundary =
                    Some((record.body.record_index, record.body.campaign_mono_ns));
            }
            "CAMPAIGN_COMMITTED" => {
                campaign_committed = campaign_committed
                    .checked_add(1)
                    .ok_or_else(|| "campaign commit count overflow".to_owned())?;
                if record.body.channel != "CAMPAIGN"
                    || record.body.generation_index.is_some()
                    || payload
                        != &serde_json::json!({
                            "event":"CAMPAIGN_COMMITTED",
                            "manifest_file":"campaign.json",
                            "manifest_sha256":campaign_manifest_sha256
                        })
                {
                    return Err("CAMPAIGN_COMMITTED identity is invalid".to_owned());
                }
            }
            "CAMPAIGN_FAILED" => {
                return Err("successful campaign journal contains CAMPAIGN_FAILED".to_owned());
            }
            "GENERATION_DISCONNECT_FAIL_CLOSED" => {
                return Err(
                    "successful campaign journal contains a fail-closed disconnect".to_owned(),
                );
            }
            "SERVER_SHUTDOWN_DURABLE" => {
                let generation =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                let lifecycle = states
                    .get(&generation.generation_index)
                    .expect("lifecycle state exists for verified generation");
                let shutdown = payload["shutdown"]
                    .as_object()
                    .ok_or_else(|| "SERVER_SHUTDOWN_DURABLE lacks shutdown object".to_owned())?;
                let shutdown_value = Value::Object(shutdown.clone());
                let stream = payload_text(&shutdown_value, "stream", event)?;
                let epoch = payload_text(&shutdown_value, "connection_epoch", event)?;
                let segment_index = payload_u64(&shutdown_value, "segment_index", event)?;
                payload_u64(&shutdown_value, "frame_index", event)?;
                let expected_raw_file = format!("segment-{segment_index:06}.bnraw");
                if record.body.channel != "CHILD_STDOUT"
                    || lifecycle
                        .process_started_record
                        .is_none_or(|started| started >= record_index)
                    || lifecycle.process_terminal_record.is_some()
                    || payload["schema"].as_str() != Some("ServerShutdownDurableProcessEventV1")
                    || payload["session_id"].as_str() != Some(generation.session_id.as_str())
                    || shutdown_value["schema"].as_str() != Some("DurableServerShutdownEventV1")
                    || !matches!(stream, "depth" | "trade")
                    || generation.stream_epochs.get(stream).map(String::as_str) != Some(epoch)
                    || shutdown_value["raw_file"].as_str() != Some(&expected_raw_file)
                    || payload_u64(&shutdown_value, "receive_mono_ns", event)? == 0
                    || payload_u64(&shutdown_value, "durable_record_count", event)? == 0
                    || payload_u64(&shutdown_value, "durable_through_offset", event)? == 0
                    || !valid_sha256(payload_text(&shutdown_value, "last_record_sha256", event)?)
                    || payload.as_object().map(|object| object.len()) != Some(4)
                    || shutdown.len() != 10
                {
                    return Err("SERVER_SHUTDOWN_DURABLE identity is invalid".to_owned());
                }
                let exact_shutdown = VerifiedServerShutdownV1 {
                    stream: stream.to_owned(),
                    connection_epoch: epoch.to_owned(),
                    segment_index,
                    raw_file: expected_raw_file,
                    frame_index: payload_u64(&shutdown_value, "frame_index", event)?,
                    receive_mono_ns: payload_u64(&shutdown_value, "receive_mono_ns", event)?,
                    durable_record_count: payload_u64(
                        &shutdown_value,
                        "durable_record_count",
                        event,
                    )?,
                    durable_through_offset: payload_u64(
                        &shutdown_value,
                        "durable_through_offset",
                        event,
                    )?,
                    last_record_sha256: payload_text(&shutdown_value, "last_record_sha256", event)?
                        .to_owned(),
                };
                if !generation.server_shutdowns.contains(&exact_shutdown)
                    || !observed_shutdown_publications
                        .insert((generation.generation_index, exact_shutdown))
                {
                    return Err(
                        "SERVER_SHUTDOWN_DURABLE does not bind one exact BNRAW record".to_owned(),
                    );
                }
                let stream_key = (generation.generation_index, stream.to_owned());
                let observed = observed_shutdowns.entry(stream_key).or_default();
                *observed = observed
                    .checked_add(1)
                    .ok_or_else(|| "serverShutdown journal count overflow".to_owned())?;
                let epoch_key = (generation.generation_index, epoch.to_owned());
                let available = available_shutdowns.entry(epoch_key).or_default();
                *available = available
                    .checked_add(1)
                    .ok_or_else(|| "available serverShutdown count overflow".to_owned())?;
            }
            "GENERATION_LAUNCHED" | "GENERATION_LAUNCHED_SERVER_SHUTDOWN" => {
                let generation =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                let state = states
                    .get(&generation.generation_index)
                    .expect("lifecycle state exists for verified generation");
                let immediate_candidate = generation.generation_index != 0
                    && active_generation == generation.generation_index.checked_sub(1)
                    && pending_candidate.is_none()
                    && warmed_generation.is_none();
                let warm_ahead = event == "GENERATION_LAUNCHED"
                    && generation.generation_index >= 2
                    && active_generation == generation.generation_index.checked_sub(2)
                    && pending_candidate == generation.generation_index.checked_sub(1)
                    && warmed_generation.is_none();
                if record.body.channel != "CAMPAIGN"
                    || state.launch_record.is_some()
                    || payload_u64(payload, "duration_s", event)? != generation.duration_requested_s
                    || if generation.generation_index == 0 {
                        event != "GENERATION_LAUNCHED"
                            || active_generation.is_some()
                            || pending_candidate.is_some()
                            || warmed_generation.is_some()
                    } else {
                        !immediate_candidate && !warm_ahead
                    }
                    || (event == "GENERATION_LAUNCHED"
                        && payload
                            != &serde_json::json!({
                                "event":"GENERATION_LAUNCHED",
                                "duration_s":generation.duration_requested_s
                            }))
                {
                    return Err(format!(
                        "generation {} launch is invalid",
                        generation.generation_index
                    ));
                }
                if event == "GENERATION_LAUNCHED_SERVER_SHUTDOWN" {
                    let source_generation = payload_u64(payload, "source_generation", event)?;
                    let source_epoch = payload_text(payload, "source_epoch", event)?;
                    if generation.generation_index == 0
                        || source_generation.checked_add(1) != Some(generation.generation_index)
                        || payload
                            != &serde_json::json!({
                                "event":"GENERATION_LAUNCHED_SERVER_SHUTDOWN",
                                "duration_s":generation.duration_requested_s,
                                "source_generation":source_generation,
                                "source_epoch":source_epoch
                            })
                    {
                        return Err("serverShutdown launch source generation is invalid".to_owned());
                    }
                    let source = generations
                        .get(usize::try_from(source_generation).map_err(|_| {
                            "serverShutdown source generation index overflow".to_owned()
                        })?)
                        .filter(|source| source.generation_index == source_generation)
                        .ok_or_else(|| "serverShutdown launch source is absent".to_owned())?;
                    if states.get(&source_generation).is_none_or(|state| {
                        state.process_terminal_record.is_some()
                            || state.generation_exited_record.is_some()
                    }) {
                        return Err("serverShutdown launch source is no longer active".to_owned());
                    }
                    if active_generation != Some(source_generation) {
                        return Err(
                            "serverShutdown launch source is not the active generation".to_owned()
                        );
                    }
                    if !source
                        .stream_epochs
                        .values()
                        .any(|epoch| epoch == source_epoch)
                    {
                        return Err(
                            "serverShutdown launch source epoch is not authoritative".to_owned()
                        );
                    }
                    let available = available_shutdowns
                        .get_mut(&(source_generation, source_epoch.to_owned()))
                        .ok_or_else(|| {
                            "serverShutdown launch lacks a prior durable source event".to_owned()
                        })?;
                    if *available == 0 {
                        return Err("serverShutdown durable source event was reused".to_owned());
                    }
                    *available -= 1;
                }
                states
                    .get_mut(&generation.generation_index)
                    .expect("lifecycle state exists for verified generation")
                    .launch_record = Some(record_index);
                if generation.generation_index != 0 {
                    if warm_ahead {
                        warmed_generation = Some(generation.generation_index);
                    } else {
                        pending_candidate = Some(generation.generation_index);
                    }
                }
            }
            "PROCESS_STARTED" => {
                let generation =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                let state = states
                    .get_mut(&generation.generation_index)
                    .expect("lifecycle state exists for verified generation");
                if record.body.channel != "CHILD_STDOUT"
                    || state.process_started_record.is_some()
                    || state
                        .launch_record
                        .is_none_or(|launch| launch >= record_index)
                    || payload["schema"].as_str() != Some("CaptureProcessEventV1")
                    || payload_u64(payload, "generation_index", event)?
                        != generation.generation_index
                    || payload["session_id"].as_str() != Some(generation.session_id.as_str())
                    || payload["symbol"].as_str() != Some(generation.symbol.as_str())
                    || payload["spec_revision"].as_str() != Some(SPEC_REVISION)
                    || payload["startup_manifest_sha256"].as_str()
                        != Some(generation.startup_sha256.as_str())
                    || payload_u64(payload, "process_id", event)? == 0
                {
                    return Err(format!(
                        "generation {} PROCESS_STARTED is invalid",
                        generation.generation_index
                    ));
                }
                validate_process_session_path(
                    payload_text(payload, "session_dir", event)?,
                    &generation.session_id,
                )?;
                state.process_started_record = Some(record_index);
                state.process_started_mono_ns = Some(record.body.campaign_mono_ns);
            }
            "PROCESS_TERMINAL" => {
                let generation =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                let prior_handover_is_promoted = generation.generation_index == 0
                    || generation
                        .generation_index
                        .checked_sub(1)
                        .is_some_and(|predecessor| {
                            promoted.contains_key(&(predecessor, generation.generation_index))
                        });
                let successor_started_before_terminal = generation
                    .generation_index
                    .checked_add(1)
                    .filter(|successor| (*successor as usize) < generations.len())
                    .is_none_or(|successor| {
                        states.get(&successor).is_some_and(|state| {
                            state
                                .process_started_record
                                .is_some_and(|started| started < record_index)
                                && state
                                    .process_started_mono_ns
                                    .is_some_and(|started| started <= record.body.campaign_mono_ns)
                        })
                    });
                let state = states
                    .get_mut(&generation.generation_index)
                    .expect("lifecycle state exists for verified generation");
                if record.body.channel != "CHILD_STDOUT"
                    || state.process_terminal_record.is_some()
                    || state
                        .process_started_record
                        .is_none_or(|started| started >= record_index)
                    || payload["schema"].as_str() != Some("CaptureTerminalProcessEventV1")
                    || payload["session_id"].as_str() != Some(generation.session_id.as_str())
                    || payload["status"].as_str() != Some("COMPLETE")
                    || payload["generation_manifest"].as_str() != Some("generation.json")
                    || !prior_handover_is_promoted
                    || !successor_started_before_terminal
                {
                    return Err(format!(
                        "generation {} PROCESS_TERMINAL is invalid",
                        generation.generation_index
                    ));
                }
                state.process_terminal_record = Some(record_index);
                state.process_terminal_mono_ns = Some(record.body.campaign_mono_ns);
            }
            "GENERATION_EXITED" => {
                let generation =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                let state = states
                    .get_mut(&generation.generation_index)
                    .expect("lifecycle state exists for verified generation");
                if record.body.channel != "CAMPAIGN"
                    || state.generation_exited_record.is_some()
                    || state
                        .process_terminal_record
                        .is_none_or(|terminal| terminal >= record_index)
                    || payload["success"].as_bool() != Some(true)
                    || payload_u64(payload, "code", event)? != 0
                {
                    return Err(format!(
                        "generation {} GENERATION_EXITED is invalid",
                        generation.generation_index
                    ));
                }
                state.generation_exited_record = Some(record_index);
                state.generation_exited_mono_ns = Some(record.body.campaign_mono_ns);
            }
            "HANDOVER_PROOF_STARTED" => {
                let successor =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                let predecessor = payload_u64(payload, "predecessor", event)?;
                let pair = (predecessor, successor.generation_index);
                let predecessor_state = states
                    .get(&predecessor)
                    .ok_or_else(|| "handover proof predecessor is absent".to_owned())?;
                let successor_state = states
                    .get(&successor.generation_index)
                    .expect("successor lifecycle state exists");
                if record.body.channel != "CAMPAIGN"
                    || predecessor.checked_add(1) != Some(successor.generation_index)
                    || payload
                        != &serde_json::json!({
                            "event":"HANDOVER_PROOF_STARTED",
                            "predecessor":predecessor
                        })
                    || !expected_handovers.contains_key(&pair)
                    || !proof_started.insert(pair)
                    || active_generation != Some(predecessor)
                    || pending_candidate != Some(successor.generation_index)
                    || !candidate_registered.contains(&successor.generation_index)
                    || predecessor_state
                        .generation_exited_record
                        .is_none_or(|exited| exited >= record_index)
                    || successor_state
                        .process_started_record
                        .is_none_or(|started| started >= record_index)
                    || successor_state.process_terminal_record.is_some()
                {
                    return Err("HANDOVER_PROOF_STARTED lifecycle/order is invalid".to_owned());
                }
            }
            "HANDOVER_PROVEN_AND_PROMOTED" => {
                let successor =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                let predecessor = payload_u64(payload, "predecessor", event)?;
                let pair = (predecessor, successor.generation_index);
                let proof_sha256 = payload_text(payload, "proof_sha256", event)?;
                let successor_state = states
                    .get(&successor.generation_index)
                    .expect("successor lifecycle state exists");
                if record.body.channel != "SUPERVISOR"
                    || predecessor.checked_add(1) != Some(successor.generation_index)
                    || payload
                        != &serde_json::json!({
                            "event":"HANDOVER_PROVEN_AND_PROMOTED",
                            "predecessor":predecessor,
                            "proof_sha256":proof_sha256
                        })
                    || !proof_started.contains(&pair)
                    || !candidate_registered.contains(&successor.generation_index)
                    || active_generation != Some(predecessor)
                    || pending_candidate != Some(successor.generation_index)
                    || promoted.insert(pair, proof_sha256.to_owned()).is_some()
                    || expected_handovers.get(&pair).copied() != Some(proof_sha256)
                    || successor_state.process_terminal_record.is_some()
                {
                    return Err(
                        "HANDOVER_PROVEN_AND_PROMOTED digest/lifecycle is invalid".to_owned()
                    );
                }
                active_generation = Some(successor.generation_index);
                pending_candidate = None;
            }
            "INITIAL_ACTIVE_REGISTERED" => {
                let generation =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                if generation.generation_index != 0
                    || initial_active_registered
                    || states[&0]
                        .process_started_record
                        .is_none_or(|started| started >= record_index)
                    || payload != &serde_json::json!({"event":"INITIAL_ACTIVE_REGISTERED"})
                {
                    return Err("INITIAL_ACTIVE_REGISTERED lifecycle is invalid".to_owned());
                }
                initial_active_registered = true;
                active_generation = Some(0);
            }
            "CANDIDATE_REGISTERED" => {
                let generation =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                if warmed_generation == Some(generation.generation_index)
                    && pending_candidate.is_none()
                    && active_generation == generation.generation_index.checked_sub(1)
                {
                    warmed_generation = None;
                    pending_candidate = Some(generation.generation_index);
                }
                if generation.generation_index == 0
                    || states[&generation.generation_index]
                        .process_started_record
                        .is_none_or(|started| started >= record_index)
                    || active_generation != generation.generation_index.checked_sub(1)
                    || pending_candidate != Some(generation.generation_index)
                    || !candidate_registered.insert(generation.generation_index)
                    || payload != &serde_json::json!({"event":"CANDIDATE_REGISTERED"})
                {
                    return Err("CANDIDATE_REGISTERED lifecycle is invalid".to_owned());
                }
            }
            "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE" | "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING" => {
                let generation =
                    lifecycle_generation(generations, record.body.generation_index, event)?;
                let source_epoch = payload_text(payload, "source_epoch", event)?;
                if !generation
                    .stream_epochs
                    .values()
                    .any(|epoch| epoch == source_epoch)
                    || payload
                        != &serde_json::json!({
                            "event":event,
                            "source_epoch":source_epoch
                        })
                    || (event == "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE"
                        && active_generation == Some(generation.generation_index))
                    || (event == "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING"
                        && (active_generation != Some(generation.generation_index)
                            || pending_candidate.is_none()))
                {
                    return Err(format!("{event} source/lifecycle is invalid"));
                }
                let available = available_shutdowns
                    .get_mut(&(generation.generation_index, source_epoch.to_owned()))
                    .ok_or_else(|| format!("{event} lacks a prior durable source event"))?;
                if *available == 0 {
                    return Err(format!("{event} reused a durable source event"));
                }
                *available -= 1;
            }
            "TRANSPORT_CONNECTED"
            | "SNAPSHOT_DURABLE"
            | "SEGMENT_DURABLE"
            | "HEARTBEAT_DURABLE" => {}
            _ => unreachable!("journal event allowlists are exhaustive"),
        }
    }

    if campaign_started != 1 || campaign_prepared != 1 || campaign_committed != 1 {
        return Err("campaign lifecycle boundary cardinality is invalid".to_owned());
    }
    if !initial_active_registered
        || active_generation != Some((generations.len() - 1) as u64)
        || pending_candidate.is_some()
        || warmed_generation.is_some()
    {
        return Err("campaign active-generation lifecycle is incomplete".to_owned());
    }
    if available_shutdowns
        .values()
        .any(|available| *available != 0)
    {
        return Err("durable serverShutdown event lacks one terminal disposition".to_owned());
    }
    for generation in generations {
        let state = states
            .get(&generation.generation_index)
            .expect("verified generation lifecycle state exists");
        if state.launch_record.is_none()
            || state.process_started_record.is_none()
            || state.process_terminal_record.is_none()
            || state.generation_exited_record.is_none()
        {
            return Err(format!(
                "generation {} lifecycle is incomplete",
                generation.generation_index
            ));
        }
        if observed_shutdown_publications
            .iter()
            .filter(|(index, _)| *index == generation.generation_index)
            .count()
            != generation.server_shutdowns.len()
        {
            return Err(format!(
                "generation {} journal/raw serverShutdown identities differ",
                generation.generation_index
            ));
        }
        for (stream, expected) in &generation.server_shutdown_events {
            if observed_shutdowns
                .get(&(generation.generation_index, stream.clone()))
                .copied()
                .unwrap_or(0)
                != *expected
            {
                return Err(format!(
                    "generation {} {stream} serverShutdown journal/raw count differs",
                    generation.generation_index
                ));
            }
        }
    }
    let required_mono_ns = total_duration_s
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "campaign duration nanoseconds overflow".to_owned())?;
    let first = states
        .get(&0)
        .ok_or_else(|| "campaign lifecycle has no first generation".to_owned())?;
    if first
        .process_started_mono_ns
        .is_none_or(|started| started > CAMPAIGN_STARTUP_GRACE_NS)
    {
        return Err("first generation PROCESS_STARTED exceeded startup grace".to_owned());
    }
    for successor_index in 1..generations.len() {
        let predecessor = states
            .get(&((successor_index - 1) as u64))
            .expect("complete predecessor lifecycle exists");
        let successor = states
            .get(&(successor_index as u64))
            .expect("complete successor lifecycle exists");
        let successor_started = successor
            .process_started_mono_ns
            .expect("complete successor lifecycle has start time");
        if predecessor
            .process_terminal_mono_ns
            .is_none_or(|terminal| successor_started >= terminal)
            || predecessor
                .generation_exited_mono_ns
                .is_none_or(|exited| successor_started >= exited)
        {
            return Err(format!(
                "generation {successor_index} did not start before its predecessor terminated"
            ));
        }
    }
    let mut covered_through_ns = first
        .process_started_mono_ns
        .and_then(|started| {
            generations[0]
                .duration_requested_s
                .checked_mul(1_000_000_000)
                .and_then(|duration| started.checked_add(duration))
        })
        .ok_or_else(|| "first generation coverage interval overflow".to_owned())?;
    let mut previous_start_ns = first
        .process_started_mono_ns
        .expect("first lifecycle start was checked");
    for index in 1..generations.len() {
        let started = states[&(index as u64)]
            .process_started_mono_ns
            .expect("complete lifecycle has process start");
        if started <= previous_start_ns || started > covered_through_ns {
            return Err(format!(
                "generation {index} declared coverage leaves a campaign gap or regresses"
            ));
        }
        let end = generations[index]
            .duration_requested_s
            .checked_mul(1_000_000_000)
            .and_then(|duration| started.checked_add(duration))
            .ok_or_else(|| format!("generation {index} coverage interval overflow"))?;
        covered_through_ns = covered_through_ns.max(end);
        previous_start_ns = started;
    }
    if covered_through_ns < required_mono_ns {
        return Err("declared generation windows do not cover the requested campaign".to_owned());
    }
    let last = states
        .get(&((generations.len() - 1) as u64))
        .expect("complete last generation lifecycle exists");
    let last_terminal_record = last
        .process_terminal_record
        .expect("complete last lifecycle has terminal record");
    let last_exit_record = last
        .generation_exited_record
        .expect("complete last lifecycle has exit record");
    let last_terminal_mono_ns = last
        .process_terminal_mono_ns
        .expect("complete last lifecycle has terminal time");
    let last_exit_mono_ns = last
        .generation_exited_mono_ns
        .expect("complete last lifecycle has exit time");
    if last_terminal_mono_ns < required_mono_ns || last_exit_mono_ns < required_mono_ns {
        return Err("last generation ended before the requested campaign duration".to_owned());
    }
    let (prepared_record, prepared_mono_ns) = campaign_prepared_boundary
        .ok_or_else(|| "campaign prepared boundary is absent".to_owned())?;
    if prepared_record <= last_terminal_record
        || prepared_record <= last_exit_record
        || prepared_mono_ns < last_terminal_mono_ns
        || prepared_mono_ns < last_exit_mono_ns
    {
        return Err("campaign prepared boundary predates the last generation end".to_owned());
    }
    let expected_pairs = expected_handovers.keys().copied().collect::<BTreeSet<_>>();
    if proof_started != expected_pairs
        || promoted.keys().copied().collect::<BTreeSet<_>>() != expected_pairs
    {
        return Err("campaign handover lifecycle cardinality is incomplete".to_owned());
    }
    Ok(())
}

fn elapsed_ns(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_nanos()).map_err(|_| "profile duration overflow".to_owned())
}

fn verify_raw_campaign_profiled_internal(
    campaign: &Path,
) -> Result<(VerifiedRawCampaignV1, RawCampaignVerificationPhaseTimingsV1)> {
    let total_started = Instant::now();
    let phase_started = Instant::now();
    let manifest_path = campaign.join("campaign.json");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    let manifest: CampaignManifestV1 = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid campaign manifest: {error}"))?;
    if manifest.schema != "RawCampaignManifestV1"
        || manifest.status != "COMPLETE"
        || campaign.file_name().and_then(|name| name.to_str()) != Some(&manifest.campaign_id)
        || !matches!(manifest.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
        || manifest.total_duration_s == 0
        || manifest.rotation_s == 0
        || manifest.overlap_s == 0
        || manifest.segment_s == 0
        || manifest.overlap_s != manifest.segment_s
        || !manifest.rotation_s.is_multiple_of(manifest.segment_s)
        || manifest.rotation_s.saturating_add(manifest.overlap_s) > 86_300
        || manifest.total_duration_s < manifest.overlap_s
        || manifest.started_wall_ns == 0
        || manifest.finished_wall_ns < manifest.started_wall_ns
        || manifest.spec_revision != SPEC_REVISION
        || manifest.credentials != "NONE"
        || manifest.order_entry != "ABSENT"
        || manifest.startup_file != "campaign-startup.json"
        || manifest.journal_file != "campaign-events.jsonl"
        || manifest.journal_boundary != "PRECOMMIT_PREFIX"
        || manifest.journal_precommit_records == 0
        || manifest.supervisor_gap_count != 0
        || ![
            &manifest.executable_sha256,
            &manifest.capture_executable_sha256,
            &manifest.public_config_sha256,
            &manifest.startup_sha256,
            &manifest.journal_precommit_sha256,
        ]
        .into_iter()
        .all(|digest| valid_sha256(digest))
    {
        return Err("campaign manifest contract/status is invalid".to_owned());
    }
    let startup_path = campaign.join(safe_relative(&manifest.startup_file)?);
    let startup_bytes = fs::read(&startup_path)
        .map_err(|error| format!("read {}: {error}", startup_path.display()))?;
    if sha256_bytes(&startup_bytes) != manifest.startup_sha256 {
        return Err("campaign startup digest mismatch".to_owned());
    }
    let startup: CampaignStartupV1 = serde_json::from_slice(&startup_bytes)
        .map_err(|error| format!("invalid campaign startup: {error}"))?;
    if startup.schema != "RawCampaignStartupV1"
        || startup.campaign_id != manifest.campaign_id
        || startup.symbol != manifest.symbol
        || startup.total_duration_s != manifest.total_duration_s
        || startup.rotation_s != manifest.rotation_s
        || startup.overlap_s != manifest.overlap_s
        || startup.segment_s != manifest.segment_s
        || startup.started_wall_ns != manifest.started_wall_ns
        || startup.process_id == 0
        || startup.executable_sha256 != manifest.executable_sha256
        || startup.capture_executable_sha256 != manifest.capture_executable_sha256
        || startup.public_config_sha256 != manifest.public_config_sha256
        || startup.spec_revision != manifest.spec_revision
        || startup.credentials != "NONE"
        || startup.order_entry != "ABSENT"
    {
        return Err("campaign startup differs from terminal manifest".to_owned());
    }
    let journal_path = campaign.join(safe_relative(&manifest.journal_file)?);
    let journal = scan_journal(&journal_path)?;
    let precommit = usize::try_from(manifest.journal_precommit_records)
        .map_err(|_| "campaign journal record count overflow".to_owned())?;
    let committed_records = precommit
        .checked_add(1)
        .ok_or_else(|| "campaign committed journal record count overflow".to_owned())?;
    if journal.records.len() != committed_records
        || journal.records[precommit - 1].record_sha256 != manifest.journal_precommit_sha256
        || journal.records[precommit - 1].body.payload["event"] != "CAMPAIGN_EVALUATION_PREPARED"
        || journal.records[0].body.payload["event"] != "CAMPAIGN_STARTED"
        || journal.records[0].body.payload["campaign_id"] != manifest.campaign_id
        || journal.records[0].body.payload["startup_sha256"] != manifest.startup_sha256
        || journal
            .records
            .iter()
            .any(|record| record.body.payload["event"] == "CAMPAIGN_FAILED")
    {
        return Err("campaign journal precommit/lifecycle is invalid".to_owned());
    }
    validate_precommit_elapsed(&journal, precommit, manifest.total_duration_s)?;
    let commit = &journal.records[precommit];
    let campaign_manifest_sha256 = sha256_bytes(&manifest_bytes);
    if commit.body.payload["event"] != "CAMPAIGN_COMMITTED"
        || commit.body.payload["manifest_file"] != "campaign.json"
        || commit.body.payload["manifest_sha256"] != campaign_manifest_sha256
        || commit.body.previous_record_sha256 != manifest.journal_precommit_sha256
    {
        return Err("campaign terminal commit does not bind campaign.json".to_owned());
    }
    if manifest.generations.is_empty()
        || manifest.handovers.len() != manifest.generations.len().saturating_sub(1)
    {
        return Err("campaign generation/handover cardinality is invalid".to_owned());
    }
    let manifest_startup_journal_ns = elapsed_ns(phase_started.elapsed())?;

    let phase_started = Instant::now();
    let mut expected_generation_dirs = BTreeSet::new();
    let mut expected_evaluations = BTreeSet::new();
    let mut verified_generations = Vec::new();
    let mut full_verifications = Vec::new();
    let mut lifecycle_generations = Vec::new();
    for (expected_index, generation) in manifest.generations.iter().enumerate() {
        if generation.generation_index != expected_index as u64
            || !valid_sha256(&generation.verification_sha256)
            || !valid_sha256(&generation.evaluation_file_sha256)
            || !valid_sha256(&generation.generation_manifest_sha256)
        {
            return Err("campaign generation result identity/digest is invalid".to_owned());
        }
        let expected_session_relative = format!("generations/{}", generation.session_id);
        if generation.session_dir != expected_session_relative {
            return Err("campaign generation path is not portable/exact".to_owned());
        }
        let session_path = campaign.join(safe_relative(&generation.session_dir)?);
        let verification = verify_segmented_generation(&session_path)?;
        campaign_generation_timing(
            verification.segment_duration_s,
            verification.duration_requested_s,
            manifest.segment_s,
            manifest.rotation_s,
            manifest.overlap_s,
        )?;
        if verification.generation_index != generation.generation_index
            || verification.session_id != generation.session_id
            || verification.symbol != manifest.symbol
            || verification.collector_executable_sha256 != manifest.capture_executable_sha256
            || verification.public_config_sha256 != manifest.public_config_sha256
            || verification.verification_sha256 != generation.verification_sha256
            || verification.generation_manifest_sha256 != generation.generation_manifest_sha256
            || stream_records(&verification, "depth")? != generation.depth_records
            || stream_records(&verification, "trade")? != generation.trade_records
        {
            return Err("reverified generation differs from campaign manifest".to_owned());
        }
        let expected_evaluation = format!(
            "evaluations/generation-{:03}-rust.json",
            generation.generation_index
        );
        if generation.evaluation_file != expected_evaluation {
            return Err("campaign evaluation path is not exact".to_owned());
        }
        let evaluation_path = campaign.join(safe_relative(&generation.evaluation_file)?);
        let evaluation_bytes = fs::read(&evaluation_path)
            .map_err(|error| format!("read {}: {error}", evaluation_path.display()))?;
        let mut portable = verification.clone();
        portable.session_dir = PathBuf::from(&generation.session_dir);
        let mut expected_bytes = serde_json::to_vec_pretty(&portable)
            .map_err(|error| format!("serialize generation report: {error}"))?;
        expected_bytes.push(b'\n');
        if evaluation_bytes != expected_bytes
            || sha256_bytes(&evaluation_bytes) != generation.evaluation_file_sha256
        {
            return Err("stored generation evaluation differs from independent replay".to_owned());
        }
        expected_generation_dirs.insert(generation.session_id.clone());
        expected_evaluations.insert(
            Path::new(&generation.evaluation_file)
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| "evaluation filename is invalid".to_owned())?
                .to_owned(),
        );
        verified_generations.push(VerifiedRawCampaignGenerationV1 {
            generation_index: generation.generation_index,
            session_id: generation.session_id.clone(),
            verification_sha256: verification.verification_sha256.clone(),
            depth_records: generation.depth_records,
            trade_records: generation.trade_records,
        });
        let startup_bytes = fs::read(session_path.join("startup.json"))
            .map_err(|error| format!("read generation startup for lifecycle: {error}"))?;
        lifecycle_generations.push(GenerationLifecycleExpectation {
            generation_index: verification.generation_index,
            session_id: verification.session_id.clone(),
            symbol: verification.symbol.clone(),
            duration_requested_s: verification.duration_requested_s,
            startup_sha256: sha256_bytes(&startup_bytes),
            stream_epochs: verification
                .streams
                .iter()
                .map(|stream| (stream.name.clone(), stream.connection_epoch.clone()))
                .collect(),
            server_shutdown_events: verification
                .streams
                .iter()
                .map(|stream| (stream.name.clone(), stream.server_shutdown_events))
                .collect(),
            server_shutdowns: verification
                .streams
                .iter()
                .flat_map(|stream| stream.server_shutdowns.iter().cloned())
                .collect(),
        });
        full_verifications.push(verification);
    }
    let generation_reverification_ns = elapsed_ns(phase_started.elapsed())?;

    let phase_started = Instant::now();
    let mut expected_handover_dirs = BTreeSet::new();
    let mut lifecycle_handovers = Vec::new();
    for (expected_predecessor, handover) in manifest.handovers.iter().enumerate() {
        let predecessor = expected_predecessor as u64;
        let successor = predecessor + 1;
        let expected_file =
            format!("handovers/handover-{predecessor:03}-to-{successor:03}/handover.json");
        if handover.predecessor_generation_index != predecessor
            || handover.successor_generation_index != successor
            || handover.proof_file != expected_file
            || !valid_sha256(&handover.proof_sha256)
            || !valid_sha256(&handover.proof_file_sha256)
        {
            return Err("campaign handover result identity/path is invalid".to_owned());
        }
        let proof_path = campaign.join(safe_relative(&handover.proof_file)?);
        let proof_bytes = fs::read(&proof_path)
            .map_err(|error| format!("read {}: {error}", proof_path.display()))?;
        if sha256_bytes(&proof_bytes) != handover.proof_file_sha256 {
            return Err("campaign handover file digest mismatch".to_owned());
        }
        let proof: RawGenerationHandoverProofV1 = serde_json::from_slice(&proof_bytes)
            .map_err(|error| format!("invalid handover proof JSON: {error}"))?;
        validate_raw_handover_proof_digest(&proof)?;
        let predecessor_verification = &full_verifications[predecessor as usize];
        let successor_verification = &full_verifications[successor as usize];
        let successor_startup_bytes = fs::read(
            campaign
                .join(&manifest.generations[successor as usize].session_dir)
                .join("startup.json"),
        )
        .map_err(|error| format!("read successor startup: {error}"))?;
        if proof.proof_sha256 != handover.proof_sha256
            || proof.predecessor_generation_index != predecessor
            || proof.successor_generation_index != successor
            || proof.predecessor_session_id != predecessor_verification.session_id
            || proof.successor_session_id != successor_verification.session_id
            || proof.symbol != manifest.symbol
            || proof.predecessor_verification_sha256 != predecessor_verification.verification_sha256
            || proof.successor_startup_sha256 != sha256_bytes(&successor_startup_bytes)
            || proof.successor_snapshot_record_sha256
                != successor_verification.snapshot_record_sha256
        {
            return Err("campaign handover proof differs from its exact generations".to_owned());
        }
        verify_terminal_raw_generation_handover_from_verified(
            &campaign.join(&manifest.generations[predecessor as usize].session_dir),
            &campaign.join(&manifest.generations[successor as usize].session_dir),
            predecessor_verification,
            successor_verification,
            &proof,
        )?;
        lifecycle_handovers.push(HandoverLifecycleExpectation {
            predecessor_generation_index: predecessor,
            successor_generation_index: successor,
            proof_sha256: proof.proof_sha256.clone(),
        });
        expected_handover_dirs.insert(format!("handover-{predecessor:03}-to-{successor:03}"));
        exact_entries(
            proof_path
                .parent()
                .ok_or_else(|| "handover proof lacks parent directory".to_owned())?,
            &BTreeSet::from(["handover.json".to_owned()]),
        )?;
    }
    let handover_reverification_ns = elapsed_ns(phase_started.elapsed())?;

    let phase_started = Instant::now();
    validate_campaign_lifecycle(
        &journal,
        &manifest.campaign_id,
        &manifest.startup_sha256,
        &campaign_manifest_sha256,
        manifest.total_duration_s,
        &lifecycle_generations,
        &lifecycle_handovers,
    )?;
    exact_entries(&campaign.join("generations"), &expected_generation_dirs)?;
    exact_entries(&campaign.join("evaluations"), &expected_evaluations)?;
    exact_entries(&campaign.join("handovers"), &expected_handover_dirs)?;
    exact_entries(&campaign.join("control"), &BTreeSet::new())?;
    exact_entries(
        campaign,
        &BTreeSet::from([
            "campaign-events.jsonl".to_owned(),
            "campaign-startup.json".to_owned(),
            "campaign.json".to_owned(),
            "control".to_owned(),
            "evaluations".to_owned(),
            "generations".to_owned(),
            "handovers".to_owned(),
        ]),
    )?;
    let journal_records = journal.records.len() as u64;
    let handovers = manifest.handovers.len() as u64;
    let material = VerificationMaterial {
        schema: "VerifiedRawCampaignDigestV1",
        campaign_id: &manifest.campaign_id,
        symbol: &manifest.symbol,
        total_duration_s: manifest.total_duration_s,
        rotation_s: manifest.rotation_s,
        overlap_s: manifest.overlap_s,
        segment_s: manifest.segment_s,
        campaign_manifest_sha256: &campaign_manifest_sha256,
        journal_records,
        journal_terminal_sha256: &journal.terminal_sha256,
        generations: &verified_generations,
        handovers,
    };
    let verification_sha256 = sha256_bytes(
        &serde_json::to_vec(&material)
            .map_err(|error| format!("serialize campaign verification digest: {error}"))?,
    );
    let verification = VerifiedRawCampaignV1 {
        schema: "VerifiedRawCampaignV1",
        status: "PASS",
        campaign_id: manifest.campaign_id,
        symbol: manifest.symbol,
        total_duration_s: manifest.total_duration_s,
        rotation_s: manifest.rotation_s,
        overlap_s: manifest.overlap_s,
        segment_s: manifest.segment_s,
        campaign_manifest_sha256,
        journal_records,
        journal_terminal_sha256: journal.terminal_sha256,
        generations: verified_generations,
        handovers,
        verification_sha256,
    };
    let lifecycle_and_finalization_ns = elapsed_ns(phase_started.elapsed())?;
    let total_ns = elapsed_ns(total_started.elapsed())?;
    let attributed_ns = manifest_startup_journal_ns
        .checked_add(generation_reverification_ns)
        .and_then(|value| value.checked_add(handover_reverification_ns))
        .and_then(|value| value.checked_add(lifecycle_and_finalization_ns))
        .ok_or_else(|| "profile attributed duration overflow".to_owned())?;
    let timings = RawCampaignVerificationPhaseTimingsV1 {
        clock: "STD_TIME_INSTANT_MONOTONIC".to_owned(),
        manifest_startup_journal_ns,
        generation_reverification_ns,
        handover_reverification_ns,
        lifecycle_and_finalization_ns,
        unattributed_ns: total_ns.saturating_sub(attributed_ns),
        total_ns,
    };
    Ok((verification, timings))
}

pub fn verify_raw_campaign(campaign: &Path) -> Result<VerifiedRawCampaignV1> {
    verify_raw_campaign_profiled_internal(campaign).map(|(verification, _)| verification)
}

pub fn profile_raw_campaign(campaign: &Path) -> Result<ProfiledRawCampaignVerificationV1> {
    let (verification, timings) = verify_raw_campaign_profiled_internal(campaign)?;
    Ok(ProfiledRawCampaignVerificationV1 {
        schema: "ProfiledRawCampaignVerificationV1".to_owned(),
        timings,
        verification,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CampaignJournalBodyV1, CampaignJournalEnvelopeV1, GenerationLifecycleExpectation,
        HandoverLifecycleExpectation, VerifiedJournal, campaign_generation_timing,
        validate_campaign_lifecycle, validate_precommit_elapsed,
    };
    use crate::generation_artifact::VerifiedServerShutdownV1;
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    const STARTUP_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MANIFEST_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PROOF_SHA: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";

    fn generation(index: u64, depth_shutdowns: u64) -> GenerationLifecycleExpectation {
        GenerationLifecycleExpectation {
            generation_index: index,
            session_id: format!("session-{index}"),
            symbol: "BTCUSDT".to_owned(),
            duration_requested_s: 60,
            startup_sha256: if index == 0 {
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned()
            } else {
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned()
            },
            stream_epochs: BTreeMap::from([
                ("depth".to_owned(), format!("depth-{index}")),
                ("trade".to_owned(), format!("trade-{index}")),
            ]),
            server_shutdown_events: BTreeMap::from([
                ("depth".to_owned(), depth_shutdowns),
                ("trade".to_owned(), 0),
            ]),
            server_shutdowns: if depth_shutdowns == 0 {
                Default::default()
            } else {
                [VerifiedServerShutdownV1 {
                    stream: "depth".to_owned(),
                    connection_epoch: format!("depth-{index}"),
                    segment_index: 0,
                    raw_file: "segment-000000.bnraw".to_owned(),
                    frame_index: 7,
                    receive_mono_ns: 3_000_000_000,
                    durable_record_count: 8,
                    durable_through_offset: 1024,
                    last_record_sha256:
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                            .to_owned(),
                }]
                .into_iter()
                .collect()
            },
        }
    }

    fn process_started(generation: &GenerationLifecycleExpectation) -> Value {
        json!({
            "schema":"CaptureProcessEventV1",
            "event":"PROCESS_STARTED",
            "session_id":generation.session_id.as_str(),
            "session_dir":format!("portable/generations/{}", generation.session_id),
            "generation_index":generation.generation_index,
            "symbol":generation.symbol.as_str(),
            "process_id":42,
            "spec_revision":SPEC_REVISION,
            "startup_manifest_sha256":generation.startup_sha256.as_str()
        })
    }

    fn process_terminal(generation: &GenerationLifecycleExpectation) -> Value {
        json!({
            "schema":"CaptureTerminalProcessEventV1",
            "event":"PROCESS_TERMINAL",
            "session_id":generation.session_id.as_str(),
            "status":"COMPLETE",
            "generation_manifest":"generation.json"
        })
    }

    fn record(
        index: usize,
        mono_ns: u64,
        generation_index: Option<u64>,
        channel: &str,
        payload: Value,
    ) -> CampaignJournalEnvelopeV1 {
        CampaignJournalEnvelopeV1 {
            body: CampaignJournalBodyV1 {
                schema: "RawCampaignJournalRecordV1".to_owned(),
                record_index: index as u64,
                wall_ns: 1,
                campaign_mono_ns: mono_ns,
                generation_index,
                channel: channel.to_owned(),
                payload,
                previous_record_sha256: "0".repeat(64),
            },
            record_sha256: "0".repeat(64),
        }
    }

    fn journal(
        use_server_shutdown: bool,
    ) -> (VerifiedJournal, Vec<GenerationLifecycleExpectation>) {
        let generations = vec![
            generation(0, u64::from(use_server_shutdown)),
            generation(1, 0),
        ];
        let mut events = vec![
            (
                None,
                "CAMPAIGN",
                json!({
                    "event":"CAMPAIGN_STARTED",
                    "campaign_id":"campaign",
                    "startup_sha256":STARTUP_SHA
                }),
            ),
            (
                Some(0),
                "CAMPAIGN",
                json!({"event":"GENERATION_LAUNCHED","duration_s":60}),
            ),
            (Some(0), "CHILD_STDOUT", process_started(&generations[0])),
            (
                Some(0),
                "SUPERVISOR",
                json!({"event":"INITIAL_ACTIVE_REGISTERED"}),
            ),
        ];
        if use_server_shutdown {
            events.push((
                Some(0),
                "CHILD_STDOUT",
                json!({
                    "schema":"ServerShutdownDurableProcessEventV1",
                    "event":"SERVER_SHUTDOWN_DURABLE",
                    "session_id":generations[0].session_id.as_str(),
                    "shutdown":{
                        "schema":"DurableServerShutdownEventV1",
                        "stream":"depth",
                        "connection_epoch":"depth-0",
                        "segment_index":0,
                        "raw_file":"segment-000000.bnraw",
                        "frame_index":7,
                        "receive_mono_ns":3_000_000_000_u64,
                        "durable_record_count":8,
                        "durable_through_offset":1024,
                        "last_record_sha256":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    }
                }),
            ));
            events.push((
                Some(1),
                "CAMPAIGN",
                json!({
                    "event":"GENERATION_LAUNCHED_SERVER_SHUTDOWN",
                    "duration_s":60,
                    "source_generation":0,
                    "source_epoch":"depth-0"
                }),
            ));
        } else {
            events.push((
                Some(1),
                "CAMPAIGN",
                json!({"event":"GENERATION_LAUNCHED","duration_s":60}),
            ));
        }
        events.extend([
            (Some(1), "CHILD_STDOUT", process_started(&generations[1])),
            (
                Some(1),
                "SUPERVISOR",
                json!({"event":"CANDIDATE_REGISTERED"}),
            ),
            (Some(0), "CHILD_STDOUT", process_terminal(&generations[0])),
            (
                Some(0),
                "CAMPAIGN",
                json!({"event":"GENERATION_EXITED","success":true,"code":0}),
            ),
            (
                Some(1),
                "CAMPAIGN",
                json!({"event":"HANDOVER_PROOF_STARTED","predecessor":0}),
            ),
            (
                Some(1),
                "SUPERVISOR",
                json!({
                    "event":"HANDOVER_PROVEN_AND_PROMOTED",
                    "predecessor":0,
                    "proof_sha256":PROOF_SHA
                }),
            ),
            (Some(1), "CHILD_STDOUT", process_terminal(&generations[1])),
            (
                Some(1),
                "CAMPAIGN",
                json!({"event":"GENERATION_EXITED","success":true,"code":0}),
            ),
            (
                None,
                "CAMPAIGN",
                json!({"event":"CAMPAIGN_EVALUATION_PREPARED"}),
            ),
            (
                None,
                "CAMPAIGN",
                json!({
                    "event":"CAMPAIGN_COMMITTED",
                    "manifest_file":"campaign.json",
                    "manifest_sha256":MANIFEST_SHA
                }),
            ),
        ]);
        let records = events
            .into_iter()
            .enumerate()
            .map(|(index, (generation, channel, payload))| {
                let mono_ns = match (payload["event"].as_str(), generation) {
                    (
                        Some("GENERATION_LAUNCHED" | "GENERATION_LAUNCHED_SERVER_SHUTDOWN"),
                        Some(1),
                    ) => 60_000_000_000,
                    (Some("PROCESS_STARTED"), Some(1)) => 61_000_000_000,
                    (Some("CANDIDATE_REGISTERED"), Some(1)) => 62_000_000_000,
                    (Some("PROCESS_TERMINAL"), Some(0)) => 63_000_000_000,
                    (Some("GENERATION_EXITED"), Some(0)) => 64_000_000_000,
                    (Some("HANDOVER_PROOF_STARTED"), Some(1)) => 65_000_000_000,
                    (Some("HANDOVER_PROVEN_AND_PROMOTED"), Some(1)) => 66_000_000_000,
                    (Some("PROCESS_TERMINAL"), Some(1)) => 121_000_000_000,
                    (Some("GENERATION_EXITED"), Some(1)) => 121_000_000_001,
                    (Some("CAMPAIGN_EVALUATION_PREPARED"), None) => 121_000_000_002,
                    (Some("CAMPAIGN_COMMITTED"), None) => 121_000_000_003,
                    _ => (index as u64) * 1_000_000_000,
                };
                record(index, mono_ns, generation, channel, payload)
            })
            .collect();
        (
            VerifiedJournal {
                records,
                terminal_sha256: "0".repeat(64),
            },
            generations,
        )
    }

    fn handovers() -> Vec<HandoverLifecycleExpectation> {
        vec![HandoverLifecycleExpectation {
            predecessor_generation_index: 0,
            successor_generation_index: 1,
            proof_sha256: PROOF_SHA.to_owned(),
        }]
    }

    fn validate(journal: &VerifiedJournal, generations: &[GenerationLifecycleExpectation]) -> bool {
        validate_campaign_lifecycle(
            journal,
            "campaign",
            STARTUP_SHA,
            MANIFEST_SHA,
            120,
            generations,
            &handovers(),
        )
        .is_ok()
    }

    fn warm_ahead_journal() -> (
        VerifiedJournal,
        Vec<GenerationLifecycleExpectation>,
        Vec<HandoverLifecycleExpectation>,
    ) {
        let mut generations = vec![generation(0, 0), generation(1, 0), generation(2, 0)];
        for generation in &mut generations {
            generation.duration_requested_s = 120;
        }
        let handovers = vec![
            HandoverLifecycleExpectation {
                predecessor_generation_index: 0,
                successor_generation_index: 1,
                proof_sha256: PROOF_SHA.to_owned(),
            },
            HandoverLifecycleExpectation {
                predecessor_generation_index: 1,
                successor_generation_index: 2,
                proof_sha256: PROOF_SHA.to_owned(),
            },
        ];
        let events = vec![
            (
                0,
                None,
                "CAMPAIGN",
                json!({"event":"CAMPAIGN_STARTED","campaign_id":"campaign","startup_sha256":STARTUP_SHA}),
            ),
            (
                100_000_000,
                Some(0),
                "CAMPAIGN",
                json!({"event":"GENERATION_LAUNCHED","duration_s":120}),
            ),
            (
                1_000_000_000,
                Some(0),
                "CHILD_STDOUT",
                process_started(&generations[0]),
            ),
            (
                2_000_000_000,
                Some(0),
                "SUPERVISOR",
                json!({"event":"INITIAL_ACTIVE_REGISTERED"}),
            ),
            (
                60_000_000_000,
                Some(1),
                "CAMPAIGN",
                json!({"event":"GENERATION_LAUNCHED","duration_s":120}),
            ),
            (
                61_000_000_000,
                Some(1),
                "CHILD_STDOUT",
                process_started(&generations[1]),
            ),
            (
                62_000_000_000,
                Some(1),
                "SUPERVISOR",
                json!({"event":"CANDIDATE_REGISTERED"}),
            ),
            // Generation 2 is transport-warm while generation 1 is still the
            // sole ownership candidate of active generation 0.
            (
                120_000_000_000,
                Some(2),
                "CAMPAIGN",
                json!({"event":"GENERATION_LAUNCHED","duration_s":120}),
            ),
            (
                121_000_000_000,
                Some(2),
                "CHILD_STDOUT",
                process_started(&generations[2]),
            ),
            (
                122_000_000_000,
                Some(0),
                "CHILD_STDOUT",
                process_terminal(&generations[0]),
            ),
            (
                123_000_000_000,
                Some(0),
                "CAMPAIGN",
                json!({"event":"GENERATION_EXITED","success":true,"code":0}),
            ),
            (
                124_000_000_000,
                Some(1),
                "CAMPAIGN",
                json!({"event":"HANDOVER_PROOF_STARTED","predecessor":0}),
            ),
            (
                125_000_000_000,
                Some(1),
                "SUPERVISOR",
                json!({"event":"HANDOVER_PROVEN_AND_PROMOTED","predecessor":0,"proof_sha256":PROOF_SHA}),
            ),
            (
                126_000_000_000,
                Some(2),
                "SUPERVISOR",
                json!({"event":"CANDIDATE_REGISTERED"}),
            ),
            (
                182_000_000_000,
                Some(1),
                "CHILD_STDOUT",
                process_terminal(&generations[1]),
            ),
            (
                183_000_000_000,
                Some(1),
                "CAMPAIGN",
                json!({"event":"GENERATION_EXITED","success":true,"code":0}),
            ),
            (
                184_000_000_000,
                Some(2),
                "CAMPAIGN",
                json!({"event":"HANDOVER_PROOF_STARTED","predecessor":1}),
            ),
            (
                185_000_000_000,
                Some(2),
                "SUPERVISOR",
                json!({"event":"HANDOVER_PROVEN_AND_PROMOTED","predecessor":1,"proof_sha256":PROOF_SHA}),
            ),
            (
                241_000_000_000,
                Some(2),
                "CHILD_STDOUT",
                process_terminal(&generations[2]),
            ),
            (
                242_000_000_000,
                Some(2),
                "CAMPAIGN",
                json!({"event":"GENERATION_EXITED","success":true,"code":0}),
            ),
            (
                243_000_000_000,
                None,
                "CAMPAIGN",
                json!({"event":"CAMPAIGN_EVALUATION_PREPARED"}),
            ),
            (
                244_000_000_000,
                None,
                "CAMPAIGN",
                json!({"event":"CAMPAIGN_COMMITTED","manifest_file":"campaign.json","manifest_sha256":MANIFEST_SHA}),
            ),
        ];
        let records = events
            .into_iter()
            .enumerate()
            .map(|(index, (mono_ns, generation, channel, payload))| {
                record(index, mono_ns, generation, channel, payload)
            })
            .collect();
        (
            VerifiedJournal {
                records,
                terminal_sha256: "0".repeat(64),
            },
            generations,
            handovers,
        )
    }

    fn validate_warm_ahead(
        journal: &VerifiedJournal,
        generations: &[GenerationLifecycleExpectation],
        handovers: &[HandoverLifecycleExpectation],
    ) -> bool {
        validate_campaign_lifecycle(
            journal,
            "campaign",
            STARTUP_SHA,
            MANIFEST_SHA,
            240,
            generations,
            handovers,
        )
        .is_ok()
    }

    #[test]
    fn one_transport_only_warm_successor_requires_ordered_authority_transfer() {
        let (valid, generations, handovers) = warm_ahead_journal();
        assert!(validate_warm_ahead(&valid, &generations, &handovers));

        let (mut premature_registration, _, _) = warm_ahead_journal();
        let promotion = premature_registration
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(1)
                    && record.body.payload["event"] == "HANDOVER_PROVEN_AND_PROMOTED"
            })
            .unwrap();
        let registration = premature_registration
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(2)
                    && record.body.payload["event"] == "CANDIDATE_REGISTERED"
            })
            .unwrap();
        let (left, right) = premature_registration.records.split_at_mut(registration);
        std::mem::swap(
            &mut left[promotion].body.channel,
            &mut right[0].body.channel,
        );
        std::mem::swap(
            &mut left[promotion].body.generation_index,
            &mut right[0].body.generation_index,
        );
        std::mem::swap(
            &mut left[promotion].body.payload,
            &mut right[0].body.payload,
        );
        assert!(!validate_warm_ahead(
            &premature_registration,
            &generations,
            &handovers
        ));

        let (mut terminal_before_promotion, _, _) = warm_ahead_journal();
        let promotion = terminal_before_promotion
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(2)
                    && record.body.payload["event"] == "HANDOVER_PROVEN_AND_PROMOTED"
            })
            .unwrap();
        let terminal = terminal_before_promotion
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(2)
                    && record.body.payload["event"] == "PROCESS_TERMINAL"
            })
            .unwrap();
        let (left, right) = terminal_before_promotion.records.split_at_mut(terminal);
        std::mem::swap(
            &mut left[promotion].body.channel,
            &mut right[0].body.channel,
        );
        std::mem::swap(
            &mut left[promotion].body.generation_index,
            &mut right[0].body.generation_index,
        );
        std::mem::swap(
            &mut left[promotion].body.payload,
            &mut right[0].body.payload,
        );
        assert!(!validate_warm_ahead(
            &terminal_before_promotion,
            &generations,
            &handovers
        ));

        let (mut duplicate_warm_launch, _, _) = warm_ahead_journal();
        let warm_launch = duplicate_warm_launch
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(2)
                    && record.body.payload["event"] == "GENERATION_LAUNCHED"
            })
            .unwrap();
        let duplicate = duplicate_warm_launch.records[warm_launch].clone();
        duplicate_warm_launch
            .records
            .insert(warm_launch + 1, duplicate);
        for (index, record) in duplicate_warm_launch.records.iter_mut().enumerate() {
            record.body.record_index = index as u64;
        }
        assert!(!validate_warm_ahead(
            &duplicate_warm_launch,
            &generations,
            &handovers
        ));
    }

    #[test]
    fn complete_planned_and_server_shutdown_lifecycles_are_valid() {
        let (planned, planned_generations) = journal(false);
        assert!(validate(&planned, &planned_generations));

        let (shutdown, shutdown_generations) = journal(true);
        assert!(validate(&shutdown, &shutdown_generations));
    }

    #[test]
    fn lifecycle_mutants_cannot_reach_terminal_pass() {
        let (mut wrong_duration, generations) = journal(false);
        wrong_duration.records[1].body.payload["duration_s"] = json!(59);
        assert!(!validate(&wrong_duration, &generations));

        let (mut ambiguous_launch, generations) = journal(false);
        ambiguous_launch.records[1].body.payload["extra"] = json!(true);
        assert!(!validate(&ambiguous_launch, &generations));

        let (mut missing_terminal, generations) = journal(false);
        let terminal = missing_terminal
            .records
            .iter_mut()
            .find(|record| {
                record.body.generation_index == Some(0)
                    && record.body.payload["event"] == "PROCESS_TERMINAL"
            })
            .unwrap();
        terminal.body.payload["event"] = json!("HEARTBEAT_DURABLE");
        assert!(!validate(&missing_terminal, &generations));

        let (mut wrong_proof, generations) = journal(false);
        let promotion = wrong_proof
            .records
            .iter_mut()
            .find(|record| record.body.payload["event"] == "HANDOVER_PROVEN_AND_PROMOTED")
            .unwrap();
        promotion.body.payload["proof_sha256"] = json!(STARTUP_SHA);
        assert!(!validate(&wrong_proof, &generations));

        let (mut child_stderr, generations) = journal(false);
        child_stderr.records[2].body.channel = "CHILD_STDERR".to_owned();
        assert!(!validate(&child_stderr, &generations));

        let (mut eventless_stdout, generations) = journal(false);
        eventless_stdout.records[2].body.payload = json!({"text":"untyped stdout"});
        assert!(!validate(&eventless_stdout, &generations));

        let (mut unknown_event, generations) = journal(false);
        unknown_event.records[2].body.payload =
            json!({"event":"UNKNOWN_CHILD_EVENT","schema":"UnknownV1"});
        assert!(!validate(&unknown_event, &generations));

        let (mut ambiguous_handover, generations) = journal(false);
        let handover = ambiguous_handover
            .records
            .iter_mut()
            .find(|record| record.body.payload["event"] == "HANDOVER_PROOF_STARTED")
            .unwrap();
        handover.body.payload["extra"] = json!(true);
        assert!(!validate(&ambiguous_handover, &generations));

        let (mut reordered, generations) = journal(false);
        let terminal_index = reordered
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(0)
                    && record.body.payload["event"] == "PROCESS_TERMINAL"
            })
            .unwrap();
        let exit_index = reordered
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(0)
                    && record.body.payload["event"] == "GENERATION_EXITED"
            })
            .unwrap();
        let terminal_channel = reordered.records[terminal_index].body.channel.clone();
        let terminal_payload = reordered.records[terminal_index].body.payload.clone();
        reordered.records[terminal_index].body.channel =
            reordered.records[exit_index].body.channel.clone();
        reordered.records[terminal_index].body.payload =
            reordered.records[exit_index].body.payload.clone();
        reordered.records[exit_index].body.channel = terminal_channel;
        reordered.records[exit_index].body.payload = terminal_payload;
        assert!(!validate(&reordered, &generations));
    }

    #[test]
    fn server_shutdown_launch_requires_its_prior_durable_raw_epoch() {
        let (mut forged, generations) = journal(true);
        let launch = forged
            .records
            .iter_mut()
            .find(|record| record.body.payload["event"] == "GENERATION_LAUNCHED_SERVER_SHUTDOWN")
            .unwrap();
        launch.body.payload["source_epoch"] = json!("trade-0");
        assert!(!validate(&forged, &generations));

        let (mut forged_identity, generations) = journal(true);
        let publication = forged_identity
            .records
            .iter_mut()
            .find(|record| record.body.payload["event"] == "SERVER_SHUTDOWN_DURABLE")
            .unwrap();
        publication.body.payload["shutdown"]["durable_through_offset"] = json!(1025);
        assert!(!validate(&forged_identity, &generations));
    }

    #[test]
    fn active_shutdown_cannot_claim_an_absent_pending_candidate() {
        let (mut forged, generations) = journal(true);
        let launch_index = forged
            .records
            .iter()
            .position(|record| {
                record.body.payload["event"] == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
            })
            .unwrap();
        forged.records[launch_index].body.generation_index = Some(0);
        forged.records[launch_index].body.channel = "SUPERVISOR".to_owned();
        forged.records[launch_index].body.payload = json!({
            "event":"SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
            "source_epoch":"depth-0"
        });
        let planned_launch = record(
            0,
            forged.records[launch_index].body.campaign_mono_ns + 1,
            Some(1),
            "CAMPAIGN",
            json!({"event":"GENERATION_LAUNCHED","duration_s":60}),
        );
        forged.records.insert(launch_index + 1, planned_launch);
        for (index, record) in forged.records.iter_mut().enumerate() {
            record.body.record_index = index as u64;
        }
        assert!(!validate(&forged, &generations));

        let (mut ambiguous_disposition, generations) = journal(true);
        let launch_index = ambiguous_disposition
            .records
            .iter()
            .position(|record| {
                record.body.payload["event"] == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
            })
            .unwrap();
        ambiguous_disposition.records[launch_index].body.payload["extra"] = json!(true);
        assert!(!validate(&ambiguous_disposition, &generations));
    }

    #[test]
    fn active_shutdown_pending_disposition_is_exact_and_consumes_one_raw_event() {
        let (mut valid, mut generations) = journal(true);
        let launch_index = valid
            .records
            .iter()
            .position(|record| {
                record.body.payload["event"] == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
            })
            .unwrap();
        let second_shutdown = VerifiedServerShutdownV1 {
            stream: "depth".to_owned(),
            connection_epoch: "depth-0".to_owned(),
            segment_index: 0,
            raw_file: "segment-000000.bnraw".to_owned(),
            frame_index: 8,
            receive_mono_ns: 4_000_000_000,
            durable_record_count: 9,
            durable_through_offset: 2048,
            last_record_sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
        };
        generations[0]
            .server_shutdown_events
            .insert("depth".to_owned(), 2);
        generations[0]
            .server_shutdowns
            .insert(second_shutdown.clone());
        let publication = record(
            0,
            valid.records[launch_index].body.campaign_mono_ns + 1,
            Some(0),
            "CHILD_STDOUT",
            json!({
                "schema":"ServerShutdownDurableProcessEventV1",
                "event":"SERVER_SHUTDOWN_DURABLE",
                "session_id":"session-0",
                "shutdown":{
                    "schema":"DurableServerShutdownEventV1",
                    "stream":second_shutdown.stream,
                    "connection_epoch":second_shutdown.connection_epoch,
                    "segment_index":second_shutdown.segment_index,
                    "raw_file":second_shutdown.raw_file,
                    "frame_index":second_shutdown.frame_index,
                    "receive_mono_ns":second_shutdown.receive_mono_ns,
                    "durable_record_count":second_shutdown.durable_record_count,
                    "durable_through_offset":second_shutdown.durable_through_offset,
                    "last_record_sha256":second_shutdown.last_record_sha256
                }
            }),
        );
        let disposition = record(
            0,
            valid.records[launch_index].body.campaign_mono_ns + 2,
            Some(0),
            "SUPERVISOR",
            json!({
                "event":"SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
                "source_epoch":"depth-0"
            }),
        );
        valid.records.insert(launch_index + 1, publication);
        valid.records.insert(launch_index + 2, disposition);
        for (index, record) in valid.records.iter_mut().enumerate() {
            record.body.record_index = index as u64;
        }
        assert!(validate(&valid, &generations));

        valid.records[launch_index + 2].body.payload["extra"] = json!(true);
        assert!(!validate(&valid, &generations));
    }

    #[test]
    fn successor_cannot_launch_before_its_predecessor_is_active() {
        let (mut forged, generations) = journal(false);
        let initial_active = forged
            .records
            .iter()
            .position(|record| record.body.payload["event"] == "INITIAL_ACTIVE_REGISTERED")
            .unwrap();
        let successor_launch = forged
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(1)
                    && record.body.payload["event"] == "GENERATION_LAUNCHED"
            })
            .unwrap();
        let active_scope = forged.records[initial_active].body.generation_index;
        let active_channel = forged.records[initial_active].body.channel.clone();
        let active_payload = forged.records[initial_active].body.payload.clone();
        forged.records[initial_active].body.generation_index =
            forged.records[successor_launch].body.generation_index;
        forged.records[initial_active].body.channel =
            forged.records[successor_launch].body.channel.clone();
        forged.records[initial_active].body.payload =
            forged.records[successor_launch].body.payload.clone();
        forged.records[successor_launch].body.generation_index = active_scope;
        forged.records[successor_launch].body.channel = active_channel;
        forged.records[successor_launch].body.payload = active_payload;
        assert!(!validate(&forged, &generations));
    }

    #[test]
    fn child_events_and_connection_epochs_keep_one_exact_identity() {
        let (mut forged_event, generations) = journal(false);
        let terminal_index = forged_event
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(0)
                    && record.body.payload["event"] == "PROCESS_TERMINAL"
            })
            .unwrap();
        let heartbeat = record(
            0,
            forged_event.records[terminal_index].body.campaign_mono_ns - 1,
            Some(0),
            "CHILD_STDOUT",
            json!({
                "schema":"HeartbeatProcessEventV1",
                "event":"HEARTBEAT_DURABLE",
                "session_id":"session-1"
            }),
        );
        forged_event.records.insert(terminal_index, heartbeat);
        for (index, record) in forged_event.records.iter_mut().enumerate() {
            record.body.record_index = index as u64;
        }
        assert!(!validate(&forged_event, &generations));

        let (journal, mut reused_epoch) = journal(false);
        reused_epoch[1]
            .stream_epochs
            .insert("depth".to_owned(), "trade-0".to_owned());
        assert!(!validate(&journal, &reused_epoch));
    }

    #[test]
    fn temporal_coverage_mutants_cannot_hide_idle_campaign_time() {
        let (mut late_start, generations) = journal(false);
        let first_start = late_start
            .records
            .iter()
            .position(|record| {
                record.body.generation_index == Some(0)
                    && record.body.payload["event"] == "PROCESS_STARTED"
            })
            .unwrap();
        for record in late_start.records.iter_mut().skip(first_start) {
            if record.body.campaign_mono_ns < 120_000_000_000 {
                record.body.campaign_mono_ns = 31_000_000_000 + record.body.record_index;
            }
        }
        assert!(!validate(&late_start, &generations));

        let (mut no_overlap, generations) = journal(false);
        let reordered_indices = [
            no_overlap
                .records
                .iter()
                .position(|record| {
                    record.body.generation_index == Some(1)
                        && record.body.payload["event"] == "GENERATION_LAUNCHED"
                })
                .unwrap(),
            no_overlap
                .records
                .iter()
                .position(|record| {
                    record.body.generation_index == Some(1)
                        && record.body.payload["event"] == "PROCESS_STARTED"
                })
                .unwrap(),
            no_overlap
                .records
                .iter()
                .position(|record| {
                    record.body.generation_index == Some(0)
                        && record.body.payload["event"] == "PROCESS_TERMINAL"
                })
                .unwrap(),
            no_overlap
                .records
                .iter()
                .position(|record| {
                    record.body.generation_index == Some(0)
                        && record.body.payload["event"] == "GENERATION_EXITED"
                })
                .unwrap(),
        ];
        let reordered_values = reordered_indices.map(|index| {
            let body = &no_overlap.records[index].body;
            (
                body.generation_index,
                body.channel.clone(),
                body.payload.clone(),
            )
        });
        for (target, source) in reordered_indices.into_iter().zip([2_usize, 3, 0, 1]) {
            let (generation_index, channel, payload) = &reordered_values[source];
            no_overlap.records[target].body.generation_index = *generation_index;
            no_overlap.records[target].body.channel.clone_from(channel);
            no_overlap.records[target].body.payload.clone_from(payload);
        }
        assert!(!validate(&no_overlap, &generations));

        let (mut early_tail, generations) = journal(false);
        for record in &mut early_tail.records {
            if record.body.generation_index == Some(1)
                && record.body.payload["event"] == "PROCESS_TERMINAL"
            {
                record.body.campaign_mono_ns = 119_000_000_000;
            } else if record.body.generation_index == Some(1)
                && record.body.payload["event"] == "GENERATION_EXITED"
            {
                record.body.campaign_mono_ns = 119_000_000_001;
            }
        }
        assert!(!validate(&early_tail, &generations));

        // A delayed terminal event is not market-data coverage.  Even if the
        // terminal/precommit timestamps reach 120 s, two declared 2 s
        // generation windows beginning near 2 s and 61 s leave a large gap.
        let (mut delayed_terminal, mut generations) = journal(false);
        for generation in &mut generations {
            generation.duration_requested_s = 2;
        }
        for record in &mut delayed_terminal.records {
            if matches!(
                record.body.payload["event"].as_str(),
                Some("GENERATION_LAUNCHED")
            ) {
                record.body.payload["duration_s"] = json!(2);
            }
        }
        assert!(!validate(&delayed_terminal, &generations));
    }

    #[test]
    fn one_short_generation_plus_idle_precommit_is_rejected() {
        let mut only_generation = generation(0, 0);
        only_generation.duration_requested_s = 83_700;
        let events = [
            record(
                0,
                0,
                None,
                "CAMPAIGN",
                json!({
                    "event":"CAMPAIGN_STARTED",
                    "campaign_id":"campaign",
                    "startup_sha256":STARTUP_SHA
                }),
            ),
            record(
                1,
                1_000_000_000,
                Some(0),
                "CAMPAIGN",
                json!({"event":"GENERATION_LAUNCHED","duration_s":83_700}),
            ),
            record(
                2,
                2_000_000_000,
                Some(0),
                "CHILD_STDOUT",
                process_started(&only_generation),
            ),
            record(
                3,
                83_700_000_000_000,
                Some(0),
                "CHILD_STDOUT",
                process_terminal(&only_generation),
            ),
            record(
                4,
                83_700_000_000_001,
                Some(0),
                "CAMPAIGN",
                json!({"event":"GENERATION_EXITED","success":true,"code":0}),
            ),
            record(
                5,
                86_400_000_000_000,
                None,
                "CAMPAIGN",
                json!({"event":"CAMPAIGN_EVALUATION_PREPARED"}),
            ),
            record(
                6,
                86_400_000_000_001,
                None,
                "CAMPAIGN",
                json!({
                    "event":"CAMPAIGN_COMMITTED",
                    "manifest_file":"campaign.json",
                    "manifest_sha256":MANIFEST_SHA
                }),
            ),
        ];
        let journal = VerifiedJournal {
            records: events.into(),
            terminal_sha256: "0".repeat(64),
        };
        assert!(
            validate_campaign_lifecycle(
                &journal,
                "campaign",
                STARTUP_SHA,
                MANIFEST_SHA,
                86_400,
                &[only_generation],
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn campaign_timing_and_precommit_duration_mutants_are_rejected() {
        campaign_generation_timing(30, 60, 30, 30, 30).unwrap();
        assert!(campaign_generation_timing(15, 60, 30, 30, 30).is_err());
        assert!(campaign_generation_timing(30, 61, 30, 30, 30).is_err());

        let (mut journal, _) = journal(false);
        let precommit = journal.records.len() - 1;
        validate_precommit_elapsed(&journal, precommit, 120).unwrap();
        journal.records[precommit - 1].body.campaign_mono_ns = 119_999_999_999;
        assert!(validate_precommit_elapsed(&journal, precommit, 120).is_err());
    }
}
