//! Neutral event-by-event replay of one campaign bound to a COMPLETE run.
//!
//! Qualification and reconstruction remain separate concerns: the launcher
//! terminal and both campaign verifiers establish the source, while this
//! module selects each market event exactly once across proven A/B overlaps.

use crate::campaign_artifact::{RawCampaignVerificationPhaseTimingsV1, profile_raw_campaign};
use crate::generation_handover::{
    RawGenerationHandoverProofV1, validate_raw_handover_proof_digest,
};
use crate::market_replay::{
    TransportIdentity, is_server_shutdown, load_json, load_transport, require_regular_file,
    sha256_file, text, u64_field, validate_frame,
};
use crate::observations::validated_trade_id;
use crate::segment_chain::{scan_segment_manifest, verify_segment_manifest_prefix_files};
use crate::{
    ApplyOutcome, LocalOrderBook, RawRecordEnvelopeV1, RawSegmentGenesisV1, Result,
    read_raw_records, read_raw_segment_records,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

pub const COMPLETE_REPLAY_USAGE: &str = "COMPLETE_RUN_NEUTRAL_REPLAY";
pub const QUALIFIED_REPLAY_RECEIPT_USAGE: &str = "QUALIFIED_COMPLETE_RUN_NEUTRAL_REPLAY";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteRunReplaySelectionV1 {
    pub schema: String,
    pub usage: String,
    pub run_directory: PathBuf,
    pub symbol: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompleteReplaySourceV1 {
    pub run_id: String,
    pub run_mode: String,
    pub run_status: String,
    pub launcher_terminal_sha256: String,
    pub campaign_id: String,
    pub campaign_manifest_sha256: String,
    pub campaign_verification_sha256: String,
    pub rust_verification_sha256: String,
    pub python_verification_sha256: String,
    pub symbol: String,
    pub generations: u64,
    pub handovers: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DepthGenerationReplayV1 {
    pub generation_index: u64,
    pub session_id: String,
    pub first_selected_frame_index: u64,
    pub last_selected_frame_index: u64,
    pub selected_raw_records: u64,
    pub selected_market_records: u64,
    pub selected_control_records: u64,
    pub final_update_id: u64,
    pub state_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TradeGenerationReplayV1 {
    pub generation_index: u64,
    pub session_id: String,
    pub first_selected_frame_index: Option<u64>,
    pub last_selected_frame_index: Option<u64>,
    pub selected_raw_records: u64,
    pub selected_market_records: u64,
    pub selected_control_records: u64,
    pub last_trade_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompleteDepthReplayV1 {
    pub total_raw_records: u64,
    pub total_control_records: u64,
    pub selected_raw_records: u64,
    pub selected_market_records: u64,
    pub selected_control_records: u64,
    pub overlap_records_excluded: u64,
    pub old_records: u64,
    pub applied_records: u64,
    pub final_update_id: u64,
    pub bid_levels: u64,
    pub ask_levels: u64,
    pub state_sha256: String,
    pub generations: Vec<DepthGenerationReplayV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompleteTradeReplayV1 {
    pub total_raw_records: u64,
    pub total_control_records: u64,
    pub selected_raw_records: u64,
    pub selected_market_records: u64,
    pub selected_control_records: u64,
    pub overlap_records_excluded: u64,
    pub first_trade_id: u64,
    pub last_trade_id: u64,
    pub trade_ids_strictly_increasing: bool,
    pub generations: Vec<TradeGenerationReplayV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompleteReplayHandoverV1 {
    pub predecessor_generation_index: u64,
    pub successor_generation_index: u64,
    pub proof_sha256: String,
    pub depth_boundary_sequence: u64,
    pub depth_boundary_state_sha256: String,
    pub depth_predecessor_last_frame_index: u64,
    pub depth_successor_first_frame_index: u64,
    pub trade_boundary_id: u64,
    pub trade_predecessor_last_frame_index: u64,
    pub trade_successor_skipped_through_frame_index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompleteRunReplayReportV1 {
    pub schema: String,
    pub usage: String,
    pub qualification_claim: bool,
    pub source: CompleteReplaySourceV1,
    pub depth: CompleteDepthReplayV1,
    pub trades: CompleteTradeReplayV1,
    pub handovers: Vec<CompleteReplayHandoverV1>,
    pub cross_stream_total_order_available: bool,
    pub economic_features: Vec<String>,
    pub report_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompleteReplayPhaseTimingsV1 {
    pub clock: String,
    pub complete_source_validation_ns: u64,
    pub campaign_reverification_ns: u64,
    pub campaign_reverification_breakdown: RawCampaignVerificationPhaseTimingsV1,
    pub topology_loading_validation_ns: u64,
    pub depth_replay_ns: u64,
    pub trade_replay_ns: u64,
    pub report_finalization_ns: u64,
    pub unattributed_ns: u64,
    pub total_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProfiledCompleteRunReplayV1 {
    pub schema: String,
    pub qualification_claim: bool,
    pub economic_features: Vec<String>,
    pub timings: CompleteReplayPhaseTimingsV1,
    pub report: CompleteRunReplayReportV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedCompleteReplayReceiptV1 {
    pub schema: String,
    pub usage: String,
    pub qualification_claim: bool,
    pub economic_features: Vec<String>,
    pub selection: CompleteRunReplaySelectionV1,
    pub source_files: Vec<QualifiedReplaySourceFileV1>,
    pub source_tree_sha256: String,
    pub report: CompleteRunReplayReportV1,
    pub receipt_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedReplaySourceFileV1 {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
}

struct CompleteSource {
    campaign: PathBuf,
    run_id: String,
    mode: String,
    terminal_sha256: String,
    campaign_id: String,
    campaign_manifest_sha256: String,
    rust_verification_sha256: String,
    python_verification_sha256: String,
}

struct GenerationSource {
    index: u64,
    session_id: String,
    root: PathBuf,
    startup: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QualifiedReplayGenerationIdentity {
    pub generation_index: u64,
    pub session_id: String,
    pub depth_stream: String,
    pub depth_connection_epoch: String,
    pub trade_stream: String,
    pub trade_connection_epoch: String,
}

pub(crate) type SelectedRecordSink<'a> =
    &'a mut dyn FnMut(u64, u64, &RawRecordEnvelopeV1) -> Result<()>;

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn report_digest(report: &CompleteRunReplayReportV1) -> Result<String> {
    let mut material = report.clone();
    material.report_sha256.clear();
    let bytes = serde_json::to_vec(&material)
        .map_err(|error| format!("serialize complete replay digest material: {error}"))?;
    Ok(crate::hex(&Sha256::digest(bytes)))
}

fn receipt_digest(receipt: &QualifiedCompleteReplayReceiptV1) -> Result<String> {
    let mut material = receipt.clone();
    material.receipt_sha256.clear();
    let bytes = serde_json::to_vec(&material)
        .map_err(|error| format!("serialize qualified replay receipt material: {error}"))?;
    Ok(crate::hex(&Sha256::digest(bytes)))
}

fn source_tree_digest(files: &[QualifiedReplaySourceFileV1]) -> Result<String> {
    let bytes = serde_json::to_vec(files)
        .map_err(|error| format!("serialize qualified replay source inventory: {error}"))?;
    Ok(crate::hex(&Sha256::digest(bytes)))
}

fn collect_source_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<QualifiedReplaySourceFileV1>,
    hash_segment_files: bool,
) -> Result<()> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|error| format!("read qualified source directory: {error}"))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| format!("enumerate qualified source directory: {error}"))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect qualified source entry: {error}"))?;
        let path = entry.path();
        if file_type.is_symlink() {
            return Err("qualified source tree cannot contain symbolic links".to_owned());
        }
        if file_type.is_dir() {
            collect_source_files(root, &path, files, hash_segment_files)?;
            continue;
        }
        if !file_type.is_file() {
            return Err("qualified source tree contains a non-regular entry".to_owned());
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "qualified source file escaped campaign root".to_owned())?;
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("qualified source file has an unsafe relative path".to_owned());
        }
        let relative_path = relative
            .components()
            .map(|component| component.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| "qualified source filename is not UTF-8".to_owned())?
            .join("/");
        let metadata = entry
            .metadata()
            .map_err(|error| format!("inspect qualified source file: {error}"))?;
        let sha256 = if hash_segment_files || !is_segment_raw_path(&relative_path) {
            sha256_file(&path)?
        } else {
            String::new()
        };
        files.push(QualifiedReplaySourceFileV1 {
            relative_path,
            bytes: metadata.len(),
            sha256,
        });
    }
    Ok(())
}

fn source_inventory(campaign: &Path) -> Result<Vec<QualifiedReplaySourceFileV1>> {
    let campaign = campaign
        .canonicalize()
        .map_err(|error| format!("resolve qualified campaign source: {error}"))?;
    let mut files = Vec::new();
    collect_source_files(&campaign, &campaign, &mut files, true)?;
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if files.is_empty() {
        return Err("qualified campaign source tree is empty".to_owned());
    }
    Ok(files)
}

fn is_segment_raw_path(relative_path: &str) -> bool {
    relative_path.ends_with(".bnraw")
        && (relative_path.contains("/depth/") || relative_path.contains("/trade/"))
}

fn validate_source_inventory_for_replay(
    campaign: &Path,
    expected: &[QualifiedReplaySourceFileV1],
) -> Result<()> {
    let campaign = campaign
        .canonicalize()
        .map_err(|error| format!("resolve qualified campaign source: {error}"))?;
    let mut actual = Vec::new();
    collect_source_files(&campaign, &campaign, &mut actual, false)?;
    actual.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if actual.len() != expected.len() {
        return Err("qualified replay source tree file set changed".to_owned());
    }
    for (actual, expected) in actual.iter().zip(expected) {
        if actual.relative_path != expected.relative_path
            || actual.bytes != expected.bytes
            || (!is_segment_raw_path(&actual.relative_path) && actual.sha256 != expected.sha256)
        {
            return Err("qualified replay source tree differs from its receipt".to_owned());
        }
    }
    Ok(())
}

fn safe_leaf(value: &str, label: &str) -> Result<PathBuf> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || path.is_absolute()
        || path.components().count() != 1
        || path
            .components()
            .any(|item| !matches!(item, Component::Normal(_)))
    {
        return Err(format!("{label} is not one safe filename"));
    }
    Ok(path.to_path_buf())
}

fn validate_verifier_artifact(
    run: &Path,
    row: &Value,
    symbol: &str,
    campaign_id: &str,
    campaign_manifest_sha256: &str,
    expected_kind: &str,
    expected_verification_sha256: &str,
) -> Result<()> {
    let name = text(row, "name", "independent verifier")?;
    let expected_name = format!("{}-{expected_kind}", symbol.to_ascii_lowercase());
    if name != expected_name
        || u64_field(row, "exit_code", "independent verifier")? != 0
        || u64_field(row, "stderr_bytes", "independent verifier")? != 0
    {
        return Err("independent verifier process result is not clean".to_owned());
    }
    let report_name = safe_leaf(
        text(row, "report_file", "independent verifier")?,
        "independent verifier report",
    )?;
    let report_path = run.join("independent-verification").join(report_name);
    let expected_file_sha = text(row, "report_sha256", "independent verifier")?;
    if !valid_sha256(expected_file_sha)
        || sha256_file(&report_path)? != expected_file_sha
        || std::fs::metadata(&report_path)
            .map_err(|error| format!("inspect verifier report: {error}"))?
            .len()
            != u64_field(row, "report_bytes", "independent verifier")?
    {
        return Err("independent verifier report bytes differ from terminal".to_owned());
    }
    let report = load_json(&report_path, "independent verifier report")?;
    let common_ok = text(&report, "campaign_id", "independent verifier report")? == campaign_id
        && text(&report, "symbol", "independent verifier report")? == symbol
        && text(
            &report,
            "verification_sha256",
            "independent verifier report",
        )? == expected_verification_sha256;
    let kind_ok = if expected_kind == "rust" {
        text(&report, "schema", "Rust verifier report")? == "VerifiedRawCampaignV1"
            && text(&report, "status", "Rust verifier report")? == "PASS"
            && text(&report, "campaign_manifest_sha256", "Rust verifier report")?
                == campaign_manifest_sha256
    } else {
        text(&report, "schema", "Python verifier report")? == "RawCampaignVerificationV1"
            && text(&report, "status", "Python verifier report")? == "VERIFIED"
            && text(
                &report,
                "campaign_manifest_file_sha256",
                "Python verifier report",
            )? == campaign_manifest_sha256
    };
    if !common_ok || !kind_ok {
        return Err("independent verifier report does not bind the selected campaign".to_owned());
    }
    Ok(())
}

fn validate_complete_source(run: &Path, symbol: &str) -> Result<CompleteSource> {
    let run = run
        .canonicalize()
        .map_err(|error| format!("resolve complete run directory: {error}"))?;
    let terminal_path = run.join("launcher-terminal.json");
    let terminal = load_json(&terminal_path, "launcher terminal")?;
    let run_id = text(&terminal, "run_id", "launcher terminal")?;
    let mode = text(&terminal, "mode", "launcher terminal")?;
    if text(&terminal, "schema", "launcher terminal")? != "RawQualificationLauncherTerminalV2"
        || text(&terminal, "status", "launcher terminal")? != "COMPLETE"
        || !matches!(mode, "Production" | "Smoke" | "Test")
        || text(&terminal, "credentials", "launcher terminal")? != "NONE"
        || text(&terminal, "order_entry", "launcher terminal")? != "ABSENT"
        || run.file_name().and_then(|item| item.to_str()) != Some(run_id)
        || PathBuf::from(text(&terminal, "run_root", "launcher terminal")?)
            .canonicalize()
            .map_err(|error| format!("resolve launcher run_root: {error}"))?
            != run
    {
        return Err("source is not an exact COMPLETE qualification run".to_owned());
    }
    let bindings_path = run.join("campaign-bindings.json");
    let bindings_sha = sha256_file(&bindings_path)?;
    if text(&terminal, "campaign_bindings_sha256", "launcher terminal")? != bindings_sha {
        return Err("COMPLETE terminal does not bind campaign-bindings.json".to_owned());
    }
    let campaigns = terminal["campaigns"]
        .as_array()
        .ok_or_else(|| "launcher terminal campaigns must be an array".to_owned())?;
    let symbols = campaigns
        .iter()
        .map(|row| text(row, "symbol", "launcher campaign"))
        .collect::<Result<BTreeSet<_>>>()?;
    if campaigns.len() != 2 || symbols != BTreeSet::from(["BTCUSDT", "ETHUSDT"]) {
        return Err("COMPLETE terminal does not contain exactly BTCUSDT and ETHUSDT".to_owned());
    }
    let row = campaigns
        .iter()
        .find(|row| row["symbol"].as_str() == Some(symbol))
        .ok_or_else(|| "selected symbol is absent from COMPLETE terminal".to_owned())?;
    if u64_field(row, "exit_code", "launcher campaign")? != 0
        || u64_field(row, "child_stderr_events", "launcher campaign")? != 0
        || u64_field(row, "stderr_file_bytes", "launcher campaign")? != 0
    {
        return Err("selected campaign did not terminate cleanly".to_owned());
    }
    let campaign = PathBuf::from(text(row, "campaign_directory", "launcher campaign")?)
        .canonicalize()
        .map_err(|error| format!("resolve selected campaign directory: {error}"))?;
    if campaign.parent() != Some(run.as_path()) {
        return Err("selected campaign is not a direct child of its run".to_owned());
    }
    let campaign_id = text(row, "campaign_id", "launcher campaign")?;
    if campaign.file_name().and_then(|item| item.to_str()) != Some(campaign_id) {
        return Err("selected campaign directory identity differs from terminal".to_owned());
    }
    let campaign_manifest_sha256 = text(row, "campaign_manifest_sha256", "launcher campaign")?;
    if !valid_sha256(campaign_manifest_sha256)
        || sha256_file(&campaign.join("campaign.json"))? != campaign_manifest_sha256
    {
        return Err("selected campaign manifest differs from terminal".to_owned());
    }
    let rust_verification_sha256 = text(row, "rust_verification_sha256", "launcher campaign")?;
    let python_verification_sha256 = text(row, "python_verification_sha256", "launcher campaign")?;
    if !valid_sha256(rust_verification_sha256) || !valid_sha256(python_verification_sha256) {
        return Err("launcher campaign verifier digest is invalid".to_owned());
    }
    let verifiers = row["independent_verifiers"]
        .as_array()
        .ok_or_else(|| "independent_verifiers must be an array".to_owned())?;
    if verifiers.len() != 2 {
        return Err("selected campaign lacks exactly two independent verifiers".to_owned());
    }
    for (kind, expected) in [
        ("rust", rust_verification_sha256),
        ("python", python_verification_sha256),
    ] {
        let verifier = verifiers
            .iter()
            .find(|item| {
                item["name"].as_str() == Some(&format!("{}-{kind}", symbol.to_ascii_lowercase()))
            })
            .ok_or_else(|| format!("selected campaign lacks {kind} verifier"))?;
        validate_verifier_artifact(
            &run,
            verifier,
            symbol,
            campaign_id,
            campaign_manifest_sha256,
            kind,
            expected,
        )?;
    }
    let bindings = load_json(&bindings_path, "campaign bindings")?;
    let binding_rows = bindings["campaigns"]
        .as_array()
        .ok_or_else(|| "campaign bindings campaigns must be an array".to_owned())?;
    let binding_matches = binding_rows
        .iter()
        .filter(|binding| {
            binding["symbol"].as_str() == Some(symbol)
                && binding["campaign_id"].as_str() == Some(campaign_id)
                && binding["campaign_directory"]
                    .as_str()
                    .and_then(|value| PathBuf::from(value).canonicalize().ok())
                    .as_deref()
                    == Some(campaign.as_path())
        })
        .count();
    if text(&bindings, "schema", "campaign bindings")? != "RawQualificationCampaignBindingsV1"
        || text(&bindings, "run_id", "campaign bindings")? != run_id
        || binding_matches != 1
    {
        return Err(
            "campaign bindings do not identify the selected campaign exactly once".to_owned(),
        );
    }
    Ok(CompleteSource {
        campaign,
        run_id: run_id.to_owned(),
        mode: mode.to_owned(),
        terminal_sha256: sha256_file(&terminal_path)?,
        campaign_id: campaign_id.to_owned(),
        campaign_manifest_sha256: campaign_manifest_sha256.to_owned(),
        rust_verification_sha256: rust_verification_sha256.to_owned(),
        python_verification_sha256: python_verification_sha256.to_owned(),
    })
}

fn generation_sources(
    campaign: &Path,
    manifest: &Value,
    symbol: &str,
) -> Result<Vec<GenerationSource>> {
    let rows = manifest["generations"]
        .as_array()
        .ok_or_else(|| "campaign generations must be an array".to_owned())?;
    let mut result = Vec::with_capacity(rows.len());
    for (expected, row) in rows.iter().enumerate() {
        let index = u64_field(row, "generation_index", "campaign generation")?;
        if index != expected as u64 {
            return Err("campaign generation order changed after verification".to_owned());
        }
        let session_id = text(row, "session_id", "campaign generation")?.to_owned();
        let session_dir = text(row, "session_dir", "campaign generation")?;
        let root = campaign
            .join(session_dir)
            .canonicalize()
            .map_err(|error| format!("resolve campaign generation: {error}"))?;
        if root.parent().and_then(Path::parent) != Some(campaign) {
            return Err("campaign generation escaped exact generations directory".to_owned());
        }
        let startup = load_json(&root.join("startup.json"), "generation startup")?;
        if text(&startup, "session_id", "generation startup")? != session_id
            || text(&startup, "symbol", "generation startup")? != symbol
            || u64_field(&startup, "generation_index", "generation startup")? != index
        {
            return Err("generation startup identity differs from campaign".to_owned());
        }
        result.push(GenerationSource {
            index,
            session_id,
            root,
            startup,
        });
    }
    if result.is_empty() {
        return Err("complete campaign contains no generation".to_owned());
    }
    Ok(result)
}

fn load_handover_proofs(
    campaign: &Path,
    manifest: &Value,
) -> Result<Vec<RawGenerationHandoverProofV1>> {
    let rows = manifest["handovers"]
        .as_array()
        .ok_or_else(|| "campaign handovers must be an array".to_owned())?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let relative = text(row, "proof_file", "campaign handover")?;
        let path = campaign.join(relative);
        require_regular_file(&path, "handover proof")?;
        let proof: RawGenerationHandoverProofV1 = serde_json::from_slice(
            &std::fs::read(&path).map_err(|error| format!("read handover proof: {error}"))?,
        )
        .map_err(|error| format!("invalid handover proof JSON: {error}"))?;
        validate_raw_handover_proof_digest(&proof)?;
        if proof.proof_sha256 != text(row, "proof_sha256", "campaign handover")?
            || sha256_file(&path)? != text(row, "proof_file_sha256", "campaign handover")?
        {
            return Err("handover proof differs after campaign verification".to_owned());
        }
        result.push(proof);
    }
    Ok(result)
}

fn stream_records<F>(
    generation: &GenerationSource,
    kind: &str,
    qualified_single_pass: bool,
    mut visit: F,
) -> Result<()>
where
    F: FnMut(&RawRecordEnvelopeV1, &TransportIdentity, u64) -> Result<()>,
{
    let identity = load_transport(
        &generation.root.join(format!("transport-{kind}.json")),
        kind,
        &generation.startup,
    )?;
    let directory = generation.root.join(kind);
    let scan = scan_segment_manifest(&directory.join("segments.bnseg"))?;
    if !scan.clean_eof || scan.entries.is_empty() {
        return Err(format!("{kind} manifest is not complete"));
    }
    if qualified_single_pass {
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
            let records = read_raw_segment_records(&directory.join(&seal.raw_file), &genesis)?;
            let count = u64::try_from(records.len())
                .map_err(|_| "qualified segment record count overflow".to_owned())?;
            let first = records
                .first()
                .ok_or_else(|| "qualified segment contains no record".to_owned())?;
            let last = records
                .last()
                .ok_or_else(|| "qualified segment contains no record".to_owned())?;
            if count != seal.records
                || first.frame.frame_index != seal.first_frame_index
                || last.frame.frame_index != seal.last_frame_index
                || last.end_offset != seal.durable_through_offset
                || last.record_sha256 != seal.terminal_record_sha256
                || records.iter().any(|record| {
                    record.frame.connection_epoch != seal.connection_epoch
                        || record.frame.stream != seal.stream
                })
            {
                return Err("qualified segment differs from its exact manifest seal".to_owned());
            }
            for record in &records {
                validate_frame(&record.frame, &identity)?;
                visit(record, &identity, seal.segment_index)?;
            }
        }
        return Ok(());
    }
    let through = scan.records - 1;
    let artifacts = verify_segment_manifest_prefix_files(&scan, &directory, through)?;
    for artifact in artifacts {
        let segment_index = artifact.seal().segment_index;
        for record in read_raw_segment_records(artifact.raw_path(), artifact.genesis())? {
            validate_frame(&record.frame, &identity)?;
            visit(&record, &identity, segment_index)?;
        }
    }
    Ok(())
}

fn replay_depth(
    generations: &[GenerationSource],
    proofs: &[RawGenerationHandoverProofV1],
    qualified_single_pass: bool,
    mut selected_sink: Option<SelectedRecordSink<'_>>,
) -> Result<CompleteDepthReplayV1> {
    let snapshot_path = generations[0].root.join("snapshot.bnraw");
    let snapshots = read_raw_records(&snapshot_path)?;
    if snapshots.len() != 1 {
        return Err("initial generation must contain one snapshot record".to_owned());
    }
    let mut book = LocalOrderBook::new(
        generations[0].startup["symbol"]
            .as_str()
            .unwrap_or_default(),
    )?;
    book.load_snapshot(&snapshots[0].frame.payload)?;
    let mut total_raw = 0_u64;
    let mut total_controls = 0_u64;
    let mut selected_raw = 0_u64;
    let mut selected_market = 0_u64;
    let mut selected_controls = 0_u64;
    let mut old_records = 0_u64;
    let mut applied_records = 0_u64;
    let mut checkpoints = Vec::with_capacity(generations.len());
    for (position, generation) in generations.iter().enumerate() {
        let start = if position == 0 {
            0
        } else {
            proofs[position - 1]
                .depth
                .successor_continuation
                .frame_index
        };
        let end = proofs
            .get(position)
            .map(|proof| proof.depth.predecessor_boundary.frame_index);
        let mut first_selected = None;
        let mut last_selected = None;
        let mut last_selected_sha = None;
        let mut generation_raw = 0_u64;
        let mut generation_market = 0_u64;
        let mut generation_controls = 0_u64;
        stream_records(
            generation,
            "depth",
            qualified_single_pass,
            |record, _identity, segment_index| {
                total_raw += 1;
                let value: Value = serde_json::from_slice(&record.frame.payload)
                    .map_err(|error| format!("invalid depth payload JSON: {error}"))?;
                let control = is_server_shutdown(&value)?;
                if control {
                    total_controls += 1;
                }
                let frame = record.frame.frame_index;
                if frame < start || end.is_some_and(|last| frame > last) {
                    return Ok(());
                }
                first_selected.get_or_insert(frame);
                last_selected = Some(frame);
                last_selected_sha = Some(record.record_sha256.clone());
                if let Some(sink) = selected_sink.as_deref_mut() {
                    sink(generation.index, segment_index, record)?;
                }
                selected_raw += 1;
                generation_raw += 1;
                if control {
                    selected_controls += 1;
                    generation_controls += 1;
                    return Ok(());
                }
                selected_market += 1;
                generation_market += 1;
                match book.apply_depth_value(&value)? {
                    ApplyOutcome::Old => old_records += 1,
                    ApplyOutcome::Applied => applied_records += 1,
                }
                Ok(())
            },
        )?;
        let first_selected = first_selected
            .ok_or_else(|| format!("generation {} selected no depth record", generation.index))?;
        let last_selected = last_selected
            .ok_or_else(|| format!("generation {} selected no depth record", generation.index))?;
        if first_selected != start || end.is_some_and(|expected| last_selected != expected) {
            return Err("depth selection boundary frame is absent".to_owned());
        }
        if position > 0 {
            let continuation = &proofs[position - 1].depth.successor_continuation;
            if first_selected != continuation.frame_index {
                return Err("depth successor did not begin at proven continuation".to_owned());
            }
        }
        if let Some(proof) = proofs.get(position) {
            // The handover state digest is recomputed for A and B from the
            // successor snapshot. This continuous replay intentionally keeps
            // the initial snapshot lineage, whose deep-book membership can
            // differ because Binance snapshots are bounded. Raw position and
            // update sequence are therefore the cross-lineage splice keys.
            if last_selected_sha.as_deref()
                != Some(proof.depth.predecessor_boundary.record_sha256.as_str())
                || book.last_update_id() != Some(proof.depth.boundary_sequence)
            {
                return Err(
                    "depth replay did not arrive at the proven raw/sequence boundary".to_owned(),
                );
            }
        }
        checkpoints.push(DepthGenerationReplayV1 {
            generation_index: generation.index,
            session_id: generation.session_id.clone(),
            first_selected_frame_index: first_selected,
            last_selected_frame_index: last_selected,
            selected_raw_records: generation_raw,
            selected_market_records: generation_market,
            selected_control_records: generation_controls,
            final_update_id: book
                .last_update_id()
                .ok_or_else(|| "depth replay has no update ID".to_owned())?,
            state_sha256: book.state_digest(),
        });
    }
    let (bid_levels, ask_levels) = book.level_counts();
    Ok(CompleteDepthReplayV1 {
        total_raw_records: total_raw,
        total_control_records: total_controls,
        selected_raw_records: selected_raw,
        selected_market_records: selected_market,
        selected_control_records: selected_controls,
        overlap_records_excluded: total_raw
            .checked_sub(selected_raw)
            .ok_or_else(|| "depth selected count exceeds total".to_owned())?,
        old_records,
        applied_records,
        final_update_id: book
            .last_update_id()
            .ok_or_else(|| "depth replay has no final update ID".to_owned())?,
        bid_levels: bid_levels as u64,
        ask_levels: ask_levels as u64,
        state_sha256: book.state_digest(),
        generations: checkpoints,
    })
}

fn replay_trades(
    generations: &[GenerationSource],
    proofs: &[RawGenerationHandoverProofV1],
    qualified_single_pass: bool,
    mut selected_sink: Option<SelectedRecordSink<'_>>,
) -> Result<CompleteTradeReplayV1> {
    let mut total_raw = 0_u64;
    let mut total_controls = 0_u64;
    let mut selected_raw = 0_u64;
    let mut selected_market = 0_u64;
    let mut selected_controls = 0_u64;
    let mut first_trade_id = None;
    let mut previous_trade_id = None;
    let mut checkpoints = Vec::with_capacity(generations.len());
    for (position, generation) in generations.iter().enumerate() {
        let start = if position == 0 {
            0
        } else {
            proofs[position - 1]
                .trade
                .successor_next_shared
                .frame_index
                .checked_add(1)
                .ok_or_else(|| "trade successor boundary overflow".to_owned())?
        };
        let end = proofs
            .get(position)
            .map(|proof| proof.trade.predecessor_next_shared.frame_index);
        let mut first_selected = None;
        let mut last_selected = None;
        let mut last_selected_sha = None;
        let mut generation_raw = 0_u64;
        let mut generation_market = 0_u64;
        let mut generation_controls = 0_u64;
        stream_records(
            generation,
            "trade",
            qualified_single_pass,
            |record, _identity, segment_index| {
                total_raw += 1;
                let value: Value = serde_json::from_slice(&record.frame.payload)
                    .map_err(|error| format!("invalid trade payload JSON: {error}"))?;
                let control = is_server_shutdown(&value)?;
                if control {
                    total_controls += 1;
                }
                let frame = record.frame.frame_index;
                if frame < start || end.is_some_and(|last| frame > last) {
                    return Ok(());
                }
                first_selected.get_or_insert(frame);
                last_selected = Some(frame);
                last_selected_sha = Some(record.record_sha256.clone());
                if let Some(sink) = selected_sink.as_deref_mut() {
                    sink(generation.index, segment_index, record)?;
                }
                selected_raw += 1;
                generation_raw += 1;
                if control {
                    selected_controls += 1;
                    generation_controls += 1;
                    return Ok(());
                }
                let trade_id = validated_trade_id(&value, &record.frame.symbol)?;
                if previous_trade_id.is_some_and(|old| trade_id <= old) {
                    return Err(
                        "selected trade ID duplicated or regressed across handover".to_owned()
                    );
                }
                first_trade_id.get_or_insert(trade_id);
                previous_trade_id = Some(trade_id);
                selected_market += 1;
                generation_market += 1;
                Ok(())
            },
        )?;
        if !valid_selected_trade_range(start, end, first_selected, last_selected) {
            return Err("trade selection boundary frame is absent".to_owned());
        }
        if let Some(proof) = proofs.get(position) {
            let raw_boundary_matches = last_selected.is_none()
                || last_selected_sha.as_deref()
                    == Some(proof.trade.predecessor_next_shared.record_sha256.as_str());
            if !raw_boundary_matches || previous_trade_id != Some(proof.trade.next_shared_trade_id)
            {
                return Err("trade replay did not arrive at the proven shared event".to_owned());
            }
        }
        checkpoints.push(TradeGenerationReplayV1 {
            generation_index: generation.index,
            session_id: generation.session_id.clone(),
            first_selected_frame_index: first_selected,
            last_selected_frame_index: last_selected,
            selected_raw_records: generation_raw,
            selected_market_records: generation_market,
            selected_control_records: generation_controls,
            last_trade_id: previous_trade_id
                .ok_or_else(|| "trade replay contains no market event".to_owned())?,
        });
    }
    Ok(CompleteTradeReplayV1 {
        total_raw_records: total_raw,
        total_control_records: total_controls,
        selected_raw_records: selected_raw,
        selected_market_records: selected_market,
        selected_control_records: selected_controls,
        overlap_records_excluded: total_raw
            .checked_sub(selected_raw)
            .ok_or_else(|| "trade selected count exceeds total".to_owned())?,
        first_trade_id: first_trade_id
            .ok_or_else(|| "trade replay contains no market event".to_owned())?,
        last_trade_id: previous_trade_id
            .ok_or_else(|| "trade replay contains no market event".to_owned())?,
        trade_ids_strictly_increasing: true,
        generations: checkpoints,
    })
}

fn valid_selected_trade_range(
    start: u64,
    end: Option<u64>,
    first: Option<u64>,
    last: Option<u64>,
) -> bool {
    if first.is_some() != last.is_some() || first.is_some_and(|value| value != start) {
        return false;
    }
    match (end, last) {
        (Some(expected), Some(value)) => value == expected,
        (Some(expected), None) => start > expected,
        (None, _) => true,
    }
}

fn validate_replay_topology(
    symbol: &str,
    generations: &[GenerationSource],
    proofs: &[RawGenerationHandoverProofV1],
) -> Result<()> {
    if proofs.len() + 1 != generations.len() {
        return Err("replay topology does not form one generation chain".to_owned());
    }
    for (index, proof) in proofs.iter().enumerate() {
        if proof.predecessor_generation_index != index as u64
            || proof.successor_generation_index != index as u64 + 1
            || proof.predecessor_session_id != generations[index].session_id
            || proof.successor_session_id != generations[index + 1].session_id
            || proof.symbol != symbol
        {
            return Err("handover proof order differs from campaign generations".to_owned());
        }
    }
    Ok(())
}

fn assemble_report(
    source: CompleteReplaySourceV1,
    depth: CompleteDepthReplayV1,
    trades: CompleteTradeReplayV1,
    proofs: &[RawGenerationHandoverProofV1],
) -> Result<CompleteRunReplayReportV1> {
    let handovers = proofs
        .iter()
        .map(|proof| CompleteReplayHandoverV1 {
            predecessor_generation_index: proof.predecessor_generation_index,
            successor_generation_index: proof.successor_generation_index,
            proof_sha256: proof.proof_sha256.clone(),
            depth_boundary_sequence: proof.depth.boundary_sequence,
            depth_boundary_state_sha256: proof.depth.boundary_state_sha256.clone(),
            depth_predecessor_last_frame_index: proof.depth.predecessor_boundary.frame_index,
            depth_successor_first_frame_index: proof.depth.successor_continuation.frame_index,
            trade_boundary_id: proof.trade.next_shared_trade_id,
            trade_predecessor_last_frame_index: proof.trade.predecessor_next_shared.frame_index,
            trade_successor_skipped_through_frame_index: proof
                .trade
                .successor_next_shared
                .frame_index,
        })
        .collect::<Vec<_>>();
    let mut report = CompleteRunReplayReportV1 {
        schema: "CompleteRunReplayReportV1".to_owned(),
        usage: COMPLETE_REPLAY_USAGE.to_owned(),
        qualification_claim: false,
        source,
        depth,
        trades,
        handovers,
        cross_stream_total_order_available: false,
        economic_features: Vec::new(),
        report_sha256: String::new(),
    };
    report.report_sha256 = report_digest(&report)?;
    Ok(report)
}

fn elapsed_ns(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_nanos()).map_err(|_| "profile duration overflow".to_owned())
}

fn replay_complete_run_profiled_internal(
    selection: &CompleteRunReplaySelectionV1,
) -> Result<(CompleteRunReplayReportV1, CompleteReplayPhaseTimingsV1)> {
    let total_started = Instant::now();
    let phase_started = Instant::now();
    if selection.schema != "CompleteRunReplaySelectionV1"
        || selection.usage != COMPLETE_REPLAY_USAGE
        || !matches!(selection.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
    {
        return Err("invalid complete-run replay selection".to_owned());
    }
    let source = validate_complete_source(&selection.run_directory, &selection.symbol)?;
    let complete_source_validation_ns = elapsed_ns(phase_started.elapsed())?;

    let phase_started = Instant::now();
    let profiled_verification = profile_raw_campaign(&source.campaign)?;
    let verified = profiled_verification.verification;
    if verified.campaign_id != source.campaign_id
        || verified.symbol != selection.symbol
        || verified.campaign_manifest_sha256 != source.campaign_manifest_sha256
        || verified.verification_sha256 != source.rust_verification_sha256
    {
        return Err("terminal and independent campaign verification disagree".to_owned());
    }
    let campaign_reverification_ns = elapsed_ns(phase_started.elapsed())?;

    let phase_started = Instant::now();
    let manifest = load_json(&source.campaign.join("campaign.json"), "campaign manifest")?;
    let generations = generation_sources(&source.campaign, &manifest, &selection.symbol)?;
    let proofs = load_handover_proofs(&source.campaign, &manifest)?;
    if proofs.len() + 1 != generations.len() || verified.handovers != proofs.len() as u64 {
        return Err("verified campaign topology differs from replay topology".to_owned());
    }
    validate_replay_topology(&selection.symbol, &generations, &proofs)?;
    let topology_loading_validation_ns = elapsed_ns(phase_started.elapsed())?;

    let phase_started = Instant::now();
    let depth = replay_depth(&generations, &proofs, false, None)?;
    let depth_replay_ns = elapsed_ns(phase_started.elapsed())?;

    let phase_started = Instant::now();
    let trades = replay_trades(&generations, &proofs, false, None)?;
    let trade_replay_ns = elapsed_ns(phase_started.elapsed())?;

    let phase_started = Instant::now();
    let report = assemble_report(
        CompleteReplaySourceV1 {
            run_id: source.run_id,
            run_mode: source.mode,
            run_status: "COMPLETE".to_owned(),
            launcher_terminal_sha256: source.terminal_sha256,
            campaign_id: source.campaign_id,
            campaign_manifest_sha256: source.campaign_manifest_sha256,
            campaign_verification_sha256: verified.verification_sha256,
            rust_verification_sha256: source.rust_verification_sha256,
            python_verification_sha256: source.python_verification_sha256,
            symbol: selection.symbol.clone(),
            generations: generations.len() as u64,
            handovers: proofs.len() as u64,
        },
        depth,
        trades,
        &proofs,
    )?;
    let report_finalization_ns = elapsed_ns(phase_started.elapsed())?;
    let total_ns = elapsed_ns(total_started.elapsed())?;
    let attributed_ns = complete_source_validation_ns
        .checked_add(campaign_reverification_ns)
        .and_then(|value| value.checked_add(topology_loading_validation_ns))
        .and_then(|value| value.checked_add(depth_replay_ns))
        .and_then(|value| value.checked_add(trade_replay_ns))
        .and_then(|value| value.checked_add(report_finalization_ns))
        .ok_or_else(|| "profile attributed duration overflow".to_owned())?;
    let timings = CompleteReplayPhaseTimingsV1 {
        clock: "STD_TIME_INSTANT_MONOTONIC".to_owned(),
        complete_source_validation_ns,
        campaign_reverification_ns,
        campaign_reverification_breakdown: profiled_verification.timings,
        topology_loading_validation_ns,
        depth_replay_ns,
        trade_replay_ns,
        report_finalization_ns,
        unattributed_ns: total_ns.saturating_sub(attributed_ns),
        total_ns,
    };
    Ok((report, timings))
}

pub fn replay_complete_run(
    selection: &CompleteRunReplaySelectionV1,
) -> Result<CompleteRunReplayReportV1> {
    replay_complete_run_profiled_internal(selection).map(|(report, _)| report)
}

pub fn qualify_complete_replay(
    selection: &CompleteRunReplaySelectionV1,
) -> Result<QualifiedCompleteReplayReceiptV1> {
    let report = replay_complete_run(selection)?;
    let source = validate_complete_source(&selection.run_directory, &selection.symbol)?;
    if report.source.run_id != source.run_id
        || report.source.campaign_id != source.campaign_id
        || report.source.campaign_manifest_sha256 != source.campaign_manifest_sha256
        || report.source.launcher_terminal_sha256 != source.terminal_sha256
        || report.source.rust_verification_sha256 != source.rust_verification_sha256
        || report.source.python_verification_sha256 != source.python_verification_sha256
    {
        return Err("qualified replay source changed after complete replay".to_owned());
    }
    let source_files = source_inventory(&source.campaign)?;
    let source_tree_sha256 = source_tree_digest(&source_files)?;
    let mut receipt = QualifiedCompleteReplayReceiptV1 {
        schema: "QualifiedCompleteReplayReceiptV1".to_owned(),
        usage: QUALIFIED_REPLAY_RECEIPT_USAGE.to_owned(),
        qualification_claim: false,
        economic_features: Vec::new(),
        selection: selection.clone(),
        source_files,
        source_tree_sha256,
        report,
        receipt_sha256: String::new(),
    };
    receipt.receipt_sha256 = receipt_digest(&receipt)?;
    Ok(receipt)
}

pub(crate) fn validate_qualified_receipt(receipt: &QualifiedCompleteReplayReceiptV1) -> Result<()> {
    if receipt.schema != "QualifiedCompleteReplayReceiptV1"
        || receipt.usage != QUALIFIED_REPLAY_RECEIPT_USAGE
        || receipt.qualification_claim
        || !receipt.economic_features.is_empty()
        || receipt.selection.schema != "CompleteRunReplaySelectionV1"
        || receipt.selection.usage != COMPLETE_REPLAY_USAGE
        || !matches!(receipt.selection.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
        || receipt.report.schema != "CompleteRunReplayReportV1"
        || receipt.report.usage != COMPLETE_REPLAY_USAGE
        || receipt.report.qualification_claim
        || receipt.report.cross_stream_total_order_available
        || !receipt.report.economic_features.is_empty()
        || receipt.report.source.symbol != receipt.selection.symbol
        || receipt.report.source.run_status != "COMPLETE"
        || receipt.source_files.is_empty()
        || !valid_sha256(&receipt.source_tree_sha256)
        || !valid_sha256(&receipt.receipt_sha256)
        || !valid_sha256(&receipt.report.report_sha256)
    {
        return Err("qualified replay receipt contract is invalid".to_owned());
    }
    if report_digest(&receipt.report)? != receipt.report.report_sha256
        || source_tree_digest(&receipt.source_files)? != receipt.source_tree_sha256
        || receipt_digest(receipt)? != receipt.receipt_sha256
    {
        return Err("qualified replay receipt digest is invalid".to_owned());
    }
    let mut previous = None;
    for file in &receipt.source_files {
        if file.relative_path.is_empty()
            || !valid_sha256(&file.sha256)
            || previous.is_some_and(|old: &str| old >= file.relative_path.as_str())
        {
            return Err("qualified replay source inventory is invalid".to_owned());
        }
        let path = Path::new(&file.relative_path);
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("qualified replay source inventory path is unsafe".to_owned());
        }
        previous = Some(file.relative_path.as_str());
    }
    Ok(())
}

pub fn replay_qualified_complete_run(
    receipt: &QualifiedCompleteReplayReceiptV1,
) -> Result<CompleteRunReplayReportV1> {
    let (generations, proofs) = qualified_replay_context(receipt)?;
    let depth = replay_depth(&generations, &proofs, true, None)?;
    let trades = replay_trades(&generations, &proofs, true, None)?;
    let report = assemble_report(receipt.report.source.clone(), depth, trades, &proofs)?;
    if report != receipt.report {
        return Err("qualified replay output differs from audit-grade replay".to_owned());
    }
    Ok(report)
}

fn qualified_replay_context(
    receipt: &QualifiedCompleteReplayReceiptV1,
) -> Result<(Vec<GenerationSource>, Vec<RawGenerationHandoverProofV1>)> {
    validate_qualified_receipt(receipt)?;
    let selection = &receipt.selection;
    let source = validate_complete_source(&selection.run_directory, &selection.symbol)?;
    let expected = &receipt.report.source;
    if expected.run_id != source.run_id
        || expected.run_mode != source.mode
        || expected.campaign_id != source.campaign_id
        || expected.campaign_manifest_sha256 != source.campaign_manifest_sha256
        || expected.launcher_terminal_sha256 != source.terminal_sha256
        || expected.campaign_verification_sha256 != source.rust_verification_sha256
        || expected.rust_verification_sha256 != source.rust_verification_sha256
        || expected.python_verification_sha256 != source.python_verification_sha256
    {
        return Err("qualified replay receipt no longer identifies its exact source".to_owned());
    }
    validate_source_inventory_for_replay(&source.campaign, &receipt.source_files)?;
    let manifest = load_json(&source.campaign.join("campaign.json"), "campaign manifest")?;
    let generations = generation_sources(&source.campaign, &manifest, &selection.symbol)?;
    let proofs = load_handover_proofs(&source.campaign, &manifest)?;
    validate_replay_topology(&selection.symbol, &generations, &proofs)?;
    if expected.generations != generations.len() as u64 || expected.handovers != proofs.len() as u64
    {
        return Err("qualified replay topology differs from its receipt".to_owned());
    }
    Ok((generations, proofs))
}

pub(crate) fn materialize_qualified_replay_records(
    receipt: &QualifiedCompleteReplayReceiptV1,
    depth_sink: SelectedRecordSink<'_>,
    trade_sink: SelectedRecordSink<'_>,
) -> Result<(RawRecordEnvelopeV1, Vec<QualifiedReplayGenerationIdentity>)> {
    let (generations, proofs) = qualified_replay_context(receipt)?;
    let snapshots = read_raw_records(&generations[0].root.join("snapshot.bnraw"))?;
    if snapshots.len() != 1 {
        return Err("qualified cache source must contain one initial snapshot".to_owned());
    }
    let mut identities = Vec::with_capacity(generations.len());
    for generation in &generations {
        let depth = load_transport(
            &generation.root.join("transport-depth.json"),
            "depth",
            &generation.startup,
        )?;
        let trade = load_transport(
            &generation.root.join("transport-trade.json"),
            "trade",
            &generation.startup,
        )?;
        identities.push(QualifiedReplayGenerationIdentity {
            generation_index: generation.index,
            session_id: generation.session_id.clone(),
            depth_stream: depth.stream,
            depth_connection_epoch: depth.connection_epoch,
            trade_stream: trade.stream,
            trade_connection_epoch: trade.connection_epoch,
        });
    }
    let depth = replay_depth(&generations, &proofs, true, Some(depth_sink))?;
    let trades = replay_trades(&generations, &proofs, true, Some(trade_sink))?;
    let report = assemble_report(receipt.report.source.clone(), depth, trades, &proofs)?;
    if report != receipt.report {
        return Err("qualified cache materialization differs from audit-grade replay".to_owned());
    }
    Ok((snapshots.into_iter().next().unwrap(), identities))
}

pub fn profile_complete_run(
    selection: &CompleteRunReplaySelectionV1,
) -> Result<ProfiledCompleteRunReplayV1> {
    let (report, timings) = replay_complete_run_profiled_internal(selection)?;
    Ok(ProfiledCompleteRunReplayV1 {
        schema: "ProfiledCompleteRunReplayV1".to_owned(),
        qualification_claim: false,
        economic_features: Vec::new(),
        timings,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        QualifiedReplaySourceFileV1, is_segment_raw_path, source_tree_digest,
        valid_selected_trade_range,
    };

    #[test]
    fn trade_range_allows_no_novel_successor_event_without_inventing_activity() {
        assert!(valid_selected_trade_range(2, None, None, None));
        assert!(valid_selected_trade_range(12, Some(10), None, None));
    }

    #[test]
    fn trade_range_requires_every_real_boundary_position_exactly() {
        assert!(valid_selected_trade_range(12, Some(20), Some(12), Some(20)));
        assert!(!valid_selected_trade_range(12, Some(20), None, None));
        assert!(!valid_selected_trade_range(
            12,
            Some(20),
            Some(13),
            Some(20)
        ));
        assert!(!valid_selected_trade_range(12, Some(20), Some(12), None));
    }

    #[test]
    fn qualified_source_tree_digest_binds_order_path_size_and_hash() {
        let first = QualifiedReplaySourceFileV1 {
            relative_path: "generations/a/depth/segment-000.bnraw".to_owned(),
            bytes: 10,
            sha256: "11".repeat(32),
        };
        let second = QualifiedReplaySourceFileV1 {
            relative_path: "generations/a/snapshot.bnraw".to_owned(),
            bytes: 20,
            sha256: "22".repeat(32),
        };
        let original = source_tree_digest(&[first.clone(), second.clone()]).unwrap();
        assert_ne!(
            original,
            source_tree_digest(&[second.clone(), first.clone()]).unwrap()
        );
        let mut changed = first;
        changed.bytes += 1;
        assert_ne!(original, source_tree_digest(&[changed, second]).unwrap());
    }

    #[test]
    fn only_manifested_stream_segments_are_deferred_to_single_pass_validation() {
        assert!(is_segment_raw_path("generations/a/depth/segment-000.bnraw"));
        assert!(is_segment_raw_path("generations/a/trade/segment-000.bnraw"));
        assert!(!is_segment_raw_path("generations/a/snapshot.bnraw"));
        assert!(!is_segment_raw_path("generations/a/depth/segments.bnseg"));
    }
}
