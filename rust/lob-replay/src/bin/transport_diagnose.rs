use lob_replay::Result;
use lob_replay::transport_journal::{
    TransportJournalDiagnosisV1, TransportJournalSealV1, diagnose_sealed_transport_journal,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_GENERATION_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticStreamV1 {
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagnosticGenerationV1 {
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
    snapshot: Option<Value>,
    telemetry: Value,
    streams: Vec<DiagnosticStreamV1>,
}

#[derive(Serialize)]
struct TransportDiagnosisReportV1 {
    schema: &'static str,
    status: &'static str,
    generation_dir: String,
    generation_manifest_sha256: String,
    session_id: String,
    generation_index: u64,
    symbol: String,
    generation_status: String,
    generation_failure: Option<String>,
    streams: Vec<TransportJournalDiagnosisV1>,
    inference_boundary: &'static str,
    verification_sha256: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("stat diagnostic input {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "diagnostic input is not a regular non-link file: {}",
            path.display()
        ));
    }
    Ok(())
}

fn consume_unused_stream_fields(stream: &DiagnosticStreamV1) {
    let _ = (
        &stream.transport_metadata_file,
        &stream.transport_metadata_sha256,
        stream.written,
        stream.durable_records,
        stream.segments,
        stream.last_socket_activity_mono_ns,
        stream.last_market_message_mono_ns,
        stream.server_shutdown_events,
        &stream.segment_manifest,
        &stream.segment_manifest_sha256,
        &stream.terminal_raw_sha256,
        &stream.error,
    );
}

fn run() -> Result<TransportDiagnosisReportV1> {
    let mut arguments = env::args_os();
    let executable = arguments
        .next()
        .unwrap_or_else(|| "transport_diagnose".into());
    let root = arguments.next().map(PathBuf::from).ok_or_else(|| {
        format!(
            "usage: {} <generation-directory>",
            PathBuf::from(executable).display()
        )
    })?;
    if arguments.next().is_some() {
        return Err("transport diagnosis received too many arguments".to_owned());
    }
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolve generation directory: {error}"))?;
    let root_metadata = fs::symlink_metadata(&root)
        .map_err(|error| format!("stat generation directory: {error}"))?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err("generation diagnosis root is not a regular directory".to_owned());
    }
    let generation_path = root.join("generation.json");
    regular_file(&generation_path)?;
    let metadata = fs::metadata(&generation_path)
        .map_err(|error| format!("stat generation manifest: {error}"))?;
    if metadata.len() == 0 || metadata.len() > MAX_GENERATION_BYTES {
        return Err("generation manifest is empty or oversized".to_owned());
    }
    let bytes =
        fs::read(&generation_path).map_err(|error| format!("read generation manifest: {error}"))?;
    let manifest_digest = sha256_hex(&bytes);
    let generation: DiagnosticGenerationV1 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse exact generation manifest: {error}"))?;
    let _ = (
        &generation.implementation,
        generation.duration_requested_s,
        generation.segment_duration_s,
        generation.started_wall_ns,
        generation.finished_wall_ns,
        &generation.collector_executable_sha256,
        &generation.public_config_sha256,
        generation.market_freshness_startup_grace_s,
        generation.market_freshness_deadline_s,
        &generation.credentials,
        &generation.order_entry,
        &generation.raw_boundary,
        &generation.spec_revision,
        &generation.startup_file,
        &generation.startup_sha256,
        &generation.snapshot,
        &generation.telemetry,
    );
    if generation.schema != "RawGenerationManifestV1"
        || !matches!(generation.status.as_str(), "COMPLETE" | "FAILED")
        || (generation.status == "COMPLETE") != generation.failure.is_none()
        || !matches!(generation.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
        || generation.streams.len() != 2
    {
        return Err("generation diagnosis identity/status contract is invalid".to_owned());
    }
    let mut diagnoses = Vec::new();
    for stream in &generation.streams {
        consume_unused_stream_fields(stream);
        if !matches!(stream.name.as_str(), "depth" | "trade") {
            return Err("generation diagnosis contains an unknown stream".to_owned());
        }
        let seal = stream
            .transport_journal
            .as_ref()
            .ok_or_else(|| format!("{} lacks transport journal evidence", stream.name))?;
        let expected_file = format!("transport-{}-events.jsonl", stream.name);
        if seal.file != expected_file {
            return Err(format!("{} transport journal path drift", stream.name));
        }
        let journal_path = root.join(&expected_file);
        regular_file(&journal_path)?;
        diagnoses.push(diagnose_sealed_transport_journal(
            &journal_path,
            &stream.name,
            &stream.connection_epoch,
            &stream.uri,
            stream.received,
            seal,
        )?);
    }
    diagnoses.sort_by(|left, right| left.stream.cmp(&right.stream));
    if diagnoses[0].stream == diagnoses[1].stream {
        return Err("generation diagnosis contains duplicate streams".to_owned());
    }
    let verification_material = serde_json::to_vec(&diagnoses)
        .map_err(|error| format!("serialize diagnosis verification material: {error}"))?;
    Ok(TransportDiagnosisReportV1 {
        schema: "TransportDiagnosisReportV1",
        status: "PASS",
        generation_dir: root.display().to_string(),
        generation_manifest_sha256: manifest_digest,
        session_id: generation.session_id,
        generation_index: generation.generation_index,
        symbol: generation.symbol,
        generation_status: generation.status,
        generation_failure: generation.failure,
        streams: diagnoses,
        inference_boundary: "Classifications name only directly observed local socket/WebSocket boundaries; ETW or external witnesses are required for narrower upstream attribution.",
        verification_sha256: sha256_hex(&verification_material),
    })
}

fn main() {
    match run() {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("serialize transport diagnosis: {error}");
                std::process::exit(1);
            }
        },
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
