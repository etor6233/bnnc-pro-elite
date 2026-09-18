use lob_replay::Result;
use lob_replay::complete_replay::QualifiedCompleteReplayReceiptV1;
use lob_replay::qualified_cache::QualifiedDepthReplaySession;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn parse_index(value: &std::ffi::OsStr, name: &str) -> Result<usize> {
    value
        .to_str()
        .ok_or_else(|| format!("{name} is not UTF-8"))?
        .parse::<usize>()
        .map_err(|error| format!("invalid {name}: {error}"))
}

fn sha256_path(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn run() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if !(7..=8).contains(&arguments.len()) {
        return Err(format!(
            "usage: {} <qualified-replay-receipt.json> <cache-directory> <checkpoint-directory> <start-checkpoint-index> <end-checkpoint-index> <iterations> [new-benchmark.json]",
            arguments
                .first()
                .map(|value| value.to_string_lossy())
                .unwrap_or_default()
        ));
    }
    let receipt_path = PathBuf::from(&arguments[1]);
    let cache_root = PathBuf::from(&arguments[2]);
    let checkpoint_root = PathBuf::from(&arguments[3]);
    let receipt: QualifiedCompleteReplayReceiptV1 = serde_json::from_slice(
        &std::fs::read(&receipt_path)
            .map_err(|error| format!("read qualified replay receipt: {error}"))?,
    )
    .map_err(|error| format!("invalid qualified replay receipt JSON: {error}"))?;
    let start_index = parse_index(&arguments[4], "start checkpoint index")?;
    let end_index = parse_index(&arguments[5], "end checkpoint index")?;
    let iterations = parse_index(&arguments[6], "iterations")?;
    if iterations == 0 || iterations > 10_000 {
        return Err("iterations must be in 1..=10000".to_owned());
    }
    let startup = Instant::now();
    let session =
        QualifiedDepthReplaySession::open_verified(&receipt, &cache_root, &checkpoint_root)?;
    let startup_ns = startup.elapsed().as_nanos();
    let mut samples_ns = Vec::with_capacity(iterations);
    let mut expected_report = None;
    for _ in 0..iterations {
        let started = Instant::now();
        let report = session.replay_window(start_index, end_index)?;
        samples_ns.push(started.elapsed().as_nanos());
        if expected_report
            .as_ref()
            .is_some_and(|expected| expected != &report)
        {
            return Err("repeated checkpoint window replay is nondeterministic".to_owned());
        }
        expected_report = Some(report);
    }
    samples_ns.sort_unstable();
    let percentile = |numerator: usize, denominator: usize| {
        let rank = (samples_ns.len() - 1) * numerator / denominator;
        samples_ns[rank]
    };
    let report = expected_report.ok_or_else(|| "benchmark produced no report".to_owned())?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve benchmark executable: {error}"))?;
    let mut output = json!({
        "schema": "CheckpointWindowReplayBenchmarkV1",
        "status": "PASS",
        "session_validation": "FULL_FAIL_CLOSED_BEFORE_TIMED_ITERATIONS",
        "symbol": report.symbol,
        "checkpoint_count": session.checkpoint_count(),
        "start_checkpoint_index": start_index,
        "end_checkpoint_index": end_index,
        "iterations": iterations,
        "provenance": {
            "executable_sha256": sha256_path(&executable)?,
            "receipt_file_sha256": sha256_path(&receipt_path)?,
            "cache_manifest_file_sha256": sha256_path(&cache_root.join("qualified-cache.json"))?,
            "checkpoint_manifest_file_sha256": sha256_path(&checkpoint_root.join("qualified-checkpoints.json"))?,
        },
        "startup_validation_ms": startup_ns as f64 / 1_000_000.0,
        "window": report,
        "latency_ms": {
            "minimum": samples_ns[0] as f64 / 1_000_000.0,
            "p50": percentile(1, 2) as f64 / 1_000_000.0,
            "p95": percentile(95, 100) as f64 / 1_000_000.0,
            "maximum": samples_ns[samples_ns.len() - 1] as f64 / 1_000_000.0,
        },
    });
    let material = serde_json::to_vec(&output)
        .map_err(|error| format!("serialize benchmark material: {error}"))?;
    output["benchmark_sha256"] =
        serde_json::Value::String(format!("{:x}", Sha256::digest(material)));
    let mut bytes = serde_json::to_vec_pretty(&output)
        .map_err(|error| format!("serialize benchmark: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = arguments.get(7) {
        let path = PathBuf::from(path);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
        file.write_all(&bytes)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", path.display()))
    } else {
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|error| format!("write benchmark: {error}"))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("checkpoint-window-replay: {error}");
        std::process::exit(1);
    }
}
