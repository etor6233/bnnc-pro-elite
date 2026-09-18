use lob_replay::boundary::{
    BoundaryDurabilityV1, BoundaryJournalWriter, BoundaryStreamKind, HandoverBoundaryV1,
    RawPositionV1, scan_boundary_journal,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, String>;
const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn position(epoch: &str, frame_index: u64, digest: &str) -> RawPositionV1 {
    RawPositionV1 {
        connection_epoch: epoch.to_owned(),
        stream: "btcusdt@depth@100ms".to_owned(),
        frame_index,
        record_sha256: digest.to_owned(),
    }
}

fn boundary(index: usize) -> HandoverBoundaryV1 {
    HandoverBoundaryV1 {
        schema: "HandoverBoundaryV1".to_owned(),
        boundary_id: format!("bench-btc-depth-{index}"),
        environment: "production-public-market-data".to_owned(),
        symbol: "BTCUSDT".to_owned(),
        stream_kind: BoundaryStreamKind::Depth,
        stream: "btcusdt@depth@100ms".to_owned(),
        predecessor_epoch: format!("epoch-a-{index}"),
        successor_epoch: format!("epoch-b-{index}"),
        boundary_sequence: 1_000_000 + index as u64,
        boundary_sha256: DIGEST_A.to_owned(),
        predecessor_last_selected: position(&format!("epoch-a-{index}"), 100, DIGEST_A),
        successor_boundary_observation: position(&format!("epoch-b-{index}"), 80, DIGEST_A),
        successor_first_selected: position(&format!("epoch-b-{index}"), 81, DIGEST_B),
        predecessor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: 100,
            durable_through_offset: 100_000,
            last_record_sha256: DIGEST_A.to_owned(),
        },
        successor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: 81,
            durable_through_offset: 90_000,
            last_record_sha256: DIGEST_B.to_owned(),
        },
        spec_revision: "976cc580553890e92031b77306147c0ed1de5a46".to_owned(),
        selector_version: "CanonicalMarketDataViewV1".to_owned(),
    }
}

fn percentile(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
    let rank = (samples.len() * numerator).div_ceil(denominator);
    samples[rank.clamp(1, samples.len()) - 1]
}

fn distribution(mut samples: Vec<u64>) -> serde_json::Value {
    samples.sort_unstable();
    let sum: u128 = samples.iter().map(|value| *value as u128).sum();
    json!({
        "count": samples.len(),
        "min_ns": samples[0],
        "p50_ns": percentile(&samples, 50, 100),
        "p95_ns": percentile(&samples, 95, 100),
        "p99_ns": percentile(&samples, 99, 100),
        "p99_9_ns": percentile(&samples, 999, 1000),
        "max_ns": samples[samples.len() - 1],
        "mean_ns": sum / samples.len() as u128,
    })
}

fn run() -> Result<PathBuf> {
    let mut args = env::args();
    let executable = args.next().unwrap_or_else(|| "boundary-bench".to_owned());
    let iterations: usize = args
        .next()
        .ok_or_else(|| format!("usage: {executable} <iterations> <journal-dir> <report.json>"))?
        .parse()
        .map_err(|error| format!("invalid iterations: {error}"))?;
    if !(10..=10_000).contains(&iterations) {
        return Err("iterations must be within 10..=10000".to_owned());
    }
    let journal_dir = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing journal dir".to_owned())?,
    );
    let report_path = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing report path".to_owned())?,
    );
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    std::fs::create_dir_all(&journal_dir)
        .map_err(|error| format!("create benchmark journal dir: {error}"))?;
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create benchmark report parent: {error}"))?;
    }
    let mut proposal_ns = Vec::with_capacity(iterations);
    let mut commit_ns = Vec::with_capacity(iterations);
    let mut total_ns = Vec::with_capacity(iterations);
    let mut total_bytes = 0_u64;
    let mut correctness = Sha256::new();
    let wall_start = Instant::now();
    for index in 0..iterations {
        let boundary = boundary(index);
        let path = journal_dir.join(format!("boundary-{index:05}.bnhandover"));
        let mut writer = BoundaryJournalWriter::create(&path)?;
        let total_start = Instant::now();
        let proposal_start = Instant::now();
        writer.propose(boundary.clone())?;
        proposal_ns.push(proposal_start.elapsed().as_nanos() as u64);
        let commit_start = Instant::now();
        let commit = writer.commit(&boundary.boundary_id)?;
        commit_ns.push(commit_start.elapsed().as_nanos() as u64);
        total_ns.push(total_start.elapsed().as_nanos() as u64);
        let scan = scan_boundary_journal(&path)?;
        if !scan.clean_eof || scan.committed.as_ref() != Some(&boundary) || scan.records != 2 {
            return Err(format!("journal correctness failure at iteration {index}"));
        }
        total_bytes += commit.durable_through_offset;
        correctness.update(commit.last_record_sha256.as_bytes());
    }
    let wall_ns = wall_start.elapsed().as_nanos() as u64;
    let generated_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system time before epoch: {error}"))?
        .as_nanos();
    let report = json!({
        "schema": "BoundaryCommitBenchmarkV1",
        "generated_at_unix_ns": generated_at_ns,
        "implementation": "rust-release",
        "environment": "local Windows filesystem",
        "iterations": iterations,
        "workload": "one new journal file, durable PROPOSED, durable COMMITTED, full rescan per iteration",
        "proposal_fsync_latency": distribution(proposal_ns),
        "commit_fsync_latency": distribution(commit_ns),
        "proposal_plus_commit_latency": distribution(total_ns),
        "wall_time_ns_including_create_and_scan": wall_ns,
        "committed_boundaries_per_second": (iterations as f64) / (wall_ns as f64 / 1_000_000_000.0),
        "total_journal_bytes": total_bytes,
        "correctness_digest_sha256": format!("{:x}", correctness.finalize()),
        "correctness": "PASS",
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "limitations": [
            "synthetic boundaries, not simultaneous Binance sockets",
            "OS-acknowledged sync, not physical power-loss qualification",
            "filesystem cache and background load are uncontrolled",
            "boundary rotation is not the per-message hot path"
        ]
    });
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize benchmark report: {error}"))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)
        .map_err(|error| format!("create benchmark report {}: {error}", report_path.display()))?;
    output
        .write_all(&bytes)
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.flush())
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("sync benchmark report: {error}"))?;
    Ok(report_path)
}

fn main() {
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            eprintln!("boundary-bench: {error}");
            std::process::exit(2);
        }
    }
}
