use lob_replay::boundary::{
    BoundaryDurabilityV1, BoundaryStreamKind, CanonicalObservationV1, HandoverBoundaryV1,
    RawPositionV1, select_canonical,
};
use serde_json::json;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

type Result<T> = std::result::Result<T, String>;
const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn observation(epoch: &str, frame: u64, sequence: u64, digest: &str) -> CanonicalObservationV1 {
    CanonicalObservationV1 {
        symbol: "BTCUSDT".to_owned(),
        stream_kind: BoundaryStreamKind::Depth,
        stream: "btcusdt@depth@100ms".to_owned(),
        connection_epoch: epoch.to_owned(),
        frame_index: frame,
        first_sequence: sequence,
        final_sequence: sequence,
        record_sha256: digest.to_owned(),
        observation_sha256: digest.to_owned(),
    }
}

fn position(epoch: &str, frame: u64, digest: &str) -> RawPositionV1 {
    RawPositionV1 {
        connection_epoch: epoch.to_owned(),
        stream: "btcusdt@depth@100ms".to_owned(),
        frame_index: frame,
        record_sha256: digest.to_owned(),
    }
}

fn percentile(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
    let rank = (samples.len() * numerator).div_ceil(denominator);
    samples[rank.clamp(1, samples.len()) - 1]
}

fn run() -> Result<PathBuf> {
    let mut args = env::args().skip(1);
    let records: usize = args
        .next()
        .ok_or_else(|| "missing records-per-source".to_owned())?
        .parse()
        .map_err(|error| format!("invalid records: {error}"))?;
    let iterations: usize = args
        .next()
        .ok_or_else(|| "missing iterations".to_owned())?
        .parse()
        .map_err(|error| format!("invalid iterations: {error}"))?;
    let report_path = PathBuf::from(
        args.next()
            .ok_or_else(|| "missing report path".to_owned())?,
    );
    if records < 1_000 || iterations < 10 || args.next().is_some() {
        return Err("usage: selector_bench <records>=1000+ <iterations>=10+ <report>".to_owned());
    }
    let overlap = 100_usize;
    if records <= overlap {
        return Err("records must exceed overlap".to_owned());
    }
    let boundary_sequence = (records - overlap) as u64;
    let predecessor_boundary_frame = boundary_sequence - 1;
    let successor_boundary_frame = (overlap - 1) as u64;
    let successor_first_frame = overlap as u64;
    let mut predecessor = Vec::with_capacity(records);
    for frame in 0..records as u64 {
        let sequence = frame + 1;
        let digest = if sequence == boundary_sequence { A } else { B };
        predecessor.push(observation("epoch-a", frame, sequence, digest));
    }
    let successor_start = boundary_sequence - successor_boundary_frame;
    let mut successor = Vec::with_capacity(records);
    for frame in 0..records as u64 {
        let sequence = successor_start + frame;
        let digest = if sequence == boundary_sequence { A } else { B };
        successor.push(observation("epoch-b", frame, sequence, digest));
    }
    let boundary = HandoverBoundaryV1 {
        schema: "HandoverBoundaryV1".to_owned(),
        boundary_id: "selector-benchmark".to_owned(),
        environment: "production-public-market-data".to_owned(),
        symbol: "BTCUSDT".to_owned(),
        stream_kind: BoundaryStreamKind::Depth,
        stream: "btcusdt@depth@100ms".to_owned(),
        predecessor_epoch: "epoch-a".to_owned(),
        successor_epoch: "epoch-b".to_owned(),
        boundary_sequence,
        boundary_sha256: A.to_owned(),
        predecessor_last_selected: position("epoch-a", predecessor_boundary_frame, A),
        successor_boundary_observation: position("epoch-b", successor_boundary_frame, A),
        successor_first_selected: position("epoch-b", successor_first_frame, B),
        predecessor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: records as u64 - 1,
            durable_through_offset: 1,
            last_record_sha256: A.to_owned(),
        },
        successor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: records as u64 - 1,
            durable_through_offset: 1,
            last_record_sha256: B.to_owned(),
        },
        spec_revision: "976cc580553890e92031b77306147c0ed1de5a46".to_owned(),
        selector_version: "CanonicalMarketDataViewV1".to_owned(),
    };
    let expected_selected = records * 2 - overlap * 2;
    let expected_excluded = overlap * 2;
    let mut samples = Vec::with_capacity(iterations);
    let mut digest = None;
    let wall = Instant::now();
    for _ in 0..iterations {
        let started = Instant::now();
        let selection = select_canonical(&boundary, &predecessor, &successor)?;
        samples.push(started.elapsed().as_nanos() as u64);
        if selection.selected.len() != expected_selected
            || selection.excluded_overlap_records != expected_excluded as u64
            || digest
                .as_ref()
                .is_some_and(|expected| expected != &selection.selection_sha256)
        {
            return Err("selector correctness/digest instability".to_owned());
        }
        digest = Some(selection.selection_sha256);
    }
    let wall_ns = wall.elapsed().as_nanos() as u64;
    samples.sort_unstable();
    let processed = (records * 2 * iterations) as f64;
    let report = json!({
        "schema": "CanonicalSelectorBenchmarkV1",
        "implementation": "rust-release",
        "records_per_source": records,
        "overlap_records_per_source": overlap,
        "iterations": iterations,
        "input_observations": records * 2 * iterations,
        "selected_observations_per_iteration": expected_selected,
        "excluded_overlap_per_iteration": expected_excluded,
        "latency_ns": {
            "min": samples[0],
            "p50": percentile(&samples, 50, 100),
            "p95": percentile(&samples, 95, 100),
            "p99": percentile(&samples, 99, 100),
            "p99_9": percentile(&samples, 999, 1000),
            "max": samples[samples.len() - 1]
        },
        "input_observations_per_second": processed / (wall_ns as f64 / 1_000_000_000.0),
        "wall_time_ns": wall_ns,
        "selection_sha256": digest,
        "correctness": "PASS",
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "limitations": [
            "synthetic validated observations in memory",
            "not JSON decode, network capture, book application or disk materialization",
            "not a simultaneous Binance A/B rotation"
        ]
    });
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create report parent: {error}"))?;
    }
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize selector benchmark: {error}"))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)
        .map_err(|error| format!("create report: {error}"))?;
    output
        .write_all(&bytes)
        .and_then(|_| output.write_all(b"\n"))
        .and_then(|_| output.flush())
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("sync report: {error}"))?;
    Ok(report_path)
}

fn main() {
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            eprintln!("selector-bench: {error}");
            std::process::exit(2);
        }
    }
}
