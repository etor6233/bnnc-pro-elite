use lob_replay::durability_progress::{
    freeze_durable_raw_prefix, scan_durability_progress, verify_progress_against_raw,
};
use serde::Serialize;
use std::env;
use std::path::PathBuf;

#[derive(Serialize)]
struct VerificationReport {
    schema: &'static str,
    progress: lob_replay::durability_progress::DurabilityProgressScanV1,
    verified_ack: lob_replay::DurabilityAckV1,
    frozen_path: Option<PathBuf>,
}

fn run() -> lob_replay::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if !(args.len() == 2 || args.len() == 3) {
        return Err(
            "usage: durability_scan <progress.bnack> <raw.bnraw> [frozen.bnraw]".to_owned(),
        );
    }
    let progress_path = PathBuf::from(&args[0]);
    let raw_path = PathBuf::from(&args[1]);
    let scan = scan_durability_progress(&progress_path)?;
    let verified_ack = if let Some(destination) = args.get(2).map(PathBuf::from) {
        freeze_durable_raw_prefix(&scan, &raw_path, &destination)?
    } else {
        verify_progress_against_raw(&scan, &raw_path)?
    };
    let report = VerificationReport {
        schema: "DurabilityProgressVerificationV1",
        progress: scan,
        verified_ack,
        frozen_path: args.get(2).map(PathBuf::from),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("serialize durability report: {error}"))?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("durability-scan: {error}");
        std::process::exit(2);
    }
}
