use lob_replay::Result;
use lob_replay::complete_replay::QualifiedCompleteReplayReceiptV1;
use lob_replay::qualified_cache::build_qualified_replay_checkpoints;
use std::path::{Path, PathBuf};

fn run() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err(format!(
            "usage: {} <qualified-replay-receipt.json> <cache-directory> <new-checkpoint-directory>",
            arguments
                .first()
                .map(|value| value.to_string_lossy())
                .unwrap_or_default()
        ));
    }
    let receipt_path = PathBuf::from(&arguments[1]);
    let receipt: QualifiedCompleteReplayReceiptV1 = serde_json::from_slice(
        &std::fs::read(&receipt_path)
            .map_err(|error| format!("read qualified replay receipt: {error}"))?,
    )
    .map_err(|error| format!("invalid qualified replay receipt JSON: {error}"))?;
    let manifest = build_qualified_replay_checkpoints(
        &receipt,
        Path::new(&arguments[2]),
        Path::new(&arguments[3]),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&manifest)
            .map_err(|error| format!("serialize checkpoint manifest: {error}"))?
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("build-replay-checkpoints: {error}");
        std::process::exit(1);
    }
}
