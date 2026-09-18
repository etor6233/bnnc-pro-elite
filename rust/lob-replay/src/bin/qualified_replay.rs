use lob_replay::Result;
use lob_replay::complete_replay::{
    QualifiedCompleteReplayReceiptV1, replay_qualified_complete_run,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

fn resolved_target(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| format!("resolve report parent: {error}"))?;
    let name = path
        .file_name()
        .ok_or_else(|| "report path has no filename".to_owned())?;
    Ok(parent.join(name))
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

fn run() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if !(2..=3).contains(&arguments.len()) {
        return Err(format!(
            "usage: {} <qualified-replay-receipt.json> [new-report.json]",
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
    let report = replay_qualified_complete_run(&receipt)?;
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize qualified replay report: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = arguments.get(2) {
        let target = resolved_target(Path::new(path))?;
        let source = receipt
            .selection
            .run_directory
            .canonicalize()
            .map_err(|error| format!("resolve immutable source run: {error}"))?;
        if target.starts_with(&source) {
            return Err(
                "qualified replay report must remain outside immutable source run".to_owned(),
            );
        }
        write_new_synced(&target, &bytes)
    } else {
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|error| format!("write qualified replay report: {error}"))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("qualified-replay: {error}");
        std::process::exit(1);
    }
}
