use lob_replay::Result;
use lob_replay::complete_replay::QualifiedCompleteReplayReceiptV1;
use lob_replay::qualified_cache::replay_qualified_cache;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| format!("resolve report parent: {error}"))?;
    let name = path
        .file_name()
        .ok_or_else(|| "report path has no filename".to_owned())?;
    let target = parent.join(name);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&target)
        .map_err(|error| format!("create {}: {error}", target.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", target.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", target.display()))
}

fn run() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if !(3..=4).contains(&arguments.len()) {
        return Err(format!(
            "usage: {} <qualified-replay-receipt.json> <cache-directory> [new-report.json]",
            arguments
                .first()
                .map(|value| value.to_string_lossy())
                .unwrap_or_default()
        ));
    }
    let receipt: QualifiedCompleteReplayReceiptV1 = serde_json::from_slice(
        &std::fs::read(PathBuf::from(&arguments[1]))
            .map_err(|error| format!("read qualified replay receipt: {error}"))?,
    )
    .map_err(|error| format!("invalid qualified replay receipt JSON: {error}"))?;
    let report = replay_qualified_cache(&receipt, Path::new(&arguments[2]))?;
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize cached replay report: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = arguments.get(3) {
        write_new_synced(Path::new(path), &bytes)
    } else {
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|error| format!("write cached replay report: {error}"))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("cached-replay: {error}");
        std::process::exit(1);
    }
}
