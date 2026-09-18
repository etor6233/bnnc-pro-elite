use lob_replay::Result;
use lob_replay::complete_replay::{CompleteRunReplaySelectionV1, qualify_complete_replay};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

fn resolved_target(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| format!("resolve receipt parent: {error}"))?;
    let name = path
        .file_name()
        .ok_or_else(|| "receipt path has no filename".to_owned())?;
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
            "usage: {} <complete-run-replay-selection.json> [new-qualified-receipt.json]",
            arguments
                .first()
                .map(|value| value.to_string_lossy())
                .unwrap_or_default()
        ));
    }
    let selection_path = PathBuf::from(&arguments[1]);
    let selection: CompleteRunReplaySelectionV1 = serde_json::from_slice(
        &std::fs::read(&selection_path)
            .map_err(|error| format!("read replay selection: {error}"))?,
    )
    .map_err(|error| format!("invalid complete replay selection JSON: {error}"))?;
    let receipt = qualify_complete_replay(&selection)?;
    let mut bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| format!("serialize qualified replay receipt: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = arguments.get(2) {
        let target = resolved_target(Path::new(path))?;
        let source = selection
            .run_directory
            .canonicalize()
            .map_err(|error| format!("resolve immutable source run: {error}"))?;
        if target.starts_with(&source) {
            return Err(
                "qualified replay receipt must remain outside immutable source run".to_owned(),
            );
        }
        write_new_synced(&target, &bytes)
    } else {
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|error| format!("write qualified replay receipt: {error}"))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("qualify-complete-replay: {error}");
        std::process::exit(1);
    }
}
