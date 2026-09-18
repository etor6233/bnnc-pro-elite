use lob_replay::Result;
use lob_replay::market_replay::{ReplayPrefixSelectionV1, replay_failed_generation_prefix};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

fn resolved_target(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|error| format!("resolve current directory: {error}"))?
            .join(path)
    };
    let mut cursor = absolute.as_path();
    let mut missing = Vec::new();
    while !cursor.exists() {
        let name = cursor
            .file_name()
            .ok_or_else(|| "output path has no existing ancestor".to_owned())?;
        missing.push(name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| "output path has no existing ancestor".to_owned())?;
    }
    let mut resolved = cursor
        .canonicalize()
        .map_err(|error| format!("resolve output ancestor: {error}"))?;
    for name in missing.into_iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

fn run() -> Result<()> {
    let mut args = env::args_os();
    let executable = PathBuf::from(args.next().unwrap_or_default());
    let selection_path = args.next().map(PathBuf::from).ok_or_else(|| {
        format!(
            "usage: {} <replay-prefix-selection.json> [new-report.json]",
            executable.display()
        )
    })?;
    let output = args.next().map(PathBuf::from);
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let selection_bytes = std::fs::read(&selection_path)
        .map_err(|error| format!("read {}: {error}", selection_path.display()))?;
    let selection: ReplayPrefixSelectionV1 = serde_json::from_slice(&selection_bytes)
        .map_err(|error| format!("invalid replay prefix selection JSON: {error}"))?;
    if let Some(path) = output.as_ref() {
        let generation = selection
            .generation_directory
            .canonicalize()
            .map_err(|error| format!("resolve generation directory: {error}"))?;
        let target = resolved_target(path)?;
        if target.starts_with(&generation) {
            return Err("replay report must remain outside immutable source generation".to_owned());
        }
    }
    let report = replay_failed_generation_prefix(&selection)?;
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize replay report: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = output {
        write_new_synced(&path, &bytes)?;
    }
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| format!("write replay report: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("market-replay: {error}");
        std::process::exit(2);
    }
}
