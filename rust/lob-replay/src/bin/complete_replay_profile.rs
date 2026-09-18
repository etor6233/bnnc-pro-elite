use lob_replay::Result;
use lob_replay::complete_replay::{CompleteRunReplaySelectionV1, profile_complete_run};
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
        missing.push(
            cursor
                .file_name()
                .ok_or_else(|| "output path has no existing ancestor".to_owned())?
                .to_os_string(),
        );
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
            "usage: {} <complete-run-replay-selection.json> [new-profile.json]",
            executable.display()
        )
    })?;
    let output = args.next().map(PathBuf::from);
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let selection: CompleteRunReplaySelectionV1 = serde_json::from_slice(
        &std::fs::read(&selection_path)
            .map_err(|error| format!("read {}: {error}", selection_path.display()))?,
    )
    .map_err(|error| format!("invalid complete replay selection JSON: {error}"))?;
    if let Some(path) = output.as_ref() {
        let run = selection
            .run_directory
            .canonicalize()
            .map_err(|error| format!("resolve run directory: {error}"))?;
        if resolved_target(path)?.starts_with(&run) {
            return Err("profile must remain outside immutable source run".to_owned());
        }
    }
    let profile = profile_complete_run(&selection)?;
    let mut bytes = serde_json::to_vec_pretty(&profile)
        .map_err(|error| format!("serialize complete replay profile: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = output {
        write_new_synced(&path, &bytes)?;
    }
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| format!("write complete replay profile: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("complete-replay-profile: {error}");
        std::process::exit(2);
    }
}
