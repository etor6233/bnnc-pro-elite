use lob_replay::Result;
use lob_replay::generation_artifact::verify_segmented_generation;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

fn write_synced_new(path: &Path, bytes: &[u8]) -> Result<()> {
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
    let session = args.next().map(PathBuf::from).ok_or_else(|| {
        format!(
            "usage: {} <segmented-generation-dir> [new-report.json]",
            executable.display()
        )
    })?;
    let output = args.next().map(PathBuf::from);
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let report = verify_segmented_generation(&session)?;
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize generation verification: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = output {
        write_synced_new(&path, &bytes)?;
    }
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| format!("write verification report: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("generation-verify: {error}");
        std::process::exit(2);
    }
}
