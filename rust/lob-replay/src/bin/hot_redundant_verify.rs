use lob_replay::Result;
use lob_replay::hot_redundancy_artifact::verify_hot_redundant_capture;
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
    let artifact = args.next().map(PathBuf::from).ok_or_else(|| {
        format!(
            "usage: {} <hot-redundant-artifact-dir> [new-report.json]",
            executable.display()
        )
    })?;
    let output = args.next().map(PathBuf::from);
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    if output
        .as_ref()
        .is_some_and(|path| path.starts_with(&artifact))
    {
        return Err("verification report cannot contaminate the artifact".to_owned());
    }
    let report = verify_hot_redundant_capture(&artifact)?;
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize hot-redundant verification: {error}"))?;
    bytes.push(b'\n');
    if let Some(path) = output {
        write_synced_new(&path, &bytes)?;
    }
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| format!("write hot-redundant verification: {error}"))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("hot-redundant-verify: {error}");
        std::process::exit(2);
    }
}
