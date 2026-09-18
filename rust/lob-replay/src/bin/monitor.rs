use lob_replay::monitor_session;
use std::env;
use std::fs;
use std::path::PathBuf;

fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    let executable = arguments.next().unwrap_or_default();
    let session = arguments.next().map(PathBuf::from).ok_or_else(|| {
        format!(
            "usage: {} <capture-session>",
            PathBuf::from(executable).display()
        )
    })?;
    if arguments.next().is_some() {
        return Err("expected exactly one capture-session argument".to_owned());
    }
    let report = monitor_session(&session)?;
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("serialize monitor report: {error}"))?
        + "\n";
    fs::write(session.join("monitor-rust.json"), output.as_bytes())
        .map_err(|error| format!("write Rust monitor report: {error}"))?;
    print!("{output}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lob-monitor: {error}");
        std::process::exit(2);
    }
}
