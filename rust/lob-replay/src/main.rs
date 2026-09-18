use lob_replay::replay_session;
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
    let result = replay_session(&session)?;
    let output = serde_json::to_string_pretty(&result)
        .map_err(|error| format!("serialize replay result: {error}"))?
        + "\n";
    fs::write(session.join("book-replay-rust.json"), output.as_bytes())
        .map_err(|error| format!("write Rust replay result: {error}"))?;
    print!("{output}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lob-replay: {error}");
        std::process::exit(2);
    }
}
