use lob_replay::boundary::scan_boundary_journal;
use std::env;
use std::path::PathBuf;

fn run() -> Result<(), String> {
    let mut args = env::args();
    let executable = args.next().unwrap_or_else(|| "boundary-scan".to_owned());
    let path = PathBuf::from(
        args.next()
            .ok_or_else(|| format!("usage: {executable} <journal.bnhandover>"))?,
    );
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let scan = scan_boundary_journal(&path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&scan)
            .map_err(|error| format!("serialize boundary scan: {error}"))?
    );
    if !scan.clean_eof {
        return Err(format!("boundary journal invalid: {:?}", scan.reason));
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("boundary-scan: {error}");
        std::process::exit(2);
    }
}
