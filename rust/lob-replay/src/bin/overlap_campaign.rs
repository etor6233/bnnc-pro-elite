use serde::Serialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type Result<T> = std::result::Result<T, String>;

#[derive(Serialize)]
struct OverlapCampaignManifestV1 {
    schema: &'static str,
    status: &'static str,
    symbol: String,
    warmup_requested_s: u64,
    overlap_requested_s: u64,
    tail_requested_s: u64,
    predecessor_duration_requested_s: u64,
    successor_duration_requested_s: u64,
    predecessor_session: String,
    successor_session: String,
    splice_dir: String,
    ownership_ledger: String,
    ownership_report: String,
    credentials: &'static str,
    order_entry: &'static str,
}

fn sibling_binary(name: &str) -> Result<PathBuf> {
    let executable = env::current_exe().map_err(|error| format!("current executable: {error}"))?;
    let parent = executable
        .parent()
        .ok_or_else(|| "current executable has no parent".to_owned())?;
    let path = parent.join(format!("{name}{}", env::consts::EXE_SUFFIX));
    if !path.is_file() {
        return Err(format!(
            "required sibling binary is absent: {}; build capture, splice_epochs and ownership_activate first",
            path.display()
        ));
    }
    Ok(path)
}

fn spawn_capture(capture: &Path, symbol: &str, duration_s: u64, output: &Path) -> Result<Child> {
    Command::new(capture)
        .arg(symbol)
        .arg(duration_s.to_string())
        .arg(output)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn capture: {error}"))
}

fn checked_output(label: &str, output: Output) -> Result<String> {
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("{label} stdout is not UTF-8: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "{label} failed with {}: stdout={stdout:?} stderr={stderr:?}",
            output.status
        ));
    }
    let value = stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| format!("{label} emitted no output path"))?
        .trim()
        .to_owned();
    if !stderr.trim().is_empty() {
        return Err(format!("{label} emitted unexpected stderr: {stderr}"));
    }
    Ok(value)
}

fn run_command(label: &str, executable: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new(executable)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("run {label}: {error}"))?;
    checked_output(label, output)
}

fn parse_positive(value: Option<String>, label: &str) -> Result<u64> {
    let value = value.ok_or_else(|| format!("missing {label}"))?;
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid {label}: {error}"))?;
    if parsed == 0 || parsed > 86_400 {
        return Err(format!("{label} must be within 1..=86400"));
    }
    Ok(parsed)
}

fn run() -> Result<PathBuf> {
    let mut args = env::args();
    let executable = args.next().unwrap_or_else(|| "overlap_campaign".to_owned());
    let symbol = args.next().ok_or_else(|| {
        format!(
            "usage: {executable} <BTCUSDT|ETHUSDT> <warmup-s> <overlap-s> <tail-s> [output-root]"
        )
    })?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err("symbol outside fixed scope".to_owned());
    }
    let warmup_s = parse_positive(args.next(), "warmup-s")?;
    let overlap_s = parse_positive(args.next(), "overlap-s")?;
    let tail_s = parse_positive(args.next(), "tail-s")?;
    let output_root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/overlap-campaigns"));
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let predecessor_duration = warmup_s
        .checked_add(overlap_s)
        .ok_or_else(|| "predecessor duration overflow".to_owned())?;
    let successor_duration = overlap_s
        .checked_add(tail_s)
        .ok_or_else(|| "successor duration overflow".to_owned())?;
    if predecessor_duration > 86_400 || successor_duration > 86_400 {
        return Err("derived capture duration exceeds 86400 seconds".to_owned());
    }
    let capture = sibling_binary("capture")?;
    let splice = sibling_binary("splice_epochs")?;
    let ownership = sibling_binary("ownership_activate")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system time: {error}"))?;
    let campaign_id = format!(
        "{}.{:09}Z-{}-overlap-{}",
        now.as_secs(),
        now.subsec_nanos(),
        symbol,
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let campaign = output_root.join(campaign_id);
    let sources = campaign.join("sources");
    fs::create_dir_all(&sources)
        .map_err(|error| format!("create campaign sources {}: {error}", sources.display()))?;

    let predecessor = spawn_capture(&capture, &symbol, predecessor_duration, &sources)?;
    thread::sleep(Duration::from_secs(warmup_s));
    let successor = match spawn_capture(&capture, &symbol, successor_duration, &sources) {
        Ok(child) => child,
        Err(error) => {
            let mut predecessor = predecessor;
            let _ = predecessor.kill();
            let _ = predecessor.wait();
            return Err(error);
        }
    };
    let predecessor_session = checked_output(
        "predecessor capture",
        predecessor
            .wait_with_output()
            .map_err(|error| format!("wait predecessor capture: {error}"))?,
    )?;
    let successor_session = checked_output(
        "successor capture",
        successor
            .wait_with_output()
            .map_err(|error| format!("wait successor capture: {error}"))?,
    )?;
    let splice_dir = campaign.join("splice");
    run_command(
        "splice epochs",
        &splice,
        &[
            &predecessor_session,
            &successor_session,
            &splice_dir.display().to_string(),
        ],
    )?;
    let ledger = splice_dir.join("ownership.bnledger");
    let ownership_report = run_command(
        "activate ownership",
        &ownership,
        &[
            &splice_dir.display().to_string(),
            &ledger.display().to_string(),
            "generation-a",
            "generation-b",
        ],
    )?;
    let manifest = OverlapCampaignManifestV1 {
        schema: "OverlapCampaignManifestV1",
        status: "ACTIVATED_POST_CAPTURE",
        symbol,
        warmup_requested_s: warmup_s,
        overlap_requested_s: overlap_s,
        tail_requested_s: tail_s,
        predecessor_duration_requested_s: predecessor_duration,
        successor_duration_requested_s: successor_duration,
        predecessor_session,
        successor_session,
        splice_dir: splice_dir.display().to_string(),
        ownership_ledger: ledger.display().to_string(),
        ownership_report,
        credentials: "NONE",
        order_entry: "ABSENT",
    };
    let manifest_path = campaign.join("campaign.json");
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize campaign manifest: {error}"))?;
    bytes.push(b'\n');
    fs::write(&manifest_path, bytes)
        .map_err(|error| format!("write {}: {error}", manifest_path.display()))?;
    Ok(manifest_path)
}

fn main() {
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            eprintln!("overlap-campaign: {error}");
            std::process::exit(2);
        }
    }
}
