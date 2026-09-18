use lob_replay::Result;
use lob_replay::ownership::{
    CanonicalSourcePointer, OwnershipLedgerWriter, SourcePointerSnapshotV1,
    derive_ownership_activation, load_committed_boundary_proof, scan_ownership_ledger,
};
use serde::Serialize;
use std::env;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Serialize)]
struct OwnershipActivationReportV1 {
    schema: &'static str,
    status: &'static str,
    ledger_path: String,
    prepared_record_sha256: String,
    activated_record_sha256: String,
    active_owner: SourcePointerSnapshotV1,
    active_owner_sha256: String,
    credentials: &'static str,
    order_entry: &'static str,
}

fn run() -> Result<PathBuf> {
    let mut args = env::args_os();
    let executable = PathBuf::from(args.next().unwrap_or_default());
    let splice_dir = args.next().map(PathBuf::from).ok_or_else(|| {
        format!(
            "usage: {} <splice-dir> <new-ledger-path> <predecessor-generation> <successor-generation>",
            executable.display()
        )
    })?;
    let ledger_path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing ledger path".to_owned())?;
    let predecessor_generation = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "missing/invalid predecessor generation".to_owned())?;
    let successor_generation = args
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(|| "missing/invalid successor generation".to_owned())?;
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let depth = load_committed_boundary_proof(&splice_dir.join("depth.bnhandover"))?;
    let trade = load_committed_boundary_proof(&splice_dir.join("trade.bnhandover"))?;
    let initial = SourcePointerSnapshotV1 {
        schema: "SourcePointerSnapshotV1".to_owned(),
        symbol: depth.boundary.symbol.clone(),
        generation_id: predecessor_generation,
        depth_epoch: depth.boundary.predecessor_epoch.clone(),
        trade_epoch: trade.boundary.predecessor_epoch.clone(),
        fencing_token: 1,
        depth_last_sequence: depth.boundary.boundary_sequence,
        trade_last_sequence: trade.boundary.boundary_sequence,
    };
    let activation = derive_ownership_activation(
        &format!("ownership-{}", Uuid::new_v4()),
        &successor_generation,
        &initial,
        &depth,
        &trade,
    )?;
    let mut writer = OwnershipLedgerWriter::create(&ledger_path, initial)?;
    let prepared = writer.prepare(activation.clone())?;
    let activated = writer.activate(&activation.activation_id)?;
    let scan = scan_ownership_ledger(&ledger_path)?;
    let pointer = CanonicalSourcePointer::recover(&scan, Some((&depth, &trade)))?;
    let active_owner_sha256 = pointer.owner.digest()?;
    let report = OwnershipActivationReportV1 {
        schema: "OwnershipActivationReportV1",
        status: "ACTIVATED",
        ledger_path: ledger_path.display().to_string(),
        prepared_record_sha256: prepared.last_record_sha256,
        activated_record_sha256: activated.last_record_sha256,
        active_owner: pointer.owner,
        active_owner_sha256,
        credentials: "NONE",
        order_entry: "ABSENT",
    };
    let report_path = ledger_path.with_extension("json");
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize ownership activation report: {error}"))?;
    bytes.push(b'\n');
    fs::write(&report_path, bytes)
        .map_err(|error| format!("write {}: {error}", report_path.display()))?;
    Ok(report_path)
}

fn main() {
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            eprintln!("ownership-activate: {error}");
            std::process::exit(2);
        }
    }
}
