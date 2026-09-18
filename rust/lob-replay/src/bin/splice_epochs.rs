use lob_replay::Result;
use lob_replay::boundary::{
    BoundaryDurabilityV1, BoundaryJournalAckV1, BoundaryJournalWriter, BoundaryStreamKind,
    CanonicalSelectionV1, HandoverBoundaryV1, scan_boundary_journal, select_canonical,
};
use lob_replay::observations::{
    ObservationMaterializationV1, materialize_depth_observations, materialize_trade_observations,
};
use lob_replay::scan_raw_log;
use lob_replay::splice::derive_handover_boundary;
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";

#[derive(Serialize)]
struct StreamSpliceReport {
    stream_kind: BoundaryStreamKind,
    journal_file: String,
    proposal_ack: BoundaryJournalAckV1,
    commit_ack: BoundaryJournalAckV1,
    boundary: HandoverBoundaryV1,
    selection: CanonicalSelectionV1,
}

#[derive(Serialize)]
struct OverlapSpliceReport {
    schema: &'static str,
    status: &'static str,
    predecessor_session: String,
    successor_session: String,
    credentials: &'static str,
    order_entry: &'static str,
    depth: StreamSpliceReport,
    trade: StreamSpliceReport,
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("manifest durability field {field} is invalid"))
}

fn durability_from_manifest(
    session: &Path,
    stream_name: &str,
    materialization: &ObservationMaterializationV1,
) -> Result<BoundaryDurabilityV1> {
    let manifest_path = session.join("manifest.json");
    let manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path)
            .map_err(|error| format!("read {}: {error}", manifest_path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", manifest_path.display()))?;
    if manifest["status"].as_str() != Some("COMPLETE")
        || manifest["credentials"].as_str() != Some("NONE")
        || manifest["order_entry"].as_str() != Some("ABSENT")
    {
        return Err("source capture manifest is not a complete public-only artifact".to_owned());
    }
    let streams = manifest["streams"]
        .as_array()
        .ok_or_else(|| "manifest streams are invalid".to_owned())?;
    let stream = streams
        .iter()
        .find(|item| item["name"].as_str() == Some(stream_name))
        .ok_or_else(|| format!("manifest lacks {stream_name} stream"))?;
    if stream["connection_epoch"].as_str() != Some(&materialization.connection_epoch)
        || stream["raw_file"].as_str()
            != Some(if stream_name == "depth" {
                "depth.bnraw"
            } else {
                "trade.bnraw"
            })
        || stream["error"] != Value::Null
    {
        return Err("manifest stream identity/status does not match materialization".to_owned());
    }
    let ack = &stream["durability_ack"];
    let raw_path = session.join(if stream_name == "depth" {
        "depth.bnraw"
    } else {
        "trade.bnraw"
    });
    let scan = scan_raw_log(&raw_path)?;
    if !scan.clean_eof
        || required_u64(ack, "durable_record_count")? != scan.records
        || required_u64(ack, "durable_through_offset")? != scan.last_good_offset
        || ack["last_record_sha256"].as_str() != Some(&scan.last_record_sha256)
    {
        return Err("manifest durability ACK does not match verified raw artifact".to_owned());
    }
    let watermarks = ack["streams"]
        .as_array()
        .ok_or_else(|| "manifest durability watermarks are invalid".to_owned())?;
    let watermark = watermarks
        .iter()
        .find(|item| {
            item["connection_epoch"].as_str() == Some(&materialization.connection_epoch)
                && item["stream"].as_str() == Some(&materialization.stream)
        })
        .ok_or_else(|| "manifest lacks matching durability watermark".to_owned())?;
    Ok(BoundaryDurabilityV1 {
        durable_through_frame_index: required_u64(watermark, "durable_through_frame_index")?,
        durable_through_offset: scan.last_good_offset,
        last_record_sha256: scan.last_record_sha256,
    })
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("serialize {}: {error}", path.display()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.display()))
}

fn commit_stream(
    output: &Path,
    name: &str,
    kind: BoundaryStreamKind,
    predecessor: &ObservationMaterializationV1,
    successor: &ObservationMaterializationV1,
    predecessor_durability: BoundaryDurabilityV1,
    successor_durability: BoundaryDurabilityV1,
) -> Result<StreamSpliceReport> {
    let boundary_id = format!("{}-{name}-{}", output.display(), Uuid::new_v4());
    let boundary = derive_handover_boundary(
        &boundary_id,
        kind,
        &predecessor.observations,
        &successor.observations,
        predecessor_durability,
        successor_durability,
        SPEC_REVISION,
    )?;
    let selection = select_canonical(
        &boundary,
        &predecessor.observations,
        &successor.observations,
    )?;
    let journal_file = format!("{name}.bnhandover");
    let journal_path = output.join(&journal_file);
    let mut journal = BoundaryJournalWriter::create(&journal_path)?;
    let proposal_ack = journal.propose(boundary.clone())?;
    let commit_ack = journal.commit(&boundary.boundary_id)?;
    let scan = scan_boundary_journal(&journal_path)?;
    if !scan.clean_eof || scan.committed.as_ref() != Some(&boundary) {
        return Err(format!("committed {name} journal failed full rescan"));
    }
    Ok(StreamSpliceReport {
        stream_kind: kind,
        journal_file,
        proposal_ack,
        commit_ack,
        boundary,
        selection,
    })
}

fn run() -> Result<PathBuf> {
    let mut args = env::args_os();
    let executable = PathBuf::from(args.next().unwrap_or_default());
    let predecessor_session = args.next().map(PathBuf::from).ok_or_else(|| {
        format!(
            "usage: {} <predecessor-session> <successor-session> <new-output-dir>",
            executable.display()
        )
    })?;
    let successor_session = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing successor session".to_owned())?;
    let output = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "missing output directory".to_owned())?;
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create splice parent {}: {error}", parent.display()))?;
    }
    fs::create_dir(&output)
        .map_err(|error| format!("create new splice output {}: {error}", output.display()))?;

    // Separate 5000-level snapshots can retain incomparable unknown tails.
    // A shared handover snapshot initializes two independently applied A/B
    // comparison feeds without mutating the original active publication book.
    let handover_snapshot = successor_session.join("snapshot.bnraw");
    let predecessor_depth = materialize_depth_observations(
        &handover_snapshot,
        &predecessor_session.join("depth.bnraw"),
    )?;
    let successor_depth =
        materialize_depth_observations(&handover_snapshot, &successor_session.join("depth.bnraw"))?;
    let predecessor_trade =
        materialize_trade_observations(&predecessor_session.join("trade.bnraw"))?;
    let successor_trade = materialize_trade_observations(&successor_session.join("trade.bnraw"))?;

    let depth = commit_stream(
        &output,
        "depth",
        BoundaryStreamKind::Depth,
        &predecessor_depth,
        &successor_depth,
        durability_from_manifest(&predecessor_session, "depth", &predecessor_depth)?,
        durability_from_manifest(&successor_session, "depth", &successor_depth)?,
    )?;
    let trade = commit_stream(
        &output,
        "trade",
        BoundaryStreamKind::Trade,
        &predecessor_trade,
        &successor_trade,
        durability_from_manifest(&predecessor_session, "trade", &predecessor_trade)?,
        durability_from_manifest(&successor_session, "trade", &successor_trade)?,
    )?;
    write_json(
        &output.join("predecessor-depth-observations.json"),
        &predecessor_depth,
    )?;
    write_json(
        &output.join("successor-depth-observations.json"),
        &successor_depth,
    )?;
    write_json(
        &output.join("predecessor-trade-observations.json"),
        &predecessor_trade,
    )?;
    write_json(
        &output.join("successor-trade-observations.json"),
        &successor_trade,
    )?;
    let report = OverlapSpliceReport {
        schema: "OverlapSpliceReportV1",
        status: "COMMITTED",
        predecessor_session: predecessor_session.display().to_string(),
        successor_session: successor_session.display().to_string(),
        credentials: "NONE",
        order_entry: "ABSENT",
        depth,
        trade,
    };
    write_json(&output.join("splice-report.json"), &report)?;
    Ok(output)
}

fn main() {
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            eprintln!("splice-epochs: {error}");
            std::process::exit(2);
        }
    }
}
