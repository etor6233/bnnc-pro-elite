//! Independent Rust verifier CLI for the live cross-lane arbitration
//! journal (ADR-16 scanner, ADR-17 B5 oracle completion).
//!
//! Two audit layers:
//!
//! 1. The strict journal audit (hash chain, sequence rules, terminal
//!    counters including `late_corrections`, correction classification
//!    against the retained published identity, resume-chain segments).
//! 2. The redundant-evidence oracle, which compares the canonical stream
//!    against the RAW capture of BOTH lanes (never against the output being
//!    verified):
//!    - trades: the canonical trade stream must equal the union of every
//!      durable raw trade above the declared trade floor (zero missing,
//!      zero invented — initial and final omissions are both visible);
//!      every published trade and every correction must carry the exact
//!      raw observation digest and a raw record lineage that exists;
//!    - depth: every canonical frame must exist in the trusted contiguous
//!      prefix of the lane that published it (PRIMARY or SHADOW), with
//!      identical range and book digest; the first frame after a typed
//!      DEPTH_REBOOTSTRAP must start at the declared snapshot boundary.
//!
//! Modes: a single journal file, `--journal-root` for a resume-chained set
//! of segments, `--oracle-generation` (one lane generation) and
//! `--oracle-artifact` (a supervisor artifact or a service symbol root with
//! multiple epoch artifacts).  `--incremental` audits a live prefix with
//! the oracle restricted to the covered prefix (no terminal is required).

use lob_replay::durability_progress::scan_durability_progress;
use lob_replay::live_arbitration::{
    scan_live_arbitration_journal, scan_live_arbitration_journal_incremental,
    scan_live_arbitration_journal_set, scan_live_arbitration_journal_set_incremental,
    scan_live_arbitration_journal_tail_incremental,
};
use lob_replay::observations::{materialize_depth_record_window, materialize_trade_record};
use lob_replay::segment_chain::{
    root_segment_genesis, scan_segment_manifest, successor_segment_genesis,
};
use lob_replay::{
    RawRecordEnvelopeV1, RawSegmentSealV1, Result, read_raw_record_range, read_raw_records,
    read_raw_records_through_offset, read_raw_segment_records,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

fn main() {
    match run() {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize verification report")
            );
        }
        Err(error) => {
            eprintln!("live-arbitration-verify: {error}");
            std::process::exit(2);
        }
    }
}

/// Ordered durable records of one stream inside a generation: sealed
/// segments via the manifest chain plus the in-flight segment's
/// BNACK-authorized durable prefix.  A stream killed before its first
/// rotation has no seals at all; its root segment's durable boundary comes
/// from its own BNACK journal on the ZERO chain (frame 0).
///
/// An in-flight segment whose BNACK carries no complete ACK contributes
/// nothing (a writer interrupted before its first ACK, or a just-created
/// empty segment): the sealed segments remain the complete durable
/// evidence either way.
fn collect_stream_records(
    stream_dir: &Path,
    _tolerate_missing_ack: bool,
) -> Result<Vec<RawRecordEnvelopeV1>> {
    let manifest_scan = scan_segment_manifest(&stream_dir.join("segments.bnseg"))?;
    let mut records = Vec::new();
    let mut previous_seal: Option<RawSegmentSealV1> = None;
    for entry in &manifest_scan.entries {
        let seal = &entry.seal;
        let raw_path = stream_dir.join(&seal.raw_file);
        let genesis = match &previous_seal {
            None => root_segment_genesis(&seal.connection_epoch, &seal.stream)?,
            Some(previous) => {
                let genesis = successor_segment_genesis(previous)?;
                if genesis.previous_segment_terminal_sha256 != seal.previous_segment_terminal_sha256
                {
                    return Err("segment manifest seal chain is discontinuous".to_owned());
                }
                genesis
            }
        };
        records.extend(read_raw_segment_records(&raw_path, &genesis)?);
        previous_seal = Some(seal.clone());
    }
    let next_index = previous_seal
        .as_ref()
        .map(|seal| seal.segment_index.saturating_add(1))
        .unwrap_or(0);
    let raw_path = stream_dir.join(format!("segment-{next_index:06}.bnraw"));
    let progress_path = stream_dir.join(format!("segment-{next_index:06}.bnack"));
    if raw_path.is_file() && progress_path.is_file() {
        let progress = scan_durability_progress(&progress_path)?;
        match progress.latest_ack.as_ref() {
            None => {
                // An in-flight segment whose BNACK carries NO complete ACK
                // contributes NO durable records: a writer interrupted
                // before its first ACK (crash recovery) or a just-created
                // empty segment.  The sealed segments remain the complete
                // durable evidence either way.
            }
            Some(ack) => {
                let durable = ack.durable_through_offset;
                match &previous_seal {
                    None => records.extend(read_raw_records_through_offset(&raw_path, durable)?),
                    Some(previous) => {
                        let genesis = successor_segment_genesis(previous)?;
                        if durable > 8 {
                            records.extend(read_raw_record_range(
                                &raw_path,
                                8,
                                durable,
                                &genesis.previous_segment_terminal_sha256,
                                &genesis.connection_epoch,
                                &genesis.stream,
                                genesis.next_frame_index,
                            )?);
                        }
                    }
                }
            }
        }
    }
    Ok(records)
}

fn sorted_directories(root: &Path) -> Result<Vec<PathBuf>> {
    let mut directories: Vec<PathBuf> = fs::read_dir(root)
        .map_err(|error| format!("read {}: {error}", root.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    directories.sort();
    Ok(directories)
}

/// Resolves the oracle root into the list of supervisor artifact directories:
/// a single artifact (`p/` and `s/` directly below), every epoch artifact
/// below a service symbol root (a service may restart whole supervisors), or
/// the one artifact inside each epoch directory (`<symbol>/e1/<artifact>`).
fn artifact_roots(artifact_root: &Path) -> Vec<PathBuf> {
    if artifact_root.join("p").is_dir() && artifact_root.join("s").is_dir() {
        return vec![artifact_root.to_path_buf()];
    }
    let mut roots = Vec::new();
    for dir in sorted_directories(artifact_root).unwrap_or_default() {
        if dir.join("p").is_dir() && dir.join("s").is_dir() {
            roots.push(dir);
            continue;
        }
        // Epoch directories: the artifact lives one level deeper.
        for nested in sorted_directories(&dir).unwrap_or_default() {
            if nested.join("p").is_dir() && nested.join("s").is_dir() {
                roots.push(nested);
            }
        }
    }
    roots
}

/// Restricts the oracle roots to the artifacts declared by the journal's
/// segment chain.  A segment declares the artifact it was bound to, so a
/// service stopped before a pending epoch transition verifies the window it
/// actually covered, never the successor epoch's raw.  Journals without the
/// declaration (legacy) keep the whole root.
fn scoped_artifact_roots(artifact_root: &Path, declared: &[String]) -> Vec<PathBuf> {
    let all = artifact_roots(artifact_root);
    if declared.is_empty() {
        return all;
    }
    all.into_iter()
        .filter(|root| {
            root.file_name()
                .is_some_and(|name| declared.iter().any(|item| item == &name.to_string_lossy()))
        })
        .collect()
}

struct ExpectedArtifactCut {
    artifacts: Vec<String>,
    journal_hashes: Vec<(PathBuf, String)>,
    sha256: String,
}

fn file_sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| format!("hash {}: {e}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn inventory_path(value: &Value, base: &Path) -> Result<PathBuf> {
    let text = value
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "inventory path must be a nonempty string".to_owned())?;
    let path = Path::new(text);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    fs::canonicalize(&path).map_err(|e| format!("resolve inventory path {}: {e}", path.display()))
}

fn inventory_path_key(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text.into_owned()
    }
}

fn check_inventory_journals(cut: &ExpectedArtifactCut) -> Result<()> {
    for (path, expected) in &cut.journal_hashes {
        if &file_sha256(path)? != expected {
            return Err("inventory journal hash mismatch".to_owned());
        }
    }
    Ok(())
}

fn select_journal_prefix(path: &Path, journals: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if fs::metadata(path)
        .map_err(|e| format!("inventory metadata: {e}"))?
        .len()
        > 16 * 1024 * 1024
    {
        return Err("artifact inventory exceeds its bound".to_owned());
    }
    let encoded = fs::read(path).map_err(|e| format!("read inventory: {e}"))?;
    let value: Value = serde_json::from_slice(
        encoded
            .strip_prefix(&[0xef, 0xbb, 0xbf])
            .unwrap_or(&encoded),
    )
    .map_err(|e| format!("invalid artifact inventory JSON: {e}"))?;
    let entries = value["journals"]
        .as_array()
        .filter(|entries| !entries.is_empty() && entries.len() <= journals.len())
        .ok_or_else(|| "journal cut is not a contiguous prefix".to_owned())?;
    for (entry, actual) in entries.iter().zip(journals) {
        let selected = inventory_path(&entry["path"], path.parent().unwrap_or(Path::new(".")))?;
        let actual =
            fs::canonicalize(actual).map_err(|e| format!("resolve prefix journal: {e}"))?;
        if inventory_path_key(&selected) != inventory_path_key(&actual) {
            return Err("journal cut is not a contiguous prefix".to_owned());
        }
    }
    Ok(journals[..entries.len()].to_vec())
}

/// Independent supervisor eligibility, tied to an exact immutable journal cut.
/// Later epochs do not enter an earlier cut merely because they now exist.
fn load_expected_inventory(
    path: &Path,
    artifact: &Path,
    journals: &[PathBuf],
    declared: &[String],
) -> Result<ExpectedArtifactCut> {
    if fs::metadata(path)
        .map_err(|e| format!("inventory metadata: {e}"))?
        .len()
        > 16 * 1024 * 1024
    {
        return Err("artifact inventory exceeds its bound".to_owned());
    }
    let encoded = fs::read(path).map_err(|e| format!("read inventory: {e}"))?;
    let body = encoded
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(&encoded);
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| format!("invalid artifact inventory JSON: {e}"))?;
    if value["schema"].as_str() != Some("LiveArbitrationExpectedArtifactsV1") {
        return Err("unsupported artifact inventory schema".to_owned());
    }
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let entries = value["artifacts"]
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "artifact inventory requires nonempty artifacts".to_owned())?;
    let mut paths = BTreeSet::new();
    let mut names = BTreeSet::new();
    for entry in entries {
        let resolved = inventory_path(entry, base)?;
        let name = resolved
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "inventory artifact lacks an identity".to_owned())?
            .to_owned();
        if !paths.insert(inventory_path_key(&resolved)) || !names.insert(name) {
            return Err("artifact inventory contains duplicate identities".to_owned());
        }
    }
    let selected: Vec<PathBuf> = artifact_roots(artifact)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| names.contains(s))
        })
        .map(|p| fs::canonicalize(&p).map_err(|e| format!("resolve oracle artifact: {e}")))
        .collect::<Result<_>>()?;
    let selected_keys: BTreeSet<String> = selected.iter().map(|p| inventory_path_key(p)).collect();
    if selected.len() != paths.len() || selected_keys != paths {
        return Err("artifact inventory paths are missing or ambiguous in oracle root".to_owned());
    }
    let entries = value["journals"]
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| "artifact inventory requires journal cuts".to_owned())?;
    let mut journal_hashes = Vec::new();
    let mut cut_paths = BTreeSet::new();
    for entry in entries {
        let sha = entry["sha256"]
            .as_str()
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| "invalid inventory journal digest".to_owned())?;
        let resolved = inventory_path(&entry["path"], base)?;
        if !cut_paths.insert(inventory_path_key(&resolved)) {
            return Err("inventory journal set differs from audited journals".to_owned());
        }
        journal_hashes.push((resolved, sha.to_ascii_lowercase()));
    }
    let actual: BTreeSet<String> = journals
        .iter()
        .map(|p| {
            fs::canonicalize(p)
                .map(|p| inventory_path_key(&p))
                .map_err(|e| format!("resolve journal: {e}"))
        })
        .collect::<Result<_>>()?;
    if cut_paths != actual {
        return Err("inventory journal set differs from audited journals".to_owned());
    }
    let cut = ExpectedArtifactCut {
        artifacts: names.iter().cloned().collect(),
        journal_hashes,
        sha256: format!("{:x}", Sha256::digest(&encoded)),
    };
    check_inventory_journals(&cut)?;
    if declared.iter().cloned().collect::<BTreeSet<_>>() != names {
        return Err("artifact inventory differs from journal declarations".to_owned());
    }
    Ok(cut)
}

/// Lanes whose depth evidence still includes an unsealed generation: a
/// live-prefix audit cannot verify frames freshly published from that
/// evidence yet (the closed segment verification runs after the seal).
fn unsealed_depth_lanes(artifact_root: &Path, declared: &[String]) -> Result<BTreeSet<String>> {
    let mut lanes = BTreeSet::new();
    for root in scoped_artifact_roots(artifact_root, declared) {
        for lane in ["p", "s"] {
            let lane_root = root.join(lane);
            if !lane_root.is_dir() {
                continue;
            }
            for campaign in sorted_directories(&lane_root)? {
                for generation in sorted_directories(&campaign.join("generations"))? {
                    if !stream_fully_sealed(&generation.join("depth"))? {
                        lanes.insert(lane.to_owned());
                        break;
                    }
                }
                if lanes.contains(lane) {
                    break;
                }
            }
        }
    }
    Ok(lanes)
}

/// One materialized raw trade: exact ID, the raw record digest and the
/// semantic observation digest.
#[derive(Clone, Debug)]
struct RawTradeEvidence {
    record_sha256: String,
    observation_sha256: String,
}

/// The capture system's complete trade evidence (ADR-17 B5): every durable
/// trade of every campaign and generation of BOTH lanes keyed by trade ID,
/// retaining the exact observation digests per raw record.  Disagreement
/// between two raw records of the same ID is itself a typed error: the raw
/// is the authority and the canonical must match it.
fn hash_file_into(digest: &mut Sha256, path: &Path) -> Result<()> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("hash {}: {error}", path.display()))?;
    let mut buffer = [0_u8; 65536];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("hash {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(())
}

/// Content key of a sealed stream. An unsealed generation is never cached.
fn sealed_stream_key(generation: &Path, stream: &str) -> Result<Option<String>> {
    let stream_dir = generation.join(stream);
    if !stream_fully_sealed(&stream_dir)? {
        return Ok(None);
    }
    let mut digest = Sha256::new();
    digest.update(b"sealed-oracle-v1\0");
    digest.update(stream.as_bytes());
    let mut files: Vec<PathBuf> = fs::read_dir(&stream_dir)
        .map_err(|error| format!("read {}: {error}", stream_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect();
    files.sort();
    for path in files {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name_bytes = name.as_bytes();
        digest.update((name_bytes.len() as u32).to_be_bytes());
        digest.update(name_bytes);
        digest.update([0_u8]);
        hash_file_into(&mut digest, &path)?;
    }
    if stream == "depth" {
        let snapshot = generation.join("snapshot.bnraw");
        if snapshot.is_file() {
            digest.update(b"snapshot.bnraw");
            hash_file_into(&mut digest, &snapshot)?;
        }
    }
    Ok(Some(format!("{:x}", digest.finalize())))
}

fn read_oracle_cache(cache_dir: &Path, kind: &str, key: &str) -> Option<Value> {
    let path = cache_dir.join(kind).join(format!("{key}.json"));
    let bytes = fs::read(path).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    if value.get("key").and_then(Value::as_str) != Some(key) {
        return None;
    }
    value.get("rows").cloned()
}

fn write_oracle_cache(cache_dir: &Path, kind: &str, key: &str, value: &Value) -> Result<()> {
    let directory = cache_dir.join(kind);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("create {}: {error}", directory.display()))?;
    let target = directory.join(format!("{key}.json"));
    let temporary = directory.join(format!("{key}.json.tmp"));
    let encoded = serde_json::json!({"key": key, "rows": value});
    let bytes =
        serde_json::to_vec(&encoded).map_err(|error| format!("encode oracle cache: {error}"))?;
    fs::write(&temporary, bytes)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    if target.is_file() {
        fs::remove_file(&target)
            .map_err(|error| format!("replace {}: {error}", target.display()))?;
    }
    fs::rename(&temporary, &target).map_err(|error| {
        format!(
            "replace {} with {}: {error}",
            target.display(),
            temporary.display()
        )
    })?;
    Ok(())
}

fn oracle_trades_union(
    artifact_root: &Path,
    declared_artifacts: &[String],
    tolerate_missing_ack: bool,
    cache_dir: Option<&Path>,
) -> Result<BTreeMap<u64, Vec<RawTradeEvidence>>> {
    let mut by_id: BTreeMap<u64, Vec<RawTradeEvidence>> = BTreeMap::new();
    for root in scoped_artifact_roots(artifact_root, declared_artifacts) {
        for lane in ["p", "s"] {
            let lane_root = root.join(lane);
            if !lane_root.is_dir() {
                continue;
            }
            for campaign in sorted_directories(&lane_root)? {
                for generation in sorted_directories(&campaign.join("generations"))? {
                    let key = match cache_dir {
                        Some(_) => sealed_stream_key(&generation, "trade")?,
                        None => None,
                    };
                    let cached = key.as_ref().and_then(|key| {
                        cache_dir.and_then(|dir| read_oracle_cache(dir, "trade", key))
                    });
                    let rows = if let Some(Value::Array(rows)) = cached {
                        let mut parsed = Vec::new();
                        let mut valid = true;
                        for row in rows {
                            let Some(trade_id) = row["trade_id"].as_u64() else {
                                valid = false;
                                break;
                            };
                            let Some(record_sha256) = row["record_sha256"].as_str() else {
                                valid = false;
                                break;
                            };
                            let Some(observation_sha256) = row["observation_sha256"].as_str()
                            else {
                                valid = false;
                                break;
                            };
                            parsed.push((
                                trade_id,
                                record_sha256.to_owned(),
                                observation_sha256.to_owned(),
                            ));
                        }
                        if valid { Some(parsed) } else { None }
                    } else {
                        None
                    };
                    let rows = if let Some(rows) = rows {
                        rows
                    } else {
                        let mut built = Vec::new();
                        for record in
                            collect_stream_records(&generation.join("trade"), tolerate_missing_ack)?
                        {
                            let observation = materialize_trade_record(&record)?;
                            built.push((
                                observation.final_sequence,
                                record.record_sha256.clone(),
                                observation.observation_sha256.clone(),
                            ));
                        }
                        if let (Some(dir), Some(key)) = (cache_dir, key.as_deref()) {
                            let encoded = Value::Array(
                                built
                                    .iter()
                                    .map(|(trade_id, record_sha256, observation_sha256)| {
                                        serde_json::json!({
                                            "trade_id": trade_id,
                                            "record_sha256": record_sha256,
                                            "observation_sha256": observation_sha256,
                                        })
                                    })
                                    .collect(),
                            );
                            write_oracle_cache(dir, "trade", key, &encoded)?;
                        }
                        built
                    };
                    for (trade_id, record_sha256, observation_sha256) in rows {
                        by_id.entry(trade_id).or_default().push(RawTradeEvidence {
                            record_sha256,
                            observation_sha256,
                        });
                    }
                }
            }
        }
    }
    Ok(by_id)
}

/// True when the generation declared its own durable terminal (status
/// COMPLETE, no failure).  Absence or a mid-write body is NEVER proof that
/// the stream ended (ADR-17 boundary authority, review 2026-09-11 risk 1;
/// defect hrs-a8d39b6c0204: the verifier previously inferred the definitive
/// end from the missing next segment file and misread a live rotation
/// window as "fully sealed", falsely rejecting freshly published frames).
fn generation_terminal_complete(generation_dir: &Path) -> Result<bool> {
    let path = generation_dir.join("generation.json");
    if !path.is_file() {
        return Ok(false);
    }
    let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        // The capture writes the terminal declaration once with
        // write+sync: a reader racing the write may see a partial body.
        // No proof of COMPLETE means the stream must stay unsealed
        // (conservative: the next poll retries).
        Err(_) => return Ok(false),
    };
    Ok(value["status"].as_str() == Some("COMPLETE") && value["failure"].is_null())
}

/// A generation whose stream still carries an in-flight (unsealed) segment
/// was interrupted before terminal evidence: its book state is untrusted for
/// identity comparison even though its records remain valid evidence.
fn stream_fully_sealed(stream_dir: &Path) -> Result<bool> {
    let generation_dir = stream_dir.parent().ok_or_else(|| {
        format!(
            "stream dir {} has no generation parent",
            stream_dir.display()
        )
    })?;
    if !generation_terminal_complete(generation_dir)? {
        return Ok(false);
    }
    let manifest_scan = scan_segment_manifest(&stream_dir.join("segments.bnseg"))?;
    let next_index = manifest_scan
        .entries
        .last()
        .map(|entry| entry.seal.segment_index.saturating_add(1))
        .unwrap_or(0);
    Ok(!stream_dir
        .join(format!("segment-{next_index:06}.bnraw"))
        .is_file())
}

/// One complete generation's depth observations restricted to the contiguous
/// prefix from its snapshot: the first update-ID jump marks the point where
/// a dropped venue event makes every later book digest untrustworthy.
fn trusted_depth_observations(
    generation: &Path,
    tolerate_missing_ack: bool,
) -> Result<Vec<(u64, u64, String)>> {
    let snapshot_path = generation.join("snapshot.bnraw");
    let snapshots = read_raw_records(&snapshot_path)?;
    if snapshots.len() != 1 {
        return Err("oracle depth snapshot must contain exactly one record".to_owned());
    }
    let snapshot_payload: Value = serde_json::from_slice(&snapshots[0].frame.payload)
        .map_err(|error| format!("parse oracle depth snapshot payload: {error}"))?;
    let snapshot_last = snapshot_payload["lastUpdateId"]
        .as_u64()
        .ok_or_else(|| "oracle depth snapshot lacks lastUpdateId".to_owned())?;
    let records = collect_stream_records(&generation.join("depth"), tolerate_missing_ack)?;
    // A sealed stream with a snapshot but zero durable records proves an
    // EMPTY window (no LIVE depth ever arrived): its trusted prefix is
    // empty, not an error — the closed oracle compares the canonical
    // against exactly that emptiness.  A stream with records that never
    // went LIVE stays a hard error (identity/materialization mismatch).
    if records.is_empty() {
        return Ok(Vec::new());
    }
    let observations = materialize_depth_record_window(&snapshots[0], &records)?;
    let mut trusted = Vec::new();
    let mut expected = snapshot_last.saturating_add(1);
    for observation in observations {
        if observation.final_sequence < expected {
            continue;
        }
        if observation.first_sequence > expected {
            break;
        }
        trusted.push((
            observation.first_sequence,
            observation.final_sequence,
            observation.observation_sha256.clone(),
        ));
        expected = observation.final_sequence.saturating_add(1);
    }
    Ok(trusted)
}

/// One lane's trusted depth oracle: final update ID -> (first, digest)
/// variants (multiple generations may cover the same update differently).
type LaneDepthOracle = BTreeMap<u64, Vec<(u64, String)>>;
/// The full depth oracle keyed by lane root (p/s).
type DepthOracle = BTreeMap<String, LaneDepthOracle>;

/// The depth oracle (ADR-17 B5): the trusted contiguous observations of
/// BOTH lanes, keyed by lane and then by final update ID.  A window served
/// exclusively by SHADOW verifies against the SHADOW oracle exactly like a
/// PRIMARY window verifies against the PRIMARY oracle.  Two generations of
/// the same lane may legitimately cover the same update ID with different
/// book digests (their REST snapshots were taken at different times — the
/// measured REST/WS inconsistency class); every variant is retained and the
/// canonical frame must match ONE of the lane's raw variants exactly.
fn oracle_depth_by_lane(
    artifact_root: &Path,
    declared_artifacts: &[String],
    tolerate_missing_ack: bool,
    unsealed_lanes: &BTreeSet<String>,
    cache_dir: Option<&Path>,
) -> Result<DepthOracle> {
    let roots = scoped_artifact_roots(artifact_root, declared_artifacts);
    if roots.is_empty() {
        return Err("oracle artifact lacks lane roots".to_owned());
    }
    let mut by_lane: DepthOracle = BTreeMap::new();
    for root in roots {
        for lane in ["p", "s"] {
            let lane_root = root.join(lane);
            if !lane_root.is_dir() {
                continue;
            }
            let lane_map = by_lane.entry(lane.to_owned()).or_default();
            for campaign in sorted_directories(&lane_root)? {
                for generation in sorted_directories(&campaign.join("generations"))? {
                    // ADR-17 B5 (defect hrs-14572a22e336): the exclusion and
                    // the tolerance must come from the SAME classification
                    // snapshot.  The caller computes unsealed_depth_lanes
                    // FIRST and hands it in here: a generation whose lane is
                    // unsealed is skipped consistently (no second read of the
                    // terminal declaration racing the oracle build — the
                    // earlier two-read interleaving rejected frames the
                    // oracle had legitimately excluded).  A generation
                    // interrupted by a crash still carries a FIXED
                    // BNACK-authorized durable prefix: the trusted contiguous
                    // prefix from its snapshot is exact evidence for the
                    // closed audit (the seal only claims "the stream ended
                    // here"); live-prefix audits keep excluding it and the
                    // tolerance handles the freshly published frames.
                    let unsealed = unsealed_lanes.contains(lane)
                        || !stream_fully_sealed(&generation.join("depth"))?;
                    if unsealed && tolerate_missing_ack {
                        continue;
                    }
                    let key = match cache_dir {
                        Some(_) if !unsealed => sealed_stream_key(&generation, "depth")?,
                        _ => None,
                    };
                    let cached = key.as_ref().and_then(|key| {
                        cache_dir.and_then(|dir| read_oracle_cache(dir, "depth", key))
                    });
                    let observations = if let Some(Value::Array(rows)) = cached {
                        let mut parsed = Vec::new();
                        let mut valid = true;
                        for row in rows {
                            let Some(list) = row.as_array() else {
                                valid = false;
                                break;
                            };
                            if list.len() != 3 {
                                valid = false;
                                break;
                            }
                            let Some(first) = list[0].as_u64() else {
                                valid = false;
                                break;
                            };
                            let Some(final_sequence) = list[1].as_u64() else {
                                valid = false;
                                break;
                            };
                            let Some(digest) = list[2].as_str() else {
                                valid = false;
                                break;
                            };
                            parsed.push((first, final_sequence, digest.to_owned()));
                        }
                        if valid { Some(parsed) } else { None }
                    } else {
                        None
                    };
                    let observations = if let Some(observations) = observations {
                        observations
                    } else {
                        let built = trusted_depth_observations(&generation, tolerate_missing_ack)?;
                        if let (Some(dir), Some(key)) = (cache_dir, key.as_deref()) {
                            let encoded = Value::Array(
                                built
                                    .iter()
                                    .map(|(first, final_sequence, digest)| {
                                        Value::Array(vec![
                                            Value::from(*first),
                                            Value::from(*final_sequence),
                                            Value::from(digest.clone()),
                                        ])
                                    })
                                    .collect(),
                            );
                            write_oracle_cache(dir, "depth", key, &encoded)?;
                        }
                        built
                    };
                    for observation in observations {
                        lane_map
                            .entry(observation.1)
                            .or_default()
                            .push((observation.0, observation.2));
                    }
                }
            }
        }
    }
    if !tolerate_missing_ack && (!by_lane.contains_key("p") || !by_lane.contains_key("s")) {
        return Err("oracle artifact lacks both lane roots".to_owned());
    }
    Ok(by_lane)
}

#[derive(Clone, Debug)]
struct CanonicalTradeRecord {
    trade_id: u64,
    /// Retained for report completeness; raw lineage is checked via record_sha256.
    #[allow(dead_code)]
    lane: Option<String>,
    record_sha256: String,
    observation_sha256: String,
}

#[derive(Clone, Debug)]
struct CanonicalDepthFrame {
    first_sequence: u64,
    final_sequence: u64,
    digest: String,
    lane: Option<String>,
}

#[derive(Clone, Debug)]
struct CanonicalCorrection {
    trade_id: u64,
    kind: String,
    record_sha256: String,
    observation_sha256: String,
}

#[derive(Default)]
struct CanonicalObservationSet {
    trades: Vec<CanonicalTradeRecord>,
    depth: Vec<CanonicalDepthFrame>,
    corrections: Vec<CanonicalCorrection>,
    /// (sequence, declared snapshot_last_update_id) right after each
    /// DEPTH_REBOOTSTRAP, so the first frame after it can be checked
    /// against the declared snapshot boundary.
    depth_rebootstraps: Vec<(u64, u64, String)>,
    terminal_serving_lane: Option<String>,
    terminal_completion_scope: Option<String>,
    trade_floor: Option<u64>,
    has_startup_context: bool,
    /// Artifact identities declared by the segment chain (STARTED /
    /// RESUMED): the raw oracle is restricted to exactly these artifacts,
    /// so a service stopped before a pending epoch transition verifies the
    /// window it actually covered, never the successor epoch's raw.
    declared_artifacts: Vec<String>,
    /// Kind of the last depth-related event ("frame", "gap" or None):
    /// the closed audit rejects a window that ends mid-gap or before the
    /// sealed evidence's trusted continuation (ADR-17 B5 final boundary).
    last_depth_event: Option<&'static str>,
}

fn collect_journal_observations(
    journal: &Path,
    set: &mut CanonicalObservationSet,
    tolerate_partial_tail: bool,
) -> Result<()> {
    let bytes =
        fs::read(journal).map_err(|error| format!("read {}: {error}", journal.display()))?;
    let mut rebootstrap_pending = false;
    for part in bytes.split_inclusive(|byte| *byte == b'\n') {
        if !part.ends_with(b"\n") && tolerate_partial_tail {
            break;
        }
        let line = part.strip_suffix(b"\n").unwrap_or(part);
        if line.is_empty() {
            continue;
        }
        let envelope: Value = serde_json::from_slice(line)
            .map_err(|error| format!("invalid journal JSON: {error}"))?;
        let payload = &envelope["body"]["payload"];
        match payload["event"].as_str() {
            Some("ARBITRATION_STARTED" | "ARBITRATION_RESUMED") => {
                set.terminal_completion_scope = None;
                if payload["event"].as_str() == Some("ARBITRATION_STARTED") {
                    set.has_startup_context = true;
                }
                // The canonical window starts at the FIRST segment's floor;
                // later segments declare their own (higher) resumed floors.
                if set.trade_floor.is_none() {
                    set.trade_floor = payload["trade_floor"].as_u64();
                }
                if let Some(artifact) = payload["artifact_root"].as_str() {
                    set.declared_artifacts.push(artifact.to_owned());
                }
                // ADR-17 B3 LIVE rebind: a segment that continues from a
                // PRIOR epoch artifact declares every prior artifact it
                // walks — the raw oracle must include them (their sealed
                // tails are part of the covered window).
                if let Some(prior) = payload["prior_artifacts"].as_array() {
                    for item in prior {
                        if let Some(name) = item.as_str() {
                            set.declared_artifacts.push(name.to_owned());
                        }
                    }
                }
            }
            Some("TRADE_OBSERVATION") => {
                set.trades.push(CanonicalTradeRecord {
                    trade_id: payload["trade_id"]
                        .as_u64()
                        .ok_or_else(|| "trade observation lacks an exact trade ID".to_owned())?,
                    lane: payload["lane"].as_str().map(str::to_owned),
                    record_sha256: payload["record_sha256"]
                        .as_str()
                        .ok_or_else(|| "trade observation lacks record_sha256".to_owned())?
                        .to_owned(),
                    observation_sha256: payload["observation_sha256"]
                        .as_str()
                        .ok_or_else(|| "trade observation lacks observation_sha256".to_owned())?
                        .to_owned(),
                });
            }
            Some("TRADE_LATE_CORRECTION") => {
                set.corrections.push(CanonicalCorrection {
                    trade_id: payload["trade_id"]
                        .as_u64()
                        .ok_or_else(|| "trade correction lacks an exact trade ID".to_owned())?,
                    kind: payload["kind"]
                        .as_str()
                        .ok_or_else(|| "trade correction lacks its kind".to_owned())?
                        .to_owned(),
                    record_sha256: payload["record_sha256"]
                        .as_str()
                        .ok_or_else(|| "trade correction lacks record_sha256".to_owned())?
                        .to_owned(),
                    observation_sha256: payload["observation_sha256"]
                        .as_str()
                        .ok_or_else(|| "trade correction lacks observation_sha256".to_owned())?
                        .to_owned(),
                });
            }
            Some("DEPTH_OBSERVATION") => {
                let frame = CanonicalDepthFrame {
                    first_sequence: payload["first_sequence"]
                        .as_u64()
                        .ok_or_else(|| "depth observation lacks first_sequence".to_owned())?,
                    final_sequence: payload["final_sequence"]
                        .as_u64()
                        .ok_or_else(|| "depth observation lacks final_sequence".to_owned())?,
                    digest: payload["observation_sha256"]
                        .as_str()
                        .ok_or_else(|| "depth observation lacks its digest".to_owned())?
                        .to_owned(),
                    lane: payload["lane"].as_str().map(str::to_owned),
                };
                if rebootstrap_pending {
                    rebootstrap_pending = false;
                }
                set.last_depth_event = Some("frame");
                set.depth.push(frame);
            }
            Some("DEPTH_REBOOTSTRAP") => {
                let snapshot_last = payload["snapshot_last_update_id"]
                    .as_u64()
                    .ok_or_else(|| "DEPTH_REBOOTSTRAP lacks snapshot_last_update_id".to_owned())?;
                let lane = payload["lane"]
                    .as_str()
                    .ok_or_else(|| "DEPTH_REBOOTSTRAP lacks its lane".to_owned())?
                    .to_owned();
                set.depth_rebootstraps
                    .push((snapshot_last, set.depth.len() as u64, lane));
                rebootstrap_pending = true;
            }
            Some("GAP") => {
                // The gap itself is audited by the scanner (declared cursor).
                set.last_depth_event = Some("gap");
            }
            Some("ARBITRATION_TERMINAL") => {
                let scope = &payload["completion_scope"];
                if !scope.is_null() && !matches!(scope.as_str(), Some("HANDOFF" | "SEALED_DRAIN")) {
                    return Err("unknown terminal completion_scope".to_owned());
                }
                set.terminal_completion_scope = scope.as_str().map(str::to_owned);
                set.terminal_serving_lane = payload["serving_lane_at_terminal"]
                    .as_str()
                    .map(str::to_owned);
            }
            _ => {}
        }
    }
    Ok(())
}

/// ADR-17 reconstructed view: ordered observations plus first UNKNOWN late
/// corrections must equal the independent raw union exactly. Duplicate late
/// records corroborate an existing identity; they never increase cardinality.
fn verify_trades_against_raw(
    canonical: &CanonicalObservationSet,
    raw_union: &BTreeMap<u64, Vec<RawTradeEvidence>>,
    bound_to_last: bool,
) -> Result<usize> {
    let floor = canonical.trade_floor.unwrap_or(0);
    let upper_bound = bound_to_last.then(|| canonical.trades.last().map_or(floor, |t| t.trade_id));
    let identity = |id: u64, record: &str, digest: &str, label: &str| -> Result<()> {
        let evidence = raw_union
            .get(&id)
            .ok_or_else(|| format!("{label} {id} has no raw evidence"))?;
        let digests: BTreeSet<&str> = evidence
            .iter()
            .map(|item| item.observation_sha256.as_str())
            .collect();
        if digests.len() != 1 {
            return Err(format!("raw trade {id} has conflicting identities"));
        }
        if !digests.contains(digest) {
            return Err(format!(
                "{label} {id} carries an observation digest absent from the raw capture"
            ));
        }
        if !evidence
            .iter()
            .any(|item| item.record_sha256 == record && item.observation_sha256 == digest)
        {
            return Err(format!(
                "{label} {id} carries a raw lineage record absent from the raw capture"
            ));
        }
        Ok(())
    };
    let mut reconstructed: BTreeMap<u64, &str> = BTreeMap::new();
    for trade in &canonical.trades {
        identity(
            trade.trade_id,
            &trade.record_sha256,
            &trade.observation_sha256,
            "canonical trade",
        )?;
        if reconstructed
            .insert(trade.trade_id, &trade.observation_sha256)
            .is_some()
        {
            return Err("canonical journal publishes a duplicate trade ID".to_owned());
        }
    }
    for correction in &canonical.corrections {
        let id = correction.trade_id;
        identity(
            id,
            &correction.record_sha256,
            &correction.observation_sha256,
            "trade correction",
        )?;
        match correction.kind.as_str() {
            "duplicate" => {
                if reconstructed.get(&id).copied() != Some(correction.observation_sha256.as_str()) {
                    return Err(format!(
                        "trade correction {id} kind=duplicate contradicts the published identity"
                    ));
                }
            }
            "unknown" => {
                if canonical.has_startup_context && id <= floor {
                    return Err(
                        "unknown correction is at or below the startup trade floor".to_owned()
                    );
                }
                if reconstructed
                    .insert(id, &correction.observation_sha256)
                    .is_some()
                {
                    return Err(format!(
                        "trade correction {id} kind=unknown contradicts the published identity"
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "trade correction {id} carries an unknown classification"
                ));
            }
        }
    }
    let expected: Vec<u64> = raw_union
        .keys()
        .copied()
        .filter(|id| *id > floor && upper_bound.is_none_or(|bound| *id <= bound))
        .collect();
    let actual: Vec<u64> = reconstructed
        .keys()
        .copied()
        .filter(|id| *id > floor)
        .collect();
    if actual != expected {
        let missing: Vec<u64> = expected
            .iter()
            .copied()
            .filter(|id| !reconstructed.contains_key(id))
            .take(8)
            .collect();
        let invented: Vec<u64> = actual
            .iter()
            .copied()
            .filter(|id| !raw_union.contains_key(id))
            .take(8)
            .collect();
        return Err(format!(
            "canonical trade stream differs from the raw union: reconstructed={} union_window={} missing_examples={missing:?} invented_examples={invented:?}",
            actual.len(),
            expected.len()
        ));
    }
    Ok(reconstructed.len())
}

/// Depth oracle (ADR-17 B5): every canonical frame must exist in the
/// trusted contiguous prefix of the lane that published it, with identical
/// range and book digest; the first frame after each DEPTH_REBOOTSTRAP must
/// start exactly at the declared snapshot boundary of the declared lane.
fn verify_depth_against_raw(
    canonical: &CanonicalObservationSet,
    raw_depth: &DepthOracle,
    tolerant_lanes: bool,
    enforce_final_boundary: bool,
    unsealed_lanes: &BTreeSet<String>,
) -> Result<()> {
    let mut next_rebootstrap_index = 0_usize;
    for (index, frame) in canonical.depth.iter().enumerate() {
        let lane_label = frame
            .lane
            .as_deref()
            .ok_or_else(|| "canonical depth frame lacks its lane".to_owned())?;
        // Canonical records carry PRIMARY/SHADOW; the raw oracle is keyed
        // by the lane roots p/s.
        let lane = match lane_label {
            "PRIMARY" => "p",
            "SHADOW" => "s",
            other => other,
        };
        let lane_oracle = raw_depth.get(lane);
        if tolerant_lanes && lane_oracle.is_none_or(|oracle| oracle.is_empty()) {
            // Live prefix / bounded tail: the lane has no trusted sealed
            // prefix yet; the closed full-set verification enforces it.
            continue;
        }
        let lane_oracle = lane_oracle
            .ok_or_else(|| format!("canonical depth frame names an unknown lane {lane}"))?;
        if let Some((declared_last, first_frame_index, declared_lane)) =
            canonical.depth_rebootstraps.get(next_rebootstrap_index)
            && *first_frame_index as usize == index
        {
            let declared_norm = match declared_lane.as_str() {
                "PRIMARY" => "p",
                "SHADOW" => "s",
                other => other,
            };
            if declared_norm != lane {
                return Err(
                    "first depth frame after DEPTH_REBOOTSTRAP names a different lane".to_owned(),
                );
            }
            if frame.first_sequence <= *declared_last {
                // The REBOOTSTRAP evidences the snapshot state AT the
                // declared lastUpdateId: the next published frame must
                // start strictly after that boundary (never republish
                // the snapshot's own coverage); the subsumed prefix
                // between the boundary and the first applied frame is
                // part of the bootstrap evidence itself.
                return Err(format!(
                    "first depth frame after DEPTH_REBOOTSTRAP starts at {} but the declared snapshot boundary requires a frame strictly after {}",
                    frame.first_sequence, declared_last
                ));
            }
            next_rebootstrap_index += 1;
        }
        match lane_oracle.get(&frame.final_sequence) {
            Some(variants) => {
                if !variants.iter().any(|(first_sequence, digest)| {
                    *first_sequence == frame.first_sequence && *digest == frame.digest
                }) {
                    if tolerant_lanes && unsealed_lanes.contains(lane) {
                        // The frame was published from evidence that is still
                        // in-flight; the closed segment verification runs
                        // after the seal.
                        continue;
                    }
                    return Err(format!(
                        "canonical depth frame {}-{} differs from the {lane} raw oracle (range or book digest)",
                        frame.first_sequence, frame.final_sequence
                    ));
                }
            }
            None => {
                if tolerant_lanes && unsealed_lanes.contains(lane) {
                    continue;
                }
                return Err(format!(
                    "canonical depth frame {}-{} is absent from the {lane} raw oracle",
                    frame.first_sequence, frame.final_sequence
                ));
            }
        }
    }
    if enforce_final_boundary
        && canonical.depth_rebootstraps.len() != next_rebootstrap_index
        && !canonical.depth_rebootstraps.is_empty()
        && canonical
            .depth_rebootstraps
            .get(next_rebootstrap_index)
            .is_some_and(|(_, index, _)| (*index as usize) >= canonical.depth.len())
    {
        return Err("a DEPTH_REBOOTSTRAP carries no following depth frame to verify".to_owned());
    }
    // ADR-17 B5 final boundary (closed audit only): the canonical depth
    // stream must reach the sealed evidence's trusted end.  A window that
    // ends mid-gap, an empty canonical against non-empty sealed evidence,
    // or a final cursor short of a TRUSTED contiguous continuation of the
    // publishing lane is a final omission — the raw proves the frames
    // existed, so the closed view is incomplete.  A genuinely empty window
    // passes only when the sealed evidence itself holds no trusted depth.
    if enforce_final_boundary {
        match canonical.last_depth_event {
            Some("gap") => {
                return Err(
                    "canonical depth stream ends with an unresolved gap: the post-gap continuation never published"
                        .to_owned(),
                );
            }
            Some("frame") => {
                let last = canonical.depth.last().expect("last depth event is a frame");
                let lane = match last.lane.as_deref() {
                    Some("PRIMARY") => "p",
                    Some("SHADOW") => "s",
                    Some(other) => other,
                    None => return Err("canonical depth frame lacks its lane".to_owned()),
                };
                let lane_oracle = raw_depth
                    .get(lane)
                    .ok_or_else(|| format!("canonical depth frame names an unknown lane {lane}"))?;
                // A trusted overlap U <= next <= u also continues the book;
                // equality of U alone misses a real terminal omission.
                if let Some(next) = last.final_sequence.checked_add(1)
                    && lane_oracle.iter().any(|(final_sequence, variants)| {
                        *final_sequence >= next && variants.iter().any(|(first, _)| *first <= next)
                    })
                {
                    return Err(format!(
                        "canonical depth stream ends at update {} but the {lane} sealed evidence continues at update {next} (final omission)",
                        last.final_sequence
                    ));
                }
            }
            Some(_) => return Ok(()),
            None => {
                for (lane, oracle) in raw_depth {
                    if !oracle.is_empty() {
                        return Err(format!(
                            "canonical depth stream is empty while the {lane} sealed evidence holds trusted depth observations"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

struct OracleVerification {
    reconstructed_trades: Option<usize>,
    trade_identity: &'static str,
    depth_scope_complete: bool,
    terminal_completion_scope: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn verify_with_oracle(
    journals: &[PathBuf],
    oracle_artifact: Option<&Path>,
    oracle_generation: Option<&Path>,
    tolerant_lanes: bool,
    bound_to_last: bool,
    enforce_final_boundary: bool,
    expected_artifacts: Option<&[String]>,
    cache_dir: Option<&Path>,
) -> Result<OracleVerification> {
    let mut canonical = CanonicalObservationSet::default();
    for (index, journal) in journals.iter().enumerate() {
        collect_journal_observations(
            journal,
            &mut canonical,
            bound_to_last || index + 1 < journals.len(),
        )?;
    }
    let trade_identity = if bound_to_last && canonical.trades.is_empty() {
        "SKIPPED_EMPTY_PREFIX"
    } else {
        "PASS"
    };
    let declared = expected_artifacts.unwrap_or(&canonical.declared_artifacts);
    if let Some(artifact) = oracle_artifact {
        // ADR-17 B5 (defect hrs-14572a22e336): compute the unsealed-lane
        // classification FIRST and share it with the oracle build, so the
        // exclusion and the tolerance always come from the SAME snapshot of
        // the generation terminal state (the earlier two-read interleaving
        // rejected frames the oracle had legitimately excluded).
        let unsealed = unsealed_depth_lanes(artifact, declared)?;
        let raw_union = oracle_trades_union(artifact, declared, tolerant_lanes, cache_dir)?;
        let raw_depth =
            oracle_depth_by_lane(artifact, declared, tolerant_lanes, &unsealed, cache_dir)?;
        let reconstructed_trades =
            verify_trades_against_raw(&canonical, &raw_union, bound_to_last)?;
        verify_depth_against_raw(
            &canonical,
            &raw_depth,
            tolerant_lanes,
            enforce_final_boundary,
            &unsealed,
        )?;
        return Ok(OracleVerification {
            trade_identity,
            reconstructed_trades: Some(reconstructed_trades),
            depth_scope_complete: unsealed.is_empty(),
            terminal_completion_scope: canonical.terminal_completion_scope,
        });
    }
    if let Some(generation) = oracle_generation {
        // Single untouched lane generation: trades must equal that
        // generation's raw trades above the floor; depth frames must exist
        // in the generation's trusted contiguous prefix (mapped to its lane).
        let mut raw_union: BTreeMap<u64, Vec<RawTradeEvidence>> = BTreeMap::new();
        for record in collect_stream_records(&generation.join("trade"), tolerant_lanes)? {
            let observation = materialize_trade_record(&record)?;
            raw_union
                .entry(observation.final_sequence)
                .or_default()
                .push(RawTradeEvidence {
                    record_sha256: record.record_sha256.clone(),
                    observation_sha256: observation.observation_sha256.clone(),
                });
        }
        let reconstructed_trades =
            verify_trades_against_raw(&canonical, &raw_union, bound_to_last)?;
        let generation_text = generation.to_string_lossy().replace('\\', "/");
        let lane = if generation_text.contains("/p/") {
            "p"
        } else if generation_text.contains("/s/") {
            "s"
        } else {
            return Err("oracle generation is not below a primary/shadow lane root".to_owned());
        };
        let mut raw_depth: DepthOracle = BTreeMap::new();
        let lane_map = raw_depth.entry(lane.to_owned()).or_default();
        if stream_fully_sealed(&generation.join("depth"))? {
            for observation in trusted_depth_observations(generation, tolerant_lanes)? {
                lane_map
                    .entry(observation.1)
                    .or_default()
                    .push((observation.0, observation.2));
            }
        }
        verify_depth_against_raw(
            &canonical,
            &raw_depth,
            tolerant_lanes,
            enforce_final_boundary,
            &BTreeSet::new(),
        )?;
        return Ok(OracleVerification {
            trade_identity,
            reconstructed_trades: Some(reconstructed_trades),
            depth_scope_complete: stream_fully_sealed(&generation.join("depth"))?,
            terminal_completion_scope: canonical.terminal_completion_scope,
        });
    }
    Err("an oracle mode must be selected for identity verification".to_owned())
}

fn sorted_journal_segments(root: &Path) -> Result<Vec<PathBuf>> {
    let mut segments: Vec<PathBuf> = fs::read_dir(root)
        .map_err(|error| format!("read {}: {error}", root.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect();
    segments.sort();
    Ok(segments)
}

/// Reads the first payload of a journal segment (resume context).
fn read_first_payload(path: &Path) -> Result<Value> {
    let file = fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut buf: Vec<u8> = Vec::new();
    let read = reader
        .read_until(b'\n', &mut buf)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if read == 0 {
        return Err(format!("journal segment {} is empty", path.display()));
    }
    let line = if buf.last() == Some(&b'\n') {
        &buf[..read - 1]
    } else {
        &buf[..read]
    };
    let envelope: Value =
        serde_json::from_slice(line).map_err(|error| format!("invalid journal JSON: {error}"))?;
    Ok(envelope["body"]["payload"].clone())
}

fn run() -> Result<serde_json::Value> {
    let mut args = env::args();
    let executable = args
        .next()
        .unwrap_or_else(|| "live_arbitration_verify".to_owned());
    let mut journal_arg: Option<String> = None;
    let mut journal_root: Option<PathBuf> = None;
    let mut oracle_generation: Option<PathBuf> = None;
    let mut oracle_artifact: Option<PathBuf> = None;
    let mut expected_artifact_inventory: Option<PathBuf> = None;
    let mut incremental = false;
    let mut tail_segment_only = false;
    let mut journal_prefix = false;
    let mut oracle_cache: Option<PathBuf> = None;
    let rest: Vec<String> = args.collect();
    let mut index = 0_usize;
    while index < rest.len() {
        match rest[index].as_str() {
            "--journal-root" => {
                if index + 1 >= rest.len() {
                    return Err("--journal-root expects exactly one directory".to_owned());
                }
                journal_root = Some(PathBuf::from(rest[index + 1].clone()));
                index += 2;
            }
            "--oracle-generation" => {
                if index + 1 >= rest.len() {
                    return Err("--oracle-generation expects exactly one directory".to_owned());
                }
                oracle_generation = Some(PathBuf::from(rest[index + 1].clone()));
                index += 2;
            }
            "--oracle-artifact" => {
                if index + 1 >= rest.len() {
                    return Err("--oracle-artifact expects exactly one directory".to_owned());
                }
                oracle_artifact = Some(PathBuf::from(rest[index + 1].clone()));
                index += 2;
            }
            "--incremental" => {
                incremental = true;
                index += 1;
            }
            "--journal-prefix" => {
                journal_prefix = true;
                index += 1;
            }
            "--expected-artifact-inventory" => {
                if index + 1 >= rest.len() {
                    return Err("--expected-artifact-inventory expects exactly one file".to_owned());
                }
                expected_artifact_inventory = Some(PathBuf::from(&rest[index + 1]));
                index += 2;
            }
            "--tail-segment-only" => {
                tail_segment_only = true;
                index += 1;
            }
            "--oracle-cache" => {
                if index + 1 >= rest.len() {
                    return Err("--oracle-cache expects exactly one directory".to_owned());
                }
                oracle_cache = Some(PathBuf::from(&rest[index + 1]));
                index += 2;
            }
            _ => {
                if journal_arg.is_some() {
                    return Err("unknown trailing arguments".to_owned());
                }
                journal_arg = Some(rest[index].clone());
                index += 1;
            }
        }
    }
    if oracle_generation.is_some() && oracle_artifact.is_some() {
        return Err("choose exactly one oracle mode".to_owned());
    }
    if expected_artifact_inventory.is_some() && oracle_artifact.is_none() {
        return Err("expected artifact inventory requires --oracle-artifact".to_owned());
    }
    if journal_prefix
        && (journal_root.is_none()
            || expected_artifact_inventory.is_none()
            || incremental
            || tail_segment_only)
    {
        return Err("--journal-prefix requires --journal-root and --expected-artifact-inventory without another prefix mode".to_owned());
    }
    let journal = match (&journal_root, journal_arg) {
        (None, Some(journal)) => PathBuf::from(journal),
        (Some(_), None) => PathBuf::from("."),
        (Some(_), Some(_)) => {
            return Err("--journal-root replaces the single journal argument".to_owned());
        }
        (None, None) => {
            return Err(format!(
                "usage: {executable} <journal> [--journal-root <dir>] [--oracle-generation <generation-dir> | --oracle-artifact <artifact-root>] [--incremental]"
            ));
        }
    };
    if tail_segment_only && (incremental || journal_root.is_some() || oracle_artifact.is_none()) {
        return Err(
            "--tail-segment-only requires one sealed resume segment and --oracle-artifact"
                .to_owned(),
        );
    }

    let mut journals: Vec<PathBuf> = match &journal_root {
        Some(root) => {
            let segments = sorted_journal_segments(root)?;
            if segments.is_empty() {
                return Err(format!(
                    "journal root {} contains no journal segments",
                    root.display()
                ));
            }
            segments
        }
        None => vec![journal.clone()],
    };
    if journal_prefix {
        journals = select_journal_prefix(
            expected_artifact_inventory
                .as_ref()
                .expect("validated inventory"),
            &journals,
        )?;
    }

    let inventory_cut = match &expected_artifact_inventory {
        Some(path) => {
            let mut canonical = CanonicalObservationSet::default();
            for (index, journal) in journals.iter().enumerate() {
                collect_journal_observations(
                    journal,
                    &mut canonical,
                    incremental || tail_segment_only || index + 1 < journals.len(),
                )?;
            }
            Some(load_expected_inventory(
                path,
                oracle_artifact.as_ref().expect("validated oracle mode"),
                &journals,
                &canonical.declared_artifacts,
            )?)
        }
        None => None,
    };
    let (scan, clean_eof, tail_bytes) = if incremental && journal_root.is_some() {
        scan_live_arbitration_journal_set_incremental(&journals)?
    } else if incremental {
        // Live prefix audit: a single active segment, terminal not required.
        // A resumed segment carries its own chain context in its
        // ARBITRATION_RESUMED record.
        let first_payload = read_first_payload(&journal)?;
        let event = first_payload
            .get("event")
            .and_then(Value::as_str)
            .ok_or_else(|| "journal segment lacks its first event".to_owned())?;
        if event == "ARBITRATION_RESUMED" {
            let previous_sha = first_payload
                .get("previous_journal_sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| "resumed segment lacks previous_journal_sha256".to_owned())?
                .to_owned();
            let floor = first_payload
                .get("trade_floor")
                .and_then(Value::as_u64)
                .ok_or_else(|| "resumed segment lacks trade_floor".to_owned())?;
            let (scan, clean_eof, tail) =
                scan_live_arbitration_journal_tail_incremental(&journal, &previous_sha, floor)?;
            (scan, clean_eof, tail)
        } else {
            let (scan, clean_eof, tail) = scan_live_arbitration_journal_incremental(&journal)?;
            (scan, clean_eof, tail)
        }
    } else if tail_segment_only {
        // Bounded per-epoch verification (ADR-17 B2): audit ONE sealed
        // segment.  A fresh segment opens with ARBITRATION_STARTED (normal
        // closed audit); a resumed segment is audited against the chain
        // context declared in its own ARBITRATION_RESUMED record, without
        // re-reading the previous segments (the full structural set audit
        // runs at the terminal).
        let first_payload = read_first_payload(&journals[0])?;
        let event = first_payload
            .get("event")
            .and_then(Value::as_str)
            .ok_or_else(|| "tail segment lacks its first event".to_owned())?;
        if event == "ARBITRATION_STARTED" {
            scan_live_arbitration_journal_incremental(&journals[0])?
        } else if event == "ARBITRATION_RESUMED" {
            let previous_sha = first_payload
                .get("previous_journal_sha256")
                .and_then(Value::as_str)
                .ok_or_else(|| "tail segment lacks previous_journal_sha256".to_owned())?
                .to_owned();
            let floor = first_payload
                .get("trade_floor")
                .and_then(Value::as_u64)
                .ok_or_else(|| "tail segment lacks trade_floor".to_owned())?;
            scan_live_arbitration_journal_tail_incremental(&journals[0], &previous_sha, floor)?
        } else {
            return Err("tail segment does not open with STARTED or RESUMED".to_owned());
        }
    } else if journals.len() == 1 {
        (scan_live_arbitration_journal(&journals[0])?, true, 0_u64)
    } else {
        (scan_live_arbitration_journal_set(&journals)?, true, 0_u64)
    };
    let (tolerant_lanes, bound_to_last, enforce_final_boundary) = if incremental || journal_prefix {
        (true, true, false)
    } else if tail_segment_only {
        // Bounded per-epoch verification: the segment ends at an epoch
        // boundary, not at the lane stream's end — the final-boundary check
        // belongs to the full-set audit at the service terminal only.
        (true, true, false)
    } else {
        (false, false, true)
    };
    let terminal_complete = scan.terminal_seen && clean_eof;
    let tail_interrupted = tail_segment_only && !terminal_complete;
    let oracle_result = if oracle_artifact.is_some() || oracle_generation.is_some() {
        verify_with_oracle(
            &journals,
            oracle_artifact.as_deref(),
            oracle_generation.as_deref(),
            tolerant_lanes,
            bound_to_last,
            enforce_final_boundary,
            inventory_cut.as_ref().map(|cut| cut.artifacts.as_slice()),
            oracle_cache.as_deref(),
        )?
    } else {
        OracleVerification {
            trade_identity: "SKIPPED",
            reconstructed_trades: None,
            depth_scope_complete: false,
            terminal_completion_scope: None,
        }
    };
    let oracle_identity = if oracle_result.trade_identity == "PASS" {
        "PASS"
    } else {
        "SKIPPED"
    };
    if let Some(cut) = &inventory_cut {
        check_inventory_journals(cut)?;
    }
    let audit_scope = if journal_prefix {
        "SEALED_JOURNAL_PREFIX"
    } else if incremental {
        "LIVE_PREFIX"
    } else if tail_interrupted {
        "INTERRUPTED_SEGMENT_PREFIX"
    } else if tail_segment_only {
        "SEALED_SEGMENT_PREFIX"
    } else {
        "CLOSED_JOURNAL_SET"
    };

    Ok(serde_json::json!({
        "schema": "LiveArbitrationVerificationV2",
        "status": "PASS",
        "journal": journal,
        "journal_root": journal_root,
        "segments": scan.segments,
        "incremental": incremental,
        "tail_segment_only": tail_segment_only,
        "journal_prefix": journal_prefix,
        "tail_interrupted": tail_interrupted,
        "terminal_complete": terminal_complete,
        "clean_eof": clean_eof,
        "audit_scope": audit_scope,
        "artifact_coverage": if inventory_cut.is_some() { "PASS" } else { "UNPROVEN" },
        "expected_artifact_inventory_sha256": inventory_cut.as_ref().map(|cut| &cut.sha256),
        "coverage_exhaustive": inventory_cut.is_some() && terminal_complete && !bound_to_last
            && oracle_identity == "PASS" && oracle_result.depth_scope_complete
            && oracle_result.terminal_completion_scope.as_deref() == Some("SEALED_DRAIN"),
        "tail_bytes": tail_bytes,
        "records": scan.records,
        "observations": scan.observations,
        "trades": scan.trades,
        "depth_frames": scan.depth_frames,
        "gaps": scan.gaps,
        "late_corrections": scan.late_corrections,
        "rebootstrap": scan.rebootstrap,
        "status_records": scan.status_records,
        "published_trades": scan.published_trades,
        "trade_floor": scan.trade_floor,
        "symbol": scan.symbol,
        "last_trade_id": scan.last_trade_id,
        "last_depth_sequence": scan.last_depth_sequence,
        "last_record_sha256": scan.last_record_sha256,
        "oracle_generation": oracle_generation,
        "oracle_artifact": oracle_artifact,
        "oracle_identity": oracle_identity,
        "oracle_trade_identity": oracle_result.trade_identity,
        "canonical_view": "OBSERVATIONS_PLUS_UNKNOWN_LATE_CORRECTIONS",
        "reconstructed_trades": oracle_result.reconstructed_trades,
        "oracle_depth_scope_complete": oracle_result.depth_scope_complete,
        "terminal_completion_scope": oracle_result.terminal_completion_scope,
        "schema_compatibility": {
            "policy": "reject_unknown_kinds",
            "detail": "Trade late corrections without kind in {duplicate, unknown} are REJECTED (fail-closed), never silently reinterpreted; legacy journals must be re-verified against raw evidence."
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_cache_rejects_a_file_whose_key_does_not_match() {
        let dir = std::env::temp_dir().join(format!("oracle-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        write_oracle_cache(&dir, "trade", "abc", &serde_json::json!([])).unwrap();
        let loaded = read_oracle_cache(&dir, "trade", "abc").expect("matching key loads");
        assert_eq!(loaded, serde_json::json!([]));
        fs::write(
            dir.join("trade").join("abc.json"),
            br#"{"key":"nope","rows":[{"trade_id":1}]}"#,
        )
        .unwrap();
        assert!(read_oracle_cache(&dir, "trade", "abc").is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    fn evidence(record: &str, observation: &str) -> Vec<RawTradeEvidence> {
        vec![RawTradeEvidence {
            record_sha256: record.to_owned(),
            observation_sha256: observation.to_owned(),
        }]
    }

    fn depth(first: u64, final_: u64, lane: &str) -> CanonicalDepthFrame {
        CanonicalDepthFrame {
            first_sequence: first,
            final_sequence: final_,
            digest: format!("d{first}"),
            lane: Some(lane.to_owned()),
        }
    }

    fn depth_oracle(entries: &[(u64, u64, &str)]) -> BTreeMap<u64, Vec<(u64, String)>> {
        let mut map = BTreeMap::new();
        for (first, final_, digest) in entries {
            map.entry(*final_)
                .or_insert_with(Vec::new)
                .push((*first, digest.to_string()));
        }
        map
    }

    /// ADR-17 B5 (audit-review-20260908 R2): a closed verification must
    /// reject an EMPTY canonical trade stream when the sealed raw union
    /// holds expected trades — the external cut is the raw, never the output.
    #[test]
    fn closed_trade_oracle_rejects_empty_canonical_when_raw_is_non_empty() {
        let canonical = CanonicalObservationSet {
            trade_floor: Some(0),
            ..CanonicalObservationSet::default()
        };
        let mut raw_union = BTreeMap::new();
        raw_union.insert(10, evidence("r", "o"));
        let error = verify_trades_against_raw(&canonical, &raw_union, false).unwrap_err();
        assert!(error.contains("canonical trade stream differs from the raw union"));
    }

    /// A genuinely empty window passes only with the external proof that the
    /// sealed evidence is empty too.
    #[test]
    fn closed_trade_oracle_accepts_a_genuinely_empty_window() {
        let canonical = CanonicalObservationSet {
            trade_floor: Some(0),
            ..CanonicalObservationSet::default()
        };
        let raw_union = BTreeMap::new();
        verify_trades_against_raw(&canonical, &raw_union, false).expect("empty window passes");
    }

    /// Live-prefix audits may legitimately have published nothing yet.
    #[test]
    fn incremental_trade_oracle_tolerates_nothing_published_yet() {
        let canonical = CanonicalObservationSet {
            trade_floor: Some(0),
            ..CanonicalObservationSet::default()
        };
        let mut raw_union = BTreeMap::new();
        raw_union.insert(10, evidence("r", "o"));
        verify_trades_against_raw(&canonical, &raw_union, true).expect("live prefix passes");
    }

    /// ADR-17 B5 (audit-review-20260908 R2): the closed depth oracle must
    /// detect a FINAL omission — the publishing lane's sealed trusted
    /// evidence continues past the canonical cursor.
    #[test]
    fn closed_depth_oracle_rejects_a_final_omission() {
        let mut canonical = CanonicalObservationSet::default();
        canonical.depth.push(depth(101, 103, "PRIMARY"));
        canonical.depth.push(depth(104, 107, "PRIMARY"));
        canonical.last_depth_event = Some("frame");
        let mut raw = BTreeMap::new();
        raw.insert(
            "p".to_owned(),
            depth_oracle(&[(101, 103, "d101"), (104, 107, "d104"), (108, 110, "d108")]),
        );
        raw.insert("s".to_owned(), BTreeMap::new());
        let error =
            verify_depth_against_raw(&canonical, &raw, false, true, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("final omission"));
    }

    /// Ending exactly at the sealed evidence's trusted boundary is complete.
    #[test]
    fn closed_depth_oracle_accepts_the_exact_trusted_boundary() {
        let mut canonical = CanonicalObservationSet::default();
        canonical.depth.push(depth(101, 103, "PRIMARY"));
        canonical.depth.push(depth(104, 107, "PRIMARY"));
        canonical.depth.push(depth(108, 110, "PRIMARY"));
        canonical.last_depth_event = Some("frame");
        let mut raw = BTreeMap::new();
        raw.insert(
            "p".to_owned(),
            depth_oracle(&[(101, 103, "d101"), (104, 107, "d104"), (108, 110, "d108")]),
        );
        raw.insert("s".to_owned(), BTreeMap::new());
        verify_depth_against_raw(&canonical, &raw, false, true, &BTreeSet::new())
            .expect("exact trusted boundary passes");
    }

    /// A window that ends mid-gap never materialized its post-gap
    /// continuation: the closed view is incomplete.
    #[test]
    fn closed_depth_oracle_rejects_a_trailing_gap() {
        let mut canonical = CanonicalObservationSet::default();
        canonical.depth.push(depth(101, 103, "PRIMARY"));
        canonical.last_depth_event = Some("gap");
        let mut raw = BTreeMap::new();
        raw.insert(
            "p".to_owned(),
            depth_oracle(&[(101, 103, "d101"), (104, 107, "d104")]),
        );
        raw.insert("s".to_owned(), BTreeMap::new());
        let error =
            verify_depth_against_raw(&canonical, &raw, false, true, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("unresolved gap"));
    }

    /// An empty canonical depth stream against non-empty sealed depth
    /// evidence is an omission; against empty evidence it is a proven
    /// empty window.
    #[test]
    fn closed_depth_oracle_empty_canonical_rules() {
        let canonical = CanonicalObservationSet::default();
        let mut raw = BTreeMap::new();
        raw.insert("p".to_owned(), depth_oracle(&[(101, 103, "d101")]));
        raw.insert("s".to_owned(), BTreeMap::new());
        let error =
            verify_depth_against_raw(&canonical, &raw, false, true, &BTreeSet::new()).unwrap_err();
        assert!(error.contains("canonical depth stream is empty"));
        let mut raw_empty = BTreeMap::new();
        raw_empty.insert("p".to_owned(), BTreeMap::new());
        raw_empty.insert("s".to_owned(), BTreeMap::new());
        verify_depth_against_raw(&canonical, &raw_empty, false, true, &BTreeSet::new())
            .expect("proven empty window passes");
    }

    /// ADR-17 B5 (defect hrs-14572a22e336): frames published from evidence
    /// the SAME classification excluded (unsealed lane) are tolerated — the
    /// exclusion and the tolerance must come from one snapshot.
    #[test]
    fn incremental_depth_oracle_tolerates_frames_excluded_by_unsealed_lane() {
        let mut canonical = CanonicalObservationSet::default();
        canonical.depth.push(depth(740743, 740752, "PRIMARY"));
        canonical.last_depth_event = Some("frame");
        let mut raw = BTreeMap::new();
        raw.insert("p".to_owned(), depth_oracle(&[(100, 103, "d100")]));
        raw.insert("s".to_owned(), BTreeMap::new());
        let mut unsealed = BTreeSet::new();
        unsealed.insert("p".to_owned());
        verify_depth_against_raw(&canonical, &raw, true, false, &unsealed)
            .expect("excluded unsealed lane is tolerated");
    }

    /// Without the shared classification the same frame is a typed rejection.
    #[test]
    fn incremental_depth_oracle_rejects_excluded_frame_without_unsealed_classification() {
        let mut canonical = CanonicalObservationSet::default();
        canonical.depth.push(depth(740743, 740752, "PRIMARY"));
        canonical.last_depth_event = Some("frame");
        let mut raw = BTreeMap::new();
        raw.insert("p".to_owned(), depth_oracle(&[(100, 103, "d100")]));
        raw.insert("s".to_owned(), BTreeMap::new());
        let error = verify_depth_against_raw(&canonical, &raw, true, false, &BTreeSet::new())
            .expect_err("frame absent from the oracle without tolerance rejects");
        assert!(error.contains("absent from the p raw oracle"));
    }

    /// ADR-17 boundary authority (defect hrs-a8d39b6c0204): the durable
    /// terminal declaration (generation.json COMPLETE) is the ONLY authority
    /// for "the stream can never deliver again".  A live rotation window with
    /// the next segment file absent, a partial mid-write declaration, or a
    /// failed generation must never be read as the definitive end.
    #[test]
    fn live_rotation_window_is_not_misread_as_terminal() {
        let temp = tempfile::tempdir().expect("tempdir");
        let generation = temp.path().join("g000");
        std::fs::create_dir_all(generation.join("depth")).expect("dirs");
        lob_replay::segment_chain::RawSegmentManifestWriter::create(
            &generation.join("depth").join("segments.bnseg"),
        )
        .expect("empty manifest");
        // No COMPLETE declaration: not fully sealed (old predicate returned
        // true here — the misclassification of defect hrs-a8d39b6c0204).
        assert!(
            !stream_fully_sealed(&generation.join("depth")).expect("live rotation stays unsealed")
        );
        // Durable COMPLETE declaration: fully sealed.
        std::fs::write(
            generation.join("generation.json"),
            r#"{"schema":"RawGenerationManifestV1","status":"COMPLETE","failure":null}"#,
        )
        .expect("write complete");
        assert!(stream_fully_sealed(&generation.join("depth")).expect("complete seals"));
        // A partial (mid-write) declaration is no proof of COMPLETE.
        std::fs::write(generation.join("generation.json"), r#"{"status":"COMPLE"#)
            .expect("write partial");
        assert!(!stream_fully_sealed(&generation.join("depth")).expect("partial stays unsealed"));
        // A failed generation is never fully sealed as success.
        std::fs::write(
            generation.join("generation.json"),
            r#"{"status":"COMPLETE","failure":{"reason":"x"}}"#,
        )
        .expect("write failed");
        assert!(!stream_fully_sealed(&generation.join("depth")).expect("failed stays unsealed"));
    }
}
