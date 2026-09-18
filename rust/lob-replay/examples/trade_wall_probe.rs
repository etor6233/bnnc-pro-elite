// Probe (test-only): dump (trade_id, receive_wall_ns, lane) for every raw
// trade record of an artifact root, restricted to an id range.
use std::path::{Path, PathBuf};

fn sorted_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|it| {
            it.flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    dirs
}

fn main() {
    let artifact_root = std::env::args().nth(1).expect("artifact root");
    let low: u64 = std::env::args()
        .nth(2)
        .expect("low id")
        .parse()
        .expect("low id parse");
    let high: u64 = std::env::args()
        .nth(3)
        .expect("high id")
        .parse()
        .expect("high id parse");
    let artifact_root = Path::new(&artifact_root);
    let mut rows: Vec<(u64, u64, String, String, u64)> = Vec::new();
    for lane in ["p", "s"] {
        let lane_root = artifact_root.join(lane);
        if !lane_root.is_dir() {
            continue;
        }
        for campaign in sorted_dirs(&lane_root) {
            for generation in sorted_dirs(&campaign.join("generations")) {
                let trade_dir = generation.join("trade");
                let scan = match lob_replay::segment_chain::scan_segment_manifest(
                    &trade_dir.join("segments.bnseg"),
                ) {
                    Ok(scan) => scan,
                    Err(e) => {
                        eprintln!("{lane} {campaign:?} {generation:?} ERR {e}");
                        continue;
                    }
                };
                let mut previous: Option<lob_replay::RawSegmentSealV1> = None;
                for entry in &scan.entries {
                    let seal = &entry.seal;
                    let genesis = match &previous {
                        None => lob_replay::segment_chain::root_segment_genesis(
                            &seal.connection_epoch,
                            &seal.stream,
                        ),
                        Some(prev) => lob_replay::segment_chain::successor_segment_genesis(prev),
                    };
                    let genesis = match genesis {
                        Ok(g) => g,
                        Err(e) => {
                            eprintln!("{lane} genesis ERR {e}");
                            continue;
                        }
                    };
                    let records = match lob_replay::read_raw_segment_records(
                        &trade_dir.join(&seal.raw_file),
                        &genesis,
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("{lane} read ERR {e}");
                            continue;
                        }
                    };
                    for record in &records {
                        if let Ok(obs) = lob_replay::observations::materialize_trade_record(record)
                        {
                            let id = obs.final_sequence;
                            if id >= low && id <= high {
                                rows.push((
                                    id,
                                    record.frame.receive_wall_ns,
                                    lane.to_string(),
                                    campaign
                                        .file_name()
                                        .map(|n| n.to_string_lossy().into_owned())
                                        .unwrap_or_default(),
                                    record.frame.frame_index,
                                ));
                            }
                        }
                    }
                    previous = Some(seal.clone());
                }
            }
        }
    }
    rows.sort_by_key(|row| (row.1, row.0));
    for (id, wall, lane, campaign, frame) in rows {
        println!("id={id} wall={wall} lane={lane} frame={frame} campaign={campaign}");
    }
}
