// Probe (test-only): dump per-generation trade id ranges of a lane root,
// following the segment manifest chain exactly like StreamFollowState::open.
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
    let lane_root = std::env::args().nth(1).expect("lane root");
    let lane_root = Path::new(&lane_root);
    for campaign in sorted_dirs(lane_root) {
        for generation in sorted_dirs(&campaign.join("generations")) {
            let trade_dir = generation.join("trade");
            let mut first: Option<u64> = None;
            let mut last: Option<u64> = None;
            let mut count = 0_u64;
            let mut err: Option<String> = None;
            match lob_replay::segment_chain::scan_segment_manifest(
                &trade_dir.join("segments.bnseg"),
            ) {
                Ok(scan) => {
                    let mut previous: Option<lob_replay::RawSegmentSealV1> = None;
                    for entry in &scan.entries {
                        let seal = &entry.seal;
                        let genesis = match &previous {
                            None => lob_replay::segment_chain::root_segment_genesis(
                                &seal.connection_epoch,
                                &seal.stream,
                            ),
                            Some(prev) => {
                                lob_replay::segment_chain::successor_segment_genesis(prev)
                            }
                        };
                        match genesis {
                            Ok(genesis) => {
                                match lob_replay::read_raw_segment_records(
                                    &trade_dir.join(&seal.raw_file),
                                    &genesis,
                                ) {
                                    Ok(records) => {
                                        for record in &records {
                                            if let Ok(obs) =
                                                lob_replay::observations::materialize_trade_record(
                                                    record,
                                                )
                                            {
                                                let id = obs.final_sequence;
                                                first = Some(first.map_or(id, |f| f.min(id)));
                                                last = Some(last.map_or(id, |l| l.max(id)));
                                                count += 1;
                                            }
                                        }
                                    }
                                    Err(e) => err = Some(e.to_string()),
                                }
                            }
                            Err(e) => err = Some(e.to_string()),
                        }
                        previous = Some(seal.clone());
                    }
                }
                Err(e) => err = Some(e.to_string()),
            }
            let gname = generation
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string();
            let cname = campaign
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string();
            match err {
                Some(e) => println!("{cname} {gname} ERR {e}"),
                None => println!("{cname} {gname} count={count} first={first:?} last={last:?}"),
            }
        }
    }
}
