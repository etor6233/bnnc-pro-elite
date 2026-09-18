use lob_replay::observations::{
    DepthObservationCursor, latest_depth_window_convergence, materialize_depth_observations,
    materialize_depth_record_window, materialize_trade_observations, materialize_trade_record,
    materialize_trade_record_window,
};
use lob_replay::{CapturedFrame, RawLogWriter, read_raw_records};
use serde_json::json;
use std::path::Path;
use tempfile::tempdir;

fn frame(stream: &str, epoch: &str, index: u64, payload: Vec<u8>) -> CapturedFrame {
    CapturedFrame {
        venue: "binance-spot".to_owned(),
        environment: "production-public-market-data".to_owned(),
        endpoint: format!("wss://data-stream.binance.vision/ws/{stream}"),
        stream: stream.to_owned(),
        symbol: "BTCUSDT".to_owned(),
        connection_epoch: epoch.to_owned(),
        frame_index: index,
        receive_wall_ns: 1_000 + index,
        receive_mono_ns: 2_000 + index,
        clock_quality: "UNSYNCHRONIZED".to_owned(),
        clock_source: "test".to_owned(),
        payload,
        spec_revision: "976cc580553890e92031b77306147c0ed1de5a46".to_owned(),
    }
}

fn write(path: &Path, frames: &[CapturedFrame]) {
    let mut writer = RawLogWriter::create(path, 1).unwrap();
    for item in frames {
        writer.append(item).unwrap();
    }
    writer.sync().unwrap();
}

#[test]
fn depth_materialization_links_state_to_exact_raw_record() {
    let directory = tempdir().unwrap();
    let snapshot_path = directory.path().join("snapshot.bnraw");
    let depth_path = directory.path().join("depth.bnraw");
    let snapshot = br#"{"lastUpdateId":99,"bids":[["60000.1","1"]],"asks":[["60000.2","1"]]}"#;
    let old = br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":90,"u":99,"b":[],"a":[]}"#;
    let update =
        br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":100,"u":102,"b":[["60000.1","2"]],"a":[]}"#;
    write(
        &snapshot_path,
        &[frame(
            "btcusdt@rest-depth-snapshot",
            "snapshot-1",
            0,
            snapshot.to_vec(),
        )],
    );
    write(
        &depth_path,
        &[
            frame("btcusdt@depth", "epoch-a", 0, old.to_vec()),
            frame("btcusdt@depth", "epoch-a", 1, update.to_vec()),
        ],
    );
    let result = materialize_depth_observations(&snapshot_path, &depth_path).unwrap();
    let records = read_raw_records(&depth_path).unwrap();
    assert_eq!(result.skipped_initial_old_records, 1);
    assert_eq!(result.observations.len(), 1);
    assert_eq!(result.observations[0].frame_index, 1);
    assert_eq!(result.observations[0].first_sequence, 100);
    assert_eq!(result.observations[0].final_sequence, 102);
    assert_eq!(
        result.observations[0].record_sha256,
        records[1].record_sha256
    );
}

fn trade_payload(trade_id: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "e": "trade", "E": 10, "s": "BTCUSDT", "t": trade_id,
        "p": "60000.20000000", "q": "0.01000000", "T": 11,
        "m": false, "M": true
    }))
    .unwrap()
}

#[test]
fn trade_materialization_requires_strict_order_without_inventing_contiguity() {
    let directory = tempdir().unwrap();
    let good = directory.path().join("good.bnraw");
    write(
        &good,
        &[
            frame("btcusdt@trade", "epoch-t", 0, trade_payload(7)),
            frame("btcusdt@trade", "epoch-t", 1, trade_payload(8)),
        ],
    );
    let result = materialize_trade_observations(&good).unwrap();
    assert_eq!((result.first_sequence, result.final_sequence), (7, 8));

    let gap = directory.path().join("gap.bnraw");
    write(
        &gap,
        &[
            frame("btcusdt@trade", "epoch-g", 0, trade_payload(7)),
            frame("btcusdt@trade", "epoch-g", 1, trade_payload(9)),
        ],
    );
    let result = materialize_trade_observations(&gap).unwrap();
    assert_eq!((result.first_sequence, result.final_sequence), (7, 9));

    let regression = directory.path().join("regression.bnraw");
    write(
        &regression,
        &[
            frame("btcusdt@trade", "epoch-r", 0, trade_payload(9)),
            frame("btcusdt@trade", "epoch-r", 1, trade_payload(7)),
        ],
    );
    assert!(
        materialize_trade_observations(&regression)
            .unwrap_err()
            .contains("regressed")
    );
}

#[test]
fn trade_dispatch_time_is_raw_lineage_not_logical_identity() {
    let directory = tempdir().unwrap();
    let first_path = directory.path().join("first.bnraw");
    let second_path = directory.path().join("second.bnraw");
    let first = trade_payload(7);
    let mut second_value: serde_json::Value = serde_json::from_slice(&first).unwrap();
    second_value["E"] = 35.into();
    write(&first_path, &[frame("btcusdt@trade", "epoch-a", 0, first)]);
    write(
        &second_path,
        &[frame(
            "btcusdt@trade",
            "epoch-b",
            0,
            serde_json::to_vec(&second_value).unwrap(),
        )],
    );
    let left = materialize_trade_observations(&first_path).unwrap();
    let right = materialize_trade_observations(&second_path).unwrap();
    assert_ne!(
        left.observations[0].record_sha256,
        right.observations[0].record_sha256
    );
    assert_eq!(
        left.observations[0].observation_sha256,
        right.observations[0].observation_sha256
    );
}

#[test]
fn incremental_depth_cursor_matches_full_replay_digest() {
    let directory = tempdir().unwrap();
    let snapshot_path = directory.path().join("snapshot.bnraw");
    let depth_path = directory.path().join("depth.bnraw");
    write(
        &snapshot_path,
        &[frame(
            "btcusdt@rest-depth-snapshot",
            "snapshot-1",
            0,
            br#"{"lastUpdateId":99,"bids":[["60000.1","1"]],"asks":[["60000.2","1"]]}"#.to_vec(),
        )],
    );
    write(
        &depth_path,
        &[
            frame(
                "btcusdt@depth",
                "epoch-a",
                0,
                br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":90,"u":99,"b":[],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-a",
                1,
                br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":100,"u":102,"b":[["60000.1","2"]],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-a",
                2,
                br#"{"e":"depthUpdate","E":3,"s":"BTCUSDT","U":103,"u":104,"b":[],"a":[["60000.2","3"]]}"#
                    .to_vec(),
            ),
        ],
    );
    let records = read_raw_records(&depth_path).unwrap();
    let mut cursor = DepthObservationCursor::from_durable_prefix(
        &snapshot_path,
        &depth_path,
        records[1].end_offset,
    )
    .unwrap();
    let incremental = cursor.apply_record(&records[2]).unwrap().unwrap();
    let complete = materialize_depth_observations(&snapshot_path, &depth_path).unwrap();
    assert_eq!(incremental, *complete.observations.last().unwrap());
}

#[test]
fn individual_trade_record_matches_full_materialization() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("trade.bnraw");
    write(
        &path,
        &[
            frame("btcusdt@trade", "epoch-t", 0, trade_payload(7)),
            frame("btcusdt@trade", "epoch-t", 1, trade_payload(8)),
        ],
    );
    let records = read_raw_records(&path).unwrap();
    let incremental = materialize_trade_record(&records[1]).unwrap();
    let complete = materialize_trade_observations(&path).unwrap();
    assert_eq!(incremental, complete.observations[1]);
}

#[test]
fn bounded_overlap_windows_can_begin_after_frame_zero_without_losing_identity() {
    let directory = tempdir().unwrap();
    let snapshot_path = directory.path().join("snapshot.bnraw");
    let depth_path = directory.path().join("depth.bnraw");
    let trade_path = directory.path().join("trade.bnraw");
    write(
        &snapshot_path,
        &[frame(
            "btcusdt@rest-depth-snapshot",
            "snapshot-window",
            0,
            br#"{"lastUpdateId":99,"bids":[["60000.1","1"]],"asks":[["60000.2","1"]]}"#.to_vec(),
        )],
    );
    write(
        &depth_path,
        &[
            frame(
                "btcusdt@depth",
                "depth-window",
                0,
                br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":90,"u":99,"b":[],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "depth-window",
                1,
                br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":100,"u":100,"b":[["60000.1","2"]],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "depth-window",
                2,
                br#"{"e":"depthUpdate","E":3,"s":"BTCUSDT","U":101,"u":101,"b":[],"a":[["60000.2","3"]]}"#
                    .to_vec(),
            ),
        ],
    );
    write(
        &trade_path,
        &[
            frame("btcusdt@trade", "trade-window", 0, trade_payload(7)),
            frame("btcusdt@trade", "trade-window", 1, trade_payload(8)),
            frame("btcusdt@trade", "trade-window", 2, trade_payload(9)),
        ],
    );

    let snapshot = read_raw_records(&snapshot_path).unwrap();
    let depth = read_raw_records(&depth_path).unwrap();
    let depth_window = materialize_depth_record_window(&snapshot[0], &depth[1..]).unwrap();
    assert_eq!(depth_window.first().unwrap().frame_index, 1);
    assert_eq!(depth_window.last().unwrap().final_sequence, 101);

    let trade = read_raw_records(&trade_path).unwrap();
    let trade_window = materialize_trade_record_window(&trade[1..]).unwrap();
    assert_eq!(trade_window.first().unwrap().frame_index, 1);
    assert_eq!(trade_window.first().unwrap().first_sequence, 8);
    assert_eq!(trade_window.last().unwrap().final_sequence, 9);

    let mut broken = trade[1..].to_vec();
    broken[1].frame.frame_index = 3;
    assert!(
        materialize_trade_record_window(&broken)
            .unwrap_err()
            .contains("frame gap")
    );
}

#[test]
fn optimized_depth_convergence_matches_full_materialization_and_rejects_divergence() {
    let directory = tempdir().unwrap();
    let snapshot_path = directory.path().join("snapshot.bnraw");
    let predecessor_path = directory.path().join("predecessor.bnraw");
    let successor_path = directory.path().join("successor.bnraw");
    write(
        &snapshot_path,
        &[frame(
            "btcusdt@rest-depth-snapshot",
            "snapshot-convergence",
            0,
            br#"{"lastUpdateId":99,"bids":[["60000.1","1"]],"asks":[["60000.2","1"]]}"#.to_vec(),
        )],
    );
    write(
        &predecessor_path,
        &[
            frame(
                "btcusdt@depth",
                "epoch-a",
                0,
                br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":90,"u":99,"b":[],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-a",
                1,
                br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":100,"u":100,"b":[["60000.1","2"]],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-a",
                2,
                br#"{"e":"depthUpdate","E":3,"s":"BTCUSDT","U":101,"u":101,"b":[],"a":[["60000.2","3"]]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-a",
                3,
                br#"{"e":"depthUpdate","E":4,"s":"BTCUSDT","U":102,"u":102,"b":[["60000.1","4"]],"a":[]}"#
                    .to_vec(),
            ),
        ],
    );
    write(
        &successor_path,
        &[
            frame(
                "btcusdt@depth",
                "epoch-b",
                0,
                br#"{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":90,"u":99,"b":[],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-b",
                1,
                br#"{"e":"depthUpdate","E":2,"s":"BTCUSDT","U":100,"u":100,"b":[["60000.1","9"]],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-b",
                2,
                br#"{"e":"depthUpdate","E":3,"s":"BTCUSDT","U":101,"u":101,"b":[],"a":[["60000.2","3"]]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-b",
                3,
                br#"{"e":"depthUpdate","E":4,"s":"BTCUSDT","U":102,"u":102,"b":[["60000.1","4"]],"a":[]}"#
                    .to_vec(),
            ),
            frame(
                "btcusdt@depth",
                "epoch-b",
                4,
                br#"{"e":"depthUpdate","E":5,"s":"BTCUSDT","U":103,"u":103,"b":[],"a":[["60000.2","4"]]}"#
                    .to_vec(),
            ),
        ],
    );
    let snapshot = read_raw_records(&snapshot_path).unwrap();
    let predecessor = read_raw_records(&predecessor_path).unwrap();
    let successor = read_raw_records(&successor_path).unwrap();
    let convergence =
        latest_depth_window_convergence(&snapshot[0], &predecessor, &successor).unwrap();
    let reference = materialize_depth_record_window(&snapshot[0], &predecessor).unwrap();
    assert_eq!(convergence.predecessor_boundary.final_sequence, 102);
    assert_eq!(convergence.successor_boundary.final_sequence, 102);
    assert_eq!(convergence.successor_continuation.first_sequence, 103);
    assert_eq!(
        convergence.predecessor_boundary.observation_sha256,
        reference.last().unwrap().observation_sha256
    );

    let divergent = successor[..3].to_vec();
    assert!(
        latest_depth_window_convergence(&snapshot[0], &predecessor[..3], &divergent)
            .unwrap_err()
            .contains("no exact depth convergence")
    );
}
