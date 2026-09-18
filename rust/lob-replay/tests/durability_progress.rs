use lob_replay::boundary::{BoundaryStreamKind, CanonicalObservationV1};
use lob_replay::durability_progress::{
    DurabilityProgressWriter, durable_cursor_at_observation, freeze_durable_raw_prefix,
    read_durable_raw_delta, scan_durability_progress, verify_progress_against_raw,
};
use lob_replay::{CapturedFrame, RawLogWriter};
use std::fs::OpenOptions;
use std::io::Write;
use tempfile::tempdir;

fn frame(index: u64) -> CapturedFrame {
    CapturedFrame {
        venue: "binance-spot".to_owned(),
        environment: "production-public-market-data".to_owned(),
        endpoint: "wss://example.invalid".to_owned(),
        stream: "btcusdt@trade".to_owned(),
        symbol: "BTCUSDT".to_owned(),
        connection_epoch: "trade-a".to_owned(),
        frame_index: index,
        receive_wall_ns: index,
        receive_mono_ns: index,
        clock_quality: "UNSYNCHRONIZED".to_owned(),
        clock_source: "test".to_owned(),
        payload: format!("{{\"t\":{index}}}").into_bytes(),
        spec_revision: "spec".to_owned(),
    }
}

#[test]
fn progress_ack_matches_exact_durable_raw_prefix_with_newer_raw_bytes() {
    let directory = tempdir().unwrap();
    let raw_path = directory.path().join("trade.bnraw");
    let progress_path = directory.path().join("trade.bnack");
    let mut raw = RawLogWriter::create(&raw_path, 2).unwrap();
    let mut progress = DurabilityProgressWriter::create(&progress_path, &raw_path).unwrap();
    raw.append(&frame(0)).unwrap();
    let ack = raw.append(&frame(1)).unwrap().durability_ack.unwrap();
    progress.append(ack.clone()).unwrap();
    raw.append(&frame(2)).unwrap();

    let scan = scan_durability_progress(&progress_path).unwrap();
    assert!(scan.clean_eof);
    assert_eq!(verify_progress_against_raw(&scan, &raw_path).unwrap(), ack);
}

#[test]
fn partial_progress_tail_preserves_only_the_last_complete_ack() {
    let directory = tempdir().unwrap();
    let raw_path = directory.path().join("trade.bnraw");
    let progress_path = directory.path().join("trade.bnack");
    let mut raw = RawLogWriter::create(&raw_path, 1).unwrap();
    let ack = raw.append(&frame(0)).unwrap().durability_ack.unwrap();
    let mut progress = DurabilityProgressWriter::create(&progress_path, &raw_path).unwrap();
    progress.append(ack.clone()).unwrap();
    drop(progress);
    OpenOptions::new()
        .append(true)
        .open(&progress_path)
        .unwrap()
        .write_all(b"{\"partial\"")
        .unwrap();

    let scan = scan_durability_progress(&progress_path).unwrap();
    assert!(!scan.clean_eof);
    assert_eq!(scan.records, 1);
    assert_eq!(verify_progress_against_raw(&scan, &raw_path).unwrap(), ack);
}

#[test]
fn duplicate_or_regressing_ack_is_rejected() {
    let directory = tempdir().unwrap();
    let raw_path = directory.path().join("trade.bnraw");
    let progress_path = directory.path().join("trade.bnack");
    let mut raw = RawLogWriter::create(&raw_path, 1).unwrap();
    let ack = raw.append(&frame(0)).unwrap().durability_ack.unwrap();
    let mut progress = DurabilityProgressWriter::create(&progress_path, &raw_path).unwrap();
    progress.append(ack.clone()).unwrap();
    assert!(progress.append(ack).is_err());
}

#[test]
fn progress_for_different_raw_chain_is_rejected() {
    let directory = tempdir().unwrap();
    let raw_a = directory.path().join("a.bnraw");
    let raw_b = directory.path().join("b.bnraw");
    let progress_path = directory.path().join("trade.bnack");
    let mut writer_a = RawLogWriter::create(&raw_a, 1).unwrap();
    let mut writer_b = RawLogWriter::create(&raw_b, 1).unwrap();
    let ack = writer_a.append(&frame(0)).unwrap().durability_ack.unwrap();
    let mut changed = frame(0);
    changed.payload = b"different".to_vec();
    writer_b.append(&changed).unwrap();
    let mut progress = DurabilityProgressWriter::create(&progress_path, &raw_a).unwrap();
    progress.append(ack).unwrap();

    let scan = scan_durability_progress(&progress_path).unwrap();
    assert!(verify_progress_against_raw(&scan, &raw_b).is_err());
}

#[test]
fn frozen_prefix_excludes_newer_complete_and_partial_live_bytes() {
    let directory = tempdir().unwrap();
    let raw_path = directory.path().join("trade.bnraw");
    let progress_path = directory.path().join("trade.bnack");
    let frozen_path = directory.path().join("frozen.bnraw");
    let mut raw = RawLogWriter::create(&raw_path, 2).unwrap();
    raw.append(&frame(0)).unwrap();
    let ack = raw.append(&frame(1)).unwrap().durability_ack.unwrap();
    let mut progress = DurabilityProgressWriter::create(&progress_path, &raw_path).unwrap();
    progress.append(ack.clone()).unwrap();
    raw.append(&frame(2)).unwrap();
    drop(raw);
    OpenOptions::new()
        .append(true)
        .open(&raw_path)
        .unwrap()
        .write_all(b"partial-live-tail")
        .unwrap();

    let scan = scan_durability_progress(&progress_path).unwrap();
    assert_eq!(
        freeze_durable_raw_prefix(&scan, &raw_path, &frozen_path).unwrap(),
        ack
    );
    let frozen = lob_replay::read_raw_records(&frozen_path).unwrap();
    assert_eq!(frozen.len(), 2);
    assert_eq!(frozen.last().unwrap().frame.frame_index, 1);
}

#[test]
fn durable_delta_reads_only_new_acknowledged_records() {
    let directory = tempdir().unwrap();
    let raw_path = directory.path().join("trade.bnraw");
    let mut raw = RawLogWriter::create(&raw_path, 2).unwrap();
    raw.append(&frame(0)).unwrap();
    let first = raw.append(&frame(1)).unwrap().durability_ack.unwrap();
    raw.append(&frame(2)).unwrap();
    let second = raw.append(&frame(3)).unwrap().durability_ack.unwrap();
    raw.append(&frame(4)).unwrap();

    let delta = read_durable_raw_delta(&raw_path, &first, &second).unwrap();
    assert_eq!(delta.len(), 2);
    assert_eq!(delta[0].frame.frame_index, 2);
    assert_eq!(delta[1].frame.frame_index, 3);
    assert_eq!(delta[1].record_sha256, second.last_record_sha256);
    assert!(read_durable_raw_delta(&raw_path, &second, &first).is_err());
}

#[test]
fn canonical_lineage_reconstructs_exact_cursor_and_next_delta() {
    let directory = tempdir().unwrap();
    let raw_path = directory.path().join("trade.bnraw");
    let mut raw = RawLogWriter::create(&raw_path, 1).unwrap();
    let mut terminal = None;
    for index in 0..4 {
        terminal = raw.append(&frame(index)).unwrap().durability_ack;
    }
    let terminal = terminal.unwrap();
    let records = lob_replay::read_raw_records(&raw_path).unwrap();
    let published = &records[1];
    let observation = CanonicalObservationV1 {
        symbol: "BTCUSDT".to_owned(),
        stream_kind: BoundaryStreamKind::Trade,
        stream: published.frame.stream.clone(),
        connection_epoch: published.frame.connection_epoch.clone(),
        frame_index: published.frame.frame_index,
        first_sequence: 1,
        final_sequence: 1,
        record_sha256: published.record_sha256.clone(),
        observation_sha256: "a".repeat(64),
    };

    let cursor = durable_cursor_at_observation(&raw_path, &terminal, &observation).unwrap();
    assert_eq!(cursor.durable_record_count, 2);
    assert_eq!(cursor.durable_through_offset, published.end_offset);
    let delta = read_durable_raw_delta(&raw_path, &cursor, &terminal).unwrap();
    assert_eq!(delta.len(), 2);
    assert_eq!(delta[0].frame.frame_index, 2);
    assert_eq!(delta[1].frame.frame_index, 3);
}
