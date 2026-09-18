use lob_replay::{
    CapturedFrame, DurableSink, RawLogWriter, RawSegmentGenesisV1, read_raw_log,
    read_raw_segment_records, recover_raw_log_prefix, scan_raw_log, scan_raw_segment,
    seal_raw_segment,
};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct SinkState {
    bytes: Vec<u8>,
    syncs: usize,
}

struct FaultSink {
    state: Arc<Mutex<SinkState>>,
    fail_write_after: Option<usize>,
    fail_sync_on: Option<usize>,
}

impl Write for FaultSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        if let Some(limit) = self.fail_write_after {
            if state.bytes.len() >= limit {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "injected partial write",
                ));
            }
            let writable = input.len().min(limit - state.bytes.len());
            state.bytes.extend_from_slice(&input[..writable]);
            return Ok(writable);
        }
        state.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DurableSink for FaultSink {
    fn sync_all(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let attempt = state.syncs + 1;
        if self.fail_sync_on == Some(attempt) {
            return Err(io::Error::other("injected sync failure"));
        }
        state.syncs = attempt;
        Ok(())
    }
}

fn frame(index: u64) -> CapturedFrame {
    CapturedFrame {
        venue: "binance-spot".to_owned(),
        environment: "production-public-market-data".to_owned(),
        endpoint: "wss://data-stream.binance.vision/ws/btcusdt@trade".to_owned(),
        stream: "btcusdt@trade".to_owned(),
        symbol: "BTCUSDT".to_owned(),
        connection_epoch: "epoch-a".to_owned(),
        frame_index: index,
        receive_wall_ns: 1_000 + index,
        receive_mono_ns: 2_000 + index,
        clock_quality: "UNSYNCHRONIZED".to_owned(),
        clock_source: "test".to_owned(),
        payload: format!("{{\"e\":\"trade\",\"s\":\"BTCUSDT\",\"t\":{index}}}").into_bytes(),
        spec_revision: "976cc580553890e92031b77306147c0ed1de5a46".to_owned(),
    }
}

#[test]
fn durability_ack_exists_only_after_group_sync() {
    let state = Arc::new(Mutex::new(SinkState::default()));
    let sink = FaultSink {
        state: Arc::clone(&state),
        fail_write_after: None,
        fail_sync_on: None,
    };
    let mut writer = RawLogWriter::from_sink(sink, 2).unwrap();
    let first = writer.append(&frame(0)).unwrap();
    assert!(first.durability_ack.is_none());
    assert!(writer.last_durability_ack().is_none());

    let second = writer.append(&frame(1)).unwrap();
    let ack = second.durability_ack.unwrap();
    assert_eq!(ack.durable_record_count, 2);
    assert_eq!(ack.last_record_sha256, second.record_sha256);
    assert_eq!(ack.durable_through_offset, second.end_offset);
    assert_eq!(ack.streams.len(), 1);
    assert_eq!(ack.streams[0].durable_through_frame_index, 1);
    let state = state.lock().unwrap();
    assert_eq!(state.syncs, 2, "magic sync plus one group commit");
    assert_eq!(state.bytes.len() as u64, ack.durable_through_offset);
}

#[test]
fn partial_write_poisoning_prevents_false_ack_or_continuation() {
    let state = Arc::new(Mutex::new(SinkState::default()));
    let sink = FaultSink {
        state: Arc::clone(&state),
        fail_write_after: Some(8 + 20),
        fail_sync_on: None,
    };
    let mut writer = RawLogWriter::from_sink(sink, 1).unwrap();
    let error = writer.append(&frame(0)).unwrap_err();
    assert!(error.contains("writer poisoned"));
    assert!(writer.is_poisoned());
    assert!(writer.last_durability_ack().is_none());
    assert!(writer.append(&frame(0)).unwrap_err().contains("poisoned"));
    assert_eq!(state.lock().unwrap().syncs, 1, "only the magic was synced");
}

#[test]
fn sync_failure_poisoning_never_emits_ack() {
    let state = Arc::new(Mutex::new(SinkState::default()));
    let sink = FaultSink {
        state,
        fail_write_after: None,
        fail_sync_on: Some(2),
    };
    let mut writer = RawLogWriter::from_sink(sink, 1).unwrap();
    let error = writer.append(&frame(0)).unwrap_err();
    assert!(error.contains("sync raw log; writer poisoned"));
    assert!(writer.is_poisoned());
    assert!(writer.last_durability_ack().is_none());
}

#[test]
fn crash_tail_recovery_preserves_source_and_copies_only_verified_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.bnraw");
    let recovered = directory.path().join("recovered.bnraw");
    {
        let mut writer = RawLogWriter::create(&source, 1).unwrap();
        writer.append(&frame(0)).unwrap();
        writer.append(&frame(1)).unwrap();
    }
    let original_size = source.metadata().unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&source)
        .unwrap()
        .set_len(original_size - 7)
        .unwrap();
    let damaged_size = source.metadata().unwrap().len();

    let scan = scan_raw_log(&source).unwrap();
    assert!(!scan.clean_eof);
    assert_eq!(scan.records, 1);
    assert_eq!(scan.reason.as_deref(), Some("partial record digest"));

    let recovery = recover_raw_log_prefix(&source, &recovered).unwrap();
    assert_eq!(source.metadata().unwrap().len(), damaged_size);
    assert_eq!(recovery.recovered_records, 1);
    assert!(recovery.excluded_tail_bytes > 0);
    let recovered_scan = scan_raw_log(&recovered).unwrap();
    assert!(recovered_scan.clean_eof);
    assert_eq!(read_raw_log(&recovered).unwrap().len(), 1);
    assert!(recover_raw_log_prefix(&recovered, &directory.path().join("again.bnraw")).is_err());
}

#[test]
fn successor_segment_continues_digest_epoch_stream_and_frame_index() {
    let directory = tempfile::tempdir().unwrap();
    let first_path = directory.path().join("trade-000000.bnraw");
    let second_path = directory.path().join("trade-000001.bnraw");

    let first_ack = {
        let mut first = RawLogWriter::create(&first_path, 2).unwrap();
        first.append(&frame(0)).unwrap();
        first.append(&frame(1)).unwrap().durability_ack.unwrap()
    };
    let genesis = RawSegmentGenesisV1 {
        schema: "RawSegmentGenesisV1".to_owned(),
        segment_index: 1,
        previous_segment_terminal_sha256: first_ack.last_record_sha256.clone(),
        connection_epoch: "epoch-a".to_owned(),
        stream: "btcusdt@trade".to_owned(),
        next_frame_index: 2,
    };
    let second_ack = {
        let mut second = RawLogWriter::create_segment(&second_path, 2, &genesis).unwrap();
        second.append(&frame(2)).unwrap();
        second.append(&frame(3)).unwrap().durability_ack.unwrap()
    };

    let ordinary_scan = scan_raw_log(&second_path).unwrap();
    assert!(!ordinary_scan.clean_eof);
    assert_eq!(
        ordinary_scan.reason.as_deref(),
        Some("record chain mismatch")
    );

    let scan = scan_raw_segment(&second_path, &genesis).unwrap();
    assert!(scan.clean_eof);
    assert_eq!(scan.records, 2);
    assert_eq!(scan.last_record_sha256, second_ack.last_record_sha256);
    assert_eq!(scan.streams[0].durable_through_frame_index, 3);
    let records = read_raw_segment_records(&second_path, &genesis).unwrap();
    assert_eq!(records[0].frame.frame_index, 2);
    assert_eq!(records[1].frame.frame_index, 3);
    let seal = seal_raw_segment(&genesis, "trade-000001.bnraw", &second_ack).unwrap();
    assert_eq!(seal.first_frame_index, 2);
    assert_eq!(seal.last_frame_index, 3);
    assert_eq!(
        seal.previous_segment_terminal_sha256,
        first_ack.last_record_sha256
    );
    assert_eq!(seal.terminal_record_sha256, second_ack.last_record_sha256);
}

#[test]
fn continuation_segment_fails_closed_on_wrong_lineage_or_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("trade-000001.bnraw");
    let genesis = RawSegmentGenesisV1 {
        schema: "RawSegmentGenesisV1".to_owned(),
        segment_index: 1,
        previous_segment_terminal_sha256:
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        connection_epoch: "epoch-a".to_owned(),
        stream: "btcusdt@trade".to_owned(),
        next_frame_index: 2,
    };
    let mut writer = RawLogWriter::create_segment(&path, 1, &genesis).unwrap();
    assert!(writer.append(&frame(0)).unwrap_err().contains("expected 2"));

    let mut wrong_identity = frame(2);
    wrong_identity.connection_epoch = "epoch-b".to_owned();
    assert!(
        writer
            .append(&wrong_identity)
            .unwrap_err()
            .contains("identity mismatch")
    );
    writer.append(&frame(2)).unwrap();
    drop(writer);

    let mut wrong_genesis = genesis.clone();
    wrong_genesis.previous_segment_terminal_sha256 = "f".repeat(64);
    let scan = scan_raw_segment(&path, &wrong_genesis).unwrap();
    assert!(!scan.clean_eof);
    assert_eq!(scan.reason.as_deref(), Some("record chain mismatch"));
}
