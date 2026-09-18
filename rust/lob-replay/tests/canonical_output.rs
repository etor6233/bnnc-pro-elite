use lob_replay::boundary::{BoundaryStreamKind, CanonicalObservationV1};
use lob_replay::canonical_output::{
    CanonicalOutputOwnerV1, CanonicalOutputWriter, recover_canonical_output_prefix,
    scan_canonical_output,
};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::tempdir;

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn observation(epoch: &str, first: u64, final_sequence: u64, frame: u64) -> CanonicalObservationV1 {
    CanonicalObservationV1 {
        symbol: "BTCUSDT".to_owned(),
        stream_kind: BoundaryStreamKind::Depth,
        stream: "btcusdt@depth@100ms".to_owned(),
        connection_epoch: epoch.to_owned(),
        frame_index: frame,
        first_sequence: first,
        final_sequence,
        record_sha256: HASH.to_owned(),
        observation_sha256: HASH.to_owned(),
    }
}

fn initial() -> CanonicalOutputOwnerV1 {
    CanonicalOutputOwnerV1 {
        generation_id: "generation-a".to_owned(),
        connection_epoch: "depth-a".to_owned(),
        fencing_token: 1,
        last_sequence: 99,
    }
}

#[test]
fn exact_a_boundary_owner_change_and_b_continuation_recover() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("depth.bnpub");
    let mut writer =
        CanonicalOutputWriter::create(&path, "BTCUSDT", BoundaryStreamKind::Depth, initial())
            .unwrap();
    writer
        .publish(observation("depth-a", 100, 102, 10))
        .unwrap();
    writer
        .change_owner("generation-b", "depth-b", 2, 102, HASH)
        .unwrap();
    writer.publish(observation("depth-b", 103, 105, 8)).unwrap();
    drop(writer);

    let scan = scan_canonical_output(&path).unwrap();
    assert!(scan.clean_eof);
    assert_eq!(scan.records, 4);
    assert_eq!(scan.observations, 2);
    assert_eq!(scan.ownership_changes, 1);
    let last = scan.last_observation.as_ref().unwrap();
    assert_eq!(last.connection_epoch, "depth-b");
    assert_eq!(last.frame_index, 8);
    assert_eq!(last.final_sequence, 105);
    let owner = scan.owner.unwrap();
    assert_eq!(owner.generation_id, "generation-b");
    assert_eq!(owner.fencing_token, 2);
    assert_eq!(owner.last_sequence, 105);
}

#[test]
fn stale_a_gap_and_duplicate_are_rejected_without_advancing() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("depth.bnpub");
    let mut writer =
        CanonicalOutputWriter::create(&path, "BTCUSDT", BoundaryStreamKind::Depth, initial())
            .unwrap();
    writer.publish(observation("depth-a", 100, 100, 1)).unwrap();
    writer
        .change_owner("generation-b", "depth-b", 2, 100, HASH)
        .unwrap();
    assert!(writer.publish(observation("depth-a", 101, 101, 2)).is_err());
    assert!(writer.publish(observation("depth-b", 102, 102, 2)).is_err());
    writer.publish(observation("depth-b", 101, 101, 2)).unwrap();
    assert!(writer.publish(observation("depth-b", 101, 101, 2)).is_err());
    assert_eq!(writer.owner().last_sequence, 101);
}

#[test]
fn partial_tail_recovers_only_complete_canonical_prefix() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("depth.bnpub");
    let mut writer =
        CanonicalOutputWriter::create(&path, "BTCUSDT", BoundaryStreamKind::Depth, initial())
            .unwrap();
    writer.publish(observation("depth-a", 100, 100, 1)).unwrap();
    drop(writer);
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&[0, 0])
        .unwrap();

    let scan = scan_canonical_output(&path).unwrap();
    assert!(!scan.clean_eof);
    assert_eq!(scan.records, 2);
    assert_eq!(scan.owner.unwrap().last_sequence, 100);
}

#[test]
fn depth_and_trade_outputs_cannot_be_mixed() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("trade.bnpub");
    let mut owner = initial();
    owner.connection_epoch = "trade-a".to_owned();
    let mut writer =
        CanonicalOutputWriter::create(&path, "BTCUSDT", BoundaryStreamKind::Trade, owner).unwrap();
    assert!(writer.publish(observation("depth-a", 100, 100, 1)).is_err());
}

#[test]
fn scanner_reads_length_prefixes_across_internal_buffer_boundaries() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("trade.bnpub");
    let owner = CanonicalOutputOwnerV1 {
        generation_id: "generation-a".to_owned(),
        connection_epoch: "trade-a".to_owned(),
        fencing_token: 1,
        last_sequence: 99,
    };
    let mut writer =
        CanonicalOutputWriter::create(&path, "BTCUSDT", BoundaryStreamKind::Trade, owner).unwrap();
    for sequence in 100..600 {
        let mut item = observation("trade-a", sequence, sequence, sequence);
        item.stream_kind = BoundaryStreamKind::Trade;
        item.stream = "btcusdt@trade".to_owned();
        writer.publish(item).unwrap();
    }
    drop(writer);

    let scan = scan_canonical_output(&path).unwrap();
    assert!(scan.clean_eof, "{:?}", scan.reason);
    assert_eq!(scan.records, 501);
    assert_eq!(scan.observations, 500);
    assert_eq!(scan.owner.unwrap().last_sequence, 599);
}

#[derive(Default)]
struct FaultState {
    bytes: Vec<u8>,
    sync_attempts: usize,
    fail_write_after: Option<usize>,
    fail_sync_on: Option<usize>,
    sync_error_kind: Option<io::ErrorKind>,
    sync_delay: Duration,
}

struct FaultSink(Arc<Mutex<FaultState>>);

impl Write for FaultSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let mut state = self.0.lock().unwrap();
        if let Some(limit) = state.fail_write_after {
            if state.bytes.len() >= limit {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "injected short write",
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

impl lob_replay::DurableSink for FaultSink {
    fn sync_all(&mut self) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        state.sync_attempts += 1;
        let delay = state.sync_delay;
        if state.fail_sync_on == Some(state.sync_attempts) {
            let kind = state.sync_error_kind.unwrap_or(io::ErrorKind::Other);
            return Err(io::Error::new(
                kind,
                "injected canonical output sync failure",
            ));
        }
        drop(state);
        std::thread::sleep(delay);
        Ok(())
    }
}

#[test]
fn partial_write_poisoning_prevents_false_publication_ack() {
    let state = Arc::new(Mutex::new(FaultState::default()));
    let sink = FaultSink(Arc::clone(&state));
    let mut writer =
        CanonicalOutputWriter::from_sink(sink, "BTCUSDT", BoundaryStreamKind::Depth, initial())
            .unwrap();
    {
        let mut locked = state.lock().unwrap();
        locked.fail_write_after = Some(locked.bytes.len() + 20);
    }
    assert!(writer.publish(observation("depth-a", 100, 100, 1)).is_err());
    assert!(writer.is_poisoned());
    assert_eq!(writer.owner().last_sequence, 99);
    assert!(writer.publish(observation("depth-a", 100, 100, 1)).is_err());
}

#[test]
fn sync_failure_poisoning_does_not_advance_owner() {
    let state = Arc::new(Mutex::new(FaultState::default()));
    let sink = FaultSink(Arc::clone(&state));
    let mut writer =
        CanonicalOutputWriter::from_sink(sink, "BTCUSDT", BoundaryStreamKind::Depth, initial())
            .unwrap();
    {
        let mut locked = state.lock().unwrap();
        locked.fail_sync_on = Some(locked.sync_attempts + 1);
    }
    assert!(writer.publish(observation("depth-a", 100, 100, 1)).is_err());
    assert!(writer.is_poisoned());
    assert_eq!(writer.owner().last_sequence, 99);
    assert!(writer.publish(observation("depth-a", 100, 100, 1)).is_err());
}

#[test]
fn storage_full_is_fail_closed_and_never_returns_a_false_ack() {
    let state = Arc::new(Mutex::new(FaultState::default()));
    let sink = FaultSink(Arc::clone(&state));
    let mut writer =
        CanonicalOutputWriter::from_sink(sink, "BTCUSDT", BoundaryStreamKind::Depth, initial())
            .unwrap();
    {
        let mut locked = state.lock().unwrap();
        locked.fail_sync_on = Some(locked.sync_attempts + 1);
        locked.sync_error_kind = Some(io::ErrorKind::StorageFull);
    }
    let error = writer
        .publish(observation("depth-a", 100, 100, 1))
        .unwrap_err();
    assert!(error.contains("writer poisoned"));
    assert!(writer.is_poisoned());
    assert_eq!(writer.owner().last_sequence, 99);
}

#[test]
fn slow_sync_applies_backpressure_before_publication_ack() {
    let state = Arc::new(Mutex::new(FaultState::default()));
    let sink = FaultSink(Arc::clone(&state));
    let mut writer =
        CanonicalOutputWriter::from_sink(sink, "BTCUSDT", BoundaryStreamKind::Depth, initial())
            .unwrap();
    state.lock().unwrap().sync_delay = Duration::from_millis(25);
    let started = Instant::now();
    let ack = writer.publish(observation("depth-a", 100, 100, 1)).unwrap();
    assert!(started.elapsed() >= Duration::from_millis(25));
    assert_eq!(ack.owner.last_sequence, 100);
    assert_eq!(writer.owner().last_sequence, 100);
}

#[test]
fn clean_restart_continues_index_hash_owner_and_sequence() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("depth.bnpub");
    {
        let mut writer =
            CanonicalOutputWriter::create(&path, "BTCUSDT", BoundaryStreamKind::Depth, initial())
                .unwrap();
        writer.publish(observation("depth-a", 100, 102, 1)).unwrap();
        writer
            .change_owner("generation-b", "depth-b", 2, 102, HASH)
            .unwrap();
        writer.publish(observation("depth-b", 103, 105, 2)).unwrap();
    }
    let before = scan_canonical_output(&path).unwrap();
    let mut resumed = CanonicalOutputWriter::resume(&path).unwrap();
    assert_eq!(resumed.owner(), before.owner.as_ref().unwrap());
    assert!(
        resumed
            .publish(observation("depth-a", 106, 106, 3))
            .is_err()
    );
    resumed
        .publish(observation("depth-b", 106, 108, 3))
        .unwrap();
    drop(resumed);

    let after = scan_canonical_output(&path).unwrap();
    assert!(after.clean_eof);
    assert_eq!(after.records, before.records + 1);
    assert_eq!(after.owner.unwrap().last_sequence, 108);
}

#[test]
fn unclean_source_is_preserved_and_resumes_from_new_verified_prefix() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("damaged.bnpub");
    let recovered = directory.path().join("recovered.bnpub");
    {
        let mut writer =
            CanonicalOutputWriter::create(&source, "BTCUSDT", BoundaryStreamKind::Depth, initial())
                .unwrap();
        writer.publish(observation("depth-a", 100, 102, 1)).unwrap();
    }
    let clean_size = source.metadata().unwrap().len();
    OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap()
        .write_all(&[0, 0])
        .unwrap();
    let damaged_size = source.metadata().unwrap().len();
    assert!(CanonicalOutputWriter::resume(&source).is_err());

    let prefix = recover_canonical_output_prefix(&source, &recovered).unwrap();
    assert!(prefix.clean_eof);
    assert_eq!(recovered.metadata().unwrap().len(), clean_size);
    assert_eq!(source.metadata().unwrap().len(), damaged_size);
    let mut writer = CanonicalOutputWriter::resume(&recovered).unwrap();
    writer.publish(observation("depth-a", 103, 105, 2)).unwrap();
    drop(writer);
    let scan = scan_canonical_output(&recovered).unwrap();
    assert!(scan.clean_eof);
    assert_eq!(scan.owner.unwrap().last_sequence, 105);
}

#[test]
fn process_restart_child_entry() {
    let Ok(mode) = std::env::var("BNPUB_CHILD_MODE") else {
        return;
    };
    let path = std::path::PathBuf::from(std::env::var("BNPUB_CHILD_PATH").unwrap());
    match mode.as_str() {
        "initialize" => {
            let mut writer = CanonicalOutputWriter::create(
                &path,
                "BTCUSDT",
                BoundaryStreamKind::Depth,
                initial(),
            )
            .unwrap();
            writer.publish(observation("depth-a", 100, 102, 1)).unwrap();
            writer
                .change_owner("generation-b", "depth-b", 2, 102, HASH)
                .unwrap();
            writer.publish(observation("depth-b", 103, 105, 2)).unwrap();
        }
        "continue" => {
            let mut writer = CanonicalOutputWriter::resume(&path).unwrap();
            writer.publish(observation("depth-b", 106, 108, 3)).unwrap();
        }
        "crash-loop" => {
            let mut writer = CanonicalOutputWriter::create(
                &path,
                "BTCUSDT",
                BoundaryStreamKind::Depth,
                initial(),
            )
            .unwrap();
            writer.publish(observation("depth-a", 100, 102, 1)).unwrap();
            writer
                .change_owner("generation-b", "depth-b", 2, 102, HASH)
                .unwrap();
            for sequence in 103_u64..=u64::MAX {
                writer
                    .publish(observation("depth-b", sequence, sequence, sequence))
                    .unwrap();
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        _ => panic!("unknown child mode"),
    }
}

#[test]
fn separate_process_restart_continues_the_same_durable_chain() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("process-restart.bnpub");
    let executable = std::env::current_exe().unwrap();
    for mode in ["initialize", "continue"] {
        let status = Command::new(&executable)
            .args(["--exact", "process_restart_child_entry", "--nocapture"])
            .env("BNPUB_CHILD_MODE", mode)
            .env("BNPUB_CHILD_PATH", &path)
            .status()
            .unwrap();
        assert!(status.success(), "child phase {mode} failed");
    }
    let scan = scan_canonical_output(&path).unwrap();
    assert!(scan.clean_eof);
    assert_eq!(scan.records, 5);
    assert_eq!(scan.observations, 3);
    assert_eq!(scan.ownership_changes, 1);
    let owner = scan.owner.unwrap();
    assert_eq!(owner.generation_id, "generation-b");
    assert_eq!(owner.fencing_token, 2);
    assert_eq!(owner.last_sequence, 108);
}

#[test]
fn abrupt_publisher_kill_recovers_prefix_and_continues_next_sequence() {
    let directory = tempdir().unwrap();
    let source = directory.path().join("killed.bnpub");
    let recovered = directory.path().join("killed-recovered.bnpub");
    let executable = std::env::current_exe().unwrap();
    let mut child = Command::new(&executable)
        .args(["--exact", "process_restart_child_entry", "--nocapture"])
        .env("BNPUB_CHILD_MODE", "crash-loop")
        .env("BNPUB_CHILD_PATH", &source)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if source
            .metadata()
            .is_ok_and(|metadata| metadata.len() > 4_096)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "publisher did not create durable records"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    child.kill().unwrap();
    child.wait().unwrap();

    let killed_scan = scan_canonical_output(&source).unwrap();
    assert!(killed_scan.records >= 4);
    let resume_path = if killed_scan.clean_eof {
        source
    } else {
        let prefix = recover_canonical_output_prefix(&source, &recovered).unwrap();
        assert!(prefix.clean_eof);
        recovered
    };
    let before = scan_canonical_output(&resume_path).unwrap();
    let owner = before.owner.as_ref().unwrap();
    assert_eq!(owner.generation_id, "generation-b");
    let next = owner.last_sequence + 1;
    let mut writer = CanonicalOutputWriter::resume(&resume_path).unwrap();
    writer
        .publish(observation("depth-b", next, next, next))
        .unwrap();
    drop(writer);

    let after = scan_canonical_output(&resume_path).unwrap();
    assert!(after.clean_eof, "{:?}", after.reason);
    assert_eq!(after.records, before.records + 1);
    assert_eq!(after.ownership_changes, 1);
    assert_eq!(after.owner.unwrap().last_sequence, next);
    assert_eq!(after.last_observation.unwrap().final_sequence, next);
}
