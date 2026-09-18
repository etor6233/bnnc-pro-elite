use lob_replay::segment_chain::{
    RawSegmentManifestWriter, recover_segment_manifest_prefix, root_segment_genesis,
    scan_segment_manifest, successor_segment_genesis, verify_and_seal_raw_segment,
    verify_segment_manifest_files,
};
use lob_replay::{CapturedFrame, DurabilityAckV1, DurableSink, RawLogWriter, RawSegmentGenesisV1};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

const EPOCH: &str = "epoch-segment-chain";
const STREAM: &str = "btcusdt@trade";

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
                    "injected manifest partial write",
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
            return Err(io::Error::other("injected manifest sync failure"));
        }
        state.syncs = attempt;
        Ok(())
    }
}

fn frame(genesis: &RawSegmentGenesisV1, index: u64) -> CapturedFrame {
    CapturedFrame {
        venue: "binance-spot".to_owned(),
        environment: "production-public-market-data".to_owned(),
        endpoint: "wss://data-stream.binance.vision/ws/btcusdt@trade".to_owned(),
        stream: genesis.stream.clone(),
        symbol: "BTCUSDT".to_owned(),
        connection_epoch: genesis.connection_epoch.clone(),
        frame_index: index,
        receive_wall_ns: 1_000 + index,
        receive_mono_ns: 2_000 + index,
        clock_quality: "UNSYNCHRONIZED".to_owned(),
        clock_source: "test".to_owned(),
        payload: format!("{{\"e\":\"trade\",\"s\":\"BTCUSDT\",\"t\":{index}}}").into_bytes(),
        spec_revision: "976cc580553890e92031b77306147c0ed1de5a46".to_owned(),
    }
}

fn create_verified(
    directory: &Path,
    raw_file: &str,
    genesis: &RawSegmentGenesisV1,
    records: u64,
) -> lob_replay::segment_chain::VerifiedRawSegmentV1 {
    let path = directory.join(raw_file);
    let mut writer = RawLogWriter::create_segment(&path, 64, genesis).unwrap();
    for distance in 0..records {
        writer
            .append(&frame(genesis, genesis.next_frame_index + distance))
            .unwrap();
    }
    let ack = writer.sync().unwrap();
    drop(writer);
    verify_and_seal_raw_segment(&path, raw_file, genesis, &ack).unwrap()
}

#[test]
fn root_successors_manifest_and_files_verify_as_one_exact_chain() {
    let directory = tempfile::tempdir().unwrap();
    let root_genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let root = create_verified(directory.path(), "trade-000000.bnraw", &root_genesis, 2);
    let next_genesis = successor_segment_genesis(root.seal()).unwrap();
    let successor = create_verified(directory.path(), "trade-000001.bnraw", &next_genesis, 3);
    let manifest_path = directory.path().join("trade.bnsegments");
    let mut manifest = RawSegmentManifestWriter::create(&manifest_path).unwrap();
    let first_ack = manifest.append_verified(&root).unwrap();
    let second_ack = manifest.append_verified(&successor).unwrap();
    assert_eq!(first_ack.segment_index, 0);
    assert_eq!(second_ack.segment_index, 1);
    assert_ne!(first_ack.record_sha256, second_ack.record_sha256);
    drop(manifest);

    let scan = scan_segment_manifest(&manifest_path).unwrap();
    assert!(scan.clean_eof);
    assert_eq!(scan.records, 2);
    assert_eq!(scan.entries[0].seal.first_frame_index, 0);
    assert_eq!(scan.entries[1].seal.first_frame_index, 2);
    assert_eq!(
        scan.entries[1].seal.previous_segment_terminal_sha256,
        scan.entries[0].seal.terminal_record_sha256
    );
    let verified = verify_segment_manifest_files(&scan, directory.path()).unwrap();
    assert_eq!(verified.len(), 2);
    assert_eq!(verified[1].seal().last_frame_index, 4);
}

#[test]
fn fabricated_ack_cannot_create_a_verified_seal() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let path = directory.path().join("trade-000000.bnraw");
    let mut writer = RawLogWriter::create_segment(&path, 64, &genesis).unwrap();
    writer.append(&frame(&genesis, 0)).unwrap();
    let real_ack = writer.sync().unwrap();
    drop(writer);

    let mut fabricated: DurabilityAckV1 = real_ack.clone();
    fabricated.last_record_sha256 = "f".repeat(64);
    assert!(
        verify_and_seal_raw_segment(&path, "trade-000000.bnraw", &genesis, &fabricated)
            .unwrap_err()
            .contains("does not match")
    );

    let mut fabricated_offset = real_ack;
    fabricated_offset.durable_through_offset -= 1;
    assert!(
        verify_and_seal_raw_segment(&path, "trade-000000.bnraw", &genesis, &fabricated_offset)
            .is_err()
    );
}

#[test]
fn manifest_rejects_wrong_digest_index_identity_omission_and_reorder() {
    let directory = tempfile::tempdir().unwrap();
    let root_genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let root = create_verified(directory.path(), "root.bnraw", &root_genesis, 2);
    let manifest_path = directory.path().join("trade.bnsegments");
    let mut manifest = RawSegmentManifestWriter::create(&manifest_path).unwrap();
    manifest.append_verified(&root).unwrap();

    let wrong_digest_genesis = RawSegmentGenesisV1 {
        schema: "RawSegmentGenesisV1".to_owned(),
        segment_index: 1,
        previous_segment_terminal_sha256: "f".repeat(64),
        connection_epoch: EPOCH.to_owned(),
        stream: STREAM.to_owned(),
        next_frame_index: 2,
    };
    let wrong_digest = create_verified(
        directory.path(),
        "wrong-digest.bnraw",
        &wrong_digest_genesis,
        1,
    );
    assert!(manifest.append_verified(&wrong_digest).is_err());

    let omitted_index_genesis = RawSegmentGenesisV1 {
        schema: "RawSegmentGenesisV1".to_owned(),
        segment_index: 2,
        previous_segment_terminal_sha256: root.seal().terminal_record_sha256.clone(),
        connection_epoch: EPOCH.to_owned(),
        stream: STREAM.to_owned(),
        next_frame_index: 2,
    };
    let omitted = create_verified(
        directory.path(),
        "omitted-index.bnraw",
        &omitted_index_genesis,
        1,
    );
    assert!(manifest.append_verified(&omitted).is_err());

    let wrong_identity_genesis = RawSegmentGenesisV1 {
        schema: "RawSegmentGenesisV1".to_owned(),
        segment_index: 1,
        previous_segment_terminal_sha256: root.seal().terminal_record_sha256.clone(),
        connection_epoch: "epoch-other".to_owned(),
        stream: STREAM.to_owned(),
        next_frame_index: 2,
    };
    let wrong_identity = create_verified(
        directory.path(),
        "wrong-identity.bnraw",
        &wrong_identity_genesis,
        1,
    );
    assert!(manifest.append_verified(&wrong_identity).is_err());

    let correct_genesis = successor_segment_genesis(root.seal()).unwrap();
    let correct = create_verified(directory.path(), "successor.bnraw", &correct_genesis, 1);
    manifest.append_verified(&correct).unwrap();
    assert!(
        manifest.append_verified(&root).is_err(),
        "root replay/reorder"
    );
    assert!(!manifest.is_poisoned());
}

#[test]
fn partial_manifest_tail_is_never_authority_and_recovery_preserves_source() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let root = create_verified(directory.path(), "root.bnraw", &genesis, 1);
    let source = directory.path().join("source.bnsegments");
    {
        let mut manifest = RawSegmentManifestWriter::create(&source).unwrap();
        manifest.append_verified(&root).unwrap();
    }
    let clean_size = source.metadata().unwrap().len();
    OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap()
        .write_all(&[0, 0])
        .unwrap();
    let damaged_size = source.metadata().unwrap().len();
    let scan = scan_segment_manifest(&source).unwrap();
    assert!(!scan.clean_eof);
    assert_eq!(scan.records, 1);
    assert_eq!(scan.last_good_offset, clean_size);
    assert_eq!(
        scan.reason.as_deref(),
        Some("partial segment manifest length prefix")
    );

    let recovered = directory.path().join("recovered.bnsegments");
    let report = recover_segment_manifest_prefix(&source, &recovered).unwrap();
    assert_eq!(source.metadata().unwrap().len(), damaged_size);
    assert_eq!(report.copied_valid_prefix_bytes, clean_size);
    assert_eq!(report.excluded_tail_bytes, 2);
    let recovered_scan = scan_segment_manifest(&recovered).unwrap();
    assert!(recovered_scan.clean_eof);
    assert_eq!(recovered_scan.records, 1);
    assert_eq!(
        verify_segment_manifest_files(&recovered_scan, directory.path())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn manifest_record_digest_corruption_is_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let root = create_verified(directory.path(), "root.bnraw", &genesis, 1);
    let path = directory.path().join("trade.bnsegments");
    {
        let mut manifest = RawSegmentManifestWriter::create(&path).unwrap();
        manifest.append_verified(&root).unwrap();
    }
    let length = path.metadata().unwrap().len();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(length - 1)).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
    let scan = scan_segment_manifest(&path).unwrap();
    assert!(!scan.clean_eof);
    assert_eq!(scan.records, 0);
    assert_eq!(
        scan.reason.as_deref(),
        Some("segment manifest record digest mismatch")
    );
}

#[test]
fn manifest_partial_write_or_sync_failure_never_returns_commit_ack() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let root = create_verified(directory.path(), "root.bnraw", &genesis, 1);

    let partial_state = Arc::new(Mutex::new(SinkState::default()));
    let partial_sink = FaultSink {
        state: Arc::clone(&partial_state),
        fail_write_after: Some(8 + 12),
        fail_sync_on: None,
    };
    let mut partial = RawSegmentManifestWriter::from_sink(partial_sink).unwrap();
    let error = partial.append_verified(&root).unwrap_err();
    assert!(error.contains("writer poisoned"));
    assert!(partial.is_poisoned());
    assert!(
        partial
            .append_verified(&root)
            .unwrap_err()
            .contains("poisoned")
    );
    assert_eq!(partial_state.lock().unwrap().syncs, 1);

    let sync_state = Arc::new(Mutex::new(SinkState::default()));
    let sync_sink = FaultSink {
        state: sync_state,
        fail_write_after: None,
        fail_sync_on: Some(2),
    };
    let mut failed_sync = RawSegmentManifestWriter::from_sink(sync_sink).unwrap();
    let error = failed_sync.append_verified(&root).unwrap_err();
    assert!(error.contains("writer poisoned"));
    assert!(failed_sync.is_poisoned());
}
