use lob_replay::DurableSink;
use lob_replay::boundary::{
    BoundaryDurabilityV1, BoundaryJournalWriter, BoundaryStreamKind, CanonicalObservationV1,
    HandoverBoundaryV1, RawPositionV1, scan_boundary_journal, select_canonical,
};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn position(epoch: &str, frame_index: u64, digest: &str) -> RawPositionV1 {
    RawPositionV1 {
        connection_epoch: epoch.to_owned(),
        stream: "btcusdt@depth@100ms".to_owned(),
        frame_index,
        record_sha256: digest.to_owned(),
    }
}

fn boundary() -> HandoverBoundaryV1 {
    HandoverBoundaryV1 {
        schema: "HandoverBoundaryV1".to_owned(),
        boundary_id: "btc-depth-a-b-100".to_owned(),
        environment: "production-public-market-data".to_owned(),
        symbol: "BTCUSDT".to_owned(),
        stream_kind: BoundaryStreamKind::Depth,
        stream: "btcusdt@depth@100ms".to_owned(),
        predecessor_epoch: "epoch-a".to_owned(),
        successor_epoch: "epoch-b".to_owned(),
        boundary_sequence: 100,
        boundary_sha256: DIGEST_A.to_owned(),
        predecessor_last_selected: position("epoch-a", 10, DIGEST_A),
        successor_boundary_observation: position("epoch-b", 7, DIGEST_A),
        successor_first_selected: position("epoch-b", 8, DIGEST_B),
        predecessor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: 10,
            durable_through_offset: 4_000,
            last_record_sha256: DIGEST_A.to_owned(),
        },
        successor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: 8,
            durable_through_offset: 3_000,
            last_record_sha256: DIGEST_B.to_owned(),
        },
        spec_revision: "976cc580553890e92031b77306147c0ed1de5a46".to_owned(),
        selector_version: "CanonicalMarketDataViewV1".to_owned(),
    }
}

fn observation(
    epoch: &str,
    frame_index: u64,
    first_sequence: u64,
    final_sequence: u64,
    record_digest: &str,
    observation_digest: &str,
) -> CanonicalObservationV1 {
    CanonicalObservationV1 {
        symbol: "BTCUSDT".to_owned(),
        stream_kind: BoundaryStreamKind::Depth,
        stream: "btcusdt@depth@100ms".to_owned(),
        connection_epoch: epoch.to_owned(),
        frame_index,
        first_sequence,
        final_sequence,
        record_sha256: record_digest.to_owned(),
        observation_sha256: observation_digest.to_owned(),
    }
}

fn trade_boundary() -> HandoverBoundaryV1 {
    let mut value = boundary();
    value.boundary_id = "btc-trade-a-b-200".to_owned();
    value.stream_kind = BoundaryStreamKind::Trade;
    value.stream = "btcusdt@trade".to_owned();
    value.boundary_sequence = 200;
    value.predecessor_last_selected = RawPositionV1 {
        connection_epoch: "epoch-a".to_owned(),
        stream: value.stream.clone(),
        frame_index: 10,
        record_sha256: DIGEST_A.to_owned(),
    };
    value.successor_boundary_observation = RawPositionV1 {
        connection_epoch: "epoch-b".to_owned(),
        stream: value.stream.clone(),
        frame_index: 7,
        record_sha256: DIGEST_A.to_owned(),
    };
    value.successor_first_selected = RawPositionV1 {
        connection_epoch: "epoch-b".to_owned(),
        stream: value.stream.clone(),
        frame_index: 8,
        record_sha256: DIGEST_B.to_owned(),
    };
    value
}

fn trade_observation(
    epoch: &str,
    frame_index: u64,
    trade_id: u64,
    record_digest: &str,
    event_digest: &str,
) -> CanonicalObservationV1 {
    CanonicalObservationV1 {
        symbol: "BTCUSDT".to_owned(),
        stream_kind: BoundaryStreamKind::Trade,
        stream: "btcusdt@trade".to_owned(),
        connection_epoch: epoch.to_owned(),
        frame_index,
        first_sequence: trade_id,
        final_sequence: trade_id,
        record_sha256: record_digest.to_owned(),
        observation_sha256: event_digest.to_owned(),
    }
}

#[test]
fn proposal_is_durable_but_not_canonical_until_commit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("boundary.bnhandover");
    let mut writer = BoundaryJournalWriter::create(&path).unwrap();
    let proposal = writer.propose(boundary()).unwrap();
    assert_eq!(proposal.durable_record_count, 1);
    let scan = scan_boundary_journal(&path).unwrap();
    assert!(scan.clean_eof);
    assert!(scan.proposal.is_some());
    assert!(scan.committed.is_none());

    let commit = writer.commit("btc-depth-a-b-100").unwrap();
    assert_eq!(commit.durable_record_count, 2);
    let scan = scan_boundary_journal(&path).unwrap();
    assert!(scan.clean_eof);
    assert_eq!(scan.committed.unwrap().boundary_sequence, 100);
}

#[test]
fn crash_during_commit_leaves_only_proposal_authoritative() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("boundary.bnhandover");
    {
        let mut writer = BoundaryJournalWriter::create(&path).unwrap();
        writer.propose(boundary()).unwrap();
        writer.commit("btc-depth-a-b-100").unwrap();
    }
    let size = path.metadata().unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(size - 7)
        .unwrap();
    let scan = scan_boundary_journal(&path).unwrap();
    assert!(!scan.clean_eof);
    assert_eq!(scan.records, 1);
    assert!(scan.proposal.is_some());
    assert!(scan.committed.is_none());
    assert_eq!(
        scan.reason.as_deref(),
        Some("partial boundary record digest")
    );
}

#[test]
fn boundary_beyond_durable_watermark_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("boundary.bnhandover");
    let mut invalid = boundary();
    invalid.successor_durability.durable_through_frame_index = 7;
    let mut writer = BoundaryJournalWriter::create(&path).unwrap();
    assert!(
        writer
            .propose(invalid)
            .unwrap_err()
            .contains("durable watermark")
    );
    let scan = scan_boundary_journal(&path).unwrap();
    assert_eq!(scan.records, 0);
}

#[derive(Default)]
struct SyncState {
    bytes: Vec<u8>,
    sync_attempts: usize,
}

struct SyncFailSink {
    state: Arc<Mutex<SyncState>>,
    fail_on: usize,
}

impl Write for SyncFailSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.state.lock().unwrap().bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl DurableSink for SyncFailSink {
    fn sync_all(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.sync_attempts += 1;
        if state.sync_attempts == self.fail_on {
            return Err(io::Error::other("injected boundary sync failure"));
        }
        Ok(())
    }
}

#[test]
fn failed_commit_sync_poisoning_never_creates_commit_ack() {
    let state = Arc::new(Mutex::new(SyncState::default()));
    let sink = SyncFailSink { state, fail_on: 3 };
    let mut writer = BoundaryJournalWriter::from_sink(sink).unwrap();
    writer.propose(boundary()).unwrap();
    let error = writer.commit("btc-depth-a-b-100").unwrap_err();
    assert!(error.contains("journal poisoned"));
    assert!(writer.is_poisoned());
    assert!(
        writer
            .commit("btc-depth-a-b-100")
            .unwrap_err()
            .contains("poisoned")
    );
}

#[test]
fn canonical_depth_splice_selects_each_side_once() {
    let predecessor = vec![
        observation("epoch-a", 8, 98, 98, DIGEST_B, DIGEST_B),
        observation("epoch-a", 9, 99, 99, DIGEST_B, DIGEST_B),
        observation("epoch-a", 10, 100, 100, DIGEST_A, DIGEST_A),
        observation("epoch-a", 11, 101, 101, DIGEST_B, DIGEST_B),
    ];
    let successor = vec![
        observation("epoch-b", 6, 99, 99, DIGEST_B, DIGEST_B),
        observation("epoch-b", 7, 100, 100, DIGEST_A, DIGEST_A),
        observation("epoch-b", 8, 101, 101, DIGEST_B, DIGEST_B),
        observation("epoch-b", 9, 102, 102, DIGEST_A, DIGEST_A),
    ];
    let selection = select_canonical(&boundary(), &predecessor, &successor).unwrap();
    assert_eq!(selection.selected.len(), 5);
    assert_eq!(selection.excluded_overlap_records, 3);
    assert_eq!(selection.excluded_duplicate_records, 0);
    assert_eq!(selection.first_sequence, 98);
    assert_eq!(selection.final_sequence, 102);
    assert_eq!(selection.selected[2].connection_epoch, "epoch-a");
    assert_eq!(selection.selected[3].connection_epoch, "epoch-b");
    assert_eq!(
        selection.selection_sha256,
        "61de54e63913d9d2317beb1434954807d6ba7311c6ee2f7fe72c588be6a3ec76"
    );
}

#[test]
fn canonical_depth_splice_rejects_gap_and_divergence() {
    let predecessor = vec![
        observation("epoch-a", 9, 99, 99, DIGEST_B, DIGEST_B),
        observation("epoch-a", 10, 100, 100, DIGEST_A, DIGEST_A),
    ];
    let mut successor = vec![
        observation("epoch-b", 7, 100, 100, DIGEST_A, DIGEST_A),
        observation("epoch-b", 8, 102, 102, DIGEST_B, DIGEST_B),
    ];
    assert!(
        select_canonical(&boundary(), &predecessor, &successor)
            .unwrap_err()
            .contains("bridge K+1")
    );
    successor[0].observation_sha256 = DIGEST_B.to_owned();
    successor[1].first_sequence = 101;
    assert!(
        select_canonical(&boundary(), &predecessor, &successor)
            .unwrap_err()
            .contains("convergence")
    );
}

#[test]
fn canonical_trade_splice_uses_t_then_t_plus_one_without_duplicates() {
    let predecessor = vec![
        trade_observation("epoch-a", 9, 199, DIGEST_B, DIGEST_B),
        trade_observation("epoch-a", 10, 200, DIGEST_A, DIGEST_A),
        trade_observation("epoch-a", 11, 201, DIGEST_B, DIGEST_B),
    ];
    let successor = vec![
        trade_observation("epoch-b", 6, 199, DIGEST_B, DIGEST_B),
        trade_observation("epoch-b", 7, 200, DIGEST_A, DIGEST_A),
        trade_observation("epoch-b", 8, 201, DIGEST_B, DIGEST_B),
        trade_observation("epoch-b", 9, 202, DIGEST_A, DIGEST_A),
    ];
    let selection = select_canonical(&trade_boundary(), &predecessor, &successor).unwrap();
    assert_eq!(selection.selected.len(), 4);
    assert_eq!(selection.excluded_overlap_records, 3);
    assert_eq!(selection.first_sequence, 199);
    assert_eq!(selection.final_sequence, 202);
    assert_eq!(selection.selected[1].connection_epoch, "epoch-a");
    assert_eq!(selection.selected[2].connection_epoch, "epoch-b");
}
