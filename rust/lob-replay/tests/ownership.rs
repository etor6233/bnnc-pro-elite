use lob_replay::DurableSink;
use lob_replay::boundary::{
    BoundaryDurabilityV1, BoundaryJournalWriter, BoundaryStreamKind, HandoverBoundaryV1,
    RawPositionV1,
};
use lob_replay::ownership::{
    CanonicalSourcePointer, LivePublicationState, OwnershipLedgerWriter, SourcePointerSnapshotV1,
    derive_ownership_activation, load_committed_boundary_proof, scan_ownership_ledger,
};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn initial() -> SourcePointerSnapshotV1 {
    SourcePointerSnapshotV1 {
        schema: "SourcePointerSnapshotV1".to_owned(),
        symbol: "BTCUSDT".to_owned(),
        generation_id: "generation-a".to_owned(),
        depth_epoch: "depth-a".to_owned(),
        trade_epoch: "trade-a".to_owned(),
        fencing_token: 1,
        depth_last_sequence: 100,
        trade_last_sequence: 200,
    }
}

fn boundary(kind: BoundaryStreamKind) -> HandoverBoundaryV1 {
    let (id, stream, predecessor, successor, sequence) = match kind {
        BoundaryStreamKind::Depth => (
            "depth-a-b",
            "btcusdt@depth@100ms",
            "depth-a",
            "depth-b",
            100,
        ),
        BoundaryStreamKind::Trade => ("trade-a-b", "btcusdt@trade", "trade-a", "trade-b", 200),
    };
    HandoverBoundaryV1 {
        schema: "HandoverBoundaryV1".to_owned(),
        boundary_id: id.to_owned(),
        environment: "production-public-market-data".to_owned(),
        symbol: "BTCUSDT".to_owned(),
        stream_kind: kind,
        stream: stream.to_owned(),
        predecessor_epoch: predecessor.to_owned(),
        successor_epoch: successor.to_owned(),
        boundary_sequence: sequence,
        boundary_sha256: A.to_owned(),
        predecessor_last_selected: RawPositionV1 {
            connection_epoch: predecessor.to_owned(),
            stream: stream.to_owned(),
            frame_index: 10,
            record_sha256: A.to_owned(),
        },
        successor_boundary_observation: RawPositionV1 {
            connection_epoch: successor.to_owned(),
            stream: stream.to_owned(),
            frame_index: 7,
            record_sha256: B.to_owned(),
        },
        successor_first_selected: RawPositionV1 {
            connection_epoch: successor.to_owned(),
            stream: stream.to_owned(),
            frame_index: 8,
            record_sha256: C.to_owned(),
        },
        predecessor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: 10,
            durable_through_offset: 1000,
            last_record_sha256: A.to_owned(),
        },
        successor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: 8,
            durable_through_offset: 900,
            last_record_sha256: B.to_owned(),
        },
        spec_revision: "spec".to_owned(),
        selector_version: "selector".to_owned(),
    }
}

fn committed_proofs(
    directory: &std::path::Path,
) -> (
    lob_replay::ownership::CommittedBoundaryProofV1,
    lob_replay::ownership::CommittedBoundaryProofV1,
) {
    let depth_path = directory.join("depth.bnhandover");
    let trade_path = directory.join("trade.bnhandover");
    for (path, value) in [
        (&depth_path, boundary(BoundaryStreamKind::Depth)),
        (&trade_path, boundary(BoundaryStreamKind::Trade)),
    ] {
        let mut writer = BoundaryJournalWriter::create(path).unwrap();
        let id = value.boundary_id.clone();
        writer.propose(value).unwrap();
        writer.commit(&id).unwrap();
    }
    (
        load_committed_boundary_proof(&depth_path).unwrap(),
        load_committed_boundary_proof(&trade_path).unwrap(),
    )
}

#[test]
fn prepared_alone_recovers_predecessor_and_activated_recovers_successor() {
    let directory = tempfile::tempdir().unwrap();
    let (depth, trade) = committed_proofs(directory.path());
    let activation =
        derive_ownership_activation("activation-a-b", "generation-b", &initial(), &depth, &trade)
            .unwrap();
    let path = directory.path().join("ownership.bnledger");
    let mut writer = OwnershipLedgerWriter::create(&path, initial()).unwrap();
    writer.prepare(activation.clone()).unwrap();
    let prepared = scan_ownership_ledger(&path).unwrap();
    assert!(prepared.clean_eof);
    assert_eq!(prepared.records, 2);
    assert_eq!(
        prepared.active_owner.as_ref().unwrap().generation_id,
        "generation-a"
    );
    assert_eq!(prepared.pending_activation.as_ref(), Some(&activation));
    let pointer = CanonicalSourcePointer::recover(&prepared, None).unwrap();
    assert_eq!(pointer.owner.generation_id, "generation-a");

    writer.activate("activation-a-b").unwrap();
    let activated = scan_ownership_ledger(&path).unwrap();
    assert!(activated.clean_eof);
    assert_eq!(activated.records, 3);
    assert!(activated.pending_activation.is_none());
    let pointer = CanonicalSourcePointer::recover(&activated, Some((&depth, &trade))).unwrap();
    assert_eq!(pointer.owner.generation_id, "generation-b");
    assert_eq!(pointer.owner.fencing_token, 2);
    assert_eq!(pointer.owner.depth_epoch, "depth-b");
    assert_eq!(pointer.owner.trade_epoch, "trade-b");
    let mut wrong_depth = depth.clone();
    wrong_depth.commit_record_sha256 = C.to_owned();
    assert!(
        CanonicalSourcePointer::recover(&activated, Some((&wrong_depth, &trade)))
            .unwrap_err()
            .contains("boundary proofs")
    );
}

#[test]
fn stale_writer_is_fenced_and_successor_must_start_at_k_t_plus_one() {
    let directory = tempfile::tempdir().unwrap();
    let (depth, trade) = committed_proofs(directory.path());
    let activation =
        derive_ownership_activation("activation-a-b", "generation-b", &initial(), &depth, &trade)
            .unwrap();
    let path = directory.path().join("ownership.bnledger");
    let mut writer = OwnershipLedgerWriter::create(&path, initial()).unwrap();
    writer.prepare(activation).unwrap();
    writer.activate("activation-a-b").unwrap();
    let scan = scan_ownership_ledger(&path).unwrap();
    let mut pointer = CanonicalSourcePointer::recover(&scan, Some((&depth, &trade))).unwrap();
    assert!(
        pointer
            .accept_observation(BoundaryStreamKind::Depth, "depth-a", 1, 101, 101)
            .unwrap_err()
            .contains("fence")
    );
    assert_eq!(pointer.fenced_rejections, 1);
    pointer
        .accept_observation(BoundaryStreamKind::Depth, "depth-b", 2, 101, 103)
        .unwrap();
    pointer
        .accept_observation(BoundaryStreamKind::Trade, "trade-b", 2, 201, 201)
        .unwrap();
    assert_eq!(pointer.owner.depth_last_sequence, 103);
    assert_eq!(pointer.owner.trade_last_sequence, 201);
}

#[test]
fn active_successor_gap_never_rolls_back_to_predecessor() {
    let directory = tempfile::tempdir().unwrap();
    let (depth, trade) = committed_proofs(directory.path());
    let activation =
        derive_ownership_activation("activation-a-b", "generation-b", &initial(), &depth, &trade)
            .unwrap();
    let path = directory.path().join("ownership.bnledger");
    let mut writer = OwnershipLedgerWriter::create(&path, initial()).unwrap();
    writer.prepare(activation).unwrap();
    writer.activate("activation-a-b").unwrap();
    let mut pointer = CanonicalSourcePointer::recover(
        &scan_ownership_ledger(&path).unwrap(),
        Some((&depth, &trade)),
    )
    .unwrap();
    pointer
        .fail_active("depth-b", "injected successor disconnect")
        .unwrap();
    assert_eq!(pointer.state, LivePublicationState::Gap);
    assert_eq!(pointer.owner.generation_id, "generation-b");
    assert!(
        pointer
            .accept_observation(BoundaryStreamKind::Depth, "depth-a", 1, 101, 101)
            .unwrap_err()
            .contains("GAP")
    );
}

#[test]
fn partial_activation_tail_is_not_recoverable_authority() {
    let directory = tempfile::tempdir().unwrap();
    let (depth, trade) = committed_proofs(directory.path());
    let activation =
        derive_ownership_activation("activation-a-b", "generation-b", &initial(), &depth, &trade)
            .unwrap();
    let path = directory.path().join("ownership.bnledger");
    {
        let mut writer = OwnershipLedgerWriter::create(&path, initial()).unwrap();
        writer.prepare(activation).unwrap();
        writer.activate("activation-a-b").unwrap();
    }
    let size = path.metadata().unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(size - 7)
        .unwrap();
    let scan = scan_ownership_ledger(&path).unwrap();
    assert!(!scan.clean_eof);
    assert_eq!(scan.records, 2);
    assert_eq!(
        scan.active_owner.as_ref().unwrap().generation_id,
        "generation-a"
    );
    assert!(CanonicalSourcePointer::recover(&scan, Some((&depth, &trade))).is_err());
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
            return Err(io::Error::other("injected ownership sync failure"));
        }
        Ok(())
    }
}

#[test]
fn failed_activation_sync_poisoning_never_emits_ack() {
    let directory = tempfile::tempdir().unwrap();
    let (depth, trade) = committed_proofs(directory.path());
    let activation =
        derive_ownership_activation("activation-a-b", "generation-b", &initial(), &depth, &trade)
            .unwrap();
    let state = Arc::new(Mutex::new(SyncState::default()));
    let sink = SyncFailSink { state, fail_on: 4 };
    let mut writer = OwnershipLedgerWriter::from_sink(sink, initial()).unwrap();
    writer.prepare(activation).unwrap();
    assert!(
        writer
            .activate("activation-a-b")
            .unwrap_err()
            .contains("poisoned")
    );
    assert!(writer.is_poisoned());
    assert!(
        writer
            .activate("activation-a-b")
            .unwrap_err()
            .contains("poisoned")
    );
}

#[test]
fn boundary_sequence_mismatch_and_token_overflow_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let (depth, trade) = committed_proofs(directory.path());
    let mut wrong_sequence = initial();
    wrong_sequence.depth_last_sequence = 99;
    assert!(
        derive_ownership_activation(
            "activation-a-b",
            "generation-b",
            &wrong_sequence,
            &depth,
            &trade,
        )
        .unwrap_err()
        .contains("continue")
    );
    let mut overflow = initial();
    overflow.fencing_token = u64::MAX;
    assert!(
        derive_ownership_activation("activation-a-b", "generation-b", &overflow, &depth, &trade,)
            .unwrap_err()
            .contains("overflow")
    );
}
