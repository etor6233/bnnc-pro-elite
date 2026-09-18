use lob_replay::boundary::{
    BoundaryDurabilityV1, BoundaryJournalWriter, BoundaryStreamKind, HandoverBoundaryV1,
    RawPositionV1,
};
use lob_replay::handover::{EpochState, HandoverController, PublicationState};
use lob_replay::live_rotation::LiveRotationCoordinator;
use lob_replay::ownership::{
    CanonicalSourcePointer, LivePublicationState, OwnershipLedgerWriter, SourcePointerSnapshotV1,
    load_committed_boundary_proof, scan_ownership_ledger,
};
use tempfile::tempdir;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn position(epoch: &str, stream: &str, frame_index: u64) -> RawPositionV1 {
    RawPositionV1 {
        connection_epoch: epoch.to_owned(),
        stream: stream.to_owned(),
        frame_index,
        record_sha256: DIGEST.to_owned(),
    }
}

fn boundary(kind: BoundaryStreamKind, sequence: u64) -> HandoverBoundaryV1 {
    let (stream, predecessor, successor) = match kind {
        BoundaryStreamKind::Depth => ("btcusdt@depth@100ms", "depth-a", "depth-b"),
        BoundaryStreamKind::Trade => ("btcusdt@trade", "trade-a", "trade-b"),
    };
    HandoverBoundaryV1 {
        schema: "HandoverBoundaryV1".to_owned(),
        boundary_id: format!("boundary-{kind:?}"),
        environment: "production-public-market-data".to_owned(),
        symbol: "BTCUSDT".to_owned(),
        stream_kind: kind,
        stream: stream.to_owned(),
        predecessor_epoch: predecessor.to_owned(),
        successor_epoch: successor.to_owned(),
        boundary_sequence: sequence,
        boundary_sha256: DIGEST.to_owned(),
        predecessor_last_selected: position(predecessor, stream, 10),
        successor_boundary_observation: position(successor, stream, 8),
        successor_first_selected: position(successor, stream, 9),
        predecessor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: 10,
            durable_through_offset: 1000,
            last_record_sha256: DIGEST.to_owned(),
        },
        successor_durability: BoundaryDurabilityV1 {
            durable_through_frame_index: 12,
            durable_through_offset: 1100,
            last_record_sha256: DIGEST.to_owned(),
        },
        spec_revision: "spec".to_owned(),
        selector_version: "CanonicalSelectorV1".to_owned(),
    }
}

fn commit(
    path: &std::path::Path,
    boundary: HandoverBoundaryV1,
) -> lob_replay::ownership::CommittedBoundaryProofV1 {
    let mut writer = BoundaryJournalWriter::create(path).unwrap();
    writer.propose(boundary).unwrap();
    let id = writer_path_boundary_id(path);
    writer.commit(&id).unwrap();
    load_committed_boundary_proof(path).unwrap()
}

fn writer_path_boundary_id(path: &std::path::Path) -> String {
    if path.file_name().unwrap() == "depth.bnhandover" {
        "boundary-Depth".to_owned()
    } else {
        "boundary-Trade".to_owned()
    }
}

fn active_handover() -> HandoverController {
    let mut handover = HandoverController::new("BTCUSDT", "depth-a").unwrap();
    for state in [
        EpochState::Buffering,
        EpochState::Snapshotting,
        EpochState::Syncing,
    ] {
        handover.transition_epoch("depth-a", state).unwrap();
    }
    handover.mark_live("depth-a", 100, DIGEST).unwrap();
    handover.activate_initial().unwrap();
    handover.begin_handover("depth-b").unwrap();
    for state in [
        EpochState::Buffering,
        EpochState::Snapshotting,
        EpochState::Syncing,
    ] {
        handover.transition_epoch("depth-b", state).unwrap();
    }
    handover.mark_live("depth-b", 100, DIGEST).unwrap();
    assert!(handover.candidate_converged());
    handover
}

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

#[test]
fn durable_rescan_precedes_promotion_and_fences_predecessor() {
    let directory = tempdir().unwrap();
    let depth = commit(
        &directory.path().join("depth.bnhandover"),
        boundary(BoundaryStreamKind::Depth, 100),
    );
    let trade = commit(
        &directory.path().join("trade.bnhandover"),
        boundary(BoundaryStreamKind::Trade, 200),
    );
    let ledger_path = directory.path().join("ownership.bnledger");
    let mut ledger = OwnershipLedgerWriter::create(&ledger_path, initial()).unwrap();
    let scan = scan_ownership_ledger(&ledger_path).unwrap();
    let pointer = CanonicalSourcePointer::recover(&scan, None).unwrap();
    let mut coordinator = LiveRotationCoordinator::new(active_handover(), pointer).unwrap();

    let report = coordinator
        .activate_committed(
            &mut ledger,
            &ledger_path,
            "activation-a-b",
            "generation-b",
            &depth,
            &trade,
        )
        .unwrap();
    assert_eq!(report.status, "ACTIVATED_LIVE_AUTHORITY");
    assert_eq!(coordinator.handover.active.epoch, "depth-b");
    assert_eq!(
        coordinator.handover.draining.as_ref().unwrap().epoch,
        "depth-a"
    );
    assert_eq!(coordinator.pointer.owner.fencing_token, 2);
    coordinator
        .accept_observation(BoundaryStreamKind::Depth, "depth-b", 2, 101, 103)
        .unwrap();
    coordinator
        .accept_observation(BoundaryStreamKind::Trade, "trade-b", 2, 201, 201)
        .unwrap();
    assert!(
        coordinator
            .accept_observation(BoundaryStreamKind::Depth, "depth-a", 1, 101, 101)
            .is_err()
    );
    assert_eq!(coordinator.pointer.fenced_rejections, 1);
}

#[test]
fn mismatched_live_book_never_prepares_ownership() {
    let directory = tempdir().unwrap();
    let mut wrong = boundary(BoundaryStreamKind::Depth, 100);
    wrong.boundary_sha256 =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    let depth = commit(&directory.path().join("depth.bnhandover"), wrong);
    let trade = commit(
        &directory.path().join("trade.bnhandover"),
        boundary(BoundaryStreamKind::Trade, 200),
    );
    let ledger_path = directory.path().join("ownership.bnledger");
    let mut ledger = OwnershipLedgerWriter::create(&ledger_path, initial()).unwrap();
    let pointer =
        CanonicalSourcePointer::recover(&scan_ownership_ledger(&ledger_path).unwrap(), None)
            .unwrap();
    let mut coordinator = LiveRotationCoordinator::new(active_handover(), pointer).unwrap();

    assert!(
        coordinator
            .activate_committed(
                &mut ledger,
                &ledger_path,
                "activation-a-b",
                "generation-b",
                &depth,
                &trade,
            )
            .is_err()
    );
    let scan = scan_ownership_ledger(&ledger_path).unwrap();
    assert_eq!(scan.records, 1);
    assert_eq!(scan.active_owner.unwrap().generation_id, "generation-a");
    assert_eq!(coordinator.handover.active.epoch, "depth-a");
}

#[test]
fn successor_failure_after_activation_is_gap_without_rollback() {
    let directory = tempdir().unwrap();
    let depth = commit(
        &directory.path().join("depth.bnhandover"),
        boundary(BoundaryStreamKind::Depth, 100),
    );
    let trade = commit(
        &directory.path().join("trade.bnhandover"),
        boundary(BoundaryStreamKind::Trade, 200),
    );
    let ledger_path = directory.path().join("ownership.bnledger");
    let mut ledger = OwnershipLedgerWriter::create(&ledger_path, initial()).unwrap();
    let pointer =
        CanonicalSourcePointer::recover(&scan_ownership_ledger(&ledger_path).unwrap(), None)
            .unwrap();
    let mut coordinator = LiveRotationCoordinator::new(active_handover(), pointer).unwrap();
    coordinator
        .activate_committed(
            &mut ledger,
            &ledger_path,
            "activation-a-b",
            "generation-b",
            &depth,
            &trade,
        )
        .unwrap();

    coordinator
        .fail_active(BoundaryStreamKind::Depth, "successor socket failed")
        .unwrap();
    assert_eq!(coordinator.pointer.state, LivePublicationState::Gap);
    assert_eq!(coordinator.pointer.owner.generation_id, "generation-b");
    assert_eq!(coordinator.handover.publication, PublicationState::Gap);
    assert_eq!(coordinator.handover.active.epoch, "depth-b");
}

#[test]
fn failed_rescan_after_durable_activation_blocks_old_in_memory_owner() {
    let directory = tempdir().unwrap();
    let depth = commit(
        &directory.path().join("depth.bnhandover"),
        boundary(BoundaryStreamKind::Depth, 100),
    );
    let trade = commit(
        &directory.path().join("trade.bnhandover"),
        boundary(BoundaryStreamKind::Trade, 200),
    );
    let ledger_path = directory.path().join("ownership.bnledger");
    let mut ledger = OwnershipLedgerWriter::create(&ledger_path, initial()).unwrap();
    let pointer =
        CanonicalSourcePointer::recover(&scan_ownership_ledger(&ledger_path).unwrap(), None)
            .unwrap();
    let mut coordinator = LiveRotationCoordinator::new(active_handover(), pointer).unwrap();

    assert!(
        coordinator
            .activate_committed(
                &mut ledger,
                &directory.path().join("missing-ledger"),
                "activation-a-b",
                "generation-b",
                &depth,
                &trade,
            )
            .is_err()
    );
    assert_eq!(coordinator.pointer.state, LivePublicationState::Gap);
    assert!(
        coordinator
            .accept_observation(BoundaryStreamKind::Depth, "depth-a", 1, 101, 101)
            .is_err()
    );
    assert_eq!(coordinator.handover.active.epoch, "depth-a");
    assert_eq!(coordinator.handover.publication, PublicationState::Handover);

    let durable = scan_ownership_ledger(&ledger_path).unwrap();
    assert_eq!(durable.active_owner.unwrap().generation_id, "generation-b");
}
