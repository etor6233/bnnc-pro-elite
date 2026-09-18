use lob_replay::handover::{EpochState, HandoverController, PublicationState};

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn advance_to_live(controller: &mut HandoverController, epoch: &str, update_id: u64, digest: &str) {
    controller
        .transition_epoch(epoch, EpochState::Buffering)
        .unwrap();
    controller
        .transition_epoch(epoch, EpochState::Snapshotting)
        .unwrap();
    controller
        .transition_epoch(epoch, EpochState::Syncing)
        .unwrap();
    controller.mark_live(epoch, update_id, digest).unwrap();
}

fn active_controller() -> HandoverController {
    let mut controller = HandoverController::new("BTCUSDT", "epoch-a").unwrap();
    advance_to_live(&mut controller, "epoch-a", 100, DIGEST_A);
    controller.activate_initial().unwrap();
    controller
}

#[test]
fn exact_overlap_convergence_is_required_before_promotion() {
    let mut controller = active_controller();
    controller.begin_handover("epoch-b").unwrap();
    advance_to_live(&mut controller, "epoch-b", 99, DIGEST_B);
    assert!(!controller.candidate_converged());
    assert!(controller.promote_candidate().is_err());

    controller.observe_book("epoch-b", 100, DIGEST_A).unwrap();
    assert!(controller.candidate_converged());
    controller.promote_candidate().unwrap();

    assert_eq!(controller.publication, PublicationState::Live);
    assert_eq!(controller.active.epoch, "epoch-b");
    assert_eq!(controller.active.state, EpochState::Active);
    assert_eq!(controller.draining.as_ref().unwrap().epoch, "epoch-a");
    controller.close_draining().unwrap();
    assert!(controller.draining.is_none());
    assert!(controller.begin_handover("epoch-a").is_err());
}

#[test]
fn same_update_id_with_different_books_never_promotes() {
    let mut controller = active_controller();
    controller.begin_handover("epoch-b").unwrap();
    advance_to_live(&mut controller, "epoch-b", 100, DIGEST_B);
    assert!(!controller.candidate_converged());
    assert!(controller.promote_candidate().is_err());
    assert_eq!(controller.active.epoch, "epoch-a");
    assert_eq!(controller.publication, PublicationState::Handover);
}

#[test]
fn candidate_failure_preserves_active_publication_and_allows_fresh_epoch() {
    let mut controller = active_controller();
    controller.begin_handover("epoch-b").unwrap();
    controller
        .fail_epoch("epoch-b", "synthetic connect timeout")
        .unwrap();
    assert_eq!(controller.publication, PublicationState::Live);
    assert_eq!(controller.active.epoch, "epoch-a");
    assert!(controller.candidate.is_none());
    assert!(controller.begin_handover("epoch-b").is_err());
    controller.begin_handover("epoch-c").unwrap();
}

#[test]
fn active_disconnect_before_explicit_promotion_is_a_gap() {
    let mut controller = active_controller();
    controller.begin_handover("epoch-b").unwrap();
    advance_to_live(&mut controller, "epoch-b", 99, DIGEST_B);
    controller
        .fail_epoch("epoch-a", "synthetic forced disconnect")
        .unwrap();
    assert_eq!(controller.publication, PublicationState::Gap);
    assert_eq!(controller.active.state, EpochState::Failed);
    assert!(controller.promote_candidate().is_err());
}

#[test]
fn update_regression_fails_closed() {
    let mut controller = active_controller();
    assert!(controller.observe_book("epoch-a", 99, DIGEST_A).is_err());
    assert_eq!(controller.publication, PublicationState::Gap);
    assert_eq!(controller.active.state, EpochState::Failed);
}

#[test]
fn expired_rotation_without_convergence_is_a_gap() {
    let mut controller = active_controller();
    controller.begin_handover("epoch-b").unwrap();
    controller
        .rotation_deadline_expired("synthetic 24-hour connection deadline")
        .unwrap();
    assert_eq!(controller.publication, PublicationState::Gap);
    assert_eq!(controller.failures.len(), 1);
}

#[test]
fn illegal_transition_and_noncanonical_digest_are_rejected() {
    let mut controller = HandoverController::new("ETHUSDT", "epoch-a").unwrap();
    assert!(
        controller
            .transition_epoch("epoch-a", EpochState::Snapshotting)
            .is_err()
    );
    controller
        .transition_epoch("epoch-a", EpochState::Buffering)
        .unwrap();
    controller
        .transition_epoch("epoch-a", EpochState::Snapshotting)
        .unwrap();
    controller
        .transition_epoch("epoch-a", EpochState::Syncing)
        .unwrap();
    assert!(controller.mark_live("epoch-a", 1, "ABC").is_err());
}

#[test]
fn draining_disconnect_does_not_invalidate_promoted_epoch() {
    let mut controller = active_controller();
    controller.begin_handover("epoch-b").unwrap();
    advance_to_live(&mut controller, "epoch-b", 100, DIGEST_A);
    controller.promote_candidate().unwrap();
    controller
        .fail_epoch("epoch-a", "synthetic old socket close")
        .unwrap();
    assert_eq!(controller.publication, PublicationState::Live);
    assert_eq!(controller.active.epoch, "epoch-b");
    assert!(controller.draining.is_none());
}
