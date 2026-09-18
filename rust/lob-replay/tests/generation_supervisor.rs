use lob_replay::generation_supervisor::{
    CandidateFact, CandidateReason, DisconnectOutcome, GenerationIdentity, RawGenerationSupervisor,
    RawSupervisorConfig, RawSupervisorState, ServerShutdownOutcome,
};

fn config() -> RawSupervisorConfig {
    RawSupervisorConfig {
        segment_interval_ns: 10,
        planned_rotation_age_ns: 100,
        active_max_age_ns: 200,
        candidate_timeout_ns: 20,
        backoff_initial_ns: 2,
        backoff_max_ns: 8,
    }
}

fn identity(index: u64) -> GenerationIdentity {
    GenerationIdentity::new(
        &format!("generation-{index}"),
        &format!("depth-epoch-{index}"),
        &format!("trade-epoch-{index}"),
    )
    .unwrap()
}

fn ready(supervisor: &mut RawGenerationSupervisor, now: u64) {
    for fact in [
        CandidateFact::DepthConnected,
        CandidateFact::TradeConnected,
        CandidateFact::SnapshotPersisted,
        CandidateFact::DepthDurable,
        CandidateFact::TradeDurable,
        CandidateFact::DepthContinuityProven,
        CandidateFact::TradeContinuityProven,
    ] {
        assert!(supervisor.observe_candidate_fact(fact, now).unwrap());
        assert!(!supervisor.observe_candidate_fact(fact, now).unwrap());
    }
}

#[test]
fn segment_clock_is_independent_from_connection_rotation() {
    let mut supervisor = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    let report = supervisor.advance_time(35).unwrap();
    assert_eq!(report.segment_rollovers, 3);
    assert_eq!(report.current_segment_index, 3);
    assert!(report.candidate_request.is_none());
    assert_eq!(supervisor.active().unwrap().identity, identity(0));

    let report = supervisor.advance_time(100).unwrap();
    assert_eq!(report.segment_rollovers, 7);
    assert_eq!(report.current_segment_index, 10);
    assert_eq!(
        report.candidate_request.unwrap().reason,
        CandidateReason::PlannedRotation
    );
    assert_eq!(supervisor.active().unwrap().identity, identity(0));
}

#[test]
fn seven_planned_rotations_promote_only_complete_raw_candidates() {
    let mut supervisor = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    let mut now = 0;
    for index in 1..=7 {
        now += 100;
        let request = supervisor
            .advance_time(now)
            .unwrap()
            .candidate_request
            .unwrap();
        assert_eq!(request.reason, CandidateReason::PlannedRotation);
        supervisor
            .start_due_candidate(identity(index), now)
            .unwrap();
        assert_eq!(supervisor.state(), RawSupervisorState::Handover);
        assert!(supervisor.promote_candidate(now).is_err());
        ready(&mut supervisor, now);
        let promotion = supervisor.promote_candidate(now).unwrap();
        assert_eq!(promotion.predecessor.unwrap(), identity(index - 1));
        assert_eq!(promotion.successor, identity(index));
        assert!(!promotion.gap_was_open);
        assert!(
            supervisor
                .close_draining(&format!("generation-{}", index - 1), now)
                .unwrap()
        );
    }
    assert_eq!(supervisor.active().unwrap().identity, identity(7));
    assert!(supervisor.draining().is_empty());
    assert_eq!(supervisor.current_segment_index(), 70);
    assert!(!supervisor.qualification_has_gap());
}

#[test]
fn server_shutdown_starts_one_immediate_candidate_and_duplicates_are_idempotent() {
    let mut supervisor = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    assert_eq!(
        supervisor
            .on_server_shutdown("depth-epoch-0", identity(1), 1)
            .unwrap(),
        ServerShutdownOutcome::CandidateStarted
    );
    assert_eq!(supervisor.state(), RawSupervisorState::Handover);
    assert_eq!(
        supervisor
            .on_server_shutdown("trade-epoch-0", identity(1), 1)
            .unwrap(),
        ServerShutdownOutcome::CandidateAlreadyInProgress
    );
    assert_eq!(
        supervisor
            .on_server_shutdown("unknown", identity(2), 1)
            .unwrap(),
        ServerShutdownOutcome::IgnoredNonActiveEpoch
    );
}

#[test]
fn active_disconnect_is_gap_but_draining_disconnect_after_promotion_is_not() {
    let mut before = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    before
        .on_server_shutdown("depth-epoch-0", identity(1), 1)
        .unwrap();
    assert_eq!(
        before
            .disconnect_epoch("trade-epoch-0", "active transport lost", 2)
            .unwrap(),
        DisconnectOutcome::ActiveFailed
    );
    assert_eq!(before.state(), RawSupervisorState::Gap);
    assert_eq!(before.gap_count(), 1);
    assert!(before.candidate().is_none());

    let mut after = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    after
        .on_server_shutdown("depth-epoch-0", identity(1), 1)
        .unwrap();
    ready(&mut after, 1);
    after.promote_candidate(1).unwrap();
    assert_eq!(
        after
            .disconnect_epoch("depth-epoch-0", "draining close", 2)
            .unwrap(),
        DisconnectOutcome::DrainingClosed
    );
    assert_eq!(after.state(), RawSupervisorState::Live);
    assert_eq!(after.active().unwrap().identity, identity(1));
    assert_eq!(after.gap_count(), 0);
    assert_eq!(
        after
            .disconnect_epoch("depth-epoch-0", "duplicate close", 2)
            .unwrap(),
        DisconnectOutcome::AlreadyTerminal
    );
}

#[test]
fn failed_candidate_retries_with_bounded_backoff_and_never_reuses_identity() {
    let mut supervisor = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    supervisor.advance_time(100).unwrap();
    supervisor.start_due_candidate(identity(1), 100).unwrap();
    assert_eq!(
        supervisor
            .disconnect_epoch("depth-epoch-1", "candidate failed", 101)
            .unwrap(),
        DisconnectOutcome::CandidateFailed
    );
    assert_eq!(supervisor.next_candidate_not_before_ns(), Some(103));
    assert!(
        supervisor
            .advance_time(102)
            .unwrap()
            .candidate_request
            .is_none()
    );
    assert_eq!(
        supervisor
            .advance_time(103)
            .unwrap()
            .candidate_request
            .unwrap()
            .reason,
        CandidateReason::RetryAfterFailure
    );
    assert!(supervisor.start_due_candidate(identity(1), 103).is_err());
    supervisor.start_due_candidate(identity(2), 103).unwrap();
    assert_eq!(
        supervisor
            .disconnect_epoch("trade-epoch-2", "candidate failed again", 104)
            .unwrap(),
        DisconnectOutcome::CandidateFailed
    );
    assert_eq!(supervisor.next_candidate_not_before_ns(), Some(108));
    supervisor.advance_time(108).unwrap();
    supervisor.start_due_candidate(identity(3), 108).unwrap();
    supervisor
        .disconnect_epoch("depth-epoch-3", "third failure", 109)
        .unwrap();
    assert_eq!(supervisor.next_candidate_not_before_ns(), Some(117));
}

#[test]
fn exact_candidate_and_active_deadlines_fail_closed() {
    let mut timeout = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    timeout.advance_time(100).unwrap();
    timeout.start_due_candidate(identity(1), 100).unwrap();
    let report = timeout.advance_time(120).unwrap();
    assert!(report.candidate_timed_out);
    assert!(timeout.candidate().is_none());
    assert_eq!(timeout.state(), RawSupervisorState::Live);

    let mut hard = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    hard.advance_time(100).unwrap();
    hard.start_due_candidate(identity(1), 100).unwrap();
    ready(&mut hard, 119);
    let report = hard.advance_time(200).unwrap();
    assert!(report.entered_gap);
    assert_eq!(hard.state(), RawSupervisorState::Gap);
    assert!(hard.promote_candidate(200).is_err());
}

#[test]
fn monotonic_regression_and_duplicate_tokens_fail_closed() {
    let mut supervisor = RawGenerationSupervisor::new(config(), identity(0), 10).unwrap();
    supervisor.advance_time(20).unwrap();
    assert!(supervisor.advance_time(19).is_err());
    assert_eq!(supervisor.current_segment_index(), 1);

    supervisor.advance_time(110).unwrap();
    let duplicate_generation =
        GenerationIdentity::new("generation-0", "fresh-depth", "fresh-trade").unwrap();
    assert!(
        supervisor
            .start_due_candidate(duplicate_generation, 110)
            .is_err()
    );
    let duplicate_epoch =
        GenerationIdentity::new("fresh-generation", "depth-epoch-0", "fresh-trade-2").unwrap();
    assert!(
        supervisor
            .start_due_candidate(duplicate_epoch, 110)
            .is_err()
    );
    assert!(supervisor.candidate().is_none());
}

#[test]
fn gap_recovery_requires_fresh_fully_verified_generation() {
    let mut supervisor = RawGenerationSupervisor::new(config(), identity(0), 0).unwrap();
    supervisor
        .disconnect_epoch("depth-epoch-0", "active failed", 10)
        .unwrap();
    assert_eq!(supervisor.state(), RawSupervisorState::Gap);
    assert!(
        supervisor
            .advance_time(11)
            .unwrap()
            .candidate_request
            .is_none()
    );
    assert_eq!(
        supervisor
            .advance_time(12)
            .unwrap()
            .candidate_request
            .unwrap()
            .reason,
        CandidateReason::RecoveryAfterGap
    );
    supervisor.start_due_candidate(identity(1), 12).unwrap();
    assert_eq!(supervisor.state(), RawSupervisorState::Recovering);
    assert!(supervisor.promote_candidate(12).is_err());
    ready(&mut supervisor, 12);
    let promotion = supervisor.promote_candidate(12).unwrap();
    assert!(promotion.predecessor.is_none());
    assert!(promotion.gap_was_open);
    assert_eq!(supervisor.state(), RawSupervisorState::Live);
    assert!(supervisor.qualification_has_gap());
}
