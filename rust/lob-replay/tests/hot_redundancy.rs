use lob_replay::hot_redundancy::{
    CaptureLane, CircuitState, CoverageState, HotRedundancyConfig, HotRedundantSupervisor,
    LaneState,
};

fn config() -> HotRedundancyConfig {
    HotRedundancyConfig {
        backoff_initial_ns: 10,
        backoff_max_ns: 80,
        jitter_max_ns: 5,
        backoff_reset_after_ns: 100,
        circuit_failure_threshold: 0,
        circuit_reset_cooldown_ns: 0,
    }
}

fn breaker_config() -> HotRedundancyConfig {
    HotRedundancyConfig {
        backoff_initial_ns: 10,
        backoff_max_ns: 80,
        jitter_max_ns: 0,
        backoff_reset_after_ns: 100,
        circuit_failure_threshold: 2,
        circuit_reset_cooldown_ns: 1_000,
    }
}

#[test]
fn one_failed_lane_degrades_without_opening_a_gap() {
    let mut supervisor = HotRedundantSupervisor::new(config(), 0).unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p0", 0)
        .unwrap();
    supervisor.start_lane(CaptureLane::Shadow, "s0", 0).unwrap();
    supervisor
        .mark_ready(CaptureLane::Primary, "p0", 1)
        .unwrap();
    let transition = supervisor.mark_ready(CaptureLane::Shadow, "s0", 2).unwrap();
    assert_eq!(transition.current, CoverageState::Redundant);

    let transition = supervisor
        .fail_lane(CaptureLane::Primary, "p0", "socket closed", 3)
        .unwrap();
    assert_eq!(transition.current, CoverageState::Degraded);
    assert!(transition.opened_gap.is_none());
    assert!(supervisor.open_gap().is_none());
    assert_eq!(
        supervisor.lane(CaptureLane::Primary).state,
        LaneState::Backoff
    );
    assert_eq!(supervisor.lane(CaptureLane::Shadow).state, LaneState::Ready);
}

#[test]
fn dual_failure_opens_one_gap_and_verified_restart_closes_it() {
    let mut supervisor = HotRedundantSupervisor::new(config(), 0).unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p0", 0)
        .unwrap();
    supervisor.start_lane(CaptureLane::Shadow, "s0", 0).unwrap();
    supervisor
        .mark_ready(CaptureLane::Primary, "p0", 1)
        .unwrap();
    supervisor.mark_ready(CaptureLane::Shadow, "s0", 1).unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p0", "primary silence", 2)
        .unwrap();
    let opened = supervisor
        .fail_lane(CaptureLane::Shadow, "s0", "shadow silence", 3)
        .unwrap()
        .opened_gap
        .unwrap();
    assert_eq!(opened.gap_id, 0);
    assert_eq!(supervisor.coverage(), CoverageState::Gap);
    assert!(supervisor.advance_time(4).unwrap().opened_gap.is_none());

    let due = supervisor
        .lane(CaptureLane::Primary)
        .restart_not_before_mono_ns
        .unwrap();
    assert_eq!(supervisor.restart_requests(due).unwrap().len(), 1);
    supervisor
        .start_lane(CaptureLane::Primary, "p1", due)
        .unwrap();
    assert_eq!(supervisor.coverage(), CoverageState::Gap);
    let closed = supervisor
        .mark_ready(CaptureLane::Primary, "p1", due + 7)
        .unwrap()
        .closed_gap
        .unwrap();
    assert_eq!(closed.gap_id, 0);
    assert_eq!(closed.unavailable_ns, Some(due + 4));
    assert_eq!(supervisor.coverage(), CoverageState::Degraded);
}

#[test]
fn stale_and_reused_run_tokens_fail_closed() {
    let mut supervisor = HotRedundantSupervisor::new(config(), 0).unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p0", 0)
        .unwrap();
    assert!(
        supervisor
            .mark_ready(CaptureLane::Primary, "stale", 1)
            .is_err()
    );
    supervisor
        .mark_ready(CaptureLane::Primary, "p0", 1)
        .unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p0", "failed", 2)
        .unwrap();
    assert!(
        supervisor
            .fail_lane(CaptureLane::Primary, "p0", "duplicate", 3)
            .is_err()
    );
    let due = supervisor
        .lane(CaptureLane::Primary)
        .restart_not_before_mono_ns
        .unwrap();
    assert!(
        supervisor
            .start_lane(CaptureLane::Primary, "p0", due)
            .is_err()
    );
    supervisor
        .start_lane(CaptureLane::Primary, "p1", due)
        .unwrap();
    assert!(
        supervisor
            .mark_ready(CaptureLane::Primary, "p0", due + 1)
            .is_err()
    );
}

#[test]
fn reconnect_backoff_is_bounded_and_monotonic_time_cannot_regress() {
    let mut supervisor = HotRedundantSupervisor::new(config(), 10).unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p0", 10)
        .unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p0", "failure one", 11)
        .unwrap();
    let first = supervisor
        .lane(CaptureLane::Primary)
        .restart_not_before_mono_ns
        .unwrap()
        - 11;
    assert!((10..=15).contains(&first));
    assert!(supervisor.advance_time(10).is_err());

    let due = 11 + first;
    supervisor
        .start_lane(CaptureLane::Primary, "p1", due)
        .unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p1", "failure two", due + 1)
        .unwrap();
    let second = supervisor
        .lane(CaptureLane::Primary)
        .restart_not_before_mono_ns
        .unwrap()
        - (due + 1);
    assert!((20..=25).contains(&second));
    assert!(second > first);
}

#[test]
fn startup_is_not_falsely_reported_as_a_market_gap() {
    let mut supervisor = HotRedundantSupervisor::new(config(), 0).unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p0", 0)
        .unwrap();
    supervisor.start_lane(CaptureLane::Shadow, "s0", 0).unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p0", "startup failure", 1)
        .unwrap();
    assert_eq!(supervisor.coverage(), CoverageState::Starting);
    assert!(supervisor.open_gap().is_none());
    supervisor.mark_ready(CaptureLane::Shadow, "s0", 2).unwrap();
    assert_eq!(supervisor.coverage(), CoverageState::Degraded);
}

#[test]
fn clean_lane_rollover_is_immediate_and_does_not_count_as_failure() {
    let mut supervisor = HotRedundantSupervisor::new(config(), 0).unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p0", 0)
        .unwrap();
    supervisor.start_lane(CaptureLane::Shadow, "s0", 0).unwrap();
    supervisor
        .mark_ready(CaptureLane::Primary, "p0", 1)
        .unwrap();
    supervisor.mark_ready(CaptureLane::Shadow, "s0", 1).unwrap();

    let transition = supervisor
        .retire_lane(CaptureLane::Primary, "p0", 10)
        .unwrap();
    assert_eq!(transition.current, CoverageState::Degraded);
    assert_eq!(
        supervisor
            .lane(CaptureLane::Primary)
            .restart_not_before_mono_ns,
        Some(10)
    );
    assert_eq!(
        supervisor.lane(CaptureLane::Primary).consecutive_failures,
        0
    );
    assert_eq!(supervisor.restart_requests(10).unwrap().len(), 1);
    supervisor
        .start_lane(CaptureLane::Primary, "p1", 10)
        .unwrap();
    supervisor
        .mark_ready(CaptureLane::Primary, "p1", 11)
        .unwrap();
    assert_eq!(supervisor.coverage(), CoverageState::Redundant);
}

// Circuit breaker (port of tetsuo SocketReconnect.c update_circuit_breaker /
// circuit_allows_attempt): N consecutive failures open the circuit, attempts
// are denied until the reset cooldown elapses, the first attempt after the
// cooldown is the single half-open probe, a failed probe reopens the circuit,
// and a successful connection closes it.

#[test]
fn circuit_breaker_opens_on_threshold_failures_and_gates_restart_probes() {
    let mut supervisor = HotRedundantSupervisor::new(breaker_config(), 0).unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p0", 0)
        .unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p0", "failure one", 1)
        .unwrap();
    // First failure: below the threshold, circuit stays closed.
    assert_eq!(
        supervisor.lane(CaptureLane::Primary).circuit_state,
        CircuitState::Closed
    );
    let due = supervisor
        .lane(CaptureLane::Primary)
        .restart_not_before_mono_ns
        .unwrap(); // 1 + 10 ns of backoff
    assert_eq!(supervisor.restart_requests(due).unwrap().len(), 1);
    supervisor
        .start_lane(CaptureLane::Primary, "p1", due)
        .unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p1", "failure two", due + 1)
        .unwrap();
    // Second consecutive failure: circuit opens at `due + 1`.
    assert_eq!(
        supervisor.lane(CaptureLane::Primary).circuit_state,
        CircuitState::Open
    );
    let due2 = supervisor
        .lane(CaptureLane::Primary)
        .restart_not_before_mono_ns
        .unwrap(); // due + 1 + 20 ns of backoff
    // Backoff elapsed but the circuit is still cooling down: no restart offered.
    assert!(supervisor.restart_requests(due2).unwrap().is_empty());
    assert!(supervisor.restart_requests(due + 1_000).unwrap().is_empty());
    // An explicit attempt while the circuit is open is also denied.
    assert!(
        supervisor
            .start_lane(CaptureLane::Primary, "blocked", due + 500)
            .is_err()
    );
    // Cooldown elapsed: a single half-open probe is offered.
    assert_eq!(supervisor.restart_requests(due + 1_001).unwrap().len(), 1);
    supervisor
        .start_lane(CaptureLane::Primary, "p2", due + 1_001)
        .unwrap();
    assert_eq!(
        supervisor.lane(CaptureLane::Primary).circuit_state,
        CircuitState::HalfOpen
    );
    // The probe fails: circuit reopens for another cooldown.
    supervisor
        .fail_lane(CaptureLane::Primary, "p2", "probe failure", due + 1_002)
        .unwrap();
    assert_eq!(
        supervisor.lane(CaptureLane::Primary).circuit_state,
        CircuitState::Open
    );
    assert!(supervisor.restart_requests(due + 2_001).unwrap().is_empty());
    assert_eq!(supervisor.restart_requests(due + 2_002).unwrap().len(), 1);
    supervisor
        .start_lane(CaptureLane::Primary, "p3", due + 2_002)
        .unwrap();
    // The probe succeeds: circuit closes and its open timestamp is cleared.
    supervisor
        .mark_ready(CaptureLane::Primary, "p3", due + 2_003)
        .unwrap();
    let status = supervisor.lane(CaptureLane::Primary);
    assert_eq!(status.circuit_state, CircuitState::Closed);
    assert!(status.circuit_open_mono_ns.is_none());
    assert_eq!(supervisor.coverage(), CoverageState::Degraded);
}

#[test]
fn circuit_breaker_disabled_at_zero_threshold_never_blocks_restarts() {
    let mut supervisor = HotRedundantSupervisor::new(config(), 0).unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p0", 0)
        .unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p0", "failure one", 1)
        .unwrap();
    let due = supervisor
        .lane(CaptureLane::Primary)
        .restart_not_before_mono_ns
        .unwrap();
    supervisor
        .start_lane(CaptureLane::Primary, "p1", due)
        .unwrap();
    supervisor
        .fail_lane(CaptureLane::Primary, "p1", "failure two", due + 1)
        .unwrap();
    let due2 = supervisor
        .lane(CaptureLane::Primary)
        .restart_not_before_mono_ns
        .unwrap();
    // Threshold 0 disables the breaker: restarts are offered as soon as backoff
    // elapses, no matter how many consecutive failures accumulated.
    assert_eq!(
        supervisor.lane(CaptureLane::Primary).circuit_state,
        CircuitState::Closed
    );
    assert_eq!(supervisor.restart_requests(due2).unwrap().len(), 1);
}

#[test]
fn circuit_breaker_validation_rejects_enabled_breaker_without_cooldown() {
    let mut cfg = config();
    cfg.circuit_failure_threshold = 1;
    cfg.circuit_reset_cooldown_ns = 0;
    assert!(cfg.validate().is_err());
    cfg.circuit_reset_cooldown_ns = 1_000;
    assert!(cfg.validate().is_ok());
    cfg.circuit_failure_threshold = 0;
    assert!(cfg.validate().is_ok());
}
