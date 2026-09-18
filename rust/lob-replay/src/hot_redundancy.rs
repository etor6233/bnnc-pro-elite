//! Pure availability state machine for two independent raw-capture lanes.
//!
//! This module does not merge market events and does not select a canonical
//! lineage.  It records whether at least one independently captured lane is
//! ready, schedules bounded reconnects, and makes intervals with no ready lane
//! explicit.  Canonical selection remains an offline, evidence-backed step.

use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureLane {
    Primary,
    Shadow,
}

impl CaptureLane {
    pub const ALL: [Self; 2] = [Self::Primary, Self::Shadow];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "PRIMARY",
            Self::Shadow => "SHADOW",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LaneState {
    Absent,
    Starting,
    Ready,
    Backoff,
    Terminal,
}

/// Per-lane circuit-breaker state (port of tetsuo `SocketReconnect.c`:
/// `update_circuit_breaker` / `circuit_allows_attempt`).  `Closed` allows
/// attempts, `Open` denies them until the reset cooldown elapses, and
/// `HalfOpen` admits exactly one probe after the cooldown.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CircuitState {
    #[default]
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageState {
    Starting,
    Redundant,
    Degraded,
    Gap,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HotRedundancyConfig {
    pub backoff_initial_ns: u64,
    pub backoff_max_ns: u64,
    pub jitter_max_ns: u64,
    pub backoff_reset_after_ns: u64,
    /// Consecutive lane failures that open the per-lane circuit breaker.
    /// `0` disables the breaker (explicit opt-out).  Port of tetsuo
    /// `SocketReconnect_Policy.circuit_failure_threshold`.
    pub circuit_failure_threshold: u32,
    /// Cooldown before a single half-open probe is allowed after the circuit
    /// opens.  Must be positive whenever the breaker is enabled.  Port of
    /// tetsuo `SocketReconnect_Policy.circuit_reset_timeout_ms`.
    pub circuit_reset_cooldown_ns: u64,
}

impl HotRedundancyConfig {
    pub fn validate(&self) -> Result<()> {
        if self.backoff_initial_ns == 0
            || self.backoff_max_ns == 0
            || self.backoff_reset_after_ns == 0
            || self.backoff_initial_ns > self.backoff_max_ns
            || self.jitter_max_ns > self.backoff_max_ns
        {
            return Err("invalid hot-redundancy reconnect policy".to_owned());
        }
        if self.circuit_failure_threshold > 0 && self.circuit_reset_cooldown_ns == 0 {
            return Err(
                "circuit breaker reset cooldown must be positive when the breaker is enabled"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneStatus {
    pub lane: CaptureLane,
    pub state: LaneState,
    pub run_token: Option<String>,
    pub launch_attempt: u64,
    pub consecutive_failures: u32,
    pub started_mono_ns: Option<u64>,
    pub ready_mono_ns: Option<u64>,
    pub restart_not_before_mono_ns: Option<u64>,
    pub last_failure_reason: Option<String>,
    #[serde(default)]
    pub circuit_state: CircuitState,
    #[serde(default)]
    pub circuit_open_mono_ns: Option<u64>,
}

impl LaneStatus {
    fn absent(lane: CaptureLane) -> Self {
        Self {
            lane,
            state: LaneState::Absent,
            run_token: None,
            launch_attempt: 0,
            consecutive_failures: 0,
            started_mono_ns: None,
            ready_mono_ns: None,
            restart_not_before_mono_ns: None,
            last_failure_reason: None,
            circuit_state: CircuitState::default(),
            circuit_open_mono_ns: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GapInterval {
    pub gap_id: u64,
    pub opened_mono_ns: u64,
    pub closed_mono_ns: Option<u64>,
    pub unavailable_ns: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RestartRequest {
    pub lane: CaptureLane,
    pub not_before_mono_ns: u64,
    pub next_launch_attempt: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CoverageTransition {
    pub previous: CoverageState,
    pub current: CoverageState,
    pub opened_gap: Option<GapInterval>,
    pub closed_gap: Option<GapInterval>,
}

#[derive(Debug)]
pub struct HotRedundantSupervisor {
    config: HotRedundancyConfig,
    lanes: BTreeMap<CaptureLane, LaneStatus>,
    used_run_tokens: BTreeSet<String>,
    coverage: CoverageState,
    ever_ready: bool,
    open_gap: Option<GapInterval>,
    next_gap_id: u64,
    last_mono_ns: u64,
    terminal: bool,
}

impl HotRedundantSupervisor {
    pub fn new(config: HotRedundancyConfig, now_mono_ns: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            lanes: BTreeMap::from([
                (
                    CaptureLane::Primary,
                    LaneStatus::absent(CaptureLane::Primary),
                ),
                (CaptureLane::Shadow, LaneStatus::absent(CaptureLane::Shadow)),
            ]),
            used_run_tokens: BTreeSet::new(),
            coverage: CoverageState::Starting,
            ever_ready: false,
            open_gap: None,
            next_gap_id: 0,
            last_mono_ns: now_mono_ns,
            terminal: false,
        })
    }

    pub fn coverage(&self) -> CoverageState {
        self.coverage
    }

    pub fn lane(&self, lane: CaptureLane) -> &LaneStatus {
        self.lanes.get(&lane).expect("both lanes are initialized")
    }

    pub fn open_gap(&self) -> Option<&GapInterval> {
        self.open_gap.as_ref()
    }

    pub fn start_lane(
        &mut self,
        lane: CaptureLane,
        run_token: &str,
        now_mono_ns: u64,
    ) -> Result<CoverageTransition> {
        self.advance_clock(now_mono_ns)?;
        if self.terminal {
            return Err("cannot start a lane after supervisor termination".to_owned());
        }
        if run_token.trim().is_empty() || !self.used_run_tokens.insert(run_token.to_owned()) {
            return Err("capture lane run token must be non-empty and never reused".to_owned());
        }
        let status = self
            .lanes
            .get_mut(&lane)
            .expect("both lanes are initialized");
        if !matches!(status.state, LaneState::Absent | LaneState::Backoff) {
            return Err(format!("{} lane is not eligible to start", lane.as_str()));
        }
        if status
            .restart_not_before_mono_ns
            .is_some_and(|deadline| now_mono_ns < deadline)
        {
            return Err(format!(
                "{} lane reconnect backoff has not elapsed",
                lane.as_str()
            ));
        }
        // Circuit-breaker gate (tetsuo `circuit_allows_attempt` semantics):
        // while OPEN, attempts are denied until the reset cooldown elapses;
        // the first attempt after the cooldown is the single half-open probe.
        if status.circuit_state == CircuitState::Open
            && status.circuit_open_mono_ns.is_some_and(|opened| {
                now_mono_ns.saturating_sub(opened) < self.config.circuit_reset_cooldown_ns
            })
        {
            return Err(format!("{} lane circuit breaker is open", lane.as_str()));
        }
        if status.circuit_state == CircuitState::Open {
            status.circuit_state = CircuitState::HalfOpen;
        }
        status.state = LaneState::Starting;
        status.run_token = Some(run_token.to_owned());
        status.launch_attempt = status
            .launch_attempt
            .checked_add(1)
            .ok_or_else(|| "lane launch-attempt overflow".to_owned())?;
        status.started_mono_ns = Some(now_mono_ns);
        status.ready_mono_ns = None;
        status.restart_not_before_mono_ns = None;
        status.last_failure_reason = None;
        self.recompute_coverage(now_mono_ns)
    }

    pub fn mark_ready(
        &mut self,
        lane: CaptureLane,
        run_token: &str,
        now_mono_ns: u64,
    ) -> Result<CoverageTransition> {
        self.advance_clock(now_mono_ns)?;
        let status = self
            .lanes
            .get_mut(&lane)
            .expect("both lanes are initialized");
        if status.run_token.as_deref() != Some(run_token) {
            return Err(format!(
                "{} readiness references a stale run token",
                lane.as_str()
            ));
        }
        if status.state == LaneState::Ready {
            return self.recompute_coverage(now_mono_ns);
        }
        if status.state != LaneState::Starting {
            return Err(format!(
                "{} readiness is illegal from its current state",
                lane.as_str()
            ));
        }
        status.state = LaneState::Ready;
        status.ready_mono_ns = Some(now_mono_ns);
        // A successful connection closes the breaker (tetsuo
        // `update_circuit_breaker(conn, /* success= */ 1)`).
        status.circuit_state = CircuitState::Closed;
        status.circuit_open_mono_ns = None;
        self.ever_ready = true;
        self.recompute_coverage(now_mono_ns)
    }

    pub fn fail_lane(
        &mut self,
        lane: CaptureLane,
        run_token: &str,
        reason: &str,
        now_mono_ns: u64,
    ) -> Result<CoverageTransition> {
        self.advance_clock(now_mono_ns)?;
        if reason.trim().is_empty() {
            return Err("lane failure reason must not be empty".to_owned());
        }
        let status = self
            .lanes
            .get_mut(&lane)
            .expect("both lanes are initialized");
        if status.run_token.as_deref() != Some(run_token) {
            return Err(format!(
                "{} failure references a stale run token",
                lane.as_str()
            ));
        }
        if !matches!(status.state, LaneState::Starting | LaneState::Ready) {
            return Err(format!("{} failure is duplicate or illegal", lane.as_str()));
        }
        status.state = LaneState::Backoff;
        status.ready_mono_ns = None;
        status.last_failure_reason = Some(reason.to_owned());
        status.consecutive_failures = status.consecutive_failures.saturating_add(1);
        if self.config.circuit_failure_threshold > 0 {
            if status.circuit_state == CircuitState::HalfOpen {
                // The half-open probe failed: reopen the circuit for another
                // full cooldown (tetsuo `update_circuit_breaker`, HALF_OPEN).
                status.circuit_state = CircuitState::Open;
                status.circuit_open_mono_ns = Some(now_mono_ns);
            } else if status.circuit_state == CircuitState::Closed
                && status.consecutive_failures >= self.config.circuit_failure_threshold
            {
                // Too many consecutive failures: open the circuit (tetsuo
                // `update_circuit_breaker`, CLOSED threshold branch).
                status.circuit_state = CircuitState::Open;
                status.circuit_open_mono_ns = Some(now_mono_ns);
            }
        }
        let delay = reconnect_delay_ns(
            &self.config,
            lane,
            status.launch_attempt,
            status.consecutive_failures,
            run_token,
        );
        status.restart_not_before_mono_ns = Some(now_mono_ns.saturating_add(delay));
        self.recompute_coverage(now_mono_ns)
    }

    pub fn retire_lane(
        &mut self,
        lane: CaptureLane,
        run_token: &str,
        now_mono_ns: u64,
    ) -> Result<CoverageTransition> {
        self.advance_clock(now_mono_ns)?;
        let status = self
            .lanes
            .get_mut(&lane)
            .expect("both lanes are initialized");
        if status.run_token.as_deref() != Some(run_token) {
            return Err(format!(
                "{} retirement references a stale run token",
                lane.as_str()
            ));
        }
        if status.state != LaneState::Ready {
            return Err(format!(
                "{} retirement requires a ready lane",
                lane.as_str()
            ));
        }
        status.state = LaneState::Backoff;
        status.ready_mono_ns = None;
        status.restart_not_before_mono_ns = Some(now_mono_ns);
        status.last_failure_reason = None;
        status.consecutive_failures = 0;
        // A deliberate, clean retirement resets the breaker like tetsuo
        // `SocketReconnect_reset`.
        status.circuit_state = CircuitState::Closed;
        status.circuit_open_mono_ns = None;
        self.recompute_coverage(now_mono_ns)
    }

    pub fn restart_requests(&mut self, now_mono_ns: u64) -> Result<Vec<RestartRequest>> {
        self.advance_clock(now_mono_ns)?;
        if self.terminal {
            return Ok(Vec::new());
        }
        let mut requests = Vec::new();
        for lane in CaptureLane::ALL {
            let status = self.lanes.get(&lane).expect("both lanes are initialized");
            // An OPEN circuit suppresses restart requests until its reset
            // cooldown elapses (tetsuo `circuit_allows_attempt`).
            let circuit_blocked = status.circuit_state == CircuitState::Open
                && status.circuit_open_mono_ns.is_some_and(|opened| {
                    now_mono_ns.saturating_sub(opened) < self.config.circuit_reset_cooldown_ns
                });
            if status.state == LaneState::Backoff
                && status
                    .restart_not_before_mono_ns
                    .is_some_and(|deadline| now_mono_ns >= deadline)
                && !circuit_blocked
            {
                requests.push(RestartRequest {
                    lane,
                    not_before_mono_ns: status.restart_not_before_mono_ns.unwrap_or(now_mono_ns),
                    next_launch_attempt: status.launch_attempt.saturating_add(1),
                });
            }
        }
        Ok(requests)
    }

    pub fn advance_time(&mut self, now_mono_ns: u64) -> Result<CoverageTransition> {
        self.advance_clock(now_mono_ns)?;
        for status in self.lanes.values_mut() {
            if status.state == LaneState::Ready
                && status.ready_mono_ns.is_some_and(|ready| {
                    now_mono_ns.saturating_sub(ready) >= self.config.backoff_reset_after_ns
                })
            {
                status.consecutive_failures = 0;
            }
        }
        self.recompute_coverage(now_mono_ns)
    }

    pub fn terminate(&mut self, now_mono_ns: u64) -> Result<CoverageTransition> {
        self.advance_clock(now_mono_ns)?;
        let previous = self.coverage;
        self.terminal = true;
        for status in self.lanes.values_mut() {
            status.state = LaneState::Terminal;
            status.restart_not_before_mono_ns = None;
        }
        self.coverage = CoverageState::Terminal;
        Ok(CoverageTransition {
            previous,
            current: CoverageState::Terminal,
            opened_gap: None,
            closed_gap: None,
        })
    }

    fn advance_clock(&mut self, now_mono_ns: u64) -> Result<()> {
        if now_mono_ns < self.last_mono_ns {
            return Err(format!(
                "hot-redundancy monotonic time regressed: {} -> {now_mono_ns}",
                self.last_mono_ns
            ));
        }
        self.last_mono_ns = now_mono_ns;
        Ok(())
    }

    fn recompute_coverage(&mut self, now_mono_ns: u64) -> Result<CoverageTransition> {
        let previous = self.coverage;
        let ready = self
            .lanes
            .values()
            .filter(|status| status.state == LaneState::Ready)
            .count();
        let current = if self.terminal {
            CoverageState::Terminal
        } else {
            match ready {
                2 => CoverageState::Redundant,
                1 => CoverageState::Degraded,
                _ if self.ever_ready => CoverageState::Gap,
                _ => CoverageState::Starting,
            }
        };
        let mut opened_gap = None;
        let mut closed_gap = None;
        if current == CoverageState::Gap && self.open_gap.is_none() {
            let gap = GapInterval {
                gap_id: self.next_gap_id,
                opened_mono_ns: now_mono_ns,
                closed_mono_ns: None,
                unavailable_ns: None,
            };
            self.next_gap_id = self
                .next_gap_id
                .checked_add(1)
                .ok_or_else(|| "gap identity overflow".to_owned())?;
            self.open_gap = Some(gap.clone());
            opened_gap = Some(gap);
        } else if ready != 0
            && let Some(mut gap) = self.open_gap.take()
        {
            gap.closed_mono_ns = Some(now_mono_ns);
            gap.unavailable_ns = Some(now_mono_ns.saturating_sub(gap.opened_mono_ns));
            closed_gap = Some(gap);
        }
        self.coverage = current;
        Ok(CoverageTransition {
            previous,
            current,
            opened_gap,
            closed_gap,
        })
    }
}

fn reconnect_delay_ns(
    config: &HotRedundancyConfig,
    lane: CaptureLane,
    launch_attempt: u64,
    consecutive_failures: u32,
    run_token: &str,
) -> u64 {
    let shift = consecutive_failures.saturating_sub(1).min(63);
    let multiplier = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
    let base = config
        .backoff_initial_ns
        .saturating_mul(multiplier)
        .min(config.backoff_max_ns);
    if config.jitter_max_ns == 0 {
        return base;
    }
    let mut hash = Sha256::new();
    hash.update(lane.as_str().as_bytes());
    hash.update(launch_attempt.to_le_bytes());
    hash.update(consecutive_failures.to_le_bytes());
    hash.update(run_token.as_bytes());
    let digest = hash.finalize();
    let sample = u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 has eight bytes"));
    let jitter = sample % config.jitter_max_ns.saturating_add(1);
    base.saturating_add(jitter).min(config.backoff_max_ns)
}
