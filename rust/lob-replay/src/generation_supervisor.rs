//! Pure lifecycle model for continuous, immutable raw capture.
//!
//! This module deliberately owns no sockets, files, canonical publisher or
//! market features. Callers persist the returned lifecycle facts separately
//! and provide a fresh identity whenever a candidate is requested.

use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RawSupervisorState {
    Live,
    Handover,
    Gap,
    Recovering,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GenerationRole {
    Active,
    Candidate,
    Draining,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamKind {
    Depth,
    Trade,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateReason {
    PlannedRotation,
    ServerShutdown,
    RetryAfterFailure,
    RecoveryAfterGap,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateFact {
    DepthConnected,
    TradeConnected,
    SnapshotPersisted,
    DepthDurable,
    TradeDurable,
    DepthContinuityProven,
    TradeContinuityProven,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GenerationIdentity {
    pub generation_id: String,
    pub depth_epoch: String,
    pub trade_epoch: String,
}

impl GenerationIdentity {
    pub fn new(generation_id: &str, depth_epoch: &str, trade_epoch: &str) -> Result<Self> {
        let identity = Self {
            generation_id: generation_id.to_owned(),
            depth_epoch: depth_epoch.to_owned(),
            trade_epoch: trade_epoch.to_owned(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.generation_id.trim().is_empty()
            || self.depth_epoch.trim().is_empty()
            || self.trade_epoch.trim().is_empty()
            || self.generation_id == self.depth_epoch
            || self.generation_id == self.trade_epoch
            || self.depth_epoch == self.trade_epoch
        {
            return Err(
                "generation ID and stream epochs must be distinct and non-empty".to_owned(),
            );
        }
        Ok(())
    }

    fn contains_epoch(&self, epoch: &str) -> bool {
        self.depth_epoch == epoch || self.trade_epoch == epoch
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateReadiness {
    pub depth_connected: bool,
    pub trade_connected: bool,
    pub snapshot_persisted: bool,
    pub depth_durable: bool,
    pub trade_durable: bool,
    pub depth_continuity_proven: bool,
    pub trade_continuity_proven: bool,
}

impl CandidateReadiness {
    fn empty() -> Self {
        Self {
            depth_connected: false,
            trade_connected: false,
            snapshot_persisted: false,
            depth_durable: false,
            trade_durable: false,
            depth_continuity_proven: false,
            trade_continuity_proven: false,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.depth_connected
            && self.trade_connected
            && self.snapshot_persisted
            && self.depth_durable
            && self.trade_durable
            && self.depth_continuity_proven
            && self.trade_continuity_proven
    }

    fn observe(&mut self, fact: CandidateFact) -> Result<bool> {
        let target = match fact {
            CandidateFact::DepthConnected => &mut self.depth_connected,
            CandidateFact::TradeConnected => &mut self.trade_connected,
            CandidateFact::SnapshotPersisted => {
                if !self.depth_connected {
                    return Err("snapshot cannot be persisted before depth connects".to_owned());
                }
                &mut self.snapshot_persisted
            }
            CandidateFact::DepthDurable => {
                if !self.depth_connected {
                    return Err("depth cannot become durable before it connects".to_owned());
                }
                &mut self.depth_durable
            }
            CandidateFact::TradeDurable => {
                if !self.trade_connected {
                    return Err("trade cannot become durable before it connects".to_owned());
                }
                &mut self.trade_durable
            }
            CandidateFact::DepthContinuityProven => {
                if !self.snapshot_persisted || !self.depth_durable {
                    return Err(
                        "depth continuity requires a durable snapshot-backed depth prefix"
                            .to_owned(),
                    );
                }
                &mut self.depth_continuity_proven
            }
            CandidateFact::TradeContinuityProven => {
                if !self.trade_durable {
                    return Err("trade continuity requires a durable trade prefix".to_owned());
                }
                &mut self.trade_continuity_proven
            }
        };
        if *target {
            return Ok(false);
        }
        *target = true;
        Ok(true)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GenerationStatus {
    pub identity: GenerationIdentity,
    pub role: GenerationRole,
    pub opened_mono_ns: u64,
    pub reason: CandidateReason,
    pub readiness: CandidateReadiness,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSupervisorConfig {
    pub segment_interval_ns: u64,
    pub planned_rotation_age_ns: u64,
    pub active_max_age_ns: u64,
    pub candidate_timeout_ns: u64,
    pub backoff_initial_ns: u64,
    pub backoff_max_ns: u64,
}

impl RawSupervisorConfig {
    pub fn validate(&self) -> Result<()> {
        if self.segment_interval_ns == 0
            || self.planned_rotation_age_ns == 0
            || self.active_max_age_ns == 0
            || self.candidate_timeout_ns == 0
            || self.backoff_initial_ns == 0
            || self.backoff_max_ns == 0
            || self.planned_rotation_age_ns >= self.active_max_age_ns
            || self.backoff_initial_ns > self.backoff_max_ns
        {
            return Err("invalid raw generation supervisor durations".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CandidateRequest {
    pub reason: CandidateReason,
    pub not_before_mono_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimeAdvance {
    pub segment_rollovers: u64,
    pub current_segment_index: u64,
    pub candidate_request: Option<CandidateRequest>,
    pub candidate_timed_out: bool,
    pub entered_gap: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerShutdownOutcome {
    CandidateStarted,
    CandidateAlreadyInProgress,
    IgnoredNonActiveEpoch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectOutcome {
    ActiveFailed,
    CandidateFailed,
    DrainingClosed,
    AlreadyTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Promotion {
    pub predecessor: Option<GenerationIdentity>,
    pub successor: GenerationIdentity,
    pub gap_was_open: bool,
}

/// Pure campaign-raw lifecycle. The segment clock is campaign-scoped and does
/// not mutate connection or generation identity.
#[derive(Debug)]
pub struct RawGenerationSupervisor {
    config: RawSupervisorConfig,
    state: RawSupervisorState,
    clock_origin_ns: u64,
    last_mono_ns: u64,
    current_segment_index: u64,
    active: Option<GenerationStatus>,
    candidate: Option<GenerationStatus>,
    draining: Vec<GenerationStatus>,
    used_tokens: BTreeSet<String>,
    pending_reason: Option<CandidateReason>,
    next_candidate_not_before_ns: Option<u64>,
    retry_attempt: u32,
    gap_count: u64,
}

impl RawGenerationSupervisor {
    pub fn new(
        config: RawSupervisorConfig,
        initial: GenerationIdentity,
        now_mono_ns: u64,
    ) -> Result<Self> {
        config.validate()?;
        initial.validate()?;
        let used_tokens = BTreeSet::from([
            initial.generation_id.clone(),
            initial.depth_epoch.clone(),
            initial.trade_epoch.clone(),
        ]);
        Ok(Self {
            config,
            state: RawSupervisorState::Live,
            clock_origin_ns: now_mono_ns,
            last_mono_ns: now_mono_ns,
            current_segment_index: 0,
            active: Some(GenerationStatus {
                identity: initial,
                role: GenerationRole::Active,
                opened_mono_ns: now_mono_ns,
                reason: CandidateReason::RecoveryAfterGap,
                readiness: CandidateReadiness {
                    depth_connected: true,
                    trade_connected: true,
                    snapshot_persisted: true,
                    depth_durable: true,
                    trade_durable: true,
                    depth_continuity_proven: true,
                    trade_continuity_proven: true,
                },
            }),
            candidate: None,
            draining: Vec::new(),
            used_tokens,
            pending_reason: None,
            next_candidate_not_before_ns: None,
            retry_attempt: 0,
            gap_count: 0,
        })
    }

    pub fn state(&self) -> RawSupervisorState {
        self.state
    }

    pub fn active(&self) -> Option<&GenerationStatus> {
        self.active.as_ref()
    }

    pub fn candidate(&self) -> Option<&GenerationStatus> {
        self.candidate.as_ref()
    }

    pub fn draining(&self) -> &[GenerationStatus] {
        &self.draining
    }

    pub fn current_segment_index(&self) -> u64 {
        self.current_segment_index
    }

    pub fn gap_count(&self) -> u64 {
        self.gap_count
    }

    pub fn qualification_has_gap(&self) -> bool {
        self.gap_count != 0
    }

    pub fn next_candidate_not_before_ns(&self) -> Option<u64> {
        self.next_candidate_not_before_ns
    }

    pub fn advance_time(&mut self, now_mono_ns: u64) -> Result<TimeAdvance> {
        self.validate_monotonic(now_mono_ns)?;
        self.last_mono_ns = now_mono_ns;

        let elapsed = now_mono_ns - self.clock_origin_ns;
        let target_segment = elapsed / self.config.segment_interval_ns;
        let segment_rollovers = target_segment
            .checked_sub(self.current_segment_index)
            .ok_or_else(|| "segment clock regressed".to_owned())?;
        self.current_segment_index = target_segment;

        let mut entered_gap = false;
        let mut candidate_timed_out = false;
        if self.active.as_ref().is_some_and(|active| {
            now_mono_ns - active.opened_mono_ns >= self.config.active_max_age_ns
        }) {
            self.enter_gap(
                now_mono_ns,
                "active generation reached its hard monotonic deadline",
            )?;
            entered_gap = true;
        } else if self.candidate.as_ref().is_some_and(|candidate| {
            now_mono_ns - candidate.opened_mono_ns >= self.config.candidate_timeout_ns
        }) {
            self.fail_candidate(now_mono_ns)?;
            candidate_timed_out = true;
        }

        let candidate_request = self.candidate_request(now_mono_ns);
        Ok(TimeAdvance {
            segment_rollovers,
            current_segment_index: self.current_segment_index,
            candidate_request,
            candidate_timed_out,
            entered_gap,
        })
    }

    pub fn start_due_candidate(
        &mut self,
        identity: GenerationIdentity,
        now_mono_ns: u64,
    ) -> Result<()> {
        identity.validate()?;
        let report = self.advance_time(now_mono_ns)?;
        let request = report
            .candidate_request
            .ok_or_else(|| "no candidate is due".to_owned())?;
        self.start_candidate(identity, request.reason, now_mono_ns)
    }

    pub fn on_server_shutdown(
        &mut self,
        source_epoch: &str,
        identity: GenerationIdentity,
        now_mono_ns: u64,
    ) -> Result<ServerShutdownOutcome> {
        identity.validate()?;
        self.advance_time(now_mono_ns)?;
        let Some(active) = &self.active else {
            return Ok(ServerShutdownOutcome::IgnoredNonActiveEpoch);
        };
        if !active.identity.contains_epoch(source_epoch) {
            return Ok(ServerShutdownOutcome::IgnoredNonActiveEpoch);
        }
        if self.candidate.is_some() {
            return Ok(ServerShutdownOutcome::CandidateAlreadyInProgress);
        }
        self.start_candidate(identity, CandidateReason::ServerShutdown, now_mono_ns)?;
        Ok(ServerShutdownOutcome::CandidateStarted)
    }

    pub fn observe_candidate_fact(
        &mut self,
        fact: CandidateFact,
        now_mono_ns: u64,
    ) -> Result<bool> {
        self.advance_time(now_mono_ns)?;
        self.candidate
            .as_mut()
            .ok_or_else(|| "candidate fact observed without a candidate".to_owned())?
            .readiness
            .observe(fact)
    }

    pub fn promote_candidate(&mut self, now_mono_ns: u64) -> Result<Promotion> {
        self.advance_time(now_mono_ns)?;
        let candidate = self
            .candidate
            .as_ref()
            .ok_or_else(|| "no candidate to promote".to_owned())?;
        if !candidate.readiness.is_ready() {
            return Err("candidate lacks complete raw continuity evidence".to_owned());
        }

        let mut successor = self.candidate.take().expect("candidate checked above");
        successor.role = GenerationRole::Active;
        let gap_was_open = self.active.is_none();
        let predecessor = if let Some(mut predecessor) = self.active.take() {
            predecessor.role = GenerationRole::Draining;
            let identity = predecessor.identity.clone();
            self.draining.push(predecessor);
            Some(identity)
        } else {
            None
        };
        let successor_identity = successor.identity.clone();
        self.active = Some(successor);
        self.state = RawSupervisorState::Live;
        self.pending_reason = None;
        self.next_candidate_not_before_ns = None;
        self.retry_attempt = 0;
        Ok(Promotion {
            predecessor,
            successor: successor_identity,
            gap_was_open,
        })
    }

    pub fn close_draining(&mut self, generation_id: &str, now_mono_ns: u64) -> Result<bool> {
        self.advance_time(now_mono_ns)?;
        let Some(index) = self
            .draining
            .iter()
            .position(|generation| generation.identity.generation_id == generation_id)
        else {
            return Ok(false);
        };
        self.draining.remove(index);
        Ok(true)
    }

    pub fn disconnect_epoch(
        &mut self,
        epoch: &str,
        reason: &str,
        now_mono_ns: u64,
    ) -> Result<DisconnectOutcome> {
        if reason.trim().is_empty() {
            return Err("disconnect reason must not be empty".to_owned());
        }
        self.advance_time(now_mono_ns)?;
        if self
            .active
            .as_ref()
            .is_some_and(|generation| generation.identity.contains_epoch(epoch))
        {
            self.enter_gap(now_mono_ns, reason)?;
            return Ok(DisconnectOutcome::ActiveFailed);
        }
        if self
            .candidate
            .as_ref()
            .is_some_and(|generation| generation.identity.contains_epoch(epoch))
        {
            self.fail_candidate(now_mono_ns)?;
            return Ok(DisconnectOutcome::CandidateFailed);
        }
        if let Some(index) = self
            .draining
            .iter()
            .position(|generation| generation.identity.contains_epoch(epoch))
        {
            self.draining.remove(index);
            return Ok(DisconnectOutcome::DrainingClosed);
        }
        if self.used_tokens.contains(epoch) {
            return Ok(DisconnectOutcome::AlreadyTerminal);
        }
        Err(format!("disconnect references unknown epoch: {epoch}"))
    }

    fn validate_monotonic(&self, now_mono_ns: u64) -> Result<()> {
        if now_mono_ns < self.last_mono_ns {
            return Err(format!(
                "supervisor monotonic time regressed: {} -> {now_mono_ns}",
                self.last_mono_ns
            ));
        }
        Ok(())
    }

    fn candidate_request(&self, now_mono_ns: u64) -> Option<CandidateRequest> {
        if self.candidate.is_some() {
            return None;
        }
        let not_before = self.next_candidate_not_before_ns.unwrap_or(now_mono_ns);
        if now_mono_ns < not_before {
            return None;
        }
        if self.active.is_none() {
            return Some(CandidateRequest {
                reason: CandidateReason::RecoveryAfterGap,
                not_before_mono_ns: not_before,
            });
        }
        if let Some(reason) = self.pending_reason {
            return Some(CandidateRequest {
                reason,
                not_before_mono_ns: not_before,
            });
        }
        let active = self.active.as_ref().expect("active checked above");
        (now_mono_ns - active.opened_mono_ns >= self.config.planned_rotation_age_ns).then_some(
            CandidateRequest {
                reason: CandidateReason::PlannedRotation,
                not_before_mono_ns: now_mono_ns,
            },
        )
    }

    fn start_candidate(
        &mut self,
        identity: GenerationIdentity,
        reason: CandidateReason,
        now_mono_ns: u64,
    ) -> Result<()> {
        if self.candidate.is_some() {
            return Err("a candidate already exists".to_owned());
        }
        self.register_identity(&identity)?;
        self.candidate = Some(GenerationStatus {
            identity,
            role: GenerationRole::Candidate,
            opened_mono_ns: now_mono_ns,
            reason,
            readiness: CandidateReadiness::empty(),
        });
        self.pending_reason = None;
        self.next_candidate_not_before_ns = None;
        self.state = if self.active.is_some() {
            RawSupervisorState::Handover
        } else {
            RawSupervisorState::Recovering
        };
        Ok(())
    }

    fn register_identity(&mut self, identity: &GenerationIdentity) -> Result<()> {
        identity.validate()?;
        for token in [
            &identity.generation_id,
            &identity.depth_epoch,
            &identity.trade_epoch,
        ] {
            if self.used_tokens.contains(token) {
                return Err(format!(
                    "generation identity token cannot be reused: {token}"
                ));
            }
        }
        self.used_tokens.insert(identity.generation_id.clone());
        self.used_tokens.insert(identity.depth_epoch.clone());
        self.used_tokens.insert(identity.trade_epoch.clone());
        Ok(())
    }

    fn fail_candidate(&mut self, now_mono_ns: u64) -> Result<()> {
        if self.candidate.take().is_none() {
            return Err("no candidate to fail".to_owned());
        }
        self.schedule_retry(now_mono_ns, CandidateReason::RetryAfterFailure);
        self.state = if self.active.is_some() {
            RawSupervisorState::Live
        } else {
            RawSupervisorState::Gap
        };
        Ok(())
    }

    fn enter_gap(&mut self, now_mono_ns: u64, _reason: &str) -> Result<()> {
        if self.active.take().is_none() {
            return Err("cannot fail an absent active generation".to_owned());
        }
        self.candidate = None;
        self.gap_count = self
            .gap_count
            .checked_add(1)
            .ok_or_else(|| "gap count overflow".to_owned())?;
        self.schedule_retry(now_mono_ns, CandidateReason::RecoveryAfterGap);
        self.state = RawSupervisorState::Gap;
        Ok(())
    }

    fn schedule_retry(&mut self, now_mono_ns: u64, reason: CandidateReason) {
        let shift = self.retry_attempt.min(63);
        let multiplier = 1_u64.checked_shl(shift).unwrap_or(u64::MAX);
        let delay = self
            .config
            .backoff_initial_ns
            .saturating_mul(multiplier)
            .min(self.config.backoff_max_ns);
        self.retry_attempt = self.retry_attempt.saturating_add(1);
        self.pending_reason = Some(reason);
        self.next_candidate_not_before_ns = Some(now_mono_ns.saturating_add(delay));
    }
}
