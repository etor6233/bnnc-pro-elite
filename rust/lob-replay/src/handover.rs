//! Pure, deterministic connection-epoch handover state machine.
//!
//! This module performs no I/O. Network and snapshot handlers must translate
//! observed facts into these transitions and cannot promote a candidate epoch
//! unless both independently reconstructed books converge exactly.

use crate::Result;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpochState {
    Connecting,
    Buffering,
    Snapshotting,
    Syncing,
    Live,
    Active,
    Draining,
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicationState {
    Unavailable,
    Live,
    Handover,
    Gap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EpochStatus {
    pub epoch: String,
    pub state: EpochState,
    pub final_update_id: Option<u64>,
    pub state_sha256: Option<String>,
}

impl EpochStatus {
    fn connecting(epoch: &str) -> Result<Self> {
        if epoch.trim().is_empty() {
            return Err("connection epoch must not be empty".to_owned());
        }
        Ok(Self {
            epoch: epoch.to_owned(),
            state: EpochState::Connecting,
            final_update_id: None,
            state_sha256: None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HandoverEvent {
    pub event_index: u64,
    pub action: &'static str,
    pub epoch: String,
    pub from: Option<EpochState>,
    pub to: Option<EpochState>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EpochFailure {
    pub epoch: String,
    pub prior_state: EpochState,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct HandoverController {
    pub symbol: String,
    pub publication: PublicationState,
    pub active: EpochStatus,
    pub candidate: Option<EpochStatus>,
    pub draining: Option<EpochStatus>,
    pub failures: Vec<EpochFailure>,
    pub events: Vec<HandoverEvent>,
    pub used_epochs: BTreeSet<String>,
    next_event_index: u64,
}

impl HandoverController {
    pub fn new(symbol: &str, initial_epoch: &str) -> Result<Self> {
        if !matches!(symbol, "BTCUSDT" | "ETHUSDT") {
            return Err(format!("symbol outside scope: {symbol}"));
        }
        let active = EpochStatus::connecting(initial_epoch)?;
        let used_epochs = BTreeSet::from([initial_epoch.to_owned()]);
        let mut controller = Self {
            symbol: symbol.to_owned(),
            publication: PublicationState::Unavailable,
            active,
            candidate: None,
            draining: None,
            failures: Vec::new(),
            events: Vec::new(),
            used_epochs,
            next_event_index: 0,
        };
        controller.record(
            "BEGIN_INITIAL_EPOCH",
            initial_epoch,
            None,
            Some(EpochState::Connecting),
            None,
        );
        Ok(controller)
    }

    pub fn transition_epoch(&mut self, epoch: &str, target: EpochState) -> Result<()> {
        let current = self.epoch(epoch)?.state;
        let allowed = matches!(
            (current, target),
            (EpochState::Connecting, EpochState::Buffering)
                | (EpochState::Buffering, EpochState::Snapshotting)
                | (EpochState::Snapshotting, EpochState::Syncing)
        );
        if !allowed {
            return Err(format!(
                "illegal epoch transition for {epoch}: {current:?} -> {target:?}"
            ));
        }
        self.epoch_mut(epoch)?.state = target;
        self.record("TRANSITION", epoch, Some(current), Some(target), None);
        Ok(())
    }

    pub fn mark_live(&mut self, epoch: &str, update_id: u64, digest: &str) -> Result<()> {
        validate_digest(digest)?;
        let current = self.epoch(epoch)?.state;
        if current != EpochState::Syncing {
            return Err(format!("epoch {epoch} cannot become LIVE from {current:?}"));
        }
        let status = self.epoch_mut(epoch)?;
        status.state = EpochState::Live;
        status.final_update_id = Some(update_id);
        status.state_sha256 = Some(digest.to_owned());
        self.record(
            "BOOK_LIVE",
            epoch,
            Some(current),
            Some(EpochState::Live),
            None,
        );
        Ok(())
    }

    pub fn activate_initial(&mut self) -> Result<()> {
        if self.publication != PublicationState::Unavailable
            || self.candidate.is_some()
            || self.draining.is_some()
            || self.active.state != EpochState::Live
        {
            return Err("initial epoch is not ready for activation".to_owned());
        }
        let epoch = self.active.epoch.clone();
        self.active.state = EpochState::Active;
        self.publication = PublicationState::Live;
        self.record(
            "ACTIVATE_INITIAL",
            &epoch,
            Some(EpochState::Live),
            Some(EpochState::Active),
            None,
        );
        Ok(())
    }

    pub fn begin_handover(&mut self, candidate_epoch: &str) -> Result<()> {
        if self.publication != PublicationState::Live || self.active.state != EpochState::Active {
            return Err("handover requires an active LIVE publication".to_owned());
        }
        if self.candidate.is_some() || self.draining.is_some() {
            return Err("another candidate or draining epoch already exists".to_owned());
        }
        if self.epoch_was_used(candidate_epoch) {
            return Err(format!(
                "connection epoch cannot be reused: {candidate_epoch}"
            ));
        }
        self.candidate = Some(EpochStatus::connecting(candidate_epoch)?);
        self.used_epochs.insert(candidate_epoch.to_owned());
        self.publication = PublicationState::Handover;
        self.record(
            "BEGIN_CANDIDATE_EPOCH",
            candidate_epoch,
            None,
            Some(EpochState::Connecting),
            None,
        );
        Ok(())
    }

    pub fn observe_book(&mut self, epoch: &str, update_id: u64, digest: &str) -> Result<()> {
        validate_digest(digest)?;
        let status = self.epoch(epoch)?;
        if !matches!(
            status.state,
            EpochState::Live | EpochState::Active | EpochState::Draining
        ) {
            return Err(format!(
                "epoch {epoch} cannot publish book observations while {:?}",
                status.state
            ));
        }
        if let Some(previous_id) = status.final_update_id {
            if update_id < previous_id {
                let reason = format!("book update ID regressed from {previous_id} to {update_id}");
                self.fail_epoch(epoch, &reason)?;
                return Err(reason);
            }
            if update_id == previous_id {
                if status.state_sha256.as_deref() == Some(digest) {
                    return Ok(());
                }
                let reason = format!("same update ID {update_id} produced a different digest");
                self.fail_epoch(epoch, &reason)?;
                return Err(reason);
            }
        }
        let target = self.epoch_mut(epoch)?;
        target.final_update_id = Some(update_id);
        target.state_sha256 = Some(digest.to_owned());
        self.record("BOOK_ADVANCE", epoch, None, None, None);
        Ok(())
    }

    pub fn candidate_converged(&self) -> bool {
        let Some(candidate) = &self.candidate else {
            return false;
        };
        candidate.state == EpochState::Live
            && self.active.state == EpochState::Active
            && candidate.final_update_id == self.active.final_update_id
            && candidate.state_sha256 == self.active.state_sha256
            && candidate.final_update_id.is_some()
    }

    pub fn promote_candidate(&mut self) -> Result<()> {
        if self.publication != PublicationState::Handover || !self.candidate_converged() {
            return Err("candidate cannot be promoted without exact convergence".to_owned());
        }
        let mut candidate = self
            .candidate
            .take()
            .ok_or_else(|| "candidate disappeared".to_owned())?;
        let old_epoch = self.active.epoch.clone();
        let new_epoch = candidate.epoch.clone();
        self.active.state = EpochState::Draining;
        candidate.state = EpochState::Active;
        let old = std::mem::replace(&mut self.active, candidate);
        self.draining = Some(old);
        self.publication = PublicationState::Live;
        self.record(
            "PROMOTE_CANDIDATE",
            &new_epoch,
            Some(EpochState::Live),
            Some(EpochState::Active),
            Some(format!("replaced {old_epoch} after exact convergence")),
        );
        Ok(())
    }

    pub fn close_draining(&mut self) -> Result<()> {
        let mut draining = self
            .draining
            .take()
            .ok_or_else(|| "no draining epoch".to_owned())?;
        if draining.state != EpochState::Draining {
            return Err("retired epoch is not draining".to_owned());
        }
        let epoch = draining.epoch.clone();
        draining.state = EpochState::Closed;
        self.record(
            "CLOSE_DRAINING",
            &epoch,
            Some(EpochState::Draining),
            Some(EpochState::Closed),
            None,
        );
        Ok(())
    }

    pub fn fail_epoch(&mut self, epoch: &str, reason: &str) -> Result<()> {
        if reason.trim().is_empty() {
            return Err("failure reason must not be empty".to_owned());
        }
        if self.active.epoch == epoch {
            let prior = self.active.state;
            if matches!(prior, EpochState::Failed | EpochState::Closed) {
                return Err(format!("active epoch is already terminal: {prior:?}"));
            }
            self.active.state = EpochState::Failed;
            self.publication = PublicationState::Gap;
            self.failures.push(EpochFailure {
                epoch: epoch.to_owned(),
                prior_state: prior,
                reason: reason.to_owned(),
            });
            self.record(
                "ACTIVE_FAILED",
                epoch,
                Some(prior),
                Some(EpochState::Failed),
                Some(reason.to_owned()),
            );
            return Ok(());
        }
        if self
            .draining
            .as_ref()
            .is_some_and(|item| item.epoch == epoch)
        {
            let mut draining = self.draining.take().expect("draining epoch checked above");
            let prior = draining.state;
            draining.state = EpochState::Failed;
            self.failures.push(EpochFailure {
                epoch: epoch.to_owned(),
                prior_state: prior,
                reason: reason.to_owned(),
            });
            self.record(
                "DRAINING_FAILED",
                epoch,
                Some(prior),
                Some(EpochState::Failed),
                Some(reason.to_owned()),
            );
            return Ok(());
        }
        if self
            .candidate
            .as_ref()
            .is_some_and(|item| item.epoch == epoch)
        {
            let mut candidate = self.candidate.take().expect("candidate checked above");
            let prior = candidate.state;
            candidate.state = EpochState::Failed;
            self.failures.push(EpochFailure {
                epoch: epoch.to_owned(),
                prior_state: prior,
                reason: reason.to_owned(),
            });
            self.publication = PublicationState::Live;
            self.record(
                "CANDIDATE_FAILED",
                epoch,
                Some(prior),
                Some(EpochState::Failed),
                Some(reason.to_owned()),
            );
            return Ok(());
        }
        Err(format!("unknown or non-failable epoch: {epoch}"))
    }

    pub fn rotation_deadline_expired(&mut self, reason: &str) -> Result<()> {
        if self.publication != PublicationState::Handover {
            return Err("rotation deadline applies only during handover".to_owned());
        }
        let active_epoch = self.active.epoch.clone();
        self.fail_epoch(&active_epoch, reason)
    }

    fn epoch(&self, epoch: &str) -> Result<&EpochStatus> {
        if self.active.epoch == epoch {
            return Ok(&self.active);
        }
        if let Some(candidate) = &self.candidate
            && candidate.epoch == epoch
        {
            return Ok(candidate);
        }
        if let Some(draining) = &self.draining
            && draining.epoch == epoch
        {
            return Ok(draining);
        }
        Err(format!("unknown connection epoch: {epoch}"))
    }

    fn epoch_mut(&mut self, epoch: &str) -> Result<&mut EpochStatus> {
        if self.active.epoch == epoch {
            return Ok(&mut self.active);
        }
        if let Some(candidate) = &mut self.candidate
            && candidate.epoch == epoch
        {
            return Ok(candidate);
        }
        if let Some(draining) = &mut self.draining
            && draining.epoch == epoch
        {
            return Ok(draining);
        }
        Err(format!("unknown connection epoch: {epoch}"))
    }

    fn epoch_was_used(&self, epoch: &str) -> bool {
        self.used_epochs.contains(epoch)
    }

    fn record(
        &mut self,
        action: &'static str,
        epoch: &str,
        from: Option<EpochState>,
        to: Option<EpochState>,
        reason: Option<String>,
    ) {
        self.events.push(HandoverEvent {
            event_index: self.next_event_index,
            action,
            epoch: epoch.to_owned(),
            from,
            to,
            reason,
        });
        self.next_event_index += 1;
    }
}

fn validate_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("state digest must be 64 lowercase hexadecimal characters".to_owned());
    }
    Ok(())
}
