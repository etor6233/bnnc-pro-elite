//! Transactional integration between convergence, durable ownership and publication.

use crate::Result;
use crate::boundary::BoundaryStreamKind;
use crate::handover::{EpochState, HandoverController, PublicationState};
use crate::ownership::{
    CanonicalSourcePointer, CommittedBoundaryProofV1, LivePublicationState, OwnershipLedgerAckV1,
    OwnershipLedgerWriter, derive_ownership_activation, scan_ownership_ledger,
};
use serde::Serialize;
use std::fs::File;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LiveActivationReportV1 {
    pub schema: &'static str,
    pub status: &'static str,
    pub depth_boundary_commit_sha256: String,
    pub trade_boundary_commit_sha256: String,
    pub prepare_ack: OwnershipLedgerAckV1,
    pub activate_ack: OwnershipLedgerAckV1,
    pub active_owner_sha256: String,
    pub active_generation: String,
    pub fencing_token: u64,
}

#[derive(Debug)]
pub struct LiveRotationCoordinator {
    pub handover: HandoverController,
    pub pointer: CanonicalSourcePointer,
}

impl LiveRotationCoordinator {
    pub fn new(handover: HandoverController, pointer: CanonicalSourcePointer) -> Result<Self> {
        if !matches!(
            handover.publication,
            PublicationState::Live | PublicationState::Handover
        ) || handover.active.state != EpochState::Active
            || pointer.state != LivePublicationState::Live
            || handover.symbol != pointer.owner.symbol
            || handover.active.epoch != pointer.owner.depth_epoch
        {
            return Err(
                "handover and source pointer do not describe the same active publication"
                    .to_owned(),
            );
        }
        Ok(Self { handover, pointer })
    }

    /// Transfer authority only after both boundary journals are already
    /// committed, PREPARED and ACTIVATED are independently durable, and a full
    /// ledger rescan recovers the successor. No caller-visible promotion occurs
    /// before that sequence completes.
    pub fn activate_committed(
        &mut self,
        ledger: &mut OwnershipLedgerWriter<File>,
        ledger_path: &Path,
        activation_id: &str,
        successor_generation: &str,
        depth: &CommittedBoundaryProofV1,
        trade: &CommittedBoundaryProofV1,
    ) -> Result<LiveActivationReportV1> {
        if !self.handover.candidate_converged() {
            return Err(
                "live ownership activation requires exact candidate convergence".to_owned(),
            );
        }
        let candidate = self
            .handover
            .candidate
            .as_ref()
            .ok_or_else(|| "converged candidate disappeared".to_owned())?;
        if depth.boundary.stream_kind != BoundaryStreamKind::Depth
            || trade.boundary.stream_kind != BoundaryStreamKind::Trade
            || depth.boundary.predecessor_epoch != self.handover.active.epoch
            || depth.boundary.successor_epoch != candidate.epoch
            || self.handover.active.final_update_id != Some(depth.boundary.boundary_sequence)
            || candidate.final_update_id != Some(depth.boundary.boundary_sequence)
            || self.handover.active.state_sha256.as_deref()
                != Some(depth.boundary.boundary_sha256.as_str())
            || candidate.state_sha256.as_deref() != Some(depth.boundary.boundary_sha256.as_str())
        {
            return Err("committed depth proof does not match converged live books".to_owned());
        }
        if self.pointer.owner.depth_epoch != depth.boundary.predecessor_epoch
            || self.pointer.owner.trade_epoch != trade.boundary.predecessor_epoch
            || self.pointer.owner.depth_last_sequence != depth.boundary.boundary_sequence
            || self.pointer.owner.trade_last_sequence != trade.boundary.boundary_sequence
        {
            return Err(
                "committed proofs do not continue the current canonical pointer".to_owned(),
            );
        }

        let activation = derive_ownership_activation(
            activation_id,
            successor_generation,
            &self.pointer.owner,
            depth,
            trade,
        )?;
        let prepare_ack = ledger.prepare(activation.clone())?;
        let activate_ack = ledger.activate(&activation.activation_id)?;
        // The durable ledger now owns B. Until a clean rescan proves that exact
        // state, the in-memory A pointer must be unable to publish.
        self.pointer.state = LivePublicationState::Gap;
        self.pointer.gap_reason = Some("durable activation awaiting verified rescan".to_owned());
        let scan = scan_ownership_ledger(ledger_path)?;
        let recovered = CanonicalSourcePointer::recover(&scan, Some((depth, trade)))?;
        if recovered.owner.depth_epoch != candidate.epoch
            || recovered.owner.trade_epoch != trade.boundary.successor_epoch
            || recovered.owner.fencing_token != self.pointer.owner.fencing_token + 1
        {
            return Err(
                "durable ownership rescan did not recover the expected successor".to_owned(),
            );
        }

        // All fallible durable work and consistency checks precede the in-memory
        // source switch. promote_candidate is now guaranteed by the unchanged
        // convergence state checked above.
        self.pointer = recovered;
        if let Err(error) = self.handover.promote_candidate() {
            let reason = format!("controller promotion failed after durable activation: {error}");
            let _ = self
                .pointer
                .fail_active(&depth.boundary.successor_epoch, &reason);
            return Err(reason);
        }
        Ok(LiveActivationReportV1 {
            schema: "LiveActivationReportV1",
            status: "ACTIVATED_LIVE_AUTHORITY",
            depth_boundary_commit_sha256: depth.commit_record_sha256.clone(),
            trade_boundary_commit_sha256: trade.commit_record_sha256.clone(),
            prepare_ack,
            activate_ack,
            active_owner_sha256: self.pointer.owner.digest()?,
            active_generation: self.pointer.owner.generation_id.clone(),
            fencing_token: self.pointer.owner.fencing_token,
        })
    }

    pub fn accept_observation(
        &mut self,
        kind: BoundaryStreamKind,
        epoch: &str,
        fencing_token: u64,
        first_sequence: u64,
        final_sequence: u64,
    ) -> Result<()> {
        if kind == BoundaryStreamKind::Depth {
            if self.handover.publication != PublicationState::Live
                || self.handover.active.state != EpochState::Active
            {
                return Err("depth publication controller is not LIVE".to_owned());
            }
            if self.handover.active.epoch != epoch {
                // Let the canonical pointer perform and count the authoritative
                // fencing rejection for a stale depth writer.
                return self.pointer.accept_observation(
                    kind,
                    epoch,
                    fencing_token,
                    first_sequence,
                    final_sequence,
                );
            }
        }
        self.pointer
            .accept_observation(kind, epoch, fencing_token, first_sequence, final_sequence)
    }

    pub fn fail_active(&mut self, kind: BoundaryStreamKind, reason: &str) -> Result<()> {
        let epoch = match kind {
            BoundaryStreamKind::Depth => self.pointer.owner.depth_epoch.clone(),
            BoundaryStreamKind::Trade => self.pointer.owner.trade_epoch.clone(),
        };
        self.pointer.fail_active(&epoch, reason)?;
        if kind == BoundaryStreamKind::Depth && self.handover.active.epoch == epoch {
            self.handover.fail_epoch(&epoch, reason)?;
        }
        Ok(())
    }
}
