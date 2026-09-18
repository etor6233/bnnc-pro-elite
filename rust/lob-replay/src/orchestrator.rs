//! Pure adapter from transport actions to handover state transitions.

use crate::Result;
use crate::handover::HandoverController;
use crate::transport::TransportAction;

#[derive(Debug)]
pub struct RotationOrchestrator {
    pub handover: HandoverController,
}

impl RotationOrchestrator {
    pub fn new(handover: HandoverController) -> Self {
        Self { handover }
    }

    pub fn apply_transport_actions(
        &mut self,
        source_epoch: &str,
        actions: &[TransportAction],
        candidate_epoch: Option<&str>,
    ) -> Result<()> {
        for action in actions {
            match action {
                TransportAction::RawEnqueued { .. }
                | TransportAction::RespondPong { .. }
                | TransportAction::SendPing { .. } => {}
                TransportAction::BeginHandover { .. } => {
                    if self.handover.active.epoch != source_epoch {
                        return Err("only the active epoch may initiate handover".to_owned());
                    }
                    let epoch = candidate_epoch.ok_or_else(|| {
                        "handover action requires a fresh candidate epoch".to_owned()
                    })?;
                    self.handover.begin_handover(epoch)?;
                }
                TransportAction::EpochClosed { reason }
                | TransportAction::InvalidateEpoch { reason } => {
                    if self
                        .handover
                        .draining
                        .as_ref()
                        .is_some_and(|draining| draining.epoch == source_epoch)
                        && matches!(action, TransportAction::EpochClosed { .. })
                    {
                        self.handover.close_draining()?;
                    } else {
                        self.handover.fail_epoch(source_epoch, reason)?;
                    }
                }
            }
        }
        Ok(())
    }
}
