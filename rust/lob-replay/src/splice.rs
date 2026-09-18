//! Derive a durable canonical A-to-B splice from independently captured epochs.

use crate::Result;
use crate::boundary::{
    BoundaryDurabilityV1, BoundaryStreamKind, CanonicalObservationV1, HandoverBoundaryV1,
    RawPositionV1,
};
use std::collections::HashMap;

pub const SELECTOR_VERSION: &str = "CanonicalSelectorV1";

fn position(observation: &CanonicalObservationV1) -> RawPositionV1 {
    RawPositionV1 {
        connection_epoch: observation.connection_epoch.clone(),
        stream: observation.stream.clone(),
        frame_index: observation.frame_index,
        record_sha256: observation.record_sha256.clone(),
    }
}

pub fn derive_handover_boundary(
    boundary_id: &str,
    stream_kind: BoundaryStreamKind,
    predecessor: &[CanonicalObservationV1],
    successor: &[CanonicalObservationV1],
    predecessor_durability: BoundaryDurabilityV1,
    successor_durability: BoundaryDurabilityV1,
    spec_revision: &str,
) -> Result<HandoverBoundaryV1> {
    if boundary_id.trim().is_empty() {
        return Err("boundary ID is required".to_owned());
    }
    let first_predecessor = predecessor
        .first()
        .ok_or_else(|| "predecessor observations are empty".to_owned())?;
    let first_successor = successor
        .first()
        .ok_or_else(|| "successor observations are empty".to_owned())?;
    if first_predecessor.symbol != first_successor.symbol
        || first_predecessor.stream != first_successor.stream
        || first_predecessor.stream_kind != stream_kind
        || first_successor.stream_kind != stream_kind
        || first_predecessor.connection_epoch == first_successor.connection_epoch
    {
        return Err(
            "A/B observation identity does not define independent matching epochs".to_owned(),
        );
    }
    let predecessor_by_sequence = predecessor
        .iter()
        .map(|item| (item.final_sequence, item))
        .collect::<HashMap<_, _>>();
    let mut selected = None;
    for window in successor.windows(2) {
        let boundary = &window[0];
        let continuation = &window[1];
        let Some(predecessor_boundary) = predecessor_by_sequence
            .get(&boundary.final_sequence)
            .copied()
        else {
            continue;
        };
        if predecessor_boundary.observation_sha256 != boundary.observation_sha256 {
            continue;
        }
        let next = boundary
            .final_sequence
            .checked_add(1)
            .ok_or_else(|| "boundary sequence overflow".to_owned())?;
        let continues = match stream_kind {
            BoundaryStreamKind::Depth => {
                continuation.first_sequence <= next && continuation.final_sequence >= next
            }
            BoundaryStreamKind::Trade => {
                predecessor_boundary.first_sequence == boundary.final_sequence
                    && boundary.first_sequence == boundary.final_sequence
                    && continuation.first_sequence == next
                    && continuation.final_sequence == next
            }
        };
        if continues
            && selected
                .as_ref()
                .is_none_or(|(old, _, _): &(&CanonicalObservationV1, _, _)| {
                    predecessor_boundary.final_sequence > old.final_sequence
                })
        {
            selected = Some((predecessor_boundary, boundary, continuation));
        }
    }
    let (predecessor_boundary, successor_boundary, successor_continuation) = selected
        .ok_or_else(|| "no converged A/B boundary with a venue-valid B continuation".to_owned())?;
    let boundary = HandoverBoundaryV1 {
        schema: "HandoverBoundaryV1".to_owned(),
        boundary_id: boundary_id.to_owned(),
        environment: "production-public-market-data".to_owned(),
        symbol: first_predecessor.symbol.clone(),
        stream_kind,
        stream: first_predecessor.stream.clone(),
        predecessor_epoch: first_predecessor.connection_epoch.clone(),
        successor_epoch: first_successor.connection_epoch.clone(),
        boundary_sequence: predecessor_boundary.final_sequence,
        boundary_sha256: predecessor_boundary.observation_sha256.clone(),
        predecessor_last_selected: position(predecessor_boundary),
        successor_boundary_observation: position(successor_boundary),
        successor_first_selected: position(successor_continuation),
        predecessor_durability,
        successor_durability,
        spec_revision: spec_revision.to_owned(),
        selector_version: SELECTOR_VERSION.to_owned(),
    };
    boundary.validate()?;
    Ok(boundary)
}
