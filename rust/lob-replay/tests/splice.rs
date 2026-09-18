use lob_replay::boundary::{
    BoundaryDurabilityV1, BoundaryStreamKind, CanonicalObservationV1, select_canonical,
};
use lob_replay::splice::derive_handover_boundary;

fn digest(character: char) -> String {
    character.to_string().repeat(64)
}

fn observation(
    kind: BoundaryStreamKind,
    epoch: &str,
    frame_index: u64,
    first: u64,
    final_id: u64,
    state: char,
) -> CanonicalObservationV1 {
    CanonicalObservationV1 {
        symbol: "BTCUSDT".to_owned(),
        stream_kind: kind,
        stream: match kind {
            BoundaryStreamKind::Depth => "btcusdt@depth@100ms",
            BoundaryStreamKind::Trade => "btcusdt@trade",
        }
        .to_owned(),
        connection_epoch: epoch.to_owned(),
        frame_index,
        first_sequence: first,
        final_sequence: final_id,
        record_sha256: digest(if epoch == "epoch-a" { 'a' } else { 'b' }),
        observation_sha256: digest(state),
    }
}

fn durability(character: char) -> BoundaryDurabilityV1 {
    BoundaryDurabilityV1 {
        durable_through_frame_index: 100,
        durable_through_offset: 10_000,
        last_record_sha256: digest(character),
    }
}

#[test]
fn derives_latest_converged_depth_boundary_and_valid_selection() {
    let predecessor = vec![
        observation(BoundaryStreamKind::Depth, "epoch-a", 0, 100, 100, '1'),
        observation(BoundaryStreamKind::Depth, "epoch-a", 1, 101, 101, '2'),
        observation(BoundaryStreamKind::Depth, "epoch-a", 2, 102, 102, '3'),
    ];
    let successor = vec![
        observation(BoundaryStreamKind::Depth, "epoch-b", 0, 101, 101, '8'),
        observation(BoundaryStreamKind::Depth, "epoch-b", 1, 102, 102, '3'),
        observation(BoundaryStreamKind::Depth, "epoch-b", 2, 103, 104, '4'),
    ];
    let boundary = derive_handover_boundary(
        "boundary-depth",
        BoundaryStreamKind::Depth,
        &predecessor,
        &successor,
        durability('c'),
        durability('d'),
        "spec",
    )
    .unwrap();
    assert_eq!(boundary.boundary_sequence, 102);
    assert_eq!(boundary.successor_first_selected.frame_index, 2);
    let selection = select_canonical(&boundary, &predecessor, &successor).unwrap();
    assert_eq!(selection.first_sequence, 100);
    assert_eq!(selection.final_sequence, 104);
    assert_eq!(selection.selected.len(), 4);
}

#[test]
fn derives_trade_boundary_independently_at_t_plus_one() {
    let predecessor = (7..=9)
        .enumerate()
        .map(|(index, trade_id)| {
            observation(
                BoundaryStreamKind::Trade,
                "epoch-a",
                index as u64,
                trade_id,
                trade_id,
                char::from_digit(trade_id as u32, 16).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let successor = (8..=10)
        .enumerate()
        .map(|(index, trade_id)| {
            observation(
                BoundaryStreamKind::Trade,
                "epoch-b",
                index as u64,
                trade_id,
                trade_id,
                char::from_digit(trade_id as u32, 16).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let boundary = derive_handover_boundary(
        "boundary-trade",
        BoundaryStreamKind::Trade,
        &predecessor,
        &successor,
        durability('c'),
        durability('d'),
        "spec",
    )
    .unwrap();
    assert_eq!(boundary.boundary_sequence, 9);
    let selection = select_canonical(&boundary, &predecessor, &successor).unwrap();
    assert_eq!(
        (selection.first_sequence, selection.final_sequence),
        (7, 10)
    );
}

#[test]
fn refuses_same_sequence_with_divergent_state() {
    let predecessor = vec![observation(
        BoundaryStreamKind::Depth,
        "epoch-a",
        0,
        100,
        100,
        '1',
    )];
    let successor = vec![
        observation(BoundaryStreamKind::Depth, "epoch-b", 0, 100, 100, '2'),
        observation(BoundaryStreamKind::Depth, "epoch-b", 1, 101, 101, '3'),
    ];
    assert!(
        derive_handover_boundary(
            "boundary-divergent",
            BoundaryStreamKind::Depth,
            &predecessor,
            &successor,
            durability('c'),
            durability('d'),
            "spec",
        )
        .unwrap_err()
        .contains("no converged")
    );
}
