use lob_replay::handover::{EpochState, HandoverController, PublicationState};
use lob_replay::orchestrator::RotationOrchestrator;
use lob_replay::transport::{
    FakeWebSocket, PublicWsSession, TransportAction, TransportState, WsInput,
};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn active_controller() -> HandoverController {
    let mut controller = HandoverController::new("BTCUSDT", "epoch-a").unwrap();
    for state in [
        EpochState::Buffering,
        EpochState::Snapshotting,
        EpochState::Syncing,
    ] {
        controller.transition_epoch("epoch-a", state).unwrap();
    }
    controller.mark_live("epoch-a", 100, DIGEST).unwrap();
    controller.activate_initial().unwrap();
    controller
}

#[test]
fn ping_gets_immediate_pong_with_identical_payload() {
    let mut session = PublicWsSession::new("epoch-a", 8).unwrap();
    let actions = session.handle(WsInput::Ping(vec![1, 2, 3]), 10).unwrap();
    assert_eq!(
        actions,
        vec![TransportAction::RespondPong {
            expected_payload: vec![1, 2, 3]
        }]
    );
}

// Watchdog ping→pong (port of tetsuo SocketWS.c ws_auto_ping_callback): a
// proactive PING every interval keeps transport liveness honest, a missing
// PONG within the deadline types the transport as DEAD, and a PONG clears the
// pending ping while recording the RTT.  Pings never mask market frames.

#[test]
fn watchdog_sends_ping_after_interval_and_pong_clears_and_records_rtt() {
    let mut session = PublicWsSession::new("epoch-a", 8).unwrap();
    let actions = session
        .watchdog_tick(0, 30_000_000_000, 5_000_000_000)
        .unwrap();
    assert_eq!(
        actions,
        vec![TransportAction::SendPing {
            payload: Vec::new()
        }]
    );
    assert!(session.awaiting_pong());
    // Inside the deadline the watchdog stays quiet.
    assert!(
        session
            .watchdog_tick(4_000_000_000, 30_000_000_000, 5_000_000_000)
            .unwrap()
            .is_empty()
    );
    // The server PONG clears the pending ping and records the RTT.
    assert!(
        session
            .handle(WsInput::Pong(Vec::new()), 4_100_000_000)
            .unwrap()
            .is_empty()
    );
    assert!(!session.awaiting_pong());
    assert_eq!(session.last_ping_rtt_ns(), Some(4_100_000_000));
    // After the full interval the watchdog pings again.
    let actions = session
        .watchdog_tick(34_100_000_000, 30_000_000_000, 5_000_000_000)
        .unwrap();
    assert_eq!(
        actions,
        vec![TransportAction::SendPing {
            payload: Vec::new()
        }]
    );
}

#[test]
fn watchdog_pong_deadline_types_transport_as_dead() {
    let mut session = PublicWsSession::new("epoch-a", 8).unwrap();
    session
        .watchdog_tick(0, 30_000_000_000, 5_000_000_000)
        .unwrap();
    let actions = session
        .watchdog_tick(5_000_000_001, 30_000_000_000, 5_000_000_000)
        .unwrap();
    assert_eq!(session.state, TransportState::Failed);
    assert!(matches!(
        actions.as_slice(),
        [TransportAction::InvalidateEpoch { reason }]
            if reason.contains("pong deadline") && reason.contains("transport dead")
    ));
}

#[test]
fn watchdog_never_masks_market_frames() {
    let mut session = PublicWsSession::new("epoch-a", 8).unwrap();
    session
        .watchdog_tick(0, 30_000_000_000, 5_000_000_000)
        .unwrap();
    let actions = session
        .handle(WsInput::Data(br#"{"e":"trade"}"#.to_vec()), 10)
        .unwrap();
    assert_eq!(session.state, TransportState::Open);
    assert!(matches!(
        actions.as_slice(),
        [TransportAction::RawEnqueued { frame_index: 0 }]
    ));
    // Market data does not clear the pending ping, and a tick inside the
    // deadline does not invalidate the epoch.
    assert!(session.awaiting_pong());
    assert!(
        session
            .watchdog_tick(11, 30_000_000_000, 5_000_000_000)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn watchdog_tick_time_cannot_regress() {
    let mut session = PublicWsSession::new("epoch-a", 8).unwrap();
    session
        .watchdog_tick(100, 30_000_000_000, 5_000_000_000)
        .unwrap();
    assert!(
        session
            .watchdog_tick(99, 30_000_000_000, 5_000_000_000)
            .is_err()
    );
}

#[test]
fn raw_data_is_queued_in_receive_order_without_interpretation() {
    let mut session = PublicWsSession::new("epoch-a", 2).unwrap();
    session
        .handle(WsInput::Data(b"not-json".to_vec()), 10)
        .unwrap();
    session
        .handle(WsInput::Data(br#"{"e":"trade"}"#.to_vec()), 11)
        .unwrap();
    let first = session.raw_sink.drain_one().unwrap();
    let second = session.raw_sink.drain_one().unwrap();
    assert_eq!(first.frame_index, 0);
    assert_eq!(first.payload, b"not-json");
    assert_eq!(second.frame_index, 1);
    assert_eq!(session.raw_sink.drained, 2);
}

#[test]
fn raw_and_combined_shutdown_are_enqueued_before_handover_action() {
    for payload in [
        br#"{"e":"serverShutdown","E":1770123456789}"#.to_vec(),
        br#"{"stream":"!serverShutdown","data":{"e":"serverShutdown","E":1770123456789}}"#.to_vec(),
    ] {
        let mut session = PublicWsSession::new("epoch-a", 2).unwrap();
        let actions = session.handle(WsInput::Data(payload.clone()), 10).unwrap();
        assert_eq!(session.state, TransportState::ShutdownAnnounced);
        assert_eq!(actions[0], TransportAction::RawEnqueued { frame_index: 0 });
        assert!(matches!(actions[1], TransportAction::BeginHandover { .. }));
        assert_eq!(session.raw_sink.drain_one().unwrap().payload, payload);
    }
}

#[test]
fn slow_writer_overflow_invalidates_epoch_and_counts_drop() {
    let mut session = PublicWsSession::new("epoch-a", 1).unwrap();
    session
        .handle(WsInput::Data(b"first".to_vec()), 10)
        .unwrap();
    let actions = session
        .handle(WsInput::Data(b"second".to_vec()), 11)
        .unwrap();
    assert_eq!(session.state, TransportState::Failed);
    assert_eq!(session.raw_sink.local_drops, 1);
    assert!(matches!(
        actions.as_slice(),
        [TransportAction::InvalidateEpoch { .. }]
    ));
}

#[test]
fn monotonic_regression_and_control_rate_fail_closed() {
    let mut regressed = PublicWsSession::new("epoch-a", 8).unwrap();
    regressed.handle(WsInput::Pong(Vec::new()), 20).unwrap();
    regressed.handle(WsInput::Pong(Vec::new()), 19).unwrap();
    assert_eq!(regressed.state, TransportState::Failed);

    let mut rate = PublicWsSession::new("epoch-b", 8).unwrap();
    for now in 0..5 {
        rate.handle(WsInput::Ping(Vec::new()), now).unwrap();
    }
    let actions = rate.handle(WsInput::Ping(Vec::new()), 5).unwrap();
    assert_eq!(rate.state, TransportState::Failed);
    assert!(matches!(
        actions.as_slice(),
        [TransportAction::InvalidateEpoch { .. }]
    ));
}

#[test]
fn fake_socket_stops_after_terminal_close() {
    let mut session = PublicWsSession::new("epoch-a", 8).unwrap();
    let mut socket = FakeWebSocket::new([
        (1, WsInput::Data(b"first".to_vec())),
        (
            2,
            WsInput::Close {
                code: Some(1000),
                reason: "synthetic".to_owned(),
            },
        ),
        (3, WsInput::Data(b"must-not-run".to_vec())),
    ]);
    let actions = socket.run(&mut session).unwrap();
    assert_eq!(session.state, TransportState::Closed);
    assert_eq!(session.next_frame_index, 1);
    assert!(matches!(
        actions.last(),
        Some(TransportAction::EpochClosed { .. })
    ));
}

#[test]
fn shutdown_starts_candidate_but_active_close_before_sync_is_gap() {
    let mut orchestrator = RotationOrchestrator::new(active_controller());
    let mut session = PublicWsSession::new("epoch-a", 8).unwrap();
    let actions = session
        .handle(
            WsInput::Data(br#"{"e":"serverShutdown","E":1770123456789}"#.to_vec()),
            10,
        )
        .unwrap();
    orchestrator
        .apply_transport_actions("epoch-a", &actions, Some("epoch-b"))
        .unwrap();
    orchestrator
        .handover
        .transition_epoch("epoch-b", EpochState::Buffering)
        .unwrap();
    let close_actions = session
        .handle(
            WsInput::Close {
                code: Some(1001),
                reason: "shutdown".to_owned(),
            },
            11,
        )
        .unwrap();
    orchestrator
        .apply_transport_actions("epoch-a", &close_actions, None)
        .unwrap();
    assert_eq!(orchestrator.handover.publication, PublicationState::Gap);
}

#[test]
fn malformed_shutdown_is_preserved_then_invalidates_epoch() {
    let mut session = PublicWsSession::new("epoch-a", 2).unwrap();
    let payload = br#"{"e":"serverShutdown","E":"not-an-integer"}"#.to_vec();
    let actions = session.handle(WsInput::Data(payload.clone()), 10).unwrap();
    assert_eq!(session.state, TransportState::Failed);
    assert_eq!(actions[0], TransportAction::RawEnqueued { frame_index: 0 });
    assert!(matches!(
        actions[1],
        TransportAction::InvalidateEpoch { .. }
    ));
    assert_eq!(session.raw_sink.drain_one().unwrap().payload, payload);
}

#[test]
fn duplicate_shutdown_is_recorded_without_starting_second_candidate() {
    let mut session = PublicWsSession::new("epoch-a", 2).unwrap();
    let payload = br#"{"e":"serverShutdown","E":1770123456789}"#.to_vec();
    session.handle(WsInput::Data(payload.clone()), 10).unwrap();
    let second = session.handle(WsInput::Data(payload), 11).unwrap();
    assert_eq!(second.len(), 1);
    assert!(matches!(
        second[0],
        TransportAction::RawEnqueued { frame_index: 1 }
    ));
}

#[test]
fn delayed_snapshot_past_rotation_deadline_is_gap() {
    let mut controller = active_controller();
    controller.begin_handover("epoch-b").unwrap();
    controller
        .transition_epoch("epoch-b", EpochState::Buffering)
        .unwrap();
    controller
        .transition_epoch("epoch-b", EpochState::Snapshotting)
        .unwrap();
    controller
        .rotation_deadline_expired("snapshot did not complete before forced rotation")
        .unwrap();
    assert_eq!(controller.publication, PublicationState::Gap);
}
