use lob_replay::liveness::ProgressWatchdog;

#[test]
fn process_alive_without_progress_expires_at_exact_deadline() {
    let mut watchdog = ProgressWatchdog::new(100).unwrap();
    watchdog
        .observe("BTCUSDT/source-b/depth", 10, 1_000)
        .unwrap();
    watchdog
        .observe("BTCUSDT/source-b/depth", 10, 1_099)
        .unwrap();
    let error = watchdog
        .observe("BTCUSDT/source-b/depth", 10, 1_100)
        .unwrap_err();
    assert!(error.contains("progress stalled"));
}

#[test]
fn each_stream_must_advance_independently() {
    let mut watchdog = ProgressWatchdog::new(100).unwrap();
    watchdog.observe("depth", 10, 1_000).unwrap();
    watchdog.observe("trade", 20, 1_000).unwrap();
    watchdog.observe("depth", 11, 1_090).unwrap();
    let error = watchdog.check(1_100).unwrap_err();
    assert!(error.contains("trade"));
}

#[test]
fn progress_reset_is_not_confused_with_process_liveness() {
    let mut watchdog = ProgressWatchdog::new(100).unwrap();
    watchdog.observe("stream", 1, 1_000).unwrap();
    watchdog.observe("stream", 2, 1_099).unwrap();
    watchdog.check(1_198).unwrap();
    assert!(watchdog.check(1_199).is_err());
}

#[test]
fn regression_and_monotonic_time_reversal_fail_closed() {
    let mut watchdog = ProgressWatchdog::new(100).unwrap();
    watchdog.observe("stream", 2, 1_000).unwrap();
    assert!(watchdog.observe("stream", 1, 1_001).is_err());
    assert!(watchdog.observe("stream", 2, 999).is_err());
}
