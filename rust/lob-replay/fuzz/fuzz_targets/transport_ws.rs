#![no_main]
// Fuzz target for the deterministic WebSocket transport model — mirror of
// tetsuo fuzz_ws_frame.c / fuzz_ws_frames.c.  Feeds arbitrary bytes as a
// sequence of WsInput frames interleaved with watchdog ticks and asserts the
// model never panics on adversarial input.
use libfuzzer_sys::fuzz_target;
use lob_replay::transport::{PublicWsSession, WsInput};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let Ok(mut session) = PublicWsSession::new("fuzz-epoch", 64) else {
        return;
    };
    let mut cursor = 1_usize;
    let mut mono_ns = 0_u64;
    while cursor + 1 < data.len() {
        let kind = data[cursor] % 5;
        let len = (data[cursor + 1] as usize) % 256;
        let end = (cursor + 2 + len).min(data.len());
        let payload = data[cursor + 2..end].to_vec();
        cursor = end;
        mono_ns = mono_ns.saturating_add(1_000_000);
        let input = match kind {
            0 => WsInput::Data(payload),
            1 => WsInput::Ping(payload),
            2 => WsInput::Pong(payload),
            3 => WsInput::Close {
                code: Some(1000),
                reason: "fuzz".to_owned(),
            },
            _ => WsInput::TransportError("fuzz".to_owned()),
        };
        if session.handle(input, mono_ns).is_err() {
            break;
        }
        // Interleave the watchdog with the same production constants.
        if session
            .watchdog_tick(mono_ns, 30_000_000_000, 5_000_000_000)
            .is_err()
        {
            break;
        }
    }
    let _ = mono_ns;
});
