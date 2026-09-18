//! Deterministic public WebSocket transport model and bounded fake sink.

use crate::Result;
use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;

const ONE_SECOND_NS: u64 = 1_000_000_000;
const MAX_CLIENT_CONTROL_PER_SECOND: usize = 5;
const MAX_CONTROL_PAYLOAD_BYTES: usize = 125;
const MAX_DATA_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WsInput {
    Data(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close { code: Option<u16>, reason: String },
    TransportError(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportState {
    Open,
    ShutdownAnnounced,
    Closed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportAction {
    RawEnqueued { frame_index: u64 },
    RespondPong { expected_payload: Vec<u8> },
    SendPing { payload: Vec<u8> },
    BeginHandover { reason: String },
    EpochClosed { reason: String },
    InvalidateEpoch { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueuedRawFrame {
    pub frame_index: u64,
    pub receive_mono_ns: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct BoundedRawSink {
    capacity: usize,
    queue: VecDeque<QueuedRawFrame>,
    pub enqueued: u64,
    pub drained: u64,
    pub max_depth: usize,
    pub local_drops: u64,
}

impl BoundedRawSink {
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err("raw sink capacity must be positive".to_owned());
        }
        Ok(Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
            enqueued: 0,
            drained: 0,
            max_depth: 0,
            local_drops: 0,
        })
    }

    pub fn depth(&self) -> usize {
        self.queue.len()
    }

    pub fn drain_one(&mut self) -> Option<QueuedRawFrame> {
        let frame = self.queue.pop_front()?;
        self.drained += 1;
        Some(frame)
    }

    fn enqueue(&mut self, frame: QueuedRawFrame) -> std::result::Result<(), QueuedRawFrame> {
        if self.queue.len() >= self.capacity {
            self.local_drops += 1;
            return Err(frame);
        }
        self.queue.push_back(frame);
        self.enqueued += 1;
        self.max_depth = self.max_depth.max(self.queue.len());
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct PublicWsSession {
    pub epoch: String,
    pub state: TransportState,
    pub raw_sink: BoundedRawSink,
    pub next_frame_index: u64,
    pub last_receive_mono_ns: Option<u64>,
    outbound_control_ns: VecDeque<u64>,
    // Watchdog ping→pong state (port of tetsuo SocketWS.c ws_auto_ping_callback).
    last_ping_sent_mono_ns: Option<u64>,
    awaiting_pong: bool,
    last_pong_mono_ns: Option<u64>,
    last_ping_rtt_ns: Option<u64>,
    last_watchdog_tick_mono_ns: Option<u64>,
}

impl PublicWsSession {
    pub fn new(epoch: &str, raw_capacity: usize) -> Result<Self> {
        if epoch.trim().is_empty() {
            return Err("transport epoch must not be empty".to_owned());
        }
        Ok(Self {
            epoch: epoch.to_owned(),
            state: TransportState::Open,
            raw_sink: BoundedRawSink::new(raw_capacity)?,
            next_frame_index: 0,
            last_receive_mono_ns: None,
            outbound_control_ns: VecDeque::new(),
            last_ping_sent_mono_ns: None,
            awaiting_pong: false,
            last_pong_mono_ns: None,
            last_ping_rtt_ns: None,
            last_watchdog_tick_mono_ns: None,
        })
    }

    /// Whether a proactive watchdog PING is still awaiting its PONG.
    pub fn awaiting_pong(&self) -> bool {
        self.awaiting_pong
    }

    /// Round-trip time of the last completed watchdog ping, in nanoseconds.
    pub fn last_ping_rtt_ns(&self) -> Option<u64> {
        self.last_ping_rtt_ns
    }

    pub fn handle(&mut self, input: WsInput, mono_ns: u64) -> Result<Vec<TransportAction>> {
        if matches!(self.state, TransportState::Closed | TransportState::Failed) {
            return Err(format!("transport epoch is terminal: {:?}", self.state));
        }
        if self
            .last_receive_mono_ns
            .is_some_and(|previous| mono_ns < previous)
        {
            return Ok(self.invalidate("monotonic receive time regressed"));
        }
        self.last_receive_mono_ns = Some(mono_ns);
        match input {
            WsInput::Data(payload) => self.handle_data(payload, mono_ns),
            WsInput::Ping(payload) => self.handle_ping(payload, mono_ns),
            WsInput::Pong(_) => {
                if self.awaiting_pong {
                    self.awaiting_pong = false;
                    self.last_pong_mono_ns = Some(mono_ns);
                    if let Some(sent) = self.last_ping_sent_mono_ns {
                        self.last_ping_rtt_ns = Some(mono_ns.saturating_sub(sent));
                    }
                }
                Ok(Vec::new())
            }
            WsInput::Close { code, reason } => {
                self.state = TransportState::Closed;
                Ok(vec![TransportAction::EpochClosed {
                    reason: format!("websocket close code={code:?} reason={reason}"),
                }])
            }
            WsInput::TransportError(reason) => {
                Ok(self.invalidate(&format!("websocket transport error: {reason}")))
            }
        }
    }

    fn handle_data(&mut self, payload: Vec<u8>, mono_ns: u64) -> Result<Vec<TransportAction>> {
        if payload.len() > MAX_DATA_PAYLOAD_BYTES {
            return Ok(self.invalidate("websocket data payload exceeds 4 MiB"));
        }
        let frame_index = self.next_frame_index;
        let next_frame_index = match self.next_frame_index.checked_add(1) {
            Some(value) => value,
            None => return Ok(self.invalidate("transport frame index overflow")),
        };
        let frame = QueuedRawFrame {
            frame_index,
            receive_mono_ns: mono_ns,
            payload,
        };
        if self.raw_sink.enqueue(frame).is_err() {
            return Ok(self.invalidate("bounded raw sink overflow; received frame was not durable"));
        }
        self.next_frame_index = next_frame_index;
        let mut actions = vec![TransportAction::RawEnqueued { frame_index }];
        let shutdown = match classify_server_shutdown(
            &self.raw_sink.queue.back().expect("just enqueued").payload,
        ) {
            Ok(value) => value,
            Err(error) => {
                actions.extend(self.invalidate(&error));
                return Ok(actions);
            }
        };
        if shutdown && self.state == TransportState::Open {
            self.state = TransportState::ShutdownAnnounced;
            actions.push(TransportAction::BeginHandover {
                reason: "official serverShutdown event".to_owned(),
            });
        }
        Ok(actions)
    }

    fn handle_ping(&mut self, payload: Vec<u8>, mono_ns: u64) -> Result<Vec<TransportAction>> {
        if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
            return Ok(self.invalidate("ping payload exceeds WebSocket control-frame limit"));
        }
        while self
            .outbound_control_ns
            .front()
            .is_some_and(|oldest| mono_ns.saturating_sub(*oldest) >= ONE_SECOND_NS)
        {
            self.outbound_control_ns.pop_front();
        }
        if self.outbound_control_ns.len() >= MAX_CLIENT_CONTROL_PER_SECOND {
            return Ok(self.invalidate("client control-message rate would exceed 5 per second"));
        }
        self.outbound_control_ns.push_back(mono_ns);
        Ok(vec![TransportAction::RespondPong {
            expected_payload: payload,
        }])
    }

    fn invalidate(&mut self, reason: &str) -> Vec<TransportAction> {
        self.state = TransportState::Failed;
        vec![TransportAction::InvalidateEpoch {
            reason: reason.to_owned(),
        }]
    }

    /// Watchdog tick (port of tetsuo `ws_auto_ping_callback`): while a PING is
    /// awaiting its PONG, exceeding `pong_deadline_ns` types the transport as
    /// DEAD and invalidates the epoch; otherwise, once `ping_interval_ns` has
    /// elapsed since the last PING, a new proactive PING is scheduled.  Pings
    /// never touch market frames, so they can never mask market silence.
    pub fn watchdog_tick(
        &mut self,
        now_mono_ns: u64,
        ping_interval_ns: u64,
        pong_deadline_ns: u64,
    ) -> Result<Vec<TransportAction>> {
        if matches!(self.state, TransportState::Closed | TransportState::Failed) {
            return Err(format!("transport epoch is terminal: {:?}", self.state));
        }
        if ping_interval_ns == 0 || pong_deadline_ns == 0 {
            return Err("watchdog ping interval and pong deadline must be positive".to_owned());
        }
        if self
            .last_watchdog_tick_mono_ns
            .is_some_and(|previous| now_mono_ns < previous)
        {
            return Err("watchdog monotonic tick time regressed".to_owned());
        }
        self.last_watchdog_tick_mono_ns = Some(now_mono_ns);
        if self.awaiting_pong {
            if self
                .last_ping_sent_mono_ns
                .is_some_and(|sent| now_mono_ns.saturating_sub(sent) >= pong_deadline_ns)
            {
                return Ok(self.invalidate("watchdog pong deadline exceeded: transport dead"));
            }
            return Ok(Vec::new());
        }
        let ping_due = self
            .last_ping_sent_mono_ns
            .is_none_or(|sent| now_mono_ns.saturating_sub(sent) >= ping_interval_ns);
        if ping_due {
            self.last_ping_sent_mono_ns = Some(now_mono_ns);
            self.awaiting_pong = true;
            return Ok(vec![TransportAction::SendPing {
                payload: Vec::new(),
            }]);
        }
        Ok(Vec::new())
    }
}

fn classify_server_shutdown(payload: &[u8]) -> Result<bool> {
    let Ok(value) = serde_json::from_slice::<Value>(payload) else {
        return Ok(false);
    };
    let raw_shutdown = value["e"] == "serverShutdown";
    let combined_shutdown =
        value["stream"] == "!serverShutdown" && value["data"]["e"] == "serverShutdown";
    if !raw_shutdown && !combined_shutdown {
        return Ok(false);
    }
    let event = if raw_shutdown { &value } else { &value["data"] };
    if event["E"].as_u64().is_none() {
        return Err("serverShutdown event has invalid event time".to_owned());
    }
    Ok(true)
}

#[derive(Debug)]
pub struct FakeWebSocket {
    inputs: VecDeque<(u64, WsInput)>,
}

impl FakeWebSocket {
    pub fn new(inputs: impl IntoIterator<Item = (u64, WsInput)>) -> Self {
        Self {
            inputs: inputs.into_iter().collect(),
        }
    }

    pub fn run(&mut self, session: &mut PublicWsSession) -> Result<Vec<TransportAction>> {
        let mut actions = Vec::new();
        while let Some((mono_ns, input)) = self.inputs.pop_front() {
            actions.extend(session.handle(input, mono_ns)?);
            if matches!(
                session.state,
                TransportState::Closed | TransportState::Failed
            ) {
                break;
            }
        }
        Ok(actions)
    }
}
