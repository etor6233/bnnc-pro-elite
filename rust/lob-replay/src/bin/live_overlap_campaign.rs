use lob_replay::DurabilityAckV1;
use lob_replay::Result;
use lob_replay::boundary::{
    BoundaryDurabilityV1, BoundaryJournalWriter, BoundaryStreamKind, HandoverBoundaryV1,
};
use lob_replay::canonical_output::{
    CanonicalOutputOwnerV1, CanonicalOutputScanV1, CanonicalOutputWriter, scan_canonical_output,
};
use lob_replay::durability_progress::{
    freeze_durable_raw_prefix, read_durable_raw_delta, scan_durability_progress,
};
use lob_replay::handover::{EpochState, HandoverController};
use lob_replay::live_rotation::{LiveActivationReportV1, LiveRotationCoordinator};
use lob_replay::liveness::ProgressWatchdog;
use lob_replay::observations::{
    DepthObservationCursor, ObservationMaterializationV1, materialize_depth_observations,
    materialize_trade_observations, materialize_trade_record,
};
use lob_replay::ownership::{
    CanonicalSourcePointer, OwnershipLedgerWriter, SourcePointerSnapshotV1,
    load_committed_boundary_proof, scan_ownership_ledger,
};
use lob_replay::splice::derive_handover_boundary;
use serde::Serialize;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const SPEC_REVISION: &str = "976cc580553890e92031b77306147c0ed1de5a46";
const DURABLE_PROGRESS_DEAD_AFTER: Duration = Duration::from_secs(60);

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn alive(&mut self) -> Result<bool> {
        Ok(self
            .0
            .as_mut()
            .ok_or_else(|| "capture child is absent".to_owned())?
            .try_wait()
            .map_err(|error| format!("poll capture child: {error}"))?
            .is_none())
    }

    fn finish(mut self, label: &str) -> Result<String> {
        let output = self
            .0
            .take()
            .expect("capture child checked")
            .wait_with_output()
            .map_err(|error| format!("wait {label}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "{label} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        String::from_utf8(output.stdout)
            .map_err(|error| format!("{label} stdout: {error}"))?
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(str::trim)
            .map(str::to_owned)
            .ok_or_else(|| format!("{label} emitted no session path"))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Serialize)]
struct LiveCampaignReportV1 {
    schema: &'static str,
    status: &'static str,
    symbol: String,
    predecessor_session: String,
    successor_session: String,
    activation_wall_ns: u64,
    predecessor_alive_at_activation: bool,
    successor_alive_at_activation: bool,
    depth_boundary_sequence: u64,
    trade_boundary_sequence: u64,
    depth_post_activation_accepted: u64,
    trade_post_activation_accepted: u64,
    fenced_predecessor_rejections: u64,
    activation: LiveActivationReportV1,
    depth_output: CanonicalOutputScanV1,
    trade_output: CanonicalOutputScanV1,
    credentials: &'static str,
    order_entry: &'static str,
}

struct FrozenPair {
    predecessor_depth: ObservationMaterializationV1,
    successor_depth: ObservationMaterializationV1,
    predecessor_trade: ObservationMaterializationV1,
    successor_trade: ObservationMaterializationV1,
    predecessor_depth_ack: DurabilityAckV1,
    successor_depth_ack: DurabilityAckV1,
    predecessor_trade_ack: DurabilityAckV1,
    successor_trade_ack: DurabilityAckV1,
}

fn unix_ns() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system time: {error}"))?
            .as_nanos(),
    )
    .map_err(|_| "wall nanoseconds overflow".to_owned())
}

fn elapsed_ns(clock: Instant) -> Result<u64> {
    u64::try_from(clock.elapsed().as_nanos())
        .map_err(|_| "monotonic campaign nanoseconds overflow".to_owned())
}

fn file_progress(path: &Path) -> Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(metadata.len()),
        Ok(_) => Err(format!("progress path is not a file: {}", path.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(0),
        Err(error) => Err(format!("inspect progress {}: {error}", path.display())),
    }
}

fn observe_capture_progress(
    watchdog: &mut ProgressWatchdog,
    clock: Instant,
    sessions: [(&str, &Path); 2],
) -> Result<()> {
    let now_ns = elapsed_ns(clock)?;
    for (source, session) in sessions {
        for stream in ["depth", "trade"] {
            let path = session.join(format!("{stream}.bnack"));
            watchdog.observe(
                &format!("{source}/{stream}/durability-journal-bytes"),
                file_progress(&path)?,
                now_ns,
            )?;
        }
    }
    Ok(())
}

fn sibling(name: &str) -> Result<PathBuf> {
    let parent = env::current_exe()
        .map_err(|error| format!("current executable: {error}"))?
        .parent()
        .ok_or_else(|| "executable has no parent".to_owned())?
        .to_owned();
    let path = parent.join(format!("{name}{}", env::consts::EXE_SUFFIX));
    if !path.is_file() {
        return Err(format!("missing sibling binary {}", path.display()));
    }
    Ok(path)
}

fn spawn_capture(capture: &Path, symbol: &str, duration: u64, root: &Path) -> Result<ChildGuard> {
    fs::create_dir_all(root).map_err(|error| format!("create {}: {error}", root.display()))?;
    Ok(ChildGuard(Some(
        Command::new(capture)
            .arg(symbol)
            .arg(duration.to_string())
            .arg(root)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("spawn capture: {error}"))?,
    )))
}

fn discover_session(root: &Path, deadline: Instant) -> Result<PathBuf> {
    loop {
        let directories = fs::read_dir(root)
            .map_err(|error| format!("read {}: {error}", root.display()))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        if directories.len() == 1 {
            return Ok(directories[0].clone());
        }
        if deadline.elapsed() > Duration::from_secs(20) {
            return Err("capture session discovery timed out".to_owned());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn durability(ack: &DurabilityAckV1) -> Result<BoundaryDurabilityV1> {
    let watermark = ack
        .streams
        .first()
        .ok_or_else(|| "ACK lacks stream watermark".to_owned())?;
    Ok(BoundaryDurabilityV1 {
        durable_through_frame_index: watermark.durable_through_frame_index,
        durable_through_offset: ack.durable_through_offset,
        last_record_sha256: ack.last_record_sha256.clone(),
    })
}

fn freeze_pair(a: &Path, b: &Path, attempt: &Path) -> Result<FrozenPair> {
    fs::create_dir_all(attempt)
        .map_err(|error| format!("create {}: {error}", attempt.display()))?;
    let freeze = |session: &Path, stream: &str, output: &Path| -> Result<DurabilityAckV1> {
        let scan = scan_durability_progress(&session.join(format!("{stream}.bnack")))?;
        freeze_durable_raw_prefix(&scan, &session.join(format!("{stream}.bnraw")), output)
    };
    let ad = attempt.join("a-depth.bnraw");
    let at = attempt.join("a-trade.bnraw");
    let bd = attempt.join("b-depth.bnraw");
    let bt = attempt.join("b-trade.bnraw");
    let predecessor_depth_ack = freeze(a, "depth", &ad)?;
    let predecessor_trade_ack = freeze(a, "trade", &at)?;
    let successor_depth_ack = freeze(b, "depth", &bd)?;
    let successor_trade_ack = freeze(b, "trade", &bt)?;
    let snapshot = b.join("snapshot.bnraw");
    Ok(FrozenPair {
        predecessor_depth: materialize_depth_observations(&snapshot, &ad)?,
        successor_depth: materialize_depth_observations(&snapshot, &bd)?,
        predecessor_trade: materialize_trade_observations(&at)?,
        successor_trade: materialize_trade_observations(&bt)?,
        predecessor_depth_ack,
        successor_depth_ack,
        predecessor_trade_ack,
        successor_trade_ack,
    })
}

fn commit_boundary(
    path: &Path,
    boundary: HandoverBoundaryV1,
) -> Result<lob_replay::ownership::CommittedBoundaryProofV1> {
    let id = boundary.boundary_id.clone();
    let mut writer = BoundaryJournalWriter::create(path)?;
    writer.propose(boundary)?;
    writer.commit(&id)?;
    load_committed_boundary_proof(path)
}

fn live_handover(depth: &HandoverBoundaryV1) -> Result<HandoverController> {
    let mut handover = HandoverController::new(&depth.symbol, &depth.predecessor_epoch)?;
    for state in [
        EpochState::Buffering,
        EpochState::Snapshotting,
        EpochState::Syncing,
    ] {
        handover.transition_epoch(&depth.predecessor_epoch, state)?;
    }
    handover.mark_live(
        &depth.predecessor_epoch,
        depth.boundary_sequence,
        &depth.boundary_sha256,
    )?;
    handover.activate_initial()?;
    handover.begin_handover(&depth.successor_epoch)?;
    for state in [
        EpochState::Buffering,
        EpochState::Snapshotting,
        EpochState::Syncing,
    ] {
        handover.transition_epoch(&depth.successor_epoch, state)?;
    }
    handover.mark_live(
        &depth.successor_epoch,
        depth.boundary_sequence,
        &depth.boundary_sha256,
    )?;
    Ok(handover)
}

fn latest_ack(session: &Path, stream: &str) -> Result<DurabilityAckV1> {
    scan_durability_progress(&session.join(format!("{stream}.bnack")))?
        .latest_ack
        .ok_or_else(|| format!("{stream} durability progress has no ACK"))
}

#[allow(clippy::too_many_arguments)]
fn publish_successor_delta(
    session: &Path,
    depth_ack: &mut DurabilityAckV1,
    trade_ack: &mut DurabilityAckV1,
    depth_cursor: &mut DepthObservationCursor,
    coordinator: &mut LiveRotationCoordinator,
    depth_output: &mut CanonicalOutputWriter,
    trade_output: &mut CanonicalOutputWriter,
    activation_wall_ns: u64,
    depth_post: &mut u64,
    trade_post: &mut u64,
) -> Result<()> {
    let next_depth = latest_ack(session, "depth")?;
    if next_depth.durable_record_count > depth_ack.durable_record_count {
        for record in read_durable_raw_delta(&session.join("depth.bnraw"), depth_ack, &next_depth)?
        {
            let Some(observation) = depth_cursor.apply_record(&record)? else {
                continue;
            };
            coordinator.accept_observation(
                BoundaryStreamKind::Depth,
                &observation.connection_epoch,
                2,
                observation.first_sequence,
                observation.final_sequence,
            )?;
            depth_output.publish(observation)?;
            if record.frame.receive_wall_ns > activation_wall_ns {
                *depth_post += 1;
            }
        }
        *depth_ack = next_depth;
    } else if next_depth != *depth_ack {
        return Err("depth durability ACK regressed or forked".to_owned());
    }

    let next_trade = latest_ack(session, "trade")?;
    if next_trade.durable_record_count > trade_ack.durable_record_count {
        for record in read_durable_raw_delta(&session.join("trade.bnraw"), trade_ack, &next_trade)?
        {
            let observation = materialize_trade_record(&record)?;
            coordinator.accept_observation(
                BoundaryStreamKind::Trade,
                &observation.connection_epoch,
                2,
                observation.first_sequence,
                observation.final_sequence,
            )?;
            trade_output.publish(observation)?;
            if record.frame.receive_wall_ns > activation_wall_ns {
                *trade_post += 1;
            }
        }
        *trade_ack = next_trade;
    } else if next_trade != *trade_ack {
        return Err("trade durability ACK regressed or forked".to_owned());
    }
    Ok(())
}

fn parse_positive(value: Option<String>, name: &str, maximum: u64) -> Result<u64> {
    let value = value.ok_or_else(|| format!("missing {name}"))?;
    let value = value
        .parse::<u64>()
        .map_err(|error| format!("invalid {name}: {error}"))?;
    if value == 0 || value > maximum {
        return Err(format!("{name} must be within 1..={maximum}"));
    }
    Ok(value)
}

fn capture_durations(warmup: u64, qualification: u64, tail: u64) -> Result<(u64, u64)> {
    let duration_a = warmup
        .checked_add(qualification)
        .and_then(|value| value.checked_add(tail))
        .ok_or_else(|| "predecessor capture duration overflow".to_owned())?;
    let duration_b = qualification
        .checked_add(tail)
        .ok_or_else(|| "successor capture duration overflow".to_owned())?;
    if duration_a > 86_400 || duration_b > 86_400 {
        return Err("each capture duration must remain within 86400 seconds".to_owned());
    }
    Ok((duration_a, duration_b))
}

fn run() -> Result<PathBuf> {
    let mut args = env::args();
    let executable = args
        .next()
        .unwrap_or_else(|| "live_overlap_campaign".to_owned());
    let symbol = args.next().ok_or_else(|| {
        format!(
            "usage: {executable} <BTCUSDT|ETHUSDT> <warmup-s> <qualification-s> <tail-s> [output]"
        )
    })?;
    if !matches!(symbol.as_str(), "BTCUSDT" | "ETHUSDT") {
        return Err("symbol outside fixed scope".to_owned());
    }
    let warmup = parse_positive(args.next(), "warmup-s", 300)?;
    let qualification = parse_positive(args.next(), "qualification-s", 86_400)?;
    let tail = parse_positive(args.next(), "tail-s", 300)?;
    let output_root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("artifacts/live-overlap-campaigns"));
    if args.next().is_some() {
        return Err("too many arguments".to_owned());
    }
    let id = format!(
        "{}-{}-live-{}",
        unix_ns()?,
        symbol,
        &Uuid::new_v4().simple().to_string()[..12]
    );
    let campaign = output_root.join(id);
    fs::create_dir_all(&campaign).map_err(|error| format!("create campaign: {error}"))?;
    let capture = sibling("capture")?;
    let (duration_a, duration_b) = capture_durations(warmup, qualification, tail)?;
    let campaign_clock = Instant::now();
    let discovery = Instant::now();
    let mut child_a = spawn_capture(&capture, &symbol, duration_a, &campaign.join("source-a"))?;
    let session_a = discover_session(&campaign.join("source-a"), discovery)?;
    thread::sleep(Duration::from_secs(warmup));
    let mut child_b = spawn_capture(&capture, &symbol, duration_b, &campaign.join("source-b"))?;
    let session_b = discover_session(&campaign.join("source-b"), Instant::now())?;
    let mut progress_watchdog = ProgressWatchdog::new(
        u64::try_from(DURABLE_PROGRESS_DEAD_AFTER.as_nanos())
            .map_err(|_| "durable progress deadline overflow".to_owned())?,
    )?;
    observe_capture_progress(
        &mut progress_watchdog,
        campaign_clock,
        [("source-a", &session_a), ("source-b", &session_b)],
    )?;

    let deadline = Instant::now() + Duration::from_secs(qualification);
    let mut attempt_index = 0_u64;
    let (pair, depth_boundary, trade_boundary) = loop {
        if !child_a.alive()? || !child_b.alive()? {
            return Err("capture stopped before live convergence".to_owned());
        }
        observe_capture_progress(
            &mut progress_watchdog,
            campaign_clock,
            [("source-a", &session_a), ("source-b", &session_b)],
        )?;
        let attempt = campaign
            .join("prefix-attempts")
            .join(attempt_index.to_string());
        attempt_index += 1;
        if let Ok(pair) = freeze_pair(&session_a, &session_b, &attempt) {
            let depth = derive_handover_boundary(
                &format!("{}-depth", Uuid::new_v4()),
                BoundaryStreamKind::Depth,
                &pair.predecessor_depth.observations,
                &pair.successor_depth.observations,
                durability(&pair.predecessor_depth_ack)?,
                durability(&pair.successor_depth_ack)?,
                SPEC_REVISION,
            );
            let trade = derive_handover_boundary(
                &format!("{}-trade", Uuid::new_v4()),
                BoundaryStreamKind::Trade,
                &pair.predecessor_trade.observations,
                &pair.successor_trade.observations,
                durability(&pair.predecessor_trade_ack)?,
                durability(&pair.successor_trade_ack)?,
                SPEC_REVISION,
            );
            if let (Ok(depth), Ok(trade)) = (depth, trade) {
                break (pair, depth, trade);
            }
        }
        if Instant::now() >= deadline {
            return Err("no durable A/B convergence before qualification deadline".to_owned());
        }
        thread::sleep(Duration::from_millis(500));
    };

    let committed = campaign.join("committed");
    fs::create_dir(&committed).map_err(|error| format!("create committed dir: {error}"))?;
    let depth_proof = commit_boundary(&committed.join("depth.bnhandover"), depth_boundary.clone())?;
    let trade_proof = commit_boundary(&committed.join("trade.bnhandover"), trade_boundary.clone())?;
    let initial = SourcePointerSnapshotV1 {
        schema: "SourcePointerSnapshotV1".to_owned(),
        symbol: symbol.clone(),
        generation_id: "generation-a".to_owned(),
        depth_epoch: depth_boundary.predecessor_epoch.clone(),
        trade_epoch: trade_boundary.predecessor_epoch.clone(),
        fencing_token: 1,
        depth_last_sequence: depth_boundary.boundary_sequence,
        trade_last_sequence: trade_boundary.boundary_sequence,
    };
    let ledger_path = committed.join("ownership.bnledger");
    let predecessor_depth_boundary = pair
        .predecessor_depth
        .observations
        .iter()
        .find(|item| item.frame_index == depth_boundary.predecessor_last_selected.frame_index)
        .ok_or_else(|| "missing predecessor depth boundary observation".to_owned())?
        .clone();
    let predecessor_trade_boundary = pair
        .predecessor_trade
        .observations
        .iter()
        .find(|item| item.frame_index == trade_boundary.predecessor_last_selected.frame_index)
        .ok_or_else(|| "missing predecessor trade boundary observation".to_owned())?
        .clone();
    let mut depth_output = CanonicalOutputWriter::create(
        &committed.join("depth.bnpub"),
        &symbol,
        BoundaryStreamKind::Depth,
        CanonicalOutputOwnerV1 {
            generation_id: "generation-a".to_owned(),
            connection_epoch: depth_boundary.predecessor_epoch.clone(),
            fencing_token: 1,
            last_sequence: predecessor_depth_boundary
                .first_sequence
                .checked_sub(1)
                .ok_or_else(|| "depth publication sequence underflow".to_owned())?,
        },
    )?;
    depth_output.publish(predecessor_depth_boundary)?;
    let mut trade_output = CanonicalOutputWriter::create(
        &committed.join("trade.bnpub"),
        &symbol,
        BoundaryStreamKind::Trade,
        CanonicalOutputOwnerV1 {
            generation_id: "generation-a".to_owned(),
            connection_epoch: trade_boundary.predecessor_epoch.clone(),
            fencing_token: 1,
            last_sequence: predecessor_trade_boundary
                .first_sequence
                .checked_sub(1)
                .ok_or_else(|| "trade publication sequence underflow".to_owned())?,
        },
    )?;
    trade_output.publish(predecessor_trade_boundary)?;
    let mut ledger = OwnershipLedgerWriter::create(&ledger_path, initial)?;
    let pointer = CanonicalSourcePointer::recover(&scan_ownership_ledger(&ledger_path)?, None)?;
    let mut coordinator = LiveRotationCoordinator::new(live_handover(&depth_boundary)?, pointer)?;
    let activation = coordinator.activate_committed(
        &mut ledger,
        &ledger_path,
        &format!("activation-{}", Uuid::new_v4()),
        "generation-b",
        &depth_proof,
        &trade_proof,
    )?;
    depth_output.change_owner(
        "generation-b",
        &depth_boundary.successor_epoch,
        2,
        depth_boundary.boundary_sequence,
        &activation.activate_ack.last_record_sha256,
    )?;
    trade_output.change_owner(
        "generation-b",
        &trade_boundary.successor_epoch,
        2,
        trade_boundary.boundary_sequence,
        &activation.activate_ack.last_record_sha256,
    )?;
    let activation_wall_ns = unix_ns()?;
    let predecessor_alive_at_activation = child_a.alive()?;
    let successor_alive_at_activation = child_b.alive()?;
    if !predecessor_alive_at_activation || !successor_alive_at_activation {
        return Err("a capture was not alive at durable activation".to_owned());
    }
    let _ = coordinator.accept_observation(
        BoundaryStreamKind::Depth,
        &depth_boundary.predecessor_epoch,
        1,
        depth_boundary.boundary_sequence + 1,
        depth_boundary.boundary_sequence + 1,
    );

    let mut depth_post = 0_u64;
    let mut trade_post = 0_u64;
    for observation in &pair.successor_depth.observations {
        if observation.frame_index < depth_boundary.successor_first_selected.frame_index
            || observation.final_sequence <= coordinator.pointer.owner.depth_last_sequence
        {
            continue;
        }
        coordinator.accept_observation(
            BoundaryStreamKind::Depth,
            &observation.connection_epoch,
            2,
            observation.first_sequence,
            observation.final_sequence,
        )?;
        depth_output.publish(observation.clone())?;
    }
    for observation in &pair.successor_trade.observations {
        if observation.frame_index < trade_boundary.successor_first_selected.frame_index
            || observation.final_sequence <= coordinator.pointer.owner.trade_last_sequence
        {
            continue;
        }
        coordinator.accept_observation(
            BoundaryStreamKind::Trade,
            &observation.connection_epoch,
            2,
            observation.first_sequence,
            observation.final_sequence,
        )?;
        trade_output.publish(observation.clone())?;
    }
    let mut depth_ack = pair.successor_depth_ack.clone();
    let mut trade_ack = pair.successor_trade_ack.clone();
    let mut depth_cursor = DepthObservationCursor::from_durable_prefix(
        &session_b.join("snapshot.bnraw"),
        &session_b.join("depth.bnraw"),
        depth_ack.durable_through_offset,
    )?;
    let campaign_end = deadline + Duration::from_secs(tail);
    while Instant::now() < campaign_end {
        if !child_a.alive()? || !child_b.alive()? {
            return Err("capture stopped before progressive campaign deadline".to_owned());
        }
        observe_capture_progress(
            &mut progress_watchdog,
            campaign_clock,
            [("source-a", &session_a), ("source-b", &session_b)],
        )?;
        publish_successor_delta(
            &session_b,
            &mut depth_ack,
            &mut trade_ack,
            &mut depth_cursor,
            &mut coordinator,
            &mut depth_output,
            &mut trade_output,
            activation_wall_ns,
            &mut depth_post,
            &mut trade_post,
        )?;
        thread::sleep(Duration::from_millis(500));
    }
    let predecessor_session = child_a.finish("predecessor capture")?;
    let successor_session = child_b.finish("successor capture")?;
    publish_successor_delta(
        &session_b,
        &mut depth_ack,
        &mut trade_ack,
        &mut depth_cursor,
        &mut coordinator,
        &mut depth_output,
        &mut trade_output,
        activation_wall_ns,
        &mut depth_post,
        &mut trade_post,
    )?;
    if depth_post == 0 || trade_post == 0 {
        return Err("no durable post-activation B continuation for both streams".to_owned());
    }

    drop(depth_output);
    drop(trade_output);
    let depth_output = scan_canonical_output(&committed.join("depth.bnpub"))?;
    let trade_output = scan_canonical_output(&committed.join("trade.bnpub"))?;
    if !depth_output.clean_eof
        || !trade_output.clean_eof
        || depth_output.ownership_changes != 1
        || trade_output.ownership_changes != 1
        || depth_output.owner.as_ref().map(|owner| owner.last_sequence)
            != Some(coordinator.pointer.owner.depth_last_sequence)
        || trade_output.owner.as_ref().map(|owner| owner.last_sequence)
            != Some(coordinator.pointer.owner.trade_last_sequence)
    {
        return Err("canonical downstream output failed final recovery".to_owned());
    }

    let report = LiveCampaignReportV1 {
        schema: "LiveCampaignReportV1",
        status: "ACTIVATED_WHILE_RECEIVING",
        symbol,
        predecessor_session,
        successor_session,
        activation_wall_ns,
        predecessor_alive_at_activation,
        successor_alive_at_activation,
        depth_boundary_sequence: depth_boundary.boundary_sequence,
        trade_boundary_sequence: trade_boundary.boundary_sequence,
        depth_post_activation_accepted: depth_post,
        trade_post_activation_accepted: trade_post,
        fenced_predecessor_rejections: coordinator.pointer.fenced_rejections,
        activation,
        depth_output,
        trade_output,
        credentials: "NONE",
        order_entry: "ABSENT",
    };
    let path = campaign.join("live-campaign.json");
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("serialize live campaign: {error}"))?;
    bytes.push(b'\n');
    fs::write(&path, bytes).map_err(|error| format!("write report: {error}"))?;
    Ok(path)
}

fn main() {
    match run() {
        Ok(path) => println!("{}", path.display()),
        Err(error) => {
            eprintln!("live-overlap-campaign: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{capture_durations, parse_positive};

    #[test]
    fn progressive_qualification_duration_is_allowed() {
        assert_eq!(
            parse_positive(Some("900".to_owned()), "qualification-s", 86_400),
            Ok(900)
        );
        assert!(parse_positive(Some("301".to_owned()), "warmup-s", 300).is_err());
    }

    #[test]
    fn combined_capture_duration_never_exceeds_exchange_limit() {
        assert_eq!(capture_durations(5, 900, 10), Ok((915, 910)));
        assert!(capture_durations(1, 86_400, 1).is_err());
        assert_eq!(capture_durations(10, 86_380, 10), Ok((86_400, 86_390)));
    }
}
