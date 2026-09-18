use lob_replay::durability_follower::SegmentDurabilityFollower;
use lob_replay::durability_progress::DurabilityProgressWriter;
use lob_replay::segment_chain::{
    root_segment_genesis, successor_segment_genesis, verify_and_seal_raw_segment,
};
use lob_replay::{
    CapturedFrame, DurabilityAckV1, RawLogWriter, RawSegmentGenesisV1, StreamDurabilityWatermarkV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

const EPOCH: &str = "epoch-follower";
const STREAM: &str = "btcusdt@trade";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize)]
struct TestProgressBody<'a> {
    schema: &'static str,
    record_index: u64,
    raw_path: &'a str,
    ack: &'a DurabilityAckV1,
    previous_record_sha256: &'a str,
}

#[derive(Serialize)]
struct TestProgressEnvelope<'a> {
    body: TestProgressBody<'a>,
    record_sha256: String,
}

fn frame(genesis: &RawSegmentGenesisV1, index: u64) -> CapturedFrame {
    CapturedFrame {
        venue: "binance-spot".to_owned(),
        environment: "production-public-market-data".to_owned(),
        endpoint: "wss://data-stream.binance.vision/ws/btcusdt@trade".to_owned(),
        stream: genesis.stream.clone(),
        symbol: "BTCUSDT".to_owned(),
        connection_epoch: genesis.connection_epoch.clone(),
        frame_index: index,
        receive_wall_ns: 1_000 + index,
        receive_mono_ns: 2_000 + index,
        clock_quality: "UNSYNCHRONIZED".to_owned(),
        clock_source: "test".to_owned(),
        payload: format!("{{\"e\":\"trade\",\"s\":\"BTCUSDT\",\"t\":{index}}}").into_bytes(),
        spec_revision: "976cc580553890e92031b77306147c0ed1de5a46".to_owned(),
    }
}

fn encode_progress(
    record_index: u64,
    raw_path: &str,
    ack: &DurabilityAckV1,
    previous: &str,
) -> (Vec<u8>, String) {
    let body = TestProgressBody {
        schema: "RawDurabilityProgressV1",
        record_index,
        raw_path,
        ack,
        previous_record_sha256: previous,
    };
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let digest = hex(&Sha256::digest(&body_bytes));
    let mut encoded = serde_json::to_vec(&TestProgressEnvelope {
        body,
        record_sha256: digest.clone(),
    })
    .unwrap();
    encoded.push(b'\n');
    (encoded, digest)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn one_record_raw(
    directory: &Path,
    raw_file: &str,
    genesis: &RawSegmentGenesisV1,
) -> (std::path::PathBuf, DurabilityAckV1) {
    let raw_path = directory.join(raw_file);
    let mut raw = RawLogWriter::create_segment(&raw_path, 1, genesis).unwrap();
    let ack = raw
        .append(&frame(genesis, genesis.next_frame_index))
        .unwrap()
        .durability_ack
        .unwrap();
    drop(raw);
    (raw_path, ack)
}

#[test]
fn follower_advances_from_cursor_without_replaying_prior_journal_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let raw_path = directory.path().join("root.bnraw");
    let progress_path = directory.path().join("root.bnack");
    let mut raw = RawLogWriter::create_segment(&raw_path, 1, &genesis).unwrap();
    let mut progress = DurabilityProgressWriter::create(&progress_path, &raw_path).unwrap();
    let mut follower =
        SegmentDurabilityFollower::open(&progress_path, &raw_path, &genesis).unwrap();
    let mut prior_journal_offset = 0;
    for index in 0..3 {
        let ack = raw
            .append(&frame(&genesis, index))
            .unwrap()
            .durability_ack
            .unwrap();
        progress.append(ack).unwrap();
        let poll = follower.poll().unwrap();
        assert_eq!(poll.records.len(), 1);
        assert_eq!(poll.records[0].record_index, index);
        assert_eq!(poll.records[0].journal_start_offset, prior_journal_offset);
        assert_eq!(poll.records[0].acknowledged_records, 1);
        prior_journal_offset = poll.records[0].journal_end_offset;
        assert_eq!(poll.cursor.journal_offset, prior_journal_offset);
        assert_eq!(poll.pending_tail_bytes, 0);
    }
    assert_eq!(follower.cursor().next_record_index, 3);
    assert_eq!(
        follower.require_clean_eof().unwrap().raw_next_frame_index,
        3
    );
}

#[test]
fn partial_journal_tail_waits_and_then_completes_exactly_once() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let (raw_path, ack) = one_record_raw(directory.path(), "root.bnraw", &genesis);
    let template = directory.path().join("template.bnack");
    {
        let mut progress = DurabilityProgressWriter::create(&template, &raw_path).unwrap();
        progress.append(ack).unwrap();
    }
    let complete = std::fs::read(&template).unwrap();
    assert_eq!(complete.last(), Some(&b'\n'));
    let target = directory.path().join("live.bnack");
    std::fs::write(&target, &complete[..complete.len() - 1]).unwrap();
    let mut follower = SegmentDurabilityFollower::open(&target, &raw_path, &genesis).unwrap();
    let pending = follower.poll().unwrap();
    assert!(pending.records.is_empty());
    assert_eq!(pending.pending_tail_bytes as usize, complete.len() - 1);
    assert_eq!(follower.cursor().next_record_index, 0);

    OpenOptions::new()
        .append(true)
        .open(&target)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    let completed = follower.poll().unwrap();
    assert_eq!(completed.records.len(), 1);
    assert_eq!(completed.pending_tail_bytes, 0);
    assert!(follower.poll().unwrap().records.is_empty());
}

#[test]
fn successor_segment_is_verified_from_nonzero_digest_and_frame_seed() {
    let directory = tempfile::tempdir().unwrap();
    let root_genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let root_path = directory.path().join("root.bnraw");
    let mut root = RawLogWriter::create_segment(&root_path, 64, &root_genesis).unwrap();
    root.append(&frame(&root_genesis, 0)).unwrap();
    root.append(&frame(&root_genesis, 1)).unwrap();
    let root_ack = root.sync().unwrap();
    drop(root);
    let root_verified =
        verify_and_seal_raw_segment(&root_path, "root.bnraw", &root_genesis, &root_ack).unwrap();

    let successor_genesis = successor_segment_genesis(root_verified.seal()).unwrap();
    let successor_path = directory.path().join("successor.bnraw");
    let progress_path = directory.path().join("successor.bnack");
    let mut raw = RawLogWriter::create_segment(&successor_path, 1, &successor_genesis).unwrap();
    let mut progress = DurabilityProgressWriter::create(&progress_path, &successor_path).unwrap();
    for index in 2..4 {
        let ack = raw
            .append(&frame(&successor_genesis, index))
            .unwrap()
            .durability_ack
            .unwrap();
        progress.append(ack).unwrap();
    }
    let mut follower =
        SegmentDurabilityFollower::open(&progress_path, &successor_path, &successor_genesis)
            .unwrap();
    let poll = follower.poll().unwrap();
    assert_eq!(poll.records.len(), 2);
    assert_eq!(
        poll.records[0].ack.streams[0].durable_through_frame_index,
        2
    );
    assert_eq!(poll.cursor.raw_next_frame_index, 4);
    assert_eq!(
        successor_genesis.previous_segment_terminal_sha256,
        root_verified.seal().terminal_record_sha256
    );
}

#[test]
fn acknowledged_prefix_ignores_a_newer_unacknowledged_raw_tail() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let raw_path = directory.path().join("root.bnraw");
    let progress_path = directory.path().join("root.bnack");
    let mut raw = RawLogWriter::create_segment(&raw_path, 64, &genesis).unwrap();
    raw.append(&frame(&genesis, 0)).unwrap();
    let ack = raw.sync().unwrap();
    let mut progress = DurabilityProgressWriter::create(&progress_path, &raw_path).unwrap();
    progress.append(ack).unwrap();
    raw.append(&frame(&genesis, 1)).unwrap();

    let mut follower =
        SegmentDurabilityFollower::open(&progress_path, &raw_path, &genesis).unwrap();
    let poll = follower.poll().unwrap();
    assert_eq!(poll.records.len(), 1);
    assert_eq!(poll.cursor.raw_record_count, 1);
    assert_eq!(poll.cursor.raw_next_frame_index, 1);
}

#[test]
fn truncation_and_replacement_are_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let (raw_path, ack) = one_record_raw(directory.path(), "root.bnraw", &genesis);

    let truncated_path = directory.path().join("truncated.bnack");
    {
        let mut progress = DurabilityProgressWriter::create(&truncated_path, &raw_path).unwrap();
        progress.append(ack).unwrap();
    }
    let mut truncated =
        SegmentDurabilityFollower::open(&truncated_path, &raw_path, &genesis).unwrap();
    let offset = truncated.poll().unwrap().cursor.journal_offset;
    OpenOptions::new()
        .write(true)
        .open(&truncated_path)
        .unwrap()
        .set_len(offset - 1)
        .unwrap();
    assert!(truncated.poll().unwrap_err().contains("truncated"));
    assert!(truncated.is_poisoned());

    let replaced_path = directory.path().join("replaced.bnack");
    std::fs::write(&replaced_path, []).unwrap();
    let mut replaced =
        SegmentDurabilityFollower::open(&replaced_path, &raw_path, &genesis).unwrap();
    std::fs::remove_file(&replaced_path).unwrap();
    std::fs::write(&replaced_path, []).unwrap();
    assert!(replaced.poll().unwrap_err().contains("replaced"));
    assert!(replaced.is_poisoned());
}

#[test]
fn raw_path_drift_regression_fork_and_fabricated_ack_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let (raw_path, ack) = one_record_raw(directory.path(), "root.bnraw", &genesis);
    let raw_path_text = raw_path.display().to_string();

    let drift_path = directory.path().join("drift.bnack");
    let (drift, _) = encode_progress(0, "different.bnraw", &ack, ZERO_DIGEST);
    std::fs::write(&drift_path, drift).unwrap();
    let mut drift_follower =
        SegmentDurabilityFollower::open(&drift_path, &raw_path, &genesis).unwrap();
    assert!(
        drift_follower
            .poll()
            .unwrap_err()
            .contains("raw_path drift")
    );

    let regression_path = directory.path().join("regression.bnack");
    let (first, first_digest) = encode_progress(0, &raw_path_text, &ack, ZERO_DIGEST);
    let (second, _) = encode_progress(1, &raw_path_text, &ack, &first_digest);
    let mut regression_bytes = first;
    regression_bytes.extend_from_slice(&second);
    std::fs::write(&regression_path, regression_bytes).unwrap();
    let mut regression =
        SegmentDurabilityFollower::open(&regression_path, &raw_path, &genesis).unwrap();
    assert!(regression.poll().unwrap_err().contains("regressed"));
    assert_eq!(regression.cursor().next_record_index, 1);

    let fork_path = directory.path().join("fork.bnack");
    let (fork, _) = encode_progress(0, &raw_path_text, &ack, &"f".repeat(64));
    std::fs::write(&fork_path, fork).unwrap();
    let mut fork_follower =
        SegmentDurabilityFollower::open(&fork_path, &raw_path, &genesis).unwrap();
    assert!(fork_follower.poll().unwrap_err().contains("fork"));

    let fabricated_path = directory.path().join("fabricated.bnack");
    let fabricated_ack = DurabilityAckV1 {
        schema: "DurabilityAckV1".to_owned(),
        durable_record_count: 1,
        durable_through_offset: ack.durable_through_offset,
        last_record_sha256: "f".repeat(64),
        streams: vec![StreamDurabilityWatermarkV1 {
            connection_epoch: EPOCH.to_owned(),
            stream: STREAM.to_owned(),
            durable_through_frame_index: 0,
        }],
    };
    let (fabricated, _) = encode_progress(0, &raw_path_text, &fabricated_ack, ZERO_DIGEST);
    std::fs::write(&fabricated_path, fabricated).unwrap();
    let mut fabricated_follower =
        SegmentDurabilityFollower::open(&fabricated_path, &raw_path, &genesis).unwrap();
    assert!(fabricated_follower.poll().is_err());
    assert!(fabricated_follower.is_poisoned());
}

#[test]
fn portable_reference_survives_moving_the_complete_artifact_directory() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let raw_file = "segment-000000.bnraw";
    let raw_path = source.join(raw_file);
    let progress_file = "segment-000000.bnack";
    let progress_path = source.join(progress_file);
    let mut raw = RawLogWriter::create_segment(&raw_path, 1, &genesis).unwrap();
    let ack = raw
        .append(&frame(&genesis, 0))
        .unwrap()
        .durability_ack
        .unwrap();
    let mut progress =
        DurabilityProgressWriter::create_with_reference(&progress_path, &raw_path, raw_file)
            .unwrap();
    progress.append(ack.clone()).unwrap();
    drop(progress);
    drop(raw);

    let moved = directory.path().join("moved");
    std::fs::rename(&source, &moved).unwrap();
    let mut follower = SegmentDurabilityFollower::open_with_reference(
        &moved.join(progress_file),
        &moved.join(raw_file),
        &genesis,
        raw_file,
    )
    .unwrap();
    let cursor = follower.require_clean_eof().unwrap();
    assert_eq!(cursor.latest_ack, Some(ack));
    assert_eq!(cursor.raw_record_count, 1);
}

#[test]
fn portable_reference_rejects_unsafe_paths_target_drift_and_journal_drift() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = root_segment_genesis(EPOCH, STREAM).unwrap();
    let raw_file = "segment-000000.bnraw";
    let (raw_path, ack) = one_record_raw(directory.path(), raw_file, &genesis);

    let unsafe_references = [
        "",
        ".",
        "..",
        "../segment-000000.bnraw",
        "subdir/../segment-000000.bnraw",
        "subdir\\segment-000000.bnraw",
        "C:\\segment-000000.bnraw",
        "/segment-000000.bnraw",
        " segment-000000.bnraw",
    ];
    for (index, reference) in unsafe_references.iter().enumerate() {
        let progress_path = directory.path().join(format!("unsafe-{index}.bnack"));
        assert!(
            DurabilityProgressWriter::create_with_reference(&progress_path, &raw_path, reference,)
                .is_err(),
            "unsafe reference was accepted: {reference:?}"
        );
        assert!(!progress_path.exists());
    }

    let other_path = directory.path().join("other.bnraw");
    let other_genesis = root_segment_genesis("epoch-other", STREAM).unwrap();
    let mut other = RawLogWriter::create_segment(&other_path, 1, &other_genesis).unwrap();
    other.append(&frame(&other_genesis, 0)).unwrap();
    drop(other);
    assert!(
        DurabilityProgressWriter::create_with_reference(
            &directory.path().join("target-drift.bnack"),
            &raw_path,
            "other.bnraw",
        )
        .err()
        .unwrap()
        .contains("does not identify")
    );

    let valid_progress_path = directory.path().join("valid.bnack");
    let mut valid =
        DurabilityProgressWriter::create_with_reference(&valid_progress_path, &raw_path, raw_file)
            .unwrap();
    valid.append(ack.clone()).unwrap();
    drop(valid);
    assert!(
        SegmentDurabilityFollower::open_with_reference(
            &valid_progress_path,
            &raw_path,
            &genesis,
            "../segment-000000.bnraw",
        )
        .is_err()
    );
    assert!(
        SegmentDurabilityFollower::open_with_reference(
            &valid_progress_path,
            &raw_path,
            &genesis,
            "other.bnraw",
        )
        .err()
        .unwrap()
        .contains("does not identify")
    );

    let drift_path = directory.path().join("portable-drift.bnack");
    let (drift, _) = encode_progress(0, "other.bnraw", &ack, ZERO_DIGEST);
    std::fs::write(&drift_path, drift).unwrap();
    let mut follower =
        SegmentDurabilityFollower::open_with_reference(&drift_path, &raw_path, &genesis, raw_file)
            .unwrap();
    assert!(follower.poll().unwrap_err().contains("raw_path drift"));
    assert!(follower.is_poisoned());
}
