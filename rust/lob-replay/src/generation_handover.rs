//! Raw-only A/B overlap proof for segmented capture generations.
//!
//! Nothing here selects a trading signal or rewrites raw evidence. Depth uses
//! Binance's documented update sequence plus exact reconstructed state
//! convergence. Individual trades use two exact ordered events observed on A
//! and B; no promise of consecutive trade IDs is invented.

use crate::boundary::{BoundaryStreamKind, CanonicalObservationV1, RawPositionV1};
use crate::durability_follower::SegmentDurabilityFollower;
use crate::generation_artifact::{
    SEGMENTED_SPEC_REVISION, VerifiedGenerationStreamV1, VerifiedGenerationV1,
    verify_segmented_generation,
};
use crate::observations::{latest_depth_window_convergence, materialize_trade_record_window};
use crate::segment_chain::{
    RawSegmentManifestEntryV1, scan_segment_manifest, verify_and_seal_raw_segment,
};
use crate::{
    DurabilityAckV1, RawRecordEnvelopeV1, RawSegmentGenesisV1, Result, StreamDurabilityWatermarkV1,
    read_raw_records, read_raw_segment_records, scan_raw_log,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSegmentPublicationV1 {
    pub schema: String,
    pub stream: String,
    pub connection_epoch: String,
    pub segment_index: u64,
    pub raw_file: String,
    pub first_frame_index: u64,
    pub last_frame_index: u64,
    pub records: u64,
    pub durable_through_offset: u64,
    pub previous_segment_terminal_sha256: String,
    pub terminal_record_sha256: String,
    pub manifest_record_index: u64,
    pub manifest_durable_through_offset: u64,
    pub manifest_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSnapshotPublicationV1 {
    pub raw_file: String,
    pub durable_through_offset: u64,
    pub last_record_sha256: String,
    pub http_metadata_file: String,
    pub http_metadata_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupManifestV1 {
    schema: String,
    implementation: String,
    session_id: String,
    generation_index: u64,
    symbol: String,
    duration_requested_s: u64,
    segment_duration_s: u64,
    started_wall_ns: u64,
    collector_executable_sha256: String,
    public_config_sha256: String,
    market_freshness_startup_grace_s: u64,
    market_freshness_deadline_s: u64,
    credentials: String,
    order_entry: String,
    raw_boundary: String,
    spec_revision: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotHttpMetadataV1 {
    schema: String,
    endpoint: String,
    http_status: u16,
    headers: HashMap<String, Vec<String>>,
    receive_wall_ns: u64,
    receive_mono_ns: u64,
    body_complete: bool,
    body_length: usize,
    body_sha256: String,
    raw_file: String,
    raw_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSegmentReferenceV1 {
    pub stream: String,
    pub connection_epoch: String,
    pub segment_index: u64,
    pub manifest_record_sha256: String,
    pub raw_file: String,
    pub first_frame_index: u64,
    pub last_frame_index: u64,
    pub terminal_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DepthOverlapEvidenceV1 {
    pub schema: String,
    pub predecessor_segment: RawSegmentReferenceV1,
    pub successor_segment: RawSegmentReferenceV1,
    pub boundary_sequence: u64,
    pub boundary_state_sha256: String,
    pub predecessor_boundary: RawPositionV1,
    pub successor_boundary: RawPositionV1,
    pub successor_continuation: RawPositionV1,
    pub successor_continuation_first_sequence: u64,
    pub successor_continuation_final_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TradeOverlapEvidenceV1 {
    pub schema: String,
    pub predecessor_segment: RawSegmentReferenceV1,
    pub successor_segment: RawSegmentReferenceV1,
    pub common_lower_trade_id: u64,
    pub common_upper_trade_id: u64,
    pub common_events: u64,
    pub first_shared_trade_id: u64,
    pub first_shared_event_sha256: String,
    pub predecessor_first_shared: RawPositionV1,
    pub successor_first_shared: RawPositionV1,
    pub next_shared_trade_id: u64,
    pub next_shared_event_sha256: String,
    pub predecessor_next_shared: RawPositionV1,
    pub successor_next_shared: RawPositionV1,
    pub trade_id_contiguity_claim: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawGenerationHandoverProofV1 {
    pub schema: String,
    pub status: String,
    pub predecessor_session_id: String,
    pub successor_session_id: String,
    pub predecessor_generation_index: u64,
    pub successor_generation_index: u64,
    pub symbol: String,
    pub credentials: String,
    pub order_entry: String,
    pub predecessor_verification_sha256: String,
    pub successor_startup_sha256: String,
    pub successor_snapshot_record_sha256: String,
    pub successor_snapshot_http_sha256: String,
    pub depth: DepthOverlapEvidenceV1,
    pub trade: TradeOverlapEvidenceV1,
    pub proof_sha256: String,
}

#[derive(Serialize)]
struct ProofDigestMaterial<'a> {
    schema: &'static str,
    predecessor_session_id: &'a str,
    successor_session_id: &'a str,
    predecessor_generation_index: u64,
    successor_generation_index: u64,
    symbol: &'a str,
    predecessor_verification_sha256: &'a str,
    successor_startup_sha256: &'a str,
    successor_snapshot_record_sha256: &'a str,
    successor_snapshot_http_sha256: &'a str,
    depth: &'a DepthOverlapEvidenceV1,
    trade: &'a TradeOverlapEvidenceV1,
}

struct SuccessorIdentity {
    session_id: String,
    generation_index: u64,
    symbol: String,
    snapshot: RawRecordEnvelopeV1,
}

fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex(&Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn validate_raw_handover_proof_digest(proof: &RawGenerationHandoverProofV1) -> Result<()> {
    if proof.schema != "RawGenerationHandoverProofV1"
        || proof.status != "PROVEN"
        || proof.credentials != "NONE"
        || proof.order_entry != "ABSENT"
        || proof.predecessor_generation_index.checked_add(1)
            != Some(proof.successor_generation_index)
        || !matches!(proof.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
        || proof.depth.schema != "DepthOverlapEvidenceV1"
        || proof.trade.schema != "TradeOverlapEvidenceV1"
        || proof.trade.trade_id_contiguity_claim
            != "NONE_OFFICIAL_CONTRACT_DOES_NOT_PROMISE_CONSECUTIVE_IDS"
        || proof.trade.common_events < 2
        || proof.trade.common_lower_trade_id > proof.trade.common_upper_trade_id
        || !valid_sha256(&proof.predecessor_verification_sha256)
        || !valid_sha256(&proof.successor_startup_sha256)
        || !valid_sha256(&proof.successor_snapshot_record_sha256)
        || !valid_sha256(&proof.successor_snapshot_http_sha256)
        || !valid_sha256(&proof.proof_sha256)
    {
        return Err("raw handover proof contract is invalid".to_owned());
    }
    let material = ProofDigestMaterial {
        schema: "RawGenerationHandoverProofDigestV1",
        predecessor_session_id: &proof.predecessor_session_id,
        successor_session_id: &proof.successor_session_id,
        predecessor_generation_index: proof.predecessor_generation_index,
        successor_generation_index: proof.successor_generation_index,
        symbol: &proof.symbol,
        predecessor_verification_sha256: &proof.predecessor_verification_sha256,
        successor_startup_sha256: &proof.successor_startup_sha256,
        successor_snapshot_record_sha256: &proof.successor_snapshot_record_sha256,
        successor_snapshot_http_sha256: &proof.successor_snapshot_http_sha256,
        depth: &proof.depth,
        trade: &proof.trade,
    };
    let digest = sha256_hex(
        &serde_json::to_vec(&material)
            .map_err(|error| format!("serialize raw handover proof digest: {error}"))?,
    );
    if digest != proof.proof_sha256 {
        return Err("raw handover proof self-digest mismatch".to_owned());
    }
    Ok(())
}

fn position(observation: &CanonicalObservationV1) -> RawPositionV1 {
    RawPositionV1 {
        connection_epoch: observation.connection_epoch.clone(),
        stream: observation.stream.clone(),
        frame_index: observation.frame_index,
        record_sha256: observation.record_sha256.clone(),
    }
}

fn ack_from_entry(entry: &RawSegmentManifestEntryV1) -> DurabilityAckV1 {
    DurabilityAckV1 {
        schema: "DurabilityAckV1".to_owned(),
        durable_record_count: entry.seal.records,
        durable_through_offset: entry.seal.durable_through_offset,
        last_record_sha256: entry.seal.terminal_record_sha256.clone(),
        streams: vec![StreamDurabilityWatermarkV1 {
            connection_epoch: entry.seal.connection_epoch.clone(),
            stream: entry.seal.stream.clone(),
            durable_through_frame_index: entry.seal.last_frame_index,
        }],
    }
}

fn genesis_from_entry(entry: &RawSegmentManifestEntryV1) -> RawSegmentGenesisV1 {
    RawSegmentGenesisV1 {
        schema: "RawSegmentGenesisV1".to_owned(),
        segment_index: entry.seal.segment_index,
        previous_segment_terminal_sha256: entry.seal.previous_segment_terminal_sha256.clone(),
        connection_epoch: entry.seal.connection_epoch.clone(),
        stream: entry.seal.stream.clone(),
        next_frame_index: entry.seal.first_frame_index,
    }
}

fn segment_reference(entry: &RawSegmentManifestEntryV1) -> RawSegmentReferenceV1 {
    RawSegmentReferenceV1 {
        stream: entry.seal.stream.clone(),
        connection_epoch: entry.seal.connection_epoch.clone(),
        segment_index: entry.seal.segment_index,
        manifest_record_sha256: entry.manifest_record_sha256.clone(),
        raw_file: entry.seal.raw_file.clone(),
        first_frame_index: entry.seal.first_frame_index,
        last_frame_index: entry.seal.last_frame_index,
        terminal_record_sha256: entry.seal.terminal_record_sha256.clone(),
    }
}

fn first_manifest_record_end(path: &Path) -> Result<u64> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut header = [0_u8; 12];
    file.read_exact(&mut header)
        .map_err(|_| "segment manifest lacks a complete first record header".to_owned())?;
    if &header[..8] != b"BNSEG\0\x01\n" {
        return Err("bad segment manifest magic".to_owned());
    }
    let body_length = u32::from_be_bytes(header[8..12].try_into().expect("four-byte slice"));
    12_u64
        .checked_add(u64::from(body_length))
        .and_then(|offset| offset.checked_add(32))
        .ok_or_else(|| "segment manifest first-record offset overflow".to_owned())
}

fn publication_matches(
    entry: &RawSegmentManifestEntryV1,
    expected_stream: &str,
    publication: &ExpectedSegmentPublicationV1,
    exact_manifest_offset: u64,
) -> bool {
    let seal = &entry.seal;
    publication.schema == "DurableSegmentEventV1"
        && publication.stream == expected_stream
        && publication.connection_epoch == seal.connection_epoch
        && publication.segment_index == 0
        && publication.segment_index == seal.segment_index
        && publication.raw_file == seal.raw_file
        && publication.first_frame_index == seal.first_frame_index
        && publication.last_frame_index == seal.last_frame_index
        && publication.records == seal.records
        && publication.durable_through_offset == seal.durable_through_offset
        && publication.previous_segment_terminal_sha256 == seal.previous_segment_terminal_sha256
        && publication.terminal_record_sha256 == seal.terminal_record_sha256
        && publication.manifest_record_index == 0
        && publication.manifest_record_index == entry.record_index
        && publication.manifest_durable_through_offset == exact_manifest_offset
        && publication.manifest_record_sha256 == entry.manifest_record_sha256
}

fn validate_successor_frame_identity(
    records: &[RawRecordEnvelopeV1],
    identity: &SuccessorIdentity,
    stream_name: &str,
    epoch: &str,
) -> Result<()> {
    let stream = if stream_name == "depth" {
        format!("{}@depth@100ms", identity.symbol.to_ascii_lowercase())
    } else {
        format!("{}@trade", identity.symbol.to_ascii_lowercase())
    };
    let endpoint = format!("wss://data-stream.binance.vision:443/ws/{stream}?timeUnit=MICROSECOND");
    if records.iter().any(|record| {
        record.frame.venue != "binance-spot"
            || record.frame.environment != "production-public-market-data"
            || record.frame.symbol != identity.symbol
            || record.frame.stream != stream
            || record.frame.connection_epoch != epoch
            || record.frame.endpoint != endpoint
            || record.frame.spec_revision != SEGMENTED_SPEC_REVISION
            || record.frame.recorder_state != "PENDING"
    }) {
        return Err(format!(
            "successor {stream_name} root segment identity drift"
        ));
    }
    Ok(())
}

fn verified_published_root(
    session: &Path,
    identity: &SuccessorIdentity,
    stream_name: &str,
    publication: &ExpectedSegmentPublicationV1,
) -> Result<(RawSegmentManifestEntryV1, Vec<RawRecordEnvelopeV1>)> {
    let stream_directory = session.join(stream_name);
    let manifest_path = stream_directory.join("segments.bnseg");
    let scan = scan_segment_manifest(&manifest_path)?;
    let entry = scan
        .entries
        .first()
        .ok_or_else(|| format!("successor {stream_name} root publication is absent"))?
        .clone();
    if !publication_matches(
        &entry,
        stream_name,
        publication,
        first_manifest_record_end(&manifest_path)?,
    ) {
        return Err(format!(
            "successor {stream_name} typed publication differs from exact BNSEG root"
        ));
    }
    let genesis = genesis_from_entry(&entry);
    let ack = ack_from_entry(&entry);
    let raw_path = stream_directory.join(&entry.seal.raw_file);
    let verified = verify_and_seal_raw_segment(&raw_path, &entry.seal.raw_file, &genesis, &ack)?;
    if verified.seal() != &entry.seal {
        return Err(format!(
            "successor {stream_name} BNRAW differs from BNSEG root"
        ));
    }
    let progress_path =
        stream_directory.join(format!("segment-{:06}.bnack", entry.seal.segment_index));
    let mut follower = SegmentDurabilityFollower::open_with_reference(
        &progress_path,
        &raw_path,
        &genesis,
        &entry.seal.raw_file,
    )?;
    if follower.require_clean_eof()?.latest_ack.as_ref() != Some(&ack) {
        return Err(format!(
            "successor {stream_name} BNACK differs from BNRAW root"
        ));
    }
    let records = read_raw_segment_records(&raw_path, &genesis)?;
    validate_successor_frame_identity(
        &records,
        identity,
        stream_name,
        &entry.seal.connection_epoch,
    )?;
    Ok((entry, records))
}

fn verified_published_segment(
    session: &Path,
    identity: &SuccessorIdentity,
    stream_name: &str,
    entry: &RawSegmentManifestEntryV1,
) -> Result<(RawSegmentManifestEntryV1, Vec<RawRecordEnvelopeV1>)> {
    let stream_directory = session.join(stream_name);
    let manifest_path = stream_directory.join("segments.bnseg");
    let scan = scan_segment_manifest(&manifest_path)?;
    if !scan
        .entries
        .iter()
        .any(|candidate| candidate.record_index == entry.record_index && candidate == entry)
    {
        return Err(format!(
            "successor {} segment {} does not match manifest",
            stream_name, entry.seal.segment_index
        ));
    }
    let genesis = genesis_from_entry(entry);
    let ack = ack_from_entry(entry);
    let raw_path = stream_directory.join(&entry.seal.raw_file);
    let verified = verify_and_seal_raw_segment(&raw_path, &entry.seal.raw_file, &genesis, &ack)?;
    if verified.seal() != &entry.seal {
        return Err(format!(
            "successor {stream_name} BNRAW differs from verified manifest segment"
        ));
    }
    let progress_path =
        stream_directory.join(format!("segment-{:06}.bnack", entry.seal.segment_index));
    let mut follower = SegmentDurabilityFollower::open_with_reference(
        &progress_path,
        &raw_path,
        &genesis,
        &entry.seal.raw_file,
    )?;
    if follower.require_clean_eof()?.latest_ack.as_ref() != Some(&ack) {
        return Err(format!(
            "successor {stream_name} BNACK differs from verified segment {}",
            entry.seal.segment_index
        ));
    }
    let records = read_raw_segment_records(&raw_path, &genesis)?;
    validate_successor_frame_identity(
        &records,
        identity,
        stream_name,
        &entry.seal.connection_epoch,
    )?;
    Ok((entry.clone(), records))
}

fn choose_trade_overlap_root(
    predecessor_trade_entry: &RawSegmentManifestEntryV1,
    predecessor_trade_records: &[CanonicalObservationV1],
    successor_session: &Path,
    identity: &SuccessorIdentity,
    entries: &[RawSegmentManifestEntryV1],
) -> Result<(
    RawSegmentManifestEntryV1,
    Vec<RawRecordEnvelopeV1>,
    TradeOverlapEvidenceV1,
)> {
    let entry = entries
        .first()
        .ok_or_else(|| "successor trade overlap is empty".to_owned())?;
    if entry.seal.segment_index != 0
        || entry.seal.connection_epoch == predecessor_trade_entry.seal.connection_epoch
    {
        return Err("successor trade root identity is invalid".to_owned());
    }
    let (segment_entry, records) =
        verified_published_segment(successor_session, identity, "trade", entry)?;
    let successor_trade = materialize_trade_record_window(&records)?;
    let trade = derive_trade_evidence(
        predecessor_trade_entry,
        &segment_entry,
        predecessor_trade_records,
        &successor_trade,
    )?;
    Ok((segment_entry, records, trade))
}

fn predecessor_terminal_segment(
    session: &Path,
    stream: &VerifiedGenerationStreamV1,
) -> Result<(RawSegmentManifestEntryV1, Vec<RawRecordEnvelopeV1>)> {
    let entry = stream
        .entries
        .last()
        .ok_or_else(|| "predecessor stream has no segment".to_owned())?
        .clone();
    let records = read_raw_segment_records(
        &session.join(&stream.name).join(&entry.seal.raw_file),
        &genesis_from_entry(&entry),
    )?;
    Ok((entry, records))
}

fn verify_successor_startup_and_snapshot(
    session: &Path,
    expected_startup_sha256: &str,
    expected_snapshot: &ExpectedSnapshotPublicationV1,
) -> Result<SuccessorIdentity> {
    let startup_bytes = fs::read(session.join("startup.json"))
        .map_err(|error| format!("read successor startup: {error}"))?;
    if sha256_hex(&startup_bytes) != expected_startup_sha256 {
        return Err("successor typed startup digest differs from startup.json".to_owned());
    }
    let startup: StartupManifestV1 = serde_json::from_slice(&startup_bytes)
        .map_err(|error| format!("invalid successor startup JSON: {error}"))?;
    if startup.schema != "RawGenerationStartupV1"
        || startup.implementation != "rust-segmented"
        || session.file_name().and_then(|name| name.to_str()) != Some(&startup.session_id)
        || !matches!(startup.symbol.as_str(), "BTCUSDT" | "ETHUSDT")
        || startup.duration_requested_s == 0
        || startup.segment_duration_s == 0
        || startup.segment_duration_s > startup.duration_requested_s
        || startup.started_wall_ns == 0
        || !valid_sha256(&startup.collector_executable_sha256)
        || !valid_sha256(&startup.public_config_sha256)
        || startup.market_freshness_startup_grace_s != 30
        || startup.market_freshness_deadline_s != 30
        || startup.credentials != "NONE"
        || startup.order_entry != "ABSENT"
        || startup.raw_boundary
            != "WebSocket application messages after TLS/framing and before JSON interpretation"
        || startup.spec_revision != SEGMENTED_SPEC_REVISION
    {
        return Err("successor startup contract is invalid".to_owned());
    }
    if expected_snapshot.raw_file != "snapshot.bnraw"
        || expected_snapshot.http_metadata_file != "snapshot-http.json"
    {
        return Err("successor snapshot typed publication path drift".to_owned());
    }
    let snapshot_path = session.join(&expected_snapshot.raw_file);
    let scan = scan_raw_log(&snapshot_path)?;
    let records = read_raw_records(&snapshot_path)?;
    if !scan.clean_eof
        || records.len() != 1
        || scan.records != 1
        || scan.last_good_offset != expected_snapshot.durable_through_offset
        || scan.last_record_sha256 != expected_snapshot.last_record_sha256
    {
        return Err("successor typed snapshot publication differs from BNRAW".to_owned());
    }
    let snapshot = records.into_iter().next().expect("one snapshot checked");
    let endpoint = format!(
        "https://data-api.binance.vision/api/v3/depth?symbol={}&limit=5000",
        startup.symbol
    );
    if snapshot.frame.venue != "binance-spot"
        || snapshot.frame.environment != "production-public-market-data"
        || snapshot.frame.endpoint != endpoint
        || snapshot.frame.symbol != startup.symbol
        || snapshot.frame.stream
            != format!(
                "{}@rest-depth-snapshot",
                startup.symbol.to_ascii_lowercase()
            )
        || snapshot.frame.frame_index != 0
        || snapshot.frame.spec_revision != SEGMENTED_SPEC_REVISION
        || snapshot.frame.recorder_state != "PENDING"
    {
        return Err("successor snapshot raw identity drift".to_owned());
    }
    let payload: Value = serde_json::from_slice(&snapshot.frame.payload)
        .map_err(|error| format!("successor snapshot payload JSON: {error}"))?;
    if payload["lastUpdateId"].as_u64().is_none()
        || payload["bids"].as_array().is_none()
        || payload["asks"].as_array().is_none()
    {
        return Err("successor snapshot payload shape is invalid".to_owned());
    }
    let http_bytes = fs::read(session.join(&expected_snapshot.http_metadata_file))
        .map_err(|error| format!("read successor snapshot HTTP metadata: {error}"))?;
    if sha256_hex(&http_bytes) != expected_snapshot.http_metadata_sha256 {
        return Err("successor typed HTTP metadata digest drift".to_owned());
    }
    let http: SnapshotHttpMetadataV1 = serde_json::from_slice(&http_bytes)
        .map_err(|error| format!("invalid successor snapshot HTTP metadata: {error}"))?;
    if http.schema != "SnapshotHttpMetadataV1"
        || http.endpoint != endpoint
        || http.http_status != 200
        || http.headers.is_empty()
        || !http.body_complete
        || http.body_length != snapshot.frame.payload.len()
        || http.body_sha256 != sha256_hex(&snapshot.frame.payload)
        || http.raw_file != expected_snapshot.raw_file
        || http.raw_record_sha256 != snapshot.record_sha256
        || http.receive_wall_ns != snapshot.frame.receive_wall_ns
        || http.receive_mono_ns != snapshot.frame.receive_mono_ns
    {
        return Err("successor HTTP metadata is not bound to snapshot raw body".to_owned());
    }
    Ok(SuccessorIdentity {
        session_id: startup.session_id,
        generation_index: startup.generation_index,
        symbol: startup.symbol,
        snapshot,
    })
}

fn derive_depth_evidence(
    predecessor_entry: &RawSegmentManifestEntryV1,
    successor_entry: &RawSegmentManifestEntryV1,
    snapshot: &RawRecordEnvelopeV1,
    predecessor_records: &[RawRecordEnvelopeV1],
    successor_records: &[RawRecordEnvelopeV1],
) -> Result<DepthOverlapEvidenceV1> {
    let convergence =
        latest_depth_window_convergence(snapshot, predecessor_records, successor_records)?;
    let predecessor_boundary = &convergence.predecessor_boundary;
    let successor_boundary = &convergence.successor_boundary;
    let continuation = &convergence.successor_continuation;
    Ok(DepthOverlapEvidenceV1 {
        schema: "DepthOverlapEvidenceV1".to_owned(),
        predecessor_segment: segment_reference(predecessor_entry),
        successor_segment: segment_reference(successor_entry),
        boundary_sequence: predecessor_boundary.final_sequence,
        boundary_state_sha256: predecessor_boundary.observation_sha256.clone(),
        predecessor_boundary: position(predecessor_boundary),
        successor_boundary: position(successor_boundary),
        successor_continuation: position(continuation),
        successor_continuation_first_sequence: continuation.first_sequence,
        successor_continuation_final_sequence: continuation.final_sequence,
    })
}

fn derive_trade_evidence(
    predecessor_entry: &RawSegmentManifestEntryV1,
    successor_entry: &RawSegmentManifestEntryV1,
    predecessor: &[CanonicalObservationV1],
    successor: &[CanonicalObservationV1],
) -> Result<TradeOverlapEvidenceV1> {
    let first_a_id = predecessor
        .first()
        .map(|item| item.final_sequence)
        .ok_or_else(|| "predecessor trade overlap is empty".to_owned())?;
    let last_a_id = predecessor
        .last()
        .map(|item| item.final_sequence)
        .ok_or_else(|| "predecessor trade overlap is empty".to_owned())?;
    let first_b_id = successor
        .first()
        .map(|item| item.final_sequence)
        .ok_or_else(|| "successor trade overlap is empty".to_owned())?;
    let last_b_id = successor
        .last()
        .map(|item| item.final_sequence)
        .ok_or_else(|| "successor trade overlap is empty".to_owned())?;
    if last_b_id < last_a_id {
        return Err(
            "successor durable trade prefix does not cover predecessor terminal trade".to_owned(),
        );
    }
    let lower = first_a_id.max(first_b_id);
    let upper = last_a_id.min(last_b_id);
    let common_a = predecessor
        .iter()
        .filter(|item| (lower..=upper).contains(&item.final_sequence))
        .collect::<Vec<_>>();
    let common_b = successor
        .iter()
        .filter(|item| (lower..=upper).contains(&item.final_sequence))
        .collect::<Vec<_>>();
    if common_a.len() < 2
        || common_a.len() != common_b.len()
        || common_a.iter().zip(&common_b).any(|(left, right)| {
            left.final_sequence != right.final_sequence
                || left.observation_sha256 != right.observation_sha256
        })
    {
        return Err(
            "complete ordered trade lists differ across their durable common ID range".to_owned(),
        );
    }
    let common_events = u64::try_from(common_a.len())
        .map_err(|_| "common trade event count overflow".to_owned())?;
    let first_a = common_a[common_a.len() - 2];
    let next_a = common_a[common_a.len() - 1];
    let first_b = common_b[common_b.len() - 2];
    let next_b = common_b[common_b.len() - 1];
    Ok(TradeOverlapEvidenceV1 {
        schema: "TradeOverlapEvidenceV1".to_owned(),
        predecessor_segment: segment_reference(predecessor_entry),
        successor_segment: segment_reference(successor_entry),
        common_lower_trade_id: lower,
        common_upper_trade_id: upper,
        common_events,
        first_shared_trade_id: first_b.final_sequence,
        first_shared_event_sha256: first_b.observation_sha256.clone(),
        predecessor_first_shared: position(first_a),
        successor_first_shared: position(first_b),
        next_shared_trade_id: next_b.final_sequence,
        next_shared_event_sha256: next_b.observation_sha256.clone(),
        predecessor_next_shared: position(next_a),
        successor_next_shared: position(next_b),
        trade_id_contiguity_claim: "NONE_OFFICIAL_CONTRACT_DOES_NOT_PROMISE_CONSECUTIVE_IDS"
            .to_owned(),
    })
}

fn write_synced_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("sync {}: {error}", path.display()))
}

#[allow(clippy::too_many_arguments)]
pub fn prove_raw_generation_handover(
    predecessor_session: &Path,
    successor_session: &Path,
    successor_startup_sha256: &str,
    successor_snapshot_publication: &ExpectedSnapshotPublicationV1,
    successor_depth_publication: &ExpectedSegmentPublicationV1,
    output: &Path,
) -> Result<RawGenerationHandoverProofV1> {
    let predecessor = verify_segmented_generation(predecessor_session)?;
    let successor = verify_successor_startup_and_snapshot(
        successor_session,
        successor_startup_sha256,
        successor_snapshot_publication,
    )?;
    if predecessor.symbol != successor.symbol
        || predecessor.generation_index >= successor.generation_index
    {
        return Err("A/B generation identity/order mismatch".to_owned());
    }
    let predecessor_depth_stream = predecessor
        .streams
        .iter()
        .find(|stream| stream.name == "depth")
        .ok_or_else(|| "predecessor lacks depth".to_owned())?;
    let predecessor_trade_stream = predecessor
        .streams
        .iter()
        .find(|stream| stream.name == "trade")
        .ok_or_else(|| "predecessor lacks trade".to_owned())?;
    let (predecessor_depth_entry, predecessor_depth_records) =
        predecessor_terminal_segment(predecessor_session, predecessor_depth_stream)?;
    let (predecessor_trade_entry, predecessor_trade_records) =
        predecessor_terminal_segment(predecessor_session, predecessor_trade_stream)?;
    let predecessor_trade = materialize_trade_record_window(&predecessor_trade_records)?;
    let (successor_depth_entry, successor_depth_records) = verified_published_root(
        successor_session,
        &successor,
        "depth",
        successor_depth_publication,
    )?;
    let trade_manifest_path = successor_session.join("trade").join("segments.bnseg");
    let trade_scan = scan_segment_manifest(&trade_manifest_path)?;
    let (successor_trade_entry, successor_trade_records, trade) = choose_trade_overlap_root(
        &predecessor_trade_entry,
        &predecessor_trade,
        successor_session,
        &successor,
        &trade_scan.entries,
    )?;
    if predecessor_depth_entry.seal.connection_epoch == successor_depth_entry.seal.connection_epoch
    {
        return Err("A/B connection epoch was reused".to_owned());
    }
    if predecessor_trade_entry.seal.connection_epoch == successor_trade_entry.seal.connection_epoch
    {
        return Err("A/B connection epoch was reused".to_owned());
    }
    let successor_trade = materialize_trade_record_window(&successor_trade_records)?;
    if successor_trade[0].stream_kind != BoundaryStreamKind::Trade {
        return Err("overlap materialization kind drift".to_owned());
    }
    let depth = derive_depth_evidence(
        &predecessor_depth_entry,
        &successor_depth_entry,
        &successor.snapshot,
        &predecessor_depth_records,
        &successor_depth_records,
    )?;
    let material = ProofDigestMaterial {
        schema: "RawGenerationHandoverProofDigestV1",
        predecessor_session_id: &predecessor.session_id,
        successor_session_id: &successor.session_id,
        predecessor_generation_index: predecessor.generation_index,
        successor_generation_index: successor.generation_index,
        symbol: &predecessor.symbol,
        predecessor_verification_sha256: &predecessor.verification_sha256,
        successor_startup_sha256,
        successor_snapshot_record_sha256: &successor.snapshot.record_sha256,
        successor_snapshot_http_sha256: &successor_snapshot_publication.http_metadata_sha256,
        depth: &depth,
        trade: &trade,
    };
    let proof_sha256 = sha256_hex(
        &serde_json::to_vec(&material)
            .map_err(|error| format!("serialize raw handover digest: {error}"))?,
    );
    let proof = RawGenerationHandoverProofV1 {
        schema: "RawGenerationHandoverProofV1".to_owned(),
        status: "PROVEN".to_owned(),
        predecessor_session_id: predecessor.session_id,
        successor_session_id: successor.session_id,
        predecessor_generation_index: predecessor.generation_index,
        successor_generation_index: successor.generation_index,
        symbol: predecessor.symbol,
        credentials: "NONE".to_owned(),
        order_entry: "ABSENT".to_owned(),
        predecessor_verification_sha256: predecessor.verification_sha256,
        successor_startup_sha256: successor_startup_sha256.to_owned(),
        successor_snapshot_record_sha256: successor.snapshot.record_sha256,
        successor_snapshot_http_sha256: successor_snapshot_publication.http_metadata_sha256.clone(),
        depth,
        trade,
        proof_sha256,
    };
    if output.exists() {
        return Err(format!(
            "handover output already exists: {}",
            output.display()
        ));
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create handover parent {}: {error}", parent.display()))?;
    }
    fs::create_dir(output)
        .map_err(|error| format!("create handover output {}: {error}", output.display()))?;
    let mut bytes = serde_json::to_vec_pretty(&proof)
        .map_err(|error| format!("serialize raw handover proof: {error}"))?;
    bytes.push(b'\n');
    write_synced_new(&output.join("handover.json"), &bytes)?;
    Ok(proof)
}

fn manifest_entry_for_reference(
    session: &Path,
    stream_name: &str,
    reference: &RawSegmentReferenceV1,
) -> Result<RawSegmentManifestEntryV1> {
    if !matches!(stream_name, "depth" | "trade") {
        return Err("handover reference uses an unknown stream directory".to_owned());
    }
    // `reference.stream` is the venue identity (`btcusdt@depth@100ms` or
    // `btcusdt@trade`), never a filesystem component. Only the closed logical
    // stream kind selects one of the two fixed generation directories.
    let manifest_path = session.join(stream_name).join("segments.bnseg");
    let scan = scan_segment_manifest(&manifest_path)?;
    scan.entries
        .into_iter()
        .find(|entry| segment_reference(entry) == *reference)
        .ok_or_else(|| {
            format!(
                "successor {} stream segment {} does not match stored manifest reference",
                reference.stream, reference.segment_index
            )
        })
}

/// Recomputes a stored handover from both terminal immutable generations.
/// No process event or previously materialized overlap field is trusted.
pub fn verify_terminal_raw_generation_handover(
    predecessor_session: &Path,
    successor_session: &Path,
    expected: &RawGenerationHandoverProofV1,
) -> Result<()> {
    validate_raw_handover_proof_digest(expected)?;
    let predecessor = verify_segmented_generation(predecessor_session)?;
    let successor_terminal = verify_segmented_generation(successor_session)?;
    verify_terminal_raw_generation_handover_from_verified(
        predecessor_session,
        successor_session,
        &predecessor,
        &successor_terminal,
        expected,
    )
}

pub(crate) fn verify_terminal_raw_generation_handover_from_verified(
    predecessor_session: &Path,
    successor_session: &Path,
    predecessor: &VerifiedGenerationV1,
    successor_terminal: &VerifiedGenerationV1,
    expected: &RawGenerationHandoverProofV1,
) -> Result<()> {
    validate_raw_handover_proof_digest(expected)?;
    let startup_bytes = fs::read(successor_session.join("startup.json"))
        .map_err(|error| format!("read terminal successor startup: {error}"))?;
    let startup_sha256 = sha256_hex(&startup_bytes);
    let snapshot_path = successor_session.join("snapshot.bnraw");
    let snapshot_scan = scan_raw_log(&snapshot_path)?;
    if !snapshot_scan.clean_eof || snapshot_scan.records != 1 {
        return Err("terminal successor snapshot raw log is invalid".to_owned());
    }
    let snapshot_http_bytes = fs::read(successor_session.join("snapshot-http.json"))
        .map_err(|error| format!("read terminal successor snapshot HTTP metadata: {error}"))?;
    let snapshot_publication = ExpectedSnapshotPublicationV1 {
        raw_file: "snapshot.bnraw".to_owned(),
        durable_through_offset: snapshot_scan.last_good_offset,
        last_record_sha256: snapshot_scan.last_record_sha256,
        http_metadata_file: "snapshot-http.json".to_owned(),
        http_metadata_sha256: sha256_hex(&snapshot_http_bytes),
    };
    let successor = verify_successor_startup_and_snapshot(
        successor_session,
        &startup_sha256,
        &snapshot_publication,
    )?;
    if predecessor.symbol != successor.symbol
        || successor_terminal.session_id != successor.session_id
        || successor_terminal.generation_index != successor.generation_index
        || successor_terminal.symbol != successor.symbol
        || predecessor.generation_index.checked_add(1) != Some(successor.generation_index)
    {
        return Err("terminal A/B generation identity/order mismatch".to_owned());
    }
    let predecessor_depth_stream = predecessor
        .streams
        .iter()
        .find(|stream| stream.name == "depth")
        .ok_or_else(|| "terminal predecessor lacks depth".to_owned())?;
    let predecessor_trade_stream = predecessor
        .streams
        .iter()
        .find(|stream| stream.name == "trade")
        .ok_or_else(|| "terminal predecessor lacks trade".to_owned())?;
    let (predecessor_depth_entry, predecessor_depth_records) =
        predecessor_terminal_segment(predecessor_session, predecessor_depth_stream)?;
    let (predecessor_trade_entry, predecessor_trade_records) =
        predecessor_terminal_segment(predecessor_session, predecessor_trade_stream)?;
    let successor_depth_reference = &expected.depth.successor_segment;
    let successor_trade_reference = &expected.trade.successor_segment;
    let successor_depth_entry =
        manifest_entry_for_reference(successor_session, "depth", successor_depth_reference)?;
    let successor_trade_entry =
        manifest_entry_for_reference(successor_session, "trade", successor_trade_reference)?;
    let (successor_depth_entry, successor_depth_records) = verified_published_segment(
        successor_session,
        &successor,
        "depth",
        &successor_depth_entry,
    )?;
    let (successor_trade_entry, successor_trade_records) = verified_published_segment(
        successor_session,
        &successor,
        "trade",
        &successor_trade_entry,
    )?;
    if predecessor_depth_entry.seal.connection_epoch == successor_depth_entry.seal.connection_epoch
        || predecessor_trade_entry.seal.connection_epoch
            == successor_trade_entry.seal.connection_epoch
    {
        return Err("terminal A/B connection epoch was reused".to_owned());
    }
    let predecessor_trade = materialize_trade_record_window(&predecessor_trade_records)?;
    let successor_trade = materialize_trade_record_window(&successor_trade_records)?;
    let depth = derive_depth_evidence(
        &predecessor_depth_entry,
        &successor_depth_entry,
        &successor.snapshot,
        &predecessor_depth_records,
        &successor_depth_records,
    )?;
    let trade = derive_trade_evidence(
        &predecessor_trade_entry,
        &successor_trade_entry,
        &predecessor_trade,
        &successor_trade,
    )?;
    let material = ProofDigestMaterial {
        schema: "RawGenerationHandoverProofDigestV1",
        predecessor_session_id: &predecessor.session_id,
        successor_session_id: &successor.session_id,
        predecessor_generation_index: predecessor.generation_index,
        successor_generation_index: successor.generation_index,
        symbol: &predecessor.symbol,
        predecessor_verification_sha256: &predecessor.verification_sha256,
        successor_startup_sha256: &startup_sha256,
        successor_snapshot_record_sha256: &successor.snapshot.record_sha256,
        successor_snapshot_http_sha256: &snapshot_publication.http_metadata_sha256,
        depth: &depth,
        trade: &trade,
    };
    let proof_sha256 = sha256_hex(
        &serde_json::to_vec(&material)
            .map_err(|error| format!("serialize terminal handover digest: {error}"))?,
    );
    let recomputed = RawGenerationHandoverProofV1 {
        schema: "RawGenerationHandoverProofV1".to_owned(),
        status: "PROVEN".to_owned(),
        predecessor_session_id: predecessor.session_id.clone(),
        successor_session_id: successor.session_id,
        predecessor_generation_index: predecessor.generation_index,
        successor_generation_index: successor.generation_index,
        symbol: predecessor.symbol.clone(),
        credentials: "NONE".to_owned(),
        order_entry: "ABSENT".to_owned(),
        predecessor_verification_sha256: predecessor.verification_sha256.clone(),
        successor_startup_sha256: startup_sha256,
        successor_snapshot_record_sha256: successor.snapshot.record_sha256,
        successor_snapshot_http_sha256: snapshot_publication.http_metadata_sha256,
        depth,
        trade,
        proof_sha256,
    };
    if &recomputed != expected {
        return Err("stored handover differs from terminal raw recomputation".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::derive_trade_evidence;
    use crate::RawSegmentSealV1;
    use crate::boundary::{BoundaryStreamKind, CanonicalObservationV1};
    use crate::segment_chain::RawSegmentManifestEntryV1;

    fn entry(epoch: &str) -> RawSegmentManifestEntryV1 {
        RawSegmentManifestEntryV1 {
            schema: "RawSegmentManifestEntryV1",
            record_index: 0,
            previous_manifest_record_sha256: "0".repeat(64),
            manifest_record_sha256: "1".repeat(64),
            seal: RawSegmentSealV1 {
                schema: "RawSegmentSealV1".to_owned(),
                segment_index: 0,
                raw_file: "segment-000000.bnraw".to_owned(),
                connection_epoch: epoch.to_owned(),
                stream: "btcusdt@trade".to_owned(),
                first_frame_index: 0,
                last_frame_index: 1,
                records: 2,
                durable_through_offset: 1,
                previous_segment_terminal_sha256: "0".repeat(64),
                terminal_record_sha256: "2".repeat(64),
            },
        }
    }

    fn trade(epoch: &str, frame_index: u64, trade_id: u64, event: &str) -> CanonicalObservationV1 {
        CanonicalObservationV1 {
            symbol: "BTCUSDT".to_owned(),
            stream_kind: BoundaryStreamKind::Trade,
            stream: "btcusdt@trade".to_owned(),
            connection_epoch: epoch.to_owned(),
            frame_index,
            first_sequence: trade_id,
            final_sequence: trade_id,
            record_sha256: format!("{epoch}-{frame_index}"),
            observation_sha256: event.to_owned(),
        }
    }

    #[test]
    fn trade_handover_rejects_an_event_omitted_by_one_overlap_side() {
        let predecessor = vec![
            trade("a", 0, 100, "event-100"),
            trade("a", 1, 101, "event-101"),
            trade("a", 2, 102, "event-102"),
        ];
        let successor = vec![
            trade("b", 0, 100, "event-100"),
            trade("b", 1, 102, "event-102"),
        ];
        assert!(derive_trade_evidence(&entry("a"), &entry("b"), &predecessor, &successor).is_err());
    }

    #[test]
    fn trade_handover_allows_equal_adjacent_events_without_claiming_id_contiguity() {
        let predecessor = vec![
            trade("a", 0, 100, "event-100"),
            trade("a", 1, 105, "event-105"),
        ];
        let successor = vec![
            trade("b", 0, 100, "event-100"),
            trade("b", 1, 105, "event-105"),
        ];
        let evidence =
            derive_trade_evidence(&entry("a"), &entry("b"), &predecessor, &successor).unwrap();
        assert_eq!(evidence.first_shared_trade_id, 100);
        assert_eq!(evidence.next_shared_trade_id, 105);
        assert_eq!(evidence.common_events, 2);
        assert_eq!(
            evidence.trade_id_contiguity_claim,
            "NONE_OFFICIAL_CONTRACT_DOES_NOT_PROMISE_CONSECUTIVE_IDS"
        );
    }

    #[test]
    fn trade_handover_rejects_successor_prefix_that_ends_before_predecessor() {
        let predecessor = vec![
            trade("a", 0, 100, "event-100"),
            trade("a", 1, 105, "event-105"),
            trade("a", 2, 110, "event-110"),
        ];
        let successor = vec![
            trade("b", 0, 100, "event-100"),
            trade("b", 1, 105, "event-105"),
        ];
        assert!(derive_trade_evidence(&entry("a"), &entry("b"), &predecessor, &successor).is_err());
    }
}
