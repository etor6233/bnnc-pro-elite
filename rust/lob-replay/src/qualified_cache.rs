//! Content-addressed binary cache for repeated neutral replay.
//!
//! The immutable BNRAW campaign and its qualified receipt remain authority.
//! This cache only removes repeated JSON-envelope/base64 decoding from the
//! consumption path. It never contains economic features or a cross-stream
//! ordering claim.

use crate::complete_replay::{
    CompleteDepthReplayV1, CompleteTradeReplayV1, DepthGenerationReplayV1,
    QualifiedCompleteReplayReceiptV1, TradeGenerationReplayV1,
    materialize_qualified_replay_records, validate_qualified_receipt,
};
use crate::market_replay::{is_server_shutdown, require_regular_file, sha256_file};
use crate::observations::validated_trade_id;
use crate::{
    ApplyOutcome, LocalOrderBook, OrderBookCheckpointV1, PreparedDepthUpdate, RawRecordEnvelopeV1,
    Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};

const CACHE_MAGIC: &[u8; 8] = b"BNEVT\0\x02\n";
const INDEX_MAGIC: &[u8; 8] = b"BNIDX\0\x02\n";
const INDEX_ENTRY_BYTES: u64 = 48;
const MAX_CACHE_RECORD_BYTES: usize = 4 * 1024 * 1024 + 128;
const CHECKPOINT_MAGIC: &[u8; 8] = b"BNCKP\0\x01\n";
const CHECKPOINT_INDEX_MAGIC: &[u8; 8] = b"BNCKI\0\x01\n";
const CHECKPOINT_INDEX_ENTRY_BYTES: u64 = 64;
const MAX_CHECKPOINT_RECORD_BYTES: usize = 64 * 1024 * 1024;
pub const QUALIFIED_CACHE_USAGE: &str = "QUALIFIED_NEUTRAL_REPLAY_CACHE";
pub const QUALIFIED_CHECKPOINT_USAGE: &str = "QUALIFIED_NEUTRAL_BOOK_CHECKPOINTS";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedReplayCacheArtifactV2 {
    pub stream_kind: String,
    pub data_file: String,
    pub data_bytes: u64,
    pub data_sha256: String,
    pub index_file: String,
    pub index_bytes: u64,
    pub index_sha256: String,
    pub records: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedReplayCacheIdentityV2 {
    pub generation_index: u64,
    pub session_id: String,
    pub depth_stream: String,
    pub depth_connection_epoch: String,
    pub trade_stream: String,
    pub trade_connection_epoch: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedReplayCacheManifestV2 {
    pub schema: String,
    pub usage: String,
    pub status: String,
    pub qualification_claim: bool,
    pub cross_stream_total_order_available: bool,
    pub economic_features: Vec<String>,
    pub receipt_sha256: String,
    pub source_tree_sha256: String,
    pub replay_report_sha256: String,
    pub symbol: String,
    pub identities: Vec<QualifiedReplayCacheIdentityV2>,
    pub snapshot: QualifiedReplayCacheArtifactV2,
    pub depth: QualifiedReplayCacheArtifactV2,
    pub trades: QualifiedReplayCacheArtifactV2,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedDepthCheckpointV1 {
    pub schema: String,
    pub generation_index: u64,
    pub segment_index: u64,
    pub last_record_ordinal: u64,
    pub next_record_ordinal: u64,
    pub next_data_offset: u64,
    pub last_frame_index: u64,
    pub last_receive_wall_ns: u64,
    pub last_receive_mono_ns: u64,
    pub last_raw_record_sha256: String,
    pub book: OrderBookCheckpointV1,
    pub checkpoint_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedReplayCheckpointArtifactV1 {
    pub data_file: String,
    pub data_bytes: u64,
    pub data_sha256: String,
    pub index_file: String,
    pub index_bytes: u64,
    pub index_sha256: String,
    pub checkpoints: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedReplayCheckpointManifestV1 {
    pub schema: String,
    pub usage: String,
    pub status: String,
    pub qualification_claim: bool,
    pub economic_features: Vec<String>,
    pub receipt_sha256: String,
    pub source_tree_sha256: String,
    pub replay_report_sha256: String,
    pub cache_manifest_sha256: String,
    pub cache_manifest_file_sha256: String,
    pub cache_depth_data_sha256: String,
    pub cache_depth_index_sha256: String,
    pub symbol: String,
    pub artifact: QualifiedReplayCheckpointArtifactV1,
    pub final_state_sha256: String,
    pub manifest_sha256: String,
}

struct CachedEvent {
    record_ordinal: u64,
    start_offset: u64,
    end_offset: u64,
    generation_index: u64,
    segment_index: u64,
    frame_index: u64,
    receive_wall_ns: u64,
    receive_mono_ns: u64,
    record_sha256: String,
    payload: Vec<u8>,
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> String {
        crate::hex(&self.hasher.finalize())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

struct CacheWriter {
    stream_kind: String,
    data_name: String,
    index_name: String,
    data_path: PathBuf,
    index_path: PathBuf,
    data: BufWriter<File>,
    index: BufWriter<File>,
    data_offset: u64,
    records: u64,
}

fn create_new(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn manifest_digest(manifest: &QualifiedReplayCacheManifestV2) -> Result<String> {
    let mut material = manifest.clone();
    material.manifest_sha256.clear();
    let bytes = serde_json::to_vec(&material)
        .map_err(|error| format!("serialize cache manifest material: {error}"))?;
    Ok(crate::hex(&Sha256::digest(bytes)))
}

fn checkpoint_digest(checkpoint: &QualifiedDepthCheckpointV1) -> Result<String> {
    let mut material = checkpoint.clone();
    material.checkpoint_sha256.clear();
    let bytes = serde_json::to_vec(&material)
        .map_err(|error| format!("serialize checkpoint material: {error}"))?;
    Ok(crate::hex(&Sha256::digest(bytes)))
}

fn checkpoint_manifest_digest(manifest: &QualifiedReplayCheckpointManifestV1) -> Result<String> {
    let mut material = manifest.clone();
    material.manifest_sha256.clear();
    let bytes = serde_json::to_vec(&material)
        .map_err(|error| format!("serialize checkpoint manifest material: {error}"))?;
    Ok(crate::hex(&Sha256::digest(bytes)))
}

impl CacheWriter {
    fn create(root: &Path, stream_kind: &str) -> Result<Self> {
        let data_name = format!("{stream_kind}.bnevt");
        let index_name = format!("{stream_kind}.bnidx");
        let data_path = root.join(&data_name);
        let index_path = root.join(&index_name);
        let mut data = BufWriter::with_capacity(8 * 1024 * 1024, create_new(&data_path)?);
        let mut index = BufWriter::with_capacity(1024 * 1024, create_new(&index_path)?);
        data.write_all(CACHE_MAGIC)
            .map_err(|error| format!("write cache magic: {error}"))?;
        index
            .write_all(INDEX_MAGIC)
            .map_err(|error| format!("write cache index magic: {error}"))?;
        Ok(Self {
            stream_kind: stream_kind.to_owned(),
            data_name,
            index_name,
            data_path,
            index_path,
            data,
            index,
            data_offset: CACHE_MAGIC.len() as u64,
            records: 0,
        })
    }

    fn append(
        &mut self,
        generation_index: u64,
        segment_index: u64,
        record: &RawRecordEnvelopeV1,
    ) -> Result<()> {
        if !valid_sha256(&record.record_sha256) {
            return Err("cache source record digest is invalid".to_owned());
        }
        let payload_len = u32::try_from(record.frame.payload.len())
            .map_err(|_| "cache payload length overflow".to_owned())?;
        let mut body = Vec::with_capacity(108 + record.frame.payload.len());
        body.extend_from_slice(&generation_index.to_be_bytes());
        body.extend_from_slice(&segment_index.to_be_bytes());
        body.extend_from_slice(&record.frame.frame_index.to_be_bytes());
        body.extend_from_slice(&record.frame.receive_wall_ns.to_be_bytes());
        body.extend_from_slice(&record.frame.receive_mono_ns.to_be_bytes());
        body.extend_from_slice(record.record_sha256.as_bytes());
        body.extend_from_slice(&payload_len.to_be_bytes());
        body.extend_from_slice(&record.frame.payload);
        let body_len = u32::try_from(body.len())
            .map_err(|_| "cache record body length overflow".to_owned())?;
        let start = self.data_offset;
        self.data
            .write_all(&body_len.to_be_bytes())
            .and_then(|_| self.data.write_all(&body))
            .and_then(|_| self.data.write_all(&Sha256::digest(&body)))
            .map_err(|error| format!("write cache record: {error}"))?;
        let encoded = 4_u64
            .checked_add(body.len() as u64)
            .and_then(|value| value.checked_add(32))
            .ok_or_else(|| "cache data offset overflow".to_owned())?;
        self.data_offset = self
            .data_offset
            .checked_add(encoded)
            .ok_or_else(|| "cache data offset overflow".to_owned())?;
        for value in [
            start,
            generation_index,
            segment_index,
            record.frame.frame_index,
            record.frame.receive_wall_ns,
            record.frame.receive_mono_ns,
        ] {
            self.index
                .write_all(&value.to_be_bytes())
                .map_err(|error| format!("write cache index: {error}"))?;
        }
        self.records = self
            .records
            .checked_add(1)
            .ok_or_else(|| "cache record count overflow".to_owned())?;
        Ok(())
    }

    fn finish(mut self) -> Result<QualifiedReplayCacheArtifactV2> {
        self.data
            .flush()
            .map_err(|error| format!("flush cache data: {error}"))?;
        self.index
            .flush()
            .map_err(|error| format!("flush cache index: {error}"))?;
        self.data
            .get_ref()
            .sync_all()
            .map_err(|error| format!("sync cache data: {error}"))?;
        self.index
            .get_ref()
            .sync_all()
            .map_err(|error| format!("sync cache index: {error}"))?;
        let data_bytes = self
            .data
            .get_ref()
            .metadata()
            .map_err(|error| format!("inspect cache data: {error}"))?
            .len();
        let index_bytes = self
            .index
            .get_ref()
            .metadata()
            .map_err(|error| format!("inspect cache index: {error}"))?
            .len();
        let expected_index_bytes = (INDEX_MAGIC.len() as u64)
            .checked_add(
                self.records
                    .checked_mul(INDEX_ENTRY_BYTES)
                    .ok_or_else(|| "cache index length overflow".to_owned())?,
            )
            .ok_or_else(|| "cache index length overflow".to_owned())?;
        if data_bytes != self.data_offset || index_bytes != expected_index_bytes {
            return Err("cache writer length accounting diverged".to_owned());
        }
        Ok(QualifiedReplayCacheArtifactV2 {
            stream_kind: self.stream_kind,
            data_file: self.data_name,
            data_bytes,
            data_sha256: sha256_file(&self.data_path)?,
            index_file: self.index_name,
            index_bytes,
            index_sha256: sha256_file(&self.index_path)?,
            records: self.records,
        })
    }
}

struct CheckpointWriter {
    data_path: PathBuf,
    index_path: PathBuf,
    data: BufWriter<File>,
    index: BufWriter<File>,
    data_offset: u64,
    checkpoints: u64,
}

impl CheckpointWriter {
    fn create(root: &Path) -> Result<Self> {
        let data_path = root.join("depth-checkpoints.bncp");
        let index_path = root.join("depth-checkpoints.bncpi");
        let mut data = BufWriter::with_capacity(8 * 1024 * 1024, create_new(&data_path)?);
        let mut index = BufWriter::with_capacity(1024 * 1024, create_new(&index_path)?);
        data.write_all(CHECKPOINT_MAGIC)
            .map_err(|error| format!("write checkpoint magic: {error}"))?;
        index
            .write_all(CHECKPOINT_INDEX_MAGIC)
            .map_err(|error| format!("write checkpoint index magic: {error}"))?;
        Ok(Self {
            data_path,
            index_path,
            data,
            index,
            data_offset: CHECKPOINT_MAGIC.len() as u64,
            checkpoints: 0,
        })
    }

    fn append(&mut self, mut checkpoint: QualifiedDepthCheckpointV1) -> Result<()> {
        checkpoint.checkpoint_sha256 = checkpoint_digest(&checkpoint)?;
        let body = serde_json::to_vec(&checkpoint)
            .map_err(|error| format!("serialize book checkpoint: {error}"))?;
        if body.len() > MAX_CHECKPOINT_RECORD_BYTES {
            return Err("book checkpoint exceeds maximum record size".to_owned());
        }
        let body_len = u32::try_from(body.len())
            .map_err(|_| "book checkpoint record length overflow".to_owned())?;
        let start = self.data_offset;
        self.data
            .write_all(&body_len.to_be_bytes())
            .and_then(|_| self.data.write_all(&body))
            .and_then(|_| self.data.write_all(&Sha256::digest(&body)))
            .map_err(|error| format!("write book checkpoint: {error}"))?;
        self.data_offset = self
            .data_offset
            .checked_add(4 + body.len() as u64 + 32)
            .ok_or_else(|| "book checkpoint data offset overflow".to_owned())?;
        for value in [
            start,
            checkpoint.last_record_ordinal,
            checkpoint.next_record_ordinal,
            checkpoint.next_data_offset,
            checkpoint.generation_index,
            checkpoint.segment_index,
            checkpoint.last_frame_index,
            checkpoint.book.last_update_id,
        ] {
            self.index
                .write_all(&value.to_be_bytes())
                .map_err(|error| format!("write book checkpoint index: {error}"))?;
        }
        self.checkpoints = self
            .checkpoints
            .checked_add(1)
            .ok_or_else(|| "book checkpoint count overflow".to_owned())?;
        Ok(())
    }

    fn finish(mut self) -> Result<QualifiedReplayCheckpointArtifactV1> {
        self.data
            .flush()
            .map_err(|error| format!("flush checkpoint data: {error}"))?;
        self.index
            .flush()
            .map_err(|error| format!("flush checkpoint index: {error}"))?;
        self.data
            .get_ref()
            .sync_all()
            .map_err(|error| format!("sync checkpoint data: {error}"))?;
        self.index
            .get_ref()
            .sync_all()
            .map_err(|error| format!("sync checkpoint index: {error}"))?;
        let data_bytes = self
            .data
            .get_ref()
            .metadata()
            .map_err(|error| format!("inspect checkpoint data: {error}"))?
            .len();
        let index_bytes = self
            .index
            .get_ref()
            .metadata()
            .map_err(|error| format!("inspect checkpoint index: {error}"))?
            .len();
        let expected_index_bytes = (CHECKPOINT_INDEX_MAGIC.len() as u64)
            .checked_add(
                self.checkpoints
                    .checked_mul(CHECKPOINT_INDEX_ENTRY_BYTES)
                    .ok_or_else(|| "checkpoint index length overflow".to_owned())?,
            )
            .ok_or_else(|| "checkpoint index length overflow".to_owned())?;
        if data_bytes != self.data_offset || index_bytes != expected_index_bytes {
            return Err("checkpoint writer length accounting diverged".to_owned());
        }
        Ok(QualifiedReplayCheckpointArtifactV1 {
            data_file: "depth-checkpoints.bncp".to_owned(),
            data_bytes,
            data_sha256: sha256_file(&self.data_path)?,
            index_file: "depth-checkpoints.bncpi".to_owned(),
            index_bytes,
            index_sha256: sha256_file(&self.index_path)?,
            checkpoints: self.checkpoints,
        })
    }
}

pub fn build_qualified_replay_cache(
    receipt: &QualifiedCompleteReplayReceiptV1,
    destination: &Path,
) -> Result<QualifiedReplayCacheManifestV2> {
    let source = receipt
        .selection
        .run_directory
        .canonicalize()
        .map_err(|error| format!("resolve cache source run: {error}"))?;
    let parent = destination
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| format!("resolve cache destination parent: {error}"))?;
    let name = destination
        .file_name()
        .ok_or_else(|| "cache destination has no directory name".to_owned())?;
    let destination = parent.join(name);
    if destination.starts_with(&source) {
        return Err("qualified cache must remain outside immutable source run".to_owned());
    }
    std::fs::create_dir(&destination)
        .map_err(|error| format!("create cache directory: {error}"))?;
    let mut snapshot_writer = CacheWriter::create(&destination, "snapshot")?;
    let mut depth_writer = CacheWriter::create(&destination, "depth")?;
    let mut trade_writer = CacheWriter::create(&destination, "trade")?;
    let mut depth_sink = |generation, segment, record: &RawRecordEnvelopeV1| {
        depth_writer.append(generation, segment, record)
    };
    let mut trade_sink = |generation, segment, record: &RawRecordEnvelopeV1| {
        trade_writer.append(generation, segment, record)
    };
    let (snapshot, identities) =
        materialize_qualified_replay_records(receipt, &mut depth_sink, &mut trade_sink)?;
    snapshot_writer.append(0, 0, &snapshot)?;
    let snapshot = snapshot_writer.finish()?;
    let depth = depth_writer.finish()?;
    let trades = trade_writer.finish()?;
    if snapshot.records != 1
        || depth.records != receipt.report.depth.selected_raw_records
        || trades.records != receipt.report.trades.selected_raw_records
    {
        return Err("cache record counts differ from qualified replay".to_owned());
    }
    let identities = identities
        .into_iter()
        .map(|identity| QualifiedReplayCacheIdentityV2 {
            generation_index: identity.generation_index,
            session_id: identity.session_id,
            depth_stream: identity.depth_stream,
            depth_connection_epoch: identity.depth_connection_epoch,
            trade_stream: identity.trade_stream,
            trade_connection_epoch: identity.trade_connection_epoch,
        })
        .collect();
    let mut manifest = QualifiedReplayCacheManifestV2 {
        schema: "QualifiedReplayCacheManifestV2".to_owned(),
        usage: QUALIFIED_CACHE_USAGE.to_owned(),
        status: "COMPLETE".to_owned(),
        qualification_claim: false,
        cross_stream_total_order_available: false,
        economic_features: Vec::new(),
        receipt_sha256: receipt.receipt_sha256.clone(),
        source_tree_sha256: receipt.source_tree_sha256.clone(),
        replay_report_sha256: receipt.report.report_sha256.clone(),
        symbol: receipt.selection.symbol.clone(),
        identities,
        snapshot,
        depth,
        trades,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = manifest_digest(&manifest)?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize cache manifest: {error}"))?;
    bytes.push(b'\n');
    let path = destination.join("qualified-cache.json");
    let mut file = create_new(&path)?;
    file.write_all(&bytes)
        .map_err(|error| format!("write cache manifest: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync cache manifest: {error}"))?;
    Ok(manifest)
}

fn safe_leaf(root: &Path, value: &str) -> Result<PathBuf> {
    let relative = Path::new(value);
    if value.is_empty()
        || relative.is_absolute()
        || relative.components().count() != 1
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("cache artifact path is not one safe filename".to_owned());
    }
    Ok(root.join(relative))
}

fn validate_artifact(
    root: &Path,
    artifact: &QualifiedReplayCacheArtifactV2,
    verify_file_sha256: bool,
) -> Result<()> {
    if !matches!(
        artifact.stream_kind.as_str(),
        "snapshot" | "depth" | "trade"
    ) || artifact.data_file != format!("{}.bnevt", artifact.stream_kind)
        || artifact.index_file != format!("{}.bnidx", artifact.stream_kind)
        || !valid_sha256(&artifact.data_sha256)
        || !valid_sha256(&artifact.index_sha256)
    {
        return Err("cache artifact contract is invalid".to_owned());
    }
    let data = safe_leaf(root, &artifact.data_file)?;
    let index = safe_leaf(root, &artifact.index_file)?;
    for (path, bytes, sha) in [
        (data, artifact.data_bytes, &artifact.data_sha256),
        (index, artifact.index_bytes, &artifact.index_sha256),
    ] {
        require_regular_file(&path, "cache artifact")?;
        if std::fs::metadata(&path)
            .map_err(|error| format!("inspect cache artifact: {error}"))?
            .len()
            != bytes
            || (verify_file_sha256 && sha256_file(&path)? != *sha)
        {
            return Err("cache artifact differs from manifest".to_owned());
        }
    }
    let expected_index = (INDEX_MAGIC.len() as u64)
        .checked_add(
            artifact
                .records
                .checked_mul(INDEX_ENTRY_BYTES)
                .ok_or_else(|| "cache index size overflow".to_owned())?,
        )
        .ok_or_else(|| "cache index size overflow".to_owned())?;
    if artifact.index_bytes != expected_index {
        return Err("cache index size differs from record count".to_owned());
    }
    Ok(())
}

fn load_cache_manifest(
    root: &Path,
    verify_file_sha256: bool,
) -> Result<QualifiedReplayCacheManifestV2> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolve cache directory: {error}"))?;
    let path = root.join("qualified-cache.json");
    require_regular_file(&path, "cache manifest")?;
    let manifest: QualifiedReplayCacheManifestV2 = serde_json::from_slice(
        &std::fs::read(&path).map_err(|error| format!("read cache manifest: {error}"))?,
    )
    .map_err(|error| format!("invalid cache manifest JSON: {error}"))?;
    if manifest.schema != "QualifiedReplayCacheManifestV2"
        || manifest.usage != QUALIFIED_CACHE_USAGE
        || manifest.status != "COMPLETE"
        || manifest.qualification_claim
        || manifest.cross_stream_total_order_available
        || !manifest.economic_features.is_empty()
        || !valid_sha256(&manifest.receipt_sha256)
        || !valid_sha256(&manifest.source_tree_sha256)
        || !valid_sha256(&manifest.replay_report_sha256)
        || manifest_digest(&manifest)? != manifest.manifest_sha256
        || manifest.identities.is_empty()
    {
        return Err("cache manifest contract or digest is invalid".to_owned());
    }
    let actual_entries = std::fs::read_dir(&root)
        .map_err(|error| format!("read cache directory: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("enumerate cache directory: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| format!("inspect cache directory entry: {error}"))?
                .is_file()
            {
                return Err("cache directory contains a non-file entry".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "cache filename is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected_entries = BTreeSet::from([
        "qualified-cache.json".to_owned(),
        manifest.snapshot.data_file.clone(),
        manifest.snapshot.index_file.clone(),
        manifest.depth.data_file.clone(),
        manifest.depth.index_file.clone(),
        manifest.trades.data_file.clone(),
        manifest.trades.index_file.clone(),
    ]);
    if actual_entries != expected_entries {
        return Err("cache directory file set differs from manifest".to_owned());
    }
    validate_artifact(&root, &manifest.snapshot, verify_file_sha256)?;
    validate_artifact(&root, &manifest.depth, verify_file_sha256)?;
    validate_artifact(&root, &manifest.trades, verify_file_sha256)?;
    Ok(manifest)
}

pub fn load_qualified_replay_cache_manifest(root: &Path) -> Result<QualifiedReplayCacheManifestV2> {
    load_cache_manifest(root, true)
}

fn take_u64(body: &[u8], cursor: &mut usize) -> Result<u64> {
    let end = cursor
        .checked_add(8)
        .ok_or_else(|| "cache record cursor overflow".to_owned())?;
    let bytes: [u8; 8] = body
        .get(*cursor..end)
        .ok_or_else(|| "cache record is truncated".to_owned())?
        .try_into()
        .map_err(|_| "cache integer width is invalid".to_owned())?;
    *cursor = end;
    Ok(u64::from_be_bytes(bytes))
}

fn visit_cache_events<F>(
    root: &Path,
    artifact: &QualifiedReplayCacheArtifactV2,
    mut visit: F,
) -> Result<()>
where
    F: FnMut(CachedEvent) -> Result<()>,
{
    let mut data = BufReader::with_capacity(
        8 * 1024 * 1024,
        HashingReader::new(
            File::open(safe_leaf(root, &artifact.data_file)?)
                .map_err(|error| format!("open cache data: {error}"))?,
        ),
    );
    let mut index = BufReader::with_capacity(
        1024 * 1024,
        HashingReader::new(
            File::open(safe_leaf(root, &artifact.index_file)?)
                .map_err(|error| format!("open cache index: {error}"))?,
        ),
    );
    let mut magic = [0_u8; 8];
    data.read_exact(&mut magic)
        .map_err(|_| "cache data magic is truncated".to_owned())?;
    if &magic != CACHE_MAGIC {
        return Err("cache data magic is invalid".to_owned());
    }
    index
        .read_exact(&mut magic)
        .map_err(|_| "cache index magic is truncated".to_owned())?;
    if &magic != INDEX_MAGIC {
        return Err("cache index magic is invalid".to_owned());
    }
    let mut offset = CACHE_MAGIC.len() as u64;
    for record_ordinal in 0..artifact.records {
        let start_offset = offset;
        let mut prefix = [0_u8; 4];
        data.read_exact(&mut prefix)
            .map_err(|_| "cache record length is truncated".to_owned())?;
        let length = u32::from_be_bytes(prefix) as usize;
        if !(108..=MAX_CACHE_RECORD_BYTES).contains(&length) {
            return Err("cache record length is invalid".to_owned());
        }
        let mut body = vec![0_u8; length];
        data.read_exact(&mut body)
            .map_err(|_| "cache record body is truncated".to_owned())?;
        let mut record_digest = [0_u8; 32];
        data.read_exact(&mut record_digest)
            .map_err(|_| "cache record digest is truncated".to_owned())?;
        let mut cursor = 0;
        let generation_index = take_u64(&body, &mut cursor)?;
        let segment_index = take_u64(&body, &mut cursor)?;
        let frame_index = take_u64(&body, &mut cursor)?;
        let receive_wall_ns = take_u64(&body, &mut cursor)?;
        let receive_mono_ns = take_u64(&body, &mut cursor)?;
        let digest_end = cursor
            .checked_add(64)
            .ok_or_else(|| "cache digest cursor overflow".to_owned())?;
        let record_sha256 = std::str::from_utf8(
            body.get(cursor..digest_end)
                .ok_or_else(|| "cache raw digest is truncated".to_owned())?,
        )
        .map_err(|_| "cache raw digest is not ASCII".to_owned())?
        .to_owned();
        if !valid_sha256(&record_sha256) {
            return Err("cache raw digest is invalid".to_owned());
        }
        cursor = digest_end;
        let payload_end = cursor
            .checked_add(4)
            .ok_or_else(|| "cache payload cursor overflow".to_owned())?;
        let payload_length = u32::from_be_bytes(
            body.get(cursor..payload_end)
                .ok_or_else(|| "cache payload length is truncated".to_owned())?
                .try_into()
                .map_err(|_| "cache payload length width is invalid".to_owned())?,
        ) as usize;
        cursor = payload_end;
        if body.len().saturating_sub(cursor) != payload_length {
            return Err("cache payload length differs from body".to_owned());
        }
        let mut index_entry = [0_u8; INDEX_ENTRY_BYTES as usize];
        index
            .read_exact(&mut index_entry)
            .map_err(|_| "cache index entry is truncated".to_owned())?;
        let (index_chunks, index_remainder) = index_entry.as_chunks::<8>();
        if !index_remainder.is_empty() {
            return Err("cache index entry width is invalid".to_owned());
        }
        let indexed = index_chunks
            .iter()
            .map(|chunk| u64::from_be_bytes(*chunk))
            .collect::<Vec<_>>();
        if indexed
            != [
                offset,
                generation_index,
                segment_index,
                frame_index,
                receive_wall_ns,
                receive_mono_ns,
            ]
        {
            return Err("cache index entry differs from data record".to_owned());
        }
        offset = offset
            .checked_add(4 + body.len() as u64 + 32)
            .ok_or_else(|| "cache reader offset overflow".to_owned())?;
        visit(CachedEvent {
            record_ordinal,
            start_offset,
            end_offset: offset,
            generation_index,
            segment_index,
            frame_index,
            receive_wall_ns,
            receive_mono_ns,
            record_sha256,
            payload: body[cursor..].to_vec(),
        })?;
    }
    let mut extra = [0_u8; 1];
    if data
        .read(&mut extra)
        .map_err(|error| format!("read cache data EOF: {error}"))?
        != 0
        || index
            .read(&mut extra)
            .map_err(|error| format!("read cache index EOF: {error}"))?
            != 0
        || offset != artifact.data_bytes
    {
        return Err("cache artifact has an unmanifested tail".to_owned());
    }
    let data_sha256 = data.into_inner().finish();
    let index_sha256 = index.into_inner().finish();
    if data_sha256 != artifact.data_sha256 || index_sha256 != artifact.index_sha256 {
        return Err("cache artifact digest differs from manifest".to_owned());
    }
    Ok(())
}

#[derive(Default)]
struct GenerationCounts {
    first: Option<u64>,
    last: Option<u64>,
    raw: u64,
    market: u64,
    controls: u64,
}

fn observe_frame(counts: &mut GenerationCounts, frame: u64, control: bool) {
    counts.first.get_or_insert(frame);
    counts.last = Some(frame);
    counts.raw += 1;
    if control {
        counts.controls += 1;
    } else {
        counts.market += 1;
    }
}

fn finish_depth_generation(
    index: usize,
    counts: &GenerationCounts,
    book: &LocalOrderBook,
    identities: &[QualifiedReplayCacheIdentityV2],
    output: &mut Vec<DepthGenerationReplayV1>,
) -> Result<()> {
    output.push(DepthGenerationReplayV1 {
        generation_index: index as u64,
        session_id: identities[index].session_id.clone(),
        first_selected_frame_index: counts
            .first
            .ok_or_else(|| "cached depth generation contains no record".to_owned())?,
        last_selected_frame_index: counts
            .last
            .ok_or_else(|| "cached depth generation contains no record".to_owned())?,
        selected_raw_records: counts.raw,
        selected_market_records: counts.market,
        selected_control_records: counts.controls,
        final_update_id: book
            .last_update_id()
            .ok_or_else(|| "cached depth replay has no update ID".to_owned())?,
        state_sha256: book.state_digest(),
    });
    Ok(())
}

fn replay_cached_depth(
    receipt: &QualifiedCompleteReplayReceiptV1,
    root: &Path,
    manifest: &QualifiedReplayCacheManifestV2,
    snapshot_payload: &[u8],
) -> Result<CompleteDepthReplayV1> {
    let mut book = LocalOrderBook::new(&manifest.symbol)?;
    book.load_snapshot(snapshot_payload)?;
    let mut generations = Vec::new();
    let mut counts = GenerationCounts::default();
    let mut generation = 0_usize;
    let mut controls = 0_u64;
    let mut market = 0_u64;
    let mut old_records = 0_u64;
    let mut applied_records = 0_u64;
    visit_cache_events(root, &manifest.depth, |event| {
        let current = usize::try_from(event.generation_index)
            .map_err(|_| "cached depth generation index overflow".to_owned())?;
        if current >= manifest.identities.len() || current < generation {
            return Err("cached depth generation order is invalid".to_owned());
        }
        while generation < current {
            finish_depth_generation(
                generation,
                &counts,
                &book,
                &manifest.identities,
                &mut generations,
            )?;
            generation += 1;
            counts = GenerationCounts::default();
        }
        let value: Value = serde_json::from_slice(&event.payload)
            .map_err(|error| format!("invalid cached depth payload: {error}"))?;
        let control = is_server_shutdown(&value)?;
        observe_frame(&mut counts, event.frame_index, control);
        if control {
            controls += 1;
        } else {
            market += 1;
            match book.apply_depth_value(&value)? {
                ApplyOutcome::Old => old_records += 1,
                ApplyOutcome::Applied => applied_records += 1,
            }
        }
        Ok(())
    })?;
    while generation < manifest.identities.len() {
        finish_depth_generation(
            generation,
            &counts,
            &book,
            &manifest.identities,
            &mut generations,
        )?;
        generation += 1;
        counts = GenerationCounts::default();
    }
    let expected = &receipt.report.depth;
    let (bid_levels, ask_levels) = book.level_counts();
    let replay = CompleteDepthReplayV1 {
        total_raw_records: expected.total_raw_records,
        total_control_records: expected.total_control_records,
        selected_raw_records: manifest.depth.records,
        selected_market_records: market,
        selected_control_records: controls,
        overlap_records_excluded: expected.overlap_records_excluded,
        old_records,
        applied_records,
        final_update_id: book
            .last_update_id()
            .ok_or_else(|| "cached depth replay has no final update ID".to_owned())?,
        bid_levels: bid_levels as u64,
        ask_levels: ask_levels as u64,
        state_sha256: book.state_digest(),
        generations,
    };
    if &replay != expected {
        return Err("cached depth replay differs from qualified replay".to_owned());
    }
    Ok(replay)
}

fn finish_trade_generation(
    index: usize,
    counts: &GenerationCounts,
    last_trade_id: Option<u64>,
    identities: &[QualifiedReplayCacheIdentityV2],
    output: &mut Vec<TradeGenerationReplayV1>,
) -> Result<()> {
    output.push(TradeGenerationReplayV1 {
        generation_index: index as u64,
        session_id: identities[index].session_id.clone(),
        first_selected_frame_index: counts.first,
        last_selected_frame_index: counts.last,
        selected_raw_records: counts.raw,
        selected_market_records: counts.market,
        selected_control_records: counts.controls,
        last_trade_id: last_trade_id
            .ok_or_else(|| "cached trade replay contains no market event".to_owned())?,
    });
    Ok(())
}

fn replay_cached_trades(
    receipt: &QualifiedCompleteReplayReceiptV1,
    root: &Path,
    manifest: &QualifiedReplayCacheManifestV2,
) -> Result<CompleteTradeReplayV1> {
    let mut generations = Vec::new();
    let mut counts = GenerationCounts::default();
    let mut generation = 0_usize;
    let mut controls = 0_u64;
    let mut market = 0_u64;
    let mut first_trade_id = None;
    let mut previous_trade_id = None;
    visit_cache_events(root, &manifest.trades, |event| {
        let current = usize::try_from(event.generation_index)
            .map_err(|_| "cached trade generation index overflow".to_owned())?;
        if current >= manifest.identities.len() || current < generation {
            return Err("cached trade generation order is invalid".to_owned());
        }
        while generation < current {
            finish_trade_generation(
                generation,
                &counts,
                previous_trade_id,
                &manifest.identities,
                &mut generations,
            )?;
            generation += 1;
            counts = GenerationCounts::default();
        }
        let value: Value = serde_json::from_slice(&event.payload)
            .map_err(|error| format!("invalid cached trade payload: {error}"))?;
        let control = is_server_shutdown(&value)?;
        observe_frame(&mut counts, event.frame_index, control);
        if control {
            controls += 1;
            return Ok(());
        }
        let trade_id = validated_trade_id(&value, &manifest.symbol)?;
        if previous_trade_id.is_some_and(|old| trade_id <= old) {
            return Err("cached trade ID duplicated or regressed".to_owned());
        }
        first_trade_id.get_or_insert(trade_id);
        previous_trade_id = Some(trade_id);
        market += 1;
        Ok(())
    })?;
    while generation < manifest.identities.len() {
        finish_trade_generation(
            generation,
            &counts,
            previous_trade_id,
            &manifest.identities,
            &mut generations,
        )?;
        generation += 1;
        counts = GenerationCounts::default();
    }
    let expected = &receipt.report.trades;
    let replay = CompleteTradeReplayV1 {
        total_raw_records: expected.total_raw_records,
        total_control_records: expected.total_control_records,
        selected_raw_records: manifest.trades.records,
        selected_market_records: market,
        selected_control_records: controls,
        overlap_records_excluded: expected.overlap_records_excluded,
        first_trade_id: first_trade_id
            .ok_or_else(|| "cached trade replay contains no market event".to_owned())?,
        last_trade_id: previous_trade_id
            .ok_or_else(|| "cached trade replay contains no market event".to_owned())?,
        trade_ids_strictly_increasing: true,
        generations,
    };
    if &replay != expected {
        return Err("cached trade replay differs from qualified replay".to_owned());
    }
    Ok(replay)
}

fn validate_cache_binding(
    receipt: &QualifiedCompleteReplayReceiptV1,
    manifest: &QualifiedReplayCacheManifestV2,
) -> Result<()> {
    if manifest.receipt_sha256 != receipt.receipt_sha256
        || manifest.source_tree_sha256 != receipt.source_tree_sha256
        || manifest.replay_report_sha256 != receipt.report.report_sha256
        || manifest.symbol != receipt.selection.symbol
        || manifest.identities.len() != receipt.report.source.generations as usize
    {
        return Err("cache manifest is not bound to the selected receipt".to_owned());
    }
    for (expected, identity) in manifest.identities.iter().enumerate() {
        if identity.generation_index != expected as u64
            || identity.session_id != receipt.report.depth.generations[expected].session_id
            || identity.session_id != receipt.report.trades.generations[expected].session_id
        {
            return Err("cache generation identity differs from replay report".to_owned());
        }
    }
    Ok(())
}

struct PendingDepthBoundary {
    generation_index: u64,
    segment_index: u64,
    record_ordinal: u64,
    next_data_offset: u64,
    frame_index: u64,
    receive_wall_ns: u64,
    receive_mono_ns: u64,
    record_sha256: String,
}

fn write_depth_boundary(
    writer: &mut CheckpointWriter,
    book: &LocalOrderBook,
    boundary: PendingDepthBoundary,
) -> Result<()> {
    let next_record_ordinal = boundary
        .record_ordinal
        .checked_add(1)
        .ok_or_else(|| "checkpoint record ordinal overflow".to_owned())?;
    writer.append(QualifiedDepthCheckpointV1 {
        schema: "QualifiedDepthCheckpointV1".to_owned(),
        generation_index: boundary.generation_index,
        segment_index: boundary.segment_index,
        last_record_ordinal: boundary.record_ordinal,
        next_record_ordinal,
        next_data_offset: boundary.next_data_offset,
        last_frame_index: boundary.frame_index,
        last_receive_wall_ns: boundary.receive_wall_ns,
        last_receive_mono_ns: boundary.receive_mono_ns,
        last_raw_record_sha256: boundary.record_sha256,
        book: book.checkpoint()?,
        checkpoint_sha256: String::new(),
    })
}

fn verify_depth_boundary(
    checkpoint: &QualifiedDepthCheckpointV1,
    book: &LocalOrderBook,
    boundary: &PendingDepthBoundary,
) -> Result<()> {
    if checkpoint.generation_index != boundary.generation_index
        || checkpoint.segment_index != boundary.segment_index
        || checkpoint.last_record_ordinal != boundary.record_ordinal
        || checkpoint.next_data_offset != boundary.next_data_offset
        || checkpoint.last_frame_index != boundary.frame_index
        || checkpoint.last_receive_wall_ns != boundary.receive_wall_ns
        || checkpoint.last_receive_mono_ns != boundary.receive_mono_ns
        || checkpoint.last_raw_record_sha256 != boundary.record_sha256
    {
        return Err("checkpoint source position differs from natural segment boundary".to_owned());
    }
    let restored = LocalOrderBook::from_checkpoint(&checkpoint.book)?;
    if !book.same_state(&restored) || book.state_digest() != checkpoint.book.state_sha256 {
        return Err("checkpoint book differs from replayed segment prefix".to_owned());
    }
    Ok(())
}

pub fn build_qualified_replay_checkpoints(
    receipt: &QualifiedCompleteReplayReceiptV1,
    cache_root: &Path,
    destination: &Path,
) -> Result<QualifiedReplayCheckpointManifestV1> {
    validate_qualified_receipt(receipt)?;
    let cache_root = cache_root
        .canonicalize()
        .map_err(|error| format!("resolve cache directory: {error}"))?;
    let cache = load_cache_manifest(&cache_root, true)?;
    validate_cache_binding(receipt, &cache)?;
    let parent = destination
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|error| format!("resolve checkpoint destination parent: {error}"))?;
    let name = destination
        .file_name()
        .ok_or_else(|| "checkpoint destination has no directory name".to_owned())?;
    let destination = parent.join(name);
    if destination.starts_with(&cache_root) || cache_root.starts_with(&destination) {
        return Err("checkpoint store and replay cache must be separate directories".to_owned());
    }
    std::fs::create_dir(&destination)
        .map_err(|error| format!("create checkpoint directory: {error}"))?;

    let mut snapshot_payload = None;
    visit_cache_events(&cache_root, &cache.snapshot, |event| {
        if event.generation_index != 0 || event.segment_index != 0 || snapshot_payload.is_some() {
            return Err("cache snapshot cardinality is invalid".to_owned());
        }
        snapshot_payload = Some(event.payload);
        Ok(())
    })?;
    let mut book = LocalOrderBook::new(&cache.symbol)?;
    book.load_snapshot(&snapshot_payload.ok_or_else(|| "cache contains no snapshot".to_owned())?)?;
    let mut writer = CheckpointWriter::create(&destination)?;
    let mut pending: Option<PendingDepthBoundary> = None;
    let mut previous_key = None;
    let mut expected_ordinal = 0_u64;
    let mut expected_offset = CACHE_MAGIC.len() as u64;
    visit_cache_events(&cache_root, &cache.depth, |event| {
        if event.record_ordinal != expected_ordinal || event.start_offset != expected_offset {
            return Err("checkpoint source cache position is not continuous".to_owned());
        }
        let key = (event.generation_index, event.segment_index);
        if let Some(old) = previous_key
            && key != old
        {
            if key.0 < old.0 || (key.0 == old.0 && key.1 <= old.1) {
                return Err("checkpoint source segment order regressed or repeated".to_owned());
            }
            write_depth_boundary(
                &mut writer,
                &book,
                pending
                    .take()
                    .ok_or_else(|| "missing prior segment boundary".to_owned())?,
            )?;
        }
        let value: Value = serde_json::from_slice(&event.payload)
            .map_err(|error| format!("invalid cached depth payload: {error}"))?;
        if !is_server_shutdown(&value)? {
            book.apply_depth_value(&value)?;
        }
        expected_ordinal = expected_ordinal
            .checked_add(1)
            .ok_or_else(|| "checkpoint source ordinal overflow".to_owned())?;
        expected_offset = event.end_offset;
        previous_key = Some(key);
        pending = Some(PendingDepthBoundary {
            generation_index: event.generation_index,
            segment_index: event.segment_index,
            record_ordinal: event.record_ordinal,
            next_data_offset: event.end_offset,
            frame_index: event.frame_index,
            receive_wall_ns: event.receive_wall_ns,
            receive_mono_ns: event.receive_mono_ns,
            record_sha256: event.record_sha256,
        });
        Ok(())
    })?;
    if expected_ordinal != cache.depth.records || expected_offset != cache.depth.data_bytes {
        return Err("checkpoint source did not consume the exact depth cache".to_owned());
    }
    write_depth_boundary(
        &mut writer,
        &book,
        pending.ok_or_else(|| "depth cache contains no checkpoint boundary".to_owned())?,
    )?;
    let final_state_sha256 = book.state_digest();
    if final_state_sha256 != receipt.report.depth.state_sha256
        || book.last_update_id() != Some(receipt.report.depth.final_update_id)
    {
        return Err("checkpoint build final book differs from qualified replay".to_owned());
    }
    let artifact = writer.finish()?;
    if artifact.checkpoints == 0 {
        return Err("checkpoint build produced no checkpoint".to_owned());
    }
    let mut manifest = QualifiedReplayCheckpointManifestV1 {
        schema: "QualifiedReplayCheckpointManifestV1".to_owned(),
        usage: QUALIFIED_CHECKPOINT_USAGE.to_owned(),
        status: "COMPLETE".to_owned(),
        qualification_claim: false,
        economic_features: Vec::new(),
        receipt_sha256: receipt.receipt_sha256.clone(),
        source_tree_sha256: receipt.source_tree_sha256.clone(),
        replay_report_sha256: receipt.report.report_sha256.clone(),
        cache_manifest_sha256: cache.manifest_sha256,
        cache_manifest_file_sha256: sha256_file(&cache_root.join("qualified-cache.json"))?,
        cache_depth_data_sha256: cache.depth.data_sha256,
        cache_depth_index_sha256: cache.depth.index_sha256,
        symbol: cache.symbol,
        artifact,
        final_state_sha256,
        manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = checkpoint_manifest_digest(&manifest)?;
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize checkpoint manifest: {error}"))?;
    bytes.push(b'\n');
    let mut file = create_new(&destination.join("qualified-checkpoints.json"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("write checkpoint manifest: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync checkpoint manifest: {error}"))?;
    Ok(manifest)
}

fn read_checkpoint_records(
    root: &Path,
    artifact: &QualifiedReplayCheckpointArtifactV1,
) -> Result<Vec<QualifiedDepthCheckpointV1>> {
    if artifact.data_file != "depth-checkpoints.bncp"
        || artifact.index_file != "depth-checkpoints.bncpi"
        || !valid_sha256(&artifact.data_sha256)
        || !valid_sha256(&artifact.index_sha256)
        || artifact.checkpoints == 0
    {
        return Err("checkpoint artifact contract is invalid".to_owned());
    }
    let data_path = safe_leaf(root, &artifact.data_file)?;
    let index_path = safe_leaf(root, &artifact.index_file)?;
    require_regular_file(&data_path, "checkpoint data")?;
    require_regular_file(&index_path, "checkpoint index")?;
    if std::fs::metadata(&data_path)
        .map_err(|error| format!("inspect checkpoint data: {error}"))?
        .len()
        != artifact.data_bytes
        || std::fs::metadata(&index_path)
            .map_err(|error| format!("inspect checkpoint index: {error}"))?
            .len()
            != artifact.index_bytes
    {
        return Err("checkpoint artifact length differs from manifest".to_owned());
    }
    let expected_index_bytes = (CHECKPOINT_INDEX_MAGIC.len() as u64)
        .checked_add(
            artifact
                .checkpoints
                .checked_mul(CHECKPOINT_INDEX_ENTRY_BYTES)
                .ok_or_else(|| "checkpoint index size overflow".to_owned())?,
        )
        .ok_or_else(|| "checkpoint index size overflow".to_owned())?;
    if artifact.index_bytes != expected_index_bytes {
        return Err("checkpoint index size differs from checkpoint count".to_owned());
    }
    let mut data = BufReader::with_capacity(
        8 * 1024 * 1024,
        HashingReader::new(
            File::open(&data_path).map_err(|error| format!("open checkpoint data: {error}"))?,
        ),
    );
    let mut index = BufReader::with_capacity(
        1024 * 1024,
        HashingReader::new(
            File::open(&index_path).map_err(|error| format!("open checkpoint index: {error}"))?,
        ),
    );
    let mut magic = [0_u8; 8];
    data.read_exact(&mut magic)
        .map_err(|_| "checkpoint data magic is truncated".to_owned())?;
    if &magic != CHECKPOINT_MAGIC {
        return Err("checkpoint data magic is invalid".to_owned());
    }
    index
        .read_exact(&mut magic)
        .map_err(|_| "checkpoint index magic is truncated".to_owned())?;
    if &magic != CHECKPOINT_INDEX_MAGIC {
        return Err("checkpoint index magic is invalid".to_owned());
    }
    let mut offset = CHECKPOINT_MAGIC.len() as u64;
    let mut result = Vec::with_capacity(artifact.checkpoints as usize);
    let mut previous_key: Option<(u64, u64)> = None;
    let mut previous_ordinal: Option<u64> = None;
    for _ in 0..artifact.checkpoints {
        let start = offset;
        let mut prefix = [0_u8; 4];
        data.read_exact(&mut prefix)
            .map_err(|_| "checkpoint record length is truncated".to_owned())?;
        let length = u32::from_be_bytes(prefix) as usize;
        if !(1..=MAX_CHECKPOINT_RECORD_BYTES).contains(&length) {
            return Err("checkpoint record length is invalid".to_owned());
        }
        let mut body = vec![0_u8; length];
        data.read_exact(&mut body)
            .map_err(|_| "checkpoint record body is truncated".to_owned())?;
        let mut stored_digest = [0_u8; 32];
        data.read_exact(&mut stored_digest)
            .map_err(|_| "checkpoint record digest is truncated".to_owned())?;
        if stored_digest.as_slice() != Sha256::digest(&body).as_slice() {
            return Err("checkpoint record digest is invalid".to_owned());
        }
        let checkpoint: QualifiedDepthCheckpointV1 = serde_json::from_slice(&body)
            .map_err(|error| format!("invalid checkpoint record JSON: {error}"))?;
        if checkpoint.schema != "QualifiedDepthCheckpointV1"
            || checkpoint.checkpoint_sha256 != checkpoint_digest(&checkpoint)?
            || !valid_sha256(&checkpoint.last_raw_record_sha256)
            || checkpoint.next_record_ordinal
                != checkpoint
                    .last_record_ordinal
                    .checked_add(1)
                    .ok_or_else(|| "checkpoint ordinal overflow".to_owned())?
        {
            return Err("checkpoint record contract or digest is invalid".to_owned());
        }
        LocalOrderBook::from_checkpoint(&checkpoint.book)?;
        let mut index_entry = [0_u8; CHECKPOINT_INDEX_ENTRY_BYTES as usize];
        index
            .read_exact(&mut index_entry)
            .map_err(|_| "checkpoint index entry is truncated".to_owned())?;
        let (chunks, remainder) = index_entry.as_chunks::<8>();
        if !remainder.is_empty() {
            return Err("checkpoint index entry width is invalid".to_owned());
        }
        let indexed = chunks
            .iter()
            .map(|chunk| u64::from_be_bytes(*chunk))
            .collect::<Vec<_>>();
        if indexed
            != [
                start,
                checkpoint.last_record_ordinal,
                checkpoint.next_record_ordinal,
                checkpoint.next_data_offset,
                checkpoint.generation_index,
                checkpoint.segment_index,
                checkpoint.last_frame_index,
                checkpoint.book.last_update_id,
            ]
        {
            return Err("checkpoint index entry differs from checkpoint record".to_owned());
        }
        let key = (checkpoint.generation_index, checkpoint.segment_index);
        if previous_key.is_some_and(|old| key.0 < old.0 || (key.0 == old.0 && key.1 <= old.1))
            || previous_ordinal.is_some_and(|old| checkpoint.last_record_ordinal <= old)
        {
            return Err("checkpoint ordering regressed or repeated".to_owned());
        }
        previous_key = Some(key);
        previous_ordinal = Some(checkpoint.last_record_ordinal);
        offset = offset
            .checked_add(4 + body.len() as u64 + 32)
            .ok_or_else(|| "checkpoint reader offset overflow".to_owned())?;
        result.push(checkpoint);
    }
    let mut extra = [0_u8; 1];
    if data
        .read(&mut extra)
        .map_err(|error| format!("read checkpoint data EOF: {error}"))?
        != 0
        || index
            .read(&mut extra)
            .map_err(|error| format!("read checkpoint index EOF: {error}"))?
            != 0
        || offset != artifact.data_bytes
    {
        return Err("checkpoint artifact has an unmanifested tail".to_owned());
    }
    if data.into_inner().finish() != artifact.data_sha256
        || index.into_inner().finish() != artifact.index_sha256
    {
        return Err("checkpoint artifact digest differs from manifest".to_owned());
    }
    Ok(result)
}

fn load_checkpoint_manifest(root: &Path) -> Result<(PathBuf, QualifiedReplayCheckpointManifestV1)> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolve checkpoint directory: {error}"))?;
    let path = root.join("qualified-checkpoints.json");
    require_regular_file(&path, "checkpoint manifest")?;
    let manifest: QualifiedReplayCheckpointManifestV1 = serde_json::from_slice(
        &std::fs::read(&path).map_err(|error| format!("read checkpoint manifest: {error}"))?,
    )
    .map_err(|error| format!("invalid checkpoint manifest JSON: {error}"))?;
    if manifest.schema != "QualifiedReplayCheckpointManifestV1"
        || manifest.usage != QUALIFIED_CHECKPOINT_USAGE
        || manifest.status != "COMPLETE"
        || manifest.qualification_claim
        || !manifest.economic_features.is_empty()
        || !valid_sha256(&manifest.receipt_sha256)
        || !valid_sha256(&manifest.source_tree_sha256)
        || !valid_sha256(&manifest.replay_report_sha256)
        || !valid_sha256(&manifest.cache_manifest_sha256)
        || !valid_sha256(&manifest.cache_manifest_file_sha256)
        || !valid_sha256(&manifest.cache_depth_data_sha256)
        || !valid_sha256(&manifest.cache_depth_index_sha256)
        || !valid_sha256(&manifest.final_state_sha256)
        || checkpoint_manifest_digest(&manifest)? != manifest.manifest_sha256
    {
        return Err("checkpoint manifest contract or digest is invalid".to_owned());
    }
    let actual_entries = std::fs::read_dir(&root)
        .map_err(|error| format!("read checkpoint directory: {error}"))?
        .map(|entry| {
            let entry =
                entry.map_err(|error| format!("enumerate checkpoint directory: {error}"))?;
            if !entry
                .file_type()
                .map_err(|error| format!("inspect checkpoint directory entry: {error}"))?
                .is_file()
            {
                return Err("checkpoint directory contains a non-file entry".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "checkpoint filename is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected_entries = BTreeSet::from([
        "qualified-checkpoints.json".to_owned(),
        manifest.artifact.data_file.clone(),
        manifest.artifact.index_file.clone(),
    ]);
    if actual_entries != expected_entries {
        return Err("checkpoint directory file set differs from manifest".to_owned());
    }
    Ok((root, manifest))
}

pub fn validate_qualified_replay_checkpoints(
    receipt: &QualifiedCompleteReplayReceiptV1,
    cache_root: &Path,
    checkpoint_root: &Path,
) -> Result<QualifiedReplayCheckpointManifestV1> {
    validate_qualified_receipt(receipt)?;
    let cache_root = cache_root
        .canonicalize()
        .map_err(|error| format!("resolve cache directory: {error}"))?;
    let cache = load_cache_manifest(&cache_root, true)?;
    validate_cache_binding(receipt, &cache)?;
    let (checkpoint_root, manifest) = load_checkpoint_manifest(checkpoint_root)?;
    if manifest.receipt_sha256 != receipt.receipt_sha256
        || manifest.source_tree_sha256 != receipt.source_tree_sha256
        || manifest.replay_report_sha256 != receipt.report.report_sha256
        || manifest.cache_manifest_sha256 != cache.manifest_sha256
        || manifest.cache_manifest_file_sha256
            != sha256_file(&cache_root.join("qualified-cache.json"))?
        || manifest.cache_depth_data_sha256 != cache.depth.data_sha256
        || manifest.cache_depth_index_sha256 != cache.depth.index_sha256
        || manifest.symbol != cache.symbol
    {
        return Err(
            "checkpoint manifest is not bound to the selected cache and receipt".to_owned(),
        );
    }
    let checkpoints = read_checkpoint_records(&checkpoint_root, &manifest.artifact)?;
    let mut snapshot_payload = None;
    visit_cache_events(&cache_root, &cache.snapshot, |event| {
        if snapshot_payload.is_some() {
            return Err("cache snapshot cardinality is invalid".to_owned());
        }
        snapshot_payload = Some(event.payload);
        Ok(())
    })?;
    let mut book = LocalOrderBook::new(&cache.symbol)?;
    book.load_snapshot(&snapshot_payload.ok_or_else(|| "cache contains no snapshot".to_owned())?)?;
    let mut checkpoint_index = 0_usize;
    let mut previous_key = None;
    let mut boundary: Option<PendingDepthBoundary> = None;
    visit_cache_events(&cache_root, &cache.depth, |event| {
        let key = (event.generation_index, event.segment_index);
        if previous_key.is_some_and(|old| old != key) {
            verify_depth_boundary(
                checkpoints
                    .get(checkpoint_index)
                    .ok_or_else(|| "checkpoint missing at segment boundary".to_owned())?,
                &book,
                boundary
                    .as_ref()
                    .ok_or_else(|| "depth cache lost prior segment position".to_owned())?,
            )?;
            checkpoint_index += 1;
        }
        let value: Value = serde_json::from_slice(&event.payload)
            .map_err(|error| format!("invalid cached depth payload: {error}"))?;
        if !is_server_shutdown(&value)? {
            book.apply_depth_value(&value)?;
        }
        previous_key = Some(key);
        boundary = Some(PendingDepthBoundary {
            generation_index: event.generation_index,
            segment_index: event.segment_index,
            record_ordinal: event.record_ordinal,
            next_data_offset: event.end_offset,
            frame_index: event.frame_index,
            receive_wall_ns: event.receive_wall_ns,
            receive_mono_ns: event.receive_mono_ns,
            record_sha256: event.record_sha256,
        });
        Ok(())
    })?;
    verify_depth_boundary(
        checkpoints
            .get(checkpoint_index)
            .ok_or_else(|| "checkpoint missing at final segment boundary".to_owned())?,
        &book,
        boundary
            .as_ref()
            .ok_or_else(|| "depth cache contains no final segment position".to_owned())?,
    )?;
    checkpoint_index += 1;
    if checkpoint_index != checkpoints.len()
        || book.state_digest() != manifest.final_state_sha256
        || manifest.final_state_sha256 != receipt.report.depth.state_sha256
    {
        return Err("checkpoint coverage or final state differs from qualified replay".to_owned());
    }
    Ok(manifest)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NeutralDepthWindowReplayV1 {
    pub schema: String,
    pub status: String,
    pub symbol: String,
    pub cross_stream_total_order_available: bool,
    pub economic_features: Vec<String>,
    pub start_checkpoint_sha256: String,
    pub end_checkpoint_sha256: String,
    pub start_generation_index: u64,
    pub start_segment_index: u64,
    pub end_generation_index: u64,
    pub end_segment_index: u64,
    pub first_record_ordinal: u64,
    pub last_record_ordinal: u64,
    pub raw_records: u64,
    pub market_records: u64,
    pub control_records: u64,
    pub old_records: u64,
    pub applied_records: u64,
    pub final_update_id: u64,
    pub bid_levels: u64,
    pub ask_levels: u64,
    pub state_sha256: String,
    pub report_sha256: String,
}

pub struct QualifiedDepthReplaySession {
    symbol: String,
    checkpoints: Vec<QualifiedDepthCheckpointV1>,
    checkpoint_books: Vec<LocalOrderBook>,
    depth_events: Vec<PreparedCachedDepthEvent>,
}

#[derive(Clone)]
enum PreparedCachedDepthEvent {
    Control,
    Market(PreparedDepthUpdate),
}

fn decode_cached_event_at(
    data: &[u8],
    start_offset: u64,
    record_ordinal: u64,
) -> Result<CachedEvent> {
    let start = usize::try_from(start_offset)
        .map_err(|_| "cache record start offset exceeds address space".to_owned())?;
    let prefix_end = start
        .checked_add(4)
        .ok_or_else(|| "cache record prefix offset overflow".to_owned())?;
    let length = u32::from_be_bytes(
        data.get(start..prefix_end)
            .ok_or_else(|| "cache record length is truncated".to_owned())?
            .try_into()
            .map_err(|_| "cache record length width is invalid".to_owned())?,
    ) as usize;
    if !(108..=MAX_CACHE_RECORD_BYTES).contains(&length) {
        return Err("cache record length is invalid".to_owned());
    }
    let body_end = prefix_end
        .checked_add(length)
        .ok_or_else(|| "cache record body offset overflow".to_owned())?;
    let digest_end = body_end
        .checked_add(32)
        .ok_or_else(|| "cache record digest offset overflow".to_owned())?;
    let body = data
        .get(prefix_end..body_end)
        .ok_or_else(|| "cache record body is truncated".to_owned())?;
    let stored_digest = data
        .get(body_end..digest_end)
        .ok_or_else(|| "cache record digest is truncated".to_owned())?;
    if stored_digest != Sha256::digest(body).as_slice() {
        return Err("cache record digest is invalid".to_owned());
    }
    let mut cursor = 0;
    let generation_index = take_u64(body, &mut cursor)?;
    let segment_index = take_u64(body, &mut cursor)?;
    let frame_index = take_u64(body, &mut cursor)?;
    let receive_wall_ns = take_u64(body, &mut cursor)?;
    let receive_mono_ns = take_u64(body, &mut cursor)?;
    let raw_digest_end = cursor
        .checked_add(64)
        .ok_or_else(|| "cache raw digest cursor overflow".to_owned())?;
    let record_sha256 = std::str::from_utf8(
        body.get(cursor..raw_digest_end)
            .ok_or_else(|| "cache raw digest is truncated".to_owned())?,
    )
    .map_err(|_| "cache raw digest is not ASCII".to_owned())?
    .to_owned();
    if !valid_sha256(&record_sha256) {
        return Err("cache raw digest is invalid".to_owned());
    }
    cursor = raw_digest_end;
    let payload_length_end = cursor
        .checked_add(4)
        .ok_or_else(|| "cache payload length cursor overflow".to_owned())?;
    let payload_length = u32::from_be_bytes(
        body.get(cursor..payload_length_end)
            .ok_or_else(|| "cache payload length is truncated".to_owned())?
            .try_into()
            .map_err(|_| "cache payload length width is invalid".to_owned())?,
    ) as usize;
    cursor = payload_length_end;
    if body.len().saturating_sub(cursor) != payload_length {
        return Err("cache payload length differs from body".to_owned());
    }
    Ok(CachedEvent {
        record_ordinal,
        start_offset,
        end_offset: u64::try_from(digest_end)
            .map_err(|_| "cache record end offset overflow".to_owned())?,
        generation_index,
        segment_index,
        frame_index,
        receive_wall_ns,
        receive_mono_ns,
        record_sha256,
        payload: body[cursor..].to_vec(),
    })
}

impl QualifiedDepthReplaySession {
    pub fn open_verified(
        receipt: &QualifiedCompleteReplayReceiptV1,
        cache_root: &Path,
        checkpoint_root: &Path,
    ) -> Result<Self> {
        validate_qualified_replay_checkpoints(receipt, cache_root, checkpoint_root)?;
        let cache_root = cache_root
            .canonicalize()
            .map_err(|error| format!("resolve cache directory: {error}"))?;
        let cache = load_cache_manifest(&cache_root, false)?;
        let (checkpoint_root, checkpoint_manifest) = load_checkpoint_manifest(checkpoint_root)?;
        let checkpoints = read_checkpoint_records(&checkpoint_root, &checkpoint_manifest.artifact)?;
        let checkpoint_books = checkpoints
            .iter()
            .map(|checkpoint| LocalOrderBook::from_checkpoint(&checkpoint.book))
            .collect::<Result<Vec<_>>>()?;
        let depth_data = std::fs::read(safe_leaf(&cache_root, &cache.depth.data_file)?)
            .map_err(|error| format!("read verified depth cache: {error}"))?;
        if depth_data.get(..CACHE_MAGIC.len()) != Some(CACHE_MAGIC.as_slice())
            || depth_data.len() as u64 != cache.depth.data_bytes
            || crate::hex(&Sha256::digest(&depth_data)) != cache.depth.data_sha256
        {
            return Err("depth cache changed after checkpoint validation".to_owned());
        }
        let mut decoded_offset = CACHE_MAGIC.len() as u64;
        for ordinal in 0..cache.depth.records {
            decoded_offset =
                decode_cached_event_at(&depth_data, decoded_offset, ordinal)?.end_offset;
        }
        if decoded_offset != cache.depth.data_bytes {
            return Err("in-memory depth decoder did not consume exact cache bytes".to_owned());
        }
        let mut snapshot_payload = None;
        visit_cache_events(&cache_root, &cache.snapshot, |event| {
            if snapshot_payload.is_some() {
                return Err("cache snapshot cardinality is invalid".to_owned());
            }
            snapshot_payload = Some(event.payload);
            Ok(())
        })?;
        let mut decoder_book = LocalOrderBook::new(&cache.symbol)?;
        decoder_book.load_snapshot(
            &snapshot_payload.ok_or_else(|| "cache contains no snapshot".to_owned())?,
        )?;
        let capacity = usize::try_from(cache.depth.records)
            .map_err(|_| "depth cache record count exceeds address space".to_owned())?;
        let mut depth_events = Vec::with_capacity(capacity);
        visit_cache_events(&cache_root, &cache.depth, |event| {
            let value: Value = serde_json::from_slice(&event.payload)
                .map_err(|error| format!("invalid cached depth payload: {error}"))?;
            if is_server_shutdown(&value)? {
                depth_events.push(PreparedCachedDepthEvent::Control);
            } else {
                let prepared = decoder_book.prepare_depth_value(&value)?;
                decoder_book.apply_prepared_depth(&prepared)?;
                depth_events.push(PreparedCachedDepthEvent::Market(prepared));
            }
            Ok(())
        })?;
        if depth_events.len() != capacity
            || decoder_book.state_digest() != receipt.report.depth.state_sha256
        {
            return Err("prepared in-memory depth events differ from qualified replay".to_owned());
        }
        Ok(Self {
            symbol: cache.symbol,
            checkpoints,
            checkpoint_books,
            depth_events,
        })
    }

    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    pub fn replay_window(
        &self,
        start_checkpoint_index: usize,
        end_checkpoint_index: usize,
    ) -> Result<NeutralDepthWindowReplayV1> {
        if start_checkpoint_index >= end_checkpoint_index {
            return Err("window requires start checkpoint before end checkpoint".to_owned());
        }
        let start = self
            .checkpoints
            .get(start_checkpoint_index)
            .ok_or_else(|| "start checkpoint index is outside the store".to_owned())?;
        let end = self
            .checkpoints
            .get(end_checkpoint_index)
            .ok_or_else(|| "end checkpoint index is outside the store".to_owned())?;
        let mut book = self
            .checkpoint_books
            .get(start_checkpoint_index)
            .ok_or_else(|| "start checkpoint book is outside the store".to_owned())?
            .clone();
        let mut ordinal = start.next_record_ordinal;
        let first_record_ordinal = ordinal;
        let mut raw_records = 0_u64;
        let mut market_records = 0_u64;
        let mut control_records = 0_u64;
        let mut old_records = 0_u64;
        let mut applied_records = 0_u64;
        while ordinal < end.next_record_ordinal {
            let index = usize::try_from(ordinal)
                .map_err(|_| "window record ordinal exceeds address space".to_owned())?;
            match self
                .depth_events
                .get(index)
                .ok_or_else(|| "window record ordinal is outside prepared events".to_owned())?
            {
                PreparedCachedDepthEvent::Control => {
                    control_records += 1;
                }
                PreparedCachedDepthEvent::Market(update) => {
                    market_records += 1;
                    match book.apply_prepared_depth(update)? {
                        ApplyOutcome::Old => old_records += 1,
                        ApplyOutcome::Applied => applied_records += 1,
                    }
                }
            }
            raw_records += 1;
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| "window record ordinal overflow".to_owned())?;
        }
        if ordinal != end.next_record_ordinal {
            return Err("window did not end at the selected checkpoint".to_owned());
        }
        let expected = self
            .checkpoint_books
            .get(end_checkpoint_index)
            .ok_or_else(|| "end checkpoint book is outside the store".to_owned())?;
        if !book.same_state(expected) {
            return Err("checkpoint window replay differs from its end checkpoint".to_owned());
        }
        let (bid_levels, ask_levels) = book.level_counts();
        let mut report = NeutralDepthWindowReplayV1 {
            schema: "NeutralDepthWindowReplayV1".to_owned(),
            status: "EXACT".to_owned(),
            symbol: self.symbol.clone(),
            cross_stream_total_order_available: false,
            economic_features: Vec::new(),
            start_checkpoint_sha256: start.checkpoint_sha256.clone(),
            end_checkpoint_sha256: end.checkpoint_sha256.clone(),
            start_generation_index: start.generation_index,
            start_segment_index: start.segment_index,
            end_generation_index: end.generation_index,
            end_segment_index: end.segment_index,
            first_record_ordinal,
            last_record_ordinal: ordinal
                .checked_sub(1)
                .ok_or_else(|| "window selected no cache record".to_owned())?,
            raw_records,
            market_records,
            control_records,
            old_records,
            applied_records,
            final_update_id: book
                .last_update_id()
                .ok_or_else(|| "window replay has no final update ID".to_owned())?,
            bid_levels: bid_levels as u64,
            ask_levels: ask_levels as u64,
            state_sha256: book.state_digest(),
            report_sha256: String::new(),
        };
        let bytes = serde_json::to_vec(&report)
            .map_err(|error| format!("serialize window report material: {error}"))?;
        report.report_sha256 = crate::hex(&Sha256::digest(bytes));
        Ok(report)
    }
}

pub fn replay_qualified_cache(
    receipt: &QualifiedCompleteReplayReceiptV1,
    root: &Path,
) -> Result<crate::complete_replay::CompleteRunReplayReportV1> {
    validate_qualified_receipt(receipt)?;
    let root = root
        .canonicalize()
        .map_err(|error| format!("resolve cache directory: {error}"))?;
    let manifest = load_cache_manifest(&root, false)?;
    validate_cache_binding(receipt, &manifest)?;
    let mut snapshot_payload = None;
    visit_cache_events(&root, &manifest.snapshot, |event| {
        if event.generation_index != 0 || snapshot_payload.is_some() {
            return Err("cache snapshot cardinality is invalid".to_owned());
        }
        snapshot_payload = Some(event.payload);
        Ok(())
    })?;
    replay_cached_depth(
        receipt,
        &root,
        &manifest,
        &snapshot_payload.ok_or_else(|| "cache contains no snapshot".to_owned())?,
    )?;
    replay_cached_trades(receipt, &root, &manifest)?;
    Ok(receipt.report.clone())
}

#[cfg(test)]
mod tests {
    use super::{
        CacheWriter, CheckpointWriter, QualifiedDepthCheckpointV1, read_checkpoint_records,
        visit_cache_events,
    };
    use crate::{LocalOrderBook, RawFrame, RawRecordEnvelopeV1};
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};

    fn record() -> RawRecordEnvelopeV1 {
        RawRecordEnvelopeV1 {
            schema: "RawRecordEnvelopeV1",
            record_index: 0,
            start_offset: 8,
            end_offset: 100,
            record_sha256: "11".repeat(32),
            frame: RawFrame {
                venue: "binance".to_owned(),
                environment: "production".to_owned(),
                endpoint: "wss://example.invalid".to_owned(),
                symbol: "BTCUSDT".to_owned(),
                stream: "btcusdt@trade".to_owned(),
                connection_epoch: "epoch-1".to_owned(),
                frame_index: 7,
                receive_wall_ns: 10,
                receive_mono_ns: 9,
                payload: br#"{"e":"trade","s":"BTCUSDT","t":1,"E":2,"T":2,"p":"1","q":"1","m":false,"M":true}"#.to_vec(),
                clock_quality: "healthy".to_owned(),
                clock_source: "test".to_owned(),
                clock_offset_ns: Some(0),
                clock_uncertainty_ns: Some(1),
                recorder_state: "DURABLE".to_owned(),
                spec_revision: "test".to_owned(),
            },
        }
    }

    #[test]
    fn cache_round_trip_and_single_byte_corruption_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = CacheWriter::create(directory.path(), "trade").unwrap();
        writer.append(3, 4, &record()).unwrap();
        let artifact = writer.finish().unwrap();
        let mut seen = 0;
        visit_cache_events(directory.path(), &artifact, |event| {
            assert_eq!(event.generation_index, 3);
            assert_eq!(event.segment_index, 4);
            assert_eq!(event.frame_index, 7);
            seen += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, 1);

        let path = directory.path().join(&artifact.data_file);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(120)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(120)).unwrap();
        byte[0] ^= 1;
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        assert!(visit_cache_events(directory.path(), &artifact, |_| Ok(())).is_err());
    }

    #[test]
    fn cache_index_single_byte_corruption_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = CacheWriter::create(directory.path(), "trade").unwrap();
        writer.append(3, 4, &record()).unwrap();
        let artifact = writer.finish().unwrap();
        let path = directory.path().join(&artifact.index_file);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(10)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(10)).unwrap();
        byte[0] ^= 1;
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        assert!(visit_cache_events(directory.path(), &artifact, |_| Ok(())).is_err());
    }

    #[test]
    fn checkpoint_round_trip_and_single_byte_corruption_fail_closed() {
        let mut book = LocalOrderBook::new("BTCUSDT").unwrap();
        book.load_snapshot(
            br#"{"lastUpdateId":99,"bids":[["60000.1","1"]],"asks":[["60000.2","1"]]}"#,
        )
        .unwrap();
        book.apply_depth(br#"{"e":"depthUpdate","s":"BTCUSDT","U":100,"u":100,"b":[],"a":[]}"#)
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut writer = CheckpointWriter::create(directory.path()).unwrap();
        writer
            .append(QualifiedDepthCheckpointV1 {
                schema: "QualifiedDepthCheckpointV1".to_owned(),
                generation_index: 2,
                segment_index: 7,
                last_record_ordinal: 9,
                next_record_ordinal: 10,
                next_data_offset: 1234,
                last_frame_index: 44,
                last_receive_wall_ns: 55,
                last_receive_mono_ns: 54,
                last_raw_record_sha256: "22".repeat(32),
                book: book.checkpoint().unwrap(),
                checkpoint_sha256: String::new(),
            })
            .unwrap();
        let artifact = writer.finish().unwrap();
        let checkpoints = read_checkpoint_records(directory.path(), &artifact).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].segment_index, 7);

        let path = directory.path().join(&artifact.data_file);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(20)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(20)).unwrap();
        byte[0] ^= 1;
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        assert!(read_checkpoint_records(directory.path(), &artifact).is_err());
    }

    #[test]
    fn checkpoint_index_single_byte_corruption_fails_closed() {
        let mut book = LocalOrderBook::new("BTCUSDT").unwrap();
        book.load_snapshot(
            br#"{"lastUpdateId":99,"bids":[["60000.1","1"]],"asks":[["60000.2","1"]]}"#,
        )
        .unwrap();
        book.apply_depth(br#"{"e":"depthUpdate","s":"BTCUSDT","U":100,"u":100,"b":[],"a":[]}"#)
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut writer = CheckpointWriter::create(directory.path()).unwrap();
        writer
            .append(QualifiedDepthCheckpointV1 {
                schema: "QualifiedDepthCheckpointV1".to_owned(),
                generation_index: 0,
                segment_index: 0,
                last_record_ordinal: 0,
                next_record_ordinal: 1,
                next_data_offset: 200,
                last_frame_index: 0,
                last_receive_wall_ns: 2,
                last_receive_mono_ns: 1,
                last_raw_record_sha256: "33".repeat(32),
                book: book.checkpoint().unwrap(),
                checkpoint_sha256: String::new(),
            })
            .unwrap();
        let artifact = writer.finish().unwrap();
        let path = directory.path().join(&artifact.index_file);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(12)).unwrap();
        let mut byte = [0_u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(12)).unwrap();
        byte[0] ^= 1;
        file.write_all(&byte).unwrap();
        file.sync_all().unwrap();
        assert!(read_checkpoint_records(directory.path(), &artifact).is_err());
    }
}
