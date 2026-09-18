use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub mod boundary;
pub mod campaign_artifact;
pub mod canonical_output;
pub mod capture_config;
pub mod complete_replay;
pub mod durability_follower;
pub mod durability_progress;
pub mod generation_artifact;
pub mod generation_handover;
pub mod generation_supervisor;
pub mod handover;
pub mod hot_redundancy;
pub mod hot_redundancy_artifact;
pub mod live_arbitration;
pub mod live_rotation;
pub mod liveness;
pub mod market_replay;
pub mod observations;
pub mod orchestrator;
pub mod ownership;
pub mod qualified_cache;
pub mod segment_chain;
pub mod splice;
pub mod transport;
pub mod transport_journal;
#[cfg(windows)]
pub mod windows_etw;
#[cfg(windows)]
pub mod windows_tcp;
#[cfg(windows)]
pub mod windows_time;

const MAGIC: &[u8; 8] = b"BNRAW\0\x01\n";
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const POW10_18: i128 = 1_000_000_000_000_000_000;
const MAX_SAFE_COEFFICIENT: i128 = i128::MAX / POW10_18;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FixedDecimal {
    coefficient: i128,
    scale: u8,
}

impl FixedDecimal {
    pub fn parse(text: &str) -> Result<Self> {
        if text.is_empty() || text.starts_with('+') || text.contains(['e', 'E']) {
            return Err(format!("invalid plain decimal: {text:?}"));
        }
        let (negative, unsigned) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let mut parts = unsigned.split('.');
        let whole = parts
            .next()
            .ok_or_else(|| "missing whole part".to_owned())?;
        let fraction = parts.next();
        if parts.next().is_some()
            || whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || (whole.len() > 1 && whole.starts_with('0'))
        {
            return Err(format!("invalid plain decimal: {text:?}"));
        }
        let fraction = fraction.unwrap_or("");
        if fraction.len() > 18
            || (text.contains('.') && fraction.is_empty())
            || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(format!("invalid decimal scale: {text:?}"));
        }
        let digits = format!("{whole}{fraction}");
        let mut coefficient = i128::from_str(&digits)
            .map_err(|error| format!("decimal coefficient overflow: {error}"))?;
        if coefficient > MAX_SAFE_COEFFICIENT {
            return Err("decimal outside comparison-safe range".to_owned());
        }
        if negative {
            coefficient = -coefficient;
        }
        Ok(Self {
            coefficient,
            scale: fraction.len() as u8,
        }
        .canonical())
    }

    pub fn canonical(mut self) -> Self {
        while self.scale > 0 && self.coefficient % 10 == 0 {
            self.coefficient /= 10;
            self.scale -= 1;
        }
        self
    }

    pub fn is_zero(self) -> bool {
        self.coefficient == 0
    }

    pub fn is_negative(self) -> bool {
        self.coefficient < 0
    }

    fn aligned(self, other: Self) -> (i128, i128) {
        let scale = self.scale.max(other.scale);
        let left = self.coefficient * 10_i128.pow((scale - self.scale) as u32);
        let right = other.coefficient * 10_i128.pow((scale - other.scale) as u32);
        (left, right)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self> {
        let scale = self.scale.max(other.scale);
        let (left, right) = self.aligned(other);
        let coefficient = left
            .checked_sub(right)
            .ok_or_else(|| "decimal subtraction overflow".to_owned())?;
        Ok(Self { coefficient, scale }.canonical())
    }

    pub fn checked_add(self, other: Self) -> Result<Self> {
        let scale = self.scale.max(other.scale);
        let (left, right) = self.aligned(other);
        let coefficient = left
            .checked_add(right)
            .ok_or_else(|| "decimal addition overflow".to_owned())?;
        Ok(Self { coefficient, scale }.canonical())
    }
}

impl Ord for FixedDecimal {
    fn cmp(&self, other: &Self) -> Ordering {
        let (left, right) = self.aligned(*other);
        left.cmp(&right)
    }
}

impl PartialOrd for FixedDecimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for FixedDecimal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let sign = if self.coefficient < 0 { "-" } else { "" };
        let mut digits = self.coefficient.unsigned_abs().to_string();
        if self.scale == 0 {
            return write!(formatter, "{sign}{digits}");
        }
        let minimum = self.scale as usize + 1;
        if digits.len() < minimum {
            digits = format!("{}{}", "0".repeat(minimum - digits.len()), digits);
        }
        let split = digits.len() - self.scale as usize;
        write!(formatter, "{sign}{}.{}", &digits[..split], &digits[split..])
    }
}

#[derive(Clone, Debug)]
pub struct RawFrame {
    pub venue: String,
    pub environment: String,
    pub endpoint: String,
    pub symbol: String,
    pub stream: String,
    pub connection_epoch: String,
    pub frame_index: u64,
    pub receive_wall_ns: u64,
    pub receive_mono_ns: u64,
    pub payload: Vec<u8>,
    pub clock_quality: String,
    pub clock_source: String,
    pub clock_offset_ns: Option<i64>,
    pub clock_uncertainty_ns: Option<u64>,
    pub recorder_state: String,
    pub spec_revision: String,
}

#[derive(Clone, Debug)]
pub struct RawRecordEnvelopeV1 {
    pub schema: &'static str,
    pub record_index: u64,
    pub start_offset: u64,
    pub end_offset: u64,
    pub record_sha256: String,
    pub frame: RawFrame,
}

#[derive(Clone, Debug)]
pub struct CapturedFrame {
    pub venue: String,
    pub environment: String,
    pub endpoint: String,
    pub stream: String,
    pub symbol: String,
    pub connection_epoch: String,
    pub frame_index: u64,
    pub receive_wall_ns: u64,
    pub receive_mono_ns: u64,
    pub clock_quality: String,
    pub clock_source: String,
    pub payload: Vec<u8>,
    pub spec_revision: String,
}

pub trait DurableSink: Write {
    fn sync_all(&mut self) -> std::io::Result<()>;
}

impl DurableSink for File {
    fn sync_all(&mut self) -> std::io::Result<()> {
        File::sync_all(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamDurabilityWatermarkV1 {
    pub connection_epoch: String,
    pub stream: String,
    pub durable_through_frame_index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DurabilityAckV1 {
    pub schema: String,
    pub durable_record_count: u64,
    pub durable_through_offset: u64,
    pub last_record_sha256: String,
    pub streams: Vec<StreamDurabilityWatermarkV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AppendReceiptV1 {
    pub schema: &'static str,
    pub record_index: u64,
    pub end_offset: u64,
    pub record_sha256: String,
    pub durability_ack: Option<DurabilityAckV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RawLogScanV1 {
    pub schema: &'static str,
    pub path: PathBuf,
    pub file_size: u64,
    pub records: u64,
    pub last_good_offset: u64,
    pub clean_eof: bool,
    pub reason: Option<String>,
    pub last_record_sha256: String,
    pub streams: Vec<StreamDurabilityWatermarkV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RawRecoveryV1 {
    pub schema: &'static str,
    pub source: PathBuf,
    pub destination: PathBuf,
    pub source_file_size: u64,
    pub copied_valid_prefix_bytes: u64,
    pub excluded_tail_bytes: u64,
    pub recovered_records: u64,
    pub last_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawSegmentGenesisV1 {
    pub schema: String,
    pub segment_index: u64,
    pub previous_segment_terminal_sha256: String,
    pub connection_epoch: String,
    pub stream: String,
    pub next_frame_index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawSegmentSealV1 {
    pub schema: String,
    pub segment_index: u64,
    pub raw_file: String,
    pub connection_epoch: String,
    pub stream: String,
    pub first_frame_index: u64,
    pub last_frame_index: u64,
    pub records: u64,
    pub durable_through_offset: u64,
    pub previous_segment_terminal_sha256: String,
    pub terminal_record_sha256: String,
}

pub struct RawLogWriter<S: DurableSink = File> {
    sink: S,
    previous_digest: String,
    expected: HashMap<(String, String), u64>,
    sync_every: u64,
    since_sync: u64,
    record_count: u64,
    end_offset: u64,
    poisoned: bool,
    last_ack: Option<DurabilityAckV1>,
    locked_identity: Option<(String, String)>,
}

#[derive(Serialize)]
struct RawRecord<'a> {
    schema: &'static str,
    venue: &'a str,
    environment: &'a str,
    endpoint: &'a str,
    stream: &'a str,
    symbol: &'a str,
    connection_epoch: &'a str,
    frame_index: u64,
    receive_wall_ns: u64,
    receive_mono_ns: u64,
    clock_quality: &'a str,
    clock_source: &'a str,
    clock_offset_ns: Option<i64>,
    clock_uncertainty_ns: Option<u64>,
    payload_length: usize,
    payload_sha256: String,
    payload_base64: String,
    recorder_state: &'static str,
    spec_revision: &'a str,
    previous_record_sha256: &'a str,
}

impl RawLogWriter<File> {
    pub fn create(path: &Path, sync_every: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create raw parent {}: {error}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create raw log {}: {error}", path.display()))?;
        Self::from_sink(file, sync_every)
    }

    pub fn create_segment(
        path: &Path,
        sync_every: u64,
        genesis: &RawSegmentGenesisV1,
    ) -> Result<Self> {
        validate_segment_genesis(genesis)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create raw parent {}: {error}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("create raw segment {}: {error}", path.display()))?;
        Self::from_sink_segment(file, sync_every, genesis)
    }
}

impl<S: DurableSink> RawLogWriter<S> {
    pub fn from_sink(sink: S, sync_every: u64) -> Result<Self> {
        Self::initialize(sink, sync_every, None)
    }

    pub fn from_sink_segment(
        sink: S,
        sync_every: u64,
        genesis: &RawSegmentGenesisV1,
    ) -> Result<Self> {
        validate_segment_genesis(genesis)?;
        Self::initialize(sink, sync_every, Some(genesis))
    }

    fn initialize(
        mut sink: S,
        sync_every: u64,
        genesis: Option<&RawSegmentGenesisV1>,
    ) -> Result<Self> {
        if sync_every == 0 {
            return Err("sync_every must be positive".to_owned());
        }
        sink.write_all(MAGIC)
            .map_err(|error| format!("write raw magic: {error}"))?;
        sink.sync_all()
            .map_err(|error| format!("sync raw magic: {error}"))?;
        let mut expected = HashMap::new();
        let (previous_digest, locked_identity) = if let Some(genesis) = genesis {
            let identity = (genesis.connection_epoch.clone(), genesis.stream.clone());
            expected.insert(identity.clone(), genesis.next_frame_index);
            (
                genesis.previous_segment_terminal_sha256.clone(),
                Some(identity),
            )
        } else {
            (ZERO_DIGEST.to_owned(), None)
        };
        Ok(Self {
            sink,
            previous_digest,
            expected,
            sync_every,
            since_sync: 0,
            record_count: 0,
            end_offset: MAGIC.len() as u64,
            poisoned: false,
            last_ack: None,
            locked_identity,
        })
    }

    pub fn append(&mut self, frame: &CapturedFrame) -> Result<AppendReceiptV1> {
        if self.poisoned {
            return Err("raw writer is poisoned".to_owned());
        }
        let key = (frame.connection_epoch.clone(), frame.stream.clone());
        if self
            .locked_identity
            .as_ref()
            .is_some_and(|identity| identity != &key)
        {
            return Err("raw segment identity mismatch".to_owned());
        }
        let next = self.expected.get(&key).copied().unwrap_or(0);
        if frame.frame_index != next {
            return Err(format!(
                "non-contiguous captured frame: expected {}, got {}",
                next, frame.frame_index
            ));
        }
        let payload_sha256 = hex(&Sha256::digest(&frame.payload));
        let record = RawRecord {
            schema: "RawFrameV1",
            venue: &frame.venue,
            environment: &frame.environment,
            endpoint: &frame.endpoint,
            stream: &frame.stream,
            symbol: &frame.symbol,
            connection_epoch: &frame.connection_epoch,
            frame_index: frame.frame_index,
            receive_wall_ns: frame.receive_wall_ns,
            receive_mono_ns: frame.receive_mono_ns,
            clock_quality: &frame.clock_quality,
            clock_source: &frame.clock_source,
            clock_offset_ns: None,
            clock_uncertainty_ns: None,
            payload_length: frame.payload.len(),
            payload_sha256,
            payload_base64: BASE64.encode(&frame.payload),
            // A frame cannot prove its own durability. DurabilityAckV1 is
            // emitted only after the containing bytes pass sync_all().
            recorder_state: "PENDING",
            spec_revision: &frame.spec_revision,
            previous_record_sha256: &self.previous_digest,
        };
        let body = serde_json::to_vec(&record)
            .map_err(|error| format!("serialize raw record: {error}"))?;
        if body.len() > MAX_RECORD_BYTES {
            return Err("raw record exceeds maximum size".to_owned());
        }
        let length = u32::try_from(body.len())
            .map_err(|_| "raw record length does not fit u32".to_owned())?;
        let digest = Sha256::digest(&body);
        let mut encoded = Vec::with_capacity(4 + body.len() + digest.len());
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&body);
        encoded.extend_from_slice(&digest);
        if let Err(error) = self.sink.write_all(&encoded) {
            self.poisoned = true;
            return Err(format!("write raw record; writer poisoned: {error}"));
        }
        self.previous_digest = hex(&digest);
        self.expected.insert(key, next + 1);
        let record_index = self.record_count;
        self.record_count += 1;
        self.end_offset = self
            .end_offset
            .checked_add(encoded.len() as u64)
            .ok_or_else(|| "raw offset overflow".to_owned())?;
        self.since_sync += 1;
        let durability_ack = if self.since_sync >= self.sync_every {
            Some(self.sync()?)
        } else {
            None
        };
        Ok(AppendReceiptV1 {
            schema: "AppendReceiptV1",
            record_index,
            end_offset: self.end_offset,
            record_sha256: self.previous_digest.clone(),
            durability_ack,
        })
    }

    pub fn sync(&mut self) -> Result<DurabilityAckV1> {
        if self.poisoned {
            return Err("raw writer is poisoned".to_owned());
        }
        if let Err(error) = self.sink.flush().and_then(|_| self.sink.sync_all()) {
            self.poisoned = true;
            return Err(format!("sync raw log; writer poisoned: {error}"));
        }
        self.since_sync = 0;
        let ack = DurabilityAckV1 {
            schema: "DurabilityAckV1".to_owned(),
            durable_record_count: self.record_count,
            durable_through_offset: self.end_offset,
            last_record_sha256: self.previous_digest.clone(),
            streams: durability_watermarks(&self.expected),
        };
        self.last_ack = Some(ack.clone());
        Ok(ack)
    }

    pub fn last_durability_ack(&self) -> Option<&DurabilityAckV1> {
        self.last_ack.as_ref()
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

impl<S: DurableSink> Drop for RawLogWriter<S> {
    fn drop(&mut self) {
        if !self.poisoned && self.since_sync > 0 {
            let _ = self.sync();
        }
    }
}

fn durability_watermarks(
    expected: &HashMap<(String, String), u64>,
) -> Vec<StreamDurabilityWatermarkV1> {
    let mut streams = expected
        .iter()
        .filter_map(|((connection_epoch, stream), next)| {
            next.checked_sub(1)
                .map(|durable_through_frame_index| StreamDurabilityWatermarkV1 {
                    connection_epoch: connection_epoch.clone(),
                    stream: stream.clone(),
                    durable_through_frame_index,
                })
        })
        .collect::<Vec<_>>();
    streams.sort_by(|left, right| {
        (&left.connection_epoch, &left.stream).cmp(&(&right.connection_epoch, &right.stream))
    });
    streams
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{field} must be a lowercase SHA-256 hex digest"));
    }
    Ok(())
}

fn validate_segment_genesis(genesis: &RawSegmentGenesisV1) -> Result<()> {
    if genesis.schema != "RawSegmentGenesisV1"
        || genesis.connection_epoch.trim().is_empty()
        || genesis.stream.trim().is_empty()
    {
        return Err("invalid raw segment genesis".to_owned());
    }
    validate_sha256(
        &genesis.previous_segment_terminal_sha256,
        "previous_segment_terminal_sha256",
    )?;
    let is_root = genesis.segment_index == 0
        && genesis.previous_segment_terminal_sha256 == ZERO_DIGEST
        && genesis.next_frame_index == 0;
    let is_successor = genesis.segment_index > 0
        && genesis.previous_segment_terminal_sha256 != ZERO_DIGEST
        && genesis.next_frame_index > 0;
    if !is_root && !is_successor {
        return Err("raw segment genesis is neither a root nor a successor".to_owned());
    }
    Ok(())
}

pub fn seal_raw_segment(
    genesis: &RawSegmentGenesisV1,
    raw_file: &str,
    ack: &DurabilityAckV1,
) -> Result<RawSegmentSealV1> {
    validate_segment_genesis(genesis)?;
    if raw_file.trim().is_empty()
        || ack.schema != "DurabilityAckV1"
        || ack.durable_record_count == 0
        || ack.streams.len() != 1
    {
        return Err("invalid raw segment seal input".to_owned());
    }
    validate_sha256(&ack.last_record_sha256, "last_record_sha256")?;
    let watermark = &ack.streams[0];
    if watermark.connection_epoch != genesis.connection_epoch
        || watermark.stream != genesis.stream
        || watermark.durable_through_frame_index < genesis.next_frame_index
    {
        return Err("raw segment seal identity or frame range mismatch".to_owned());
    }
    let expected_records = watermark
        .durable_through_frame_index
        .checked_sub(genesis.next_frame_index)
        .and_then(|distance| distance.checked_add(1))
        .ok_or_else(|| "raw segment record range overflow".to_owned())?;
    if ack.durable_record_count != expected_records {
        return Err("raw segment ACK count does not match frame range".to_owned());
    }
    Ok(RawSegmentSealV1 {
        schema: "RawSegmentSealV1".to_owned(),
        segment_index: genesis.segment_index,
        raw_file: raw_file.to_owned(),
        connection_epoch: genesis.connection_epoch.clone(),
        stream: genesis.stream.clone(),
        first_frame_index: genesis.next_frame_index,
        last_frame_index: watermark.durable_through_frame_index,
        records: ack.durable_record_count,
        durable_through_offset: ack.durable_through_offset,
        previous_segment_terminal_sha256: genesis.previous_segment_terminal_sha256.clone(),
        terminal_record_sha256: ack.last_record_sha256.clone(),
    })
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("missing/invalid string field {field}"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("missing/invalid integer field {field}"))
}

fn read_next_raw_record<R: Read>(
    reader: &mut R,
    previous: &str,
    expected: &mut HashMap<(String, String), u64>,
) -> Result<Option<(RawFrame, String, u64)>> {
    let mut prefix = [0_u8; 4];
    let first = reader
        .read(&mut prefix[..1])
        .map_err(|error| format!("read record prefix: {error}"))?;
    if first == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut prefix[1..])
        .map_err(|_| "partial length prefix".to_owned())?;
    let body_length = u32::from_be_bytes(prefix) as usize;
    if body_length > MAX_RECORD_BYTES {
        return Err("record length exceeds limit".to_owned());
    }
    let mut body = vec![0_u8; body_length];
    reader
        .read_exact(&mut body)
        .map_err(|_| "partial record body".to_owned())?;
    let mut digest = [0_u8; 32];
    reader
        .read_exact(&mut digest)
        .map_err(|_| "partial record digest".to_owned())?;
    let actual: [u8; 32] = Sha256::digest(&body).into();
    if actual != digest {
        return Err("record digest mismatch".to_owned());
    }
    let value: Value =
        serde_json::from_slice(&body).map_err(|error| format!("invalid record JSON: {error}"))?;
    if required_str(&value, "schema")? != "RawFrameV1" {
        return Err("unknown raw schema".to_owned());
    }
    if required_str(&value, "previous_record_sha256")? != previous {
        return Err("record chain mismatch".to_owned());
    }
    if !matches!(
        required_str(&value, "recorder_state")?,
        "PENDING" | "DURABLE" | "FAILED"
    ) {
        return Err("invalid recorder state".to_owned());
    }
    let payload = BASE64
        .decode(required_str(&value, "payload_base64")?)
        .map_err(|error| format!("invalid payload base64: {error}"))?;
    if payload.len() as u64 != required_u64(&value, "payload_length")? {
        return Err("payload length mismatch".to_owned());
    }
    let payload_digest = hex(&Sha256::digest(&payload));
    if payload_digest != required_str(&value, "payload_sha256")? {
        return Err("payload digest mismatch".to_owned());
    }
    let stream = required_str(&value, "stream")?.to_owned();
    let connection_epoch = required_str(&value, "connection_epoch")?.to_owned();
    let frame_index = required_u64(&value, "frame_index")?;
    let key = (connection_epoch.clone(), stream.clone());
    let next = expected.entry(key).or_insert(0);
    if frame_index != *next {
        return Err(format!(
            "non-contiguous frame index: expected {}, got {frame_index}",
            *next
        ));
    }
    *next += 1;
    let record_digest = hex(&digest);
    Ok(Some((
        RawFrame {
            venue: required_str(&value, "venue")?.to_owned(),
            environment: required_str(&value, "environment")?.to_owned(),
            endpoint: required_str(&value, "endpoint")?.to_owned(),
            symbol: required_str(&value, "symbol")?.to_owned(),
            stream,
            connection_epoch,
            frame_index,
            receive_wall_ns: required_u64(&value, "receive_wall_ns")?,
            receive_mono_ns: required_u64(&value, "receive_mono_ns")?,
            payload,
            clock_quality: required_str(&value, "clock_quality")?.to_owned(),
            clock_source: required_str(&value, "clock_source")?.to_owned(),
            clock_offset_ns: value["clock_offset_ns"].as_i64(),
            clock_uncertainty_ns: value["clock_uncertainty_ns"].as_u64(),
            recorder_state: required_str(&value, "recorder_state")?.to_owned(),
            spec_revision: required_str(&value, "spec_revision")?.to_owned(),
        },
        record_digest,
        (4 + body_length + 32) as u64,
    )))
}

fn read_magic<R: Read>(reader: &mut R) -> Result<()> {
    let mut magic = [0_u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|_| "bad raw log magic".to_owned())?;
    if &magic != MAGIC {
        return Err("bad raw log magic".to_owned());
    }
    Ok(())
}

pub fn read_raw_log(path: &Path) -> Result<Vec<RawFrame>> {
    Ok(read_raw_records(path)?
        .into_iter()
        .map(|record| record.frame)
        .collect())
}

pub fn read_raw_records(path: &Path) -> Result<Vec<RawRecordEnvelopeV1>> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    read_magic(&mut reader)?;
    read_raw_records_after_magic(&mut reader, MAGIC.len() as u64, ZERO_DIGEST, HashMap::new())
}

pub fn read_raw_segment_records(
    path: &Path,
    genesis: &RawSegmentGenesisV1,
) -> Result<Vec<RawRecordEnvelopeV1>> {
    validate_segment_genesis(genesis)?;
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    read_magic(&mut reader)?;
    let identity = (genesis.connection_epoch.clone(), genesis.stream.clone());
    let mut expected = HashMap::new();
    expected.insert(identity.clone(), genesis.next_frame_index);
    let records = read_raw_records_after_magic(
        &mut reader,
        MAGIC.len() as u64,
        &genesis.previous_segment_terminal_sha256,
        expected,
    )?;
    if records.iter().any(|record| {
        (
            record.frame.connection_epoch.as_str(),
            record.frame.stream.as_str(),
        ) != (identity.0.as_str(), identity.1.as_str())
    }) {
        return Err("raw segment identity mismatch".to_owned());
    }
    Ok(records)
}

fn read_raw_records_after_magic<R: Read>(
    reader: &mut R,
    mut start_offset: u64,
    initial_previous: &str,
    mut expected: HashMap<(String, String), u64>,
) -> Result<Vec<RawRecordEnvelopeV1>> {
    let mut records = Vec::new();
    let mut previous = initial_previous.to_owned();
    while let Some((frame, digest, encoded_length)) =
        read_next_raw_record(reader, &previous, &mut expected)?
    {
        let end_offset = start_offset
            .checked_add(encoded_length)
            .ok_or_else(|| "raw record offset overflow".to_owned())?;
        records.push(RawRecordEnvelopeV1 {
            schema: "RawRecordEnvelopeV1",
            record_index: records.len() as u64,
            start_offset,
            end_offset,
            record_sha256: digest.clone(),
            frame,
        });
        previous = digest;
        start_offset = end_offset;
    }
    Ok(records)
}

pub fn read_raw_records_through_offset(
    path: &Path,
    durable_through_offset: u64,
) -> Result<Vec<RawRecordEnvelopeV1>> {
    if durable_through_offset < MAGIC.len() as u64 {
        return Err("raw prefix ends before magic".to_owned());
    }
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_size = file
        .metadata()
        .map_err(|error| format!("metadata {}: {error}", path.display()))?
        .len();
    if file_size < durable_through_offset {
        return Err("raw file is shorter than requested durable prefix".to_owned());
    }
    let mut reader = BufReader::new(file.take(durable_through_offset));
    read_magic(&mut reader)?;
    let records =
        read_raw_records_after_magic(&mut reader, MAGIC.len() as u64, ZERO_DIGEST, HashMap::new())?;
    let end = records
        .last()
        .map(|record| record.end_offset)
        .unwrap_or(MAGIC.len() as u64);
    if end != durable_through_offset {
        return Err("requested durable prefix does not end on a record boundary".to_owned());
    }
    Ok(records)
}

/// Incremental durable-prefix reader for live followers (ADR-16): continues
/// an already-verified hash chain inside one raw segment from `start_offset`
/// up to `end_offset`, both of which must sit on record boundaries.  Used by
/// the live arbitration sidecar to consume only new BNACK-authorized bytes
/// without re-reading a segment from byte zero on every poll.
pub fn read_raw_record_range(
    path: &Path,
    start_offset: u64,
    end_offset: u64,
    previous_record_sha256: &str,
    connection_epoch: &str,
    stream: &str,
    next_frame_index: u64,
) -> Result<Vec<RawRecordEnvelopeV1>> {
    if start_offset < MAGIC.len() as u64 || end_offset <= start_offset {
        return Err("invalid raw record range".to_owned());
    }
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_size = file
        .metadata()
        .map_err(|error| format!("metadata {}: {error}", path.display()))?
        .len();
    if file_size < end_offset {
        return Err("raw file is shorter than requested record range".to_owned());
    }
    file.seek(SeekFrom::Start(start_offset))
        .map_err(|error| format!("seek raw record range: {error}"))?;
    let mut expected = HashMap::new();
    expected.insert(
        (connection_epoch.to_owned(), stream.to_owned()),
        next_frame_index,
    );
    let mut reader = BufReader::new(file.take(end_offset - start_offset));
    let records =
        read_raw_records_after_magic(&mut reader, start_offset, previous_record_sha256, expected)?;
    if records.last().map(|record| record.end_offset) != Some(end_offset) {
        return Err("raw record range does not end on the requested boundary".to_owned());
    }
    Ok(records)
}

pub fn scan_raw_log(path: &Path) -> Result<RawLogScanV1> {
    scan_raw_log_from(path, ZERO_DIGEST, HashMap::new(), None)
}

pub fn scan_raw_segment(path: &Path, genesis: &RawSegmentGenesisV1) -> Result<RawLogScanV1> {
    validate_segment_genesis(genesis)?;
    let identity = (genesis.connection_epoch.clone(), genesis.stream.clone());
    let mut expected = HashMap::new();
    expected.insert(identity.clone(), genesis.next_frame_index);
    scan_raw_log_from(
        path,
        &genesis.previous_segment_terminal_sha256,
        expected,
        Some(identity),
    )
}

fn scan_raw_log_from(
    path: &Path,
    initial_previous: &str,
    mut expected: HashMap<(String, String), u64>,
    locked_identity: Option<(String, String)>,
) -> Result<RawLogScanV1> {
    let file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_size = file
        .metadata()
        .map_err(|error| format!("metadata {}: {error}", path.display()))?
        .len();
    let mut reader = BufReader::new(file);
    if read_magic(&mut reader).is_err() {
        return Ok(RawLogScanV1 {
            schema: "RawLogScanV1",
            path: path.to_path_buf(),
            file_size,
            records: 0,
            last_good_offset: 0,
            clean_eof: false,
            reason: Some("bad raw log magic".to_owned()),
            last_record_sha256: initial_previous.to_owned(),
            streams: Vec::new(),
        });
    }
    let mut previous = initial_previous.to_owned();
    let mut records = 0_u64;
    let mut last_good_offset = MAGIC.len() as u64;
    let mut reason = None;
    loop {
        match read_next_raw_record(&mut reader, &previous, &mut expected) {
            Ok(Some((frame, digest, encoded_length))) => {
                if locked_identity.as_ref().is_some_and(|identity| {
                    (frame.connection_epoch.as_str(), frame.stream.as_str())
                        != (identity.0.as_str(), identity.1.as_str())
                }) {
                    reason = Some("raw segment identity mismatch".to_owned());
                    break;
                }
                records += 1;
                last_good_offset = last_good_offset
                    .checked_add(encoded_length)
                    .ok_or_else(|| "raw scan offset overflow".to_owned())?;
                previous = digest;
            }
            Ok(None) => break,
            Err(error) => {
                reason = Some(error);
                break;
            }
        }
    }
    Ok(RawLogScanV1 {
        schema: "RawLogScanV1",
        path: path.to_path_buf(),
        file_size,
        records,
        last_good_offset,
        clean_eof: reason.is_none(),
        reason,
        last_record_sha256: previous,
        streams: durability_watermarks(&expected),
    })
}

pub fn recover_raw_log_prefix(source: &Path, destination: &Path) -> Result<RawRecoveryV1> {
    let source_scan = scan_raw_log(source)?;
    if source_scan.clean_eof {
        return Err("source raw log already has a clean EOF".to_owned());
    }
    if source_scan.last_good_offset < MAGIC.len() as u64 {
        return Err("source has no recoverable BNRAW prefix".to_owned());
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create recovery parent {}: {error}", parent.display()))?;
    }
    let mut input = File::open(source)
        .map_err(|error| format!("open recovery source {}: {error}", source.display()))?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|error| format!("create recovery output {}: {error}", destination.display()))?;
    let copied = std::io::copy(
        &mut Read::by_ref(&mut input).take(source_scan.last_good_offset),
        &mut output,
    )
    .map_err(|error| format!("copy recoverable raw prefix: {error}"))?;
    if copied != source_scan.last_good_offset {
        return Err(format!(
            "short recovery copy: expected {}, copied {copied}",
            source_scan.last_good_offset
        ));
    }
    output
        .flush()
        .and_then(|_| output.sync_all())
        .map_err(|error| format!("sync recovered raw log: {error}"))?;
    let recovered_scan = scan_raw_log(destination)?;
    if !recovered_scan.clean_eof
        || recovered_scan.records != source_scan.records
        || recovered_scan.last_record_sha256 != source_scan.last_record_sha256
    {
        return Err("recovered raw prefix failed verification".to_owned());
    }
    Ok(RawRecoveryV1 {
        schema: "RawRecoveryV1",
        source: source.to_path_buf(),
        destination: destination.to_path_buf(),
        source_file_size: source_scan.file_size,
        copied_valid_prefix_bytes: copied,
        excluded_tail_bytes: source_scan.file_size - copied,
        recovered_records: recovered_scan.records,
        last_record_sha256: recovered_scan.last_record_sha256,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BookState {
    Empty,
    Syncing,
    Live,
    Gap,
    Invalid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrderBookCheckpointV1 {
    pub schema: String,
    pub symbol: String,
    pub last_update_id: u64,
    pub bids: Vec<[String; 2]>,
    pub asks: Vec<[String; 2]>,
    pub state_sha256: String,
}

#[derive(Clone)]
pub struct LocalOrderBook {
    symbol: String,
    state: BookState,
    last_update_id: Option<u64>,
    bids: BTreeMap<FixedDecimal, FixedDecimal>,
    asks: BTreeMap<FixedDecimal, FixedDecimal>,
    level_fingerprint: [u64; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApplyOutcome {
    Applied,
    Old,
}

#[derive(Clone)]
pub(crate) enum PreparedDepthUpdate {
    Old {
        first_id: u64,
        final_id: u64,
    },
    Apply {
        first_id: u64,
        final_id: u64,
        bids: Vec<(FixedDecimal, FixedDecimal)>,
        asks: Vec<(FixedDecimal, FixedDecimal)>,
    },
}

fn parse_level(value: &Value, side: &str) -> Result<(FixedDecimal, FixedDecimal)> {
    let level = value
        .as_array()
        .filter(|items| items.len() == 2)
        .ok_or_else(|| format!("invalid {side} level"))?;
    let price = FixedDecimal::parse(
        level[0]
            .as_str()
            .ok_or_else(|| format!("invalid {side} price"))?,
    )?;
    let quantity = FixedDecimal::parse(
        level[1]
            .as_str()
            .ok_or_else(|| format!("invalid {side} quantity"))?,
    )?;
    if price.is_zero() || price.is_negative() || quantity.is_negative() {
        return Err(format!("invalid {side} price/quantity"));
    }
    Ok((price, quantity))
}

impl LocalOrderBook {
    pub fn new(symbol: &str) -> Result<Self> {
        if !matches!(symbol, "BTCUSDT" | "ETHUSDT") {
            return Err(format!("symbol outside scope: {symbol}"));
        }
        Ok(Self {
            symbol: symbol.to_owned(),
            state: BookState::Empty,
            last_update_id: None,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            level_fingerprint: [0; 4],
        })
    }

    pub fn load_snapshot(&mut self, payload: &[u8]) -> Result<u64> {
        if self.state != BookState::Empty {
            return Err("snapshot requires empty book".to_owned());
        }
        let value: Value = serde_json::from_slice(payload)
            .map_err(|error| format!("invalid snapshot JSON: {error}"))?;
        let update_id = required_u64(&value, "lastUpdateId")?;
        self.bids = Self::load_side(&value["bids"], "bid")?;
        self.asks = Self::load_side(&value["asks"], "ask")?;
        self.level_fingerprint = [0; 4];
        for (price, quantity) in &self.bids {
            Self::xor_level_fingerprint(
                &mut self.level_fingerprint,
                Self::level_fingerprint(b'b', *price, *quantity),
            );
        }
        for (price, quantity) in &self.asks {
            Self::xor_level_fingerprint(
                &mut self.level_fingerprint,
                Self::level_fingerprint(b'a', *price, *quantity),
            );
        }
        self.last_update_id = Some(update_id);
        self.state = BookState::Syncing;
        self.check_invariants()?;
        Ok(update_id)
    }

    fn load_side(value: &Value, side: &str) -> Result<BTreeMap<FixedDecimal, FixedDecimal>> {
        let levels = value
            .as_array()
            .ok_or_else(|| format!("snapshot {side} side is not array"))?;
        let mut result = BTreeMap::new();
        for value in levels {
            let (price, quantity) = parse_level(value, side)?;
            if quantity.is_zero() {
                continue;
            }
            if result.insert(price, quantity).is_some() {
                return Err(format!("duplicate {side} price"));
            }
        }
        if result.is_empty() {
            return Err(format!("empty {side} side"));
        }
        Ok(result)
    }

    pub(crate) fn checkpoint(&self) -> Result<OrderBookCheckpointV1> {
        if self.state != BookState::Live {
            return Err("checkpoint requires a live book".to_owned());
        }
        Ok(OrderBookCheckpointV1 {
            schema: "OrderBookCheckpointV1".to_owned(),
            symbol: self.symbol.clone(),
            last_update_id: self
                .last_update_id
                .ok_or_else(|| "checkpoint book has no update ID".to_owned())?,
            bids: self
                .bids
                .iter()
                .rev()
                .map(|(price, quantity)| [price.to_string(), quantity.to_string()])
                .collect(),
            asks: self
                .asks
                .iter()
                .map(|(price, quantity)| [price.to_string(), quantity.to_string()])
                .collect(),
            state_sha256: self.state_digest(),
        })
    }

    pub(crate) fn from_checkpoint(checkpoint: &OrderBookCheckpointV1) -> Result<Self> {
        if checkpoint.schema != "OrderBookCheckpointV1"
            || checkpoint.state_sha256.len() != 64
            || !checkpoint
                .state_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("book checkpoint identity is invalid".to_owned());
        }
        let mut book = Self::new(&checkpoint.symbol)?;
        book.bids = Self::checkpoint_side(&checkpoint.bids, "bid", true)?;
        book.asks = Self::checkpoint_side(&checkpoint.asks, "ask", false)?;
        book.last_update_id = Some(checkpoint.last_update_id);
        book.state = BookState::Live;
        for (price, quantity) in &book.bids {
            Self::xor_level_fingerprint(
                &mut book.level_fingerprint,
                Self::level_fingerprint(b'b', *price, *quantity),
            );
        }
        for (price, quantity) in &book.asks {
            Self::xor_level_fingerprint(
                &mut book.level_fingerprint,
                Self::level_fingerprint(b'a', *price, *quantity),
            );
        }
        book.check_invariants()?;
        if book.state_digest() != checkpoint.state_sha256 {
            return Err("book checkpoint state digest is invalid".to_owned());
        }
        Ok(book)
    }

    fn checkpoint_side(
        levels: &[[String; 2]],
        side: &str,
        descending: bool,
    ) -> Result<BTreeMap<FixedDecimal, FixedDecimal>> {
        if levels.is_empty() {
            return Err(format!("book checkpoint has empty {side} side"));
        }
        let mut result = BTreeMap::new();
        let mut previous = None;
        for level in levels {
            let price = FixedDecimal::parse(&level[0])?;
            let quantity = FixedDecimal::parse(&level[1])?;
            if price.is_zero()
                || price.is_negative()
                || quantity.is_zero()
                || quantity.is_negative()
            {
                return Err(format!("invalid checkpoint {side} price/quantity"));
            }
            if previous.is_some_and(|old| {
                if descending {
                    old <= price
                } else {
                    old >= price
                }
            }) {
                return Err(format!(
                    "checkpoint {side} levels are not canonically ordered"
                ));
            }
            if result.insert(price, quantity).is_some() {
                return Err(format!("duplicate checkpoint {side} price"));
            }
            previous = Some(price);
        }
        Ok(result)
    }

    pub(crate) fn apply_depth(&mut self, payload: &[u8]) -> Result<ApplyOutcome> {
        let value: Value = serde_json::from_slice(payload)
            .map_err(|error| format!("invalid depth JSON: {error}"))?;
        self.apply_depth_value(&value)
    }

    pub(crate) fn apply_depth_value(&mut self, value: &Value) -> Result<ApplyOutcome> {
        let prepared = self.prepare_depth_value(value)?;
        self.apply_prepared_depth(&prepared)
    }

    pub(crate) fn prepare_depth_value(&mut self, value: &Value) -> Result<PreparedDepthUpdate> {
        if !matches!(self.state, BookState::Syncing | BookState::Live) {
            return Err("book cannot accept depth in current state".to_owned());
        }
        if required_str(value, "e")? != "depthUpdate" || required_str(value, "s")? != self.symbol {
            return Err("unexpected depth type/symbol".to_owned());
        }
        let first_id = required_u64(value, "U")?;
        let final_id = required_u64(value, "u")?;
        if first_id > final_id {
            return Err("invalid depth IDs".to_owned());
        }
        let expected = self
            .last_update_id
            .ok_or_else(|| "snapshot not loaded".to_owned())?
            .checked_add(1)
            .ok_or_else(|| "update ID overflow".to_owned())?;
        if final_id < expected {
            return Ok(PreparedDepthUpdate::Old { first_id, final_id });
        }
        if first_id > expected || final_id < expected {
            self.state = BookState::Gap;
            return Err(format!(
                "depth gap: expected bridge {expected}, received U={first_id}, u={final_id}"
            ));
        }
        let bids = value["b"]
            .as_array()
            .ok_or_else(|| "depth bids not array".to_owned())?;
        let asks = value["a"]
            .as_array()
            .ok_or_else(|| "depth asks not array".to_owned())?;
        let bid_updates = bids
            .iter()
            .map(|level| parse_level(level, "bid"))
            .collect::<Result<Vec<_>>>()?;
        let ask_updates = asks
            .iter()
            .map(|level| parse_level(level, "ask"))
            .collect::<Result<Vec<_>>>()?;
        Ok(PreparedDepthUpdate::Apply {
            first_id,
            final_id,
            bids: bid_updates,
            asks: ask_updates,
        })
    }

    pub(crate) fn apply_prepared_depth(
        &mut self,
        update: &PreparedDepthUpdate,
    ) -> Result<ApplyOutcome> {
        if !matches!(self.state, BookState::Syncing | BookState::Live) {
            return Err("book cannot accept prepared depth in current state".to_owned());
        }
        let expected = self
            .last_update_id
            .ok_or_else(|| "snapshot not loaded".to_owned())?
            .checked_add(1)
            .ok_or_else(|| "update ID overflow".to_owned())?;
        match update {
            PreparedDepthUpdate::Old { first_id, final_id } => {
                if first_id > final_id || *final_id >= expected {
                    self.state = BookState::Gap;
                    return Err("prepared old depth no longer matches book position".to_owned());
                }
                Ok(ApplyOutcome::Old)
            }
            PreparedDepthUpdate::Apply {
                first_id,
                final_id,
                bids,
                asks,
            } => {
                if first_id > final_id || *first_id > expected || *final_id < expected {
                    self.state = BookState::Gap;
                    return Err("prepared depth does not bridge book position".to_owned());
                }
                Self::apply_side(&mut self.bids, bids, b'b', &mut self.level_fingerprint);
                Self::apply_side(&mut self.asks, asks, b'a', &mut self.level_fingerprint);
                self.last_update_id = Some(*final_id);
                if self.state == BookState::Syncing {
                    self.state = BookState::Live;
                }
                self.check_invariants()?;
                Ok(ApplyOutcome::Applied)
            }
        }
    }

    fn apply_side(
        side: &mut BTreeMap<FixedDecimal, FixedDecimal>,
        updates: &[(FixedDecimal, FixedDecimal)],
        side_tag: u8,
        fingerprint: &mut [u64; 4],
    ) {
        for &(price, quantity) in updates {
            if let Some(old_quantity) = side.get(&price).copied() {
                Self::xor_level_fingerprint(
                    fingerprint,
                    Self::level_fingerprint(side_tag, price, old_quantity),
                );
            }
            if quantity.is_zero() {
                side.remove(&price);
            } else {
                side.insert(price, quantity);
                Self::xor_level_fingerprint(
                    fingerprint,
                    Self::level_fingerprint(side_tag, price, quantity),
                );
            }
        }
    }

    fn level_fingerprint(side_tag: u8, price: FixedDecimal, quantity: FixedDecimal) -> [u64; 4] {
        let mut digest = Sha256::new();
        digest.update([side_tag]);
        digest.update(price.coefficient.to_le_bytes());
        digest.update([price.scale]);
        digest.update(quantity.coefficient.to_le_bytes());
        digest.update([quantity.scale]);
        let bytes = digest.finalize();
        let mut result = [0_u64; 4];
        for (index, value) in result.iter_mut().enumerate() {
            let start = index * 8;
            *value = u64::from_le_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .expect("SHA-256 digest chunk has eight bytes"),
            );
        }
        result
    }

    fn xor_level_fingerprint(target: &mut [u64; 4], value: [u64; 4]) {
        for (target, value) in target.iter_mut().zip(value) {
            *target ^= value;
        }
    }

    fn best_bid(&self) -> Result<FixedDecimal> {
        self.bids
            .last_key_value()
            .map(|(price, _)| *price)
            .ok_or_else(|| "empty bid side".to_owned())
    }

    fn best_ask(&self) -> Result<FixedDecimal> {
        self.asks
            .first_key_value()
            .map(|(price, _)| *price)
            .ok_or_else(|| "empty ask side".to_owned())
    }

    fn check_invariants(&mut self) -> Result<()> {
        let bid = self.best_bid()?;
        let ask = self.best_ask()?;
        if bid >= ask {
            self.state = BookState::Invalid;
            return Err(format!("crossed/locked book: bid={bid}, ask={ask}"));
        }
        Ok(())
    }

    pub fn state_digest(&self) -> String {
        let mut canonical = String::from("{\"asks\":[");
        for (index, (price, quantity)) in self.asks.iter().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            canonical.push_str(&format!("[\"{price}\",\"{quantity}\"]"));
        }
        canonical.push_str("],\"bids\":[");
        for (index, (price, quantity)) in self.bids.iter().rev().enumerate() {
            if index > 0 {
                canonical.push(',');
            }
            canonical.push_str(&format!("[\"{price}\",\"{quantity}\"]"));
        }
        canonical.push_str(&format!(
            "],\"last_update_id\":{},\"symbol\":\"{}\"}}",
            self.last_update_id.unwrap_or_default(),
            self.symbol
        ));
        hex(&Sha256::digest(canonical.as_bytes()))
    }

    pub(crate) fn same_state(&self, other: &Self) -> bool {
        self.symbol == other.symbol
            && self.state == other.state
            && self.last_update_id == other.last_update_id
            && self.bids == other.bids
            && self.asks == other.asks
    }

    pub(crate) fn same_state_fingerprint(&self, other: &Self) -> bool {
        self.last_update_id == other.last_update_id
            && self.bids.len() == other.bids.len()
            && self.asks.len() == other.asks.len()
            && self.level_fingerprint == other.level_fingerprint
    }

    pub(crate) fn is_live(&self) -> bool {
        self.state == BookState::Live
    }

    pub(crate) fn last_update_id(&self) -> Option<u64> {
        self.last_update_id
    }

    pub(crate) fn level_counts(&self) -> (usize, usize) {
        (self.bids.len(), self.asks.len())
    }
}

#[derive(Debug, Serialize)]
pub struct ReplayResult {
    pub symbol: String,
    pub state: &'static str,
    pub snapshot_last_update_id: u64,
    pub final_update_id: u64,
    pub depth_records: usize,
    pub applied_records: usize,
    pub old_records: usize,
    pub first_applied_frame_index: u64,
    pub bid_levels: usize,
    pub ask_levels: usize,
    pub best_bid: String,
    pub best_ask: String,
    pub spread: String,
    pub state_sha256: String,
}

pub fn replay_session(session: &Path) -> Result<ReplayResult> {
    let snapshots = read_raw_log(&session.join("snapshot.bnraw"))?;
    if snapshots.len() != 1 {
        return Err("session must contain exactly one snapshot".to_owned());
    }
    let depth = read_raw_log(&session.join("depth.bnraw"))?;
    let mut book = LocalOrderBook::new(&snapshots[0].symbol)?;
    let snapshot_id = book.load_snapshot(&snapshots[0].payload)?;
    let mut applied = 0_usize;
    let mut old = 0_usize;
    let mut first_applied = None;
    for frame in &depth {
        match book.apply_depth(&frame.payload)? {
            ApplyOutcome::Old => old += 1,
            ApplyOutcome::Applied => {
                first_applied.get_or_insert(frame.frame_index);
                applied += 1;
            }
        }
    }
    if book.state != BookState::Live {
        return Err("replay did not reach LIVE".to_owned());
    }
    let best_bid = book.best_bid()?;
    let best_ask = book.best_ask()?;
    Ok(ReplayResult {
        symbol: book.symbol.clone(),
        state: "LIVE",
        snapshot_last_update_id: snapshot_id,
        final_update_id: book
            .last_update_id
            .ok_or_else(|| "missing final ID".to_owned())?,
        depth_records: depth.len(),
        applied_records: applied,
        old_records: old,
        first_applied_frame_index: first_applied.ok_or_else(|| "no applied frame".to_owned())?,
        bid_levels: book.bids.len(),
        ask_levels: book.asks.len(),
        best_bid: best_bid.to_string(),
        best_ask: best_ask.to_string(),
        spread: best_ask.checked_sub(best_bid)?.to_string(),
        state_sha256: book.state_digest(),
    })
}

const PPM_SCALE: i128 = 1_000_000;

fn sum_decimals(mut values: impl Iterator<Item = FixedDecimal>) -> Result<FixedDecimal> {
    values.try_fold(
        FixedDecimal {
            coefficient: 0,
            scale: 0,
        },
        FixedDecimal::checked_add,
    )
}

fn ratio_ppm(numerator: FixedDecimal, denominator: FixedDecimal) -> Result<i64> {
    if denominator.coefficient <= 0 {
        return Err("ratio denominator must be positive".to_owned());
    }
    let scale = numerator.scale.max(denominator.scale);
    let numerator = numerator
        .coefficient
        .checked_mul(10_i128.pow((scale - numerator.scale) as u32))
        .and_then(|value| value.checked_mul(PPM_SCALE))
        .ok_or_else(|| "ppm numerator overflow".to_owned())?;
    let denominator = denominator.coefficient * 10_i128.pow((scale - denominator.scale) as u32);
    i64::try_from(numerator / denominator).map_err(|_| "ppm result outside i64".to_owned())
}

fn imbalance_ppm(left: FixedDecimal, right: FixedDecimal) -> Result<i64> {
    ratio_ppm(left.checked_sub(right)?, left.checked_add(right)?)
}

fn clock_permits_one_way(frame: &RawFrame) -> bool {
    frame.clock_quality == "SYNCHRONIZED"
        && frame.clock_offset_ns.is_some()
        && frame.clock_uncertainty_ns.is_some()
}

fn add_clock(
    frame: &RawFrame,
    qualities: &mut BTreeSet<String>,
    sources: &mut BTreeSet<String>,
    permits_event_age: &mut bool,
) {
    qualities.insert(frame.clock_quality.clone());
    sources.insert(frame.clock_source.clone());
    *permits_event_age &= clock_permits_one_way(frame);
}

fn trade_identity_report(frames: &[RawFrame], expected_symbol: &str) -> Result<Value> {
    if frames.is_empty() {
        return Err("trade log is empty".to_owned());
    }
    let mut first_id = None;
    let mut previous_id = None;
    let mut missing_ids = 0_u64;
    let mut duplicate_ids = 0_u64;
    let mut out_of_order_ids = 0_u64;
    for frame in frames {
        let value: Value = serde_json::from_slice(&frame.payload)
            .map_err(|error| format!("invalid trade JSON: {error}"))?;
        if required_str(&value, "e")? != "trade"
            || required_str(&value, "s")? != expected_symbol
            || frame.symbol != expected_symbol
        {
            return Err("unexpected trade type/symbol".to_owned());
        }
        let trade_id = required_u64(&value, "t")?;
        first_id.get_or_insert(trade_id);
        if let Some(previous) = previous_id {
            if trade_id == previous {
                duplicate_ids += 1;
            } else if trade_id < previous {
                out_of_order_ids += 1;
            } else if trade_id > previous + 1 {
                missing_ids = missing_ids
                    .checked_add(trade_id - previous - 1)
                    .ok_or_else(|| "missing trade ID count overflow".to_owned())?;
            }
        }
        previous_id = Some(trade_id);
    }
    Ok(json!({
        "records": frames.len(),
        "first_trade_id": first_id,
        "last_trade_id": previous_id,
        "missing_trade_ids": missing_ids,
        "duplicate_trade_ids": duplicate_ids,
        "out_of_order_trade_ids": out_of_order_ids,
    }))
}

pub fn audit_session(session: &Path) -> Result<Value> {
    let snapshot_frames = read_raw_log(&session.join("snapshot.bnraw"))?;
    let depth_frames = read_raw_log(&session.join("depth.bnraw"))?;
    let trade_frames = read_raw_log(&session.join("trade.bnraw"))?;
    if snapshot_frames.len() != 1 {
        return Err("session must contain exactly one snapshot".to_owned());
    }
    let symbol = snapshot_frames[0].symbol.clone();
    let replay = replay_session(session)?;
    let trades = trade_identity_report(&trade_frames, &symbol)?;
    let mut qualities = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut permits_event_age = true;
    for frame in snapshot_frames
        .iter()
        .chain(depth_frames.iter())
        .chain(trade_frames.iter())
    {
        add_clock(frame, &mut qualities, &mut sources, &mut permits_event_age);
    }
    let trade_ids_contiguous = trades["missing_trade_ids"] == 0
        && trades["duplicate_trade_ids"] == 0
        && trades["out_of_order_trade_ids"] == 0;
    let mut validity = vec!["RAW_INTEGRITY", "BOOK_LIVE"];
    if trade_ids_contiguous {
        validity.push("TRADE_IDS_CONTIGUOUS");
    }
    let depth_epochs: BTreeSet<String> = depth_frames
        .iter()
        .map(|frame| frame.connection_epoch.clone())
        .collect();
    let trade_epochs: BTreeSet<String> = trade_frames
        .iter()
        .map(|frame| frame.connection_epoch.clone())
        .collect();
    let mut audit = json!({
        "schema": "DatasetAuditV1",
        "symbol": symbol,
        "dataset_policy": "RAW_IMMUTABLE_DERIVATIONS_SEPARATE",
        "lineage": {
            "snapshot_connection_epoch": snapshot_frames[0].connection_epoch,
            "depth_connection_epochs": depth_epochs,
            "trade_connection_epochs": trade_epochs,
            "cross_stream_total_order_available": false,
        },
        "clock": {
            "qualities": qualities,
            "sources": sources,
            "event_age_available": permits_event_age,
        },
        "health": {
            "raw_integrity": "PASS",
            "book_state": replay.state,
            "snapshot_last_update_id": replay.snapshot_last_update_id,
            "final_update_id": replay.final_update_id,
            "depth_records": replay.depth_records,
            "applied_depth_records": replay.applied_records,
            "old_depth_records": replay.old_records,
            "first_applied_frame_index": replay.first_applied_frame_index,
            "trade_ids_contiguous": trade_ids_contiguous,
            "validity": validity,
        },
        "book": {
            "bid_levels": replay.bid_levels,
            "ask_levels": replay.ask_levels,
            "best_bid": replay.best_bid,
            "best_ask": replay.best_ask,
            "spread": replay.spread,
            "state_sha256": replay.state_sha256,
        },
        "trades": trades,
        "excluded_from_audit": [
            "IMBALANCE",
            "MICROPRICE",
            "AGGRESSOR_AGGREGATES",
            "SIGNALS",
            "FILL_OR_PROFITABILITY_CLAIMS",
        ],
    });
    let canonical = serde_json::to_vec(&audit)
        .map_err(|error| format!("serialize canonical audit: {error}"))?;
    audit["audit_sha256"] = Value::String(hex(&Sha256::digest(&canonical)));
    Ok(audit)
}

fn trade_report(
    path: &Path,
    expected_symbol: &str,
    qualities: &mut BTreeSet<String>,
    sources: &mut BTreeSet<String>,
    permits_event_age: &mut bool,
) -> Result<(Value, BTreeSet<String>)> {
    let frames = read_raw_log(path)?;
    if frames.is_empty() {
        return Err("trade log is empty".to_owned());
    }
    let mut first_id = None;
    let mut previous_id = None;
    let mut missing_ids = 0_u64;
    let mut duplicate_ids = 0_u64;
    let mut out_of_order_ids = 0_u64;
    let mut buyer_count = 0_u64;
    let mut seller_count = 0_u64;
    let mut buyer_quantities = Vec::new();
    let mut seller_quantities = Vec::new();
    let mut epochs = BTreeSet::new();
    for frame in &frames {
        epochs.insert(frame.connection_epoch.clone());
        add_clock(frame, qualities, sources, permits_event_age);
        let value: Value = serde_json::from_slice(&frame.payload)
            .map_err(|error| format!("invalid trade JSON: {error}"))?;
        if required_str(&value, "e")? != "trade"
            || required_str(&value, "s")? != expected_symbol
            || frame.symbol != expected_symbol
        {
            return Err("unexpected trade type/symbol".to_owned());
        }
        let trade_id = required_u64(&value, "t")?;
        let quantity = FixedDecimal::parse(required_str(&value, "q")?)?;
        if quantity.is_zero() || quantity.is_negative() {
            return Err("trade quantity must be positive".to_owned());
        }
        let buyer_is_maker = value["m"]
            .as_bool()
            .ok_or_else(|| "missing/invalid boolean field m".to_owned())?;
        first_id.get_or_insert(trade_id);
        if let Some(previous) = previous_id {
            if trade_id == previous {
                duplicate_ids += 1;
            } else if trade_id < previous {
                out_of_order_ids += 1;
            } else if trade_id > previous + 1 {
                missing_ids = missing_ids
                    .checked_add(trade_id - previous - 1)
                    .ok_or_else(|| "missing trade ID count overflow".to_owned())?;
            }
        }
        previous_id = Some(trade_id);
        // Binance m=true: buyer is maker, therefore seller is aggressor.
        if buyer_is_maker {
            seller_count += 1;
            seller_quantities.push(quantity);
        } else {
            buyer_count += 1;
            buyer_quantities.push(quantity);
        }
    }
    let buyer_qty = sum_decimals(buyer_quantities.into_iter())?;
    let seller_qty = sum_decimals(seller_quantities.into_iter())?;
    let report = json!({
        "records": frames.len(),
        "first_trade_id": first_id,
        "last_trade_id": previous_id,
        "missing_trade_ids": missing_ids,
        "duplicate_trade_ids": duplicate_ids,
        "out_of_order_trade_ids": out_of_order_ids,
        "buyer_aggressor_count": buyer_count,
        "seller_aggressor_count": seller_count,
        "buyer_aggressor_base_qty": buyer_qty.to_string(),
        "seller_aggressor_base_qty": seller_qty.to_string(),
        "aggressor_qty_imbalance_ppm": imbalance_ppm(buyer_qty, seller_qty)?,
    });
    Ok((report, epochs))
}

pub fn monitor_session(session: &Path) -> Result<Value> {
    let snapshots = read_raw_log(&session.join("snapshot.bnraw"))?;
    if snapshots.len() != 1 {
        return Err("session must contain exactly one snapshot".to_owned());
    }
    let symbol = snapshots[0].symbol.clone();
    let mut book = LocalOrderBook::new(&symbol)?;
    let snapshot_id = book.load_snapshot(&snapshots[0].payload)?;
    let depth = read_raw_log(&session.join("depth.bnraw"))?;
    let mut applied = 0_usize;
    let mut old = 0_usize;
    let mut first_applied = None;
    let mut qualities = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut permits_event_age = true;
    add_clock(
        &snapshots[0],
        &mut qualities,
        &mut sources,
        &mut permits_event_age,
    );
    for frame in &depth {
        if frame.symbol != symbol {
            return Err("unexpected depth symbol".to_owned());
        }
        add_clock(frame, &mut qualities, &mut sources, &mut permits_event_age);
        match book.apply_depth(&frame.payload)? {
            ApplyOutcome::Old => old += 1,
            ApplyOutcome::Applied => {
                first_applied.get_or_insert(frame.frame_index);
                applied += 1;
            }
        }
    }
    if book.state != BookState::Live {
        return Err("replay did not reach LIVE".to_owned());
    }
    let top_bids: Vec<_> = book.bids.iter().rev().take(20).collect();
    let top_asks: Vec<_> = book.asks.iter().take(20).collect();
    if top_bids.len() < 20 || top_asks.len() < 20 {
        return Err("book has fewer than 20 levels on one side".to_owned());
    }
    let (best_bid, top_bid_qty) = (*top_bids[0].0, *top_bids[0].1);
    let (best_ask, top_ask_qty) = (*top_asks[0].0, *top_asks[0].1);
    let bid_5_qty = sum_decimals(top_bids.iter().take(5).map(|(_, quantity)| **quantity))?;
    let ask_5_qty = sum_decimals(top_asks.iter().take(5).map(|(_, quantity)| **quantity))?;
    let bid_20_qty = sum_decimals(top_bids.iter().map(|(_, quantity)| **quantity))?;
    let ask_20_qty = sum_decimals(top_asks.iter().map(|(_, quantity)| **quantity))?;
    let (trades, trade_epochs) = trade_report(
        &session.join("trade.bnraw"),
        &symbol,
        &mut qualities,
        &mut sources,
        &mut permits_event_age,
    )?;
    let trade_ids_contiguous = trades["missing_trade_ids"] == 0
        && trades["duplicate_trade_ids"] == 0
        && trades["out_of_order_trade_ids"] == 0;
    let mut validity = vec!["RAW_INTEGRITY", "BOOK_LIVE"];
    if trade_ids_contiguous {
        validity.push("TRADE_IDS_CONTIGUOUS");
    }
    let mut report = json!({
        "schema": "MicrostructureReportV1",
        "symbol": symbol,
        "lineage_policy": "DEPTH_AND_TRADE_INDEPENDENT_NO_TOTAL_ORDER",
        "lineage": {
            "snapshot_connection_epoch": snapshots[0].connection_epoch,
            "depth_connection_epochs": depth.iter().map(|frame| &frame.connection_epoch).collect::<BTreeSet<_>>(),
            "trade_connection_epochs": trade_epochs,
        },
        "clock": {
            "qualities": qualities,
            "sources": sources,
            "event_age_available": permits_event_age,
        },
        "health": {
            "raw_integrity": "PASS",
            "book_state": "LIVE",
            "snapshot_last_update_id": snapshot_id,
            "final_update_id": book.last_update_id.ok_or_else(|| "missing final ID".to_owned())?,
            "depth_records": depth.len(),
            "applied_depth_records": applied,
            "old_depth_records": old,
            "first_applied_frame_index": first_applied.ok_or_else(|| "no applied frame".to_owned())?,
            "trade_ids_contiguous": trade_ids_contiguous,
            "validity": validity,
        },
        "book": {
            "bid_levels": book.bids.len(),
            "ask_levels": book.asks.len(),
            "best_bid": best_bid.to_string(),
            "best_ask": best_ask.to_string(),
            "spread": best_ask.checked_sub(best_bid)?.to_string(),
            "top_bid_base_qty": top_bid_qty.to_string(),
            "top_ask_base_qty": top_ask_qty.to_string(),
            "top_imbalance_ppm": imbalance_ppm(top_bid_qty, top_ask_qty)?,
            "microprice_position_ppm": ratio_ppm(top_bid_qty, top_bid_qty.checked_add(top_ask_qty)?)?,
            "bid_5_base_qty": bid_5_qty.to_string(),
            "ask_5_base_qty": ask_5_qty.to_string(),
            "depth_5_imbalance_ppm": imbalance_ppm(bid_5_qty, ask_5_qty)?,
            "bid_20_base_qty": bid_20_qty.to_string(),
            "ask_20_base_qty": ask_20_qty.to_string(),
            "depth_20_imbalance_ppm": imbalance_ppm(bid_20_qty, ask_20_qty)?,
            "state_sha256": book.state_digest(),
        },
        "trades": trades,
        "limitations": [
            "NO_DEPTH_TRADE_TOTAL_ORDER",
            "NO_L3_QUEUE_POSITION",
            "NO_HIDDEN_LIQUIDITY_INFERENCE",
            "NO_FILL_OR_PROFITABILITY_CLAIM",
        ],
    });
    let canonical = serde_json::to_vec(&report)
        .map_err(|error| format!("serialize canonical report: {error}"))?;
    report["report_sha256"] = Value::String(hex(&Sha256::digest(&canonical)));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimals_are_exact_and_canonical() {
        assert_eq!(
            FixedDecimal::parse("60000.10000000").unwrap().to_string(),
            "60000.1"
        );
        assert_eq!(
            FixedDecimal::parse("1.00").unwrap(),
            FixedDecimal::parse("1").unwrap()
        );
        assert!(FixedDecimal::parse("1e-8").is_err());
        assert!(FixedDecimal::parse("01.0").is_err());
    }

    #[test]
    fn snapshot_bridge_delete_and_gap() {
        let mut book = LocalOrderBook::new("BTCUSDT").unwrap();
        book.load_snapshot(
            br#"{"lastUpdateId":99,"bids":[["60000.1","0.25"],["59999.9","1"]],"asks":[["60000.2","0.1"]]}"#,
        )
        .unwrap();
        book.apply_depth(
            br#"{"e":"depthUpdate","s":"BTCUSDT","U":100,"u":102,"b":[["59999.9","0"]],"a":[]}"#,
        )
        .unwrap();
        assert_eq!(book.state, BookState::Live);
        assert_eq!(book.bids.len(), 1);
        let gap =
            book.apply_depth(br#"{"e":"depthUpdate","s":"BTCUSDT","U":104,"u":104,"b":[],"a":[]}"#);
        assert!(gap.is_err());
        assert_eq!(book.state, BookState::Gap);
    }

    #[test]
    fn book_checkpoint_round_trip_is_exact_and_tampering_fails_closed() {
        let mut book = LocalOrderBook::new("BTCUSDT").unwrap();
        book.load_snapshot(
            br#"{"lastUpdateId":99,"bids":[["60000.1","0.25"],["59999.9","1"]],"asks":[["60000.2","0.1"],["60000.3","2"]]}"#,
        )
        .unwrap();
        book.apply_depth(
            br#"{"e":"depthUpdate","s":"BTCUSDT","U":100,"u":102,"b":[["59999.9","0.5"]],"a":[["60000.3","0"]]}"#,
        )
        .unwrap();
        let checkpoint = book.checkpoint().unwrap();
        let restored = LocalOrderBook::from_checkpoint(&checkpoint).unwrap();
        assert!(book.same_state(&restored));
        assert_eq!(book.state_digest(), restored.state_digest());

        let mut tampered = checkpoint;
        tampered.bids[0][1] = "999".to_owned();
        assert!(LocalOrderBook::from_checkpoint(&tampered).is_err());
    }

    #[test]
    fn prepared_depth_path_is_exact_and_preserves_old_event_semantics() {
        let snapshot = br#"{"lastUpdateId":99,"bids":[["60000.1","1"]],"asks":[["60000.2","1"]]}"#;
        let value: Value = serde_json::from_slice(
            br#"{"e":"depthUpdate","s":"BTCUSDT","U":100,"u":101,"b":[["60000.1","2"]],"a":[["60000.3","4"]]}"#,
        )
        .unwrap();
        let mut direct = LocalOrderBook::new("BTCUSDT").unwrap();
        direct.load_snapshot(snapshot).unwrap();
        direct.apply_depth_value(&value).unwrap();

        let mut prepared_book = LocalOrderBook::new("BTCUSDT").unwrap();
        prepared_book.load_snapshot(snapshot).unwrap();
        let prepared = prepared_book.prepare_depth_value(&value).unwrap();
        prepared_book.apply_prepared_depth(&prepared).unwrap();
        assert!(direct.same_state(&prepared_book));
        assert_eq!(direct.state_digest(), prepared_book.state_digest());

        let old: Value = serde_json::from_slice(
            br#"{"e":"depthUpdate","s":"BTCUSDT","U":1,"u":2,"b":"not-consumed","a":null}"#,
        )
        .unwrap();
        let prepared_old = prepared_book.prepare_depth_value(&old).unwrap();
        assert_eq!(
            prepared_book.apply_prepared_depth(&prepared_old).unwrap(),
            ApplyOutcome::Old
        );
    }

    #[test]
    fn monitor_ppm_math_is_exact_and_signed() {
        let one = FixedDecimal::parse("1").unwrap();
        let three = FixedDecimal::parse("3").unwrap();
        assert_eq!(ratio_ppm(one, three).unwrap(), 333_333);
        assert_eq!(imbalance_ppm(three, one).unwrap(), 500_000);
        assert_eq!(imbalance_ppm(one, three).unwrap(), -500_000);
    }

    #[test]
    fn trade_identity_keeps_integrity_separate_from_features() {
        let make_frame = |trade_id: u64| RawFrame {
            venue: "binance-spot".to_owned(),
            environment: "test".to_owned(),
            endpoint: "test".to_owned(),
            symbol: "BTCUSDT".to_owned(),
            stream: "btcusdt@trade".to_owned(),
            connection_epoch: "epoch".to_owned(),
            frame_index: trade_id,
            receive_wall_ns: trade_id,
            receive_mono_ns: trade_id,
            payload: format!(
                "{{\"e\":\"trade\",\"s\":\"BTCUSDT\",\"t\":{trade_id},\"q\":\"1\",\"m\":false}}"
            )
            .into_bytes(),
            clock_quality: "UNSYNCHRONIZED".to_owned(),
            clock_source: "test".to_owned(),
            clock_offset_ns: None,
            clock_uncertainty_ns: None,
            recorder_state: "PENDING".to_owned(),
            spec_revision: "test".to_owned(),
        };
        let frames = vec![
            make_frame(10),
            make_frame(12),
            make_frame(12),
            make_frame(11),
        ];
        let report = trade_identity_report(&frames, "BTCUSDT").unwrap();
        assert_eq!(report["missing_trade_ids"], 1);
        assert_eq!(report["duplicate_trade_ids"], 1);
        assert_eq!(report["out_of_order_trade_ids"], 1);
        assert!(report.get("aggressor_qty_imbalance_ppm").is_none());
    }
}
