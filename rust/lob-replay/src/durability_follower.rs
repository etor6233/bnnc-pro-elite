//! Incremental, segment-aware audit of an append-only BNACK journal.
//!
//! This follower is a recovery/audit reader.  It is deliberately **not** the
//! live publication linearization point: a different process may observe bytes
//! after the BNACK writer's `write` but before its `sync_all` returns.  Live
//! ownership and liveness may use only the typed ACK communicated after
//! `DurabilityProgressWriter::append` has returned successfully.  Once a writer
//! is stopped, this module verifies the journal's surviving chain and every ACK
//! against the exact acknowledged BNRAW segment ranges.

use crate::durability_progress::verify_portable_raw_reference;
use crate::{DurabilityAckV1, RawSegmentGenesisV1, Result, read_raw_record_range};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const RAW_MAGIC: &[u8; 8] = b"BNRAW\0\x01\n";
const MAX_PROGRESS_RECORD_BYTES: usize = 1024 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProgressBodyV1 {
    schema: String,
    record_index: u64,
    raw_path: String,
    ack: DurabilityAckV1,
    previous_record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProgressEnvelopeV1 {
    body: ProgressBodyV1,
    record_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurabilityFollowerCursorV1 {
    pub schema: &'static str,
    pub journal_offset: u64,
    pub next_record_index: u64,
    pub previous_progress_record_sha256: String,
    pub latest_ack: Option<DurabilityAckV1>,
    pub raw_record_count: u64,
    pub raw_offset: u64,
    pub raw_previous_record_sha256: String,
    pub raw_next_frame_index: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedDurabilityProgressV1 {
    pub schema: &'static str,
    pub record_index: u64,
    pub journal_start_offset: u64,
    pub journal_end_offset: u64,
    pub progress_record_sha256: String,
    pub acknowledged_records: u64,
    pub ack: DurabilityAckV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DurabilityFollowerPollV1 {
    pub schema: &'static str,
    pub records: Vec<VerifiedDurabilityProgressV1>,
    pub pending_tail_bytes: u64,
    pub journal_read_offset: u64,
    pub cursor: DurabilityFollowerCursorV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentityV1 {
    first: u64,
    second: u64,
}

pub struct SegmentDurabilityFollower {
    progress_path: PathBuf,
    raw_path: PathBuf,
    expected_raw_path: String,
    genesis: RawSegmentGenesisV1,
    progress_file: File,
    progress_identity: FileIdentityV1,
    raw_identity: FileIdentityV1,
    read_offset: u64,
    pending: Vec<u8>,
    cursor: DurabilityFollowerCursorV1,
    poisoned: bool,
}

impl SegmentDurabilityFollower {
    /// Opens a legacy journal whose records identify the raw segment using the
    /// caller's display-form path.
    pub fn open(
        progress_path: &Path,
        raw_path: &Path,
        genesis: &RawSegmentGenesisV1,
    ) -> Result<Self> {
        Self::open_with_raw_identity(
            progress_path,
            raw_path,
            genesis,
            raw_path.display().to_string(),
        )
    }

    /// Opens a portable journal and binds its safe relative reference to the
    /// supplied BNRAW path before accepting any durability record.
    pub fn open_with_reference(
        progress_path: &Path,
        raw_path: &Path,
        genesis: &RawSegmentGenesisV1,
        expected_reference: &str,
    ) -> Result<Self> {
        verify_portable_raw_reference(progress_path, raw_path, expected_reference)?;
        Self::open_with_raw_identity(
            progress_path,
            raw_path,
            genesis,
            expected_reference.to_owned(),
        )
    }

    fn open_with_raw_identity(
        progress_path: &Path,
        raw_path: &Path,
        genesis: &RawSegmentGenesisV1,
        expected_raw_path: String,
    ) -> Result<Self> {
        validate_genesis(genesis)?;
        let mut raw = File::open(raw_path)
            .map_err(|error| format!("open raw segment {}: {error}", raw_path.display()))?;
        let raw_identity = file_identity(&raw)?;
        let mut magic = [0_u8; 8];
        raw.read_exact(&mut magic)
            .map_err(|_| "bad raw segment magic".to_owned())?;
        if &magic != RAW_MAGIC {
            return Err("bad raw segment magic".to_owned());
        }
        let progress_file = File::open(progress_path).map_err(|error| {
            format!(
                "open durability progress {}: {error}",
                progress_path.display()
            )
        })?;
        let progress_identity = file_identity(&progress_file)?;
        Ok(Self {
            progress_path: progress_path.to_path_buf(),
            raw_path: raw_path.to_path_buf(),
            expected_raw_path,
            genesis: genesis.clone(),
            progress_file,
            progress_identity,
            raw_identity,
            read_offset: 0,
            pending: Vec::new(),
            cursor: DurabilityFollowerCursorV1 {
                schema: "DurabilityFollowerCursorV1",
                journal_offset: 0,
                next_record_index: 0,
                previous_progress_record_sha256: ZERO_DIGEST.to_owned(),
                latest_ack: None,
                raw_record_count: 0,
                raw_offset: RAW_MAGIC.len() as u64,
                raw_previous_record_sha256: genesis.previous_segment_terminal_sha256.clone(),
                raw_next_frame_index: genesis.next_frame_index,
            },
            poisoned: false,
        })
    }

    /// Reads only bytes at and after the retained cursor.  A non-newline tail
    /// remains buffered and non-authoritative until a later poll completes it.
    pub fn poll(&mut self) -> Result<DurabilityFollowerPollV1> {
        if self.poisoned {
            return Err("durability follower is poisoned".to_owned());
        }
        let result = self.poll_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn poll_inner(&mut self) -> Result<DurabilityFollowerPollV1> {
        self.check_file_identity_and_length()?;
        self.progress_file
            .seek(SeekFrom::Start(self.read_offset))
            .map_err(|error| format!("seek durability progress cursor: {error}"))?;
        let mut verified = Vec::new();
        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        loop {
            let read = self
                .progress_file
                .read(&mut chunk)
                .map_err(|error| format!("read durability progress tail: {error}"))?;
            if read == 0 {
                break;
            }
            self.read_offset = self
                .read_offset
                .checked_add(read as u64)
                .ok_or_else(|| "durability progress read offset overflow".to_owned())?;
            self.pending.extend_from_slice(&chunk[..read]);
            self.consume_complete_records(&mut verified)?;
            if self.pending.len() > MAX_PROGRESS_RECORD_BYTES {
                return Err("durability progress record exceeds maximum size".to_owned());
            }
        }
        Ok(DurabilityFollowerPollV1 {
            schema: "DurabilityFollowerPollV1",
            records: verified,
            pending_tail_bytes: self.pending.len() as u64,
            journal_read_offset: self.read_offset,
            cursor: self.cursor.clone(),
        })
    }

    fn consume_complete_records(
        &mut self,
        verified: &mut Vec<VerifiedDurabilityProgressV1>,
    ) -> Result<()> {
        while let Some(line_length) = self.pending.iter().position(|byte| *byte == b'\n') {
            if line_length == 0 || line_length > MAX_PROGRESS_RECORD_BYTES {
                return Err("invalid durability progress record length".to_owned());
            }
            let line = &self.pending[..line_length];
            let envelope: ProgressEnvelopeV1 = serde_json::from_slice(line)
                .map_err(|error| format!("invalid durability progress JSON: {error}"))?;
            let body_bytes = serde_json::to_vec(&envelope.body)
                .map_err(|error| format!("reserialize durability progress: {error}"))?;
            let digest = hex(&Sha256::digest(&body_bytes));
            if envelope.body.schema != "RawDurabilityProgressV1"
                || envelope.body.record_index != self.cursor.next_record_index
                || envelope.body.previous_record_sha256
                    != self.cursor.previous_progress_record_sha256
                || envelope.record_sha256 != digest
            {
                return Err("durability progress fork or invalid hash chain".to_owned());
            }
            if envelope.body.raw_path != self.expected_raw_path {
                return Err("durability progress raw_path drift".to_owned());
            }
            self.check_file_identity_and_length()?;
            let acknowledged_records = self.verify_ack_against_raw(&envelope.body.ack)?;
            let start_offset = self.cursor.journal_offset;
            let encoded_length = line_length
                .checked_add(1)
                .ok_or_else(|| "durability progress line length overflow".to_owned())?;
            let end_offset = start_offset
                .checked_add(encoded_length as u64)
                .ok_or_else(|| "durability progress cursor overflow".to_owned())?;
            verified.push(VerifiedDurabilityProgressV1 {
                schema: "VerifiedDurabilityProgressV1",
                record_index: envelope.body.record_index,
                journal_start_offset: start_offset,
                journal_end_offset: end_offset,
                progress_record_sha256: digest.clone(),
                acknowledged_records,
                ack: envelope.body.ack.clone(),
            });
            self.cursor.journal_offset = end_offset;
            self.cursor.next_record_index = self
                .cursor
                .next_record_index
                .checked_add(1)
                .ok_or_else(|| "durability progress record index overflow".to_owned())?;
            self.cursor.previous_progress_record_sha256 = digest;
            self.cursor.latest_ack = Some(envelope.body.ack);
            self.pending.drain(..encoded_length);
        }
        Ok(())
    }

    fn verify_ack_against_raw(&mut self, ack: &DurabilityAckV1) -> Result<u64> {
        validate_ack(ack, &self.genesis)?;
        if let Some(previous) = &self.cursor.latest_ack
            && (ack.durable_record_count <= previous.durable_record_count
                || ack.durable_through_offset <= previous.durable_through_offset
                || ack.streams[0].durable_through_frame_index
                    <= previous.streams[0].durable_through_frame_index)
        {
            return Err("durability progress ACK regressed or did not advance".to_owned());
        }
        if ack.durable_record_count <= self.cursor.raw_record_count
            || ack.durable_through_offset <= self.cursor.raw_offset
        {
            return Err("durability progress ACK does not advance raw cursor".to_owned());
        }
        let raw_metadata = std::fs::metadata(&self.raw_path).map_err(|error| {
            format!("metadata raw segment {}: {error}", self.raw_path.display())
        })?;
        if raw_metadata.len() < ack.durable_through_offset {
            return Err("raw segment is shorter than durability ACK".to_owned());
        }
        let records = read_raw_record_range(
            &self.raw_path,
            self.cursor.raw_offset,
            ack.durable_through_offset,
            &self.cursor.raw_previous_record_sha256,
            &self.genesis.connection_epoch,
            &self.genesis.stream,
            self.cursor.raw_next_frame_index,
        )?;
        let acknowledged_records = ack
            .durable_record_count
            .checked_sub(self.cursor.raw_record_count)
            .ok_or_else(|| "durability ACK record count regressed".to_owned())?;
        let last = records
            .last()
            .ok_or_else(|| "durability ACK produced no raw records".to_owned())?;
        if records.len() as u64 != acknowledged_records
            || records.iter().any(|record| {
                record.frame.connection_epoch != self.genesis.connection_epoch
                    || record.frame.stream != self.genesis.stream
            })
            || last.end_offset != ack.durable_through_offset
            || last.record_sha256 != ack.last_record_sha256
            || last.frame.frame_index != ack.streams[0].durable_through_frame_index
        {
            return Err("durability ACK does not match exact raw segment range".to_owned());
        }
        self.cursor.raw_record_count = ack.durable_record_count;
        self.cursor.raw_offset = ack.durable_through_offset;
        self.cursor.raw_previous_record_sha256 = ack.last_record_sha256.clone();
        self.cursor.raw_next_frame_index = ack.streams[0]
            .durable_through_frame_index
            .checked_add(1)
            .ok_or_else(|| "durability raw frame cursor overflow".to_owned())?;
        Ok(acknowledged_records)
    }

    fn check_file_identity_and_length(&self) -> Result<()> {
        let progress_metadata = std::fs::metadata(&self.progress_path).map_err(|error| {
            format!(
                "metadata durability progress {}: {error}",
                self.progress_path.display()
            )
        })?;
        if path_file_identity(&self.progress_path)? != self.progress_identity {
            return Err("durability progress file was replaced".to_owned());
        }
        if progress_metadata.len() < self.read_offset
            || progress_metadata.len() < self.cursor.journal_offset
        {
            return Err("durability progress file was truncated".to_owned());
        }
        let raw_metadata = std::fs::metadata(&self.raw_path).map_err(|error| {
            format!("metadata raw segment {}: {error}", self.raw_path.display())
        })?;
        if path_file_identity(&self.raw_path)? != self.raw_identity {
            return Err("raw segment file was replaced".to_owned());
        }
        if raw_metadata.len() < self.cursor.raw_offset {
            return Err("raw segment file was truncated below verified cursor".to_owned());
        }
        Ok(())
    }

    /// Requires the currently visible journal to end at a verified newline.
    /// Call only after the BNACK writer has stopped; while it is live a partial
    /// tail is an expected transient state.
    pub fn require_clean_eof(&mut self) -> Result<DurabilityFollowerCursorV1> {
        let poll = self.poll()?;
        if poll.pending_tail_bytes != 0 {
            self.poisoned = true;
            return Err("partial durability progress tail at final audit".to_owned());
        }
        Ok(self.cursor.clone())
    }

    pub fn cursor(&self) -> &DurabilityFollowerCursorV1 {
        &self.cursor
    }

    pub fn pending_tail_bytes(&self) -> usize {
        self.pending.len()
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

fn validate_genesis(genesis: &RawSegmentGenesisV1) -> Result<()> {
    if genesis.schema != "RawSegmentGenesisV1"
        || genesis.connection_epoch.trim().is_empty()
        || genesis.stream.trim().is_empty()
    {
        return Err("invalid durability follower segment genesis".to_owned());
    }
    validate_digest(
        &genesis.previous_segment_terminal_sha256,
        "previous_segment_terminal_sha256",
    )?;
    let root = genesis.segment_index == 0
        && genesis.next_frame_index == 0
        && genesis.previous_segment_terminal_sha256 == ZERO_DIGEST;
    let successor = genesis.segment_index > 0
        && genesis.next_frame_index > 0
        && genesis.previous_segment_terminal_sha256 != ZERO_DIGEST;
    if !root && !successor {
        return Err("durability follower genesis is neither root nor successor".to_owned());
    }
    Ok(())
}

fn validate_ack(ack: &DurabilityAckV1, genesis: &RawSegmentGenesisV1) -> Result<()> {
    if ack.schema != "DurabilityAckV1"
        || ack.durable_record_count == 0
        || ack.durable_through_offset <= RAW_MAGIC.len() as u64
        || ack.streams.len() != 1
    {
        return Err("invalid durability follower ACK".to_owned());
    }
    validate_digest(&ack.last_record_sha256, "last_record_sha256")?;
    let watermark = &ack.streams[0];
    if watermark.connection_epoch != genesis.connection_epoch || watermark.stream != genesis.stream
    {
        return Err("durability follower ACK identity drift".to_owned());
    }
    let expected_frame = genesis
        .next_frame_index
        .checked_add(ack.durable_record_count - 1)
        .ok_or_else(|| "durability follower ACK frame range overflow".to_owned())?;
    if watermark.durable_through_frame_index != expected_frame {
        return Err("durability follower ACK count/frame mismatch".to_owned());
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{field} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

#[cfg(windows)]
fn file_identity(file: &File) -> Result<FileIdentityV1> {
    use std::ffi::c_void;
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = MaybeUninit::<ByHandleFileInformation>::uninit();
    // SAFETY: `file` owns a valid handle for the call and `information` has
    // the exact writable BY_HANDLE_FILE_INFORMATION layout expected by Win32.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
    if succeeded == 0 {
        return Err(format!(
            "query Windows file identity: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: a nonzero return guarantees initialization of the output.
    let information = unsafe { information.assume_init() };
    Ok(FileIdentityV1 {
        first: u64::from(information.volume_serial_number),
        second: (u64::from(information.file_index_high) << 32)
            | u64::from(information.file_index_low),
    })
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<FileIdentityV1> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|error| format!("query Unix file identity: {error}"))?;
    Ok(FileIdentityV1 {
        first: metadata.dev(),
        second: metadata.ino(),
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File) -> Result<FileIdentityV1> {
    Err("durability follower lacks file identity support on this platform".to_owned())
}

fn path_file_identity(path: &Path) -> Result<FileIdentityV1> {
    let file = File::open(path)
        .map_err(|error| format!("open {} for identity check: {error}", path.display()))?;
    file_identity(&file)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
