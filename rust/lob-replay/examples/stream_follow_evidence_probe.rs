// Probe (test-only): drives the REAL StreamFollowState consumption logic
// (copied verbatim from bin/live_arbitration.rs) against the final evidence
// of hrs-fa053dbc4a86 p/g002 depth. A healthy follower must consume all
// sealed records (370) in ONE refresh; anything less reproduces the drain
// lag that left the canonical one update short of the trusted end.
use lob_replay::durability_follower::SegmentDurabilityFollower;
use lob_replay::segment_chain::{
    root_segment_genesis, scan_segment_manifest, successor_segment_genesis,
};
use lob_replay::{RawRecordEnvelopeV1, read_raw_record_range, read_raw_records};
use std::path::{Path, PathBuf};

fn segment_file_name(index: u64) -> String {
    format!("segment-{index:06}.bnraw")
}
fn progress_file_name(index: u64) -> String {
    format!("segment-{index:06}.bnack")
}

struct StreamFollowState {
    stream_dir: PathBuf,
    stream_suffix: String,
    records: Vec<RawRecordEnvelopeV1>,
    segment_index: u64,
    genesis: Option<lob_replay::RawSegmentGenesisV1>,
    follower: Option<SegmentDurabilityFollower>,
    last_durable_offset: u64,
    segment_record_start: usize,
    poisoned: bool,
}

impl StreamFollowState {
    fn open(stream_dir: &Path, stream_suffix: &str) -> lob_replay::Result<Self> {
        Ok(Self {
            stream_dir: stream_dir.to_path_buf(),
            stream_suffix: stream_suffix.to_owned(),
            records: Vec::new(),
            segment_index: 0,
            genesis: None,
            follower: None,
            last_durable_offset: 8,
            segment_record_start: 0,
            poisoned: false,
        })
    }

    fn refresh(&mut self) -> lob_replay::Result<usize> {
        if self.poisoned {
            return Err("stream follower is poisoned".to_owned());
        }
        let mut appended_total = 0_usize;
        loop {
            if self.follower.is_none() && !self.try_bind_follower()? {
                return Ok(appended_total);
            }
            let durable_offset = {
                let follower = self
                    .follower
                    .as_mut()
                    .ok_or_else(|| "stream follower is missing".to_owned())?;
                let poll = match follower.poll() {
                    Ok(poll) => poll,
                    Err(error) => {
                        self.poisoned = true;
                        return Err(error);
                    }
                };
                poll.cursor.raw_offset
            };
            if durable_offset < self.last_durable_offset {
                self.poisoned = true;
                return Err("in-flight durable offset regressed".to_owned());
            }
            if durable_offset > self.last_durable_offset {
                appended_total += self.extend_in_flight(durable_offset)?;
            }
            let manifest = scan_segment_manifest(&self.stream_dir.join("segments.bnseg"))?;
            if !manifest.clean_eof {
                return Ok(appended_total);
            }
            let sealed_count = manifest.entries.len() as u64;
            if sealed_count <= self.segment_index {
                return Ok(appended_total);
            }
            let mut advanced = false;
            while self.segment_index < sealed_count {
                let entry = &manifest.entries[self.segment_index as usize];
                let seal = &entry.seal;
                if seal.segment_index != self.segment_index {
                    self.poisoned = true;
                    return Err("segment manifest seal index discontinuity".to_owned());
                }
                let genesis = match &self.genesis {
                    Some(genesis) => genesis.clone(),
                    None => {
                        let root = root_segment_genesis(&seal.connection_epoch, &seal.stream)?;
                        self.genesis = Some(root.clone());
                        root
                    }
                };
                if seal.previous_segment_terminal_sha256 != genesis.previous_segment_terminal_sha256
                    || seal.connection_epoch != genesis.connection_epoch
                    || seal.stream != genesis.stream
                {
                    self.poisoned = true;
                    return Err("segment manifest seal diverges from the followed chain".to_owned());
                }
                if seal.durable_through_offset < self.last_durable_offset {
                    self.poisoned = true;
                    return Err("segment seal durable offset regressed".to_owned());
                }
                if seal.durable_through_offset > self.last_durable_offset {
                    appended_total += self.extend_in_flight(seal.durable_through_offset)?;
                }
                let terminal = if self.records.len() == self.segment_record_start {
                    genesis.previous_segment_terminal_sha256.clone()
                } else {
                    self.records
                        .last()
                        .map(|record| record.record_sha256.clone())
                        .unwrap_or_default()
                };
                let segment_records = (self.records.len() - self.segment_record_start) as u64;
                let first_frame = self
                    .records
                    .get(self.segment_record_start)
                    .map(|record| record.frame.frame_index);
                let last_frame = self.records.last().map(|record| record.frame.frame_index);
                if terminal != seal.terminal_record_sha256
                    || segment_records != seal.records
                    || first_frame != Some(seal.first_frame_index)
                    || last_frame != Some(seal.last_frame_index)
                {
                    self.poisoned = true;
                    return Err("sealed segment does not converge on the manifest seal".to_owned());
                }
                self.genesis = Some(successor_segment_genesis(seal)?);
                self.segment_index = seal.segment_index.saturating_add(1);
                self.segment_record_start = self.records.len();
                self.follower = None;
                self.last_durable_offset = 8;
                advanced = true;
            }
            if advanced {
                continue;
            }
            return Ok(appended_total);
        }
    }

    fn try_bind_follower(&mut self) -> lob_replay::Result<bool> {
        let raw_path = self.stream_dir.join(segment_file_name(self.segment_index));
        let progress_path = self.stream_dir.join(progress_file_name(self.segment_index));
        if !raw_path.is_file() || !progress_path.is_file() {
            return Ok(false);
        }
        if self.genesis.is_none() {
            let probe = read_raw_records(&raw_path)
                .map_err(|error| format!("probe root segment identity: {error}"))?;
            let first = probe
                .first()
                .ok_or_else(|| "root segment has no records yet".to_owned())?;
            if !first.frame.stream.contains(&self.stream_suffix) {
                return Err("root segment stream suffix mismatch".to_owned());
            }
            self.genesis = Some(root_segment_genesis(
                &first.frame.connection_epoch,
                &first.frame.stream,
            )?);
        }
        let genesis = self
            .genesis
            .as_ref()
            .ok_or_else(|| "in-flight follower lost its genesis".to_owned())?
            .clone();
        let raw_name = segment_file_name(self.segment_index);
        let mut opened = SegmentDurabilityFollower::open_with_reference(
            &progress_path,
            &raw_path,
            &genesis,
            &raw_name,
        )?;
        let poll = opened.poll()?;
        let durable_offset = poll.cursor.raw_offset;
        if durable_offset < 8 {
            return Err("in-flight durable offset before magic".to_owned());
        }
        self.follower = Some(opened);
        self.last_durable_offset = 8;
        self.segment_record_start = self.records.len();
        if durable_offset > 8 {
            self.extend_in_flight(durable_offset)?;
        }
        Ok(true)
    }

    fn extend_in_flight(&mut self, end_offset: u64) -> lob_replay::Result<usize> {
        let genesis = self
            .genesis
            .as_ref()
            .ok_or_else(|| "in-flight follower lost its genesis".to_owned())?
            .clone();
        let previous = self
            .records
            .last()
            .map(|record| record.record_sha256.clone())
            .unwrap_or_else(|| genesis.previous_segment_terminal_sha256.clone());
        let next_frame_index = self
            .records
            .last()
            .map(|record| record.frame.frame_index.saturating_add(1))
            .unwrap_or(genesis.next_frame_index);
        let raw_path = self.stream_dir.join(segment_file_name(self.segment_index));
        let appended = read_raw_record_range(
            &raw_path,
            self.last_durable_offset,
            end_offset,
            &previous,
            &genesis.connection_epoch,
            &genesis.stream,
            next_frame_index,
        )
        .inspect_err(|_| self.poisoned = true)?;
        let count = appended.len();
        self.records.extend(appended);
        self.last_durable_offset = end_offset;
        Ok(count)
    }
}

fn main() {
    let stream_dir = std::env::args().nth(1).expect("depth stream dir");
    let mut state = StreamFollowState::open(Path::new(&stream_dir), "@depth").unwrap();
    for poll in 1..=4 {
        match state.refresh() {
            Ok(new) => {
                let last_frame = state.records.last().map(|r| r.frame.frame_index);
                println!(
                    "poll {poll}: new={new} total={} segment_index={} last_frame={last_frame:?} poisoned={}",
                    state.records.len(),
                    state.segment_index,
                    state.poisoned
                );
            }
            Err(error) => {
                println!("poll {poll}: ERR {error}");
                return;
            }
        }
    }
}
