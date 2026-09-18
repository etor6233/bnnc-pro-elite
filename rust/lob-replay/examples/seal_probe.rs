// Probe (test-only): dump the seal records of one stream directory's manifest.
use std::path::Path;

fn main() {
    let stream_dir = std::env::args().nth(1).expect("stream dir");
    let stream_dir = Path::new(&stream_dir);
    let scan = lob_replay::segment_chain::scan_segment_manifest(&stream_dir.join("segments.bnseg"))
        .expect("scan manifest");
    println!(
        "entries={} clean_eof={}",
        scan.entries.len(),
        scan.clean_eof
    );
    for entry in &scan.entries {
        let seal = &entry.seal;
        println!(
            "seg={} records={} first_frame={} last_frame={} durable_through_offset={} terminal={}..",
            seal.segment_index,
            seal.records,
            seal.first_frame_index,
            seal.last_frame_index,
            seal.durable_through_offset,
            &seal.terminal_record_sha256[..16]
        );
    }
}
