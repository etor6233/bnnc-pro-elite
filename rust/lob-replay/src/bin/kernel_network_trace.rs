#[cfg(not(windows))]
fn main() {
    eprintln!("kernel_network_trace is supported only on Windows");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> Result<(), String> {
    use lob_replay::windows_etw::{
        KernelNetworkTrace, TCP_IPV4_IPV6_KEYWORDS, TCP_LIFECYCLE_EVENT_IDS, abi_contract,
    };
    use serde_json::json;
    use std::env;
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant};

    let arguments: Vec<String> = env::args().collect();
    if arguments.len() == 2 && arguments[1] == "validate" {
        abi_contract()?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": "KernelNetworkTraceValidationV1",
                "status": "PASS",
                "provider_guid": "7dd42a49-5329-4832-8dfd-43d979153a88",
                "event_ids": TCP_LIFECYCLE_EVENT_IDS,
                "match_any_keyword": format!("0x{TCP_IPV4_IPV6_KEYWORDS:016X}"),
                "raw_packet_payload_capture": false,
            }))
            .map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    if arguments.len() != 6 {
        return Err(
            "usage: kernel_network_trace <session> <absolute.etl> <stop-file> <max-MiB> <deadline-s>\n       kernel_network_trace validate"
                .to_owned(),
        );
    }

    let session_name = &arguments[1];
    let etl_path = PathBuf::from(&arguments[2]);
    let stop_file = PathBuf::from(&arguments[3]);
    let maximum_file_mib = arguments[4]
        .parse::<u32>()
        .map_err(|error| format!("invalid max-MiB: {error}"))?;
    let deadline_seconds = arguments[5]
        .parse::<u64>()
        .map_err(|error| format!("invalid deadline-s: {error}"))?;
    // The observer is armed before the campaign and remains live through the
    // bounded terminal drain.  Eight days covers the immutable seven-day
    // profile plus startup/terminal margin without creating an unbounded ETW
    // session; the circular file size remains independently bounded.
    if deadline_seconds == 0 || deadline_seconds > 691_200 {
        return Err("deadline-s must be within 1..=691200".to_owned());
    }
    if stop_file.exists() {
        return Err(format!(
            "stop file already exists (create-only run required): {}",
            stop_file.display()
        ));
    }
    if !stop_file.is_absolute() {
        return Err("stop-file must be absolute".to_owned());
    }

    abi_contract()?;
    let mut trace = KernelNetworkTrace::start(session_name, &etl_path, maximum_file_mib)?;
    let initial = trace.query()?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "KernelNetworkTraceReadyV1",
            "status": "READY",
            "session_name": session_name,
            "etl_path": etl_path,
            "stop_file": stop_file,
            "event_ids": TCP_LIFECYCLE_EVENT_IDS,
            "match_any_keyword": format!("0x{TCP_IPV4_IPV6_KEYWORDS:016X}"),
            "statistics": {
                "number_of_buffers": initial.number_of_buffers,
                "free_buffers": initial.free_buffers,
                "events_lost": initial.events_lost,
                "buffers_written": initial.buffers_written,
                "log_buffers_lost": initial.log_buffers_lost,
                "realtime_buffers_lost": initial.realtime_buffers_lost,
            }
        }))
        .map_err(|error| error.to_string())?
    );
    io::stdout().flush().map_err(|error| error.to_string())?;

    let start = Instant::now();
    let deadline = Duration::from_secs(deadline_seconds);
    let stop_reason = loop {
        if stop_file.is_file() {
            break "STOP_FILE";
        }
        if start.elapsed() >= deadline {
            break "DEADLINE";
        }
        thread::sleep(Duration::from_millis(100));
    };

    let statistics = trace.finish()?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "KernelNetworkTraceSealV1",
            "status": "SEALED",
            "session_name": session_name,
            "etl_path": etl_path,
            "stop_reason": stop_reason,
            "elapsed_ms": start.elapsed().as_millis(),
            "statistics": {
                "number_of_buffers": statistics.number_of_buffers,
                "free_buffers": statistics.free_buffers,
                "events_lost": statistics.events_lost,
                "buffers_written": statistics.buffers_written,
                "log_buffers_lost": statistics.log_buffers_lost,
                "realtime_buffers_lost": statistics.realtime_buffers_lost,
            }
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}
