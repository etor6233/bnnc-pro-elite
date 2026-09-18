"""Independent verifier for the public Binance WebSocket/ETW canary.

The canary is diagnostic evidence only.  It launches the production raw
collector unchanged, verifies the resulting generation independently in both
Rust and Python, and correlates its exact process identity with the filtered
Microsoft-Windows-Kernel-Network trace.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha256
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
from typing import Any

from .kernel_network_etw import (
    MIB,
    SELECTED_EVENT_IDS,
    _bytes,
    _controller_records,
    _digest,
    _json,
    _lines,
    _parse_kernel_events,
    _regular_root,
    _text,
    _time,
    _uint,
)
from .segment_chain import SegmentChainCorruption, verify_segmented_generation


EXPECTED_FILES = {
    "collector.stderr.txt",
    "collector.stdout.jsonl",
    "controller.stderr.txt",
    "controller.stdout.jsonl",
    "generation-verification.json",
    "kernel-network.etl",
    "kernel-network.xml",
    "stop.request",
    "websocket-canary.json",
}
REPORT_KEYS = (
    "schema",
    "run_id",
    "status",
    "started_utc",
    "collector_started_utc",
    "collector_completed_utc",
    "completed_utc",
    "diagnostic_only",
    "training_eligible",
    "controller_executable",
    "controller_sha256",
    "session_name",
    "controller_pid",
    "controller_exit_code",
    "controller_records",
    "controller_stderr_file",
    "controller_stderr_bytes",
    "controller_stderr_sha256",
    "collector_executable",
    "collector_sha256",
    "collector_pid",
    "collector_exit_code",
    "collector_stdout_file",
    "collector_stdout_bytes",
    "collector_stdout_sha256",
    "collector_stderr_file",
    "collector_stderr_bytes",
    "collector_stderr_sha256",
    "public_config",
    "public_config_sha256",
    "generation_verifier_executable",
    "generation_verifier_sha256",
    "generation_verifier_exit_code",
    "symbol",
    "generation_index",
    "duration_s",
    "segment_s",
    "websocket_host",
    "websocket_port",
    "dns_addresses",
    "generation_directory",
    "generation_verification_file",
    "generation_verification_bytes",
    "generation_verification_sha256",
    "etl_file",
    "etl_bytes",
    "etl_sha256",
    "decoded_file",
    "decoded_bytes",
    "decoded_sha256",
    "tracerpt_exit_code",
    "tracerpt_output",
    "orphan_query_exit_code",
    "orphan_query_output",
    "selected_event_ids",
    "raw_packet_payload_capture",
    "correlation_status",
)


class KernelNetworkWebSocketCorruption(ValueError):
    """Raised when public WebSocket canary evidence violates its contract."""


def _fail(message: str) -> None:
    raise KernelNetworkWebSocketCorruption(message)


def _same_file_digest(path_value: Any, expected: str, label: str) -> Path:
    path = Path(_text(path_value, f"{label} path")).resolve(strict=True)
    data = _bytes(path, 512 * MIB, label)
    if sha256(data).hexdigest() != expected:
        _fail(f"{label} changed after the canary bound its identity")
    return path


def _strict_ip_list(value: Any) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        _fail("DNS address inventory is empty or oversized")
    result: list[str] = []
    for item in value:
        text = _text(item, "DNS address")
        try:
            canonical = str(ip_address(text))
        except ValueError:
            _fail("DNS address inventory contains an invalid IP address")
        if text != canonical or text in result:
            _fail("DNS address inventory is noncanonical or contains duplicates")
        result.append(text)
    if result != sorted(result):
        _fail("DNS address inventory is not ordinally sorted")
    return result


def _verify_rust_generation_report(
    report: dict[str, Any],
    generation_root: Path,
    collector_digest: str,
    config_digest: str,
) -> None:
    required = {
        "schema",
        "status",
        "session_id",
        "session_dir",
        "generation_index",
        "symbol",
        "duration_requested_s",
        "segment_duration_s",
        "started_wall_ns",
        "finished_wall_ns",
        "collector_executable_sha256",
        "public_config_sha256",
        "generation_manifest_sha256",
        "snapshot_sha256",
        "snapshot_record_sha256",
        "snapshot_last_update_id",
        "telemetry_sha256",
        "telemetry_records",
        "streams",
        "verification_sha256",
    }
    if set(report) != required:
        _fail("Rust generation verification property inventory drifted")
    if report["schema"] != "VerifiedGenerationV1" or report["status"] != "PASS":
        _fail("Rust generation verification is not PASS")
    if Path(_text(report["session_dir"], "Rust session_dir")).resolve(strict=True) != generation_root:
        _fail("Rust verifier generation path disagrees")
    if report["generation_index"] != 0 or report["symbol"] != "BTCUSDT":
        _fail("Rust verifier generation identity disagrees")
    if report["duration_requested_s"] != 30 or report["segment_duration_s"] != 10:
        _fail("Rust verifier timing identity disagrees")
    if report["collector_executable_sha256"] != collector_digest:
        _fail("Rust verifier collector digest disagrees")
    if report["public_config_sha256"] != config_digest:
        _fail("Rust verifier public-config digest disagrees")
    _digest(report["verification_sha256"], "Rust verification digest")


def _correlate_websocket_attempts(
    events: list[dict[str, Any]],
    collector_pid: int,
    dns_addresses: list[str],
    collector_started: datetime,
    collector_completed: datetime,
) -> tuple[list[dict[str, Any]], set[tuple[Any, Any, Any, Any]]]:
    lower = collector_started - timedelta(seconds=1)
    upper = collector_completed + timedelta(seconds=1)
    attempts: list[dict[str, Any]] = []
    dns_set = set(dns_addresses)
    for event in events:
        fields = event["fields"]
        try:
            destination_port = int(fields["dport"])
            destination_address = str(ip_address(fields["daddr"]))
        except (KeyError, ValueError):
            continue
        observed = _time(event["system_time"], "event system_time")
        if (
            event["event_id"] in (12, 28)
            and event["process_id"] == collector_pid
            and destination_port == 443
            and destination_address in dns_set
            and lower <= observed <= upper
        ):
            attempts.append(event)
    endpoint_keys = {
        (
            event["fields"].get("saddr"),
            event["fields"].get("sport"),
            event["fields"].get("daddr"),
            event["fields"].get("dport"),
        )
        for event in attempts
    }
    if len(endpoint_keys) < 2:
        _fail("fewer than two exact collector PID/WebSocket endpoint TCP-attempt correlations")
    return attempts, endpoint_keys


def verify_kernel_network_websocket(root: Path) -> dict[str, Any]:
    """Fail closed unless the isolated public WebSocket canary is exact."""

    root = _regular_root(root)
    if {entry.name for entry in root.iterdir()} != EXPECTED_FILES:
        _fail("WebSocket canary evidence file inventory is not exact")

    stdout = _bytes(root / "controller.stdout.jsonl", MIB, "controller stdout")
    controller_stderr = _bytes(
        root / "controller.stderr.txt", MIB, "controller stderr", allow_empty=True
    )
    collector_stdout = _bytes(root / "collector.stdout.jsonl", 16 * MIB, "collector stdout")
    collector_stderr = _bytes(
        root / "collector.stderr.txt", MIB, "collector stderr", allow_empty=True
    )
    _bytes(root / "stop.request", 16, "stop request", allow_empty=True)
    etl = _bytes(root / "kernel-network.etl", 64 * MIB, "ETL")
    xml = _bytes(root / "kernel-network.xml", 64 * MIB, "decoded XML")
    rust_bytes = _bytes(
        root / "generation-verification.json", 16 * MIB, "Rust generation verification"
    )
    report = _json(
        _bytes(root / "websocket-canary.json", 2 * MIB, "WebSocket canary report"),
        "WebSocket canary report",
    )
    if tuple(report) != REPORT_KEYS:
        _fail("WebSocket canary report property set/order is invalid")
    if report["schema"] != "KernelNetworkWebSocketCanaryV1" or report["status"] != "CANDIDATE":
        _fail("WebSocket canary report status/schema is invalid")
    if not re.fullmatch(r"ws-canary-[0-9a-f]{12}", _text(report["run_id"], "run_id")):
        _fail("WebSocket canary run_id is invalid")

    started = _time(report["started_utc"], "started_utc")
    collector_started = _time(report["collector_started_utc"], "collector_started_utc")
    collector_completed = _time(report["collector_completed_utc"], "collector_completed_utc")
    completed = _time(report["completed_utc"], "completed_utc")
    if not started <= collector_started <= collector_completed <= completed:
        _fail("WebSocket canary time interval regressed")
    if report["diagnostic_only"] is not True or report["training_eligible"] is not False:
        _fail("WebSocket canary is not explicitly excluded from dataset use")

    controller_digest = _digest(report["controller_sha256"], "controller digest")
    _same_file_digest(report["controller_executable"], controller_digest, "controller executable")
    session = _text(report["session_name"], "session_name")
    if not re.fullmatch(r"BinanceKernelNetwork_[0-9a-f]{12}", session):
        _fail("WebSocket canary ETW session identity is invalid")
    _uint(report["controller_pid"], "controller PID", (1 << 32) - 1)
    if report["controller_exit_code"] != 0:
        _fail("ETW controller exit code is nonzero")
    records = _controller_records(stdout, root, session)
    if report["controller_records"] != records:
        _fail("embedded ETW controller records disagree")
    if report["controller_stderr_file"] != "controller.stderr.txt":
        _fail("controller stderr path drifted")
    if _uint(report["controller_stderr_bytes"], "controller stderr bytes") != len(controller_stderr):
        _fail("controller stderr size disagrees")
    if _digest(report["controller_stderr_sha256"], "controller stderr digest") != sha256(controller_stderr).hexdigest() or controller_stderr:
        _fail("ETW controller stderr is not exactly empty")

    collector_digest = _digest(report["collector_sha256"], "collector digest")
    _same_file_digest(report["collector_executable"], collector_digest, "collector executable")
    collector_pid = _uint(report["collector_pid"], "collector PID", (1 << 32) - 1)
    if collector_pid == 0 or report["collector_exit_code"] != 0:
        _fail("collector identity/exit code is invalid")
    if report["collector_stdout_file"] != "collector.stdout.jsonl":
        _fail("collector stdout path drifted")
    if _uint(report["collector_stdout_bytes"], "collector stdout bytes") != len(collector_stdout):
        _fail("collector stdout size disagrees")
    if _digest(report["collector_stdout_sha256"], "collector stdout digest") != sha256(collector_stdout).hexdigest():
        _fail("collector stdout digest disagrees")
    if report["collector_stderr_file"] != "collector.stderr.txt":
        _fail("collector stderr path drifted")
    if _uint(report["collector_stderr_bytes"], "collector stderr bytes") != len(collector_stderr):
        _fail("collector stderr size disagrees")
    if _digest(report["collector_stderr_sha256"], "collector stderr digest") != sha256(collector_stderr).hexdigest() or collector_stderr:
        _fail("collector stderr is not exactly empty")

    config_digest = _digest(report["public_config_sha256"], "public config digest")
    _same_file_digest(report["public_config"], config_digest, "public config")
    verifier_digest = _digest(report["generation_verifier_sha256"], "generation verifier digest")
    _same_file_digest(
        report["generation_verifier_executable"],
        verifier_digest,
        "generation verifier executable",
    )
    if report["generation_verifier_exit_code"] != 0:
        _fail("generation verifier exit code is nonzero")
    if (
        report["symbol"] != "BTCUSDT"
        or report["generation_index"] != 0
        or report["duration_s"] != 30
        or report["segment_s"] != 10
        or report["websocket_host"] != "data-stream.binance.vision"
        or report["websocket_port"] != 443
    ):
        _fail("public WebSocket canary identity/timing drifted")
    dns_addresses = _strict_ip_list(report["dns_addresses"])

    generation_root = Path(_text(report["generation_directory"], "generation directory")).resolve(strict=True)
    try:
        collector_lines = collector_stdout.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as error:
        _fail(f"collector stdout is not UTF-8: {error}")
    if len(collector_lines) != 1:
        _fail("collector stdout is not exactly one generation path")
    try:
        emitted_generation = Path(collector_lines[0]).resolve(strict=True)
    except OSError as error:
        _fail(f"collector stdout generation path is invalid: {error}")
    if emitted_generation != generation_root:
        _fail("collector stdout does not identify the verified generation")
    if report["generation_verification_file"] != "generation-verification.json":
        _fail("Rust generation verification path drifted")
    if _uint(report["generation_verification_bytes"], "Rust verification bytes") != len(rust_bytes):
        _fail("Rust generation verification size disagrees")
    if _digest(report["generation_verification_sha256"], "Rust verification digest") != sha256(rust_bytes).hexdigest():
        _fail("Rust generation verification digest disagrees")
    rust_report = _json(rust_bytes, "Rust generation verification")
    _verify_rust_generation_report(rust_report, generation_root, collector_digest, config_digest)
    try:
        python_report = verify_segmented_generation(generation_root)
    except SegmentChainCorruption as error:
        _fail(f"independent Python generation verification failed: {error}")
    if (
        python_report.get("schema") != "SegmentedGenerationVerificationV1"
        or python_report.get("status") != "VERIFIED"
        or python_report.get("symbol") != "BTCUSDT"
        or python_report.get("generation_index") != 0
        or python_report.get("collector_executable_sha256") != collector_digest
        or python_report.get("public_config_sha256") != config_digest
    ):
        _fail("independent Python generation identity disagrees")

    if report["etl_file"] != "kernel-network.etl" or _uint(report["etl_bytes"], "ETL bytes") != len(etl):
        _fail("ETL size/path metadata disagrees")
    if _digest(report["etl_sha256"], "ETL digest") != sha256(etl).hexdigest():
        _fail("ETL digest disagrees")
    if report["decoded_file"] != "kernel-network.xml" or _uint(report["decoded_bytes"], "XML bytes") != len(xml):
        _fail("decoded XML size/path metadata disagrees")
    if _digest(report["decoded_sha256"], "XML digest") != sha256(xml).hexdigest():
        _fail("decoded XML digest disagrees")
    if report["tracerpt_exit_code"] != 0:
        _fail("tracerpt exit code is nonzero")
    _lines(report["tracerpt_output"], "tracerpt output")
    if not isinstance(report["orphan_query_exit_code"], int) or report["orphan_query_exit_code"] == 0:
        _fail("orphan-session query did not prove absence")
    _lines(report["orphan_query_output"], "orphan query output")
    if tuple(report["selected_event_ids"]) != SELECTED_EVENT_IDS:
        _fail("WebSocket canary event-ID allowlist drifted")
    if report["raw_packet_payload_capture"] is not False:
        _fail("raw packet payload capture is not disabled")
    if report["correlation_status"] != "OPEN_PENDING_INDEPENDENT_VERIFY":
        _fail("producer made an unauthorized correlation claim")

    events = _parse_kernel_events(xml)
    attempts, endpoint_keys = _correlate_websocket_attempts(
        events,
        collector_pid,
        dns_addresses,
        collector_started,
        collector_completed,
    )

    counts: dict[str, int] = {}
    for event in events:
        key = str(event["event_id"])
        counts[key] = counts.get(key, 0) + 1
    return {
        "schema": "KernelNetworkWebSocketVerificationV1",
        "status": "PASS",
        "run_id": report["run_id"],
        "root": str(root),
        "diagnostic_only": True,
        "training_eligible": False,
        "generation_directory": str(generation_root),
        "rust_generation_status": "PASS",
        "python_generation_status": "VERIFIED",
        "collector_pid": collector_pid,
        "dns_addresses": dns_addresses,
        "selected_kernel_event_count": len(events),
        "selected_event_counts": counts,
        "event_filter_leaks": 0,
        "events_lost": 0,
        "log_buffers_lost": 0,
        "realtime_buffers_lost": 0,
        "raw_packet_payload_capture": False,
        "tcp_attempt_correlations": len(attempts),
        "distinct_attempt_endpoints": len(endpoint_keys),
        "correlation_status": "EXACT_COLLECTOR_PID_WEBSOCKET_ATTEMPT_AND_APPLICATION_SUCCESS_PASS",
    }
