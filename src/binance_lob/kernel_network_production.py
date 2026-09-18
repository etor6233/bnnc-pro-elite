"""Independent verifier for production-lifecycle Kernel-Network ETW evidence.

This sidecar is diagnostic only.  It verifies the privileged controller and
sealed bytes, then exposes exact per-process TCP lifecycle observations without
turning their absence into a causal claim.
"""

from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
import json
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


EXPECTED_FILES = {
    "controller.stderr.txt",
    "controller.stdout.jsonl",
    "kernel-network-capture.json",
    "kernel-network.etl",
    "kernel-network.xml",
    "stop.request",
}
REPORT_KEYS = (
    "schema", "run_id", "status", "started_utc", "completed_utc",
    "controller_executable", "controller_sha256", "controller_pid",
    "session_name", "controller_exit_code", "controller_records",
    "controller_stderr_file", "controller_stderr_bytes", "controller_stderr_sha256",
    "maximum_file_mib", "deadline_s", "etl_file", "etl_bytes", "etl_sha256",
    "decoded_file", "decoded_bytes", "decoded_sha256", "tracerpt_exit_code",
    "tracerpt_output", "orphan_query_exit_code", "orphan_query_output",
    "monitored_processes", "selected_event_ids", "raw_packet_payload_capture",
    "diagnostic_only", "training_eligible", "correlation_status",
)
PROCESS_KEYS = (
    "role", "symbol", "pid", "interval_start_utc", "interval_end_utc",
)


class KernelNetworkProductionCorruption(ValueError):
    """Raised when production ETW evidence is incomplete or inconsistent."""


def _fail(message: str) -> None:
    raise KernelNetworkProductionCorruption(message)


def _processes(value: Any, capture_started: Any, capture_completed: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 4096:
        _fail("monitored process inventory is empty or oversized")
    result: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    capture_lower = _time(capture_started, "capture started") - timedelta(seconds=2)
    capture_upper = _time(capture_completed, "capture completed") + timedelta(seconds=2)
    for row in value:
        if not isinstance(row, dict) or tuple(row) != PROCESS_KEYS:
            _fail("monitored process property set/order is invalid")
        role = _text(row["role"], "process role")
        if role not in {"LAUNCHER", "CAMPAIGN", "COLLECTOR", "WATCHDOG"}:
            _fail("monitored process role is invalid")
        symbol = row["symbol"]
        if symbol is not None and symbol not in {"BTCUSDT", "ETHUSDT"}:
            _fail("monitored process symbol is invalid")
        pid = _uint(row["pid"], "process PID", (1 << 32) - 1)
        started = _time(row["interval_start_utc"], "process interval start")
        ended = _time(row["interval_end_utc"], "process interval end")
        identity = (pid, row["interval_start_utc"], row["interval_end_utc"])
        if pid == 0 or identity in seen or ended < started or started < capture_lower or ended > capture_upper:
            _fail("monitored process identity/interval is invalid or duplicated")
        seen.add(identity)
        result.append(row)
    if sum(row["role"] == "LAUNCHER" for row in result) != 1:
        _fail("monitored process inventory lacks one exact launcher")
    return result


def verify_kernel_network_production(root: Path) -> dict[str, Any]:
    root = _regular_root(root)
    if {entry.name for entry in root.iterdir()} != EXPECTED_FILES:
        _fail("production ETW evidence file inventory is not exact")

    stdout = _bytes(root / "controller.stdout.jsonl", MIB, "controller stdout")
    stderr = _bytes(root / "controller.stderr.txt", MIB, "controller stderr", allow_empty=True)
    _bytes(root / "stop.request", 16, "stop request", allow_empty=True)
    report_bytes = _bytes(root / "kernel-network-capture.json", 4 * MIB, "capture report")
    report = _json(report_bytes, "capture report")
    if tuple(report) != REPORT_KEYS:
        _fail("capture report property set/order is invalid")
    if report["schema"] != "KernelNetworkProductionCaptureV1" or report["status"] != "CANDIDATE":
        _fail("capture report status/schema is invalid")
    if not re.fullmatch(r"observed-[0-9a-f]{12}", _text(report["run_id"], "run_id")):
        _fail("capture run identity is invalid")
    if _time(report["completed_utc"], "completed_utc") < _time(report["started_utc"], "started_utc"):
        _fail("capture time interval regressed")

    executable = Path(_text(report["controller_executable"], "controller executable")).resolve(strict=True)
    executable_bytes = _bytes(executable, 512 * MIB, "controller executable")
    if _digest(report["controller_sha256"], "controller digest") != sha256(executable_bytes).hexdigest():
        _fail("controller executable changed after capture")
    _uint(report["controller_pid"], "controller PID", (1 << 32) - 1)
    if report["controller_exit_code"] != 0:
        _fail("controller exit code is nonzero")
    session = _text(report["session_name"], "session name")
    if not re.fullmatch(r"BinanceProduction_[0-9a-f]{12}", session):
        _fail("production ETW session identity is invalid")
    records = _controller_records(stdout, root, session)
    if report["controller_records"] != records:
        _fail("capture report does not bind exact controller records")
    if report["controller_stderr_file"] != "controller.stderr.txt":
        _fail("controller stderr identity drifted")
    if _uint(report["controller_stderr_bytes"], "controller stderr bytes") != len(stderr):
        _fail("controller stderr size disagrees")
    if _digest(report["controller_stderr_sha256"], "controller stderr digest") != sha256(stderr).hexdigest() or stderr:
        _fail("controller stderr is not exactly empty")
    maximum_mib = _uint(report["maximum_file_mib"], "maximum file MiB", 1024)
    if not 16 <= maximum_mib <= 1024:
        _fail("maximum ETW file size is outside the controller contract")
    if not 1 <= _uint(report["deadline_s"], "deadline seconds") <= 691200:
        _fail("ETW deadline is outside the controller contract")

    etl = _bytes(root / "kernel-network.etl", maximum_mib * MIB, "ETL")
    xml = _bytes(root / "kernel-network.xml", 1024 * MIB, "decoded XML")
    if report["etl_file"] != "kernel-network.etl" or report["etl_bytes"] != len(etl):
        _fail("ETL path/size metadata disagrees")
    if _digest(report["etl_sha256"], "ETL digest") != sha256(etl).hexdigest():
        _fail("ETL digest disagrees")
    if report["decoded_file"] != "kernel-network.xml" or report["decoded_bytes"] != len(xml):
        _fail("decoded XML path/size metadata disagrees")
    if _digest(report["decoded_sha256"], "decoded digest") != sha256(xml).hexdigest():
        _fail("decoded XML digest disagrees")
    if report["tracerpt_exit_code"] != 0:
        _fail("tracerpt failed")
    _lines(report["tracerpt_output"], "tracerpt output")
    if not isinstance(report["orphan_query_exit_code"], int) or report["orphan_query_exit_code"] == 0:
        _fail("named ETW session still exists after seal")
    _lines(report["orphan_query_output"], "orphan query output")
    processes = _processes(report["monitored_processes"], report["started_utc"], report["completed_utc"])
    if tuple(report["selected_event_ids"]) != SELECTED_EVENT_IDS:
        _fail("selected event inventory drifted")
    if report["raw_packet_payload_capture"] is not False:
        _fail("raw packet payload capture was enabled")
    if report["diagnostic_only"] is not True or report["training_eligible"] is not False:
        _fail("ETW diagnostic boundary was broadened")
    if report["correlation_status"] != "OPEN_PENDING_INDEPENDENT_VERIFY":
        _fail("producer made an unauthorized correlation claim")

    events = _parse_kernel_events(xml)
    summaries: list[dict[str, Any]] = []
    for process in processes:
        # Event timestamps and application publication are different clocks.
        # A fixed two-second envelope is correlation tolerance, not a claim
        # that the process existed outside its observed interval.
        lower = _time(process["interval_start_utc"], "process interval start") - timedelta(seconds=2)
        upper = _time(process["interval_end_utc"], "process interval end") + timedelta(seconds=2)
        matching = [
            event for event in events
            if event["process_id"] == process["pid"]
            and lower <= _time(event["system_time"], "event system time") <= upper
        ]
        counts: dict[str, int] = {}
        endpoints: set[tuple[Any, Any, Any, Any]] = set()
        for event in matching:
            key = str(event["event_id"])
            counts[key] = counts.get(key, 0) + 1
            fields = event["fields"]
            endpoint = (fields.get("saddr"), fields.get("sport"), fields.get("daddr"), fields.get("dport"))
            if all(endpoint):
                endpoints.add(endpoint)
        summaries.append({
            **process,
            "selected_event_count": len(matching),
            "selected_event_counts": dict(sorted(counts.items())),
            "distinct_endpoints": len(endpoints),
        })
    all_counts: dict[str, int] = {}
    for event in events:
        key = str(event["event_id"])
        all_counts[key] = all_counts.get(key, 0) + 1
    return {
        "schema": "KernelNetworkProductionVerificationV1",
        "status": "PASS",
        "run_id": report["run_id"],
        "root": str(root),
        "etl_sha256": report["etl_sha256"],
        "decoded_sha256": report["decoded_sha256"],
        "selected_kernel_event_count": len(events),
        "selected_event_counts": dict(sorted(all_counts.items())),
        "event_filter_leaks": 0,
        "events_lost": 0,
        "log_buffers_lost": 0,
        "realtime_buffers_lost": 0,
        "raw_packet_payload_capture": False,
        "process_correlations": summaries,
        "correlation_scope": "EXACT_RETAINED_PROCESS_PID_AND_KERNEL_NETWORK_EVENT_ONLY",
    }
