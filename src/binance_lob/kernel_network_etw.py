"""Independent verifier for the bounded filtered Kernel-Network ETW smoke."""

from __future__ import annotations

from datetime import datetime
from datetime import timedelta
from hashlib import sha256
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
from typing import Any
import xml.etree.ElementTree as ET


MIB = 1024 * 1024
PROVIDER_GUID = "7dd42a49-5329-4832-8dfd-43d979153a88"
SELECTED_EVENT_IDS = (12, 13, 14, 15, 16, 17, 28, 29, 30, 31, 32)
MATCH_ANY_KEYWORD = "0x0000000000000030"
EXPECTED_FILES = {
    "controller.stdout.jsonl",
    "controller.stderr.txt",
    "fault-smoke.json",
    "kernel-network.etl",
    "kernel-network.xml",
    "stop.request",
}
REPORT_KEYS = (
    "schema",
    "run_id",
    "status",
    "started_utc",
    "completed_utc",
    "controller_executable",
    "controller_sha256",
    "session_name",
    "controller_records",
    "controller_stderr_bytes",
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
    "deterministic_fault_evidence_root",
    "deterministic_fault_report",
    "deterministic_fault_report_sha256",
    "deterministic_faults",
    "selected_event_ids",
    "raw_packet_payload_capture",
    "correlation_status",
)


class KernelNetworkEtwCorruption(ValueError):
    """Raised when filtered ETW evidence violates its exact contract."""


def _fail(message: str) -> None:
    raise KernelNetworkEtwCorruption(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def _json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{label} is not strict JSON: {error}")
    if not isinstance(value, dict):
        _fail(f"{label} is not an object")
    return value


def _regular_root(path: Path) -> Path:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            status = os.lstat(current)
        except OSError as error:
            _fail(f"cannot stat filtered ETW path component {current}: {error}")
        if getattr(status, "st_file_attributes", 0) & 0x400 or current.is_symlink():
            _fail("filtered ETW root contains a reparse point")
    resolved = absolute.resolve(strict=True)
    if not resolved.is_dir():
        _fail("filtered ETW root is not a directory")
    return resolved


def _bytes(path: Path, maximum: int, label: str, *, allow_empty: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} is not a regular non-link file")
    value = path.read_bytes()
    if (not value and not allow_empty) or len(value) > maximum:
        _fail(f"{label} is empty or oversized")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        _fail(f"{label} is not a non-empty string")
    return value


def _uint(value: Any, label: str, maximum: int = (1 << 64) - 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        _fail(f"{label} is outside its unsigned integer contract")
    return value


def _digest(value: Any, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        _fail(f"{label} is not a lowercase SHA-256")
    return result


def _time(value: Any, label: str) -> datetime:
    text = _text(value, label)
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        _fail(f"{label} is not ISO-8601: {error}")


def _lines(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 4096 or any(not isinstance(line, str) for line in value):
        _fail(f"{label} is not a bounded string array")
    return value


def _stats(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "number_of_buffers",
        "free_buffers",
        "events_lost",
        "buffers_written",
        "log_buffers_lost",
        "realtime_buffers_lost",
    }:
        _fail(f"{label} statistics inventory is invalid")
    for key, item in value.items():
        _uint(item, f"{label}.{key}", (1 << 32) - 1)
    for key in ("events_lost", "log_buffers_lost", "realtime_buffers_lost"):
        if value[key] != 0:
            _fail(f"{label}.{key} is nonzero")
    return value


def _controller_records(data: bytes, root: Path, session_name: str) -> list[dict[str, Any]]:
    try:
        lines = data.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as error:
        _fail(f"controller stdout is not UTF-8: {error}")
    if len(lines) != 2:
        _fail("controller stdout is not exactly READY then SEALED")
    records = [_json(line.encode("utf-8"), f"controller line {index}") for index, line in enumerate(lines)]
    ready, seal = records
    if ready.get("schema") != "KernelNetworkTraceReadyV1" or ready.get("status") != "READY":
        _fail("controller READY record is invalid")
    if seal.get("schema") != "KernelNetworkTraceSealV1" or seal.get("status") != "SEALED":
        _fail("controller SEAL record is invalid")
    if ready.get("session_name") != session_name or seal.get("session_name") != session_name:
        _fail("controller session identity drifted")
    expected_etl = (root / "kernel-network.etl").resolve()
    if Path(_text(ready.get("etl_path"), "READY ETL path")).resolve() != expected_etl:
        _fail("READY ETL path is outside the evidence root")
    if Path(_text(seal.get("etl_path"), "SEAL ETL path")).resolve() != expected_etl:
        _fail("SEAL ETL path is outside the evidence root")
    if tuple(ready.get("event_ids", ())) != SELECTED_EVENT_IDS:
        _fail("READY event-ID allowlist drifted")
    if ready.get("match_any_keyword") != MATCH_ANY_KEYWORD:
        _fail("READY keyword filter drifted")
    if seal.get("stop_reason") != "STOP_FILE":
        _fail("controller did not seal from the explicit stop request")
    _uint(seal.get("elapsed_ms"), "controller elapsed_ms")
    _stats(ready.get("statistics"), "READY")
    _stats(seal.get("statistics"), "SEAL")
    return records


def _parse_kernel_events(xml_bytes: bytes) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as error:
        _fail(f"decoded ETW XML is invalid: {error}")
    namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    events: list[dict[str, Any]] = []
    for event in root.findall(f"{namespace}Event"):
        system = event.find(f"{namespace}System")
        if system is None:
            continue
        provider = system.find(f"{namespace}Provider")
        if provider is None:
            continue
        guid = provider.attrib.get("Guid", "").strip("{}").lower()
        if guid != PROVIDER_GUID:
            continue
        if provider.attrib.get("Name") != "Microsoft-Windows-Kernel-Network":
            _fail("Kernel-Network provider name/GUID disagreement")
        event_id_node = system.find(f"{namespace}EventID")
        if event_id_node is None or event_id_node.text is None:
            _fail("Kernel-Network event has no event ID")
        try:
            event_id = int(event_id_node.text.strip())
        except ValueError:
            _fail("Kernel-Network event ID is not numeric")
        if event_id not in SELECTED_EVENT_IDS:
            _fail(f"provider-side event filter leaked event ID {event_id}")
        execution = system.find(f"{namespace}Execution")
        if execution is None:
            _fail("Kernel-Network event has no execution identity")
        try:
            header_process_id = int(execution.attrib["ProcessID"])
        except (KeyError, ValueError):
            _fail("Kernel-Network ProcessID is invalid")
        created = system.find(f"{namespace}TimeCreated")
        if created is None or "SystemTime" not in created.attrib:
            _fail("Kernel-Network event has no SystemTime")
        observed_time = _time(created.attrib["SystemTime"], "Kernel-Network SystemTime")
        data_fields: dict[str, str] = {}
        event_data = event.find(f"{namespace}EventData")
        if event_data is not None:
            for item in event_data.findall(f"{namespace}Data"):
                name = item.attrib.get("Name")
                if not name or name in data_fields:
                    _fail("Kernel-Network EventData has an empty or duplicate name")
                data_fields[name] = (item.text or "").strip()
        # The installed Microsoft-Windows-Kernel-Network manifest is the
        # event-payload authority.  Event 17 (TCPv4 connection-attempt failed)
        # contains exactly Proto and FailureCode; it has no provider PID or
        # endpoints.  EVENT_HEADER.ProcessId is a different identity and must
        # never be substituted for an absent provider payload PID.
        payload_process_id: int | None
        if event_id == 17:
            if set(data_fields) != {"Proto", "FailureCode"}:
                _fail("Kernel-Network event 17 payload schema differs")
            try:
                protocol = int(data_fields["Proto"])
                failure_code = int(data_fields["FailureCode"])
            except ValueError:
                _fail("Kernel-Network event 17 payload is not numeric")
            if not 0 <= protocol <= 255 or not 0 <= failure_code <= (1 << 32) - 1:
                _fail("Kernel-Network event 17 payload is outside bounds")
            payload_process_id = None
        else:
            if "PID" not in data_fields:
                _fail("Kernel-Network PID-bearing event has no provider payload PID")
            try:
                payload_process_id = int(data_fields["PID"])
            except ValueError:
                _fail("Kernel-Network payload PID is invalid")
            if not 0 < payload_process_id <= (1 << 32) - 1:
                _fail("Kernel-Network payload PID is outside uint32 or zero")
        for address_field in ("saddr", "daddr"):
            if address_field in data_fields:
                try:
                    ip_address(data_fields[address_field])
                except ValueError:
                    _fail(f"Kernel-Network {address_field} is invalid")
        for port_field in ("sport", "dport"):
            if port_field in data_fields:
                try:
                    port = int(data_fields[port_field])
                except ValueError:
                    _fail(f"Kernel-Network {port_field} is invalid")
                if not 0 <= port <= 65535:
                    _fail(f"Kernel-Network {port_field} is outside uint16")
        events.append(
            {
                "event_id": event_id,
                # EVENT_HEADER.ProcessId identifies the context that logged the
                # event. Kernel-Network separately declares PID only for the
                # event schemas that carry it. Preserve both; correlate only a
                # present provider PID and never manufacture one for event 17.
                "process_id": payload_process_id,
                "header_process_id": header_process_id,
                "payload_process_id": payload_process_id,
                "system_time": observed_time.isoformat(),
                "fields": data_fields,
            }
        )
    if not events:
        _fail("decoded ETW contains no selected Kernel-Network event")
    return events


def _correlate_faults(events: list[dict[str, Any]], faults: list[dict[str, Any]]) -> list[dict[str, Any]]:
    correlations: list[dict[str, Any]] = []
    for fault in faults:
        name = _text(fault.get("name"), "fault name")
        server_port = _uint(fault.get("port"), f"{name} server port", 65535)
        client_port = _uint(fault.get("client_port"), f"{name} client port", 65535)
        process_id = _uint(fault.get("process_id"), f"{name} process ID", (1 << 32) - 1)
        if server_port == 0 or client_port == 0 or process_id == 0 or server_port == client_port:
            _fail(f"{name} has invalid endpoint/process identity")
        started = _time(fault.get("started_utc"), f"{name} started_utc")
        completed = _time(fault.get("completed_utc"), f"{name} completed_utc")
        if completed < started:
            _fail(f"{name} interval regressed")
        lower = started - timedelta(seconds=1)
        upper = completed + timedelta(seconds=1)
        matches: list[dict[str, Any]] = []
        for event in events:
            fields = event["fields"]
            try:
                observed_ports = {int(fields["sport"]), int(fields["dport"])}
            except (KeyError, ValueError):
                continue
            observed_time = _time(event["system_time"], "event system_time")
            if (
                observed_ports == {server_port, client_port}
                and event["process_id"] == process_id
                and lower <= observed_time <= upper
            ):
                matches.append(event)
        if not matches:
            _fail(f"{name} has no exact PID/endpoint/time Kernel-Network correlation")
        correlations.append(
            {
                "name": name,
                "process_id": process_id,
                "server_port": server_port,
                "client_port": client_port,
                "matching_event_ids": sorted({event["event_id"] for event in matches}),
                "matching_event_count": len(matches),
            }
        )
    return correlations


def verify_kernel_network_etw(root: Path) -> dict[str, Any]:
    """Verify filtered ETW lifecycle evidence without trusting its producer."""

    root = _regular_root(root)
    if {entry.name for entry in root.iterdir()} != EXPECTED_FILES:
        _fail("filtered ETW file inventory is not exact")
    stdout_bytes = _bytes(root / "controller.stdout.jsonl", MIB, "controller stdout")
    stderr_bytes = _bytes(root / "controller.stderr.txt", MIB, "controller stderr", allow_empty=True)
    _bytes(root / "stop.request", 16, "stop request", allow_empty=True)
    etl_bytes = _bytes(root / "kernel-network.etl", 64 * MIB, "ETL")
    xml_bytes = _bytes(root / "kernel-network.xml", 32 * MIB, "decoded XML")
    report_bytes = _bytes(root / "fault-smoke.json", MIB, "fault report")
    report = _json(report_bytes, "fault report")
    if tuple(report) != REPORT_KEYS:
        _fail("fault report property set/order is invalid")
    if report["schema"] != "KernelNetworkTraceFaultSmokeV1" or report["status"] != "PASS":
        _fail("fault report status/schema is invalid")
    if not re.fullmatch(r"etw-fault-[0-9a-f]{12}", _text(report["run_id"], "run_id")):
        _fail("filtered ETW run_id is invalid")
    if _time(report["completed_utc"], "completed_utc") < _time(report["started_utc"], "started_utc"):
        _fail("filtered ETW time interval regressed")
    _digest(report["controller_sha256"], "controller digest")
    session_name = _text(report["session_name"], "session_name")
    if not re.fullmatch(r"BinanceKernelNetwork_[0-9a-f]{12}", session_name):
        _fail("filtered ETW session_name is invalid")
    records = _controller_records(stdout_bytes, root, session_name)
    if report["controller_records"] != records:
        _fail("fault report does not embed the exact controller records")
    if _uint(report["controller_stderr_bytes"], "stderr bytes") != len(stderr_bytes) or stderr_bytes:
        _fail("controller stderr is not exactly empty")
    if report["etl_file"] != "kernel-network.etl" or _uint(report["etl_bytes"], "ETL bytes") != len(etl_bytes):
        _fail("ETL size/path metadata disagrees")
    if _digest(report["etl_sha256"], "ETL digest") != sha256(etl_bytes).hexdigest():
        _fail("ETL digest disagrees")
    if report["decoded_file"] != "kernel-network.xml" or _uint(report["decoded_bytes"], "XML bytes") != len(xml_bytes):
        _fail("decoded XML size/path metadata disagrees")
    if _digest(report["decoded_sha256"], "XML digest") != sha256(xml_bytes).hexdigest():
        _fail("decoded XML digest disagrees")
    if report["tracerpt_exit_code"] != 0:
        _fail("tracerpt exit code is nonzero")
    _lines(report["tracerpt_output"], "tracerpt output")
    if not isinstance(report["orphan_query_exit_code"], int) or report["orphan_query_exit_code"] == 0:
        _fail("orphan-session query did not prove absence")
    _lines(report["orphan_query_output"], "orphan query output")
    if tuple(report["selected_event_ids"]) != SELECTED_EVENT_IDS:
        _fail("fault report event-ID allowlist drifted")
    if report["raw_packet_payload_capture"] is not False:
        _fail("raw packet payload capture is not disabled")
    if report["correlation_status"] != "OPEN_PENDING_SEMANTIC_DECODE":
        _fail("unexpected correlation claim")

    inner_path = Path(_text(report["deterministic_fault_report"], "deterministic fault report")).resolve(strict=True)
    inner_bytes = _bytes(inner_path, MIB, "deterministic fault report")
    if _digest(report["deterministic_fault_report_sha256"], "deterministic report digest") != sha256(inner_bytes).hexdigest():
        _fail("deterministic fault report digest disagrees")
    inner = _json(inner_bytes, "deterministic fault report")
    if inner.get("status") != "PASS" or not isinstance(inner.get("faults"), list):
        _fail("deterministic fault report is not PASS")
    if report["deterministic_faults"] != inner["faults"]:
        _fail("embedded deterministic faults disagree with their hashed source")
    if any(not isinstance(fault, dict) or fault.get("status") != "PASS" for fault in inner["faults"]):
        _fail("a deterministic application fault did not pass")

    events = _parse_kernel_events(xml_bytes)
    correlations = _correlate_faults(events, inner["faults"])
    counts: dict[str, int] = {}
    for event in events:
        key = str(event["event_id"])
        counts[key] = counts.get(key, 0) + 1
    return {
        "schema": "KernelNetworkTraceVerificationV1",
        "status": "PASS",
        "run_id": report["run_id"],
        "root": str(root),
        "etl_sha256": report["etl_sha256"],
        "decoded_sha256": report["decoded_sha256"],
        "selected_kernel_event_count": len(events),
        "selected_event_counts": counts,
        "event_filter_leaks": 0,
        "events_lost": 0,
        "log_buffers_lost": 0,
        "realtime_buffers_lost": 0,
        "raw_packet_payload_capture": False,
        "fault_correlations": correlations,
        "correlation_status": "EXACT_PID_ENDPOINT_TIME_CORRELATION_PASS",
    }
