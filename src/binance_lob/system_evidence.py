"""Independent verifier for bounded Windows host/system evidence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


MIB = 1024 * 1024
EXPECTED_FILES = {"system-evidence.json", "system-evidence-seal.json"}
SYSTEM_PROVIDERS = [
    "Microsoft-Windows-Kernel-Power",
    "Microsoft-Windows-Power-Troubleshooter",
    "Microsoft-Windows-NDIS",
    "Microsoft-Windows-TCPIP",
    "Tcpip",
    "Microsoft-Windows-WHEA-Logger",
    "Microsoft-Windows-Ntfs",
    "Ntfs",
    "disk",
    "stornvme",
    "storahci",
    "Microsoft-Windows-Eventlog",
    "Microsoft-Windows-Time-Service",
    "Service Control Manager",
]
APPLICATION_PROVIDERS = ["Application Error", "Application Hang", "Windows Error Reporting"]
EVIDENCE_KEYS = (
    "schema", "run_id", "status", "collected_utc", "collected_qpc_timestamp",
    "qpc_frequency", "requested_start_utc", "requested_end_utc",
    "maximum_events_per_log", "maximum_artifact_mib", "collector_pid",
    "computer_name", "os_last_boot_utc", "os_version", "os_build_number",
    "system_manufacturer", "system_model", "adapters", "log_coverage",
    "event_queries", "inference_boundary",
)
ADAPTER_KEYS = (
    "interface_guid", "interface_index", "name", "interface_description", "status",
    "media_connection_state", "link_speed", "driver_information", "driver_file_name",
    "driver_version", "driver_date", "ndis_version", "connector_present", "virtual",
)
COVERAGE_KEYS = (
    "log_name", "query_status", "is_enabled", "log_mode", "maximum_size_bytes",
    "record_count", "oldest_available_utc", "newest_available_utc",
    "requested_start_is_covered", "error",
)
QUERY_KEYS = (
    "log_name", "query_status", "requested_provider_names", "returned_events",
    "maximum_events", "result_limit_reached", "xml_bytes", "errors", "events",
)
EVENT_KEYS = (
    "log_name", "provider_name", "event_id", "level", "record_id",
    "time_created_utc", "process_id", "thread_id", "xml",
)
SEAL_KEYS = (
    "schema", "run_id", "status", "evidence_file", "evidence_bytes",
    "evidence_sha256", "sealed_utc",
)


class SystemEvidenceCorruption(ValueError):
    """Raised when host/system evidence violates its exact contract."""


def _fail(message: str) -> None:
    raise SystemEvidenceCorruption(message)


def _keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or tuple(value) != expected:
        _fail(f"{label} property set/order is invalid")
    return value


def _text(value: Any, label: str, *, maximum: int = 131072) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail(f"{label} is not a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        _fail(f"{label} exceeds its UTF-8 allowance")
    return value


def _optional_text(value: Any, label: str, *, maximum: int = 131072) -> str | None:
    if value is None:
        return None
    return _text(value, label, maximum=maximum)


def _inventory_text(value: Any, label: str, *, maximum: int = 8192) -> str | None:
    """Accept absent/empty fields that Windows legitimately omits for hidden adapters."""
    if value is None:
        return None
    if not isinstance(value, str) or "\x00" in value or len(value.encode("utf-8")) > maximum:
        _fail(f"{label} is not bounded inventory text")
    return value


def _uint(value: Any, label: str, minimum: int = 0, maximum: int = (1 << 64) - 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        _fail(f"{label} is outside its unsigned integer contract")
    return value


def _optional_uint(value: Any, label: str, maximum: int = (1 << 64) - 1) -> int | None:
    if value is None:
        return None
    return _uint(value, label, maximum=maximum)


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        _fail(f"{label} is not boolean")
    return value


def _utc(value: Any, label: str) -> datetime:
    text = _text(value, label, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        _fail(f"{label} is not ISO-8601: {error}")
    if parsed.tzinfo is None:
        _fail(f"{label} has no UTC offset")
    return parsed.astimezone(timezone.utc)


def _optional_utc(value: Any, label: str) -> datetime | None:
    return None if value is None else _utc(value, label)


def _digest(value: Any, label: str) -> str:
    result = _text(value, label, maximum=64)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        _fail(f"{label} is not lowercase SHA-256")
    return result


def _root(path: Path) -> Path:
    candidate = path.absolute()
    current = Path(candidate.anchor)
    for component in candidate.parts[1:]:
        current /= component
        try:
            status = os.lstat(current)
        except OSError as error:
            _fail(f"cannot stat system evidence path component: {error}")
        if current.is_symlink() or getattr(status, "st_file_attributes", 0) & 0x400:
            _fail("system evidence path contains a reparse point")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        _fail("system evidence root is not a directory")
    if {entry.name for entry in resolved.iterdir()} != EXPECTED_FILES:
        _fail("system evidence inventory is not exact")
    return resolved


def _json_bytes(path: Path, maximum: int, label: str) -> tuple[bytes, dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} is not a regular file")
    data = path.read_bytes()
    if not data or len(data) > maximum:
        _fail(f"{label} is empty or oversized")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{label} is not strict UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        _fail(f"{label} is not an object")
    return data, value


def _event_xml(event: dict[str, Any], label: str) -> None:
    xml = _text(event["xml"], f"{label} XML")
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as error:
        _fail(f"{label} XML is malformed: {error}")
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", namespace)
    if system is None:
        _fail(f"{label} XML has no System element")
    provider = system.find("e:Provider", namespace)
    event_id = system.find("e:EventID", namespace)
    if provider is None or event_id is None:
        _fail(f"{label} XML lacks provider or event id")
    if provider.attrib.get("Name") != event["provider_name"]:
        _fail(f"{label} provider differs from XML")
    try:
        xml_event_id = int(event_id.text or "")
    except ValueError:
        _fail(f"{label} XML event id is invalid")
    if xml_event_id != event["event_id"]:
        _fail(f"{label} event id differs from XML")
    comparisons = (
        ("e:Level", "level"),
        ("e:EventRecordID", "record_id"),
    )
    for xpath, field in comparisons:
        node = system.find(xpath, namespace)
        xml_value = None if node is None or node.text is None else int(node.text)
        if xml_value != event[field]:
            _fail(f"{label} {field} differs from XML")
    created = system.find("e:TimeCreated", namespace)
    xml_time = None if created is None else created.attrib.get("SystemTime")
    if (xml_time is None) != (event["time_created_utc"] is None):
        _fail(f"{label} timestamp presence differs from XML")
    if xml_time is not None and _utc(xml_time, f"{label} XML time") != _utc(event["time_created_utc"], f"{label} time"):
        _fail(f"{label} timestamp differs from XML")
    execution = system.find("e:Execution", namespace)
    for attribute, field in (("ProcessID", "process_id"), ("ThreadID", "thread_id")):
        xml_value = None if execution is None or attribute not in execution.attrib else int(execution.attrib[attribute])
        if xml_value != event[field]:
            _fail(f"{label} {field} differs from XML")


def verify_system_evidence(root: Path) -> dict[str, Any]:
    """Verify sealed host evidence without trusting its PowerShell producer."""

    root = _root(root)
    seal_bytes, seal = _json_bytes(root / "system-evidence-seal.json", MIB, "seal")
    _keys(seal, SEAL_KEYS, "seal")
    if seal["schema"] != "RawQualificationSystemEvidenceSealV1" or seal["status"] != "SEALED":
        _fail("system evidence seal lifecycle is invalid")
    maximum_evidence = 32 * MIB
    evidence_bytes, evidence = _json_bytes(root / "system-evidence.json", maximum_evidence, "evidence")
    _keys(evidence, EVIDENCE_KEYS, "evidence")
    run_id = _text(evidence["run_id"], "run id", maximum=128)
    if not run_id[0].isalnum() or any(not (character.isalnum() or character == "-") for character in run_id):
        _fail("run id violates its lexical contract")
    if (
        evidence["schema"] != "RawQualificationSystemEvidenceV1"
        or evidence["status"] not in {"COMPLETE", "INSUFFICIENT_COVERAGE"}
        or seal["run_id"] != run_id
        or seal["evidence_file"] != "system-evidence.json"
    ):
        _fail("system evidence identity/lifecycle is invalid")
    artifact_mib = _uint(evidence["maximum_artifact_mib"], "maximum artifact MiB", 1, 32)
    if len(evidence_bytes) > artifact_mib * MIB:
        _fail("evidence exceeds its declared allowance")
    if _uint(seal["evidence_bytes"], "sealed evidence bytes", 1) != len(evidence_bytes):
        _fail("sealed evidence length differs")
    evidence_digest = sha256(evidence_bytes).hexdigest()
    if _digest(seal["evidence_sha256"], "sealed evidence digest") != evidence_digest:
        _fail("sealed evidence digest differs")
    collected = _utc(evidence["collected_utc"], "collected UTC")
    sealed = _utc(seal["sealed_utc"], "sealed UTC")
    start = _utc(evidence["requested_start_utc"], "requested start UTC")
    end = _utc(evidence["requested_end_utc"], "requested end UTC")
    if not start < end <= collected <= sealed or end - start > timedelta(days=8):
        _fail("system evidence time ordering is invalid")
    _uint(evidence["collected_qpc_timestamp"], "collected QPC")
    _uint(evidence["qpc_frequency"], "QPC frequency", 1)
    maximum_events = _uint(evidence["maximum_events_per_log"], "maximum events", 1, 4096)
    _uint(evidence["collector_pid"], "collector PID", 1, (1 << 32) - 1)
    for field in ("computer_name", "os_version", "os_build_number", "system_manufacturer", "system_model", "inference_boundary"):
        _text(evidence[field], field, maximum=8192)
    _utc(evidence["os_last_boot_utc"], "OS last boot UTC")

    adapters = evidence["adapters"]
    if not isinstance(adapters, list) or not adapters or len(adapters) > 1024:
        _fail("adapter inventory is empty or oversized")
    adapter_ids: set[tuple[str, int]] = set()
    for index, adapter_value in enumerate(adapters):
        adapter = _keys(adapter_value, ADAPTER_KEYS, f"adapter {index}")
        identity = (_text(adapter["interface_guid"], f"adapter {index} GUID", maximum=128), _uint(adapter["interface_index"], f"adapter {index} index", maximum=(1 << 32) - 1))
        if identity in adapter_ids:
            _fail("adapter inventory has a duplicate identity")
        adapter_ids.add(identity)
        for field in ("name", "status", "media_connection_state", "link_speed", "driver_information"):
            _text(adapter[field], f"adapter {index} {field}", maximum=8192)
        for field in ("interface_description", "driver_file_name", "driver_version", "ndis_version"):
            _inventory_text(adapter[field], f"adapter {index} {field}")
        _optional_utc(adapter["driver_date"], f"adapter {index} driver date")
        _boolean(adapter["connector_present"], f"adapter {index} connector")
        _boolean(adapter["virtual"], f"adapter {index} virtual")

    coverage = evidence["log_coverage"]
    if not isinstance(coverage, list) or [item.get("log_name") for item in coverage if isinstance(item, dict)] != ["System", "Application"]:
        _fail("log coverage inventory is not exact")
    coverage_complete = True
    for index, item in enumerate(coverage):
        entry = _keys(item, COVERAGE_KEYS, f"coverage {index}")
        if entry["query_status"] not in {"PASS", "FAILED"}:
            _fail("coverage query status is invalid")
        covered = _boolean(entry["requested_start_is_covered"], f"coverage {index} covered")
        if entry["query_status"] == "PASS":
            enabled = _boolean(entry["is_enabled"], f"coverage {index} enabled")
            _text(entry["log_mode"], f"coverage {index} log mode", maximum=128)
            _uint(entry["maximum_size_bytes"], f"coverage {index} maximum size", 1)
            _optional_uint(entry["record_count"], f"coverage {index} record count")
            oldest = _optional_utc(entry["oldest_available_utc"], f"coverage {index} oldest")
            newest = _optional_utc(entry["newest_available_utc"], f"coverage {index} newest")
            if oldest is not None and newest is not None and oldest > newest:
                _fail("log coverage timestamps regress")
            if covered != (oldest is not None and oldest <= start):
                _fail("requested-start coverage contradicts oldest retained event")
            if entry["error"] is not None:
                _fail("successful coverage contains an error")
            coverage_complete &= enabled and covered
        else:
            _text(entry["error"], f"coverage {index} error", maximum=4096)
            coverage_complete = False

    queries = evidence["event_queries"]
    expected_queries = [("System", SYSTEM_PROVIDERS), ("Application", APPLICATION_PROVIDERS)]
    if not isinstance(queries, list) or len(queries) != len(expected_queries):
        _fail("event query inventory is not exact")
    queries_complete = True
    for query_index, (query_value, (log_name, providers)) in enumerate(zip(queries, expected_queries, strict=True)):
        query = _keys(query_value, QUERY_KEYS, f"query {query_index}")
        if query["log_name"] != log_name or query["requested_provider_names"] != providers:
            _fail("event query policy differs")
        if query["query_status"] not in {"PASS", "FAILED"}:
            _fail("event query status is invalid")
        if _uint(query["maximum_events"], "query maximum events", 1, 4096) != maximum_events:
            _fail("event query maximum differs")
        limited = _boolean(query["result_limit_reached"], "query result limit")
        errors = query["errors"]
        events = query["events"]
        if not isinstance(errors, list) or any(not isinstance(error, str) or not error for error in errors):
            _fail("event query errors are invalid")
        if not isinstance(events, list) or len(events) > maximum_events:
            _fail("event query results are oversized")
        if _uint(query["returned_events"], "returned events") != len(events):
            _fail("returned event count differs")
        if limited != (len(events) == maximum_events):
            _fail("event limit marker is inconsistent")
        calculated_xml_bytes = 0
        ordering: list[tuple[datetime, int]] = []
        for event_index, event_value in enumerate(events):
            event = _keys(event_value, EVENT_KEYS, f"event {query_index}:{event_index}")
            if event["log_name"] != log_name or event["provider_name"] not in providers:
                _fail("event escaped its query policy")
            _uint(event["event_id"], "event id", maximum=(1 << 32) - 1)
            _optional_uint(event["level"], "event level", maximum=(1 << 32) - 1)
            record_id = _optional_uint(event["record_id"], "event record id")
            event_time = _optional_utc(event["time_created_utc"], "event time")
            _optional_uint(event["process_id"], "event process id", maximum=(1 << 32) - 1)
            _optional_uint(event["thread_id"], "event thread id", maximum=(1 << 32) - 1)
            if event_time is not None and not start <= event_time <= end:
                _fail("event is outside the requested interval")
            if event_time is not None:
                ordering.append((event_time, -1 if record_id is None else record_id))
            calculated_xml_bytes += len(_text(event["xml"], "event XML").encode("utf-8"))
            _event_xml(event, f"event {query_index}:{event_index}")
        if ordering != sorted(ordering):
            _fail("events are not chronologically ordered")
        if _uint(query["xml_bytes"], "query XML bytes") != calculated_xml_bytes:
            _fail("event XML byte total differs")
        if query["query_status"] == "PASS" and errors:
            _fail("successful event query contains errors")
        if query["query_status"] == "FAILED" and not errors:
            _fail("failed event query has no error")
        queries_complete &= query["query_status"] == "PASS" and not limited

    expected_status = "COMPLETE" if coverage_complete and queries_complete else "INSUFFICIENT_COVERAGE"
    if evidence["status"] != expected_status:
        _fail("system evidence status contradicts measured coverage")

    return {
        "schema": "RawQualificationSystemEvidenceVerificationV1",
        "status": "PASS",
        "coverage_status": evidence["status"],
        "run_id": run_id,
        "root": str(root),
        "evidence_bytes": len(evidence_bytes),
        "evidence_sha256": evidence_digest,
        "seal_sha256": sha256(seal_bytes).hexdigest(),
        "adapter_count": len(adapters),
        "event_count": sum(len(query["events"]) for query in queries),
    }
