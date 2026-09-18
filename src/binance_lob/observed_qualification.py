"""Independent verification for the production observability envelope."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
from typing import Any

from .kernel_network_production import verify_kernel_network_production
from .network_witness import verify_network_witness
from .system_evidence import verify_system_evidence


TERMINAL_KEYS = (
    "schema", "status", "run_id", "started_utc", "finished_utc",
    "raw_qualification_root", "raw_launcher_terminal", "raw_launcher_terminal_sha256",
    "raw_launcher_status", "raw_launcher_failure", "observer_failure", "cause_domain",
    "cause_domain_boundary", "kernel_network_root", "kernel_network_verification_file",
    "kernel_network_verification_sha256", "network_witness_root",
    "network_witness_verification_file", "network_witness_verification_sha256",
    "system_evidence_root", "system_evidence_verification_file",
    "system_evidence_verification_sha256", "network_incident_file", "network_incident_sha256",
    "network_incident_classification", "etw_verification_status", "witness_verification_status",
    "system_verification_status", "implementation_lock_file", "implementation_lock_sha256",
    "implementation_lock_status", "diagnostic_only", "raw_lineage_authority", "credentials",
    "order_entry", "artifact_inventory",
)
INVENTORY_KEYS = ("path", "bytes", "sha256")
IMPLEMENTATION_LOCK_KEYS = (
    "schema", "status", "run_id", "created_utc", "wrapper_path", "wrapper_bytes",
    "wrapper_sha256", "sealed_runtime", "files", "external_runtime",
)
IMPLEMENTATION_FILE_KEYS = ("path", "bytes", "sha256")
EXTERNAL_RUNTIME_KEYS = ("name", "path", "bytes", "sha256")
EXTERNAL_RUNTIME_NAMES = ("LOGMAN", "POWERSHELL", "PYTHON", "TRACERPT")
SOCKET_CLASSES = {
    "CORRELATED_BINANCE_PATH_SPECIFIC_FAILURE_FROM_THIS_HOST",
    "CORRELATED_BINANCE_DNS_FAILURE_FROM_THIS_HOST",
    "SOCKET_SILENCE_WHILE_NEW_TCP_PROBES_WERE_REACHABLE",
    "WEBSOCKET_CLOSE_FRAME_AT_APPLICATION_BOUNDARY",
    "SOCKET_READ_ERROR_AT_APPLICATION_BOUNDARY",
    "CONNECT_FAILURE_AT_APPLICATION_BOUNDARY",
    "WEBSOCKET_UPGRADE_REJECTION_AT_APPLICATION_BOUNDARY",
    "TRANSPORT_SILENCE_CAUSE_UNRESOLVED_AT_OBSERVED_BOUNDARIES",
}
LOCAL_CLASSES = {
    "CORRELATED_LOCAL_INTERFACE_OR_ROUTE_FAILURE_FROM_THIS_HOST",
    "CORRELATED_SHARED_PATH_FAILURE_FROM_THIS_HOST",
}
CLOCK_KEYS = (
    "healthy", "leap_indicator", "stratum", "source", "last_successful_sync",
    "root_delay_s", "root_dispersion_s", "phase_offset_s", "seconds_since_last_good_sync",
    "maximum_last_good_sync_age_s", "state_machine", "last_sync_error", "poll_interval_s",
    "raw_status_sha256", "query_exit_code",
)
CLOCK_PROVIDER_EVIDENCE_KEYS = (
    "stdout_path", "stdout_bytes", "stdout_sha256", "stderr_path", "stderr_bytes", "stderr_sha256",
)
CLOCK_VIOLATIONS = {
    "QUERY_EXIT_NONZERO", "LEAP_INDICATOR_NOT_ZERO", "STRATUM_OUT_OF_RANGE",
    "SOURCE_LOCAL_OR_UNSPECIFIED", "STATE_MACHINE_NOT_SYNC", "LAST_SYNC_ERROR_NONZERO",
    "LAST_GOOD_SYNC_ABSENT_STALE_OR_NEGATIVE", "HEALTH_FLAG_CONTRADICTS_PARSED_FIELDS",
}


class ObservedQualificationCorruption(ValueError):
    pass


def _fail(message: str) -> None:
    raise ObservedQualificationCorruption(message)


def _load(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} is not a regular non-link file")
    data = path.read_bytes()
    if not data or len(data) > 64 * 1024 * 1024:
        _fail(f"{label} is empty or oversized")
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{label} is not strict JSON: {error}")
    if not isinstance(value, dict):
        _fail(f"{label} is not an object")
    return value, data


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        _fail(f"{label} is not a lowercase SHA-256")
    return value


def classify_cause_domain(
    *, observer_failure: str | None, raw_status: str | None, raw_failure: str | None = None,
    incident_classification: str | None
) -> str:
    if observer_failure is not None:
        return "OBSERVABILITY_INTERNAL_FAILURE"
    if raw_status is None:
        return "INNER_QUALIFICATION_TERMINAL_MISSING"
    if raw_status == "COMPLETE":
        return "NONE"
    if isinstance(raw_failure, str) and raw_failure.startswith("HOST_CLOCK_HEALTH_GATE_FAILED:"):
        return "HOST_TIME_SYNCHRONIZATION_FAILURE"
    if incident_classification is None:
        return "INDETERMINATE_BECAUSE_CROSS_PLANE_INCIDENT_EVIDENCE_DID_NOT_VERIFY"
    if incident_classification in LOCAL_CLASSES:
        return "HOST_OR_LOCAL_ACCESS_NETWORK_OUTSIDE_CAPTURE_PROCESS"
    if incident_classification in SOCKET_CLASSES:
        return "EXTERNAL_TO_CAPTURE_PROCESS_AT_OBSERVED_SOCKET_BOUNDARY"
    return "CAPTURE_OR_SUPERVISOR_INTERNAL_OR_NON_NETWORK_FAILURE"


def _inventory(root: Path, terminal_name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=str):
        if path.is_symlink():
            _fail("observability root contains a symbolic link")
        if not path.is_file() or path.name == terminal_name and path.parent == root:
            continue
        data = path.read_bytes()
        rows.append({
            "path": path.relative_to(root).as_posix(),
            "bytes": len(data),
            "sha256": sha256(data).hexdigest(),
        })
    return rows


def _positive_size(value: Any, label: str, maximum: int = 1024 * 1024 * 1024) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > maximum:
        _fail(f"{label} is not a bounded positive byte count")
    return value


def _clock_violation_names(clock: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    if clock["query_exit_code"] != 0:
        violations.append("QUERY_EXIT_NONZERO")
    if clock["leap_indicator"] != 0:
        violations.append("LEAP_INDICATOR_NOT_ZERO")
    if not isinstance(clock["stratum"], int) or isinstance(clock["stratum"], bool) or not 1 <= clock["stratum"] <= 15:
        violations.append("STRATUM_OUT_OF_RANGE")
    source = clock["source"]
    if not isinstance(source, str) or not source.strip() or re.search(
        r"Local CMOS|Free-running|VM IC Time Synchronization|unspecified", source, re.IGNORECASE
    ):
        violations.append("SOURCE_LOCAL_OR_UNSPECIFIED")
    if clock["state_machine"] != 2:
        violations.append("STATE_MACHINE_NOT_SYNC")
    if clock["last_sync_error"] != 0:
        violations.append("LAST_SYNC_ERROR_NONZERO")
    age = clock["seconds_since_last_good_sync"]
    maximum = clock["maximum_last_good_sync_age_s"]
    if (
        isinstance(age, bool) or not isinstance(age, (int, float))
        or isinstance(maximum, bool) or not isinstance(maximum, (int, float))
        or age < 0 or age > maximum
    ):
        violations.append("LAST_GOOD_SYNC_ABSENT_STALE_OR_NEGATIVE")
    if not violations and clock["healthy"] is not True:
        violations.append("HEALTH_FLAG_CONTRADICTS_PARSED_FIELDS")
    return violations


def _verify_host_clock_failure_evidence(raw_root: Path, failure: str) -> None:
    prefix = "HOST_CLOCK_HEALTH_GATE_FAILED: violations="
    if not failure.startswith(prefix) or "; observation=" not in failure or "; provider_evidence=" not in failure:
        _fail("structured host clock failure is incomplete")
    violation_text, remainder = failure[len(prefix):].split("; observation=", 1)
    observation_text, provider_text = remainder.rsplit("; provider_evidence=", 1)
    violations = violation_text.split(",") if violation_text else []
    if not violations or len(violations) != len(set(violations)) or any(item not in CLOCK_VIOLATIONS for item in violations):
        _fail("structured host clock failure has invalid violations")
    try:
        observation = json.loads(observation_text)
        evidence = json.loads(provider_text)
    except json.JSONDecodeError as error:
        _fail(f"structured host clock failure embeds invalid JSON: {error}")
    if not isinstance(observation, dict) or tuple(observation) != CLOCK_KEYS:
        _fail("structured host clock observation has invalid properties/order")
    if observation["healthy"] is not False or _clock_violation_names(observation) != violations:
        _fail("structured host clock violations disagree with the observation")
    if not isinstance(evidence, dict) or tuple(evidence) != CLOCK_PROVIDER_EVIDENCE_KEYS:
        _fail("structured host clock provider evidence has invalid properties/order")
    expected_names = {
        "stdout_path": re.compile(r"^host-probes/host-[0-9]{6}\.stdout\.json$"),
        "stderr_path": re.compile(r"^host-probes/host-[0-9]{6}\.stderr\.log$"),
    }
    root = raw_root.resolve(strict=True)
    for kind in ("stdout", "stderr"):
        relative = evidence[f"{kind}_path"]
        if not isinstance(relative, str) or not expected_names[f"{kind}_path"].fullmatch(relative):
            _fail(f"structured host clock {kind} path is invalid")
        path = root / Path(relative)
        if path.is_symlink() or not path.is_file() or path.resolve(strict=True).parent != (root / "host-probes").resolve(strict=True):
            _fail(f"structured host clock {kind} evidence is not a regular in-root file")
        data = path.read_bytes()
        expected_bytes = evidence[f"{kind}_bytes"]
        if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int) or expected_bytes != len(data):
            _fail(f"structured host clock {kind} byte count disagrees")
        if _digest(evidence[f"{kind}_sha256"], f"structured host clock {kind} digest") != sha256(data).hexdigest():
            _fail(f"structured host clock {kind} digest disagrees")
    if evidence["stdout_bytes"] <= 0 or evidence["stderr_bytes"] != 0:
        _fail("structured host clock provider did not publish clean JSON-only evidence")
    provider, _ = _load(root / evidence["stdout_path"], "structured host clock provider stdout")
    if provider.get("schema") != "RawQualificationTelemetryProbeV1" or provider.get("clock") != observation:
        _fail("structured host clock provider stdout disagrees with its bound observation")


def _verify_implementation_lock(root: Path, terminal: dict[str, Any]) -> None:
    if terminal["implementation_lock_status"] != "VERIFIED_UNCHANGED_AT_TERMINAL":
        _fail("implementation lock was not verified unchanged at terminal publication")
    lock_name = terminal["implementation_lock_file"]
    if lock_name != "implementation-lock.json":
        _fail("implementation lock filename is invalid")
    lock, lock_bytes = _load(root / lock_name, "implementation lock")
    if _digest(terminal["implementation_lock_sha256"], "implementation lock digest") != sha256(lock_bytes).hexdigest():
        _fail("implementation lock digest disagrees")
    if tuple(lock) != IMPLEMENTATION_LOCK_KEYS:
        _fail("implementation lock property set/order is invalid")
    if lock["schema"] != "ObservedImplementationLockV1" or lock["status"] != "LOCKED" or lock["run_id"] != terminal["run_id"]:
        _fail("implementation lock identity is invalid")
    if not isinstance(lock["created_utc"], str) or not lock["created_utc"].endswith(("Z", "+00:00")):
        _fail("implementation lock UTC timestamp is invalid")
    wrapper = lock["wrapper_path"]
    if not isinstance(wrapper, str) or not os.path.isabs(wrapper):
        _fail("implementation wrapper path is not absolute")
    _positive_size(lock["wrapper_bytes"], "implementation wrapper")
    _digest(lock["wrapper_sha256"], "implementation wrapper digest")
    if lock["sealed_runtime"] != "sealed-observer-runtime":
        _fail("sealed observer runtime name is invalid")
    runtime_root = root / lock["sealed_runtime"]
    if runtime_root.is_symlink() or not runtime_root.is_dir():
        _fail("sealed observer runtime is absent or not a regular directory")

    declared = lock["files"]
    if not isinstance(declared, list) or not declared or len(declared) > 512:
        _fail("sealed observer file inventory is empty or oversized")
    observed: list[dict[str, Any]] = []
    for path in sorted(runtime_root.rglob("*"), key=str):
        if path.is_symlink():
            _fail("sealed observer runtime contains a symbolic link")
        if not path.is_file():
            continue
        data = path.read_bytes()
        observed.append({
            "path": path.relative_to(runtime_root).as_posix(),
            "bytes": len(data),
            "sha256": sha256(data).hexdigest(),
        })
    for row in declared:
        if not isinstance(row, dict) or tuple(row) != IMPLEMENTATION_FILE_KEYS:
            _fail("sealed observer file row is invalid")
        path = row["path"]
        if not isinstance(path, str) or not path or "\\" in path or Path(path).is_absolute() or ".." in Path(path).parts:
            _fail("sealed observer file path is unsafe")
        _positive_size(row["bytes"], "sealed observer file")
        _digest(row["sha256"], "sealed observer file digest")
    if declared != observed:
        _fail("sealed observer runtime inventory changed or is incomplete")

    external = lock["external_runtime"]
    if not isinstance(external, list) or tuple(row.get("name") for row in external if isinstance(row, dict)) != EXTERNAL_RUNTIME_NAMES:
        _fail("external observer runtime inventory is invalid")
    for row in external:
        if not isinstance(row, dict) or tuple(row) != EXTERNAL_RUNTIME_KEYS:
            _fail("external observer runtime row is invalid")
        if not isinstance(row["path"], str) or not os.path.isabs(row["path"]):
            _fail("external observer runtime path is not absolute")
        _positive_size(row["bytes"], "external observer runtime")
        _digest(row["sha256"], "external observer runtime digest")


def verify_observed_qualification(root: Path) -> dict[str, Any]:
    root = Path(os.path.abspath(root)).resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        _fail("observability root is not a regular directory")
    terminal_path = root / "observed-qualification-terminal.json"
    terminal, terminal_bytes = _load(terminal_path, "observed terminal")
    if tuple(terminal) != TERMINAL_KEYS:
        _fail("observed terminal property set/order is invalid")
    if terminal["schema"] != "ObservedRawQualificationTerminalV1" or terminal["status"] not in {"COMPLETE", "FAILED"}:
        _fail("observed terminal status/schema is invalid")
    if terminal["cause_domain_boundary"] != "INTERNAL_OR_EXTERNAL_IS_RELATIVE_TO_THE_CAPTURE_PROCESS;_SINGLE_HOST_EVIDENCE_DOES_NOT_SEPARATE_ROUTER_ISP_TRANSIT_OR_BINANCE_INTERNALS":
        _fail("cause-domain boundary was broadened")
    if terminal["diagnostic_only"] is not True or terminal["raw_lineage_authority"] != "NONE" or terminal["credentials"] != "NONE" or terminal["order_entry"] != "ABSENT":
        _fail("observability sidecar authority/scope is invalid")

    _verify_implementation_lock(root, terminal)

    declared_inventory = terminal["artifact_inventory"]
    if not isinstance(declared_inventory, list) or any(not isinstance(row, dict) or tuple(row) != INVENTORY_KEYS for row in declared_inventory):
        _fail("artifact inventory is invalid")
    if declared_inventory != _inventory(root, terminal_path.name):
        _fail("observability artifact inventory changed or is incomplete")

    etw = verify_kernel_network_production(Path(terminal["kernel_network_root"]))
    witness = verify_network_witness(Path(terminal["network_witness_root"]))
    system = verify_system_evidence(Path(terminal["system_evidence_root"]))
    for label, report, name, digest_name in (
        ("kernel verification", etw, terminal["kernel_network_verification_file"], terminal["kernel_network_verification_sha256"]),
        ("witness verification", witness, terminal["network_witness_verification_file"], terminal["network_witness_verification_sha256"]),
        ("system verification", system, terminal["system_evidence_verification_file"], terminal["system_evidence_verification_sha256"]),
    ):
        stored, data = _load(root / name, label)
        if stored != report or _digest(digest_name, f"{label} digest") != sha256(data).hexdigest():
            _fail(f"{label} differs from independent recomputation")

    raw_status = terminal["raw_launcher_status"]
    if raw_status not in {"COMPLETE", "FAILED", None}:
        _fail("raw launcher status is invalid")
    raw_root = terminal["raw_qualification_root"]
    if raw_root is not None:
        raw_terminal = Path(raw_root) / terminal["raw_launcher_terminal"]
        raw, raw_bytes = _load(raw_terminal, "raw launcher terminal")
        if raw.get("status") != raw_status or _digest(terminal["raw_launcher_terminal_sha256"], "raw terminal digest") != sha256(raw_bytes).hexdigest():
            _fail("raw launcher terminal identity/digest disagrees")

    incident_class = terminal["network_incident_classification"]
    if terminal["network_incident_file"] is None:
        if terminal["network_incident_sha256"] is not None or incident_class is not None:
            _fail("absent network incident has non-null bindings")
    else:
        incident, incident_bytes = _load(root / terminal["network_incident_file"], "network incident")
        if (
            _digest(terminal["network_incident_sha256"], "network incident digest") != sha256(incident_bytes).hexdigest()
            or incident.get("status") != "EVIDENCE_CLASSIFIED"
            or incident.get("classification") != incident_class
            or incident.get("raw_lineage_authority") != "NONE_DIAGNOSTIC_ONLY"
        ):
            _fail("network incident binding/classification is invalid")

    expected_domain = classify_cause_domain(
        observer_failure=terminal["observer_failure"],
        raw_status=raw_status,
        raw_failure=terminal["raw_launcher_failure"],
        incident_classification=incident_class,
    )
    if expected_domain == "HOST_TIME_SYNCHRONIZATION_FAILURE":
        if not isinstance(raw_root, str) or not isinstance(terminal["raw_launcher_failure"], str):
            _fail("host clock cause lacks its raw root or structured failure")
        _verify_host_clock_failure_evidence(Path(raw_root), terminal["raw_launcher_failure"])
    if terminal["cause_domain"] != expected_domain:
        _fail("producer cause domain differs from independent causal matrix")
    if (terminal["status"] == "COMPLETE") != (raw_status == "COMPLETE" and expected_domain == "NONE"):
        _fail("observed status contradicts raw status or cause domain")
    return {
        "schema": "ObservedRawQualificationVerificationV1",
        "status": "PASS",
        "run_id": terminal["run_id"],
        "qualification_status": terminal["status"],
        "cause_domain": expected_domain,
        "network_incident_classification": incident_class,
        "artifact_files": len(declared_inventory),
        "terminal_sha256": sha256(terminal_bytes).hexdigest(),
        "raw_lineage_authority": "NONE_DIAGNOSTIC_ONLY",
    }
