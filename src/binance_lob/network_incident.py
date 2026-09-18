"""Cross-plane incident bundle with deliberately bounded causal attribution."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Iterable

from .network_trace import verify_network_trace
from .network_witness import verify_network_witness


MAX_DIAGNOSTIC_BYTES = 32 * 1024 * 1024
_REPORT_KEYS = (
    "schema", "status", "generation_dir", "generation_manifest_sha256",
    "session_id", "generation_index", "symbol", "generation_status",
    "generation_failure", "streams", "inference_boundary", "verification_sha256",
)
_STREAM_KEYS = (
    "schema", "stream", "connection_epoch", "records", "terminal_record_sha256",
    "terminal_status", "terminal_error", "terminal_received",
    "websocket_remote_endpoint", "read_timeouts", "last_tcp_info", "event_counts",
    "classification", "attribution_scope",
)


class NetworkIncidentError(ValueError):
    """Raised when incident inputs are absent, mutable or internally inconsistent."""


def _fail(message: str) -> None:
    raise NetworkIncidentError(message)


def _sha_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        _fail(f"{label} is not a lowercase SHA-256")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        _fail(f"{label} is not a non-empty string")
    return value


def _u64(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << 64:
        _fail(f"{label} is not an unsigned 64-bit integer")
    return value


def _regular_file(path: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        status = os.lstat(current)
        if getattr(status, "st_file_attributes", 0) & 0x400 or current.is_symlink():
            _fail(f"{label} path contains a reparse point")
    if not path.is_file():
        _fail(f"{label} is not a regular non-link file")
    return path.resolve(strict=True)


def _regular_directory(path: Path, label: str) -> Path:
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        status = os.lstat(current)
        if getattr(status, "st_file_attributes", 0) & 0x400 or current.is_symlink():
            _fail(f"{label} path contains a reparse point")
    if not path.is_dir():
        _fail(f"{label} is not a regular directory")
    return path.resolve(strict=True)


def _minimal_environment() -> dict[str, str]:
    names = ("SystemDrive", "SystemRoot", "TEMP", "TMP", "WINDIR")
    environment: dict[str, str] = {}
    for name in names:
        value = os.environ.get(name)
        if not value or "\x00" in value:
            _fail(f"required diagnostic environment variable {name} is absent")
        environment[name] = value
    return environment


def _validate_transport_report(report: Any, generation: Path) -> dict[str, Any]:
    if not isinstance(report, dict) or tuple(report) != _REPORT_KEYS:
        _fail("transport diagnosis report property set/order is invalid")
    if report["schema"] != "TransportDiagnosisReportV1" or report["status"] != "PASS":
        _fail("transport diagnosis report did not pass")
    reported_text = _text(report["generation_dir"], "generation dir")
    if os.name == "nt" and reported_text.startswith("\\\\?\\"):
        reported_text = reported_text[4:]
    reported_generation = Path(reported_text).resolve(strict=True)
    if reported_generation != generation:
        _fail("transport diagnosis report names a different generation")
    manifest = _regular_file(generation / "generation.json", "generation manifest")
    if _digest(report["generation_manifest_sha256"], "generation manifest digest") != _sha_file(manifest):
        _fail("generation manifest changed after transport diagnosis")
    if report["symbol"] not in {"BTCUSDT", "ETHUSDT"} or report["generation_status"] not in {"COMPLETE", "FAILED"}:
        _fail("transport diagnosis generation identity/status is invalid")
    _text(report["session_id"], "session id")
    _u64(report["generation_index"], "generation index")
    if (report["generation_status"] == "COMPLETE") != (report["generation_failure"] is None):
        _fail("generation status contradicts its failure")
    if report["generation_failure"] is not None:
        _text(report["generation_failure"], "generation failure")
    _text(report["inference_boundary"], "transport inference boundary")

    streams = report["streams"]
    if not isinstance(streams, list) or len(streams) != 2:
        _fail("transport diagnosis does not contain exactly two streams")
    names: set[str] = set()
    for stream in streams:
        if not isinstance(stream, dict) or tuple(stream) != _STREAM_KEYS:
            _fail("transport stream diagnosis property set/order is invalid")
        if stream["schema"] != "TransportJournalDiagnosisV1" or stream["stream"] not in {"depth", "trade"}:
            _fail("transport stream diagnosis identity is invalid")
        if stream["stream"] in names:
            _fail("transport stream diagnosis is duplicated")
        names.add(stream["stream"])
        _text(stream["connection_epoch"], "connection epoch")
        _u64(stream["records"], "transport records")
        _digest(stream["terminal_record_sha256"], "transport terminal digest")
        if stream["terminal_status"] not in {"STOPPED", "FAILED"}:
            _fail("transport terminal status is invalid")
        if stream["terminal_error"] is not None:
            _text(stream["terminal_error"], "transport terminal error")
        _u64(stream["terminal_received"], "transport terminal received")
        _u64(stream["read_timeouts"], "transport read timeouts")
        if stream["websocket_remote_endpoint"] is not None:
            _text(stream["websocket_remote_endpoint"], "WebSocket remote endpoint")
        if stream["last_tcp_info"] is not None and not isinstance(stream["last_tcp_info"], dict):
            _fail("last TCP information is neither an object nor null")
        counts = stream["event_counts"]
        if not isinstance(counts, dict) or not counts:
            _fail("transport event counts are absent")
        for event, count in counts.items():
            _text(event, "transport event")
            _u64(count, "transport event count")
        _text(stream["classification"], "transport classification")
        if stream["attribution_scope"] != "OBSERVED_LOCAL_SOCKET_AND_WEBSOCKET_BOUNDARY_ONLY":
            _fail("transport attribution scope was broadened")
    if names != {"depth", "trade"}:
        _fail("transport diagnosis stream set is incomplete")
    material = json.dumps(streams, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if _digest(report["verification_sha256"], "transport verification digest") != sha256(material).hexdigest():
        _fail("transport diagnosis verification digest is invalid")
    return report


def run_transport_diagnosis(executable: Path, generation: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    executable = _regular_file(executable, "transport diagnosis executable")
    generation = _regular_directory(generation, "generation root")
    try:
        completed = subprocess.run(
            [str(executable), str(generation)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=300,
            check=False,
            env=_minimal_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        _fail(f"transport diagnosis process failed: {error}")
    if len(completed.stdout) > MAX_DIAGNOSTIC_BYTES or len(completed.stderr) > MAX_DIAGNOSTIC_BYTES:
        _fail("transport diagnosis output exceeded its bound")
    if completed.returncode != 0 or completed.stderr:
        _fail(
            f"transport diagnosis rejected generation (exit={completed.returncode}): "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    try:
        report = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"transport diagnosis output is not strict UTF-8 JSON: {error}")
    validated = _validate_transport_report(report, generation)
    execution = {
        "executable": str(executable),
        "executable_sha256": _sha_file(executable),
        "exit_code": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stdout_sha256": sha256(completed.stdout).hexdigest(),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": sha256(completed.stderr).hexdigest(),
    }
    return validated, execution


def _nearest_witness(report: dict[str, Any], incident_wall_ns: int) -> dict[str, Any] | None:
    nearest: dict[str, Any] | None = None
    nearest_delta: int | None = None
    for run in report["classification_runs"]:
        first = _u64(run["first_wall_ns"], "witness run first wall")
        last = _u64(run["last_wall_ns"], "witness run last wall")
        delta = first - incident_wall_ns if incident_wall_ns < first else incident_wall_ns - last if incident_wall_ns > last else 0
        if nearest_delta is None or delta < nearest_delta:
            nearest = dict(run)
            nearest_delta = delta
    if nearest is None or nearest_delta is None:
        return None
    tolerance = report["interval_s"] * 1_000_000_000 + report["probe_timeout_ms"] * 1_000_000
    nearest["incident_distance_ns"] = nearest_delta
    nearest["within_sampling_tolerance"] = nearest_delta <= tolerance
    return nearest


def _classify(transports: Iterable[dict[str, Any]], witness: dict[str, Any] | None) -> str:
    classes = {stream["classification"] for report in transports for stream in report["streams"]}
    failing = {name for name in classes if name != "CLEAN_CLIENT_STOP"}
    if not failing:
        return "NO_TRANSPORT_FAILURE_IN_SUPPLIED_GENERATIONS"
    if "WEBSOCKET_CLOSE_FRAME_OBSERVED" in failing:
        return "WEBSOCKET_CLOSE_FRAME_AT_APPLICATION_BOUNDARY"
    if "SOCKET_READ_ERROR_OBSERVED" in failing:
        return "SOCKET_READ_ERROR_AT_APPLICATION_BOUNDARY"
    witness_class = None if witness is None or not witness["within_sampling_tolerance"] else witness["classification"]
    if any(name.startswith("TRANSPORT_SILENCE") for name in failing):
        correlated = {
            "LOCAL_INTERFACE_OR_ROUTE_UNAVAILABLE": "CORRELATED_LOCAL_INTERFACE_OR_ROUTE_FAILURE_FROM_THIS_HOST",
            "SHARED_PATH_FAILURE_FROM_THIS_HOST": "CORRELATED_SHARED_PATH_FAILURE_FROM_THIS_HOST",
            "BINANCE_PATH_SPECIFIC_TCP_FAILURE_FROM_THIS_HOST": "CORRELATED_BINANCE_PATH_SPECIFIC_FAILURE_FROM_THIS_HOST",
            "BINANCE_DNS_UNAVAILABLE_INTERNET_TCP_REACHABLE": "CORRELATED_BINANCE_DNS_FAILURE_FROM_THIS_HOST",
            "BINANCE_AND_INDEPENDENT_TCP_REACHABLE": "SOCKET_SILENCE_WHILE_NEW_TCP_PROBES_WERE_REACHABLE",
        }
        return correlated.get(witness_class, "TRANSPORT_SILENCE_CAUSE_UNRESOLVED_AT_OBSERVED_BOUNDARIES")
    if "CONNECT_FAILURE_OBSERVED" in failing:
        return "CONNECT_FAILURE_AT_APPLICATION_BOUNDARY"
    if "WEBSOCKET_UPGRADE_REJECTION_OBSERVED" in failing:
        return "WEBSOCKET_UPGRADE_REJECTION_AT_APPLICATION_BOUNDARY"
    if "SUPERVISOR_FAILURE_STOP_OBSERVED" in failing:
        return "SUPERVISOR_FAILURE_STOP_AT_APPLICATION_BOUNDARY"
    return "LOCAL_PRODUCER_FAILURE_WITHOUT_NARROWER_OBSERVED_CAUSE"


def build_network_incident(
    *,
    generation_roots: Iterable[Path],
    transport_executable: Path,
    incident_wall_ns: int,
    witness_root: Path | None = None,
    trace_root: Path | None = None,
) -> dict[str, Any]:
    incident_wall_ns = _u64(incident_wall_ns, "incident wall ns")
    if incident_wall_ns == 0:
        _fail("incident wall ns must be positive")
    transport_reports: list[dict[str, Any]] = []
    executions: list[dict[str, Any]] = []
    for generation in generation_roots:
        report, execution = run_transport_diagnosis(transport_executable, generation)
        transport_reports.append(report)
        executions.append(execution)
    if not transport_reports:
        _fail("incident bundle requires at least one generation")
    identities = {(report["symbol"], report["session_id"]) for report in transport_reports}
    if len(identities) != len(transport_reports):
        _fail("incident bundle contains duplicate generation identities")

    witness_report = None if witness_root is None else verify_network_witness(witness_root)
    nearest = None if witness_report is None else _nearest_witness(witness_report, incident_wall_ns)
    trace_report = None if trace_root is None else verify_network_trace(trace_root)
    classification = _classify(transport_reports, nearest)
    return {
        "schema": "NetworkIncidentBundleV1",
        "status": "EVIDENCE_CLASSIFIED",
        "incident_wall_ns": incident_wall_ns,
        "classification": classification,
        "classification_scope": "NO_ATTRIBUTION_BEYOND_DIRECT_LOCAL_AND_CORRELATED_SINGLE_HOST_BOUNDARIES",
        "transport_reports": transport_reports,
        "transport_executions": executions,
        "witness_verification": witness_report,
        "nearest_witness_classification_run": nearest,
        "trace_verification": trace_report,
        "upstream_attribution": "REQUIRES_INDEPENDENT_EXTERNAL_VANTAGE_AND_PROVIDER_EVIDENCE",
        "raw_lineage_authority": "NONE_DIAGNOSTIC_ONLY",
    }
