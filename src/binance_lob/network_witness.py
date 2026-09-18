"""Independent verifier for the bounded host/network witness sidecar."""

from __future__ import annotations

from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
from typing import Any


ZERO_SHA256 = "0" * 64
MAX_STARTUP_BYTES = 1024 * 1024
MAX_SEAL_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
MAX_JOURNAL_BYTES = 256 * 1024 * 1024

_STARTUP_KEYS = (
    "schema", "observation_id", "evidence_root", "started_utc", "process_id",
    "monotonic_origin_qpc_timestamp", "monotonic_frequency", "duration_s",
    "interval_s", "probe_timeout_ms", "binance_host", "independent_ip",
    "credentials", "order_entry",
)
_STARTUP_KEYS_V2 = (
    "schema", "observation_id", "evidence_root", "started_utc", "process_id",
    "monotonic_origin_qpc_timestamp", "monotonic_frequency", "duration_s",
    "interval_s", "probe_timeout_ms", "stop_file", "binance_host", "independent_ip",
    "credentials", "order_entry",
)
_SEAL_KEYS = (
    "schema", "observation_id", "status", "error", "startup_file",
    "startup_sha256", "journal_file", "journal_records",
    "journal_terminal_record_sha256", "journal_bytes", "journal_sha256",
    "samples", "finished_utc", "attribution_boundary",
)
_SEAL_KEYS_V2 = (
    "schema", "observation_id", "status", "error", "startup_file",
    "startup_sha256", "journal_file", "journal_records",
    "journal_terminal_record_sha256", "journal_bytes", "journal_sha256",
    "samples", "stop_reason", "finished_utc", "attribution_boundary",
)
_ENVELOPE_KEYS = ("body", "record_sha256")
_BODY_KEYS = (
    "schema", "record_index", "wall_ns", "monotonic_tick", "channel",
    "payload", "previous_record_sha256",
)
_SAMPLE_KEYS = (
    "event", "observation_id", "sequence", "sample_elapsed_ms", "interfaces",
    "dns", "routes", "tcp",
)
_TERMINAL_KEYS = ("event", "observation_id", "status", "error", "samples")
_TERMINAL_KEYS_V2 = (
    "event", "observation_id", "status", "error", "samples", "stop_reason",
)
_INTERFACE_KEYS = (
    "id", "name", "type", "status", "speed_bps", "gateways",
    "unicast_addresses",
)
_DNS_KEYS = ("host", "status", "elapsed_ms", "addresses", "error")
_ROUTE_KEYS = ("target", "address", "status", "local_endpoint", "error")
_TCP_KEYS = (
    "target", "address", "port", "status", "elapsed_ms", "local_endpoint",
    "remote_endpoint", "error",
)
_ERROR_KEYS = ("type", "hresult", "socket_error_code", "message")


class NetworkWitnessCorruption(ValueError):
    """Raised when witness bytes do not satisfy the exact contract."""


def _fail(message: str) -> None:
    raise NetworkWitnessCorruption(message)


def _regular_directory(path: Path) -> Path:
    candidate = path.absolute()
    current = Path(candidate.anchor)
    for component in candidate.parts[1:]:
        current /= component
        try:
            status = os.lstat(current)
        except OSError as error:
            _fail(f"cannot stat witness path component {current}: {error}")
        if getattr(status, "st_file_attributes", 0) & 0x400 or current.is_symlink():
            _fail("witness path contains a reparse point")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        _fail("witness root is not a directory")
    return resolved


def _keys(value: dict[str, Any], expected: tuple[str, ...], label: str) -> None:
    if tuple(value) != expected:
        _fail(f"{label} property set/order is invalid")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} is not an object")
    return value


def _u64(value: Any, label: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << 64:
        _fail(f"{label} is not an unsigned 64-bit integer")
    if positive and value == 0:
        _fail(f"{label} must be positive")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        _fail(f"{label} is not a non-empty string")
    return value


def _digest(value: Any, label: str) -> str:
    text = _text(value, label)
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        _fail(f"{label} is not a lowercase SHA-256")
    return text


def _regular_bytes(path: Path, maximum: int, label: str, *, allow_empty: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} is not a regular non-link file")
    data = path.read_bytes()
    if (not data and not allow_empty) or len(data) > maximum:
        _fail(f"{label} is empty or oversized")
    return data


def _json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{label} is not strict UTF-8 JSON: {error}")
    return _object(value, label)


def _compact(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _ip(value: Any, label: str) -> str:
    text = _text(value, label)
    host = text.split("%", 1)[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        _fail(f"{label} is not an IP address")
    return text


def _endpoint(value: Any, label: str) -> str:
    text = _text(value, label)
    host, separator, port_text = text.rpartition(":")
    if not separator or not host or not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        _fail(f"{label} is not an endpoint")
    host = host.strip("[]")
    _ip(host, f"{label} address")
    return text


def _error(value: Any, label: str) -> None:
    error = _object(value, label)
    _keys(error, _ERROR_KEYS, label)
    _text(error.get("type"), f"{label}.type")
    if not isinstance(error.get("hresult"), int) or isinstance(error.get("hresult"), bool):
        _fail(f"{label}.hresult is not an integer")
    socket_error = error.get("socket_error_code")
    if socket_error is not None and (not isinstance(socket_error, int) or isinstance(socket_error, bool)):
        _fail(f"{label}.socket_error_code is invalid")
    _text(error.get("message"), f"{label}.message")


def _optional_error(value: Any, label: str, *, required: bool) -> None:
    if value is None:
        if required:
            _fail(f"{label} is required")
        return
    _error(value, label)


def _validate_sample(payload: dict[str, Any], observation_id: str, sequence: int) -> None:
    _keys(payload, _SAMPLE_KEYS, "witness sample")
    if payload.get("event") != "NETWORK_WITNESS_SAMPLE" or payload.get("observation_id") != observation_id:
        _fail("witness sample identity is invalid")
    if _u64(payload.get("sequence"), "witness sequence") != sequence:
        _fail("witness sequence is discontinuous")
    _u64(payload.get("sample_elapsed_ms"), "sample_elapsed_ms")

    interfaces = payload.get("interfaces")
    if not isinstance(interfaces, list) or not 1 <= len(interfaces) <= 128:
        _fail("interface inventory cardinality is invalid")
    ids: set[str] = set()
    for index, raw in enumerate(interfaces):
        row = _object(raw, f"interface[{index}]")
        _keys(row, _INTERFACE_KEYS, f"interface[{index}]")
        identity = _text(row.get("id"), f"interface[{index}].id")
        if identity in ids:
            _fail("interface inventory contains duplicate IDs")
        ids.add(identity)
        for field in ("name", "type", "status"):
            _text(row.get(field), f"interface[{index}].{field}")
        _u64(row.get("speed_bps"), f"interface[{index}].speed_bps")
        for field in ("gateways", "unicast_addresses"):
            values = row.get(field)
            if not isinstance(values, list) or len(values) > 128:
                _fail(f"interface[{index}].{field} is invalid")
            for item in values:
                _ip(item, f"interface[{index}].{field}")

    dns_rows = payload.get("dns")
    if not isinstance(dns_rows, list) or len(dns_rows) != 1:
        _fail("DNS witness cardinality is invalid")
    dns = _object(dns_rows[0], "DNS witness")
    _keys(dns, _DNS_KEYS, "DNS witness")
    if dns.get("host") != "data-stream.binance.vision" or dns.get("status") not in {"RESOLVED", "EMPTY", "TIMEOUT", "FAILED"}:
        _fail("DNS witness identity/status is invalid")
    _u64(dns.get("elapsed_ms"), "DNS elapsed_ms")
    addresses = dns.get("addresses")
    if not isinstance(addresses, list) or len(addresses) > 128:
        _fail("DNS addresses are invalid")
    for address in addresses:
        _ip(address, "DNS address")
    if dns.get("status") == "RESOLVED" and not addresses:
        _fail("resolved DNS witness has no addresses")
    _optional_error(dns.get("error"), "DNS error", required=dns.get("status") == "FAILED")

    for collection_name, expected_keys in (("routes", _ROUTE_KEYS), ("tcp", _TCP_KEYS)):
        rows = payload.get(collection_name)
        if not isinstance(rows, list) or not 1 <= len(rows) <= 2:
            _fail(f"{collection_name} witness cardinality is invalid")
        targets: set[str] = set()
        for index, raw in enumerate(rows):
            row = _object(raw, f"{collection_name}[{index}]")
            _keys(row, expected_keys, f"{collection_name}[{index}]")
            target = _text(row.get("target"), f"{collection_name}[{index}].target")
            if target not in {"BINANCE_PUBLIC_STREAM", "INDEPENDENT_INTERNET"} or target in targets:
                _fail(f"{collection_name} target is invalid or duplicated")
            targets.add(target)
            _ip(row.get("address"), f"{collection_name}[{index}].address")
            status = _text(row.get("status"), f"{collection_name}[{index}].status")
            if collection_name == "routes":
                if status not in {"ROUTE_SELECTED", "FAILED"}:
                    _fail("route status is invalid")
                if status == "ROUTE_SELECTED":
                    _endpoint(row.get("local_endpoint"), "route local_endpoint")
                elif row.get("local_endpoint") is not None:
                    _fail("failed route published a local endpoint")
                _optional_error(row.get("error"), "route error", required=status == "FAILED")
            else:
                if row.get("port") != 443 or status not in {"CONNECTED", "TIMEOUT", "FAILED"}:
                    _fail("TCP witness port/status is invalid")
                _u64(row.get("elapsed_ms"), "TCP elapsed_ms")
                if status == "CONNECTED":
                    _endpoint(row.get("local_endpoint"), "TCP local_endpoint")
                    _endpoint(row.get("remote_endpoint"), "TCP remote_endpoint")
                elif row.get("local_endpoint") is not None or row.get("remote_endpoint") is not None:
                    _fail("failed TCP witness published endpoints")
                _optional_error(row.get("error"), "TCP error", required=status == "FAILED")
        if "INDEPENDENT_INTERNET" not in targets:
            _fail(f"{collection_name} lacks its independent Internet witness")


def classify_network_witness_sample(payload: dict[str, Any]) -> str:
    """Classify only directly witnessed reachability boundaries, never market state."""
    dns = payload["dns"][0]
    tcp = {row["target"]: row for row in payload["tcp"]}
    routes = {row["target"]: row for row in payload["routes"]}
    independent = tcp["INDEPENDENT_INTERNET"]["status"]
    binance_row = tcp.get("BINANCE_PUBLIC_STREAM")
    binance = None if binance_row is None else binance_row["status"]
    if dns["status"] != "RESOLVED" and independent == "CONNECTED":
        return "BINANCE_DNS_UNAVAILABLE_INTERNET_TCP_REACHABLE"
    if binance == "CONNECTED" and independent == "CONNECTED":
        return "BINANCE_AND_INDEPENDENT_TCP_REACHABLE"
    if binance in {"FAILED", "TIMEOUT"} and independent == "CONNECTED":
        return "BINANCE_PATH_SPECIFIC_TCP_FAILURE_FROM_THIS_HOST"
    if binance == "CONNECTED" and independent in {"FAILED", "TIMEOUT"}:
        return "INDEPENDENT_WITNESS_FAILURE_BINANCE_TCP_REACHABLE"
    if independent in {"FAILED", "TIMEOUT"} and binance in {None, "FAILED", "TIMEOUT"}:
        up_with_gateway = any(
            row["status"] == "Up" and row["type"] != "Loopback" and row["gateways"]
            for row in payload["interfaces"]
        )
        independent_route = routes["INDEPENDENT_INTERNET"]["status"]
        if not up_with_gateway or independent_route != "ROUTE_SELECTED":
            return "LOCAL_INTERFACE_OR_ROUTE_UNAVAILABLE"
        return "SHARED_PATH_FAILURE_FROM_THIS_HOST"
    return "INSUFFICIENT_NETWORK_WITNESS_EVIDENCE"


def verify_network_witness(root: str | Path) -> dict[str, Any]:
    directory = _regular_directory(Path(root))
    names = {entry.name for entry in directory.iterdir()}
    expected_names = {
        "network-witness-startup.json", "network-witness-events.jsonl",
        "network-witness-seal.json",
    }
    if names not in (expected_names, expected_names | {"stop.request"}):
        _fail("witness root inventory is not exact")

    startup_bytes = _regular_bytes(directory / "network-witness-startup.json", MAX_STARTUP_BYTES, "startup")
    journal_bytes = _regular_bytes(directory / "network-witness-events.jsonl", MAX_JOURNAL_BYTES, "journal")
    seal_bytes = _regular_bytes(directory / "network-witness-seal.json", MAX_SEAL_BYTES, "seal")
    startup = _json(startup_bytes, "startup")
    seal = _json(seal_bytes, "seal")
    version = 2 if startup.get("schema") == "RawQualificationNetworkWitnessStartupV2" else 1
    if (version == 2) != ("stop.request" in names):
        _fail("witness version and stop-file inventory disagree")
    if version == 2 and _regular_bytes(directory / "stop.request", 16, "stop request", allow_empty=True):
        _fail("V2 witness stop request is not exactly empty")
    _keys(startup, _STARTUP_KEYS_V2 if version == 2 else _STARTUP_KEYS, "startup")
    _keys(seal, _SEAL_KEYS_V2 if version == 2 else _SEAL_KEYS, "seal")
    observation_id = _text(startup.get("observation_id"), "observation_id")
    if (
        startup.get("schema") != f"RawQualificationNetworkWitnessStartupV{version}"
        or Path(_text(startup.get("evidence_root"), "evidence_root")).resolve() != directory
        or _u64(startup.get("process_id"), "process_id", positive=True) > 0xFFFFFFFF
        or _u64(startup.get("monotonic_origin_qpc_timestamp"), "origin", positive=True) == 0
        or _u64(startup.get("monotonic_frequency"), "frequency", positive=True) == 0
        or not 1 <= _u64(startup.get("duration_s"), "duration_s") <= 691200
        or not 5 <= _u64(startup.get("interval_s"), "interval_s") <= 300
        or not 250 <= _u64(startup.get("probe_timeout_ms"), "probe_timeout_ms") <= 10000
        or startup.get("binance_host") != "data-stream.binance.vision"
        or startup.get("independent_ip") != "1.1.1.1"
        or startup.get("credentials") != "NONE"
        or startup.get("order_entry") != "ABSENT"
    ):
        _fail("startup contract is invalid")
    if version == 2 and startup.get("stop_file") != "stop.request":
        _fail("V2 witness stop-file identity is invalid")

    if not journal_bytes.endswith(b"\n"):
        _fail("witness journal has a partial tail")
    previous = ZERO_SHA256
    previous_mono = 0
    samples = 0
    classifications: dict[str, int] = {}
    classification_runs: list[dict[str, Any]] = []
    last_classification: str | None = None
    terminal: dict[str, Any] | None = None
    lines = journal_bytes.splitlines()
    for index, line in enumerate(lines):
        if not line or len(line) > MAX_RECORD_BYTES:
            _fail("witness journal contains an empty or oversized record")
        envelope = _json(line, f"journal record {index}")
        _keys(envelope, _ENVELOPE_KEYS, f"journal record {index}")
        body = _object(envelope.get("body"), f"journal body {index}")
        _keys(body, _BODY_KEYS, f"journal body {index}")
        digest = sha256(_compact(body)).hexdigest()
        if (
            body.get("schema") != f"RawQualificationNetworkWitnessRecordV{version}"
            or body.get("record_index") != index
            or _u64(body.get("wall_ns"), "wall_ns", positive=True) == 0
            or _u64(body.get("monotonic_tick"), "monotonic_tick", positive=True) < previous_mono
            or body.get("channel") != "NETWORK_WITNESS"
            or body.get("previous_record_sha256") != previous
            or envelope.get("record_sha256") != digest
        ):
            _fail("witness journal hash/identity/clock chain is invalid")
        if terminal is not None:
            _fail("witness journal continued after terminal evidence")
        payload = _object(body.get("payload"), f"payload {index}")
        if payload.get("event") == "NETWORK_WITNESS_SAMPLE":
            _validate_sample(payload, observation_id, samples)
            last_classification = classify_network_witness_sample(payload)
            classifications[last_classification] = classifications.get(last_classification, 0) + 1
            wall_ns = body["wall_ns"]
            monotonic_tick = body["monotonic_tick"]
            if classification_runs and classification_runs[-1]["classification"] == last_classification:
                classification_runs[-1]["last_sequence"] = samples
                classification_runs[-1]["last_wall_ns"] = wall_ns
                classification_runs[-1]["last_monotonic_tick"] = monotonic_tick
                classification_runs[-1]["samples"] += 1
            else:
                classification_runs.append({
                    "classification": last_classification,
                    "first_sequence": samples,
                    "last_sequence": samples,
                    "first_wall_ns": wall_ns,
                    "last_wall_ns": wall_ns,
                    "first_monotonic_tick": monotonic_tick,
                    "last_monotonic_tick": monotonic_tick,
                    "samples": 1,
                })
            samples += 1
        elif payload.get("event") == "NETWORK_WITNESS_TERMINAL":
            _keys(payload, _TERMINAL_KEYS_V2 if version == 2 else _TERMINAL_KEYS, "witness terminal")
            if (
                payload.get("observation_id") != observation_id
                or payload.get("status") not in {"COMPLETE", "FAILED"}
                or payload.get("samples") != samples
                or (payload.get("status") == "COMPLETE" and payload.get("error") is not None)
                or (payload.get("status") == "FAILED" and not isinstance(payload.get("error"), str))
            ):
                _fail("witness terminal contract is invalid")
            if version == 2 and payload.get("stop_reason") not in {"STOP_FILE", "DEADLINE"}:
                _fail("V2 witness terminal stop reason is invalid")
            terminal = payload
        else:
            _fail("witness journal contains an unknown event")
        previous = digest
        previous_mono = body["monotonic_tick"]

    if terminal is None or samples == 0:
        _fail("witness journal lacks samples or terminal evidence")
    _keys(seal, _SEAL_KEYS_V2 if version == 2 else _SEAL_KEYS, "seal")
    if (
        seal.get("schema") != f"RawQualificationNetworkWitnessSealV{version}"
        or seal.get("observation_id") != observation_id
        or seal.get("status") != terminal.get("status")
        or seal.get("error") != terminal.get("error")
        or seal.get("startup_file") != "network-witness-startup.json"
        or seal.get("startup_sha256") != sha256(startup_bytes).hexdigest()
        or seal.get("journal_file") != "network-witness-events.jsonl"
        or seal.get("journal_records") != len(lines)
        or seal.get("journal_terminal_record_sha256") != previous
        or seal.get("journal_bytes") != len(journal_bytes)
        or seal.get("journal_sha256") != sha256(journal_bytes).hexdigest()
        or seal.get("samples") != samples
        or (version == 2 and seal.get("stop_reason") != terminal.get("stop_reason"))
        or seal.get("attribution_boundary")
        != "ONE_HOST_WITNESS_CANNOT_SEPARATE_ISP_FROM_REMOTE_OR_INTERMEDIATE_FAILURE_WITHOUT_AN_EXTERNAL_VANTAGE"
    ):
        _fail("witness seal differs from the exact verified bytes")

    material = {
        "observation_id": observation_id,
        "version": version,
        "samples": samples,
        "interval_s": startup["interval_s"],
        "probe_timeout_ms": startup["probe_timeout_ms"],
        "journal_sha256": sha256(journal_bytes).hexdigest(),
        "terminal_record_sha256": previous,
        "last_classification": last_classification,
        "classification_counts": dict(sorted(classifications.items())),
        "classification_runs": classification_runs,
    }
    return {
        "schema": "RawQualificationNetworkWitnessVerificationV1",
        "status": "PASS",
        **material,
        "classification_scope": "DIRECT_LOCAL_HOST_REACHABILITY_ONLY",
        "verification_sha256": sha256(_compact(material)).hexdigest(),
    }
