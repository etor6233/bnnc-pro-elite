"""Independent verifier for the dual-symbol hot-redundant service envelope.

The PowerShell producer is not trusted.  This verifier reconstructs its
durable journal, checks the precommit/commit boundary, and reruns each nested
Python verifier against the exact artifacts referenced by the terminal file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any

from .hot_redundant import HotRedundantCorruption, verify_hot_redundant_capture
from .kernel_network_production import verify_kernel_network_production
from .network_witness import verify_network_witness
from .system_evidence import verify_system_evidence


ZERO = "0" * 64
MIB = 1024 * 1024
PREFLIGHT_KEYS = (
    "schema", "status", "mode", "total_seconds", "continuous",
    "epoch_window_seconds", "time_scale", "skip_kernel_observer", "symbols",
    "topology", "disk", "clock", "implementation", "run_id", "run_root",
)
TERMINAL_KEYS = (
    "schema", "status", "run_id", "started_utc", "finished_utc", "mode",
    "continuous", "epoch_window_s", "time_scale", "stop_requested",
    "storage_safe_stop", "observers_skipped", "requested_duration_s",
    "observer_failures", "outer_gaps", "verification", "verified_windows",
    "open_outer_gaps", "observer_verification", "journal_precommit",
)
FAILURE_KEYS = (
    "schema", "status", "run_id", "observed_utc", "elapsed_s", "failure",
    "script_stack_trace", "observer_failures", "active_processes",
    "journal_precommit",
)
BODY_KEYS = (
    "schema", "record_index", "wall_ns", "monotonic_tick", "channel",
    "payload", "previous_record_sha256",
)
PREFIX_KEYS = ("file_bytes", "file_sha256", "records", "terminal_record_sha256")
PASS_VERIFICATION_KEYS = (
    "symbol", "epoch", "status", "supervisor_id", "terminal_sha256",
    "journal_sha256", "artifact", "rust_report", "rust_report_sha256",
    "python_report", "python_report_sha256",
)
PASS_VERIFIED_IN_LOOP_KEYS = (
    "symbol", "epoch", "status", "verified_in_loop", "rust_report",
    "python_report", "artifact",
)
LIVE_ARBITRATION_KEYS = (
    "symbol", "journal", "journal_root", "journal_sha256", "rust_report",
    "rust_report_sha256", "python_report", "python_report_sha256",
    "oracle_identity", "canonical_trades", "canonical_depth_frames",
    "canonical_gaps", "canonical_segments", "exit_code",
)
LIVE_ARBITRATION_KEYS_V2 = LIVE_ARBITRATION_KEYS + (
    "expected_artifact_inventory", "expected_artifact_inventory_sha256",
)
OBSERVER_WINDOW_KEYS = (
    "epoch", "artifact_root", "started_wall_ns", "ready_wall_ns",
    "stop_requested_wall_ns", "terminal_wall_ns", "verification_path",
    "verification_sha256",
)
INCOMPLETE_VERIFICATION_KEYS = (
    "symbol", "epoch", "status", "exit_code", "artifact",
)


class HotServiceCorruption(ValueError):
    """The service envelope cannot support its stated result."""


def _fail(message: str) -> None:
    raise HotServiceCorruption(message)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def _json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8-sig"), object_pairs_hook=_pairs,
            parse_constant=lambda value: _fail(f"non-finite JSON constant: {value}"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{label} is not strict JSON: {error}")
    if not isinstance(value, dict):
        _fail(f"{label} is not an object")
    return value


def _bytes(path: Path, maximum: int, label: str, *, empty: bool = False) -> bytes:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} is not a regular file")
    data = path.read_bytes()
    if (not data and not empty) or len(data) > maximum:
        _fail(f"{label} is empty or oversized")
    return data


def _root(path: Path) -> Path:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        status = os.lstat(current)
        if getattr(status, "st_file_attributes", 0) & 0x400 or current.is_symlink():
            _fail("service root contains a reparse point")
    resolved = absolute.resolve(strict=True)
    if not resolved.is_dir():
        _fail("service root is not a directory")
    return resolved


def _file_sha256(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} is not a regular file")
    before = path.stat()
    digest = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(MIB), b""):
            digest.update(block)
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        _fail(f"{label} changed during verification")
    return digest.hexdigest()


def _u64(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 64:
        _fail(f"{label} is not uint64")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        _fail(f"{label} is not non-empty text")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        _fail(f"{label} is not lowercase SHA-256")
    return value


def _time(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        _fail(f"{label} is not text")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        _fail(f"{label} is not ISO-8601: {error}")


def _compact(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def _relative(root: Path, value: Any, label: str, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        _fail(f"{label} is not a portable relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts:
        _fail(f"{label} escapes the service root")
    target = (root / Path(*pure.parts)).resolve(strict=True)
    try:
        target.relative_to(root)
    except ValueError:
        _fail(f"{label} escapes the service root")
    if directory and not target.is_dir():
        _fail(f"{label} is not a directory")
    if not directory and not target.is_file():
        _fail(f"{label} is not a file")
    return target


def _scan_journal(data: bytes) -> tuple[list[dict[str, Any]], list[bytes]]:
    lines = data.splitlines(keepends=True)
    if not lines or any(not line.endswith(b"\n") for line in lines):
        _fail("service journal has an empty or partial tail")
    records: list[dict[str, Any]] = []
    previous = ZERO
    prior_tick = -1
    for index, raw in enumerate(lines):
        if len(raw) > MIB:
            _fail("service journal record exceeds one MiB")
        encoded = raw[:-1]
        envelope = _json(encoded, f"service journal record {index}")
        if tuple(envelope) != ("body", "record_sha256"):
            _fail("service journal envelope schema/order drifted")
        claimed = _digest(envelope["record_sha256"], "service journal record digest")
        prefix = b'{"body":'
        suffix = b',"record_sha256":"' + claimed.encode("ascii") + b'"}'
        if not encoded.startswith(prefix) or not encoded.endswith(suffix):
            _fail("service journal envelope is not in its exact compact lexical form")
        body_bytes = encoded[len(prefix):-len(suffix)]
        body = envelope["body"]
        if not isinstance(body, dict) or tuple(body) != BODY_KEYS:
            _fail("service journal body schema/order drifted")
        tick = _u64(body["monotonic_tick"], "monotonic tick")
        # Hash the producer's exact embedded body bytes. Re-serializing parsed
        # IEEE-754 values would make Python's `e` spelling disagree with
        # PowerShell's `E` spelling despite identical JSON semantics.
        actual = sha256(body_bytes).hexdigest()
        if (
            body["schema"] != "HotRedundantServiceJournalRecordV1"
            or _u64(body["record_index"], "record index") != index
            or body["previous_record_sha256"] != previous
            or claimed != actual
            or tick <= prior_tick
        ):
            _fail("service journal chain/index/monotonic order is invalid")
        previous, prior_tick = actual, tick
        records.append(envelope)
    return records, lines


def _observer_entry(root: Path, value: Any, expected_path: str, identity: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"observer {identity} entry is not an object")
    if value.get("status") == "SKIPPED_NOT_ELEVATED":
        # Test-only non-elevated runs record the observer skip honestly
        # instead of fabricating evidence; nothing is re-verified below.
        if tuple(value) != ("status", identity):
            _fail(f"observer {identity} skip entry schema/order drifted")
        return {"status": "SKIPPED_NOT_ELEVATED", identity: value[identity]}
    if tuple(value) != ("path", "sha256", identity):
        _fail(f"observer {identity} entry schema/order drifted")
    if value["path"] != expected_path:
        _fail(f"observer {identity} report path drifted")
    path = _relative(root, value["path"], f"observer {identity} report")
    data = _bytes(path, 8 * MIB, f"observer {identity} report")
    if sha256(data).hexdigest() != _digest(value["sha256"], f"observer {identity} report digest"):
        _fail(f"observer {identity} report digest disagrees")
    report = _json(data, f"observer {identity} report")
    if report.get(identity) != value[identity]:
        _fail(f"observer {identity} identity disagrees")
    return report


def _utc_ns(value: Any, label: str) -> int:
    stamp = _time(value, label)
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        _fail(f"{label} has no timezone")
    delta = stamp.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000


def _verify_observer_windows(
    root: Path, observers: dict[str, Any], records: list[dict[str, Any]], *, skipped: bool,
) -> dict[str, Any]:
    """Verify V2 observer lifecycles, not continuous network reachability.

    The service journal independently inventories starts/stops, while each
    nested verifier replays the sealed artifact bytes. Only the conservative
    READY -> stop-request interval counts, never process exit or report time.
    """
    kinds = {"kernel_network": ("kernel", "run_id"),
             "network_witness": ("network", "observation_id")}
    inventory = {kind: observers[kind] for kind in kinds}
    if any(not isinstance(items, list) for items in inventory.values()):
        _fail("V2 observer inventories must be arrays")
    events: dict[tuple[str, int, str], tuple[int, dict[str, Any]]] = {}
    boundaries: dict[str, int] = {}
    capture_started: dict[tuple[str, int], int] = {}
    capture_ended: dict[tuple[str, int], int] = {}
    for index, record in enumerate(records):
        body = record["body"]
        payload = body["payload"]
        event = payload.get("event") if isinstance(payload, dict) else None
        if event in {"SYMBOL_EPOCH_LAUNCHED", "SYMBOL_EPOCH_EXITED", "SYMBOL_FINAL_EPOCH_EXITED"}:
            key = (payload.get("symbol"), _u64(payload.get("epoch"), "capture epoch"))
            if key[0] not in {"BTCUSDT", "ETHUSDT"} or key[1] == 0:
                _fail("capture lifecycle identity is invalid")
            wall = _u64(body["wall_ns"], "capture lifecycle wall clock")
            if event == "SYMBOL_EPOCH_LAUNCHED":
                if key in capture_started:
                    _fail("capture lifecycle launch is duplicated")
                capture_started[key] = wall
            else:
                if key not in capture_started or key in capture_ended or wall < capture_started[key]:
                    _fail("capture lifecycle exit is unmatched or regressed")
                capture_ended[key] = wall
        if event in {"OBSERVER_CAPTURE_INTERVAL_STARTED", "OBSERVER_CAPTURE_INTERVAL_ENDED"}:
            if tuple(payload) != ("event",) or event in boundaries:
                _fail("observer capture boundary is duplicated or malformed")
            boundaries[event] = _u64(body["wall_ns"], "observer capture boundary")
        elif event in {"OBSERVER_WINDOW_READY", "OBSERVER_WINDOW_STOP_REQUESTED", "OBSERVER_WINDOW_SEALED"}:
            kind = payload.get("kind")
            epoch = _u64(payload.get("epoch"), "observer event epoch")
            if kind not in kinds or epoch == 0:
                _fail("observer event identity is invalid")
            key = (kind, epoch, event)
            if key in events:
                _fail("observer lifecycle event is duplicated")
            events[key] = (index, payload)
    if skipped:
        if events or any(inventory.values()):
            _fail("skipped observers nevertheless declare window evidence")
        return {"status": "SKIPPED_NOT_ELEVATED", "windows": 0}
    if set(boundaries) != {"OBSERVER_CAPTURE_INTERVAL_STARTED", "OBSERVER_CAPTURE_INTERVAL_ENDED"}:
        _fail("observer coverage lacks its exact required interval")
    lower = boundaries["OBSERVER_CAPTURE_INTERVAL_STARTED"]
    upper = boundaries["OBSERVER_CAPTURE_INTERVAL_ENDED"]
    if upper <= lower:
        _fail("observer required interval regressed or is empty")
    if (not capture_started or set(capture_started) != set(capture_ended)
            or min(capture_started.values()) < lower or max(capture_ended.values()) > upper):
        _fail("observer boundaries do not cover the complete capture lifecycle")
    count = len(inventory["kernel_network"])
    if not count or len(inventory["network_witness"]) != count:
        _fail("observer window pairs are missing")
    epoch_root = root / "obs" / "epochs"
    if not epoch_root.is_dir() or {item.name for item in epoch_root.iterdir() if item.is_dir()} != {
        f"{epoch:06d}" for epoch in range(1, count + 1)
    }:
        _fail("observer on-disk window inventory differs from the terminal")
    consumed: set[tuple[str, int, str]] = set()
    for kind, (folder, identity) in kinds.items():
        covered_until = lower
        previous_stops: list[int] = []
        previous_ready = -1
        identities: set[str] = set()
        for epoch, item in enumerate(inventory[kind], 1):
            if not isinstance(item, dict) or tuple(item) != OBSERVER_WINDOW_KEYS + (identity,):
                _fail("observer window schema/order drifted")
            if _u64(item["epoch"], "observer epoch") != epoch:
                _fail("observer window sequence is not complete")
            expected_root = f"obs/epochs/{epoch:06d}/{folder}"
            expected_report = f"verification/observers/{epoch:06d}/{folder}.json"
            if item["artifact_root"] != expected_root or item["verification_path"] != expected_report:
                _fail("observer window paths disagree with its epoch")
            observer_id = _text(item[identity], "observer identity")
            if observer_id in identities:
                _fail("observer window identity was reused")
            identities.add(observer_id)
            start, ready, stop, terminal = (
                _u64(item[key], key) for key in (
                    "started_wall_ns", "ready_wall_ns", "stop_requested_wall_ns", "terminal_wall_ns",
                )
            )
            if not 0 < start <= ready < stop <= terminal or ready <= previous_ready:
                _fail("observer lifecycle timestamps are invalid")
            if ready > covered_until or stop <= lower:
                _fail("observer coverage has a gap or a window outside the required interval")
            if len(previous_stops) >= 2 and ready < previous_stops[-2]:
                _fail("more than two observer windows overlap")
            prior_index = -1
            for event, fields in (
                ("OBSERVER_WINDOW_READY", ("artifact_root", "started_wall_ns", "ready_wall_ns")),
                ("OBSERVER_WINDOW_STOP_REQUESTED", ("stop_requested_wall_ns",)),
                ("OBSERVER_WINDOW_SEALED", ("terminal_wall_ns", "verification_path", "verification_sha256")),
            ):
                key = (kind, epoch, event)
                if key not in events:
                    _fail("observer window lacks journal lifecycle evidence")
                index, payload = events[key]
                expected = {"event": event, "kind": kind, "epoch": epoch,
                            **{field: item[field] for field in fields}}
                if payload != expected or index <= prior_index:
                    _fail("observer lifecycle differs from the service journal")
                consumed.add(key)
                prior_index = index
            artifact = _relative(root, expected_root, "observer artifact", directory=True)
            # Reject links/reparse points rather than auditing another tree.
            _root(root / expected_root)
            stored = _observer_entry(root, {
                "path": expected_report, "sha256": item["verification_sha256"], identity: observer_id,
            }, expected_report, identity)
            try:
                actual = (verify_kernel_network_production(artifact) if kind == "kernel_network"
                          else verify_network_witness(artifact))
            except ValueError as error:
                raise HotServiceCorruption(f"{kind} window failed independent replay: {error}") from error
            if stored != actual or actual.get("status") != "PASS":
                _fail("observer window report differs from independent replay")
            if kind == "kernel_network":
                capture = _json(_bytes(artifact / "kernel-network-capture.json", 4 * MIB, "kernel capture"), "kernel capture")
                actual_start = _utc_ns(capture["started_utc"], "kernel start")
                actual_end = _utc_ns(capture["completed_utc"], "kernel end")
                if capture["controller_records"][-1].get("stop_reason") != "STOP_FILE":
                    _fail("kernel observer stopped before its requested rotation")
            else:
                startup = _json(_bytes(artifact / "network-witness-startup.json", MIB, "witness startup"), "witness startup")
                seal = _json(_bytes(artifact / "network-witness-seal.json", MIB, "witness seal"), "witness seal")
                actual_start = _utc_ns(startup["started_utc"], "witness start")
                actual_end = _utc_ns(seal["finished_utc"], "witness end")
                if seal.get("stop_reason") != "STOP_FILE":
                    _fail("network witness stopped before its requested rotation")
            # datetime truncates sub-microsecond .NET timestamp precision;
            # this tolerance applies only to conversion, never gap filling.
            if actual_start > ready or actual_end + 999 < stop:
                _fail("observer coverage exceeds its independently sealed lifetime")
            covered_until = max(covered_until, stop)
            previous_ready = ready
            previous_stops.append(stop)
        if covered_until < upper:
            _fail("observer coverage ends before capture stopped")
    if consumed != set(events):
        _fail("observer terminal omitted a journalled window")
    return {"status": "COMPLETE", "windows": count, "required_start_wall_ns": lower,
            "required_end_wall_ns": upper, "scope": "OBSERVER_LIFECYCLE_NOT_CONTINUOUS_REACHABILITY"}


def _verify_expected_artifacts(
    root: Path, entry: dict[str, Any], records: list[dict[str, Any]], symbol: str,
) -> str:
    path = _relative(root, entry["expected_artifact_inventory"], "expected artifact inventory")
    data = _bytes(path, 16 * MIB, "expected artifact inventory")
    digest = sha256(data).hexdigest()
    if digest != _digest(entry["expected_artifact_inventory_sha256"], "expected inventory digest"):
        _fail("expected artifact inventory digest disagrees")
    inventory = _json(data, "expected artifact inventory")
    if tuple(inventory) != ("schema", "artifacts", "journals") or inventory["schema"] != "LiveArbitrationExpectedArtifactsV1":
        _fail("expected artifact inventory schema drifted")
    admitted: set[Path] = set()
    for record in records:
        payload = record["body"]["payload"]
        if isinstance(payload, dict) and payload.get("event") == "RAW_ARTIFACT_DISCOVERED":
            if tuple(payload) != ("event", "symbol", "epoch", "artifact"):
                _fail("raw artifact admission schema drifted")
            if payload["symbol"] not in {"BTCUSDT", "ETHUSDT"} or _u64(payload["epoch"], "admitted epoch") == 0:
                _fail("raw artifact admission identity is invalid")
            artifact = _relative(root, payload["artifact"], "admitted raw artifact", directory=True)
            if payload["symbol"] == symbol.upper():
                if artifact in admitted:
                    _fail("raw artifact was admitted twice")
                admitted.add(artifact)
    expected = inventory["artifacts"]
    if not isinstance(expected, list) or not expected:
        _fail("expected artifact inventory is empty")
    expected_paths: list[Path] = []
    for value in expected:
        absolute = Path(_text(value, "expected artifact"))
        if not absolute.is_absolute():
            _fail("service expected artifact is not absolute")
        resolved = _root(absolute)
        if not resolved.is_relative_to(root):
            _fail("service expected artifact escapes its run")
        expected_paths.append(resolved)
    if len(set(expected_paths)) != len(expected_paths) or set(expected_paths) != admitted:
        _fail("expected artifacts differ from independently journalled admissions")
    # Admission and manifest have the same producer. Independently enumerate
    # the service's fixed physical source layout too, so a forgotten epoch
    # cannot disappear from both lists and still obtain a complete result.
    source_root = root / symbol[0].lower()
    if not source_root.is_dir():
        _fail("service symbol source root is missing")
    discovered: set[Path] = set()
    for epoch_root in source_root.iterdir():
        if not epoch_root.is_dir():
            continue
        if not re.fullmatch(r"e[1-9][0-9]*", epoch_root.name):
            _fail("service source epoch directory is invalid")
        for artifact in epoch_root.iterdir():
            if artifact.is_dir():
                discovered.add(_root(artifact))
    if discovered != admitted:
        _fail("raw source directories differ from the admitted inventory")
    journals = inventory["journals"]
    if not isinstance(journals, list) or not journals:
        _fail("expected inventory has no journal cuts")
    journal_root = _relative(root, entry["journal_root"], "canonical journal root", directory=True)
    cuts: set[Path] = set()
    for cut in journals:
        if not isinstance(cut, dict) or tuple(cut) != ("path", "sha256"):
            _fail("expected journal cut schema drifted")
        cut_path = Path(_text(cut["path"], "expected journal cut"))
        if not cut_path.is_absolute():
            _fail("expected journal cut is not absolute")
        cut_path = cut_path.resolve(strict=True)
        if cut_path.parent != journal_root or cut_path in cuts or not cut_path.is_file():
            _fail("expected journal cut escapes or duplicates its journal set")
        # Stream potentially large immutable canonical journals.
        if _file_sha256(cut_path, "expected journal cut") != _digest(cut["sha256"], "expected journal cut digest"):
            _fail("expected journal cut changed after oracle verification")
        cuts.add(cut_path)
    # Match the canonical verifier's own journal-root glob, independently of
    # the producer's supplied list. Other evidence JSON is not a journal.
    actual_journals = {item.resolve() for item in journal_root.glob("*.jsonl") if item.is_file()}
    if cuts != actual_journals:
        _fail("expected inventory omitted a canonical journal")
    return digest


def _verify_failure(root: Path) -> dict[str, Any]:
    preflight_data = _bytes(root / "preflight.json", 4 * MIB, "preflight")
    failure_data = _bytes(root / "service-failure.json", 8 * MIB, "failure")
    journal_data = _bytes(root / "service-events.jsonl", 64 * MIB, "journal")
    preflight = _json(preflight_data, "preflight")
    failure = _json(failure_data, "failure")
    if tuple(preflight) != PREFLIGHT_KEYS or tuple(failure) != FAILURE_KEYS:
        _fail("failure preflight/report schema or order drifted")
    run_id = root.name
    if (
        not re.fullmatch(r"hrs-[0-9a-f]{12}", run_id)
        or preflight.get("run_id") != run_id
        or failure["schema"] != "HotRedundantQualificationFailureV1"
        or failure["status"] != "FAILED"
        or failure["run_id"] != run_id
    ):
        _fail("failure identity is invalid")
    summary = failure["failure"]
    if not isinstance(summary, dict) or tuple(summary) != (
        "exception_type", "hresult", "fully_qualified_error_id", "category", "message",
    ):
        _fail("failure summary schema/order drifted")
    for key in ("exception_type", "fully_qualified_error_id", "category", "message"):
        _text(summary[key], f"failure {key}")
    if isinstance(summary["hresult"], bool) or not isinstance(summary["hresult"], int):
        _fail("failure HRESULT is not an integer")
    records, lines = _scan_journal(journal_data)
    first = records[0]["body"]["payload"]
    last = records[-1]["body"]["payload"]
    failure_sha = sha256(failure_data).hexdigest()
    if (
        first != {"event": "SERVICE_STARTED", "run_id": run_id, "preflight_sha256": sha256(preflight_data).hexdigest()}
        or last != {"event": "SERVICE_FAILED_COMMITTED", "failure_file": "service-failure.json", "failure_sha256": failure_sha}
    ):
        _fail("failure journal start/commit authority is invalid")
    prefix = failure["journal_precommit"]
    if not isinstance(prefix, dict) or tuple(prefix) != PREFIX_KEYS:
        _fail("failure precommit schema/order drifted")
    count = _u64(prefix["records"], "failure precommit records")
    size = _u64(prefix["file_bytes"], "failure precommit bytes")
    if count == 0 or count + 1 != len(records) or size != sum(map(len, lines[:count])):
        _fail("failure precommit boundary is invalid")
    if (
        sha256(journal_data[:size]).hexdigest() != _digest(prefix["file_sha256"], "failure precommit digest")
        or prefix["terminal_record_sha256"] != records[count - 1]["record_sha256"]
        or records[count - 1]["body"]["payload"] != {"event": "SERVICE_FAILURE_PREPARED", "failure": failure["failure"]}
    ):
        _fail("failure report does not match its exact prepared journal prefix")
    _time(failure["observed_utc"], "failure observation")
    if not isinstance(failure["elapsed_s"], (int, float)) or isinstance(failure["elapsed_s"], bool) or failure["elapsed_s"] < 0:
        _fail("failure elapsed time is invalid")
    return {
        "schema": "HotRedundantServiceVerificationV1",
        "status": "PASS",
        "run_id": run_id,
        "terminal_status": "FAILED",
        "failure_sha256": failure_sha,
        "journal_sha256": sha256(journal_data).hexdigest(),
        "journal_records": len(records),
        "failure_type": summary["exception_type"],
        "failure_message": summary["message"],
    }


def verify_hot_service(path: Path) -> dict[str, Any]:
    root = _root(path)
    has_terminal = (root / "service-terminal.json").is_file()
    has_failure = (root / "service-failure.json").is_file()
    if has_terminal == has_failure:
        _fail("service root must contain exactly one success terminal or failure report")
    if has_failure:
        return _verify_failure(root)
    preflight_data = _bytes(root / "preflight.json", 4 * MIB, "preflight")
    terminal_data = _bytes(root / "service-terminal.json", 8 * MIB, "terminal")
    journal_data = _bytes(root / "service-events.jsonl", 64 * MIB, "journal")
    preflight = _json(preflight_data, "preflight")
    terminal = _json(terminal_data, "terminal")
    if tuple(preflight) != PREFLIGHT_KEYS or tuple(terminal) != TERMINAL_KEYS:
        _fail("preflight or terminal schema/order drifted")
    run_id = root.name
    if not re.fullmatch(r"hrs-[0-9a-f]{12}", run_id):
        _fail("service run identity is invalid")
    if (
        preflight["schema"] != "HotRedundantQualificationPreflightV1"
        or preflight["status"] != "PASS"
        or preflight["run_id"] != run_id
        or Path(_text(preflight["run_root"], "preflight run root")).resolve() != root
        or preflight["symbols"] != ["BTCUSDT", "ETHUSDT"]
        or terminal["schema"] not in {"HotRedundantQualificationTerminalV1", "HotRedundantQualificationTerminalV2"}
        or terminal["run_id"] != run_id
        or terminal["requested_duration_s"] != preflight["total_seconds"]
        or _time(terminal["finished_utc"], "finished") < _time(terminal["started_utc"], "started")
    ):
        _fail("preflight and terminal identities disagree")
    # Continuous-mode envelope (ADR-17 B2): the terminal must declare the
    # same mode and control-clock contract the preflight sealed, with typed
    # booleans for every lifecycle flag (never missing, never a string).
    for key in ("continuous", "skip_kernel_observer"):
        if not isinstance(preflight[key], bool):
            _fail(f"preflight {key} is not a boolean")
    for key in (
        "continuous", "stop_requested", "storage_safe_stop", "observers_skipped",
    ):
        if not isinstance(terminal[key], bool):
            _fail(f"terminal {key} is not a boolean")
    if (
        terminal["mode"] != preflight["mode"]
        or terminal["continuous"] != preflight["continuous"]
        or terminal["time_scale"] != preflight["time_scale"]
        or terminal["epoch_window_s"] != preflight["epoch_window_seconds"]
        or terminal["observers_skipped"] != preflight["skip_kernel_observer"]
        or (terminal["continuous"] and terminal["storage_safe_stop"] and terminal["stop_requested"] is False)
    ):
        _fail("preflight and terminal mode/clock contracts disagree")
    if not isinstance(terminal["verified_windows"], list):
        _fail("verified windows inventory is not a list")

    records, lines = _scan_journal(journal_data)
    first = records[0]["body"]["payload"]
    last = records[-1]["body"]["payload"]
    terminal_sha = sha256(terminal_data).hexdigest()
    if (
        records[0]["body"]["channel"] != "SERVICE"
        or first != {"event": "SERVICE_STARTED", "run_id": run_id, "preflight_sha256": sha256(preflight_data).hexdigest()}
        or records[-1]["body"]["channel"] != "SERVICE"
        or last != {"event": "SERVICE_COMMITTED", "terminal_file": "service-terminal.json", "terminal_sha256": terminal_sha}
    ):
        _fail("service start/commit authority is invalid")
    prefix = terminal["journal_precommit"]
    if not isinstance(prefix, dict) or tuple(prefix) != PREFIX_KEYS:
        _fail("journal precommit schema/order drifted")
    prefix_records = _u64(prefix["records"], "precommit records")
    prefix_bytes = _u64(prefix["file_bytes"], "precommit bytes")
    if prefix_records == 0 or prefix_records + 1 != len(records) or prefix_bytes != sum(map(len, lines[:prefix_records])):
        _fail("journal precommit boundary is not exact")
    exact_prefix = journal_data[:prefix_bytes]
    if (
        sha256(exact_prefix).hexdigest() != _digest(prefix["file_sha256"], "precommit digest")
        or prefix["terminal_record_sha256"] != records[prefix_records - 1]["record_sha256"]
        or records[prefix_records - 1]["body"]["payload"] != {"event": "SERVICE_TERMINAL_PREPARED"}
    ):
        _fail("journal precommit prefix disagrees")

    statuses: dict[str, int] = {"BTCUSDT": 0, "ETHUSDT": 0}
    verification = terminal["verification"]
    if not isinstance(verification, list) or not verification:
        _fail("nested verification inventory is empty")
    for item in verification:
        if not isinstance(item, dict) or item.get("symbol") not in statuses:
            _fail("nested verification identity is invalid")
        if item.get("status") == "INCOMPLETE_PRESERVED":
            if tuple(item) != INCOMPLETE_VERIFICATION_KEYS:
                _fail("incomplete nested verification schema drifted")
            _relative(root, item["artifact"], "incomplete artifact", directory=True)
            continue
        if tuple(item) == PASS_VERIFIED_IN_LOOP_KEYS and item.get("verified_in_loop") is True:
            # Continuous (ADR-17 B2): the window was sealed and verified
            # in-loop by both oracles; the terminal references those exact
            # reports without re-running the closed verification.
            artifact = _relative(root, item["artifact"], "hot artifact", directory=True)
            rust_path = _relative(root, item["rust_report"], "Rust report")
            python_path = _relative(root, item["python_report"], "Python report")
            rust_data = _bytes(rust_path, 8 * MIB, "Rust report")
            python_data = _bytes(python_path, 8 * MIB, "Python report")
            try:
                actual = verify_hot_redundant_capture(artifact)
            except HotRedundantCorruption as error:
                raise HotServiceCorruption(f"nested hot artifact rejected: {error}") from error
            if actual["symbol"] != item["symbol"]:
                _fail("nested hot artifact disagrees with the service terminal")
            rust_stored = _json(rust_data, "Rust report")
            python_stored = _json(python_data, "Python report")
            if python_stored != actual:
                _fail("stored Python report differs from independent replay")
            if (
                rust_stored.get("status") != "PASS"
                or rust_stored.get("supervisor_id") != actual["supervisor_id"]
                or rust_stored.get("terminal_file_sha256") != actual["terminal_file_sha256"]
                or rust_stored.get("journal_terminal_sha256") != actual["journal_terminal_sha256"]
            ):
                _fail("stored Rust report does not converge with independent replay")
            statuses[item["symbol"]] += 1
            continue
        if item.get("status") != "PASS" or tuple(item) != PASS_VERIFICATION_KEYS:
            _fail("PASS nested verification schema drifted")
        artifact = _relative(root, item["artifact"], "hot artifact", directory=True)
        rust_path = _relative(root, item["rust_report"], "Rust report")
        python_path = _relative(root, item["python_report"], "Python report")
        rust_data = _bytes(rust_path, 8 * MIB, "Rust report")
        python_data = _bytes(python_path, 8 * MIB, "Python report")
        if sha256(rust_data).hexdigest() != _digest(item["rust_report_sha256"], "Rust report digest"):
            _fail("Rust report digest disagrees")
        if sha256(python_data).hexdigest() != _digest(item["python_report_sha256"], "Python report digest"):
            _fail("Python report digest disagrees")
        try:
            actual = verify_hot_redundant_capture(artifact)
        except HotRedundantCorruption as error:
            raise HotServiceCorruption(f"nested hot artifact rejected: {error}") from error
        if (
            actual["symbol"] != item["symbol"]
            or actual["supervisor_id"] != item["supervisor_id"]
            or actual["terminal_file_sha256"] != item["terminal_sha256"]
            or actual["journal_terminal_sha256"] != item["journal_sha256"]
        ):
            _fail("nested hot artifact disagrees with the service terminal")
        rust_stored = _json(rust_data, "Rust report")
        python_stored = _json(python_data, "Python report")
        if python_stored != actual:
            _fail("stored Python report differs from independent replay")
        if (
            rust_stored.get("status") != "PASS"
            or rust_stored.get("supervisor_id") != actual["supervisor_id"]
            or rust_stored.get("terminal_file_sha256") != actual["terminal_file_sha256"]
            or rust_stored.get("journal_terminal_sha256") != actual["journal_terminal_sha256"]
        ):
            _fail("stored Rust report does not converge with independent replay")
        statuses[item["symbol"]] += 1
    if any(count == 0 for count in statuses.values()):
        _fail("one symbol has no independently verified artifact")

    observers = terminal["observer_verification"]
    if not isinstance(observers, dict) or tuple(observers) != (
        "kernel_network", "network_witness", "system_evidence", "live_arbitration",
    ):
        _fail("observer verification inventory drifted")
    system_stored = _observer_entry(root, observers["system_evidence"], "verification/system-evidence.json", "run_id")
    if terminal["schema"] == "HotRedundantQualificationTerminalV2":
        observer_coverage = _verify_observer_windows(
            root, observers, records[:prefix_records], skipped=terminal["observers_skipped"],
        )
    else:
        kernel_stored = _observer_entry(root, observers["kernel_network"], "verification/kernel-network.json", "run_id")
        network_stored = _observer_entry(root, observers["network_witness"], "verification/network-witness.json", "observation_id")
        skipped = {
            "kernel_network": kernel_stored.get("status") == "SKIPPED_NOT_ELEVATED",
            "network_witness": network_stored.get("status") == "SKIPPED_NOT_ELEVATED",
        }
        if skipped["kernel_network"] or skipped["network_witness"]:
            if terminal["observers_skipped"] is not True:
                _fail("observer skip recorded but the terminal does not declare observers_skipped")
        kernel = verify_kernel_network_production(root / "obs" / "kernel") if not skipped["kernel_network"] else None
        network = verify_network_witness(root / "obs" / "network") if not skipped["network_witness"] else None
        for stored, actual, label in ((kernel_stored, kernel, "kernel"), (network_stored, network, "network")):
            if actual is not None and stored != actual:
                _fail(f"stored {label} verification differs from independent replay")
        observer_coverage = {"status": "UNVERIFIED_LEGACY_V1"}
    system = verify_system_evidence(root / "obs" / "system")
    if system_stored != system:
        _fail("stored system verification differs from independent replay")

    # Live arbitration (ADR-17 B5): the terminal references the closed
    # journal-set oracle reports executed at the terminal in BOTH languages.
    # The heavy raw walk is not re-derived here (it is re-EXECUTED by the
    # launcher at the terminal and by the independent closed audit); this
    # verifier enforces the stored digests and the content contract.
    live = observers["live_arbitration"]
    if not isinstance(live, dict) or tuple(live) != ("btcusdt", "ethusdt"):
        _fail("live arbitration inventory drifted")
    for symbol in ("btcusdt", "ethusdt"):
        entry = live[symbol]
        v2 = terminal["schema"] == "HotRedundantQualificationTerminalV2"
        if not isinstance(entry, dict) or tuple(entry) != (LIVE_ARBITRATION_KEYS_V2 if v2 else LIVE_ARBITRATION_KEYS):
            _fail("live arbitration entry schema drifted")
        expected_digest = _verify_expected_artifacts(root, entry, records[:prefix_records], symbol) if v2 else None
        if entry["oracle_identity"] != "PASS" or entry["exit_code"] != 0:
            _fail(f"{symbol} live arbitration oracle identity is not PASS")
        _relative(root, entry["journal_root"], "canonical journal root", directory=True)
        journal_file = _relative(root, entry["journal"], f"{symbol} journal")
        if _file_sha256(journal_file, f"{symbol} journal") != _digest(entry["journal_sha256"], f"{symbol} journal digest"):
            _fail(f"{symbol} journal digest disagrees")
        rust_path = _relative(root, entry["rust_report"], "Rust arbitration report")
        python_path = _relative(root, entry["python_report"], "Python arbitration report")
        rust_data = _bytes(rust_path, 8 * MIB, "Rust arbitration report")
        python_data = _bytes(python_path, 8 * MIB, "Python arbitration report")
        if sha256(rust_data).hexdigest() != _digest(entry["rust_report_sha256"], "Rust arbitration digest"):
            _fail(f"{symbol} Rust arbitration report digest disagrees")
        if sha256(python_data).hexdigest() != _digest(entry["python_report_sha256"], "Python arbitration digest"):
            _fail(f"{symbol} Python arbitration report digest disagrees")
        rust_stored = _json(rust_data, "Rust arbitration report")
        python_stored = _json(python_data, "Python arbitration report")
        for stored, label in ((rust_stored, "Rust"), (python_stored, "Python")):
            if stored.get("status") != "PASS" or stored.get("oracle_identity") != "PASS":
                _fail(f"{symbol} {label} arbitration report is not PASS")
            if v2 and (
                stored.get("schema") != "LiveArbitrationVerificationV2"
                or stored.get("artifact_coverage") != "PASS"
                or stored.get("terminal_complete") is not True
                or stored.get("terminal_completion_scope") != "SEALED_DRAIN"
                or stored.get("canonical_view") != "OBSERVATIONS_PLUS_UNKNOWN_LATE_CORRECTIONS"
                or stored.get("coverage_exhaustive") is not True
                or stored.get("expected_artifact_inventory_sha256") != expected_digest
            ):
                _fail(f"{symbol} {label} arbitration report does not prove complete expected coverage")
        if (
            rust_stored.get("trades") != entry["canonical_trades"]
            or rust_stored.get("depth_frames") != entry["canonical_depth_frames"]
            or rust_stored.get("gaps") != entry["canonical_gaps"]
            or rust_stored.get("segments") != entry["canonical_segments"]
        ):
            _fail(f"{symbol} arbitration counts disagree with the terminal")
        if v2:
            python_audit = python_stored.get("audit")
            if not isinstance(python_audit, dict):
                _fail(f"{symbol} Python arbitration audit is missing")
            for report in (rust_stored, python_audit):
                for field in ("trades", "depth_frames", "gaps", "segments", "late_corrections"):
                    _u64(report.get(field), f"{symbol} oracle {field}")
                _digest(report.get("last_record_sha256"), f"{symbol} oracle last record digest")
            if any(
                python_audit.get(field) != rust_stored.get(field)
                for field in ("trades", "depth_frames", "gaps", "segments", "late_corrections", "last_record_sha256")
            ):
                _fail(f"{symbol} independent arbitration reports disagree")
            reconstructed = _u64(rust_stored.get("reconstructed_trades"), "Rust reconstructed trades")
            python_reconstructed = _u64(python_stored.get("reconstructed_trades"), "Python reconstructed trades")
            if (reconstructed != python_reconstructed or reconstructed < rust_stored["trades"]
                    or reconstructed > rust_stored["trades"] + rust_stored["late_corrections"]):
                _fail(f"{symbol} reconstructed trade views disagree or have impossible counts")

    failures = terminal["observer_failures"]
    closed = terminal["outer_gaps"]
    opened = terminal["open_outer_gaps"]
    if not all(isinstance(value, list) for value in (failures, closed, opened)):
        _fail("failure/gap inventories are not arrays")
    if terminal["schema"] == "HotRedundantQualificationTerminalV2":
        declared_failures = [_text(value, "observer failure ID") for value in failures]
        journal_failures = {
            _text(record["body"]["payload"].get("failure_id"), "journal observer failure ID")
            for record in records[:prefix_records]
            if isinstance(record["body"]["payload"], dict)
            and record["body"]["payload"].get("event") == "OBSERVER_FAILED"
        }
        if len(set(declared_failures)) != len(declared_failures) or set(declared_failures) != journal_failures:
            _fail("terminal observer failure inventory differs from the journal")
    active_gaps: dict[str, dict[str, Any]] = {}
    journal_closed: list[dict[str, Any]] = []
    for record in records[:prefix_records]:
        payload = record["body"]["payload"]
        if not isinstance(payload, dict):
            _fail("service event payload is not an object")
        event = payload.get("event")
        if event == "OUTER_GAP_OPENED":
            symbol = payload.get("symbol")
            if symbol not in statuses or symbol in active_gaps:
                _fail("outer gap opened with an invalid symbol/state")
            active_gaps[symbol] = {
                "symbol": symbol,
                "gap_id": payload.get("gap_id"),
                "opened_elapsed_ticks": payload.get("opened_elapsed_ticks"),
            }
        elif event == "OUTER_GAP_CLOSED":
            gap = payload.get("gap")
            if not isinstance(gap, dict) or tuple(gap) != (
                "symbol", "gap_id", "opened_elapsed_ticks", "closed_elapsed_ticks",
                "unavailable_ticks",
            ):
                _fail("closed outer gap schema/order drifted")
            symbol = gap["symbol"]
            prior = active_gaps.pop(symbol, None)
            opened_tick = _u64(gap["opened_elapsed_ticks"], "gap opening")
            closed_tick = _u64(gap["closed_elapsed_ticks"], "gap closing")
            unavailable = _u64(gap["unavailable_ticks"], "gap duration")
            if (
                prior is None or prior != {key: gap[key] for key in prior}
                or closed_tick < opened_tick or unavailable != closed_tick - opened_tick
            ):
                _fail("closed outer gap does not match its opening")
            journal_closed.append(gap)
    journal_open = [active_gaps[symbol] for symbol in sorted(active_gaps)]
    terminal_open = sorted(opened, key=lambda item: item.get("symbol", "") if isinstance(item, dict) else "")
    if closed != journal_closed or terminal_open != journal_open:
        _fail("terminal outer gaps disagree with the journal state machine")
    expected_status = (
        "PASS" if not failures and not closed and not opened else
        "CAPTURE_COMPLETE_WITH_EXPLICIT_GAPS" if not failures else
        "CAPTURE_COMPLETE_WITH_OBSERVABILITY_FAILURES"
    )
    if terminal["status"] != expected_status:
        _fail("terminal status contradicts its failure/gap evidence")
    return {
        "schema": "HotRedundantServiceVerificationV2",
        "status": "PASS",
        "run_id": run_id,
        "terminal_status": terminal["status"],
        "observer_coverage": observer_coverage,
        "terminal_sha256": terminal_sha,
        "journal_sha256": sha256(journal_data).hexdigest(),
        "journal_records": len(records),
        "verified_symbol_epochs": statuses,
        "closed_outer_gaps": len(closed),
        "open_outer_gaps": len(opened),
        "observer_failures": len(failures),
    }
