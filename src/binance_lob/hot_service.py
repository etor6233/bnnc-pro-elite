"""Independent verifier for the dual-symbol hot-redundant service envelope.

The PowerShell producer is not trusted.  This verifier reconstructs its
durable journal, checks the precommit/commit boundary, and reruns each nested
Python verifier against the exact artifacts referenced by the terminal file.
"""

from __future__ import annotations

from datetime import datetime
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
        or terminal["schema"] != "HotRedundantQualificationTerminalV1"
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
    kernel_stored = _observer_entry(root, observers["kernel_network"], "verification/kernel-network.json", "run_id")
    network_stored = _observer_entry(root, observers["network_witness"], "verification/network-witness.json", "observation_id")
    system_stored = _observer_entry(root, observers["system_evidence"], "verification/system-evidence.json", "run_id")
    skipped = {
        "kernel_network": kernel_stored.get("status") == "SKIPPED_NOT_ELEVATED",
        "network_witness": network_stored.get("status") == "SKIPPED_NOT_ELEVATED",
    }
    if skipped["kernel_network"] or skipped["network_witness"]:
        if terminal["observers_skipped"] is not True:
            _fail("observer skip recorded but the terminal does not declare observers_skipped")
    kernel = verify_kernel_network_production(root / "obs" / "kernel") if not skipped["kernel_network"] else None
    network = verify_network_witness(root / "obs" / "network") if not skipped["network_witness"] else None
    system = verify_system_evidence(root / "obs" / "system")
    for stored, actual, label in (
        (kernel_stored, kernel, "kernel"), (network_stored, network, "network"),
        (system_stored, system, "system"),
    ):
        if actual is None:
            continue
        if stored != actual:
            _fail(f"stored {label} verification differs from independent replay")

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
        if not isinstance(entry, dict) or tuple(entry) != LIVE_ARBITRATION_KEYS:
            _fail("live arbitration entry schema drifted")
        if entry["oracle_identity"] != "PASS" or entry["exit_code"] != 0:
            _fail(f"{symbol} live arbitration oracle identity is not PASS")
        _relative(root, entry["journal_root"], "canonical journal root", directory=True)
        journal_file = _relative(root, entry["journal"], f"{symbol} journal")
        journal_data = _bytes(journal_file, 256 * MIB, f"{symbol} journal")
        if sha256(journal_data).hexdigest() != _digest(entry["journal_sha256"], f"{symbol} journal digest"):
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
        if (
            rust_stored.get("trades") != entry["canonical_trades"]
            or rust_stored.get("depth_frames") != entry["canonical_depth_frames"]
            or rust_stored.get("gaps") != entry["canonical_gaps"]
            or rust_stored.get("segments") != entry["canonical_segments"]
        ):
            _fail(f"{symbol} arbitration counts disagree with the terminal")

    failures = terminal["observer_failures"]
    closed = terminal["outer_gaps"]
    opened = terminal["open_outer_gaps"]
    if not all(isinstance(value, list) for value in (failures, closed, opened)):
        _fail("failure/gap inventories are not arrays")
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
        "schema": "HotRedundantServiceVerificationV1",
        "status": "PASS",
        "run_id": run_id,
        "terminal_status": terminal["status"],
        "terminal_sha256": terminal_sha,
        "journal_sha256": sha256(journal_data).hexdigest(),
        "journal_records": len(records),
        "verified_symbol_epochs": statuses,
        "closed_outer_gaps": len(closed),
        "open_outer_gaps": len(opened),
        "observer_failures": len(failures),
    }
