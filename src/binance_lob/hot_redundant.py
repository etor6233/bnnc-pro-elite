"""Independent offline verifier for hot-redundant capture artifacts.

This module deliberately performs no network or order-entry operation.  It
validates the supervisor envelope in Python and delegates each successful raw
lane to the already independent Python RawCampaignV1 verifier.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
from typing import Any

from .raw_campaign import RawCampaignCorruption, verify_raw_campaign

_SPEC_REVISION = "976cc580553890e92031b77306147c0ed1de5a46"
_ZERO_SHA256 = "0" * 64
_MAX_RECORD_BYTES = 1024 * 1024
_STARTUP_KEYS = {
    "schema", "supervisor_id", "artifact_id", "symbol", "total_duration_s",
    "primary_rotation_s", "shadow_rotation_s", "overlap_s", "segment_s",
    "primary_window_s", "shadow_window_s", "process_id", "started_wall_ns",
    "executable_sha256", "raw_campaign_executable_sha256",
    "public_config_sha256", "spec_revision", "credentials", "order_entry",
}
_TERMINAL_KEYS = {
    "schema", "status", "supervisor_id", "symbol", "finished_wall_ns",
    "final_coverage", "gaps", "lane_runs", "journal_boundary",
    "journal_precommit_records", "journal_precommit_sha256", "credentials",
    "order_entry",
}
_LANE_RUN_KEYS = {
    "lane", "token", "requested_s", "started_mono_ns", "ready",
    "campaign_id", "campaign_dir", "exit_success", "exit_code",
    "failure_reason", "failure_record_sha256", "stderr_lines",
}
_JOURNAL_BODY_KEYS = {
    "schema", "record_index", "wall_ns", "supervisor_mono_ns", "channel",
    "payload", "previous_record_sha256",
}


class HotRedundantCorruption(ValueError):
    """The artifact cannot support its claimed terminal state."""


def _reject_constant(value: str) -> None:
    raise HotRedundantCorruption(f"non-finite JSON constant: {value}")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HotRedundantCorruption(f"duplicate JSON property: {key}")
        result[key] = value
    return result


def _decode(data: bytes, label: str) -> Any:
    try:
        return json.loads(
            data, parse_constant=_reject_constant, object_pairs_hook=_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HotRedundantCorruption(f"parse {label}: {exc}") from exc


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise HotRedundantCorruption(f"{label} has an inexact schema")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HotRedundantCorruption(f"{label} is not an unsigned integer")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HotRedundantCorruption(f"{label} is empty or not text")
    return value


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _compact(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _read_pretty(path: Path, label: str) -> tuple[bytes, dict[str, Any]]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise HotRedundantCorruption(f"read {label}: {exc}") from exc
    if not data.endswith(b"\n"):
        raise HotRedundantCorruption(f"{label} lacks terminal newline")
    value = _decode(data, label)
    if not isinstance(value, dict):
        raise HotRedundantCorruption(f"{label} is not an object")
    return data, value


def _scan_journal(path: Path, body_keys: set[str], schema: str) -> list[dict[str, Any]]:
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise HotRedundantCorruption(f"read {path.name}: {exc}") from exc
    records: list[dict[str, Any]] = []
    previous = _ZERO_SHA256
    for line in lines:
        if not line:
            continue
        if len(line) > _MAX_RECORD_BYTES:
            raise HotRedundantCorruption(f"{path.name} record exceeds its bound")
        envelope = _object(
            _decode(line, path.name), {"body", "record_sha256"}, "journal envelope"
        )
        body = _object(envelope["body"], body_keys, "journal body")
        actual = _digest(_compact(body))
        if (
            body["schema"] != schema
            or _integer(body["record_index"], "record index") != len(records)
            or body["previous_record_sha256"] != previous
            or envelope["record_sha256"] != actual
        ):
            raise HotRedundantCorruption(f"{path.name} hash chain is invalid")
        previous = actual
        records.append(envelope)
    if not records:
        raise HotRedundantCorruption(f"{path.name} is empty")
    return records


def _safe_campaign(root: Path, relative: Any, campaign_id: str, lane: str) -> Path:
    relative = _text(relative, "campaign directory")
    if "\\" in relative:
        raise HotRedundantCorruption("campaign directory is not portable")
    pure = PurePosixPath(relative)
    expected = f"{'p' if lane == 'PRIMARY' else 's'}/{campaign_id}"
    if pure.is_absolute() or ".." in pure.parts or relative != expected:
        raise HotRedundantCorruption("campaign directory is not exact and portable")
    try:
        resolved = (root / Path(*pure.parts)).resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise HotRedundantCorruption("campaign directory escaped its artifact") from exc
    return resolved


def _validate_gap(gap: Any, label: str) -> dict[str, Any]:
    gap = _object(
        gap,
        {"gap_id", "opened_mono_ns", "closed_mono_ns", "unavailable_ns"},
        label,
    )
    _integer(gap["gap_id"], f"{label} ID")
    opened = _integer(gap["opened_mono_ns"], f"{label} opening")
    closed = gap["closed_mono_ns"]
    unavailable = gap["unavailable_ns"]
    if closed is None:
        if unavailable is not None:
            raise HotRedundantCorruption(f"{label} open duration is contradictory")
    else:
        closed = _integer(closed, f"{label} closing")
        unavailable = _integer(unavailable, f"{label} duration")
        if closed < opened or unavailable != closed - opened:
            raise HotRedundantCorruption(f"{label} duration is invalid")
    return gap


def _failed_campaign(campaign: Path, reason: str, expected_digest: str) -> None:
    if (campaign / "campaign.json").exists():
        raise HotRedundantCorruption("failed lane contains a committed campaign")
    body_keys = {
        "schema", "record_index", "wall_ns", "campaign_mono_ns",
        "generation_index", "channel", "payload", "previous_record_sha256",
    }
    records = _scan_journal(
        campaign / "campaign-events.jsonl", body_keys, "RawCampaignJournalRecordV1"
    )
    matched = any(
        record["body"]["channel"] == "CAMPAIGN"
        and isinstance(record["body"]["payload"], dict)
        and record["body"]["payload"].get("event") == "CAMPAIGN_FAILED"
        and record["body"]["payload"].get("error") == reason
        and record["record_sha256"] == expected_digest
        for record in records
    )
    if not matched:
        raise HotRedundantCorruption("failed lane is not bound to CAMPAIGN_FAILED")


def verify_hot_redundant_capture(directory: Path) -> dict[str, Any]:
    """Verify a committed two-lane capture without trusting the Rust supervisor."""

    try:
        root = directory.resolve(strict=True)
    except OSError as exc:
        raise HotRedundantCorruption(f"resolve artifact: {exc}") from exc
    if not root.is_dir():
        raise HotRedundantCorruption("hot-redundant artifact is not a directory")
    startup_bytes, startup_value = _read_pretty(
        root / "supervisor-startup.json", "supervisor startup"
    )
    terminal_bytes, terminal_value = _read_pretty(
        root / "supervisor-terminal.json", "supervisor terminal"
    )
    startup = _object(startup_value, _STARTUP_KEYS, "supervisor startup")
    terminal = _object(terminal_value, _TERMINAL_KEYS, "supervisor terminal")
    unsigned_startup = (
        "total_duration_s", "primary_rotation_s", "shadow_rotation_s",
        "overlap_s", "segment_s", "primary_window_s", "shadow_window_s",
        "process_id", "started_wall_ns",
    )
    for key in unsigned_startup:
        _integer(startup[key], f"startup {key}")
    _integer(terminal["finished_wall_ns"], "terminal finished_wall_ns")
    if (
        startup["schema"] != "HotRedundantCaptureStartupV1"
        or terminal["schema"] != "HotRedundantCaptureTerminalV1"
        or startup["artifact_id"] != root.name
        or startup["supervisor_id"] != terminal["supervisor_id"]
        or startup["symbol"] != terminal["symbol"]
        or startup["symbol"] not in {"BTCUSDT", "ETHUSDT"}
        or startup["total_duration_s"] == 0
        or startup["total_duration_s"] > 365 * 24 * 60 * 60
        or startup["primary_rotation_s"] == startup["shadow_rotation_s"]
        or startup["overlap_s"] == 0
        or startup["overlap_s"] != startup["segment_s"]
        or startup["primary_rotation_s"] % startup["segment_s"]
        or startup["shadow_rotation_s"] % startup["segment_s"]
        or startup["primary_rotation_s"] + startup["overlap_s"] > 86_300
        or startup["shadow_rotation_s"] + startup["overlap_s"] > 86_300
        or startup["primary_window_s"] == startup["shadow_window_s"]
        or not startup["overlap_s"] <= startup["primary_window_s"] <= 604_800
        or not startup["overlap_s"] <= startup["shadow_window_s"] <= 604_800
        or startup["process_id"] == 0
        or terminal["finished_wall_ns"] < startup["started_wall_ns"]
        or terminal["final_coverage"] != "TERMINAL"
        or startup["spec_revision"] != _SPEC_REVISION
        or any(
            not _is_sha256(startup[key])
            for key in (
                "executable_sha256", "raw_campaign_executable_sha256",
                "public_config_sha256",
            )
        )
        or startup["credentials"] != terminal["credentials"] != "NONE"
        or startup["credentials"] != "NONE"
        or startup["order_entry"] != "ABSENT"
        or terminal["order_entry"] != "ABSENT"
    ):
        raise HotRedundantCorruption("startup and terminal contract is invalid")

    if not isinstance(terminal["gaps"], list) or not isinstance(terminal["lane_runs"], list):
        raise HotRedundantCorruption("terminal collections are invalid")
    terminal_gaps = [
        _validate_gap(gap, f"terminal gap {index}")
        for index, gap in enumerate(terminal["gaps"])
    ]
    expected_status = (
        "COMPLETE_WITH_OPEN_GAP"
        if any(gap["closed_mono_ns"] is None for gap in terminal_gaps)
        else "COMPLETE_NO_DUAL_OUTAGE" if not terminal_gaps
        else "COMPLETE_WITH_EXPLICIT_GAPS"
    )
    if terminal["status"] != expected_status:
        raise HotRedundantCorruption("terminal status contradicts gaps")

    journal = _scan_journal(
        root / "supervisor-events.jsonl", _JOURNAL_BODY_KEYS,
        "HotRedundantJournalRecordV1",
    )
    startup_digest = _digest(startup_bytes)
    if (
        journal[0]["body"]["channel"] != "SUPERVISOR"
        or journal[0]["body"]["payload"] != {
            "event": "SUPERVISOR_STARTED",
            "supervisor_id": startup["supervisor_id"],
            "startup_file": "supervisor-startup.json",
            "startup_sha256": startup_digest,
        }
    ):
        raise HotRedundantCorruption("supervisor startup lacks an exact durable binding")
    precommit_count = _integer(
        terminal["journal_precommit_records"], "precommit record count"
    )
    terminal_digest = _digest(terminal_bytes)
    if (
        terminal["journal_boundary"] != "PRECOMMIT_PREFIX"
        or precommit_count == 0
        or precommit_count + 1 != len(journal)
        or journal[precommit_count - 1]["record_sha256"]
        != terminal["journal_precommit_sha256"]
        or journal[precommit_count - 1]["body"]["payload"]
        != {"event": "SUPERVISOR_TERMINAL_PREPARED"}
        or journal[-1]["body"]["channel"] != "SUPERVISOR"
        or journal[-1]["body"]["payload"] != {
            "event": "SUPERVISOR_COMMITTED",
            "terminal_file": "supervisor-terminal.json",
            "terminal_sha256": terminal_digest,
        }
    ):
        raise HotRedundantCorruption("supervisor commit binding is invalid")

    gaps: dict[int, dict[str, Any]] = {}
    launches: dict[str, dict[str, Any]] = {}
    for record in journal:
        payload = record["body"]["payload"]
        if not isinstance(payload, dict):
            raise HotRedundantCorruption("journal payload is not an object")
        event = payload.get("event")
        if event == "GAP_OPENED":
            gap = _validate_gap(payload.get("gap"), "opened gap")
            if gap["gap_id"] != len(gaps) or gap["closed_mono_ns"] is not None:
                raise HotRedundantCorruption("opened gap is invalid")
            gaps[gap["gap_id"]] = gap
        elif event == "GAP_CLOSED":
            gap = _validate_gap(payload.get("gap"), "closed gap")
            prior = gaps.get(gap["gap_id"])
            if prior is None or prior["closed_mono_ns"] is not None or prior["opened_mono_ns"] != gap["opened_mono_ns"]:
                raise HotRedundantCorruption("closed gap is invalid")
            gaps[gap["gap_id"]] = gap
        elif event in {"LANE_LAUNCHED", "LANE_RESTARTED"}:
            token = _text(payload.get("token"), "lane token")
            if token in launches or payload.get("lane") not in {"PRIMARY", "SHADOW"}:
                raise HotRedundantCorruption("lane launch is invalid or duplicated")
            launches[token] = {
                "lane": payload["lane"],
                "requested_s": _integer(payload.get("requested_s"), "requested duration"),
                "ready": False, "campaign_id": None, "success": None,
                "failure_reason": None,
            }
        elif event == "LANE_READY":
            token = _text(payload.get("token"), "lane token")
            launch = launches.get(token)
            if launch is None or launch["ready"]:
                raise HotRedundantCorruption("lane readiness is invalid or duplicated")
            launch["ready"] = True
            launch["campaign_id"] = _text(payload.get("campaign_id"), "campaign ID")
        elif event in {"LANE_FAILED", "LANE_WINDOW_COMPLETED"}:
            token = _text(payload.get("token"), "lane token")
            launch = launches.get(token)
            if launch is None or launch["success"] is not None:
                raise HotRedundantCorruption("lane outcome is invalid or duplicated")
            launch["success"] = event == "LANE_WINDOW_COMPLETED"
            if not launch["success"]:
                launch["failure_reason"] = _text(payload.get("reason"), "failure reason")
    if list(gaps.values()) != terminal_gaps:
        raise HotRedundantCorruption("terminal gaps differ from durable events")

    seen: set[str] = set()
    complete = {"PRIMARY": 0, "SHADOW": 0}
    verified_lanes: list[dict[str, Any]] = []
    for lane_value in terminal["lane_runs"]:
        lane_run = _object(lane_value, _LANE_RUN_KEYS, "lane run")
        lane = lane_run["lane"]
        token = _text(lane_run["token"], "lane token")
        evidence = launches.get(token)
        if lane not in complete or token in seen or evidence is None:
            raise HotRedundantCorruption("lane run is invalid, reused, or unlaunched")
        seen.add(token)
        requested_s = _integer(lane_run["requested_s"], "lane requested duration")
        started_ns = _integer(lane_run["started_mono_ns"], "lane start")
        if (
            evidence["lane"] != lane
            or evidence["requested_s"] != requested_s
            or evidence["ready"] is not lane_run["ready"]
            or evidence["success"] is not lane_run["exit_success"]
            or evidence["campaign_id"] != lane_run["campaign_id"]
            or started_ns > startup["total_duration_s"] * 1_000_000_000
            or not isinstance(lane_run["stderr_lines"], list)
            or any(not isinstance(line, str) for line in lane_run["stderr_lines"])
            or (lane_run["exit_success"] and lane_run["stderr_lines"])
        ):
            raise HotRedundantCorruption("lane run differs from durable lifecycle")
        campaign_id = _text(lane_run["campaign_id"], "campaign ID")
        if len(campaign_id) > 80 or not all(c.isalnum() or c == "-" for c in campaign_id):
            raise HotRedundantCorruption("campaign ID is not a safe component")
        campaign = _safe_campaign(root, lane_run["campaign_dir"], campaign_id, lane)
        if lane_run["exit_success"]:
            if (
                lane_run["ready"] is not True or lane_run["exit_code"] != 0
                or lane_run["failure_reason"] is not None
                or lane_run["failure_record_sha256"] is not None
                or evidence["failure_reason"] is not None
            ):
                raise HotRedundantCorruption("successful lane has failure evidence")
            try:
                verified = verify_raw_campaign(campaign)
            except RawCampaignCorruption as exc:
                raise HotRedundantCorruption(f"child campaign rejected: {exc}") from exc
            if (
                verified["symbol"] != terminal["symbol"]
                or verified["campaign_id"] != campaign_id
                or verified["total_duration_s"] != requested_s
            ):
                raise HotRedundantCorruption("child campaign differs from lane result")
            complete[lane] += 1
            verified_lanes.append({
                "lane": lane, "token": token, "campaign_id": campaign_id,
                "status": "VERIFIED_COMPLETE",
                "campaign_verification_sha256": verified["verification_sha256"],
                "failure_record_sha256": None,
            })
        else:
            reason = _text(lane_run["failure_reason"], "failure reason")
            failure_digest = lane_run["failure_record_sha256"]
            if not _is_sha256(failure_digest) or evidence["failure_reason"] != reason:
                raise HotRedundantCorruption("failed lane lacks exact failure binding")
            _failed_campaign(campaign, reason, failure_digest)
            verified_lanes.append({
                "lane": lane, "token": token, "campaign_id": campaign_id,
                "status": "VERIFIED_FAILED_PRESERVED",
                "campaign_verification_sha256": None,
                "failure_record_sha256": failure_digest,
            })
    if seen != set(launches) or any(count == 0 for count in complete.values()):
        raise HotRedundantCorruption("a launched run is omitted or a lane never completed")

    report: dict[str, Any] = {
        "schema": "VerifiedHotRedundantCaptureV1",
        "status": "PASS",
        "supervisor_id": terminal["supervisor_id"],
        "artifact_id": startup["artifact_id"],
        "symbol": terminal["symbol"],
        "terminal_status": terminal["status"],
        "terminal_file_sha256": terminal_digest,
        "journal_records": len(journal),
        "journal_terminal_sha256": journal[-1]["record_sha256"],
        "gaps": terminal_gaps,
        "lane_campaigns": verified_lanes,
    }
    report["verification_sha256"] = _digest(_compact(report))
    return report
