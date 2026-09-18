"""Independent verifier for intentional ETW-controller abort cleanup evidence."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
from typing import Any

from .kernel_network_etw import (
    MATCH_ANY_KEYWORD,
    MIB,
    SELECTED_EVENT_IDS,
    KernelNetworkEtwCorruption,
    _bytes,
    _digest,
    _json,
    _lines,
    _regular_root,
    _stats,
    _text,
    _uint,
)


EXPECTED_FILES = {
    "controller.stderr.txt",
    "controller.stdout.jsonl",
    "abort-cleanup.json",
    "kernel-network.etl",
    "wrapper-failure.json",
}


def _fail(message: str) -> None:
    raise KernelNetworkEtwCorruption(message)


def verify_kernel_network_cleanup(root: Path) -> dict[str, Any]:
    """Prove an injected controller death was detected, cleaned and never passed."""

    root = _regular_root(root)
    if {entry.name for entry in root.iterdir()} != EXPECTED_FILES:
        _fail("cleanup evidence file inventory is not exact")

    stdout = _bytes(root / "controller.stdout.jsonl", MIB, "controller stdout")
    stderr = _bytes(root / "controller.stderr.txt", MIB, "controller stderr", allow_empty=True)
    etl = _bytes(root / "kernel-network.etl", 64 * MIB, "aborted ETL")
    cleanup = _json(_bytes(root / "abort-cleanup.json", MIB, "cleanup report"), "cleanup report")
    failure = _json(_bytes(root / "wrapper-failure.json", MIB, "wrapper failure"), "wrapper failure")

    if stderr:
        _fail("aborted controller stderr is not empty")
    try:
        lines = stdout.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as error:
        _fail(f"aborted controller stdout is not UTF-8: {error}")
    if len(lines) != 1:
        _fail("aborted controller did not publish exactly one READY record")
    ready = _json(lines[0].encode("utf-8"), "controller READY")
    session_name = _text(ready.get("session_name"), "READY session name")
    if ready.get("schema") != "KernelNetworkTraceReadyV1" or ready.get("status") != "READY":
        _fail("aborted controller READY schema/status is invalid")
    if not re.fullmatch(r"BinanceKernelNetwork_[0-9a-f]{12}", session_name):
        _fail("aborted controller session name is invalid")
    if tuple(ready.get("event_ids", ())) != SELECTED_EVENT_IDS:
        _fail("aborted controller event-ID allowlist drifted")
    if ready.get("match_any_keyword") != MATCH_ANY_KEYWORD:
        _fail("aborted controller keyword filter drifted")
    if Path(_text(ready.get("etl_path"), "READY ETL path")).resolve() != (root / "kernel-network.etl").resolve():
        _fail("aborted controller ETL path escaped evidence root")
    _stats(ready.get("statistics"), "READY")

    expected_cleanup_keys = {
        "schema", "status", "trigger", "outcome", "session_name", "controller_pid",
        "controller_has_exited", "controller_exit_code", "termination_requested_exit_code",
        "termination_observed_exit_code", "controller_stdout_file",
        "controller_stdout_bytes", "controller_stdout_sha256", "controller_stderr_file",
        "controller_stderr_bytes", "controller_stderr_sha256", "etl_file", "etl_bytes",
        "etl_sha256", "orphan_observed_before_cleanup", "cleanup_attempted",
        "cleanup_exit_code", "cleanup_output",
        "post_cleanup_query_exit_code", "post_cleanup_query_output",
    }
    if set(cleanup) != expected_cleanup_keys:
        _fail("cleanup report property inventory is invalid")
    if cleanup["schema"] != "KernelNetworkTraceAbortCleanupV1" or cleanup["status"] != "PASS":
        _fail("abort cleanup report did not pass")
    if cleanup["trigger"] != "INJECTED_CONTROLLER_ABORT_AFTER_READY":
        _fail("cleanup trigger is not the intentional abort gate")
    if cleanup["session_name"] != session_name:
        _fail("cleanup session identity disagrees with READY")
    if cleanup["controller_has_exited"] is not True:
        _fail("injected controller was not observed exited")
    _uint(cleanup["controller_pid"], "controller PID", (1 << 32) - 1)
    if cleanup["controller_pid"] == 0:
        _fail("controller PID is zero")
    requested_exit = _uint(cleanup["termination_requested_exit_code"], "requested termination exit code", (1 << 32) - 1)
    observed_exit = _uint(cleanup["termination_observed_exit_code"], "observed termination exit code", (1 << 32) - 1)
    if requested_exit != 0xE701 or observed_exit != requested_exit:
        _fail("injected TerminateProcess exit identity disagrees")
    if not isinstance(cleanup["controller_exit_code"], int):
        _fail("System.Diagnostics controller exit code is not an integer")
    if cleanup["controller_stdout_file"] != "controller.stdout.jsonl" or cleanup["controller_stdout_bytes"] != len(stdout):
        _fail("cleanup stdout metadata disagrees")
    if _digest(cleanup["controller_stdout_sha256"], "cleanup stdout digest") != sha256(stdout).hexdigest():
        _fail("cleanup stdout digest disagrees")
    if cleanup["controller_stderr_file"] != "controller.stderr.txt" or cleanup["controller_stderr_bytes"] != 0:
        _fail("cleanup stderr metadata disagrees")
    if _digest(cleanup["controller_stderr_sha256"], "cleanup stderr digest") != sha256(stderr).hexdigest():
        _fail("cleanup stderr digest disagrees")
    if cleanup["etl_file"] != "kernel-network.etl" or cleanup["etl_bytes"] != len(etl):
        _fail("cleanup ETL metadata disagrees")
    if _digest(cleanup["etl_sha256"], "cleanup ETL digest") != sha256(etl).hexdigest():
        _fail("cleanup ETL digest disagrees")
    orphan_observed = cleanup["orphan_observed_before_cleanup"]
    cleanup_attempted = cleanup["cleanup_attempted"]
    if not isinstance(orphan_observed, bool) or not isinstance(cleanup_attempted, bool):
        _fail("abort cleanup booleans are invalid")
    if cleanup_attempted is not orphan_observed:
        _fail("cleanup attempt does not match pre-cleanup orphan observation")
    if orphan_observed:
        if cleanup["outcome"] != "STOPPED_BY_WRAPPER" or cleanup["cleanup_exit_code"] != 0:
            _fail("observed orphan was not stopped by the wrapper")
    elif cleanup["outcome"] != "ALREADY_ABSENT_AFTER_ABORT" or cleanup["cleanup_exit_code"] is not None:
        _fail("already-absent outcome is internally inconsistent")
    _lines(cleanup["cleanup_output"], "cleanup output")
    if not isinstance(cleanup["post_cleanup_query_exit_code"], int) or cleanup["post_cleanup_query_exit_code"] == 0:
        _fail("post-cleanup query did not prove session absence")
    _lines(cleanup["post_cleanup_query_output"], "post-cleanup query output")

    if failure.get("schema") != "KernelNetworkTraceWrapperFailureV1" or failure.get("status") != "FAILED":
        _fail("wrapper did not persist an explicit FAILED terminal")
    if failure.get("message") != "Injected controller abort cleanup qualification completed; normal PASS is forbidden.":
        _fail("wrapper failure reason does not bind abort cleanup qualification")

    return {
        "schema": "KernelNetworkTraceCleanupVerificationV1",
        "status": "PASS",
        "root": str(root),
        "session_name": session_name,
        "controller_pid": cleanup["controller_pid"],
        "controller_exit_code": cleanup["controller_exit_code"],
        "termination_exit_code": observed_exit,
        "cleanup_outcome": cleanup["outcome"],
        "etl_bytes": len(etl),
        "etl_sha256": cleanup["etl_sha256"],
        "events_lost_at_ready": 0,
        "orphan_session_after_cleanup": False,
        "false_pass": False,
    }
