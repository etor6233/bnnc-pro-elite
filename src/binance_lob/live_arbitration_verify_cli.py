"""Independent Python verifier for the live cross-lane arbitration journal.

Mirrors the Rust `live_arbitration_verify` contract with strict audit rules
(ADR-16 scanner, ADR-17 B5 oracle completion):

- the journal is an append-only hash chain (`LiveArbitrationJournalRecordV1`);
- a unique `ARBITRATION_STARTED` opens the FIRST segment; later segments of a
  resume-chained set open with `ARBITRATION_RESUMED` chaining the previous
  segment's last record SHA-256 and declaring the exact trade floor;
- every trade observation carries a strictly increasing trade ID above the
  declared floor, plus its raw lineage digests; duplicates and regressions
  are rejected;
- corrections are classified against the retained published identity:
  `duplicate` must match the published digest, `unknown` must reference an
  ID the journal never published; the terminal must declare
  `late_corrections` exactly equal to the recalculated count;
- depth observations are exactly contiguous between typed GAP records, carry
  their lane and book digest, and the first frame after a
  DEPTH_REBOOTSTRAP must start at the declared snapshot boundary;
- oracle modes compare the canonical stream against the RAW capture of both
  lanes: trades must equal the raw union above the trade floor (initial and
  final omissions are both visible), each record must carry the exact raw
  observation digest and an existing raw lineage record, and every depth
  frame must exist in the trusted contiguous prefix of the lane that
  published it (PRIMARY or SHADOW).

Nothing here rewrites raw evidence; it only reads immutable inputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import os
import sys
from pathlib import Path
from typing import BinaryIO

from .book import ApplyOutcome, LocalOrderBook
from .observations import materialize_trade_observations
from .raw_log import (
    ZERO_DIGEST,
    first_raw_segment_record,
    iter_raw_records,
    iter_raw_segment_prefix,
    iter_raw_segment_records,
)
from .segment_chain import (
    scan_durability_progress,
    scan_segment_manifest_seals,
)

JOURNAL_SCHEMA = "LiveArbitrationJournalRecordV1"
MAX_RECORD_BYTES = 1024 * 1024


class ArbitrationVerificationError(ValueError):
    """Raised with a stable reason when the journal fails its audit."""


def _digest(body: dict[str, object]) -> str:
    encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_hex64(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


class _AuditState:
    """Cumulative audit state carried across a journal set."""

    def __init__(self) -> None:
        self.records = 0
        self.observations = 0
        self.trades = 0
        self.depth_frames = 0
        self.gaps = 0
        self.late_corrections = 0
        self.rebootstrap = 0
        self.status_records = 0
        self.last_trade_id: int | None = None
        self.last_depth_sequence: int | None = None
        self.exact_next_depth: int | None = None
        self.published: dict[int, str] = {}
        self.corrected: dict[int, str] = {}
        self.started_seen = False
        self.terminal_seen = False
        self.trade_floor: int | None = None
        self.symbol: str | None = None
        self.segments = 0
        self.last_segment_sha: str | None = None
        self.last_segment_tail = 0
        self.last_record_sha = ZERO_DIGEST
        self.preset_context = False


def _read_line(handle: BinaryIO) -> bytes | None:
    line = handle.readline()
    if not line:
        return None
    if len(line) > MAX_RECORD_BYTES:
        raise ArbitrationVerificationError("journal record exceeds its bound")
    if not line.endswith(b"\n"):
        raise ArbitrationVerificationError("journal contains a partial record")
    return line[:-1]


def _apply_record(
    state: _AuditState,
    envelope: dict[str, object],
    file_index: int,
    first_of_file: bool,
    previous: str,
) -> None:
    body = envelope.get("body")
    if not isinstance(body, dict):
        raise ArbitrationVerificationError("journal record lacks its body")
    if (
        body.get("schema") != JOURNAL_SCHEMA
        or body.get("record_index") != file_index
        or body.get("channel") != "LIVE"
        or body.get("previous_record_sha256") != previous
        or envelope.get("record_sha256") != _digest(body)
    ):
        raise ArbitrationVerificationError("journal hash chain is invalid")
    payload = body.get("payload")
    if not isinstance(payload, dict):
        raise ArbitrationVerificationError("journal record lacks its payload")
    if state.terminal_seen:
        raise ArbitrationVerificationError("journal carries records after its terminal")
    event = payload.get("event")
    if event == "ARBITRATION_STARTED":
        if not first_of_file or state.segments != 0:
            raise ArbitrationVerificationError(
                "journal does not begin with ARBITRATION_STARTED"
            )
        symbol = payload.get("symbol")
        if not isinstance(symbol, str):
            raise ArbitrationVerificationError("ARBITRATION_STARTED lacks its symbol")
        state.symbol = symbol
        floor = payload.get("trade_floor")
        if floor is not None and (type(floor) is not int or floor < 0):
            raise ArbitrationVerificationError("ARBITRATION_STARTED trade_floor is invalid")
        state.trade_floor = floor
        state.started_seen = True
    elif event == "ARBITRATION_RESUMED":
        if not first_of_file or state.segments == 0:
            raise ArbitrationVerificationError(
                "ARBITRATION_RESUMED must open a later journal segment"
            )
        if not state.started_seen:
            raise ArbitrationVerificationError(
                "ARBITRATION_RESUMED lacks its ARBITRATION_STARTED segment"
            )
        symbol = payload.get("symbol")
        if state.preset_context:
            state.symbol = symbol
        elif symbol != state.symbol:
            raise ArbitrationVerificationError("ARBITRATION_RESUMED changes the journal symbol")
        chain = payload.get("previous_journal_sha256")
        if not _is_hex64(chain):
            raise ArbitrationVerificationError(
                "ARBITRATION_RESUMED lacks previous_journal_sha256"
            )
        if chain != state.last_segment_sha:
            raise ArbitrationVerificationError(
                "ARBITRATION_RESUMED does not chain the previous journal segment"
            )
        floor = payload.get("trade_floor")
        if type(floor) is not int:
            raise ArbitrationVerificationError("ARBITRATION_RESUMED lacks its trade_floor")
        expected_floor = max(state.last_trade_id or 0, state.trade_floor or 0)
        if floor != expected_floor:
            raise ArbitrationVerificationError(
                f"ARBITRATION_RESUMED trade floor {floor} does not equal the previous "
                f"segment's effective trade floor {expected_floor}"
            )
        if not isinstance(payload.get("mode"), str):
            raise ArbitrationVerificationError("ARBITRATION_RESUMED lacks its mode")
        # Crash recovery evidence: a torn previous segment must declare
        # exactly its measured tail bytes; a clean one must declare none.
        declared_tail = payload.get("previous_tail_bytes", 0)
        if type(declared_tail) is not int:
            declared_tail = 0
        if not state.preset_context and declared_tail != state.last_segment_tail:
            raise ArbitrationVerificationError(
                f"ARBITRATION_RESUMED previous_tail_bytes {declared_tail} does not match "
                f"the measured torn tail {state.last_segment_tail}"
            )
        if state.preset_context:
            state.last_segment_tail = declared_tail
    elif event == "ARBITRATION_TERMINAL":
        if not state.started_seen:
            raise ArbitrationVerificationError("journal has no ARBITRATION_STARTED")
        if payload.get("status") != "COMPLETE":
            raise ArbitrationVerificationError("journal terminal status is not COMPLETE")
        declared = (
            payload.get("trades"),
            payload.get("depth_frames"),
            payload.get("gaps"),
            payload.get("late_corrections"),
        )
        if not state.preset_context and declared != (
            state.trades, state.depth_frames, state.gaps, state.late_corrections
        ):
            raise ArbitrationVerificationError(
                "journal terminal counters do not match the audit: declared "
                f"{declared}, audited {(state.trades, state.depth_frames, state.gaps, state.late_corrections)}"
            )
        # Tail audits carry segment-local counters while the terminal
        # declares the CUMULATIVE chain counters: the equality is enforced
        # by the full-set audit at the service terminal.
        state.terminal_seen = True
    elif event == "TRADE_OBSERVATION":
        trade_id = payload.get("trade_id")
        if type(trade_id) is not int or trade_id <= 0:
            raise ArbitrationVerificationError("trade observation lacks an exact trade ID")
        observation_sha = payload.get("observation_sha256")
        if not _is_hex64(observation_sha):
            raise ArbitrationVerificationError(
                "trade observation lacks its observation digest"
            )
        if not _is_hex64(payload.get("record_sha256")):
            raise ArbitrationVerificationError("trade observation lacks its raw lineage record")
        if state.last_trade_id is not None and trade_id <= state.last_trade_id:
            raise ArbitrationVerificationError("journal trade IDs are not strictly increasing")
        if state.trade_floor is not None and trade_id <= state.trade_floor:
            raise ArbitrationVerificationError(
                "journal publishes a trade at or below its declared floor"
            )
        state.last_trade_id = trade_id
        state.published[trade_id] = observation_sha
        state.trades += 1
        state.observations += 1
    elif event == "TRADE_LATE_CORRECTION":
        trade_id = payload.get("trade_id")
        if type(trade_id) is not int:
            raise ArbitrationVerificationError("trade late correction lacks an exact trade ID")
        if state.last_trade_id is None or trade_id > state.last_trade_id:
            raise ArbitrationVerificationError(
                "trade late correction is not below the canonical position"
            )
        observation_sha = payload.get("observation_sha256")
        if not _is_hex64(observation_sha):
            raise ArbitrationVerificationError(
                "trade late correction lacks its observation digest"
            )
        if not _is_hex64(payload.get("record_sha256")):
            raise ArbitrationVerificationError(
                "trade late correction lacks its raw lineage record"
            )
        kind = payload.get("kind")
        if kind == "duplicate":
            published_digest = state.published.get(trade_id, state.corrected.get(trade_id))
            if published_digest is None:
                raise ArbitrationVerificationError(
                    "trade late correction kind=duplicate references an unpublished identity"
                )
            if published_digest != observation_sha:
                raise ArbitrationVerificationError(
                    "trade late correction kind=duplicate contradicts the published identity"
                )
        elif kind == "unknown":
            if not state.preset_context and trade_id <= (state.trade_floor or 0):
                raise ArbitrationVerificationError("unknown correction is at or below the startup trade floor")
            if trade_id in state.published or trade_id in state.corrected:
                raise ArbitrationVerificationError(
                    "trade late correction kind=unknown contradicts the published identity"
                )
            state.corrected[trade_id] = observation_sha
        else:
            # Schema compatibility policy (ADR-17 B5): corrections without a
            # known classification are REJECTED, never silently reinterpreted.
            raise ArbitrationVerificationError("trade late correction lacks its classification")
        state.late_corrections += 1
    elif event == "TRADE_LAG":
        if type(payload.get("buffered")) is not int:
            raise ArbitrationVerificationError("TRADE_LAG lacks its buffered count")
        state.status_records += 1
    elif event == "TRADE_CONFLICT":
        if type(payload.get("trade_id")) is not int:
            raise ArbitrationVerificationError("TRADE_CONFLICT lacks its trade ID")
        state.status_records += 1
    elif event == "DEPTH_OBSERVATION":
        first = payload.get("first_sequence")
        final = payload.get("final_sequence")
        if type(first) is not int or type(final) is not int:
            raise ArbitrationVerificationError("depth observation lacks exact sequences")
        if first <= 0 or final < first:
            raise ArbitrationVerificationError("journal depth range is invalid")
        if not isinstance(payload.get("lane"), str):
            raise ArbitrationVerificationError("depth observation lacks its lane")
        if not _is_hex64(payload.get("observation_sha256")):
            raise ArbitrationVerificationError("depth observation lacks its book digest")
        if not _is_hex64(payload.get("record_sha256")):
            raise ArbitrationVerificationError("depth observation lacks its raw lineage record")
        if state.exact_next_depth is not None:
            if first != state.exact_next_depth:
                raise ArbitrationVerificationError(
                    "journal depth ranges are not exactly contiguous"
                )
        elif state.last_depth_sequence is not None and first <= state.last_depth_sequence:
            raise ArbitrationVerificationError(
                "journal depth ranges regress outside a typed gap"
            )
        state.exact_next_depth = final + 1
        state.last_depth_sequence = final
        state.depth_frames += 1
        state.observations += 1
    elif event == "GAP":
        declared_last = payload.get("canonical_last_sequence")
        if type(declared_last) is not int:
            raise ArbitrationVerificationError("journal gap lacks its canonical boundary")
        if state.preset_context:
            # The boundary references the previous segment's cursor, which
            # the tail audit does not carry: the record's own declaration is
            # the context (the full set audit enforces the cross-segment
            # equality at the terminal).
            state.last_depth_sequence = declared_last
        elif declared_last != (state.last_depth_sequence or 0):
            raise ArbitrationVerificationError(
                f"journal gap boundary {declared_last} does not equal the canonical "
                f"cursor {state.last_depth_sequence or 0}"
            )
        state.exact_next_depth = None
        state.gaps += 1
    elif event == "DEPTH_REBOOTSTRAP":
        if state.gaps == 0 or state.exact_next_depth is not None:
            raise ArbitrationVerificationError("DEPTH_REBOOTSTRAP must follow a typed gap")
        for field in ("generation", "snapshot_record_sha256", "snapshot_last_update_id"):
            if field not in payload:
                raise ArbitrationVerificationError(f"DEPTH_REBOOTSTRAP lacks {field}")
        state.rebootstrap += 1
        state.status_records += 1
    elif event == "DEPTH_SWITCH_PROVEN":
        state.status_records += 1
    else:
        raise ArbitrationVerificationError(f"journal carries an unknown event: {event}")
    state.last_record_sha = str(envelope["record_sha256"])
    state.records += 1


def _audit_file(path: Path, state: _AuditState, incremental: bool, preserve_context: bool = False) -> tuple[bool, int]:
    """Walks one journal segment file against the shared audit state.

    Returns (clean_eof, tail_bytes).  `preserve_context`: a tail audit
    supplies the previous-segment chain context up front (bounded per-epoch
    verification); the walk must not overwrite it."""
    if state.segments > 0 and not preserve_context:
        state.last_segment_sha = state.last_record_sha
    # A terminal closes its own segment file; a resumed continuation
    # segment opens a fresh one.
    state.terminal_seen = False
    previous = ZERO_DIGEST
    file_index = 0
    tail_bytes = 0
    clean_eof = True
    with path.open("rb") as handle:
        while True:
            line = handle.readline()
            if not line:
                break
            if len(line) > MAX_RECORD_BYTES:
                raise ArbitrationVerificationError("journal record exceeds its bound")
            if not line.endswith(b"\n"):
                if incremental:
                    tail_bytes = len(line)
                    clean_eof = False
                    break
                raise ArbitrationVerificationError("journal contains a partial record")
            line = line[:-1]
            if not line:
                continue
            try:
                envelope = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as error:
                raise ArbitrationVerificationError(
                    f"journal record is not valid JSON: {error}"
                ) from error
            if not isinstance(envelope, dict):
                raise ArbitrationVerificationError("journal envelope is not an object")
            _apply_record(state, envelope, file_index, file_index == 0, previous)
            previous = str(envelope["record_sha256"])
            file_index += 1
    if file_index == 0:
        raise ArbitrationVerificationError("journal is empty")
    state.segments += 1
    state.last_segment_tail = tail_bytes
    return clean_eof, tail_bytes


def _finish(state: _AuditState, incremental: bool) -> dict[str, object]:
    if not state.started_seen:
        raise ArbitrationVerificationError("journal lacks ARBITRATION_STARTED")
    if not incremental and not state.terminal_seen:
        raise ArbitrationVerificationError("journal lacks a terminal record")
    return {
        "records": state.records,
        "observations": state.observations,
        "trades": state.trades,
        "depth_frames": state.depth_frames,
        "gaps": state.gaps,
        "late_corrections": state.late_corrections,
        "rebootstrap": state.rebootstrap,
        "status_records": state.status_records,
        "published_trades": len(state.published),
        "trade_floor": state.trade_floor,
        "symbol": state.symbol,
        "segments": state.segments,
        "last_trade_id": state.last_trade_id,
        "last_depth_sequence": state.last_depth_sequence,
        "last_record_sha256": state.last_record_sha,
        "terminal_seen": state.terminal_seen,
        "tail_bytes": 0,
    }


def audit_journal(path: Path, incremental: bool = False) -> dict[str, object]:
    """Strict audit of one journal segment (ADR-16/ADR-17 rules)."""
    state = _AuditState()
    clean_eof, tail_bytes = _audit_file(path, state, incremental)
    if not clean_eof and not incremental:
        raise ArbitrationVerificationError(
            f"journal ends with a partial tail ({tail_bytes} bytes)"
        )
    report = _finish(state, incremental)
    report["tail_bytes"] = tail_bytes
    return report


def audit_journal_set(paths: list[Path], incremental: bool = False) -> dict[str, object]:
    """Carry actual prior identities; a successor must declare torn predecessor bytes."""
    if not paths:
        raise ArbitrationVerificationError("arbitration journal set is empty")
    state = _AuditState()
    tail_bytes = 0
    for index, path in enumerate(paths):
        tolerate_tail = incremental or index < len(paths) - 1
        clean_eof, tail_bytes = _audit_file(path, state, tolerate_tail)
        if not clean_eof and not tolerate_tail:
            raise ArbitrationVerificationError(
                f"journal segment {path} ends with a partial tail ({tail_bytes} bytes)"
            )
    report = _finish(state, incremental)
    report["tail_bytes"] = tail_bytes
    return report


def _first_payload(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        line = handle.readline()
    if not line:
        raise ArbitrationVerificationError("journal segment is empty")
    if not line.endswith(b"\n"):
        line = line[:-1] if line else line
    envelope = json.loads(line.decode("utf-8"))
    payload = envelope["body"]["payload"]
    if not isinstance(payload, dict):
        raise ArbitrationVerificationError("journal record lacks its payload")
    return payload


def _audit_tail(path: Path, previous_segment_sha256: str, trade_floor: int) -> dict[str, object]:
    """Closed audit of ONE resume-chained tail segment with a supplied chain
    context (ADR-17 bounded per-epoch verification)."""
    state = _AuditState()
    state.segments = 1
    state.started_seen = True
    state.preset_context = True
    state.last_segment_sha = previous_segment_sha256
    state.last_trade_id = trade_floor
    state.trade_floor = trade_floor
    clean_eof, tail_bytes = _audit_file(path, state, False, preserve_context=True)
    if not clean_eof:
        raise ArbitrationVerificationError(
            f"tail segment ends with a partial tail ({tail_bytes} bytes)"
        )
    return _finish(state, False)


def _audit_tail_incremental(
    path: Path, previous_segment_sha256: str, trade_floor: int
) -> tuple[dict[str, object], bool, int]:
    """Live-prefix audit of ONE active resume-chained tail segment with a
    supplied chain context (terminal not required; torn tail reported)."""
    state = _AuditState()
    state.segments = 1
    state.started_seen = True
    state.preset_context = True
    state.last_segment_sha = previous_segment_sha256
    state.last_trade_id = trade_floor
    state.trade_floor = trade_floor
    clean_eof, tail_bytes = _audit_file(path, state, True, preserve_context=True)
    return _finish(state, True), clean_eof, tail_bytes


def _stream_records(generation: Path, stream: str, tolerate_missing_ack: bool = False) -> list:
    """Ordered durable records of one stream inside a generation: sealed
    segments via the manifest plus the in-flight segment's BNACK-authorized
    durable prefix.  A stream killed before its first rotation has no seals;
    its root segment's durable boundary comes from its own BNACK journal on
    the ZERO chain (frame 0).  `tolerate_missing_ack`: live-prefix audits
    accept an in-flight BNACK without a complete ACK (contributing no
    in-flight records); closed audits treat it as an error."""
    stream_dir = generation / stream
    records = []
    previous_seal = None
    for seal in scan_segment_manifest_seals(stream_dir / "segments.bnseg"):
        if previous_seal is None:
            previous_digest = ZERO_DIGEST
            next_frame = 0
        else:
            previous_digest = str(previous_seal["terminal_record_sha256"])
            next_frame = int(previous_seal["last_frame_index"]) + 1
        records.extend(
            iter_raw_segment_records(
                stream_dir / str(seal["raw_file"]),
                previous_digest,
                next_frame,
                str(seal["connection_epoch"]),
                str(seal["stream"]),
            )
        )
        previous_seal = seal
    if previous_seal is not None:
        next_index = int(previous_seal["segment_index"]) + 1
        in_flight = stream_dir / f"segment-{next_index:06d}.bnraw"
        progress = stream_dir / f"segment-{next_index:06d}.bnack"
        if in_flight.exists() and progress.exists():
            scan = scan_durability_progress(progress)
            ack = scan.get("latest_ack")
            if ack is None:
                # An in-flight segment whose BNACK carries NO complete ACK
                # contributes NO durable records (a writer interrupted
                # before its first ACK, or a just-created empty segment):
                # the sealed segments remain the complete durable evidence.
                pass
            else:
                end = int(ack["durable_through_offset"])
                records.extend(
                    iter_raw_segment_prefix(
                        in_flight,
                        str(previous_seal["terminal_record_sha256"]),
                        int(previous_seal["last_frame_index"]) + 1,
                        str(previous_seal["connection_epoch"]),
                        str(previous_seal["stream"]),
                        end,
                    )
                )
    else:
        in_flight = stream_dir / "segment-000000.bnraw"
        progress = stream_dir / "segment-000000.bnack"
        if in_flight.exists() and progress.exists():
            scan = scan_durability_progress(progress)
            ack = scan.get("latest_ack")
            if ack is None:
                pass
            else:
                end = int(ack["durable_through_offset"])
                first = first_raw_segment_record(in_flight)
                records.extend(
                    iter_raw_segment_prefix(
                        in_flight,
                        ZERO_DIGEST,
                        0,
                        first.frame.connection_epoch,
                        first.frame.stream,
                        end,
                    )
                )
    return records


def _trade_id(payload: bytes) -> int:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ArbitrationVerificationError(f"trade payload is not JSON: {error}") from error
    trade_id = value.get("t")
    if type(trade_id) is not int:
        raise ArbitrationVerificationError("trade payload lacks an exact trade ID")
    return trade_id


def oracle_depth_observations(
    generation: Path, tolerate_missing_ack: bool = False
) -> list[tuple[int, int, str]]:
    """Materializes the untouched lane's depth book frame-by-frame and
    returns (first_update_id, final_update_id, book_digest) per frame."""
    snapshots = list(iter_raw_records(generation / "snapshot.bnraw"))
    if len(snapshots) != 1:
        raise ArbitrationVerificationError("depth oracle requires one snapshot")
    snapshot = snapshots[0]
    book = LocalOrderBook(snapshot.frame.symbol)
    book.load_snapshot(snapshot.frame.payload)
    observations: list[tuple[int, int, str]] = []
    for record in _stream_records(generation, "depth", tolerate_missing_ack):
        try:
            payload = json.loads(record.frame.payload)
        except json.JSONDecodeError as error:
            raise ArbitrationVerificationError(f"depth payload is not JSON: {error}") from error
        first = payload.get("U")
        final = payload.get("u")
        if type(first) is not int or type(final) is not int:
            raise ArbitrationVerificationError("depth payload lacks exact U/u")
        outcome = book.apply_depth(record.frame.payload)
        if outcome is ApplyOutcome.OLD:
            if observations:
                raise ArbitrationVerificationError(
                    "stale depth record appeared after canonical LIVE observations"
                )
            continue
        observations.append((first, final, book.state_digest()))
    return observations


def _sorted_directories(root: Path) -> list[Path]:
    entries = [entry for entry in root.iterdir() if entry.is_dir()]
    entries.sort()
    return entries


def _generation_terminal_complete(generation: Path) -> bool:
    """True only with the generation's durable terminal declaration (status
    COMPLETE, no failure).  Absence or a partial mid-write body is never proof
    that the stream ended (ADR-17 boundary authority, review 2026-09-11 risk
    1; defect hrs-a8d39b6c0204: the verifier previously inferred the
    definitive end from the missing next segment file and misread a live
    rotation window as fully sealed)."""
    path = generation / "generation.json"
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # The capture writes the terminal declaration once with write+sync:
        # a reader racing the write may see a partial body.  No proof of
        # COMPLETE means the stream must stay unsealed (conservative).
        return False
    return data.get("status") == "COMPLETE" and data.get("failure") is None


def _stream_fully_sealed(generation: Path, stream: str) -> bool:
    """A generation whose stream still carries an in-flight (unsealed)
    segment was interrupted before terminal evidence: its book state is
    untrusted for identity comparison even though its records remain valid
    evidence."""
    if not _generation_terminal_complete(generation):
        return False
    stream_dir = generation / stream
    seals = list(scan_segment_manifest_seals(stream_dir / "segments.bnseg"))
    next_index = int(seals[-1]["segment_index"]) + 1 if seals else 0
    return not (stream_dir / f"segment-{next_index:06d}.bnraw").exists()


def _artifact_roots(artifact: Path) -> list[Path]:
    """Resolves the oracle root into supervisor artifact directories: a single
    artifact (`p/` and `s/` directly below), every epoch artifact below a
    service symbol root, or the one artifact inside each epoch directory
    (`<symbol>/e1/<artifact>`)."""
    if (artifact / "p").is_dir() and (artifact / "s").is_dir():
        return [artifact]
    if not artifact.is_dir():
        return []
    roots: list[Path] = []
    for entry in sorted(entry for entry in artifact.iterdir() if entry.is_dir()):
        if (entry / "p").is_dir() and (entry / "s").is_dir():
            roots.append(entry)
            continue
        for nested in sorted(child for child in entry.iterdir() if child.is_dir()):
            if (nested / "p").is_dir() and (nested / "s").is_dir():
                roots.append(nested)
    return roots


def _scoped_artifact_roots(artifact: Path, declared: list[str]) -> list[Path]:
    """Restricts the oracle roots to the artifacts declared by the journal's
    segment chain (each segment declares the artifact it was bound to)."""
    roots = _artifact_roots(artifact)
    if not declared:
        return roots
    return [root for root in roots if root.name in declared]


def _file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _check_inventory_journals(cut: dict) -> None:
    for path, expected in cut["journal_hashes"]:
        if _file_sha256(path) != expected:
            raise ArbitrationVerificationError("inventory journal hash mismatch")


def _select_journal_prefix(path: Path, journals: list[Path]) -> list[Path]:
    """Only an externally frozen contiguous prefix may supply prior context."""
    if path.stat().st_size > 16 * MAX_RECORD_BYTES:
        raise ArbitrationVerificationError("artifact inventory exceeds its bound")
    try:
        value = json.loads(path.read_bytes().decode("utf-8-sig"))
    except (UnicodeError, ValueError) as error:
        raise ArbitrationVerificationError("invalid artifact inventory JSON") from error
    entries = value.get("journals") if isinstance(value, dict) else None
    if not isinstance(entries, list) or not entries or len(entries) > len(journals):
        raise ArbitrationVerificationError("journal cut is not a contiguous prefix")
    for entry, actual in zip(entries, journals):
        name = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name:
            raise ArbitrationVerificationError("invalid prefix journal path")
        candidate = Path(name)
        resolved = (candidate if candidate.is_absolute() else path.parent / candidate).resolve(strict=True)
        if resolved != actual.resolve(strict=True):
            raise ArbitrationVerificationError("journal cut is not a contiguous prefix")
    return journals[:len(entries)]


def _load_expected_inventory(
    path: Path, artifact: Path, journals: list[Path], declared: list[str]
) -> dict:
    """An independently produced, immutable journal cut, not output-selected raw.

    A historical cut may intentionally exclude future artifacts. The producer
    must derive eligibility from the supervisor ledger, never the journal.
    Paths are absolute or relative to the inventory's own directory.
    """
    if path.stat().st_size > 16 * MAX_RECORD_BYTES:
        raise ArbitrationVerificationError("artifact inventory exceeds its bound")
    encoded = path.read_bytes()
    try:
        value = json.loads(encoded.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as error:
        raise ArbitrationVerificationError("invalid artifact inventory JSON") from error
    if not isinstance(value, dict) or value.get("schema") != "LiveArbitrationExpectedArtifactsV1":
        raise ArbitrationVerificationError("unsupported artifact inventory schema")

    def resolve(item: object) -> Path:
        if not isinstance(item, str) or not item:
            raise ArbitrationVerificationError("inventory path must be a nonempty string")
        candidate = Path(item)
        return (candidate if candidate.is_absolute() else path.parent / candidate).resolve(strict=True)

    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ArbitrationVerificationError("artifact inventory requires nonempty artifacts")
    expected = [resolve(item) for item in artifacts]
    expected_names = [item.name for item in expected]
    if len(set(expected)) != len(expected) or len(set(expected_names)) != len(expected):
        raise ArbitrationVerificationError("artifact inventory contains duplicate identities")
    discovered = _artifact_roots(artifact)
    selected = [item.resolve(strict=True) for item in discovered if item.name in expected_names]
    if len(selected) != len(expected) or set(selected) != set(expected):
        raise ArbitrationVerificationError("artifact inventory paths are missing or ambiguous in oracle root")
    journal_entries = value.get("journals")
    if not isinstance(journal_entries, list) or not journal_entries:
        raise ArbitrationVerificationError("artifact inventory requires journal cuts")
    hashes = []
    for entry in journal_entries:
        if not isinstance(entry, dict) or not _is_hex64(entry.get("sha256")):
            raise ArbitrationVerificationError("invalid inventory journal digest")
        hashes.append((resolve(entry.get("path")), entry["sha256"].lower()))
    cut_paths = [item[0] for item in hashes]
    if len(set(cut_paths)) != len(cut_paths) or set(cut_paths) != {item.resolve(strict=True) for item in journals}:
        raise ArbitrationVerificationError("inventory journal set differs from audited journals")
    cut = {"artifacts": expected_names, "journal_hashes": hashes,
           "sha256": hashlib.sha256(encoded).hexdigest()}
    _check_inventory_journals(cut)
    if set(declared) != set(expected_names):
        raise ArbitrationVerificationError("artifact inventory differs from journal declarations")
    return cut


def _unsealed_depth_lanes(artifact: Path, declared: list[str]) -> set[str]:
    """Lanes whose depth evidence still includes an unsealed generation: a
    live-prefix audit cannot verify frames freshly published from that
    evidence yet (the closed segment verification runs after the seal)."""
    lanes: set[str] = set()
    for root in _scoped_artifact_roots(artifact, declared):
        for lane in ("p", "s"):
            lane_root = root / lane
            if not lane_root.is_dir():
                continue
            for campaign in _sorted_directories(lane_root):
                for generation in _sorted_directories(campaign / "generations"):
                    if not _stream_fully_sealed(generation, "depth"):
                        lanes.add(lane)
                        break
                if lane in lanes:
                    break
    return lanes


def _sealed_stream_key(generation: Path, stream: str) -> str | None:
    """Content key of a sealed stream. Unsealed generations are never cached."""
    if not _stream_fully_sealed(generation, stream):
        return None
    digest = hashlib.sha256()
    digest.update(b"sealed-oracle-v1\0")
    digest.update(stream.encode("utf-8"))
    stream_dir = generation / stream
    for path in sorted(entry for entry in stream_dir.iterdir() if entry.is_file()):
        name = path.name.encode("utf-8")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    if stream == "depth":
        snapshot = generation / "snapshot.bnraw"
        if snapshot.is_file():
            digest.update(b"snapshot.bnraw")
            with snapshot.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def _read_oracle_cache(cache_dir: Path, kind: str, key: str) -> object | None:
    """Returns the cached rows only when the file names its own content key."""
    path = cache_dir / kind / f"{key}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("key") != key:
        return None
    return value.get("rows")


def _write_oracle_cache(cache_dir: Path, kind: str, key: str, value: object) -> None:
    directory = cache_dir / kind
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{key}.json"
    temporary = directory / f"{key}.json.tmp"
    temporary.write_text(json.dumps({"key": key, "rows": value}), encoding="utf-8")
    temporary.replace(target)


def _trade_cache_rows(value: object) -> list[dict[str, object]] | None:
    if not isinstance(value, list):
        return None
    rows: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict):
            return None
        trade_id = item.get("trade_id")
        record_sha = item.get("record_sha256")
        observation_sha = item.get("observation_sha256")
        if type(trade_id) is not int or not isinstance(record_sha, str) or not isinstance(observation_sha, str):
            return None
        rows.append(item)
    return rows


def _depth_cache_rows(value: object) -> list[tuple[int, int, str]] | None:
    if not isinstance(value, list):
        return None
    rows: list[tuple[int, int, str]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 3
            or type(item[0]) is not int
            or type(item[1]) is not int
            or not isinstance(item[2], str)
        ):
            return None
        rows.append((item[0], item[1], item[2]))
    return rows


def oracle_trades_union(
    artifact: Path,
    tolerate_missing_ack: bool = False,
    declared_artifacts: list[str] | None = None,
    cache_dir: Path | None = None,
) -> dict[int, list[dict[str, str]]]:
    """The capture system's complete trade evidence (ADR-17 B5): every
    durable trade of every campaign and generation of BOTH lanes keyed by
    trade ID with the exact raw record and observation digests."""
    declared = declared_artifacts or []
    by_id: dict[int, list[dict[str, str]]] = {}
    for root in _scoped_artifact_roots(artifact, declared):
        for lane in ("p", "s"):
            lane_root = root / lane
            if not lane_root.is_dir():
                continue
            for campaign in _sorted_directories(lane_root):
                for generation in _sorted_directories(campaign / "generations"):
                    key = _sealed_stream_key(generation, "trade") if cache_dir is not None else None
                    cached = _trade_cache_rows(_read_oracle_cache(cache_dir, "trade", key)) if key is not None and cache_dir is not None else None
                    if cached is None:
                        cached = []
                        for record in _stream_records(generation, "trade", tolerate_missing_ack):
                            trade_id, record_sha, observation_sha = _materialize_one_trade(record)
                            cached.append(
                                {
                                    "trade_id": trade_id,
                                    "record_sha256": record_sha,
                                    "observation_sha256": observation_sha,
                                }
                            )
                        if key is not None and cache_dir is not None:
                            _write_oracle_cache(cache_dir, "trade", key, cached)
                    for row in cached:
                        by_id.setdefault(int(row["trade_id"]), []).append(
                            {
                                "record_sha256": str(row["record_sha256"]),
                                "observation_sha256": str(row["observation_sha256"]),
                            }
                        )
    return by_id


def _materialize_one_trade(record) -> tuple[int, str, str]:
    """Materializes one trade raw record into (id, record_sha256,
    observation_sha256) using the project's own trade materialization
    contract (the same canonical digest the arbiter publishes)."""
    from .observations import _trade_observation_digest

    trade_id, digest = _trade_observation_digest(record.frame.payload, record.frame.symbol)
    return trade_id, str(record.record_sha256), digest


def _trusted_depth_observations(
    generation: Path, tolerate_missing_ack: bool = False
) -> list[tuple[int, int, str]]:
    """One complete generation's depth observations restricted to the
    contiguous prefix from its snapshot: the first update-ID jump marks the
    point where a dropped venue event makes every later book digest
    untrustworthy (gap-free is not the same as correct)."""
    snapshots = list(iter_raw_records(generation / "snapshot.bnraw"))
    if len(snapshots) != 1:
        raise ArbitrationVerificationError("depth oracle requires one snapshot")
    snapshot_payload = json.loads(snapshots[0].frame.payload)
    snapshot_last = snapshot_payload.get("lastUpdateId")
    if type(snapshot_last) is not int:
        raise ArbitrationVerificationError("depth snapshot lacks lastUpdateId")
    trusted: list[tuple[int, int, str]] = []
    expected = snapshot_last + 1
    for observation in oracle_depth_observations(generation, tolerate_missing_ack):
        first, final, digest = observation
        if final < expected:
            continue
        if first > expected:
            break
        trusted.append(observation)
        expected = final + 1
    return trusted


def _trusted_depth_worker(generation_str: str) -> list[tuple[int, int, str]] | None:
    """Pool worker (spawn-safe): one generation's trusted contiguous depth
    observations.  Each generation owns its snapshot, so digests are
    generation-local and the parallel order never affects the bytes."""
    return _trusted_depth_observations(Path(generation_str), False)


def oracle_depth_by_lane(
    artifact: Path,
    tolerate_missing_ack: bool = False,
    declared_artifacts: list[str] | None = None,
    unsealed_lanes: set[str] | None = None,
    cache_dir: Path | None = None,
) -> dict[str, dict[int, list[tuple[int, str]]]]:
    """The depth oracle (ADR-17 B5): trusted contiguous observations of BOTH
    lanes keyed by lane and final update ID, so a window served exclusively
    by SHADOW verifies against SHADOW exactly like PRIMARY against PRIMARY.
    Two generations of the same lane may cover the same update ID with
    different book digests (snapshots taken at different times); every raw
    variant is retained and the canonical frame must match ONE variant.
    Live-prefix audits tolerate lanes without a trusted sealed prefix yet."""
    declared = declared_artifacts or []
    unsealed = unsealed_lanes or set()
    roots = _scoped_artifact_roots(artifact, declared)
    if not roots:
        raise ArbitrationVerificationError("oracle artifact lacks lane roots")
    # Classification snapshot (ADR-17 B5, defect hrs-14572a22e336): every
    # sealing/unsealed decision is taken HERE, once, in the parent, in
    # deterministic sorted order — never re-read in a worker.
    tasks: list[tuple[str, Path]] = []
    for root in roots:
        for lane in ("p", "s"):
            lane_root = root / lane
            if not lane_root.is_dir():
                continue
            for campaign in _sorted_directories(lane_root):
                for generation in _sorted_directories(campaign / "generations"):
                    if lane in unsealed:
                        if tolerate_missing_ack:
                            continue
                    elif not _stream_fully_sealed(generation, "depth"):
                        if tolerate_missing_ack:
                            continue
                    tasks.append((lane, generation))
    # Each generation owns its snapshot, so digests do not depend on order.
    # A prefix audit only enqueues generations this parent already classified
    # as sealed; the in-flight files tolerant mode may still be writing are
    # not in `tasks`. Those sealed generations use the same spawn pool as a
    # closed audit. One generation stays in-process.
    pool_size = min(os.cpu_count() or 2, 12)
    cached_hits: list[tuple[str, list[tuple[int, int, str]]]] = []
    misses: list[tuple[str, Path, str | None]] = []
    for lane, generation in tasks:
        key = _sealed_stream_key(generation, "depth") if cache_dir is not None else None
        cached = _depth_cache_rows(_read_oracle_cache(cache_dir, "depth", key)) if key is not None and cache_dir is not None else None
        if cached is not None:
            cached_hits.append((lane, cached))
        else:
            misses.append((lane, generation, key))
    use_pool = len(misses) > 1 and pool_size > 1
    if use_pool:
        with multiprocessing.get_context("spawn").Pool(pool_size) as pool:
            computed = pool.map(_trusted_depth_worker, [str(g) for _, g, _ in misses])
    else:
        computed = [
            _trusted_depth_observations(g, tolerate_missing_ack) for _, g, _ in misses
        ]
    for (_lane, _generation, key), observations in zip(misses, computed):
        if key is not None and cache_dir is not None and observations is not None:
            _write_oracle_cache(
                cache_dir,
                "depth",
                key,
                [[first, final, digest] for first, final, digest in observations],
            )
    by_lane: dict[str, dict[int, list[tuple[int, str]]]] = {}
    for lane, observations in cached_hits:
        lane_map = by_lane.setdefault(lane, {})
        for first, final, digest in observations:
            lane_map.setdefault(final, []).append((first, digest))
    for (lane, _generation, _key), observations in zip(misses, computed):
        lane_map = by_lane.setdefault(lane, {})
        for first, final, digest in observations:
            lane_map.setdefault(final, []).append((first, digest))
    if not tolerate_missing_ack and ("p" not in by_lane or "s" not in by_lane):
        raise ArbitrationVerificationError("oracle artifact lacks both lane roots")
    return by_lane


class _Canonical:
    def __init__(self) -> None:
        self.trades: list[dict[str, object]] = []
        self.depth: list[dict[str, object]] = []
        self.corrections: list[dict[str, object]] = []
        self.depth_rebootstraps: list[tuple[int, int, str]] = []
        self.terminal_serving_lane: str | None = None
        self.terminal_completion_scope: str | None = None
        self.trade_floor: int | None = None
        self.has_startup_context = False
        # Artifact identities declared by the segment chain: the raw oracle
        # is restricted to exactly these artifacts (a service stopped before
        # a pending epoch transition verifies the window it covered).
        self.declared_artifacts: list[str] = []
        # Kind of the last depth-related event ("frame", "gap" or None):
        # the closed audit rejects a window that ends mid-gap or before the
        # sealed evidence's trusted continuation (ADR-17 B5 final boundary).
        self.last_depth_event: str | None = None


def _canonical_observations(journals: list[Path], tolerate_partial_tail: bool = False) -> _Canonical:
    canonical = _Canonical()
    for journal_index, journal in enumerate(journals):
        with journal.open("rb") as handle:
            while True:
                line = handle.readline(MAX_RECORD_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_RECORD_BYTES:
                    raise ArbitrationVerificationError("journal record exceeds its bound")
                if not line.endswith(b"\n"):
                    if tolerate_partial_tail or journal_index < len(journals) - 1:
                        break
                    raise ArbitrationVerificationError("journal contains a partial record")
                if not line.strip():
                    continue
                envelope = json.loads(line.decode("utf-8"))
                payload = envelope["body"]["payload"]
                event = payload.get("event")
                if event in ("ARBITRATION_STARTED", "ARBITRATION_RESUMED"):
                    canonical.terminal_completion_scope = None
                    if event == "ARBITRATION_STARTED":
                        canonical.has_startup_context = True
                    # The canonical window starts at the FIRST segment's
                    # floor; later segments declare their own resumed floors.
                    if canonical.trade_floor is None:
                        canonical.trade_floor = payload.get("trade_floor")
                    artifact = payload.get("artifact_root")
                    if isinstance(artifact, str):
                        canonical.declared_artifacts.append(artifact)
                    # ADR-17 B3 LIVE rebind: a segment that continues from a
                    # PRIOR epoch artifact declares every prior artifact it
                    # walks — the raw oracle must include them (their sealed
                    # tails are part of the covered window).
                    prior = payload.get("prior_artifacts")
                    if isinstance(prior, list):
                        for item in prior:
                            if isinstance(item, str):
                                canonical.declared_artifacts.append(item)
                elif event == "TRADE_OBSERVATION":
                    canonical.trades.append(
                        {
                            "trade_id": payload["trade_id"],
                            "lane": payload.get("lane"),
                            "record_sha256": payload["record_sha256"],
                            "observation_sha256": payload["observation_sha256"],
                        }
                    )
                elif event == "TRADE_LATE_CORRECTION":
                    canonical.corrections.append(
                        {
                            "trade_id": payload["trade_id"],
                            "kind": payload["kind"],
                            "record_sha256": payload["record_sha256"],
                            "observation_sha256": payload["observation_sha256"],
                        }
                    )
                elif event == "DEPTH_OBSERVATION":
                    canonical.depth.append(
                        {
                            "first_sequence": payload["first_sequence"],
                            "final_sequence": payload["final_sequence"],
                            "digest": payload["observation_sha256"],
                            "lane": payload.get("lane"),
                        }
                    )
                    canonical.last_depth_event = "frame"
                elif event == "DEPTH_REBOOTSTRAP":
                    canonical.depth_rebootstraps.append(
                        (
                            payload["snapshot_last_update_id"],
                            len(canonical.depth),
                            str(payload["lane"]),
                        )
                    )
                elif event == "GAP":
                    # The gap itself is audited by the scanner (declared
                    # cursor); the closed audit rejects a window that ends
                    # mid-gap (final boundary).
                    canonical.last_depth_event = "gap"
                elif event == "ARBITRATION_TERMINAL":
                    canonical.terminal_serving_lane = payload.get("serving_lane_at_terminal")
                    scope = payload.get("completion_scope")
                    if scope is not None and scope not in ("HANDOFF", "SEALED_DRAIN"):
                        raise ArbitrationVerificationError("unknown terminal completion_scope")
                    canonical.terminal_completion_scope = scope
    return canonical


def verify_trade_identity(canonical_ids: list[int], oracle_ids: list[int]) -> None:
    """Exact event-identity comparison (ADR-17 B5): the canonical trade
    stream must equal the oracle stream EXACTLY — the expected interval is
    derived from external evidence (the raw union above the trade floor),
    never trimmed to the canonical first/last extremes, so initial and
    final omissions are visible."""
    if not canonical_ids or not oracle_ids:
        raise ArbitrationVerificationError("trade identity oracle requires both sequences")
    if canonical_ids != oracle_ids:
        raise ArbitrationVerificationError(
            "canonical trade stream differs from the oracle "
            f"(canonical {len(canonical_ids)}, oracle {len(oracle_ids)})"
        )


def _verify_trades(
    canonical: _Canonical,
    raw_union: dict[int, list[dict[str, str]]],
    bound_to_last: bool,
) -> int:
    """Reconstruct OBSERVATION + first UNKNOWN; raw equality remains exact.

    Corrections never rewrite the ordered publication stream. A standalone
    resumed tail proves only its local interval; prior identities need context.
    """
    floor = canonical.trade_floor or 0
    upper_bound = (int(canonical.trades[-1]["trade_id"]) if canonical.trades else floor) if bound_to_last else None
    reconstructed: dict[int, str] = {}

    def identity(item: dict[str, object], label: str) -> tuple[int, str]:
        trade_id = int(item["trade_id"])
        evidence = raw_union.get(trade_id)
        if not evidence:
            raise ArbitrationVerificationError(f"{label} {trade_id} has no raw evidence")
        digests = {entry["observation_sha256"] for entry in evidence}
        if len(digests) != 1:
            raise ArbitrationVerificationError(f"raw trade {trade_id} has conflicting identities")
        digest = str(item["observation_sha256"])
        if digest not in digests:
            raise ArbitrationVerificationError(f"{label} {trade_id} carries an observation digest absent from the raw capture")
        if not any(entry["record_sha256"] == item["record_sha256"]
                   and entry["observation_sha256"] == digest for entry in evidence):
            raise ArbitrationVerificationError(f"{label} {trade_id} carries a raw lineage record absent from the raw capture")
        return trade_id, digest

    for trade in canonical.trades:
        trade_id, digest = identity(trade, "canonical trade")
        if trade_id in reconstructed:
            raise ArbitrationVerificationError("canonical journal publishes a duplicate trade ID")
        reconstructed[trade_id] = digest
    for correction in canonical.corrections:
        trade_id, digest = identity(correction, "trade correction")
        kind = correction["kind"]
        if kind == "duplicate":
            if reconstructed.get(trade_id) != digest:
                raise ArbitrationVerificationError(f"trade correction {trade_id} kind=duplicate contradicts the published identity")
        elif kind == "unknown":
            if canonical.has_startup_context and trade_id <= floor:
                raise ArbitrationVerificationError("unknown correction is at or below the startup trade floor")
            if trade_id in reconstructed:
                raise ArbitrationVerificationError(f"trade correction {trade_id} kind=unknown contradicts the published identity")
            reconstructed[trade_id] = digest
        else:
            raise ArbitrationVerificationError(f"trade correction {trade_id} carries an unknown classification")
    expected = sorted(trade_id for trade_id in raw_union
                      if trade_id > floor and (upper_bound is None or trade_id <= upper_bound))
    actual = sorted(trade_id for trade_id in reconstructed if trade_id > floor)
    if actual != expected:
        missing = [trade_id for trade_id in expected if trade_id not in reconstructed][:8]
        invented = [trade_id for trade_id in actual if trade_id not in raw_union][:8]
        raise ArbitrationVerificationError(
            "canonical trade stream differs from the raw union: "
            f"reconstructed {len(actual)}, union window {len(expected)}, "
            f"missing examples {missing}, invented examples {invented}"
        )
    return len(reconstructed)


def _verify_depth(
    canonical: _Canonical,
    raw_depth: dict[str, dict[int, list[tuple[int, str]]]],
    tolerant_lanes: bool,
    enforce_final_boundary: bool,
    unsealed_lanes: set[str] | None = None,
) -> None:
    unsealed_lanes = unsealed_lanes or set()
    next_rebootstrap = 0
    for index, frame in enumerate(canonical.depth):
        lane_label = frame.get("lane")
        if not isinstance(lane_label, str):
            raise ArbitrationVerificationError("canonical depth frame lacks its lane")
        # Canonical records carry PRIMARY/SHADOW; the raw oracle is keyed
        # by the lane roots p/s.
        lane = {"PRIMARY": "p", "SHADOW": "s"}.get(lane_label, lane_label)
        lane_oracle = raw_depth.get(lane)
        if tolerant_lanes and (lane_oracle is None or not lane_oracle):
            # Live prefix / bounded tail: the lane has no trusted sealed
            # prefix yet; the closed full-set verification enforces it.
            continue
        if lane_oracle is None:
            raise ArbitrationVerificationError(
                f"canonical depth frame names an unknown lane {lane}"
            )
        if next_rebootstrap < len(canonical.depth_rebootstraps):
            declared_last, first_frame_index, declared_lane = canonical.depth_rebootstraps[next_rebootstrap]
            if first_frame_index == index:
                declared_norm = {"PRIMARY": "p", "SHADOW": "s"}.get(declared_lane, declared_lane)
                if declared_norm != lane:
                    raise ArbitrationVerificationError(
                        "first depth frame after DEPTH_REBOOTSTRAP names a different lane"
                    )
                if frame["first_sequence"] <= declared_last:
                    # The REBOOTSTRAP evidences the snapshot state AT the
                    # declared lastUpdateId: the next published frame must
                    # start strictly after that boundary (never republish
                    # the snapshot's own coverage); the subsumed prefix is
                    # part of the bootstrap evidence itself.
                    raise ArbitrationVerificationError(
                        f"first depth frame after DEPTH_REBOOTSTRAP starts at "
                        f"{frame['first_sequence']} but the declared snapshot boundary "
                        f"requires a frame strictly after {declared_last}"
                    )
                next_rebootstrap += 1
        variants = lane_oracle.get(frame["final_sequence"])
        if variants is None or not any(
            first == frame["first_sequence"] and digest == frame["digest"]
            for first, digest in variants
        ):
            if tolerant_lanes and lane in unsealed_lanes:
                # Published from evidence that is still in-flight; the
                # closed segment verification runs after the seal.
                continue
            raise ArbitrationVerificationError(
                f"canonical depth frame {frame['first_sequence']}-{frame['final_sequence']} "
                f"differs from or is absent from the {lane} raw oracle"
            )
    if enforce_final_boundary and next_rebootstrap < len(canonical.depth_rebootstraps):
        declared_last, first_frame_index, _ = canonical.depth_rebootstraps[next_rebootstrap]
        if first_frame_index >= len(canonical.depth):
            raise ArbitrationVerificationError(
                "a DEPTH_REBOOTSTRAP carries no following depth frame to verify"
            )
    # ADR-17 B5 final boundary (closed audit only): the canonical depth
    # stream must reach the sealed evidence's trusted end.  A window that
    # ends mid-gap, an empty canonical against non-empty sealed evidence,
    # or a final cursor short of a TRUSTED contiguous continuation of the
    # publishing lane is a final omission — the raw proves the frames
    # existed, so the closed view is incomplete.  A genuinely empty window
    # passes only when the sealed evidence itself holds no trusted depth.
    if enforce_final_boundary:
        if canonical.last_depth_event == "gap":
            raise ArbitrationVerificationError(
                "canonical depth stream ends with an unresolved gap: the post-gap "
                "continuation never published"
            )
        if canonical.last_depth_event == "frame":
            last = canonical.depth[-1]
            lane_label = last.get("lane")
            if not isinstance(lane_label, str):
                raise ArbitrationVerificationError("canonical depth frame lacks its lane")
            lane = {"PRIMARY": "p", "SHADOW": "s"}.get(lane_label, lane_label)
            lane_oracle = raw_depth.get(lane)
            if lane_oracle is None:
                raise ArbitrationVerificationError(
                    f"canonical depth frame names an unknown lane {lane}"
                )
            next_update = int(last["final_sequence"]) + 1
            if any(
                first <= next_update <= final_sequence
                for final_sequence, variants in lane_oracle.items()
                for first, _digest in variants
            ):
                raise ArbitrationVerificationError(
                    f"canonical depth stream ends at update {last['final_sequence']} but "
                    f"the {lane} sealed evidence continues at update {next_update} "
                    "(final omission)"
                )
        if canonical.last_depth_event is None:
            for lane, oracle in raw_depth.items():
                if oracle:
                    raise ArbitrationVerificationError(
                        f"canonical depth stream is empty while the {lane} sealed "
                        "evidence holds trusted depth observations"
                    )


def _verify_with_oracle(
    journals: list[Path],
    oracle_artifact: Path | None,
    oracle_generation: Path | None,
    tolerant_lanes: bool,
    bound_to_last: bool,
    enforce_final_boundary: bool,
    expected_artifacts: list[str] | None = None,
    cache_dir: Path | None = None,
) -> dict:
    canonical = _canonical_observations(journals, tolerate_partial_tail=bound_to_last)
    trade_identity = "SKIPPED_EMPTY_PREFIX" if bound_to_last and not canonical.trades else "PASS"
    declared = canonical.declared_artifacts if expected_artifacts is None else expected_artifacts
    if oracle_artifact is not None:
        # ADR-17 B5 (defect hrs-14572a22e336): compute the unsealed-lane
        # classification FIRST and share it with the oracle build, so the
        # exclusion and the tolerance always come from the SAME snapshot of
        # the generation terminal state (the earlier two-read interleaving
        # rejected frames the oracle had legitimately excluded).
        unsealed = _unsealed_depth_lanes(oracle_artifact, declared)
        raw_union = oracle_trades_union(
            oracle_artifact, tolerant_lanes, declared, cache_dir
        )
        raw_depth = oracle_depth_by_lane(
            oracle_artifact, tolerant_lanes, declared, unsealed, cache_dir
        )
        reconstructed_trades = _verify_trades(canonical, raw_union, bound_to_last)
        _verify_depth(
            canonical, raw_depth, tolerant_lanes, enforce_final_boundary, unsealed
        )
        return {"trade_identity": trade_identity, "depth_scope_complete": not unsealed,
                "terminal_completion_scope": canonical.terminal_completion_scope,
                "reconstructed_trades": reconstructed_trades}
    if oracle_generation is not None:
        raw_union: dict[int, list[dict[str, str]]] = {}
        for record in _stream_records(oracle_generation, "trade", tolerant_lanes):
            trade_id, record_sha, observation_sha = _materialize_one_trade(record)
            raw_union.setdefault(trade_id, []).append(
                {"record_sha256": record_sha, "observation_sha256": observation_sha}
            )
        reconstructed_trades = _verify_trades(canonical, raw_union, bound_to_last)
        generation_text = str(oracle_generation).replace("\\", "/")
        if "/p/" in generation_text:
            lane = "p"
        elif "/s/" in generation_text:
            lane = "s"
        else:
            raise ArbitrationVerificationError(
                "oracle generation is not below a primary/shadow lane root"
            )
        lane_map: dict[int, list[tuple[int, str]]] = {}
        if _stream_fully_sealed(oracle_generation, "depth"):
            for first, final, digest in _trusted_depth_observations(
                oracle_generation, tolerant_lanes
            ):
                lane_map.setdefault(final, []).append((first, digest))
        _verify_depth(canonical, {lane: lane_map}, tolerant_lanes, enforce_final_boundary)
        return {"trade_identity": trade_identity,
                "depth_scope_complete": _stream_fully_sealed(oracle_generation, "depth"),
                "terminal_completion_scope": canonical.terminal_completion_scope,
                "reconstructed_trades": reconstructed_trades}
    raise ArbitrationVerificationError("an oracle mode must be selected for identity verification")


def _sorted_journal_segments(root: Path) -> list[Path]:
    segments = [entry for entry in root.iterdir() if entry.is_file()]
    segments = [entry for entry in segments if entry.suffix == ".jsonl"]
    segments.sort()
    return segments


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path, nargs="?", default=None,
                        help="canonical live arbitration journal (omitted with --journal-root)")
    parser.add_argument("--journal-root", type=Path, default=None,
                        help="resume-chained journal segment directory (ADR-17 continuous)")
    parser.add_argument("--oracle-generation", type=Path, default=None,
                        help="untouched lane generation directory (trades + depth oracle)")
    parser.add_argument("--oracle-artifact", type=Path, default=None,
                        help="supervisor artifact root or service symbol root (trades = "
                              "union of both lanes, depth = trusted prefixes of both lanes)")
    parser.add_argument("--expected-artifact-inventory", type=Path, default=None,
                        help="independent supervisor inventory bound to exact journal hashes")
    parser.add_argument("--journal-prefix", action="store_true",
                        help="audit the complete chain through a sealed inventory cut; never exhaustive")
    parser.add_argument("--incremental", action="store_true",
                        help="live prefix audit: the terminal record is not required and a "
                             "partial final line is reported instead of rejected; the oracle "
                             "window is bounded by the published position")
    parser.add_argument("--tail-segment-only", action="store_true",
                        help="bounded per-epoch verification: audit ONE sealed resume segment "
                             "against the chain context declared in its own ARBITRATION_RESUMED "
                             "record (requires --oracle-artifact)")
    parser.add_argument("--oracle-cache", type=Path, default=None,
                        help="reuse sealed generation evidence when the raw bytes are unchanged")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    tail_interrupted = False
    try:
        if args.oracle_generation is not None and args.oracle_artifact is not None:
            raise ArbitrationVerificationError("choose exactly one oracle mode")
        if args.expected_artifact_inventory is not None and args.oracle_artifact is None:
            raise ArbitrationVerificationError("expected artifact inventory requires --oracle-artifact")
        if args.journal_prefix and (args.journal_root is None or args.expected_artifact_inventory is None
                                    or args.incremental or args.tail_segment_only):
            raise ArbitrationVerificationError("--journal-prefix requires --journal-root and --expected-artifact-inventory without another prefix mode")
        if args.tail_segment_only and (
            args.incremental or args.journal_root is not None or args.oracle_artifact is None
        ):
            raise ArbitrationVerificationError(
                "--tail-segment-only requires one sealed resume segment and --oracle-artifact"
            )
        if args.journal_root is None and args.journal is None:
            raise ArbitrationVerificationError("missing journal path")
        if args.journal_root is not None and args.journal is not None:
            raise ArbitrationVerificationError(
                "--journal-root replaces the single journal argument"
            )
        if args.journal_root is not None:
            journals = _sorted_journal_segments(args.journal_root)
            if not journals:
                raise ArbitrationVerificationError(
                    f"journal root {args.journal_root} contains no journal segments"
                )
        else:
            journals = [args.journal]
        if args.journal_prefix:
            journals = _select_journal_prefix(args.expected_artifact_inventory, journals)
        if args.incremental and args.journal_root is not None:
            audit = audit_journal_set(journals, incremental=True)
            tail_bytes = audit["tail_bytes"]
            terminal_complete = bool(audit["terminal_seen"]) and tail_bytes == 0
        elif args.incremental:
            first_payload = _first_payload(journals[0])
            if first_payload.get("event") == "ARBITRATION_RESUMED":
                previous_sha = first_payload.get("previous_journal_sha256")
                floor = first_payload.get("trade_floor")
                if not _is_hex64(previous_sha) or type(floor) is not int:
                    raise ArbitrationVerificationError(
                        "resumed segment lacks its chain context"
                    )
                audit, clean_eof, tail_bytes = _audit_tail_incremental(
                    journals[0], str(previous_sha), int(floor)
                )
                terminal_complete = bool(audit["terminal_seen"]) and clean_eof
            else:
                audit = audit_journal(journals[0], incremental=True)
                terminal_complete = bool(audit["terminal_seen"]) and audit.get("tail_bytes", 0) == 0
                tail_bytes = audit["tail_bytes"]
        elif args.tail_segment_only:
            first_payload = _first_payload(journals[0])
            event = first_payload.get("event")
            tail_interrupted = False
            if event == "ARBITRATION_STARTED":
                audit = audit_journal(journals[0], incremental=True)
                tail_bytes = audit["tail_bytes"]
            elif event == "ARBITRATION_RESUMED":
                previous_sha = first_payload.get("previous_journal_sha256")
                floor = first_payload.get("trade_floor")
                if not _is_hex64(previous_sha):
                    raise ArbitrationVerificationError(
                        "tail segment lacks previous_journal_sha256"
                    )
                if type(floor) is not int:
                    raise ArbitrationVerificationError("tail segment lacks trade_floor")
                audit, clean_eof, tail_bytes = _audit_tail_incremental(
                    journals[0], str(previous_sha), int(floor)
                )
            else:
                raise ArbitrationVerificationError(
                    "tail segment does not open with STARTED or RESUMED"
                )
            terminal_complete = bool(audit["terminal_seen"]) and tail_bytes == 0
            tail_interrupted = not terminal_complete
        elif len(journals) == 1:
            audit = audit_journal(journals[0], incremental=False)
            terminal_complete = True
            tail_bytes = 0
        else:
            audit = audit_journal_set(journals)
            terminal_complete = True
            tail_bytes = 0
        inventory_cut = None
        if args.expected_artifact_inventory is not None:
            inventory_cut = _load_expected_inventory(
                args.expected_artifact_inventory, args.oracle_artifact, journals,
                _canonical_observations(journals, args.incremental or args.tail_segment_only).declared_artifacts,
            )
        (tolerant_lanes, bound_to_last, enforce_final_boundary) = (
            (True, True, False)
            if (args.incremental or args.tail_segment_only or args.journal_prefix)
            else (False, False, True)
        )
        oracle_identity = "SKIPPED"
        oracle_result = {"trade_identity": "SKIPPED", "depth_scope_complete": False,
                         "terminal_completion_scope": None, "reconstructed_trades": None}
        if args.oracle_artifact is not None or args.oracle_generation is not None:
            oracle_result = _verify_with_oracle(
                journals,
                args.oracle_artifact,
                args.oracle_generation,
                tolerant_lanes,
                bound_to_last,
                enforce_final_boundary,
                inventory_cut["artifacts"] if inventory_cut is not None else None,
                args.oracle_cache,
            )
            oracle_identity = "PASS" if oracle_result["trade_identity"] == "PASS" else "SKIPPED"
        if inventory_cut is not None:
            _check_inventory_journals(inventory_cut)
        audit_scope = (
            "SEALED_JOURNAL_PREFIX" if args.journal_prefix else
            "LIVE_PREFIX" if args.incremental else
            "INTERRUPTED_SEGMENT_PREFIX" if tail_interrupted else
            "SEALED_SEGMENT_PREFIX" if args.tail_segment_only else "CLOSED_JOURNAL_SET"
        )
        report = {
            "schema": "LiveArbitrationVerificationV2",
            "status": "PASS",
            "journal": str(args.journal) if args.journal is not None else None,
            "journal_root": str(args.journal_root) if args.journal_root is not None else None,
            "audit": audit,
            "incremental": args.incremental,
            "tail_segment_only": args.tail_segment_only,
            "journal_prefix": args.journal_prefix,
            "tail_interrupted": tail_interrupted,
            "terminal_complete": terminal_complete,
            "clean_eof": tail_bytes == 0,
            "audit_scope": audit_scope,
            "artifact_coverage": "PASS" if inventory_cut is not None else "UNPROVEN",
            "expected_artifact_inventory_sha256": inventory_cut["sha256"] if inventory_cut else None,
            "coverage_exhaustive": bool(inventory_cut is not None and terminal_complete
                                         and not bound_to_last and oracle_identity == "PASS"
                                         and oracle_result["depth_scope_complete"]
                                         and oracle_result["terminal_completion_scope"] == "SEALED_DRAIN"),
            "tail_bytes": tail_bytes,
            "oracle_generation": (
                str(args.oracle_generation) if args.oracle_generation is not None else None
            ),
            "oracle_artifact": (
                str(args.oracle_artifact) if args.oracle_artifact is not None else None
            ),
            "oracle_identity": oracle_identity,
            "oracle_trade_identity": oracle_result["trade_identity"],
            "canonical_view": "OBSERVATIONS_PLUS_UNKNOWN_LATE_CORRECTIONS",
            "reconstructed_trades": oracle_result["reconstructed_trades"],
            "oracle_depth_scope_complete": oracle_result["depth_scope_complete"],
            "terminal_completion_scope": oracle_result["terminal_completion_scope"],
            "schema_compatibility": {
                "policy": "reject_unknown_kinds",
                "detail": "Trade late corrections without kind in {duplicate, unknown} are "
                          "REJECTED (fail-closed), never silently reinterpreted; legacy "
                          "journals must be re-verified against raw evidence.",
            },
        }
    except (ArbitrationVerificationError, OSError) as error:
        report = {
            "schema": "LiveArbitrationVerificationV2",
            "status": "REJECTED",
            "journal": str(args.journal) if args.journal is not None else None,
            "reason": str(error),
        }
        text = json.dumps(report, indent=2) + "\n"
        sys.stderr.write(text)
        return 2
    text = json.dumps(report, indent=2) + "\n"
    if args.output is not None:
        args.output.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
