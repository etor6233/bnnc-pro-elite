"""Independent Python verification of a Rust-produced A/B splice artifact."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path

from .boundary import scan_boundary_journal, select_canonical
from .observations import (
    materialize_depth_observations,
    materialize_trade_observations,
)


@dataclass(frozen=True, slots=True)
class VerifiedStreamSpliceV1:
    boundary_sequence: int
    boundary_sha256: str
    selection_sha256: str
    selected_observations: int
    excluded_overlap_records: int
    predecessor_materialization_sha256: str
    successor_materialization_sha256: str


@dataclass(frozen=True, slots=True)
class SpliceVerificationV1:
    schema: str
    status: str
    splice_dir: str
    depth: VerifiedStreamSpliceV1
    trade: VerifiedStreamSpliceV1
    credentials: str
    order_entry: str


def _read_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read valid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value


def verify_splice(splice_dir: Path) -> SpliceVerificationV1:
    splice_dir = Path(splice_dir)
    report = _read_object(splice_dir / "splice-report.json")
    if (
        report.get("schema") != "OverlapSpliceReportV1"
        or report.get("status") != "COMMITTED"
        or report.get("credentials") != "NONE"
        or report.get("order_entry") != "ABSENT"
    ):
        raise ValueError("splice report is not a committed public-only artifact")
    predecessor = Path(str(report["predecessor_session"]))
    successor = Path(str(report["successor_session"]))
    handover_snapshot = successor / "snapshot.bnraw"
    predecessor_depth = materialize_depth_observations(
        handover_snapshot, predecessor / "depth.bnraw"
    )
    successor_depth = materialize_depth_observations(
        handover_snapshot, successor / "depth.bnraw"
    )
    predecessor_trade = materialize_trade_observations(predecessor / "trade.bnraw")
    successor_trade = materialize_trade_observations(successor / "trade.bnraw")

    def verify_kind(
        name: str, predecessor_materialization: object, successor_materialization: object
    ) -> VerifiedStreamSpliceV1:
        predecessor_observations = predecessor_materialization.observations  # type: ignore[attr-defined]
        successor_observations = successor_materialization.observations  # type: ignore[attr-defined]
        journal = scan_boundary_journal(splice_dir / f"{name}.bnhandover")
        if not journal.clean_eof or journal.committed is None:
            raise ValueError(f"{name} journal has no valid durable commit")
        selection = select_canonical(
            journal.committed,
            list(predecessor_observations),
            list(successor_observations),
        )
        raw_stream = report.get(name)
        if not isinstance(raw_stream, dict):
            raise ValueError(f"splice report lacks {name}")
        raw_boundary = raw_stream.get("boundary")
        raw_selection = raw_stream.get("selection")
        if not isinstance(raw_boundary, dict) or not isinstance(raw_selection, dict):
            raise ValueError(f"splice report has malformed {name} boundary/selection")
        if (
            raw_boundary.get("boundary_id") != journal.committed.boundary_id
            or raw_boundary.get("boundary_sequence") != journal.committed.boundary_sequence
            or raw_boundary.get("boundary_sha256") != journal.committed.boundary_sha256
            or raw_selection.get("selection_sha256") != selection.selection_sha256
            or raw_selection.get("selected") != [asdict(item) for item in selection.selected]
        ):
            raise ValueError(f"{name} report differs from Python journal/selector replay")
        return VerifiedStreamSpliceV1(
            boundary_sequence=journal.committed.boundary_sequence,
            boundary_sha256=journal.committed.boundary_sha256,
            selection_sha256=selection.selection_sha256,
            selected_observations=len(selection.selected),
            excluded_overlap_records=selection.excluded_overlap_records,
            predecessor_materialization_sha256=(
                predecessor_materialization.materialization_sha256  # type: ignore[attr-defined]
            ),
            successor_materialization_sha256=(
                successor_materialization.materialization_sha256  # type: ignore[attr-defined]
            ),
        )

    return SpliceVerificationV1(
        schema="SpliceVerificationV1",
        status="PASS",
        splice_dir=str(splice_dir),
        depth=verify_kind("depth", predecessor_depth, successor_depth),
        trade=verify_kind("trade", predecessor_trade, successor_trade),
        credentials="NONE",
        order_entry="ABSENT",
    )
