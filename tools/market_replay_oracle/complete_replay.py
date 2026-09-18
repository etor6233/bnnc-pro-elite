"""Independent neutral replay of one campaign bound to a COMPLETE run."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Callable

from binance_lob.book import ApplyOutcome, LocalOrderBook
from binance_lob.raw_campaign import verify_raw_campaign
from binance_lob.segment_chain import _scan_raw_segment, _scan_segment_manifest

from .market_replay import (
    MarketReplayCorruption,
    _expectations,
    _integer,
    _load_object,
    _payload_object,
    _server_shutdown,
    _sha256_file,
    _text,
    _transport,
    _verify_scan_against_seal,
)


COMPLETE_REPLAY_USAGE = "COMPLETE_RUN_NEUTRAL_REPLAY"


def _fail(reason: str) -> None:
    raise MarketReplayCorruption(reason)


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_leaf(value: str, label: str) -> Path:
    path = Path(value)
    if not value.strip() or path.is_absolute() or len(path.parts) != 1 or path.name != value:
        _fail(f"{label} is not one safe filename")
    return path


def _validate_verifier(
    run: Path,
    row: dict[str, object],
    symbol: str,
    campaign_id: str,
    campaign_manifest_sha: str,
    kind: str,
    expected_verification_sha: str,
) -> None:
    if (
        _text(row, "name", "independent verifier") != f"{symbol.lower()}-{kind}"
        or _integer(row, "exit_code", "independent verifier") != 0
        or _integer(row, "stderr_bytes", "independent verifier") != 0
    ):
        _fail("independent verifier process result is not clean")
    report_name = _safe_leaf(
        _text(row, "report_file", "independent verifier"),
        "independent verifier report",
    )
    report_path = run / "independent-verification" / report_name
    expected_file_sha = _text(row, "report_sha256", "independent verifier")
    if (
        not _valid_digest(expected_file_sha)
        or _sha256_file(report_path) != expected_file_sha
        or report_path.stat().st_size
        != _integer(row, "report_bytes", "independent verifier")
    ):
        _fail("independent verifier report bytes differ from terminal")
    report = _load_object(report_path, "independent verifier report")
    common = (
        _text(report, "campaign_id", "independent verifier report") == campaign_id
        and _text(report, "symbol", "independent verifier report") == symbol
        and _text(report, "verification_sha256", "independent verifier report")
        == expected_verification_sha
    )
    if kind == "rust":
        exact = (
            _text(report, "schema", "Rust verifier report")
            == "VerifiedRawCampaignV1"
            and _text(report, "status", "Rust verifier report") == "PASS"
            and _text(
                report,
                "campaign_manifest_sha256",
                "Rust verifier report",
            )
            == campaign_manifest_sha
        )
    else:
        exact = (
            _text(report, "schema", "Python verifier report")
            == "RawCampaignVerificationV1"
            and _text(report, "status", "Python verifier report") == "VERIFIED"
            and _text(
                report,
                "campaign_manifest_file_sha256",
                "Python verifier report",
            )
            == campaign_manifest_sha
        )
    if not common or not exact:
        _fail("independent verifier report does not bind the selected campaign")


def _complete_source(raw_run: str, symbol: str) -> dict[str, object]:
    run = Path(raw_run).resolve(strict=True)
    terminal_path = run / "launcher-terminal.json"
    terminal = _load_object(terminal_path, "launcher terminal")
    run_id = _text(terminal, "run_id", "launcher terminal")
    mode = _text(terminal, "mode", "launcher terminal")
    if (
        _text(terminal, "schema", "launcher terminal")
        != "RawQualificationLauncherTerminalV2"
        or _text(terminal, "status", "launcher terminal") != "COMPLETE"
        or mode not in {"Production", "Smoke", "Test"}
        or _text(terminal, "credentials", "launcher terminal") != "NONE"
        or _text(terminal, "order_entry", "launcher terminal") != "ABSENT"
        or run.name != run_id
        or Path(_text(terminal, "run_root", "launcher terminal")).resolve(strict=True)
        != run
    ):
        _fail("source is not an exact COMPLETE qualification run")
    bindings_path = run / "campaign-bindings.json"
    bindings_sha = _sha256_file(bindings_path)
    if (
        _text(terminal, "campaign_bindings_sha256", "launcher terminal")
        != bindings_sha
    ):
        _fail("COMPLETE terminal does not bind campaign-bindings.json")
    campaign_rows = terminal.get("campaigns")
    if not isinstance(campaign_rows, list) or len(campaign_rows) != 2:
        _fail("COMPLETE terminal does not contain exactly two campaigns")
    campaigns: list[dict[str, object]] = []
    for item in campaign_rows:
        if not isinstance(item, dict):
            _fail("launcher campaign must be an object")
        campaigns.append(item)
    if {_text(item, "symbol", "launcher campaign") for item in campaigns} != {
        "BTCUSDT",
        "ETHUSDT",
    }:
        _fail("COMPLETE terminal does not contain exactly BTCUSDT and ETHUSDT")
    matches = [item for item in campaigns if item.get("symbol") == symbol]
    if len(matches) != 1:
        _fail("selected symbol is absent or duplicated in COMPLETE terminal")
    row = matches[0]
    if (
        _integer(row, "exit_code", "launcher campaign") != 0
        or _integer(row, "child_stderr_events", "launcher campaign") != 0
        or _integer(row, "stderr_file_bytes", "launcher campaign") != 0
    ):
        _fail("selected campaign did not terminate cleanly")
    campaign = Path(
        _text(row, "campaign_directory", "launcher campaign")
    ).resolve(strict=True)
    campaign_id = _text(row, "campaign_id", "launcher campaign")
    if campaign.parent != run or campaign.name != campaign_id:
        _fail("selected campaign is not the exact direct child bound by terminal")
    campaign_manifest_sha = _text(
        row, "campaign_manifest_sha256", "launcher campaign"
    )
    if (
        not _valid_digest(campaign_manifest_sha)
        or _sha256_file(campaign / "campaign.json") != campaign_manifest_sha
    ):
        _fail("selected campaign manifest differs from terminal")
    rust_verification_sha = _text(
        row, "rust_verification_sha256", "launcher campaign"
    )
    python_verification_sha = _text(
        row, "python_verification_sha256", "launcher campaign"
    )
    if not _valid_digest(rust_verification_sha) or not _valid_digest(
        python_verification_sha
    ):
        _fail("launcher campaign verifier digest is invalid")
    raw_verifiers = row.get("independent_verifiers")
    if not isinstance(raw_verifiers, list) or len(raw_verifiers) != 2:
        _fail("selected campaign lacks exactly two independent verifiers")
    verifiers: list[dict[str, object]] = []
    for item in raw_verifiers:
        if not isinstance(item, dict):
            _fail("independent verifier must be an object")
        verifiers.append(item)
    for kind, expected in (
        ("rust", rust_verification_sha),
        ("python", python_verification_sha),
    ):
        exact = [
            item for item in verifiers if item.get("name") == f"{symbol.lower()}-{kind}"
        ]
        if len(exact) != 1:
            _fail(f"selected campaign lacks exact {kind} verifier")
        _validate_verifier(
            run,
            exact[0],
            symbol,
            campaign_id,
            campaign_manifest_sha,
            kind,
            expected,
        )
    bindings = _load_object(bindings_path, "campaign bindings")
    raw_bindings = bindings.get("campaigns")
    if not isinstance(raw_bindings, list):
        _fail("campaign bindings campaigns must be an array")
    binding_matches = 0
    for item in raw_bindings:
        if not isinstance(item, dict):
            _fail("campaign binding must be an object")
        try:
            path_matches = (
                Path(_text(item, "campaign_directory", "campaign binding")).resolve(
                    strict=True
                )
                == campaign
            )
        except OSError:
            path_matches = False
        if (
            item.get("symbol") == symbol
            and item.get("campaign_id") == campaign_id
            and path_matches
        ):
            binding_matches += 1
    if (
        _text(bindings, "schema", "campaign bindings")
        != "RawQualificationCampaignBindingsV1"
        or _text(bindings, "run_id", "campaign bindings") != run_id
        or binding_matches != 1
    ):
        _fail("campaign bindings do not identify selected campaign exactly once")
    return {
        "run": run,
        "campaign": campaign,
        "run_id": run_id,
        "mode": mode,
        "terminal_sha256": _sha256_file(terminal_path),
        "campaign_id": campaign_id,
        "campaign_manifest_sha256": campaign_manifest_sha,
        "rust_verification_sha256": rust_verification_sha,
        "python_verification_sha256": python_verification_sha,
    }


def _generations(
    campaign: Path, manifest: dict[str, object], symbol: str
) -> list[dict[str, object]]:
    raw_rows = manifest.get("generations")
    if not isinstance(raw_rows, list) or not raw_rows:
        _fail("complete campaign contains no generation")
    result: list[dict[str, object]] = []
    for expected, raw_row in enumerate(raw_rows):
        if not isinstance(raw_row, dict):
            _fail("campaign generation must be an object")
        index = _integer(raw_row, "generation_index", "campaign generation")
        session_id = _text(raw_row, "session_id", "campaign generation")
        if index != expected:
            _fail("campaign generation order changed after verification")
        root = (campaign / _text(raw_row, "session_dir", "campaign generation")).resolve(
            strict=True
        )
        if root.parent.parent != campaign:
            _fail("campaign generation escaped exact generations directory")
        startup = _load_object(root / "startup.json", "generation startup")
        if (
            _text(startup, "session_id", "generation startup") != session_id
            or _text(startup, "symbol", "generation startup") != symbol
            or _integer(startup, "generation_index", "generation startup") != index
        ):
            _fail("generation startup identity differs from campaign")
        result.append(
            {
                "index": index,
                "session_id": session_id,
                "root": root,
                "startup": startup,
            }
        )
    return result


def _proofs(campaign: Path, manifest: dict[str, object]) -> list[dict[str, object]]:
    rows = manifest.get("handovers")
    if not isinstance(rows, list):
        _fail("campaign handovers must be an array")
    result: list[dict[str, object]] = []
    for raw_row in rows:
        if not isinstance(raw_row, dict):
            _fail("campaign handover must be an object")
        proof_path = campaign / _text(raw_row, "proof_file", "campaign handover")
        proof = _load_object(proof_path, "handover proof")
        if (
            _text(proof, "proof_sha256", "handover proof")
            != _text(raw_row, "proof_sha256", "campaign handover")
            or _sha256_file(proof_path)
            != _text(raw_row, "proof_file_sha256", "campaign handover")
        ):
            _fail("handover proof differs after campaign verification")
        result.append(proof)
    return result


def _stream_records(
    generation: dict[str, object],
    kind: str,
    visit: Callable[[object, int], None],
) -> None:
    root = generation["root"]
    startup = generation["startup"]
    assert isinstance(root, Path) and isinstance(startup, dict)
    identity = _transport(root, kind, startup)
    directory = root / kind
    manifest = _scan_segment_manifest(directory / "segments.bnseg")
    if not manifest.seals:
        _fail(f"{kind} manifest is not complete")
    segment_duration_ns = (
        _integer(startup, "segment_duration_s", "generation startup") * 1_000_000_000
    )
    for seal in manifest.seals:
        segment_index = _integer(seal, "segment_index", "seal")
        raw_file = _text(seal, "raw_file", "seal")
        if Path(raw_file).name != raw_file:
            _fail(f"{kind} manifest raw file is not local")
        scan = _scan_raw_segment(
            directory / raw_file,
            _expectations(seal, identity),
            capture_records=True,
            segment_index=segment_index,
            segment_duration_ns=segment_duration_ns,
        )
        _verify_scan_against_seal(scan, seal, kind)
        if scan.captured_records is None:
            _fail(f"{kind} scan retained no records")
        frame_index = _integer(seal, "first_frame_index", "seal")
        for record in scan.captured_records:
            visit(record, frame_index)
            frame_index += 1


def _depth_replay(
    generations: list[dict[str, object]], proofs: list[dict[str, object]]
) -> dict[str, object]:
    first_root = generations[0]["root"]
    assert isinstance(first_root, Path)
    from binance_lob.raw_log import iter_raw_records

    snapshots = list(iter_raw_records(first_root / "snapshot.bnraw"))
    if len(snapshots) != 1:
        _fail("initial generation must contain one snapshot record")
    symbol = _text(generations[0]["startup"], "symbol", "generation startup")  # type: ignore[arg-type]
    book = LocalOrderBook(symbol)
    book.load_snapshot(snapshots[0].frame.payload)
    total_raw = total_controls = selected_raw = selected_market = 0
    selected_controls = old_records = applied_records = 0
    checkpoints: list[dict[str, object]] = []
    for position, generation in enumerate(generations):
        prior_depth = proofs[position - 1]["depth"] if position else None
        next_depth = proofs[position]["depth"] if position < len(proofs) else None
        if prior_depth is not None and not isinstance(prior_depth, dict):
            _fail("handover depth must be an object")
        if next_depth is not None and not isinstance(next_depth, dict):
            _fail("handover depth must be an object")
        start = (
            0
            if prior_depth is None
            else _integer(
                prior_depth["successor_continuation"],  # type: ignore[arg-type]
                "frame_index",
                "depth successor continuation",
            )
        )
        end = (
            None
            if next_depth is None
            else _integer(
                next_depth["predecessor_boundary"],  # type: ignore[arg-type]
                "frame_index",
                "depth predecessor boundary",
            )
        )
        first_selected: int | None = None
        last_selected: int | None = None
        last_selected_sha: str | None = None
        generation_raw = generation_market = generation_controls = 0

        def visit(record: object, frame: int) -> None:
            nonlocal total_raw, total_controls, selected_raw, selected_market
            nonlocal selected_controls, old_records, applied_records
            nonlocal first_selected, last_selected, last_selected_sha
            nonlocal generation_raw, generation_market, generation_controls
            payload = record.payload  # type: ignore[attr-defined]
            total_raw += 1
            value = _payload_object(payload, "depth payload")
            control = _server_shutdown(value)
            if control:
                total_controls += 1
            if frame < start or (end is not None and frame > end):
                return
            if first_selected is None:
                first_selected = frame
            last_selected = frame
            last_selected_sha = record.record_sha256  # type: ignore[attr-defined]
            selected_raw += 1
            generation_raw += 1
            if control:
                selected_controls += 1
                generation_controls += 1
                return
            selected_market += 1
            generation_market += 1
            outcome = book.apply_depth(payload)
            if outcome is ApplyOutcome.OLD:
                old_records += 1
            else:
                applied_records += 1

        _stream_records(generation, "depth", visit)
        if first_selected != start or last_selected is None or (
            end is not None and last_selected != end
        ):
            _fail("depth selection boundary frame is absent")
        if next_depth is not None:
            predecessor = next_depth["predecessor_boundary"]
            if not isinstance(predecessor, dict):
                _fail("depth predecessor boundary must be an object")
            if (
                last_selected_sha
                != _text(predecessor, "record_sha256", "depth predecessor boundary")
                or book.last_update_id
                != _integer(next_depth, "boundary_sequence", "depth handover")
            ):
                _fail("depth replay did not arrive at proven raw/sequence boundary")
        assert first_selected is not None and last_selected is not None
        checkpoints.append(
            {
                "generation_index": generation["index"],
                "session_id": generation["session_id"],
                "first_selected_frame_index": first_selected,
                "last_selected_frame_index": last_selected,
                "selected_raw_records": generation_raw,
                "selected_market_records": generation_market,
                "selected_control_records": generation_controls,
                "final_update_id": book.last_update_id,
                "state_sha256": book.state_digest(),
            }
        )
    if book.last_update_id is None:
        _fail("depth replay has no final update ID")
    return {
        "total_raw_records": total_raw,
        "total_control_records": total_controls,
        "selected_raw_records": selected_raw,
        "selected_market_records": selected_market,
        "selected_control_records": selected_controls,
        "overlap_records_excluded": total_raw - selected_raw,
        "old_records": old_records,
        "applied_records": applied_records,
        "final_update_id": book.last_update_id,
        "bid_levels": book.bid_levels,
        "ask_levels": book.ask_levels,
        "state_sha256": book.state_digest(),
        "generations": checkpoints,
    }


def _trade_replay(
    generations: list[dict[str, object]], proofs: list[dict[str, object]]
) -> dict[str, object]:
    total_raw = total_controls = selected_raw = selected_market = 0
    selected_controls = 0
    first_trade_id: int | None = None
    previous_trade_id: int | None = None
    checkpoints: list[dict[str, object]] = []
    for position, generation in enumerate(generations):
        prior_trade = proofs[position - 1]["trade"] if position else None
        next_trade = proofs[position]["trade"] if position < len(proofs) else None
        if prior_trade is not None and not isinstance(prior_trade, dict):
            _fail("handover trade must be an object")
        if next_trade is not None and not isinstance(next_trade, dict):
            _fail("handover trade must be an object")
        start = (
            0
            if prior_trade is None
            else _integer(
                prior_trade["successor_next_shared"],  # type: ignore[arg-type]
                "frame_index",
                "trade successor boundary",
            )
            + 1
        )
        end = (
            None
            if next_trade is None
            else _integer(
                next_trade["predecessor_next_shared"],  # type: ignore[arg-type]
                "frame_index",
                "trade predecessor boundary",
            )
        )
        first_selected: int | None = None
        last_selected: int | None = None
        last_selected_sha: str | None = None
        generation_raw = generation_market = generation_controls = 0

        def visit(record: object, frame: int) -> None:
            nonlocal total_raw, total_controls, selected_raw, selected_market
            nonlocal selected_controls, first_trade_id, previous_trade_id
            nonlocal first_selected, last_selected, last_selected_sha
            nonlocal generation_raw, generation_market, generation_controls
            payload = record.payload  # type: ignore[attr-defined]
            total_raw += 1
            value = _payload_object(payload, "trade payload")
            control = _server_shutdown(value)
            if control:
                total_controls += 1
            if frame < start or (end is not None and frame > end):
                return
            if first_selected is None:
                first_selected = frame
            last_selected = frame
            last_selected_sha = record.record_sha256  # type: ignore[attr-defined]
            selected_raw += 1
            generation_raw += 1
            if control:
                selected_controls += 1
                generation_controls += 1
                return
            if value.get("e") != "trade" or value.get("s") != generation["startup"]["symbol"]:  # type: ignore[index]
                _fail("unexpected selected trade event identity")
            trade_id = _integer(value, "t", "trade")
            _integer(value, "E", "trade")
            _integer(value, "T", "trade")
            if previous_trade_id is not None and trade_id <= previous_trade_id:
                _fail("selected trade ID duplicated or regressed across handover")
            if first_trade_id is None:
                first_trade_id = trade_id
            previous_trade_id = trade_id
            selected_market += 1
            generation_market += 1

        _stream_records(generation, "trade", visit)
        if (first_selected is not None and first_selected != start) or (
            end is not None
            and (
                (last_selected is not None and last_selected != end)
                or (last_selected is None and start <= end)
            )
        ):
            _fail("trade selection boundary frame is absent")
        if next_trade is not None:
            predecessor = next_trade["predecessor_next_shared"]
            if not isinstance(predecessor, dict):
                _fail("trade predecessor boundary must be an object")
            if (
                (
                    last_selected is not None
                    and last_selected_sha
                    != _text(
                        predecessor, "record_sha256", "trade predecessor boundary"
                    )
                )
                or previous_trade_id
                != _integer(next_trade, "next_shared_trade_id", "trade handover")
            ):
                _fail("trade replay did not arrive at proven shared event")
        if previous_trade_id is None:
            _fail("trade replay contains no market event")
        checkpoints.append(
            {
                "generation_index": generation["index"],
                "session_id": generation["session_id"],
                "first_selected_frame_index": first_selected,
                "last_selected_frame_index": last_selected,
                "selected_raw_records": generation_raw,
                "selected_market_records": generation_market,
                "selected_control_records": generation_controls,
                "last_trade_id": previous_trade_id,
            }
        )
    if first_trade_id is None or previous_trade_id is None:
        _fail("trade replay contains no market event")
    return {
        "total_raw_records": total_raw,
        "total_control_records": total_controls,
        "selected_raw_records": selected_raw,
        "selected_market_records": selected_market,
        "selected_control_records": selected_controls,
        "overlap_records_excluded": total_raw - selected_raw,
        "first_trade_id": first_trade_id,
        "last_trade_id": previous_trade_id,
        "trade_ids_strictly_increasing": True,
        "generations": checkpoints,
    }


def replay_complete_run(selection: dict[str, object]) -> dict[str, object]:
    if set(selection) != {"schema", "usage", "run_directory", "symbol"} or (
        selection.get("schema") != "CompleteRunReplaySelectionV1"
        or selection.get("usage") != COMPLETE_REPLAY_USAGE
        or selection.get("symbol") not in {"BTCUSDT", "ETHUSDT"}
        or not isinstance(selection.get("run_directory"), str)
    ):
        _fail("invalid complete-run replay selection")
    symbol = str(selection["symbol"])
    source = _complete_source(str(selection["run_directory"]), symbol)
    campaign = source["campaign"]
    assert isinstance(campaign, Path)
    verified = verify_raw_campaign(campaign)
    if (
        verified.get("campaign_id") != source["campaign_id"]
        or verified.get("symbol") != symbol
        or verified.get("campaign_manifest_file_sha256")
        != source["campaign_manifest_sha256"]
        or verified.get("verification_sha256")
        != source["python_verification_sha256"]
    ):
        _fail("terminal and independent campaign verification disagree")
    manifest = _load_object(campaign / "campaign.json", "campaign manifest")
    generations = _generations(campaign, manifest, symbol)
    proofs = _proofs(campaign, manifest)
    if len(proofs) + 1 != len(generations):
        _fail("verified campaign topology differs from replay topology")
    for index, proof in enumerate(proofs):
        if (
            _integer(proof, "predecessor_generation_index", "handover proof")
            != index
            or _integer(proof, "successor_generation_index", "handover proof")
            != index + 1
            or _text(proof, "predecessor_session_id", "handover proof")
            != generations[index]["session_id"]
            or _text(proof, "successor_session_id", "handover proof")
            != generations[index + 1]["session_id"]
            or _text(proof, "symbol", "handover proof") != symbol
        ):
            _fail("handover proof order differs from campaign generations")
    depth = _depth_replay(generations, proofs)
    trades = _trade_replay(generations, proofs)
    handovers: list[dict[str, object]] = []
    for proof in proofs:
        depth_proof = proof["depth"]
        trade_proof = proof["trade"]
        if not isinstance(depth_proof, dict) or not isinstance(trade_proof, dict):
            _fail("handover stream evidence must be objects")
        depth_predecessor = depth_proof["predecessor_boundary"]
        depth_continuation = depth_proof["successor_continuation"]
        trade_predecessor = trade_proof["predecessor_next_shared"]
        trade_successor = trade_proof["successor_next_shared"]
        if not all(
            isinstance(item, dict)
            for item in (
                depth_predecessor,
                depth_continuation,
                trade_predecessor,
                trade_successor,
            )
        ):
            _fail("handover raw positions must be objects")
        handovers.append(
            {
                "predecessor_generation_index": _integer(
                    proof, "predecessor_generation_index", "handover proof"
                ),
                "successor_generation_index": _integer(
                    proof, "successor_generation_index", "handover proof"
                ),
                "proof_sha256": _text(proof, "proof_sha256", "handover proof"),
                "depth_boundary_sequence": _integer(
                    depth_proof, "boundary_sequence", "depth handover"
                ),
                "depth_boundary_state_sha256": _text(
                    depth_proof, "boundary_state_sha256", "depth handover"
                ),
                "depth_predecessor_last_frame_index": _integer(
                    depth_predecessor,  # type: ignore[arg-type]
                    "frame_index",
                    "depth predecessor boundary",
                ),
                "depth_successor_first_frame_index": _integer(
                    depth_continuation,  # type: ignore[arg-type]
                    "frame_index",
                    "depth successor continuation",
                ),
                "trade_boundary_id": _integer(
                    trade_proof, "next_shared_trade_id", "trade handover"
                ),
                "trade_predecessor_last_frame_index": _integer(
                    trade_predecessor,  # type: ignore[arg-type]
                    "frame_index",
                    "trade predecessor boundary",
                ),
                "trade_successor_skipped_through_frame_index": _integer(
                    trade_successor,  # type: ignore[arg-type]
                    "frame_index",
                    "trade successor boundary",
                ),
            }
        )
    report: dict[str, object] = {
        "schema": "CompleteRunReplayReportV1",
        "usage": COMPLETE_REPLAY_USAGE,
        "qualification_claim": False,
        "source": {
            "run_id": source["run_id"],
            "run_mode": source["mode"],
            "run_status": "COMPLETE",
            "launcher_terminal_sha256": source["terminal_sha256"],
            "campaign_id": source["campaign_id"],
            "campaign_manifest_sha256": source["campaign_manifest_sha256"],
            "campaign_verification_sha256": source["rust_verification_sha256"],
            "rust_verification_sha256": source["rust_verification_sha256"],
            "python_verification_sha256": source["python_verification_sha256"],
            "symbol": symbol,
            "generations": len(generations),
            "handovers": len(proofs),
        },
        "depth": depth,
        "trades": trades,
        "handovers": handovers,
        "cross_stream_total_order_available": False,
        "economic_features": [],
        "report_sha256": "",
    }
    digest_material = json.dumps(
        report, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    report["report_sha256"] = sha256(digest_material).hexdigest()
    return report


__all__ = [
    "COMPLETE_REPLAY_USAGE",
    "replay_complete_run",
]
