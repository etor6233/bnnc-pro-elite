from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import tempfile
import unittest

from binance_lob.cli import main
from binance_lob.raw_campaign import (
    RawCampaignCorruption,
    _expected_evaluation,
    _journal_events,
    _proof_digest,
    _recompute_handover_evidence,
    _rust_value,
    _scan_journal,
    verify_raw_campaign,
)
from binance_lob.segment_chain import verify_segmented_generation
from test_segment_chain import SPEC_REVISION, _build_generation


def _compact(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _pretty(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _journal_record(
    index: int,
    previous: str,
    generation_index: int | None,
    channel: str,
    payload: dict[str, object],
    started_wall_ns: int,
) -> tuple[bytes, str]:
    body = {
        "schema": "RawCampaignJournalRecordV1",
        "record_index": index,
        "wall_ns": started_wall_ns + index,
        "campaign_mono_ns": index * 300_000_000,
        "generation_index": generation_index,
        "channel": channel,
        "payload": _rust_value(payload),
        "previous_record_sha256": previous,
    }
    digest = sha256(_compact(body)).hexdigest()
    return _compact({"body": body, "record_sha256": digest}) + b"\n", digest


def _build_campaign(parent: Path, *, server_shutdown: bool = False) -> Path:
    campaign_id = "1700000000000000000-BTCUSDT-raw-aaaaaaaaaaaa"
    campaign = parent / campaign_id
    generations_root = campaign / "generations"
    evaluations_root = campaign / "evaluations"
    handovers_root = campaign / "handovers"
    control_root = campaign / "control"
    for directory in (
        campaign,
        generations_root,
        evaluations_root,
        handovers_root,
        control_root,
    ):
        directory.mkdir()

    campaign_started = 1_700_000_000_000_000_000
    evaluations: list[dict[str, object]] = []
    oracles: list[dict[str, object]] = []
    generation_rows: list[dict[str, object]] = []
    generation_manifests: list[dict[str, object]] = []
    for index in range(2):
        session_id = f"170000000{index}-BTCUSDT-g{index:03}-{'a' * 12}"
        generation_root = generations_root / session_id
        generation_root.mkdir()
        generation = _build_generation(
            generation_root,
            generation_index=index,
            duration_s=2,
            started_wall_ns=campaign_started + index * 1_000_000_000,
            epoch_suffix=f"-{index}",
            trade_ids=(10, 12),
            single_overlap_segment=True,
            server_shutdown_stream=("depth" if server_shutdown and index == 0 else None),
        )
        generation_manifests.append(generation)
        oracle = verify_segmented_generation(generation_root)
        oracles.append(oracle)
        session_dir = f"generations/{session_id}"
        evaluation = _expected_evaluation(
            generation_root, oracle, generation, session_dir
        )
        evaluations.append(evaluation)
        (evaluations_root / f"generation-{index:03}-rust.json").write_bytes(
            _pretty(evaluation)
        )
        by_name = {
            str(stream["name"]): stream
            for stream in evaluation["streams"]  # type: ignore[index]
            if isinstance(stream, dict)
        }
        generation_rows.append(
            {
                "generation_index": index,
                "session_id": session_id,
                "session_dir": session_dir,
                "verification_sha256": evaluation["verification_sha256"],
                "evaluation_file": f"evaluations/generation-{index:03}-rust.json",
                "evaluation_file_sha256": sha256(_pretty(evaluation)).hexdigest(),
                "generation_manifest_sha256": evaluation["generation_manifest_sha256"],
                "depth_records": by_name["depth"]["records"],
                "trade_records": by_name["trade"]["records"],
            }
        )

    predecessor_root = generations_root / str(evaluations[0]["session_id"])
    successor_generation_root = generations_root / str(evaluations[1]["session_id"])
    successor_startup_sha = sha256(
        (successor_generation_root / "startup.json").read_bytes()
    ).hexdigest()
    successor_http_sha = sha256(
        (successor_generation_root / "snapshot-http.json").read_bytes()
    ).hexdigest()
    depth_evidence, trade_evidence = _recompute_handover_evidence(
        predecessor_root,
        successor_generation_root,
        evaluations[0],
        evaluations[1],
    )
    proof: dict[str, object] = {
        "schema": "RawGenerationHandoverProofV1",
        "status": "PROVEN",
        "predecessor_session_id": evaluations[0]["session_id"],
        "successor_session_id": evaluations[1]["session_id"],
        "predecessor_generation_index": 0,
        "successor_generation_index": 1,
        "symbol": "BTCUSDT",
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "predecessor_verification_sha256": evaluations[0]["verification_sha256"],
        "successor_startup_sha256": successor_startup_sha,
        "successor_snapshot_record_sha256": evaluations[1]["snapshot_record_sha256"],
        "successor_snapshot_http_sha256": successor_http_sha,
        "depth": depth_evidence,
        "trade": trade_evidence,
    }
    proof["proof_sha256"] = _proof_digest(proof)
    handover_directory = handovers_root / "handover-000-to-001"
    handover_directory.mkdir()
    (handover_directory / "handover.json").write_bytes(_pretty(proof))

    startup = {
        "schema": "RawCampaignStartupV1",
        "campaign_id": campaign_id,
        "symbol": "BTCUSDT",
        "total_duration_s": 3,
        "rotation_s": 1,
        "overlap_s": 1,
        "segment_s": 1,
        "started_wall_ns": campaign_started,
        "process_id": 1,
        "executable_sha256": "f" * 64,
        "capture_executable_sha256": "a" * 64,
        "public_config_sha256": "b" * 64,
        "spec_revision": SPEC_REVISION,
        "credentials": "NONE",
        "order_entry": "ABSENT",
    }
    startup_bytes = _pretty(startup)
    (campaign / "campaign-startup.json").write_bytes(startup_bytes)

    process_started_payloads = [
        {
            "event": "PROCESS_STARTED",
            "schema": "CaptureProcessEventV1",
            "generation_index": index,
            "process_id": index + 10,
            "session_dir": str(
                generations_root / str(generation_rows[index]["session_id"])
            ),
            "session_id": generation_rows[index]["session_id"],
            "spec_revision": SPEC_REVISION,
            "startup_manifest_sha256": sha256(
                (
                    generations_root
                    / str(generation_rows[index]["session_id"])
                    / "startup.json"
                ).read_bytes()
            ).hexdigest(),
            "symbol": "BTCUSDT",
        }
        for index in range(2)
    ]
    process_terminal_payloads = [
        {
            "event": "PROCESS_TERMINAL",
            "generation_manifest": "generation.json",
            "schema": "CaptureTerminalProcessEventV1",
            "session_id": generation_rows[index]["session_id"],
            "status": "COMPLETE",
        }
        for index in range(2)
    ]
    shutdown_identity: dict[str, object] | None = None
    if server_shutdown:
        depth_oracle = next(
            stream
            for stream in oracles[0]["streams"]
            if stream["name"] == "depth"
        )
        shutdowns = depth_oracle["server_shutdowns"]
        assert isinstance(shutdowns, list) and len(shutdowns) == 1
        shutdown_identity = dict(shutdowns[0])
    lifecycle: list[tuple[int | None, str, dict[str, object]]] = [
        (
            None,
            "CAMPAIGN",
            {
                "event": "CAMPAIGN_STARTED",
                "campaign_id": campaign_id,
                "startup_sha256": sha256(startup_bytes).hexdigest(),
            },
        ),
        (0, "CAMPAIGN", {"event": "GENERATION_LAUNCHED", "duration_s": 2}),
        (0, "CHILD_STDOUT", process_started_payloads[0]),
        (0, "SUPERVISOR", {"event": "INITIAL_ACTIVE_REGISTERED"}),
        *(
            [
                (
                    0,
                    "CHILD_STDOUT",
                    {
                        "event": "SERVER_SHUTDOWN_DURABLE",
                        "schema": "ServerShutdownDurableProcessEventV1",
                        "session_id": generation_rows[0]["session_id"],
                        "shutdown": {
                            "schema": "DurableServerShutdownEventV1",
                            **shutdown_identity,
                        },
                    },
                )
            ]
            if shutdown_identity is not None
            else []
        ),
        (
            1,
            "CAMPAIGN",
            (
                {
                    "event": "GENERATION_LAUNCHED_SERVER_SHUTDOWN",
                    "duration_s": 2,
                    "source_generation": 0,
                    "source_epoch": shutdown_identity["connection_epoch"],
                }
                if shutdown_identity is not None
                else {"event": "GENERATION_LAUNCHED", "duration_s": 2}
            ),
        ),
        (1, "CHILD_STDOUT", process_started_payloads[1]),
        (1, "SUPERVISOR", {"event": "CANDIDATE_REGISTERED"}),
        (0, "CHILD_STDOUT", process_terminal_payloads[0]),
        (0, "CAMPAIGN", {"event": "GENERATION_EXITED", "success": True, "code": 0}),
        (1, "CAMPAIGN", {"event": "HANDOVER_PROOF_STARTED", "predecessor": 0}),
        (
            1,
            "SUPERVISOR",
            {
                "event": "HANDOVER_PROVEN_AND_PROMOTED",
                "predecessor": 0,
                "proof_sha256": proof["proof_sha256"],
            },
        ),
        (1, "CHILD_STDOUT", process_terminal_payloads[1]),
        (1, "CAMPAIGN", {"event": "GENERATION_EXITED", "success": True, "code": 0}),
    ]
    lifecycle.append(
        (None, "CAMPAIGN", {"event": "CAMPAIGN_EVALUATION_PREPARED"})
    )
    journal = bytearray()
    previous = "0" * 64
    for index, (generation_index, channel, payload) in enumerate(lifecycle):
        record, previous = _journal_record(
            index,
            previous,
            generation_index,
            channel,
            payload,
            campaign_started,
        )
        journal.extend(record)
    precommit_records = len(lifecycle)
    precommit_sha256 = previous

    manifest = {
        "schema": "RawCampaignManifestV1",
        "status": "COMPLETE",
        "campaign_id": campaign_id,
        "symbol": "BTCUSDT",
        "total_duration_s": 3,
        "rotation_s": 1,
        "overlap_s": 1,
        "segment_s": 1,
        "started_wall_ns": campaign_started,
        "finished_wall_ns": campaign_started + 3_000_000_000,
        "spec_revision": SPEC_REVISION,
        "credentials": "NONE",
        "order_entry": "ABSENT",
        "executable_sha256": "f" * 64,
        "capture_executable_sha256": "a" * 64,
        "public_config_sha256": "b" * 64,
        "startup_file": "campaign-startup.json",
        "startup_sha256": sha256(startup_bytes).hexdigest(),
        "journal_file": "campaign-events.jsonl",
        "journal_boundary": "PRECOMMIT_PREFIX",
        "journal_precommit_records": precommit_records,
        "journal_precommit_sha256": precommit_sha256,
        "supervisor_gap_count": 0,
        "generations": generation_rows,
        "handovers": [
            {
                "predecessor_generation_index": 0,
                "successor_generation_index": 1,
                "proof_sha256": proof["proof_sha256"],
                "proof_file": "handovers/handover-000-to-001/handover.json",
                "proof_file_sha256": sha256(_pretty(proof)).hexdigest(),
            }
        ],
    }
    manifest_bytes = _pretty(manifest)
    (campaign / "campaign.json").write_bytes(manifest_bytes)
    commit_record, previous = _journal_record(
        precommit_records,
        precommit_sha256,
        None,
        "CAMPAIGN",
        {
            "event": "CAMPAIGN_COMMITTED",
            "manifest_file": "campaign.json",
            "manifest_sha256": sha256(manifest_bytes).hexdigest(),
        },
        campaign_started,
    )
    journal.extend(commit_record)
    (campaign / "campaign-events.jsonl").write_bytes(bytes(journal))
    return campaign


class RawCampaignVerificationTests(unittest.TestCase):
    def test_one_warm_successor_has_no_authority_until_ordered_registration(self) -> None:
        campaign_id = "1700000000000000000-BTCUSDT-raw-warmahead000"
        startup_digest = "a" * 64
        manifest_digest = "b" * 64
        proof_digest = "c" * 64

        def generation(index: int) -> dict[str, object]:
            return {
                "session_id": f"generation-{index}",
                "symbol": "BTCUSDT",
                "duration_requested_s": 120,
                "startup_sha256": f"{index + 1:064x}",
                "streams": [
                    {
                        "name": name,
                        "connection_epoch": f"{name}-epoch-{index}",
                        "server_shutdown_events": 0,
                    }
                    for name in ("depth", "trade")
                ],
                "_raw_server_shutdowns": [],
            }

        generations = [generation(index) for index in range(3)]
        handovers = [
            {
                "predecessor_generation_index": index,
                "successor_generation_index": index + 1,
                "proof_sha256": proof_digest,
            }
            for index in range(2)
        ]

        def started(index: int) -> dict[str, object]:
            return {
                "event": "PROCESS_STARTED",
                "schema": "CaptureProcessEventV1",
                "generation_index": index,
                "process_id": 10 + index,
                "session_dir": f"C:/evidence/{campaign_id}/generations/generation-{index}",
                "session_id": f"generation-{index}",
                "spec_revision": SPEC_REVISION,
                "startup_manifest_sha256": f"{index + 1:064x}",
                "symbol": "BTCUSDT",
            }

        def terminal(index: int) -> dict[str, object]:
            return {
                "event": "PROCESS_TERMINAL",
                "schema": "CaptureTerminalProcessEventV1",
                "session_id": f"generation-{index}",
                "status": "COMPLETE",
                "generation_manifest": "generation.json",
            }

        entries: list[tuple[int, int | None, str, dict[str, object]]] = [
            (0, None, "CAMPAIGN", {"event": "CAMPAIGN_STARTED", "campaign_id": campaign_id, "startup_sha256": startup_digest}),
            (100_000_000, 0, "CAMPAIGN", {"event": "GENERATION_LAUNCHED", "duration_s": 120}),
            (1_000_000_000, 0, "CHILD_STDOUT", started(0)),
            (2_000_000_000, 0, "SUPERVISOR", {"event": "INITIAL_ACTIVE_REGISTERED"}),
            (60_000_000_000, 1, "CAMPAIGN", {"event": "GENERATION_LAUNCHED", "duration_s": 120}),
            (61_000_000_000, 1, "CHILD_STDOUT", started(1)),
            (62_000_000_000, 1, "SUPERVISOR", {"event": "CANDIDATE_REGISTERED"}),
            (120_000_000_000, 2, "CAMPAIGN", {"event": "GENERATION_LAUNCHED", "duration_s": 120}),
            (121_000_000_000, 2, "CHILD_STDOUT", started(2)),
            (122_000_000_000, 0, "CHILD_STDOUT", terminal(0)),
            (123_000_000_000, 0, "CAMPAIGN", {"event": "GENERATION_EXITED", "success": True, "code": 0}),
            (124_000_000_000, 1, "CAMPAIGN", {"event": "HANDOVER_PROOF_STARTED", "predecessor": 0}),
            (125_000_000_000, 1, "SUPERVISOR", {"event": "HANDOVER_PROVEN_AND_PROMOTED", "predecessor": 0, "proof_sha256": proof_digest}),
            (126_000_000_000, 2, "SUPERVISOR", {"event": "CANDIDATE_REGISTERED"}),
            (182_000_000_000, 1, "CHILD_STDOUT", terminal(1)),
            (183_000_000_000, 1, "CAMPAIGN", {"event": "GENERATION_EXITED", "success": True, "code": 0}),
            (184_000_000_000, 2, "CAMPAIGN", {"event": "HANDOVER_PROOF_STARTED", "predecessor": 1}),
            (185_000_000_000, 2, "SUPERVISOR", {"event": "HANDOVER_PROVEN_AND_PROMOTED", "predecessor": 1, "proof_sha256": proof_digest}),
            (241_000_000_000, 2, "CHILD_STDOUT", terminal(2)),
            (242_000_000_000, 2, "CAMPAIGN", {"event": "GENERATION_EXITED", "success": True, "code": 0}),
            (243_000_000_000, None, "CAMPAIGN", {"event": "CAMPAIGN_EVALUATION_PREPARED"}),
            (244_000_000_000, None, "CAMPAIGN", {"event": "CAMPAIGN_COMMITTED", "manifest_file": "campaign.json", "manifest_sha256": manifest_digest}),
        ]
        records = [
            {
                "record_index": index,
                "campaign_mono_ns": mono_ns,
                "channel": channel,
                "generation_index": generation_index,
                "payload": payload,
            }
            for index, (mono_ns, generation_index, channel, payload) in enumerate(entries)
        ]

        def validate(rows: list[dict[str, object]]) -> None:
            _journal_events(
                rows,
                startup_digest,
                manifest_digest,
                campaign_id,
                240,
                generations,
                handovers,
            )

        validate(records)

        premature = deepcopy(records)
        promotion = next(i for i, row in enumerate(premature) if row["generation_index"] == 1 and row["payload"]["event"] == "HANDOVER_PROVEN_AND_PROMOTED")  # type: ignore[index]
        registration = next(i for i, row in enumerate(premature) if row["generation_index"] == 2 and row["payload"]["event"] == "CANDIDATE_REGISTERED")  # type: ignore[index]
        for key in ("generation_index", "channel", "payload"):
            premature[promotion][key], premature[registration][key] = premature[registration][key], premature[promotion][key]
        with self.assertRaises(RawCampaignCorruption):
            validate(premature)

        terminal_first = deepcopy(records)
        promotion = next(i for i, row in enumerate(terminal_first) if row["generation_index"] == 2 and row["payload"]["event"] == "HANDOVER_PROVEN_AND_PROMOTED")  # type: ignore[index]
        terminal_index = next(i for i, row in enumerate(terminal_first) if row["generation_index"] == 2 and row["payload"]["event"] == "PROCESS_TERMINAL")  # type: ignore[index]
        for key in ("generation_index", "channel", "payload"):
            terminal_first[promotion][key], terminal_first[terminal_index][key] = terminal_first[terminal_index][key], terminal_first[promotion][key]
        with self.assertRaises(RawCampaignCorruption):
            validate(terminal_first)

        duplicate = deepcopy(records)
        warm_launch = next(i for i, row in enumerate(duplicate) if row["generation_index"] == 2 and row["payload"]["event"] == "GENERATION_LAUNCHED")  # type: ignore[index]
        duplicate.insert(warm_launch + 1, deepcopy(duplicate[warm_launch]))
        for index, row in enumerate(duplicate):
            row["record_index"] = index
        with self.assertRaises(RawCampaignCorruption):
            validate(duplicate)

    def test_server_shutdown_launch_requires_prior_durable_source_event(self) -> None:
        campaign_id = "1700000000000000000-BTCUSDT-raw-aaaaaaaaaaaa"
        startup_digest = "a" * 64
        manifest_digest = "b" * 64
        proof_digest = "c" * 64

        def generation(index: int, shutdowns: int) -> dict[str, object]:
            result: dict[str, object] = {
                "session_id": f"generation-{index}",
                "symbol": "BTCUSDT",
                "duration_requested_s": 2,
                "startup_sha256": f"{index + 1:064x}",
                "streams": [
                    {
                        "name": "depth",
                        "connection_epoch": f"depth-epoch-{index}",
                        "server_shutdown_events": shutdowns,
                    },
                    {
                        "name": "trade",
                        "connection_epoch": f"trade-epoch-{index}",
                        "server_shutdown_events": 0,
                    },
                ],
            }
            result["_raw_server_shutdowns"] = (
                [
                    {
                        "stream": "depth",
                        "connection_epoch": f"depth-epoch-{index}",
                        "segment_index": 0,
                        "raw_file": "segment-000000.bnraw",
                        "frame_index": 1,
                        "receive_mono_ns": 1,
                        "durable_record_count": 2,
                        "durable_through_offset": 3,
                        "last_record_sha256": "d" * 64,
                    }
                ]
                if shutdowns
                else []
            )
            return result

        generations = [generation(0, 1), generation(1, 0)]
        handovers = [
            {
                "predecessor_generation_index": 0,
                "successor_generation_index": 1,
                "proof_sha256": proof_digest,
            }
        ]
        entries: list[tuple[int | None, str, dict[str, object]]] = [
            (
                None,
                "CAMPAIGN",
                {
                    "campaign_id": campaign_id,
                    "event": "CAMPAIGN_STARTED",
                    "startup_sha256": startup_digest,
                },
            ),
            (0, "CAMPAIGN", {"event": "GENERATION_LAUNCHED", "duration_s": 2}),
            (
                0,
                "CHILD_STDOUT",
                {
                    "event": "PROCESS_STARTED",
                    "schema": "CaptureProcessEventV1",
                    "generation_index": 0,
                    "process_id": 10,
                    "session_dir": f"C:/evidence/{campaign_id}/generations/generation-0",
                    "session_id": "generation-0",
                    "spec_revision": SPEC_REVISION,
                    "startup_manifest_sha256": f"{1:064x}",
                    "symbol": "BTCUSDT",
                },
            ),
            (0, "SUPERVISOR", {"event": "INITIAL_ACTIVE_REGISTERED"}),
            (
                0,
                "CHILD_STDOUT",
                {
                    "event": "SERVER_SHUTDOWN_DURABLE",
                    "schema": "ServerShutdownDurableProcessEventV1",
                    "session_id": "generation-0",
                    "shutdown": {
                        "schema": "DurableServerShutdownEventV1",
                        "stream": "depth",
                        "connection_epoch": "depth-epoch-0",
                        "segment_index": 0,
                        "raw_file": "segment-000000.bnraw",
                        "frame_index": 1,
                        "receive_mono_ns": 1,
                        "durable_record_count": 2,
                        "durable_through_offset": 3,
                        "last_record_sha256": "d" * 64,
                    },
                },
            ),
            (
                1,
                "CAMPAIGN",
                {
                    "event": "GENERATION_LAUNCHED_SERVER_SHUTDOWN",
                    "duration_s": 2,
                    "source_generation": 0,
                    "source_epoch": "depth-epoch-0",
                },
            ),
            (
                1,
                "CHILD_STDOUT",
                {
                    "event": "PROCESS_STARTED",
                    "schema": "CaptureProcessEventV1",
                    "generation_index": 1,
                    "process_id": 11,
                    "session_dir": f"C:/evidence/{campaign_id}/generations/generation-1",
                    "session_id": "generation-1",
                    "spec_revision": SPEC_REVISION,
                    "startup_manifest_sha256": f"{2:064x}",
                    "symbol": "BTCUSDT",
                },
            ),
            (1, "SUPERVISOR", {"event": "CANDIDATE_REGISTERED"}),
            (
                0,
                "CHILD_STDOUT",
                {
                    "event": "PROCESS_TERMINAL",
                    "schema": "CaptureTerminalProcessEventV1",
                    "session_id": "generation-0",
                    "status": "COMPLETE",
                    "generation_manifest": "generation.json",
                },
            ),
            (0, "CAMPAIGN", {"event": "GENERATION_EXITED", "success": True, "code": 0}),
            (1, "CAMPAIGN", {"event": "HANDOVER_PROOF_STARTED", "predecessor": 0}),
            (
                1,
                "SUPERVISOR",
                {
                    "event": "HANDOVER_PROVEN_AND_PROMOTED",
                    "predecessor": 0,
                    "proof_sha256": proof_digest,
                },
            ),
            (
                1,
                "CHILD_STDOUT",
                {
                    "event": "PROCESS_TERMINAL",
                    "schema": "CaptureTerminalProcessEventV1",
                    "session_id": "generation-1",
                    "status": "COMPLETE",
                    "generation_manifest": "generation.json",
                },
            ),
            (1, "CAMPAIGN", {"event": "GENERATION_EXITED", "success": True, "code": 0}),
            (None, "CAMPAIGN", {"event": "CAMPAIGN_EVALUATION_PREPARED"}),
            (
                None,
                "CAMPAIGN",
                {
                    "event": "CAMPAIGN_COMMITTED",
                    "manifest_file": "campaign.json",
                    "manifest_sha256": manifest_digest,
                },
            ),
        ]
        records = [
            {
                "record_index": index,
                "campaign_mono_ns": index * 300_000_000,
                "channel": channel,
                "generation_index": generation_index,
                "payload": payload,
            }
            for index, (generation_index, channel, payload) in enumerate(entries)
        ]
        _journal_events(
            records,
            startup_digest,
            manifest_digest,
            campaign_id,
            3,
            generations,
            handovers,
        )

        with self.assertRaisesRegex(RawCampaignCorruption, "requested campaign"):
            _journal_events(
                records,
                startup_digest,
                manifest_digest,
                campaign_id,
                20,
                generations,
                handovers,
            )

        by_event = {
            str(record["payload"]["event"]): record  # type: ignore[index]
            for record in records
            if record["payload"]["event"]  # type: ignore[index]
            not in {"PROCESS_STARTED", "PROCESS_TERMINAL", "GENERATION_EXITED"}
        }
        starts = [
            record
            for record in records
            if record["payload"]["event"] == "PROCESS_STARTED"  # type: ignore[index]
        ]
        terminals = [
            record
            for record in records
            if record["payload"]["event"] == "PROCESS_TERMINAL"  # type: ignore[index]
        ]
        exits = [
            record
            for record in records
            if record["payload"]["event"] == "GENERATION_EXITED"  # type: ignore[index]
        ]
        gap_records = [
            by_event["CAMPAIGN_STARTED"],
            by_event["GENERATION_LAUNCHED"],
            starts[0],
            by_event["SERVER_SHUTDOWN_DURABLE"],
            terminals[0],
            exits[0],
            by_event["GENERATION_LAUNCHED_SERVER_SHUTDOWN"],
            starts[1],
            by_event["HANDOVER_PROOF_STARTED"],
            by_event["HANDOVER_PROVEN_AND_PROMOTED"],
            terminals[1],
            exits[1],
            by_event["CAMPAIGN_EVALUATION_PREPARED"],
            by_event["CAMPAIGN_COMMITTED"],
        ]
        gap_records = [dict(record) for record in gap_records]
        for index, record in enumerate(gap_records):
            record["record_index"] = index
            record["campaign_mono_ns"] = index * 1_000_000_000
        with self.assertRaisesRegex(RawCampaignCorruption, "PROCESS_TERMINAL"):
            _journal_events(
                gap_records,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        without_durable = [
            record
            for record in records
            if record["payload"].get("event") != "SERVER_SHUTDOWN_DURABLE"  # type: ignore[union-attr]
        ]
        for index, record in enumerate(without_durable):
            record["record_index"] = index
        with self.assertRaisesRegex(RawCampaignCorruption, "prior unused durable"):
            _journal_events(
                without_durable,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        fabricated_shutdown = deepcopy(records)
        shutdown_record = next(
            record
            for record in fabricated_shutdown
            if record["payload"].get("event") == "SERVER_SHUTDOWN_DURABLE"  # type: ignore[union-attr]
        )
        shutdown_payload = shutdown_record["payload"]
        assert isinstance(shutdown_payload, dict)
        shutdown_identity = shutdown_payload["shutdown"]
        assert isinstance(shutdown_identity, dict)
        shutdown_identity["last_record_sha256"] = "e" * 64
        with self.assertRaisesRegex(RawCampaignCorruption, "exact BNRAW record"):
            _journal_events(
                fabricated_shutdown,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        missing_event = deepcopy(records)
        missing_payload = missing_event[2]["payload"]
        assert isinstance(missing_payload, dict)
        missing_payload.pop("event")
        with self.assertRaisesRegex(RawCampaignCorruption, "lacks a string event"):
            _journal_events(
                missing_event,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        unknown_event = deepcopy(records)
        unknown_payload = unknown_event[2]["payload"]
        assert isinstance(unknown_payload, dict)
        unknown_payload["event"] = "UNDECLARED_CHILD_EVENT"
        with self.assertRaisesRegex(RawCampaignCorruption, "unknown or invalid"):
            _journal_events(
                unknown_event,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        wrong_schema = deepcopy(records)
        schema_payload = wrong_schema[2]["payload"]
        assert isinstance(schema_payload, dict)
        schema_payload["schema"] = "WrongProcessEventV1"
        with self.assertRaisesRegex(RawCampaignCorruption, "wrong child event schema"):
            _journal_events(
                wrong_schema,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        delayed_but_terminally_late = deepcopy(records)
        successor_start_index = next(
            index
            for index, record in enumerate(delayed_but_terminally_late)
            if record["generation_index"] == 1
            and record["payload"].get("event") == "PROCESS_STARTED"  # type: ignore[union-attr]
        )
        for offset, record in enumerate(
            delayed_but_terminally_late[successor_start_index:]
        ):
            record["campaign_mono_ns"] = 5_000_000_000 + offset * 100_000_000
        with self.assertRaisesRegex(RawCampaignCorruption, "coverage leaves a campaign gap"):
            _journal_events(
                delayed_but_terminally_late,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        falsely_nonactive = deepcopy(records)
        launch_record = next(
            record
            for record in falsely_nonactive
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
        )
        launch_record["generation_index"] = 0
        launch_record["channel"] = "SUPERVISOR"
        launch_record["payload"] = {
            "event": "SERVER_SHUTDOWN_IGNORED_NON_ACTIVE",
            "source_epoch": "depth-epoch-0",
        }
        with self.assertRaisesRegex(RawCampaignCorruption, "source/lifecycle"):
            _journal_events(
                falsely_nonactive,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        planned_generations = deepcopy(generations)
        planned_streams = planned_generations[0]["streams"]
        assert isinstance(planned_streams, list)
        planned_depth = planned_streams[0]
        assert isinstance(planned_depth, dict)
        planned_depth["server_shutdown_events"] = 0
        planned_generations[0]["_raw_server_shutdowns"] = []
        planned_records = [
            deepcopy(record)
            for record in records
            if record["payload"].get("event")  # type: ignore[union-attr]
            != "SERVER_SHUTDOWN_DURABLE"
        ]
        planned_launch_payload = next(
            record["payload"]
            for record in planned_records
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
        )
        assert isinstance(planned_launch_payload, dict)
        planned_launch_payload.clear()
        planned_launch_payload.update(
            {"event": "GENERATION_LAUNCHED", "duration_s": 2}
        )
        for index, record in enumerate(planned_records):
            record["record_index"] = index
            record["campaign_mono_ns"] = index * 300_000_000
        _journal_events(
            planned_records,
            startup_digest,
            manifest_digest,
            campaign_id,
            3,
            planned_generations,
            handovers,
        )
        ambiguous_planned_launch = deepcopy(planned_records)
        ambiguous_planned_payload = next(
            record["payload"]
            for record in ambiguous_planned_launch
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "GENERATION_LAUNCHED"
            and record["generation_index"] == 1
        )
        assert isinstance(ambiguous_planned_payload, dict)
        ambiguous_planned_payload["extra"] = True
        with self.assertRaises(RawCampaignCorruption):
            _journal_events(
                ambiguous_planned_launch,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                planned_generations,
                handovers,
            )

        ambiguous_launch = deepcopy(records)
        ambiguous_launch_payload = next(
            record["payload"]
            for record in ambiguous_launch
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
        )
        assert isinstance(ambiguous_launch_payload, dict)
        ambiguous_launch_payload["extra"] = True
        with self.assertRaises(RawCampaignCorruption):
            _journal_events(
                ambiguous_launch,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        ambiguous_handover = deepcopy(records)
        handover_payload = next(
            record["payload"]
            for record in ambiguous_handover
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "HANDOVER_PROOF_STARTED"
        )
        assert isinstance(handover_payload, dict)
        handover_payload["extra"] = True
        with self.assertRaises(RawCampaignCorruption):
            _journal_events(
                ambiguous_handover,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        ambiguous_promotion = deepcopy(records)
        promotion_payload = next(
            record["payload"]
            for record in ambiguous_promotion
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "HANDOVER_PROVEN_AND_PROMOTED"
        )
        assert isinstance(promotion_payload, dict)
        promotion_payload["extra"] = True
        with self.assertRaises(RawCampaignCorruption):
            _journal_events(
                ambiguous_promotion,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        absent_pending = deepcopy(records)
        launch_index = next(
            index
            for index, record in enumerate(absent_pending)
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
        )
        absent_pending[launch_index]["generation_index"] = 0
        absent_pending[launch_index]["channel"] = "SUPERVISOR"
        absent_pending[launch_index]["payload"] = {
            "event": "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
            "source_epoch": "depth-epoch-0",
        }
        absent_pending.insert(
            launch_index + 1,
            {
                "record_index": 0,
                "campaign_mono_ns": 0,
                "generation_index": 1,
                "channel": "CAMPAIGN",
                "payload": {"event": "GENERATION_LAUNCHED", "duration_s": 2},
            },
        )
        for index, record in enumerate(absent_pending):
            record["record_index"] = index
            record["campaign_mono_ns"] = index * 300_000_000
        with self.assertRaisesRegex(RawCampaignCorruption, "source/lifecycle"):
            _journal_events(
                absent_pending,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        pending_generations = deepcopy(generations)
        second_shutdown = {
            "stream": "depth",
            "connection_epoch": "depth-epoch-0",
            "segment_index": 0,
            "raw_file": "segment-000000.bnraw",
            "frame_index": 2,
            "receive_mono_ns": 2,
            "durable_record_count": 3,
            "durable_through_offset": 4,
            "last_record_sha256": "1" * 64,
        }
        raw_shutdowns = pending_generations[0]["_raw_server_shutdowns"]
        assert isinstance(raw_shutdowns, list)
        raw_shutdowns.append(second_shutdown)
        generation_streams = pending_generations[0]["streams"]
        assert isinstance(generation_streams, list)
        depth_stream = generation_streams[0]
        assert isinstance(depth_stream, dict)
        depth_stream["server_shutdown_events"] = 2
        valid_pending = deepcopy(records)
        pending_launch_index = next(
            index
            for index, record in enumerate(valid_pending)
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
        )
        valid_pending.insert(
            pending_launch_index + 1,
            {
                "record_index": 0,
                "campaign_mono_ns": 0,
                "generation_index": 0,
                "channel": "CHILD_STDOUT",
                "payload": {
                    "schema": "ServerShutdownDurableProcessEventV1",
                    "event": "SERVER_SHUTDOWN_DURABLE",
                    "session_id": "generation-0",
                    "shutdown": {
                        "schema": "DurableServerShutdownEventV1",
                        **second_shutdown,
                    },
                },
            },
        )
        valid_pending.insert(
            pending_launch_index + 2,
            {
                "record_index": 0,
                "campaign_mono_ns": 0,
                "generation_index": 0,
                "channel": "SUPERVISOR",
                "payload": {
                    "event": "SERVER_SHUTDOWN_CANDIDATE_ALREADY_PENDING",
                    "source_epoch": "depth-epoch-0",
                },
            },
        )
        for index, record in enumerate(valid_pending):
            record["record_index"] = index
            record["campaign_mono_ns"] = index * 300_000_000
        _journal_events(
            valid_pending,
            startup_digest,
            manifest_digest,
            campaign_id,
            3,
            pending_generations,
            handovers,
        )
        ambiguous_disposition = deepcopy(valid_pending)
        disposition_payload = ambiguous_disposition[pending_launch_index + 2][
            "payload"
        ]
        assert isinstance(disposition_payload, dict)
        disposition_payload["extra"] = True
        with self.assertRaises(RawCampaignCorruption):
            _journal_events(
                ambiguous_disposition,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                pending_generations,
                handovers,
            )

        premature_successor = deepcopy(records)
        initial_index = next(
            index
            for index, record in enumerate(premature_successor)
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "INITIAL_ACTIVE_REGISTERED"
        )
        successor_launch_index = next(
            index
            for index, record in enumerate(premature_successor)
            if record["payload"].get("event")  # type: ignore[union-attr]
            == "GENERATION_LAUNCHED_SERVER_SHUTDOWN"
        )
        for field in ("generation_index", "channel", "payload"):
            premature_successor[initial_index][field], premature_successor[
                successor_launch_index
            ][field] = (
                premature_successor[successor_launch_index][field],
                premature_successor[initial_index][field],
            )
        with self.assertRaises(RawCampaignCorruption):
            _journal_events(
                premature_successor,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        wrong_child_session = deepcopy(records)
        terminal_payload = next(
            record["payload"]
            for record in wrong_child_session
            if record["generation_index"] == 0
            and record["payload"].get("event") == "PROCESS_TERMINAL"  # type: ignore[union-attr]
        )
        assert isinstance(terminal_payload, dict)
        terminal_payload["session_id"] = "generation-1"
        with self.assertRaisesRegex(RawCampaignCorruption, "child session/lifecycle"):
            _journal_events(
                wrong_child_session,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        child_after_terminal = deepcopy(records)
        terminal_index = next(
            index
            for index, record in enumerate(child_after_terminal)
            if record["generation_index"] == 0
            and record["payload"].get("event") == "PROCESS_TERMINAL"  # type: ignore[union-attr]
        )
        child_after_terminal.insert(
            terminal_index + 1,
            {
                "record_index": 0,
                "campaign_mono_ns": 0,
                "generation_index": 0,
                "channel": "CHILD_STDOUT",
                "payload": {
                    "schema": "HeartbeatProcessEventV1",
                    "event": "HEARTBEAT_DURABLE",
                    "session_id": "generation-0",
                },
            },
        )
        for index, record in enumerate(child_after_terminal):
            record["record_index"] = index
            record["campaign_mono_ns"] = index * 300_000_000
        with self.assertRaisesRegex(RawCampaignCorruption, "child session/lifecycle"):
            _journal_events(
                child_after_terminal,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                generations,
                handovers,
            )

        reused_epoch_generations = deepcopy(generations)
        successor_streams = reused_epoch_generations[1]["streams"]
        assert isinstance(successor_streams, list)
        successor_depth = successor_streams[0]
        assert isinstance(successor_depth, dict)
        successor_depth["connection_epoch"] = "trade-epoch-0"
        with self.assertRaisesRegex(RawCampaignCorruption, "identity was reused"):
            _journal_events(
                records,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                reused_epoch_generations,
                handovers,
            )

        reused_session_generations = deepcopy(generations)
        reused_session_generations[1]["session_id"] = "generation-0"
        with self.assertRaisesRegex(RawCampaignCorruption, "identity was reused"):
            _journal_events(
                records,
                startup_digest,
                manifest_digest,
                campaign_id,
                3,
                reused_session_generations,
                handovers,
            )

    def test_successful_campaign_journal_rejects_child_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "campaign.journal.jsonl"
            record, _ = _journal_record(
                0,
                "0" * 64,
                0,
                "CHILD_STDERR",
                {"event": "diagnostic"},
                1_700_000_000_000_000_000,
            )
            path.write_bytes(record)
            with self.assertRaisesRegex(RawCampaignCorruption, "child stderr"):
                _scan_journal(path, 1)

    def test_valid_campaign_is_deterministic_raw_only_and_trade_ids_need_not_be_t_plus_one(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            first = verify_raw_campaign(campaign)
            second = verify_raw_campaign(campaign)
            self.assertEqual(first, second)
            self.assertEqual(first["status"], "VERIFIED")
            self.assertEqual(len(first["generations"]), 2)
            encoded = json.dumps(first)
            self.assertNotIn("imbalance", encoded)
            self.assertNotIn("canonical", encoded.lower())

    def test_exact_raw_server_shutdown_identity_integrates_without_changing_rust_evaluation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory), server_shutdown=True)
            report = verify_raw_campaign(campaign)
            self.assertEqual(report["status"], "VERIFIED")
            evaluation = json.loads(
                (campaign / "evaluations" / "generation-000-rust.json").read_text()
            )
            for stream in evaluation["streams"]:
                self.assertNotIn("server_shutdowns", stream)

    def test_cli_writes_report_outside_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            output = Path(directory) / "report.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(["verify-raw-campaign", str(campaign), "--output", str(output)]),
                    0,
                )
            self.assertEqual(json.loads(output.read_text())["status"], "VERIFIED")

    def test_cli_refuses_to_pollute_exact_campaign_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                status = main(
                    [
                        "verify-raw-campaign",
                        str(campaign),
                        "--output",
                        str(campaign / "report.json"),
                    ]
                )
            self.assertEqual(status, 2)

    def test_journal_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            journal = campaign / "campaign-events.jsonl"
            data = journal.read_bytes().replace(b"GENERATION_EXITED", b"GENERATION_FAILED", 1)
            journal.write_bytes(data)
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)

    def test_missing_campaign_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            journal = campaign / "campaign-events.jsonl"
            records = journal.read_bytes().splitlines(keepends=True)
            journal.write_bytes(b"".join(records[:-1]))
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)

    def test_reordered_campaign_journal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            journal = campaign / "campaign-events.jsonl"
            records = journal.read_bytes().splitlines(keepends=True)
            records[2], records[3] = records[3], records[2]
            journal.write_bytes(b"".join(records))
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)

    def test_manifest_rewrite_without_new_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            path = campaign / "campaign.json"
            manifest = json.loads(path.read_text())
            manifest["finished_wall_ns"] += 1
            path.write_bytes(_pretty(manifest))
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)

    def test_evaluation_omission_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            (campaign / "evaluations" / "generation-001-rust.json").unlink()
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)

    def test_generation_reordering_is_rejected_even_if_manifest_is_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            path = campaign / "campaign.json"
            manifest = json.loads(path.read_text())
            manifest["generations"].reverse()
            path.write_bytes(_pretty(manifest))
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)

    def test_handover_proof_autodigest_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            path = campaign / "handovers" / "handover-000-to-001" / "handover.json"
            proof = json.loads(path.read_text())
            proof["trade"]["next_shared_trade_id"] = 11
            path.write_bytes(_pretty(proof))
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)

    def test_self_consistent_but_fabricated_handover_is_replayed_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            path = campaign / "handovers" / "handover-000-to-001" / "handover.json"
            proof = json.loads(path.read_text())
            proof["depth"]["boundary_state_sha256"] = "c" * 64
            proof["proof_sha256"] = _proof_digest(proof)
            path.write_bytes(_pretty(proof))
            with self.assertRaisesRegex(
                RawCampaignCorruption,
                "independent terminal raw A/B replay",
            ):
                verify_raw_campaign(campaign)

    def test_missing_handover_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            path = campaign / "campaign.json"
            manifest = json.loads(path.read_text())
            manifest["handovers"] = []
            path.write_bytes(_pretty(manifest))
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)

    def test_unknown_inventory_entry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            campaign = _build_campaign(Path(directory))
            (campaign / "unexpected.txt").write_text("contamination")
            with self.assertRaises(RawCampaignCorruption):
                verify_raw_campaign(campaign)


if __name__ == "__main__":
    unittest.main()
