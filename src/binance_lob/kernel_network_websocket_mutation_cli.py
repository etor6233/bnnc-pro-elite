"""Controlled fail-closed mutations for a real WebSocket/ETW canary."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Callable

from .kernel_network_websocket import (
    KernelNetworkWebSocketCorruption,
    verify_kernel_network_websocket,
)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _json_line_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} is not a JSON object")
    return value


def _write(path: Path, value: object) -> None:
    path.write_bytes(_json_bytes(value))


def _relocate(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination)
    stdout_path = destination / "controller.stdout.jsonl"
    records = [json.loads(line) for line in stdout_path.read_text(encoding="utf-8-sig").splitlines()]
    for record in records:
        record["etl_path"] = str((destination / "kernel-network.etl").resolve())
        if record.get("schema") == "KernelNetworkTraceReadyV1":
            record["stop_file"] = str((destination / "stop.request").resolve())
    stdout_path.write_bytes(b"".join(_json_line_bytes(record) for record in records))
    report_path = destination / "websocket-canary.json"
    report = _load(report_path)
    report["controller_records"] = records
    _write(report_path, report)


def _mutate_etl(root: Path) -> None:
    path = root / "kernel-network.etl"
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(data)


def _mutate_pid(root: Path) -> None:
    path = root / "websocket-canary.json"
    report = _load(path)
    report["collector_pid"] = int(report["collector_pid"]) + 1
    _write(path, report)


def _mutate_training(root: Path) -> None:
    path = root / "websocket-canary.json"
    report = _load(path)
    report["training_eligible"] = True
    _write(path, report)


def _mutate_dns(root: Path) -> None:
    path = root / "websocket-canary.json"
    report = _load(path)
    report["dns_addresses"] = ["192.0.2.1"]
    _write(path, report)


def _mutate_loss(root: Path) -> None:
    stdout_path = root / "controller.stdout.jsonl"
    records = [json.loads(line) for line in stdout_path.read_text(encoding="utf-8-sig").splitlines()]
    records[1]["statistics"]["events_lost"] = 1
    stdout_path.write_bytes(b"".join(_json_line_bytes(record) for record in records))
    report_path = root / "websocket-canary.json"
    report = _load(report_path)
    report["controller_records"] = records
    _write(report_path, report)


def _mutate_rust_verification(root: Path) -> None:
    verification_path = root / "generation-verification.json"
    verification = _load(verification_path)
    verification["status"] = "FAIL"
    data = _json_bytes(verification)
    verification_path.write_bytes(data)
    report_path = root / "websocket-canary.json"
    report = _load(report_path)
    report["generation_verification_bytes"] = len(data)
    report["generation_verification_sha256"] = sha256(data).hexdigest()
    _write(report_path, report)


def _mutate_extra_file(root: Path) -> None:
    (root / "unowned.bin").write_bytes(b"forbidden")


def _mutate_collector_stdout(root: Path) -> None:
    report_path = root / "websocket-canary.json"
    report = _load(report_path)
    forged = (str(Path(str(report["generation_directory"])).parent.resolve()) + "\n").encode()
    (root / "collector.stdout.jsonl").write_bytes(forged)
    report["collector_stdout_bytes"] = len(forged)
    report["collector_stdout_sha256"] = sha256(forged).hexdigest()
    _write(report_path, report)


def _mutate_false_pass(root: Path) -> None:
    path = root / "websocket-canary.json"
    report = _load(path)
    report["status"] = "PASS"
    _write(path, report)


MUTATIONS: tuple[tuple[str, Callable[[Path], None]], ...] = (
    ("ONE_BYTE_ETL_CORRUPTION", _mutate_etl),
    ("COLLECTOR_PID_FORGERY", _mutate_pid),
    ("TRAINING_ELIGIBILITY_FORGERY", _mutate_training),
    ("DNS_ENDPOINT_FORGERY", _mutate_dns),
    ("ETW_LOSS_FORGERY", _mutate_loss),
    ("RUST_VERIFICATION_FORGERY_WITH_REHASH", _mutate_rust_verification),
    ("UNOWNED_EXTRA_FILE", _mutate_extra_file),
    ("COLLECTOR_STDOUT_FORGERY_WITH_REHASH", _mutate_collector_stdout),
    ("PRODUCER_FALSE_PASS", _mutate_false_pass),
)


def _write_synced_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    baseline = verify_kernel_network_websocket(source)
    results: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="binance-ws-mutants-") as temporary:
        temporary_root = Path(temporary)
        baseline_root = temporary_root / "baseline"
        _relocate(source, baseline_root)
        if verify_kernel_network_websocket(baseline_root).get("status") != "PASS":
            raise RuntimeError("relocated mutation baseline did not pass")
        shutil.rmtree(baseline_root)
        for index, (name, mutation) in enumerate(MUTATIONS):
            mutant = temporary_root / f"mutant-{index:02}"
            _relocate(source, mutant)
            mutation(mutant)
            try:
                verify_kernel_network_websocket(mutant)
            except (OSError, ValueError, KernelNetworkWebSocketCorruption) as error:
                results.append({"name": name, "status": "REJECTED", "reason": str(error)})
            else:
                raise RuntimeError(f"unsafe verifier accepted mutant {name}")
            shutil.rmtree(mutant)
    report = {
        "schema": "KernelNetworkWebSocketMutationGateV1",
        "status": "PASS",
        "source_run_id": baseline["run_id"],
        "source_root": str(source),
        "source_report_sha256": sha256((source / "websocket-canary.json").read_bytes()).hexdigest(),
        "baseline_status": "PASS",
        "mutation_count": len(results),
        "accepted_mutations": 0,
        "mutations": results,
    }
    payload = _json_bytes(report)
    _write_synced_new(args.output.resolve(strict=False), payload)
    print(payload.decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
