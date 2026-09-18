"""CLI for a create-only cross-plane network incident bundle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .network_incident import NetworkIncidentError, build_network_incident
from .network_trace import NetworkTraceCorruption
from .network_witness import NetworkWitnessCorruption


def _write_new(path: Path, data: bytes) -> None:
    path = path.absolute()
    path.parent.resolve(strict=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generation", action="append", required=True, type=Path)
    parser.add_argument("--transport-diagnose", required=True, type=Path)
    parser.add_argument("--incident-wall-ns", required=True, type=int)
    parser.add_argument("--witness-root", type=Path)
    parser.add_argument("--trace-root", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        report = build_network_incident(
            generation_roots=arguments.generation,
            transport_executable=arguments.transport_diagnose,
            incident_wall_ns=arguments.incident_wall_ns,
            witness_root=arguments.witness_root,
            trace_root=arguments.trace_root,
        )
        data = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
        _write_new(arguments.output, data)
    except (OSError, NetworkIncidentError, NetworkTraceCorruption, NetworkWitnessCorruption) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(str(arguments.output.absolute()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

