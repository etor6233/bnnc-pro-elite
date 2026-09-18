"""Independent verifier for a sealed Windows PktMon qualification trace."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any


MIB = 1024 * 1024
MAX_JSON_BYTES = MIB
EXPECTED_FILES = {
    "network-trace-control.json",
    "network-trace-start.json",
    "network-trace.etl",
    "network-trace-seal.json",
}

_CONTROL_KEYS_V1 = (
    "schema", "run_id", "status", "requested_utc",
    "requested_qpc_timestamp", "qpc_frequency", "owner_pid", "provider",
    "capture_scope", "raw_packet_flag", "log_mode", "maximum_file_mib",
    "etl_file", "pktmon_executable", "pktmon_executable_sha256", "arguments",
)
_CONTROL_KEYS_V2 = (
    "schema", "run_id", "status", "requested_utc",
    "requested_qpc_timestamp", "qpc_frequency", "owner_pid", "event_providers",
    "capture_scope", "raw_packet_flag", "log_mode", "maximum_file_mib",
    "etl_file", "pktmon_executable", "pktmon_executable_sha256", "arguments",
)
_CONTROL_KEYS_V4 = (
    "schema", "run_id", "status", "requested_utc",
    "requested_qpc_timestamp", "qpc_frequency", "owner_pid", "event_providers",
    "winsock_afd_profile", "winsock_afd_keywords", "winsock_afd_level",
    "capture_scope", "raw_packet_flag", "log_mode", "maximum_file_mib",
    "etl_file", "pktmon_executable", "pktmon_executable_sha256", "arguments",
)
_CONTROL_KEYS_V5 = (
    "schema", "run_id", "status", "requested_utc",
    "requested_qpc_timestamp", "qpc_frequency", "owner_pid", "event_providers",
    "winsock_afd_profile", "winsock_afd_keywords", "winsock_afd_level",
    "kernel_network_enabled", "kernel_network_keywords", "kernel_network_level",
    "capture_scope", "raw_packet_flag", "log_mode", "maximum_file_mib",
    "etl_file", "pktmon_executable", "pktmon_executable_sha256", "arguments",
)
_START_KEYS = (
    "schema", "run_id", "status", "observed_utc", "observed_qpc_timestamp",
    "control_file", "control_sha256", "pktmon_exit_code", "pktmon_output",
    "pktmon_output_bytes", "status_exit_code", "status_output",
    "status_output_bytes",
)
_SEAL_KEYS = (
    "schema", "run_id", "status", "stopped_utc", "control_file",
    "control_sha256", "start_file", "start_sha256", "etl_file", "etl_bytes",
    "etl_sha256", "pktmon_executable_sha256", "pktmon_exit_code",
    "pktmon_output", "pktmon_output_bytes", "pre_stop_status_exit_code",
    "pre_stop_status_output", "pre_stop_status_output_bytes",
    "inference_boundary",
)


class NetworkTraceCorruption(ValueError):
    """Raised when a network trace artifact violates its exact contract."""


def _fail(message: str) -> None:
    raise NetworkTraceCorruption(message)


def _regular_directory(path: Path) -> Path:
    candidate = path.absolute()
    current = Path(candidate.anchor)
    for component in candidate.parts[1:]:
        current /= component
        try:
            status = os.lstat(current)
        except OSError as error:
            _fail(f"cannot stat network trace path component {current}: {error}")
        if getattr(status, "st_file_attributes", 0) & 0x400 or current.is_symlink():
            _fail("network trace path contains a reparse point")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        _fail("network trace root is not a directory")
    return resolved


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{label} is not an object")
    return value


def _keys(value: dict[str, Any], expected: tuple[str, ...], label: str) -> None:
    if tuple(value) != expected:
        _fail(f"{label} property set/order is invalid")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        _fail(f"{label} is not a non-empty string")
    return value


def _digest(value: Any, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(ch not in "0123456789abcdef" for ch in result):
        _fail(f"{label} is not a lowercase SHA-256")
    return result


def _uint(value: Any, label: str, *, minimum: int = 0, maximum: int = (1 << 64) - 1) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        _fail(f"{label} is outside its unsigned integer contract")
    return value


def _zero(value: Any, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value != 0:
        _fail(f"{label} is not zero")


def _lines(value: Any, reported_bytes: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 4096 or any(not isinstance(line, str) for line in value):
        _fail(f"{label} is not a bounded string array")
    joined = "\n".join(value).encode("utf-8")
    if _uint(reported_bytes, f"{label} reported bytes", maximum=MIB) != len(joined):
        _fail(f"{label} byte count differs from its UTF-8 content")
    return value


def _regular_bytes(path: Path, maximum: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        _fail(f"{label} is not a regular non-link file")
    data = path.read_bytes()
    if not data or len(data) > maximum:
        _fail(f"{label} is empty or oversized")
    return data


def _json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"{label} is not strict UTF-8 JSON: {error}")
    return _object(value, label)


def verify_network_trace(root: Path) -> dict[str, Any]:
    """Verify a completed trace without trusting its producer or manifest."""

    root = _regular_directory(root)
    names = {entry.name for entry in root.iterdir()}
    if names != EXPECTED_FILES:
        _fail("network trace inventory is not exact")

    control_path = root / "network-trace-control.json"
    start_path = root / "network-trace-start.json"
    etl_path = root / "network-trace.etl"
    seal_path = root / "network-trace-seal.json"
    control_bytes = _regular_bytes(control_path, MAX_JSON_BYTES, "control")
    start_bytes = _regular_bytes(start_path, MAX_JSON_BYTES, "start")
    seal_bytes = _regular_bytes(seal_path, MAX_JSON_BYTES, "seal")
    control = _json(control_bytes, "control")
    start = _json(start_bytes, "start")
    seal = _json(seal_bytes, "seal")
    _keys(start, _START_KEYS, "start")
    _keys(seal, _SEAL_KEYS, "seal")

    schema = control.get("schema")
    afd_profile: str | None = None
    afd_keywords: str | None = None
    afd_level: int | None = None
    kernel_network_enabled = False
    kernel_network_keywords = ""
    kernel_network_level = 0
    if schema == "RawQualificationNetworkTraceControlV1":
        version = 1
        _keys(control, _CONTROL_KEYS_V1, "control")
        expected_start_schema = "RawQualificationNetworkTraceStartV1"
        expected_seal_schema = "RawQualificationNetworkTraceSealV1"
        expected_providers = ["Microsoft-Windows-TCPIP"]
        expected_scope = "NIC_DROP_METADATA_ONLY"
    elif schema == "RawQualificationNetworkTraceControlV2":
        version = 2
        _keys(control, _CONTROL_KEYS_V2, "control")
        expected_start_schema = "RawQualificationNetworkTraceStartV2"
        expected_seal_schema = "RawQualificationNetworkTraceSealV2"
        expected_providers = [
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-DNS-Client",
            "Microsoft-Windows-NDIS",
        ]
        expected_scope = "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_ETW"
    elif schema == "RawQualificationNetworkTraceControlV3":
        version = 3
        _keys(control, _CONTROL_KEYS_V2, "control")
        expected_start_schema = "RawQualificationNetworkTraceStartV3"
        expected_seal_schema = "RawQualificationNetworkTraceSealV3"
        expected_providers = [
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-DNS-Client",
            "Microsoft-Windows-NDIS",
            "Microsoft-Windows-Winsock-AFD",
        ]
        expected_scope = "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_ERROR_ETW"
        afd_profile = "ErrorOnly"
        afd_keywords = "0x800000000000000C"
        afd_level = 2
    elif schema == "RawQualificationNetworkTraceControlV4":
        version = 4
        _keys(control, _CONTROL_KEYS_V4, "control")
        expected_start_schema = "RawQualificationNetworkTraceStartV4"
        expected_seal_schema = "RawQualificationNetworkTraceSealV4"
        expected_providers = [
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-DNS-Client",
            "Microsoft-Windows-NDIS",
            "Microsoft-Windows-Winsock-AFD",
        ]
        afd_profile = control["winsock_afd_profile"]
        if afd_profile not in ("ErrorOnly", "DiagnosticInfo"):
            _fail("Winsock-AFD profile is unsupported")
        afd_keywords = control["winsock_afd_keywords"]
        afd_level = control["winsock_afd_level"]
        expected_level = 2 if afd_profile == "ErrorOnly" else 4
        if afd_keywords != "0x800000000000000C" or afd_level != expected_level:
            _fail("Winsock-AFD policy differs from its named profile")
        expected_scope = (
            "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_ERROR_ETW"
            if afd_profile == "ErrorOnly"
            else "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_DIAGNOSTIC_ETW"
        )
    elif schema == "RawQualificationNetworkTraceControlV5":
        version = 5
        _keys(control, _CONTROL_KEYS_V5, "control")
        expected_start_schema = "RawQualificationNetworkTraceStartV5"
        expected_seal_schema = "RawQualificationNetworkTraceSealV5"
        afd_profile = control["winsock_afd_profile"]
        if afd_profile not in ("ErrorOnly", "DiagnosticInfo"):
            _fail("Winsock-AFD profile is unsupported")
        afd_keywords = control["winsock_afd_keywords"]
        afd_level = control["winsock_afd_level"]
        expected_level = 2 if afd_profile == "ErrorOnly" else 4
        if afd_keywords != "0x800000000000000C" or afd_level != expected_level:
            _fail("Winsock-AFD policy differs from its named profile")
        kernel_network_enabled = control["kernel_network_enabled"]
        if not isinstance(kernel_network_enabled, bool):
            _fail("Kernel-Network enabled state is not boolean")
        expected_kernel_enabled = afd_profile == "DiagnosticInfo"
        if kernel_network_enabled != expected_kernel_enabled:
            _fail("Kernel-Network enablement differs from the named profile")
        kernel_network_keywords = control["kernel_network_keywords"]
        kernel_network_level = control["kernel_network_level"]
        if kernel_network_enabled:
            if kernel_network_keywords != "0x8000000000000030" or kernel_network_level != 4:
                _fail("Kernel-Network diagnostic policy is invalid")
        elif kernel_network_keywords != "" or kernel_network_level != 0:
            _fail("disabled Kernel-Network policy is not empty")
        expected_providers = [
            "Microsoft-Windows-TCPIP",
            "Microsoft-Windows-DNS-Client",
            "Microsoft-Windows-NDIS",
            "Microsoft-Windows-Winsock-AFD",
        ]
        if kernel_network_enabled:
            expected_providers.append("Microsoft-Windows-Kernel-Network")
        expected_scope = (
            "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_ERROR_ETW"
            if afd_profile == "ErrorOnly"
            else "NIC_DROP_METADATA_PLUS_TCPIP_DNS_NDIS_WINSOCK_AFD_AND_KERNEL_NETWORK_DIAGNOSTIC_ETW"
        )
    else:
        _fail("network trace control schema is unsupported")

    run_id = _text(control["run_id"], "run id")
    if len(run_id) > 128 or not run_id[0].isalnum() or any(not (ch.isalnum() or ch == "-") for ch in run_id):
        _fail("run id violates its lexical contract")
    if (
        control["status"] != "START_ATTEMPTED"
        or start["schema"] != expected_start_schema
        or start["status"] != "STARTED"
        or seal["schema"] != expected_seal_schema
        or seal["status"] != "SEALED"
        or start["run_id"] != run_id
        or seal["run_id"] != run_id
    ):
        _fail("network trace identity/lifecycle is invalid")

    for value, label in (
        (control["requested_utc"], "requested utc"),
        (start["observed_utc"], "observed utc"),
        (seal["stopped_utc"], "stopped utc"),
    ):
        _text(value, label)
    requested_qpc = _uint(control["requested_qpc_timestamp"], "requested qpc")
    observed_qpc = _uint(start["observed_qpc_timestamp"], "observed qpc")
    if observed_qpc < requested_qpc:
        _fail("start observation precedes its request")
    _uint(control["qpc_frequency"], "qpc frequency", minimum=1)
    _uint(control["owner_pid"], "owner pid", minimum=1, maximum=(1 << 32) - 1)
    maximum_mib = _uint(control["maximum_file_mib"], "maximum file MiB", minimum=64, maximum=2048)

    providers = (
        [control["provider"]]
        if version == 1
        else control["event_providers"]
    )
    if (
        not isinstance(providers, list)
        or providers != expected_providers
        or control["capture_scope"] != expected_scope
        or control["raw_packet_flag"] != "DISABLED_FLAGS_0x00F"
        or control["log_mode"] != "CIRCULAR"
        or control["etl_file"] != "network-trace.etl"
    ):
        _fail("trace collection policy differs from its bounded contract")
    pktmon_path = _text(control["pktmon_executable"], "PktMon executable")
    pktmon_digest = _digest(control["pktmon_executable_sha256"], "PktMon digest")

    expected_arguments = [
        "start", "--capture", "--comp", "nics", "--type", "drop", "--flags", "0x00F",
        "--trace",
    ]
    for provider in expected_providers:
        expected_arguments.extend(["--provider", provider])
        if version >= 3 and provider == "Microsoft-Windows-Winsock-AFD":
            expected_arguments.extend([
                "--keywords", afd_keywords, "--level", str(afd_level),
            ])
        elif version == 5 and provider == "Microsoft-Windows-Kernel-Network":
            expected_arguments.extend([
                "--keywords", kernel_network_keywords,
                "--level", str(kernel_network_level),
            ])
    expected_arguments.extend([
        "--file-name", str(etl_path), "--file-size", str(maximum_mib),
        "--log-mode", "circular",
    ])
    if control["arguments"] != expected_arguments:
        _fail("PktMon arguments differ from the exact bounded command")

    control_digest = sha256(control_bytes).hexdigest()
    if (
        start["control_file"] != "network-trace-control.json"
        or _digest(start["control_sha256"], "start control digest") != control_digest
    ):
        _fail("start is not bound to the exact control bytes")
    _zero(start["pktmon_exit_code"], "start exit code")
    _lines(start["pktmon_output"], start["pktmon_output_bytes"], "start output")
    _zero(start["status_exit_code"], "initial status exit code")
    initial_status_lines = _lines(
        start["status_output"], start["status_output_bytes"], "initial status output"
    )
    if version >= 2:
        initial_status_text = "\n".join(initial_status_lines)
        if any(provider not in initial_status_text for provider in expected_providers):
            _fail("initial PktMon status does not enumerate every required provider")

    start_digest = sha256(start_bytes).hexdigest()
    if (
        seal["control_file"] != "network-trace-control.json"
        or _digest(seal["control_sha256"], "seal control digest") != control_digest
        or seal["start_file"] != "network-trace-start.json"
        or _digest(seal["start_sha256"], "seal start digest") != start_digest
        or seal["etl_file"] != "network-trace.etl"
        or _digest(seal["pktmon_executable_sha256"], "seal PktMon digest") != pktmon_digest
    ):
        _fail("seal is not bound to its exact control/start identity")
    _text(pktmon_path, "PktMon executable")
    _zero(seal["pktmon_exit_code"], "stop exit code")
    _lines(seal["pktmon_output"], seal["pktmon_output_bytes"], "stop output")
    _zero(seal["pre_stop_status_exit_code"], "pre-stop status exit code")
    pre_stop_status_lines = _lines(
        seal["pre_stop_status_output"],
        seal["pre_stop_status_output_bytes"],
        "pre-stop status output",
    )
    if version >= 2:
        pre_stop_status_text = "\n".join(pre_stop_status_lines)
        if any(provider not in pre_stop_status_text for provider in expected_providers):
            _fail("pre-stop PktMon status does not enumerate every required provider")
    _text(seal["inference_boundary"], "inference boundary")

    if etl_path.is_symlink() or not etl_path.is_file():
        _fail("ETL is not a regular non-link file")
    etl_bytes = etl_path.read_bytes()
    etl_size = _uint(seal["etl_bytes"], "ETL bytes", minimum=1)
    if len(etl_bytes) != etl_size or etl_size > maximum_mib * MIB + 16 * MIB:
        _fail("ETL size differs from its seal or bounded allowance")
    etl_digest = sha256(etl_bytes).hexdigest()
    if _digest(seal["etl_sha256"], "ETL digest") != etl_digest:
        _fail("ETL digest differs from its sealed bytes")

    return {
        "schema": f"RawQualificationNetworkTraceVerificationV{max(2, version)}",
        "status": "PASS",
        "run_id": run_id,
        "root": str(root),
        "control_sha256": control_digest,
        "start_sha256": start_digest,
        "seal_sha256": sha256(seal_bytes).hexdigest(),
        "etl_bytes": etl_size,
        "etl_sha256": etl_digest,
        "pktmon_executable": pktmon_path,
        "pktmon_executable_sha256": pktmon_digest,
        "capture_scope": control["capture_scope"],
        "event_providers": providers,
        "raw_packet_payload_capture": False,
        "attribution_scope": {
            1: "LOCAL_WINDOWS_KERNEL_NIC_AND_TCPIP_BOUNDARIES_ONLY",
            2: "LOCAL_WINDOWS_KERNEL_NIC_TCPIP_DNS_AND_NDIS_BOUNDARIES_ONLY",
            3: "LOCAL_WINDOWS_KERNEL_NIC_TCPIP_DNS_NDIS_AND_WINSOCK_AFD_ERROR_BOUNDARIES_ONLY",
            4: (
                "LOCAL_WINDOWS_KERNEL_NIC_TCPIP_DNS_NDIS_AND_WINSOCK_AFD_ERROR_BOUNDARIES_ONLY"
                if afd_profile == "ErrorOnly"
                else "LOCAL_WINDOWS_KERNEL_NIC_TCPIP_DNS_NDIS_AND_WINSOCK_AFD_DIAGNOSTIC_BOUNDARIES_ONLY"
            ),
            5: (
                "LOCAL_WINDOWS_KERNEL_NIC_TCPIP_DNS_NDIS_AND_WINSOCK_AFD_ERROR_BOUNDARIES_ONLY"
                if afd_profile == "ErrorOnly"
                else "LOCAL_WINDOWS_KERNEL_NIC_TCPIP_DNS_NDIS_WINSOCK_AFD_AND_KERNEL_NETWORK_DIAGNOSTIC_BOUNDARIES_ONLY"
            ),
        }[version],
    }
