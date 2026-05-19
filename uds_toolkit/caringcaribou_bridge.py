from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .config import CanConfig, TargetConfig
from .utils import can_id_hx, parse_byte, parse_can_id, parse_int_range


CARINGCARIBOU_TYPES = {"arb_id_fuzzer", "service_fuzzer", "subservice_fuzzer"}


@dataclass(frozen=True)
class CaringCaribouCommand:
    argv: list[str]
    description: str


def wants_caringcaribou(testcase: Mapping[str, Any]) -> bool:
    if str(testcase.get("type") or "") not in CARINGCARIBOU_TYPES:
        return False
    engine = str(testcase.get("engine", testcase.get("fuzz_engine", "caringcaribou")) or "").strip().lower()
    return engine in {"", "caringcaribou", "caring-caribou", "caribou", "cc"}


def resolve_caringcaribou_command(testcase: Mapping[str, Any] | None = None) -> list[str] | None:
    explicit = str((testcase or {}).get("caringcaribou_cmd") or os.environ.get("CARINGCARIBOU_CMD") or "").strip()
    if explicit:
        return shlex.split(explicit)
    for name in ("caringcaribou", "cc.py"):
        path = shutil.which(name)
        if path:
            return [path]
    try:
        import caringcaribou  # noqa: F401
    except Exception:
        return None
    return [sys.executable, "-m", "caringcaribou.caringcaribou"]


def build_caringcaribou_command(testcase: Mapping[str, Any], target: TargetConfig, can_cfg: CanConfig) -> CaringCaribouCommand:
    base = resolve_caringcaribou_command(testcase)
    if not base:
        raise FileNotFoundError(
            "CaringCaribou command not found. Install it or set CARINGCARIBOU_CMD/caringcaribou_cmd "
            "(examples: caringcaribou, cc.py, or python3 -m caringcaribou.caringcaribou)."
        )

    case_type = str(testcase.get("type") or "")
    timeout = float(testcase.get("per_id_timeout", testcase.get("timeout", 0.2)) or 0.2)
    argv = [*base, "uds"]
    description = ""

    if case_type == "arb_id_fuzzer":
        extended = bool(testcase.get("extended_id", target.extended_id if target else can_cfg.extended_id))
        max_items = int(testcase.get("max_items", 128) or 128)
        ids = parse_int_range(
            testcase.get("txid_range", "0x700-0x7FF"),
            item_parser=lambda item: parse_can_id(item, extended=extended),
            max_items=max_items,
        )
        if not ids:
            raise ValueError("arb_id_fuzzer requires a non-empty txid_range")
        argv += ["discovery", "-min", can_id_hx(min(ids)), "-max", can_id_hx(max(ids)), "-t", f"{timeout:g}"]
        delay = float(testcase.get("delay", 0) or 0)
        if delay > 0:
            argv += ["-d", f"{delay:g}"]
        blacklist = int(testcase.get("autoblacklist_seconds", 0) or 0)
        if blacklist > 0:
            argv += ["-ab", str(blacklist)]
        description = f"UDS discovery {can_id_hx(min(ids))}..{can_id_hx(max(ids))}"

    elif case_type == "service_fuzzer":
        argv += ["services", can_id_hx(target.txid), can_id_hx(target.rxid), "-t", f"{timeout:g}"]
        description = f"UDS service discovery {can_id_hx(target.txid)}->{can_id_hx(target.rxid)}"

    elif case_type == "subservice_fuzzer":
        dtype = _diagnostic_session_type(testcase, target)
        stype = parse_byte(testcase.get("service", 0x10))
        argv += ["subservices", f"0x{dtype:02X}", f"0x{stype:02X}", can_id_hx(target.txid), can_id_hx(target.rxid), "-t", f"{timeout:g}"]
        description = f"UDS subservice discovery service=0x{stype:02X} session=0x{dtype:02X}"

    else:
        raise ValueError(f"CaringCaribou engine does not support testcase type {case_type!r}")

    return CaringCaribouCommand(argv=argv, description=description)


def run_caringcaribou(
    command: CaringCaribouCommand,
    *,
    cwd: str | None = None,
    line_callback: Callable[[str], None] | None = None,
) -> int:
    proc = subprocess.Popen(
        command.argv,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        if line_callback:
            line_callback(line.rstrip("\n"))
    return int(proc.wait())


def _diagnostic_session_type(testcase: Mapping[str, Any], target: TargetConfig) -> int:
    flow = testcase.get("session_flow", target.session_flow)
    if isinstance(flow, Sequence) and not isinstance(flow, (str, bytes, bytearray)) and flow:
        return parse_byte(flow[-1])
    if flow not in (None, ""):
        parts = str(flow).replace(",", " ").split()
        if parts:
            return parse_byte(parts[-1])
    return 0x03
