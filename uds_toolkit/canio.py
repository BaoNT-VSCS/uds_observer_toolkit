from __future__ import annotations

import platform
import subprocess
import sys
from typing import Any

from .config import CanConfig, ConfigError


def import_python_can() -> Any:
    try:
        import can  # type: ignore
        return can
    except ImportError as exc:
        print("Missing dependency: python-can. Install with: pip install python-can", file=sys.stderr)
        raise SystemExit(2) from exc


def open_bus(can_cfg: CanConfig) -> tuple[Any, Any]:
    preflight_socketcan(can_cfg)
    can_mod = import_python_can()
    kwargs: dict[str, Any] = {
        "channel": can_cfg.channel,
        "interface": can_cfg.interface,
        "receive_own_messages": can_cfg.receive_own_messages,
    }
    if can_cfg.bitrate is not None:
        kwargs["bitrate"] = can_cfg.bitrate
    try:
        try:
            bus = can_mod.interface.Bus(**kwargs)
        except TypeError:
            kwargs["bustype"] = kwargs.pop("interface")
            bus = can_mod.interface.Bus(**kwargs)
    except Exception as exc:
        raise ConfigError(
            f"failed to open CAN interface {can_cfg.interface}:{can_cfg.channel}: {exc}. "
            f"Check wiring/bitrate and run: bash can_config.sh {can_cfg.channel}"
        ) from exc
    return can_mod, bus


def preflight_socketcan(can_cfg: CanConfig) -> None:
    if platform.system().lower() != "linux":
        return
    if str(can_cfg.interface).lower() not in {"socketcan", "socketcan_native"}:
        return
    try:
        result = subprocess.run(
            ["ip", "-details", "link", "show", can_cfg.channel],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ConfigError("socketcan requires the Linux 'ip' command from iproute2") from exc
    except subprocess.TimeoutExpired as exc:
        raise ConfigError(f"timed out checking CAN interface {can_cfg.channel}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise ConfigError(
            f"CAN channel '{can_cfg.channel}' was not found. {detail} "
            f"Connect the adapter and run: bash can_config.sh {can_cfg.channel}"
        )
    first_line = (result.stdout or "").splitlines()[0] if result.stdout else ""
    flags = first_line.split("<", 1)[1].split(">", 1)[0].split(",") if "<" in first_line and ">" in first_line else []
    if "UP" not in flags:
        raise ConfigError(
            f"CAN channel '{can_cfg.channel}' is not UP. Run: bash can_config.sh {can_cfg.channel}"
        )
