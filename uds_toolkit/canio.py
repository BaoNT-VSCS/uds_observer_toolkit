from __future__ import annotations

import sys
from typing import Any

from .config import CanConfig


def import_python_can() -> Any:
    try:
        import can  # type: ignore
        return can
    except ImportError as exc:
        print("Missing dependency: python-can. Install with: pip install python-can", file=sys.stderr)
        raise SystemExit(2) from exc


def open_bus(can_cfg: CanConfig) -> tuple[Any, Any]:
    can_mod = import_python_can()
    kwargs: dict[str, Any] = {
        "channel": can_cfg.channel,
        "interface": can_cfg.interface,
        "receive_own_messages": can_cfg.receive_own_messages,
    }
    if can_cfg.bitrate is not None:
        kwargs["bitrate"] = can_cfg.bitrate
    try:
        bus = can_mod.interface.Bus(**kwargs)
    except TypeError:
        kwargs["bustype"] = kwargs.pop("interface")
        bus = can_mod.interface.Bus(**kwargs)
    return can_mod, bus
