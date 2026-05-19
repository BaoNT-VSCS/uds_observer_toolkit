from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

import yaml

from .utils import parse_byte, parse_can_id, parse_hex_int


class ConfigError(ValueError):
    pass


def deep_merge(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    """Merge YAML configs.

    Mapping values are merged recursively. The `testcases` list is concatenated
    instead of overwritten so the GUI and CLI can load multiple testcase packs
    in one run, for example security_access.yaml + seed_sampling.yaml.
    """
    out = copy.deepcopy(base)
    for key, value in override.items():
        if key == "testcases" and isinstance(value, list):
            existing = out.get(key)
            if isinstance(existing, list):
                out[key] = copy.deepcopy(existing) + copy.deepcopy(value)
            else:
                out[key] = copy.deepcopy(value)
        elif isinstance(value, Mapping) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_yaml(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"YAML root must be a mapping: {p}")
    return data


def load_config(paths: Iterable[str | Path]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for path in paths:
        merged = deep_merge(merged, load_yaml(path))
    return merged


@dataclass(frozen=True)
class CanConfig:
    channel: str = "can0"
    interface: str = "socketcan"
    extended_id: bool = False
    padding: int = 0x00
    bitrate: int | None = None
    receive_own_messages: bool = False

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | None) -> "CanConfig":
        raw = raw or {}
        return cls(
            channel=str(raw.get("channel", "can0")),
            interface=str(raw.get("interface", "socketcan")),
            extended_id=bool(raw.get("extended_id", False)),
            padding=parse_byte(raw.get("padding", 0x00)),
            bitrate=int(raw["bitrate"]) if raw.get("bitrate") is not None else None,
            receive_own_messages=bool(raw.get("receive_own_messages", False)),
        )


@dataclass(frozen=True)
class TimingConfig:
    timeout: float = 1.0
    response_pending_timeout: float = 5.0
    post_session_delay: float = 0.05
    request_stmin: float = 0.0
    fc_wait_timeout: float = 3.0
    fc_bs: int = 0x00
    fc_stmin: int = 0x00
    delay: float = 0.2
    drain_before_request: float = 0.0

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | None) -> "TimingConfig":
        raw = raw or {}
        obj = cls(
            timeout=float(raw.get("timeout", 1.0)),
            response_pending_timeout=float(raw.get("response_pending_timeout", 5.0)),
            post_session_delay=float(raw.get("post_session_delay", 0.05)),
            request_stmin=float(raw.get("request_stmin", 0.0)),
            fc_wait_timeout=float(raw.get("fc_wait_timeout", 3.0)),
            fc_bs=parse_byte(raw.get("fc_bs", 0x00)),
            fc_stmin=parse_byte(raw.get("fc_stmin", 0x00)),
            delay=float(raw.get("delay", 0.2)),
            drain_before_request=float(raw.get("drain_before_request", 0.0)),
        )
        for name in ("timeout", "response_pending_timeout", "fc_wait_timeout"):
            if getattr(obj, name) <= 0:
                raise ConfigError(f"timing.{name} must be > 0")
        for name in ("post_session_delay", "request_stmin", "delay", "drain_before_request"):
            if getattr(obj, name) < 0:
                raise ConfigError(f"timing.{name} must be >= 0")
        return obj


@dataclass(frozen=True)
class TargetConfig:
    name: str
    txid: int
    rxid: int
    session_flow: List[int]
    extended_id: bool | None = None

    @classmethod
    def from_dict(cls, name: str, raw: Mapping[str, Any], inherited_extended_id: bool) -> "TargetConfig":
        if "txid" not in raw or "rxid" not in raw:
            raise ConfigError(f"target '{name}' requires txid and rxid")
        ext = raw.get("extended_id")
        extended_id = inherited_extended_id if ext is None else bool(ext)
        return cls(
            name=name,
            txid=parse_can_id(raw["txid"], extended=extended_id),
            rxid=parse_can_id(raw["rxid"], extended=extended_id),
            session_flow=[parse_byte(x) for x in raw.get("session_flow", [])],
            extended_id=extended_id,
        )


def get_targets(config: Mapping[str, Any], can_cfg: CanConfig) -> Dict[str, TargetConfig]:
    raw_targets = config.get("targets") or {}
    if not isinstance(raw_targets, Mapping):
        raise ConfigError("targets must be a mapping")
    targets: Dict[str, TargetConfig] = {}
    for name, raw in raw_targets.items():
        if not isinstance(raw, Mapping):
            raise ConfigError(f"target '{name}' must be a mapping")
        targets[str(name)] = TargetConfig.from_dict(str(name), raw, can_cfg.extended_id)
    return targets


def get_testcases(config: Mapping[str, Any]) -> List[Dict[str, Any]]:
    raw = config.get("testcases") or []
    if not isinstance(raw, list):
        raise ConfigError("testcases must be a list")
    out: List[Dict[str, Any]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ConfigError(f"testcase #{idx} must be a mapping")
        if not item.get("name"):
            raise ConfigError(f"testcase #{idx} requires name")
        if not item.get("type"):
            raise ConfigError(f"testcase '{item.get('name')}' requires type")
        out.append(item)
    return out
