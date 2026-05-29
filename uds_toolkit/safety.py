from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class SafetyGuard:
    max_duration_seconds: float = 30.0
    max_frame_rate: float = 10.0
    max_messages: int = 300
    max_send_rate: float = 10.0
    stop_button_required: bool = True
    stop_on_bus_error: bool = True
    stop_on_no_response_threshold: int = 10
    tester_present_enabled: bool = False
    tester_present_interval_seconds: float = 2.0

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "SafetyGuard":
        raw = dict(value or {})
        return cls(
            max_duration_seconds=_float(raw.get("max_duration_seconds"), 30.0),
            max_frame_rate=_float(raw.get("max_frame_rate"), 10.0),
            max_messages=_int(raw.get("max_messages"), 300),
            max_send_rate=_float(raw.get("max_send_rate", raw.get("max_frame_rate")), 10.0),
            stop_button_required=_bool(raw.get("stop_button_required", True)),
            stop_on_bus_error=_bool(raw.get("stop_on_bus_error", True)),
            stop_on_no_response_threshold=_int(raw.get("stop_on_no_response_threshold"), 10),
            tester_present_enabled=_bool(raw.get("tester_present_enabled", False)),
            tester_present_interval_seconds=_float(raw.get("tester_present_interval_seconds"), 2.0),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_duration_seconds": self.max_duration_seconds,
            "max_frame_rate": self.max_frame_rate,
            "max_messages": self.max_messages,
            "max_send_rate": self.max_send_rate,
            "stop_button_required": self.stop_button_required,
            "stop_on_bus_error": self.stop_on_bus_error,
            "stop_on_no_response_threshold": self.stop_on_no_response_threshold,
            "tester_present_enabled": self.tester_present_enabled,
            "tester_present_interval_seconds": self.tester_present_interval_seconds,
        }


def validate_safety_guard(guard: SafetyGuard) -> dict[str, str]:
    errors: dict[str, str] = {}
    if guard.max_duration_seconds <= 0:
        errors["max_duration_seconds"] = "max_duration_seconds must be > 0"
    if guard.max_frame_rate <= 0:
        errors["max_frame_rate"] = "max_frame_rate must be > 0"
    if guard.max_send_rate <= 0:
        errors["max_send_rate"] = "max_send_rate must be > 0"
    if guard.max_messages <= 0:
        errors["max_messages"] = "max_messages must be > 0"
    if guard.stop_on_no_response_threshold < 0:
        errors["stop_on_no_response_threshold"] = "stop_on_no_response_threshold must be >= 0"
    if guard.tester_present_enabled and guard.tester_present_interval_seconds <= 0:
        errors["tester_present_interval_seconds"] = "tester_present_interval_seconds must be > 0"
    return errors


def _bool(value: Any, default: bool = False) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "checked"}


def _float(value: Any, default: float) -> float:
    if value in (None, ""):
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int) -> int:
    if value in (None, ""):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default
