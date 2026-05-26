from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class SafetyGuard:
    bench_mode_required: bool = True
    manual_confirm_required: bool = True
    max_duration_seconds: float = 30.0
    max_frame_rate: float = 10.0
    stop_button_required: bool = True
    stop_on_bus_error: bool = True
    tester_present_enabled: bool = False
    tester_present_interval_seconds: float = 2.0

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "SafetyGuard":
        raw = dict(value or {})
        return cls(
            bench_mode_required=bool(raw.get("bench_mode_required", True)),
            manual_confirm_required=bool(raw.get("manual_confirm_required", True)),
            max_duration_seconds=float(raw.get("max_duration_seconds", 30.0)),
            max_frame_rate=float(raw.get("max_frame_rate", 10.0)),
            stop_button_required=bool(raw.get("stop_button_required", True)),
            stop_on_bus_error=bool(raw.get("stop_on_bus_error", True)),
            tester_present_enabled=bool(raw.get("tester_present_enabled", False)),
            tester_present_interval_seconds=float(raw.get("tester_present_interval_seconds", 2.0)),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "bench_mode_required": self.bench_mode_required,
            "manual_confirm_required": self.manual_confirm_required,
            "max_duration_seconds": self.max_duration_seconds,
            "max_frame_rate": self.max_frame_rate,
            "stop_button_required": self.stop_button_required,
            "stop_on_bus_error": self.stop_on_bus_error,
            "tester_present_enabled": self.tester_present_enabled,
            "tester_present_interval_seconds": self.tester_present_interval_seconds,
        }


def validate_safety_guard(guard: SafetyGuard) -> dict[str, str]:
    errors: dict[str, str] = {}
    if guard.max_duration_seconds <= 0:
        errors["max_duration_seconds"] = "max_duration_seconds must be > 0"
    if guard.max_frame_rate <= 0:
        errors["max_frame_rate"] = "max_frame_rate must be > 0"
    if guard.tester_present_interval_seconds <= 0:
        errors["tester_present_interval_seconds"] = "tester_present_interval_seconds must be > 0"
    return errors
