from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any


EVIDENCE_SCHEMA_FIELDS = (
    "timestamp",
    "target_profile",
    "session_flow",
    "request_payload",
    "response_payload",
    "physical_observation_note",
    "verdict",
    "raw_log_path",
)


@dataclass(frozen=True)
class EvidenceSchema:
    fields: tuple[str, ...] = EVIDENCE_SCHEMA_FIELDS

    def as_dict(self) -> dict[str, Any]:
        return {"fields": list(self.fields)}


@dataclass(frozen=True)
class EvidenceRecord:
    timestamp: str
    target_profile: dict[str, Any]
    session_flow: str
    request_payload: str
    response_payload: str
    physical_observation_note: str
    verdict: str
    raw_log_path: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target_profile": self.target_profile,
            "session_flow": self.session_flow,
            "request_payload": self.request_payload,
            "response_payload": self.response_payload,
            "physical_observation_note": self.physical_observation_note,
            "verdict": self.verdict,
            "raw_log_path": self.raw_log_path,
        }


def build_placeholder_evidence_record(
    *,
    target_profile: dict[str, Any],
    session_flow: str,
    request_payload: str = "",
    physical_observation_note: str = "",
    verdict: str = "NOT_IMPLEMENTED / STUB",
    raw_log_path: str = "",
) -> EvidenceRecord:
    return EvidenceRecord(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        target_profile=target_profile,
        session_flow=session_flow,
        request_payload=request_payload,
        response_payload="",
        physical_observation_note=physical_observation_note,
        verdict=verdict,
        raw_log_path=raw_log_path,
    )
