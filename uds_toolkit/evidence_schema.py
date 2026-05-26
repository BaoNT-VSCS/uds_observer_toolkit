from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any


EVIDENCE_SCHEMA_FIELDS = (
    "timestamp",
    "display_id",
    "canonical_id",
    "target_profile",
    "session_flow",
    "selected_subfunction",
    "selected_subfunction_meaning",
    "suppress_positive_response_requested",
    "raw_payload_override",
    "request_payload",
    "response_payload",
    "response_classification",
    "positive_response",
    "nrc",
    "timeout_or_no_response",
    "authorization_state_note",
    "diagnostic_observation_note",
    "dtc_update_effect_confirmed",
    "physical_observation_note",
    "analyst_note",
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
    display_id: str = ""
    canonical_id: str = ""
    selected_subfunction: str = ""
    selected_subfunction_meaning: str = ""
    suppress_positive_response_requested: bool = False
    raw_payload_override: str = ""
    response_classification: str = ""
    positive_response: bool = False
    nrc: str = ""
    timeout_or_no_response: bool = False
    authorization_state_note: str = ""
    diagnostic_observation_note: str = ""
    dtc_update_effect_confirmed: str = "unknown"
    analyst_note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "display_id": self.display_id,
            "canonical_id": self.canonical_id,
            "target_profile": self.target_profile,
            "session_flow": self.session_flow,
            "selected_subfunction": self.selected_subfunction,
            "selected_subfunction_meaning": self.selected_subfunction_meaning,
            "suppress_positive_response_requested": self.suppress_positive_response_requested,
            "raw_payload_override": self.raw_payload_override,
            "request_payload": self.request_payload,
            "response_payload": self.response_payload,
            "response_classification": self.response_classification,
            "positive_response": self.positive_response,
            "nrc": self.nrc,
            "timeout_or_no_response": self.timeout_or_no_response,
            "authorization_state_note": self.authorization_state_note,
            "diagnostic_observation_note": self.diagnostic_observation_note,
            "dtc_update_effect_confirmed": self.dtc_update_effect_confirmed,
            "physical_observation_note": self.physical_observation_note,
            "analyst_note": self.analyst_note,
            "verdict": self.verdict,
            "raw_log_path": self.raw_log_path,
        }


def build_evidence_record(
    *,
    target_profile: dict[str, Any],
    session_flow: str,
    request_payload: str = "",
    response_payload: str = "",
    physical_observation_note: str = "",
    verdict: str = "",
    raw_log_path: str = "",
    display_id: str = "",
    canonical_id: str = "",
    selected_subfunction: str = "",
    selected_subfunction_meaning: str = "",
    suppress_positive_response_requested: bool = False,
    raw_payload_override: str = "",
    response_classification: str = "",
    positive_response: bool = False,
    nrc: str = "",
    timeout_or_no_response: bool = False,
    authorization_state_note: str = "",
    diagnostic_observation_note: str = "",
    dtc_update_effect_confirmed: str = "unknown",
    analyst_note: str = "",
) -> EvidenceRecord:
    return EvidenceRecord(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        target_profile=target_profile,
        session_flow=session_flow,
        display_id=display_id,
        canonical_id=canonical_id,
        selected_subfunction=selected_subfunction,
        selected_subfunction_meaning=selected_subfunction_meaning,
        suppress_positive_response_requested=suppress_positive_response_requested,
        raw_payload_override=raw_payload_override,
        request_payload=request_payload,
        response_payload=response_payload,
        response_classification=response_classification,
        positive_response=positive_response,
        nrc=nrc,
        timeout_or_no_response=timeout_or_no_response,
        authorization_state_note=authorization_state_note,
        diagnostic_observation_note=diagnostic_observation_note,
        dtc_update_effect_confirmed=dtc_update_effect_confirmed,
        physical_observation_note=physical_observation_note,
        analyst_note=analyst_note,
        verdict=verdict,
        raw_log_path=raw_log_path,
    )


def build_placeholder_evidence_record(
    *,
    target_profile: dict[str, Any],
    session_flow: str,
    request_payload: str = "",
    physical_observation_note: str = "",
    verdict: str = "NOT_IMPLEMENTED / STUB",
    raw_log_path: str = "",
) -> EvidenceRecord:
    return build_evidence_record(
        target_profile=target_profile,
        session_flow=session_flow,
        request_payload=request_payload,
        physical_observation_note=physical_observation_note,
        verdict=verdict,
        raw_log_path=raw_log_path,
    )
