from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Mapping


CASE_MODEL_FIELDS = (
    "case_id",
    "title",
    "category",
    "risk_property",
    "service_id",
    "default_payload",
    "preconditions",
    "parameters",
    "safety_level",
    "expected_behavior",
    "pass_criteria",
    "fail_criteria",
    "evidence_fields",
)


@dataclass(frozen=True)
class TestCaseModel:
    case_id: str
    title: str
    category: str
    risk_property: str
    service_id: str
    default_payload: str
    preconditions: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    safety_level: str = "probing"
    expected_behavior: str = ""
    pass_criteria: list[str] = field(default_factory=list)
    fail_criteria: list[str] = field(default_factory=list)
    evidence_fields: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "category": self.category,
            "risk_property": self.risk_property,
            "service_id": self.service_id,
            "default_payload": self.default_payload,
            "preconditions": list(self.preconditions),
            "parameters": copy.deepcopy(self.parameters),
            "safety_level": self.safety_level,
            "expected_behavior": self.expected_behavior,
            "pass_criteria": list(self.pass_criteria),
            "fail_criteria": list(self.fail_criteria),
            "evidence_fields": list(self.evidence_fields),
        }


def normalize_case_model(tc: Mapping[str, Any]) -> TestCaseModel:
    case_id = str(tc.get("case_id") or tc.get("test_id") or _first(tc.get("test_ids")) or tc.get("name") or tc.get("internal_name") or "UNMAPPED")
    title = str(tc.get("title") or tc.get("name") or tc.get("internal_name") or case_id)
    category = str(tc.get("category") or "UNMAPPED")
    risk_property = str(tc.get("risk_property") or tc.get("threat_condition") or _risk_from_type(tc))
    service_id = str(tc.get("service_id") or tc.get("service") or "")
    default_payload = str(tc.get("default_payload") or _default_payload_from_config(tc))
    preconditions = _listify(tc.get("preconditions") or _preconditions_from_config(tc))
    parameters = _parameters_from_config(tc)
    safety_level = str(tc.get("safety_level") or "probing")
    expected_behavior = str(tc.get("expected_behavior") or "")
    pass_criteria = _listify(tc.get("pass_criteria") or _default_pass_criteria(tc, expected_behavior))
    fail_criteria = _listify(tc.get("fail_criteria") or _default_fail_criteria(tc, risk_property))
    evidence_fields = _listify(tc.get("evidence_fields") or tc.get("evidence_output_fields") or _default_evidence_fields(tc))

    return TestCaseModel(
        case_id=case_id,
        title=title,
        category=category,
        risk_property=risk_property,
        service_id=service_id,
        default_payload=default_payload,
        preconditions=preconditions,
        parameters=parameters,
        safety_level=safety_level,
        expected_behavior=expected_behavior,
        pass_criteria=pass_criteria,
        fail_criteria=fail_criteria,
        evidence_fields=evidence_fields,
    )


def apply_case_model_fields(tc: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(tc))
    model = normalize_case_model(out)
    for key, value in model.as_dict().items():
        out.setdefault(key, value)
    out["case_model"] = model.as_dict()
    return out


def _first(value: Any) -> str:
    if isinstance(value, (list, tuple)) and value:
        return str(value[0])
    return ""


def _listify(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _risk_from_type(tc: Mapping[str, Any]) -> str:
    case_type = str(tc.get("type") or "")
    if case_type == "security_access" or "seed_sampler" in case_type:
        return "SecurityAccess robustness and resistance to bypass"
    if case_type == "uds_access_control_probe":
        return "Unauthorized access to sensitive UDS service"
    if case_type in {"diagnostic_service", "arbid_range_scan", "flood", "robustness", "can_priority_flood"}:
        return "Future UDS-26..32 validation placeholder"
    if case_type.endswith("fuzzer"):
        return "Unexpected diagnostic exposure or robustness issue"
    return ""


def _default_payload_from_config(tc: Mapping[str, Any]) -> str:
    payload = tc.get("payload")
    if payload not in (None, ""):
        return str(payload)
    requests = tc.get("requests")
    if isinstance(requests, list) and requests and isinstance(requests[0], Mapping):
        return str(requests[0].get("payload") or "")
    service = tc.get("service")
    subfunction = tc.get("subfunction")
    if service not in (None, "") and subfunction not in (None, ""):
        return f"{service} {subfunction}"
    return str(service or "")


def _preconditions_from_config(tc: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    session_flow = tc.get("session_flow")
    if session_flow not in (None, "", []):
        out.append(f"Open diagnostic session flow: {session_flow}")
    if bool(tc.get("destructive_confirm_required")) or bool(tc.get("destructive_confirm")):
        out.append("Operator authorization and disruptive-test confirmation required.")
    return out


def _parameters_from_config(tc: Mapping[str, Any]) -> dict[str, Any]:
    ignored = {
        "case_model",
        "case_id",
        "test_id",
        "test_ids",
        "title",
        "category",
        "risk_property",
        "service_id",
        "default_payload",
        "preconditions",
        "parameters",
        "safety_level",
        "expected_behavior",
        "pass_criteria",
        "fail_criteria",
        "evidence_fields",
        "evidence_output_fields",
        "objective",
        "threat_condition",
        "group",
        "mode",
        "source_yaml",
        "source_file",
        "display_name",
        "metadata_warning",
    }
    return {str(key): copy.deepcopy(value) for key, value in tc.items() if str(key) not in ignored and not str(key).startswith("_")}


def _default_pass_criteria(tc: Mapping[str, Any], expected_behavior: str) -> list[str]:
    case_type = str(tc.get("type") or "")
    service = str(tc.get("service") or tc.get("service_id") or "")
    if case_type == "uds_access_control_probe" or service in {"0x11", "0x2E", "0x22", "0x28", "0x34", "0x35"}:
        return ["ECU denies the tested request with an expected negative response or no unsafe state change is observed."]
    if case_type == "security_access":
        return ["Observed SecurityAccess behavior satisfies sequence, timeout, retry, and response-count expectations for this case."]
    if case_type == "diagnostic_service":
        return ["Diagnostic service response satisfies the case-specific expected behavior."]
    if case_type == "arbid_range_scan":
        return ["Manual ArbID range scan records response, timeout, NRC, or positive response for each candidate."]
    if case_type == "flood":
        return ["ECU and bus remain stable within bounded flood guard limits."]
    if case_type == "can_priority_flood":
        return ["CAN bus remains available and arbitration behavior stays within the case-specific guard limits."]
    if case_type == "robustness":
        return ["ECU rejects malformed or boundary input with expected NRCs and remains stable."]
    if "seed_sampler" in case_type:
        return ["Collected seeds satisfy configured uniqueness, length, entropy, and rate-limit expectations."]
    if case_type.endswith("fuzzer"):
        return ["No unexpected positive response, crash, bus disruption, or unsupported-service exposure is observed."]
    if expected_behavior:
        return [expected_behavior]
    return ["Observed behavior matches the expected behavior and produces a conclusive PASS verdict."]


def _default_fail_criteria(tc: Mapping[str, Any], risk_property: str) -> list[str]:
    case_type = str(tc.get("type") or "")
    service = str(tc.get("service") or tc.get("service_id") or "")
    if case_type == "uds_access_control_probe" or service in {"0x11", "0x2E", "0x22", "0x28", "0x34", "0x35"}:
        return ["ECU returns a positive response or otherwise accepts the tested sensitive request without the required authorization/precondition."]
    if case_type == "security_access":
        return ["ECU accepts an invalid SecurityAccess sequence/key or does not enforce the configured attempt/timeout behavior."]
    if case_type == "diagnostic_service":
        return ["Diagnostic service response violates the case-specific fail criteria."]
    if case_type == "arbid_range_scan":
        return ["Unexpected positive response, bus error, ECU reset, physical function interruption, or recovery failure is observed."]
    if case_type == "flood":
        return ["ECU, bus, or diagnostic session becomes unstable within bounded flood guard limits."]
    if case_type == "can_priority_flood":
        return ["CAN bus availability or arbitration behavior is degraded within bounded guard limits."]
    if case_type == "robustness":
        return ["ECU accepts malformed/boundary input unexpectedly or becomes unstable."]
    if "seed_sampler" in case_type:
        return ["Seeds repeat, are too short, are trivially predictable, or RequestSeed remains unlimited where enforcement is expected."]
    if case_type.endswith("fuzzer"):
        return ["Unexpected positive response, instability, or diagnostic exposure is observed."]
    if risk_property:
        return [risk_property]
    return ["Observed behavior violates fail criteria or produces a finding verdict."]


def _default_evidence_fields(tc: Mapping[str, Any]) -> list[str]:
    case_type = str(tc.get("type") or "")
    if case_type in {"security_access", "seed_sampler_same_session", "seed_sampler_cross_session"}:
        return ["request_hex", "response_hex", "nrc", "seed_hex", "verdict", "rationale", "metrics"]
    if case_type == "uds_access_control_probe":
        return ["request_hex", "response_hex", "nrc", "verdict", "rationale", "security_access_observed_before_target"]
    if case_type in {"diagnostic_service", "arbid_range_scan", "flood", "robustness", "can_priority_flood"}:
        return ["timestamp", "target_profile", "session_flow", "request_payload", "response_payload", "physical_observation_note", "verdict", "raw_log_path"]
    if case_type.endswith("fuzzer"):
        return ["request_hex", "response_hex", "status", "nrc", "notes"]
    return ["request_hex", "response_hex", "verdict", "rationale"]
