from __future__ import annotations

import copy
import re
from typing import Any, Mapping

from .testcase_model import apply_case_model_fields


LEGACY_METADATA: dict[str, dict[str, Any]] = {
    "seed_cross_session_20": {
        "test_id": "UDS-10",
        "title": "Guessable Seeds Generated Across Different Sessions",
        "group": "Group A - First Seed Across Sessions",
        "category": "Seed Sampling",
        "mode": "cross-session-seed-sampling",
        "service": "0x27",
        "subfunction": "0x01",
        "objective": "Collect first seeds across diagnostic session boundaries.",
        "expected_behavior": "Seeds should not be predictable or trivially repeated across sessions.",
        "threat_condition": "Repeated or guessable seeds enable easier SecurityAccess bypass analysis.",
        "safety_level": "probing",
    },
    "seed_same_session_20": {
        "test_ids": ["UDS-11", "UDS-12", "UDS-15"],
        "title": "Same-session seed sampling / seed length / RequestSeed limit",
        "group": "Group B - Same Session Seed Behaviour",
        "category": "Seed Sampling",
        "mode": "same-session-seed-sampling",
        "service": "0x27",
        "subfunction": "0x01",
        "objective": "Sample repeated RequestSeed responses in one active diagnostic session.",
        "expected_behavior": "Seeds should have sufficient length, entropy, and rate limiting.",
        "threat_condition": "Weak, repeated, short, or unlimited seeds can weaken SecurityAccess.",
        "safety_level": "probing",
    },
    "sa_key_without_seed": {
        "test_id": "UDS-13",
        "title": "SendKey Without Prior RequestSeed",
        "group": "Group C - SecurityAccess Sequence Enforcement",
        "category": "SecurityAccess",
        "mode": "security-access-sequence",
        "service": "0x27",
        "subfunction": "0x02",
        "objective": "Send a key subfunction before requesting a seed.",
        "expected_behavior": "ECU should reject the sequence with an NRC such as requestSequenceError or securityAccessDenied.",
        "threat_condition": "ECU accepts SendKey without a matching seed challenge.",
        "safety_level": "probing",
    },
    "sa_seed_timeout_key": {
        "test_id": "UDS-14",
        "title": "SendKey After Seed Timeout",
        "group": "Group C - SecurityAccess Sequence Enforcement",
        "category": "SecurityAccess",
        "mode": "security-access-timeout",
        "service": "0x27",
        "subfunction": "0x02",
        "objective": "Request a seed, wait for the configured timeout window, then send a key.",
        "expected_behavior": "ECU should reject stale seed/key use after timeout.",
        "threat_condition": "ECU accepts a key after the seed challenge should have expired.",
        "safety_level": "probing",
    },
    "sa_one_seed_many_keys": {
        "test_id": "UDS-16",
        "title": "Multiple SendKey Attempts For One Seed",
        "group": "Group C - SecurityAccess Attempt Handling",
        "category": "SecurityAccess",
        "mode": "one-seed-many-keys",
        "service": "0x27",
        "subfunction": "0x02",
        "objective": "Check whether one seed can be reused for multiple key attempts.",
        "expected_behavior": "ECU should enforce retry limits and invalidate stale attempts as required.",
        "threat_condition": "One seed permits repeated key guesses without proper lockout.",
        "safety_level": "probing",
    },
    "sa_seed_key_exchange_loop": {
        "test_id": "UDS-17",
        "title": "SecurityAccess Exchange Attempt Limit",
        "group": "Group C - SecurityAccess Attempt Handling",
        "category": "SecurityAccess",
        "mode": "seed-key-exchange-limit",
        "service": "0x27",
        "subfunction": "0x01/0x02",
        "objective": "Repeat seed/key exchanges to observe retry limiting.",
        "expected_behavior": "ECU should enforce attempt limits and delay/lockout policy.",
        "threat_condition": "ECU allows unlimited repeated SecurityAccess attempts.",
        "safety_level": "probing",
    },
    "sa_penalty_then_seed": {
        "test_id": "UDS-18",
        "title": "Penalty State Then RequestSeed",
        "group": "Group C - SecurityAccess Penalty Handling",
        "category": "SecurityAccess",
        "mode": "penalty-then-seed",
        "service": "0x27",
        "subfunction": "0x01",
        "objective": "Trigger penalty handling and then request another seed.",
        "expected_behavior": "ECU should enforce required delay or lockout before new seeds.",
        "threat_condition": "ECU issues new seeds immediately during penalty state.",
        "safety_level": "probing",
    },
    "sa_multi_seed_response": {
        "test_id": "UDS-19",
        "title": "Multiple Seed Responses To One Request",
        "group": "Group C - SecurityAccess Response Handling",
        "category": "SecurityAccess",
        "mode": "multi-seed-response",
        "service": "0x27",
        "subfunction": "0x01",
        "objective": "Observe whether one RequestSeed generates multiple seed responses.",
        "expected_behavior": "ECU should send one well-formed seed response per request.",
        "threat_condition": "ECU emits multiple or inconsistent seed responses.",
        "safety_level": "probing",
    },
    "payload_regression_small": {
        "test_id": "UDS-05",
        "title": "Malformed Or Invalid Request NRC Behaviour",
        "group": "Group A - Basic Diagnostic Robustness",
        "category": "Fuzzing",
        "mode": "explicit-payload-regression",
        "objective": "Send a bounded set of known payloads to observe invalid request handling.",
        "expected_behavior": "ECU should return appropriate NRCs and remain stable.",
        "threat_condition": "Malformed or invalid requests cause unexpected positive responses or instability.",
        "safety_level": "probing",
    },
}


TYPE_METADATA: dict[str, dict[str, Any]] = {
    "arb_id_fuzzer": {
        "test_id": "RECON-01",
        "title": "Arbitration ID Discovery",
        "group": "Recon",
        "category": "Reconnaissance",
        "mode": "arb-id-fuzzer",
        "objective": "Probe a bounded CAN arbitration ID range for diagnostic responses.",
        "expected_behavior": "Only authorized lab targets should respond as expected.",
        "threat_condition": "Unexpected diagnostic endpoints are discoverable.",
        "safety_level": "probing",
    },
    "service_fuzzer": {
        "test_id": "RECON-02",
        "title": "UDS Service Discovery",
        "group": "Recon",
        "category": "Reconnaissance",
        "mode": "service-fuzzer",
        "objective": "Probe a bounded UDS service range on a known target.",
        "expected_behavior": "Unsupported or unavailable services should be denied with NRCs.",
        "threat_condition": "Unexpected services are exposed in the active session.",
        "safety_level": "probing",
    },
    "subservice_fuzzer": {
        "test_id": "RECON-03",
        "title": "UDS Subfunction Discovery",
        "group": "Recon",
        "category": "Reconnaissance",
        "mode": "subservice-fuzzer",
        "objective": "Probe a bounded subfunction range for one UDS service.",
        "expected_behavior": "Unsupported subfunctions should be denied with NRCs.",
        "threat_condition": "Unexpected subfunctions are exposed in the active session.",
        "safety_level": "probing",
    },
}


def infer_test_id_from_legacy_name(name: str, case_type: str = "") -> dict[str, Any]:
    if name in LEGACY_METADATA:
        return copy.deepcopy(LEGACY_METADATA[name])
    if name.startswith("sa_seed_key_exchange_l"):
        return copy.deepcopy(LEGACY_METADATA["sa_seed_key_exchange_loop"])
    if name.startswith("payload_regression_"):
        return copy.deepcopy(LEGACY_METADATA["payload_regression_small"])
    if case_type in TYPE_METADATA:
        return copy.deepcopy(TYPE_METADATA[case_type])
    return {}


def normalize_testcase_metadata(tc: Mapping[str, Any], *, source_yaml: str = "") -> dict[str, Any]:
    out = copy.deepcopy(dict(tc))
    internal_name = str(out.get("internal_name") or out.get("name") or "")
    case_type = str(out.get("type") or "")
    inferred = infer_test_id_from_legacy_name(internal_name, case_type)

    for key, value in inferred.items():
        out.setdefault(key, value)

    if out.get("test_ids") and not isinstance(out["test_ids"], list):
        out["test_ids"] = [str(out["test_ids"])]
    if not out.get("test_ids") and out.get("test_id"):
        out["test_ids"] = [str(out["test_id"])]
    if out.get("test_ids") and not out.get("test_id"):
        out["test_id"] = str(out["test_ids"][0])

    out["internal_name"] = internal_name
    if source_yaml:
        out["source_yaml"] = source_yaml
        out["source_file"] = source_yaml
    else:
        out.setdefault("source_yaml", out.get("source_file", ""))
        out.setdefault("source_file", out.get("source_yaml", ""))

    out.setdefault("title", internal_name or "Untitled testcase")
    out.setdefault("display_id", out.get("test_id") or _first(out.get("test_ids")) or internal_name)
    out.setdefault("canonical_id", out.get("name") or internal_name)
    out.setdefault("group", "UNMAPPED")
    out.setdefault("category", _category_from_type(case_type))
    out.setdefault("mode", _mode_from_config(out))
    out.setdefault("target", "ecu1")
    out.setdefault("service", _service_from_config(out))
    out.setdefault("subfunction", _subfunction_from_config(out))
    out.setdefault("objective", "")
    out.setdefault("expected_behavior", "")
    out.setdefault("threat_condition", "")
    out.setdefault("safety_level", _safety_level_from_config(out))
    out.setdefault("destructive_confirm_required", bool(out.get("safety_level") == "disruptive"))
    out = apply_case_model_fields(out)
    out["display_name"] = format_display_name(out)
    out["metadata_warning"] = "" if out.get("test_ids") else "This testcase has no explicit test_id metadata. Add test_id in YAML for report traceability."
    return out


def format_display_name(tc: Mapping[str, Any]) -> str:
    ids = list(tc.get("test_ids") or [])
    title = str(tc.get("title") or tc.get("name") or "Untitled testcase")
    mode = str(tc.get("mode") or tc.get("type") or "")
    if ids:
        return f"{_compact_ids(ids)} — {title} [{mode}]"
    return f"UNMAPPED — {tc.get('internal_name') or tc.get('name') or title}"


def sort_testcases_by_report_order(testcases: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized = [normalize_testcase_metadata(tc) for tc in testcases]
    return sorted(normalized, key=_sort_key)


def test_id_label(tc: Mapping[str, Any]) -> str:
    ids = list(tc.get("test_ids") or ([] if not tc.get("test_id") else [tc.get("test_id")]))
    return _compact_ids([str(x) for x in ids]) if ids else "UNMAPPED"


def metadata_for_event(tc: Mapping[str, Any]) -> dict[str, Any]:
    # Runtime-only keys such as _bus and _can_module can contain socket/module
    # objects. Metadata normalization deep-copies the testcase, so strip those
    # keys before building event context.
    metadata_source = {key: value for key, value in dict(tc).items() if not str(key).startswith("_")}
    effective_parameters = tc.get("_effective_parameters")
    normalized = normalize_testcase_metadata(metadata_source)
    keys = [
        "test_id",
        "test_ids",
        "display_id",
        "canonical_id",
        "title",
        "display_name",
        "internal_name",
        "type",
        "group",
        "category",
        "mode",
        "safety_level",
        "case_id",
        "risk_property",
        "service_id",
        "default_payload",
        "preconditions",
        "parameters",
        "expected_behavior",
        "pass_criteria",
        "fail_criteria",
        "evidence_fields",
        "case_model",
        "source_yaml",
    ]
    out = {key: normalized.get(key, "" if key != "test_ids" else []) for key in keys}
    out["testcase_type"] = normalized.get("type", "")
    if effective_parameters is not None:
        out["effective_parameters"] = effective_parameters
    return out


def _compact_ids(ids: list[str]) -> str:
    if not ids:
        return "UNMAPPED"
    uds_numbers = []
    prefix = None
    for value in ids:
        match = re.fullmatch(r"([A-Z]+)-(\d+)", value)
        if not match or (prefix is not None and match.group(1) != prefix):
            return "/".join(ids)
        prefix = match.group(1)
        uds_numbers.append(match.group(2))
    if prefix == "UDS" and len(ids) > 1:
        return f"UDS-{'/'.join(uds_numbers)}"
    return ids[0] if len(ids) == 1 else f"{prefix}-{'/'.join(uds_numbers)}"


def _sort_key(tc: Mapping[str, Any]) -> tuple[int, int, str]:
    ids = list(tc.get("test_ids") or [])
    first = str(ids[0]) if ids else str(tc.get("test_id") or "")
    recon = re.fullmatch(r"RECON-(\d+)", first)
    if recon:
        return (0, int(recon.group(1)), str(tc.get("internal_name", "")))
    uds = re.fullmatch(r"UDS-(\d+)", first)
    if uds:
        return (1, int(uds.group(1)), str(tc.get("internal_name", "")))
    return (2, 9999, str(tc.get("internal_name", "")))


def _category_from_type(case_type: str) -> str:
    if case_type == "security_access":
        return "SecurityAccess"
    if "seed_sampler" in case_type:
        return "Seed Sampling"
    if case_type == "uds_access_control_probe":
        return "Access Control"
    if case_type in {"diagnostic_service", "flood", "robustness", "can_priority_flood"}:
        return "UDS-26..32 Framework"
    if case_type.endswith("fuzzer"):
        return "Fuzzing"
    return "UNMAPPED"


def _mode_from_config(tc: Mapping[str, Any]) -> str:
    mode = str(tc.get("mode") or tc.get("type") or "")
    return mode.replace("_", "-")


def _service_from_config(tc: Mapping[str, Any]) -> str:
    if tc.get("service") is not None:
        return _hexish(tc.get("service"))
    if tc.get("type") == "security_access" or "seed_sampler" in str(tc.get("type", "")):
        return "0x27"
    requests = tc.get("requests")
    if isinstance(requests, list) and requests and isinstance(requests[0], Mapping):
        service = requests[0].get("service")
        if service is not None:
            return _hexish(service)
    return ""


def _subfunction_from_config(tc: Mapping[str, Any]) -> str:
    for key in ("seed_subfn", "subfunction"):
        if tc.get(key) is not None:
            return _hexish(tc.get(key))
    return ""


def _safety_level_from_config(tc: Mapping[str, Any]) -> str:
    if bool(tc.get("destructive_confirm_required")):
        return "disruptive"
    if tc.get("type") == "uds_access_control_probe":
        requests = tc.get("requests") or []
        for req in requests if isinstance(requests, list) else []:
            if isinstance(req, Mapping) and _hexish(req.get("service")) in {"0x11", "0x2E", "0x34", "0x35", "0x28"}:
                return "disruptive"
        return "read-only"
    if str(tc.get("type", "")) in {"diagnostic_service", "flood", "robustness", "can_priority_flood"}:
        return str(tc.get("safety_level") or "framework-placeholder")
    if str(tc.get("type", "")).endswith("fuzzer"):
        return "probing"
    return "probing"


def _hexish(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, int):
        return f"0x{value:02X}"
    text = str(value)
    try:
        return f"0x{int(text, 16):02X}"
    except Exception:
        return text
