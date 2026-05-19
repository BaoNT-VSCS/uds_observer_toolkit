from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping

from .testcase_metadata import normalize_testcase_metadata, test_id_label
from .utils import can_id_hx, parse_byte, parse_can_id, parse_hex_bytes, parse_int_range, spaced


DESTRUCTIVE_SERVICES = {0x11, 0x2E, 0x34, 0x35, 0x28}
BUILTIN_DEFAULTS: Dict[str, Any] = {
    "can": {
        "channel": "can0",
        "interface": "socketcan",
        "extended_id": False,
        "padding": 0x00,
    },
    "timing": {
        "timeout": 1.0,
        "response_pending_timeout": 5.0,
        "post_session_delay": 0.05,
        "delay": 0.20,
    },
    "safety": {
        "authorized": False,
        "dry_run": True,
    },
    "default_target": "ecu1",
    "targets": {},
}


@dataclass(frozen=True)
class ValidationMessage:
    severity: str
    field: str
    message: str


def deep_merge(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def field(
    key: str,
    label: str,
    field_type: str,
    default: Any = None,
    *,
    required: bool = False,
    help: str = "",
    options: Iterable[str] | None = None,
    visible_if: Mapping[str, Any] | None = None,
    validation: str = "",
) -> Dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "type": field_type,
        "default": default,
        "required": required,
        "help": help,
        "options": list(options or []),
        "visible_if": dict(visible_if or {}),
        "validation": validation,
    }


COMMON_SECURITY = [
    field("security_mode", "Mode", "dropdown", "request_seed_only", required=True, options=[
        "request_seed_only",
        "key_without_seed",
        "seed_timeout_key",
        "one_seed_many_keys",
        "seed_key_exchange_loop",
        "penalty_then_seed",
        "multi_seed_response",
    ]),
    field("session_flow", "Session flow", "hex_list", []),
    field("seed_subfn", "Seed subfunction", "hex_byte", "0x01", required=True),
    field("key_subfn", "Key subfunction", "hex_byte", "0x02"),
    field("key_policy", "Key policy", "dropdown", "format-random", options=["format-random", "invalid-bitflip", "pattern", "explicit"]),
    field("key_hex", "Explicit key", "payload_list", "", visible_if={"key_policy": "explicit"}),
    field("attempts", "Count / attempts", "int", 1, visible_if={"security_mode": ["one_seed_many_keys", "seed_key_exchange_loop", "penalty_then_seed"]}),
    field("delay", "Delay", "float", 0.2, visible_if={"security_mode": ["one_seed_many_keys", "seed_key_exchange_loop"]}),
    field("penalty_probe_delay", "Penalty attempts delay", "float", 0.05, visible_if={"security_mode": "penalty_then_seed"}),
    field("capture_window", "Capture window", "float", 1.0, visible_if={"security_mode": "multi_seed_response"}),
    field("stop_on_positive_unlock", "Stop on positive unlock", "bool", True),
]


SCHEMAS: Dict[str, Dict[str, Any]] = {
    "security_access": {
        "common_fields": [],
        "parameter_fields": COMMON_SECURITY,
        "advanced_fields": [
            field("key_delay", "Key delay", "float", 0.05),
            field("s3_wait", "S3 / timeout wait", "float", 6.0),
            field("strict_session", "Strict session open", "bool", False),
        ],
        "safety_fields": [],
        "validation_rules": ["security_access"],
    },
    "seed_sampler_same_session": {
        "parameter_fields": [
            field("session_flow", "Session flow", "hex_list", []),
            field("seed_subfn", "Seed subfunction", "hex_byte", "0x01", required=True),
            field("samples", "Count", "int", 20, required=True),
            field("delay", "Delay", "float", 0.2),
            field("retry_on_nrc37", "Retry on NRC 0x37", "bool", True),
            field("nrc37_wait", "NRC 0x37 wait", "float", 1.0),
            field("nrc37_max_retries", "NRC 0x37 max retries", "int", 3),
            field("stop_on_sequence_error", "Stop on sequence error", "bool", True),
            field("stop_on_session_lost", "Stop on session lost", "bool", True),
        ],
        "advanced_fields": [
            field("tester_present", "TesterPresent enabled", "bool", False),
            field("tester_present_interval", "TesterPresent interval", "float", 2.0),
            field("strict_session", "Strict session open", "bool", False),
        ],
        "safety_fields": [],
        "validation_rules": ["seed_sampler"],
    },
    "seed_sampler_cross_session": {
        "parameter_fields": [
            field("session_flow", "Session flow", "hex_list", []),
            field("seed_subfn", "Seed subfunction", "hex_byte", "0x01", required=True),
            field("samples", "Count", "int", 20, required=True),
            field("session_boundary", "Session boundary", "dropdown", "default", options=["default", "reset", "s3", "none"]),
            field("default_session_subfn", "Default session subfn", "hex_byte", "0x01", visible_if={"session_boundary": "default"}),
            field("reset_subfn", "Reset subfn", "hex_byte", "0x01", visible_if={"session_boundary": "reset"}),
            field("reset_wait", "Reset wait", "float", 2.0, visible_if={"session_boundary": "reset"}),
            field("s3_wait", "S3 wait", "float", 6.0, visible_if={"session_boundary": "s3"}),
            field("inter_session_delay", "Inter-session delay", "float", 0.2),
            field("post_boundary_delay", "Post-boundary delay", "float", 0.05),
            field("strict_boundary", "Strict boundary", "bool", False),
            field("stop_on_boundary_error", "Stop on boundary error", "bool", True),
        ],
        "advanced_fields": [field("strict_session", "Strict session open", "bool", False)],
        "safety_fields": [],
        "validation_rules": ["seed_sampler"],
    },
    "arb_id_fuzzer": {
        "parameter_fields": [
            field("arb_id_start", "Arb ID start", "hex_id", "0x700", required=True),
            field("arb_id_end", "Arb ID end", "hex_id", "0x70F", required=True),
            field("arb_id_list", "Arb ID list", "range", ""),
            field("probe_payload", "Payload template", "payload_list", "3E 00", required=True),
            field("rx_id_strategy", "RX ID strategy", "dropdown", "listen_rx_range", options=["listen_rx_range", "any_response", "target_rx_id"]),
            field("max_items", "Max items", "int", 32, required=True),
            field("delay", "Delay", "float", 0.01),
            field("rate_limit", "Rate limit", "float", 0.0),
            field("per_id_timeout", "Timeout", "float", 0.08),
            field("stop_on_first_response", "Stop on first positive", "bool", False),
        ],
        "advanced_fields": [field("collect_limit_per_id", "Collect limit per ID", "int", 5)],
        "safety_fields": [],
        "validation_rules": ["fuzzer"],
    },
    "service_fuzzer": {
        "parameter_fields": [
            field("session_flow", "Session flow", "hex_list", []),
            field("service_start", "Service start", "hex_byte", "0x10", required=True),
            field("service_end", "Service end", "hex_byte", "0x3E", required=True),
            field("service_list", "Service list", "range", ""),
            field("payload_template", "Payload template", "payload_list", ""),
            field("max_items", "Max items", "int", 64, required=True),
            field("delay", "Delay", "float", 0.05),
            field("acceptable_nrcs", "Acceptable NRCs", "hex_list", []),
            field("stop_on_positive", "Stop on positive", "bool", False),
        ],
        "advanced_fields": [field("strict_session", "Strict session open", "bool", False)],
        "safety_fields": [],
        "validation_rules": ["fuzzer"],
    },
    "subservice_fuzzer": {
        "parameter_fields": [
            field("session_flow", "Session flow", "hex_list", []),
            field("service", "Service ID", "hex_byte", "0x10", required=True),
            field("subservice_start", "Subservice start", "hex_byte", "0x01", required=True),
            field("subservice_end", "Subservice end", "hex_byte", "0x7F", required=True),
            field("subservice_list", "Subservice list", "range", ""),
            field("max_items", "Max items", "int", 64, required=True),
            field("delay", "Delay", "float", 0.05),
            field("acceptable_nrcs", "Acceptable NRCs", "hex_list", []),
            field("stop_on_positive", "Stop on positive", "bool", False),
        ],
        "advanced_fields": [
            field("suppress_positive_response_bit", "Suppress positive response bit", "bool", False),
            field("strict_session", "Strict session open", "bool", False),
        ],
        "safety_fields": [],
        "validation_rules": ["fuzzer"],
    },
    "payload_fuzzer": {
        "parameter_fields": [
            field("session_flow", "Session flow", "hex_list", []),
            field("payloads", "Payload list", "payload_list", [], required=True),
            field("expected_positive_sid", "Expected positive SID", "hex_byte", ""),
            field("acceptable_nrcs", "Acceptable NRCs", "hex_list", []),
            field("check_subfn", "Check subfunction", "bool", False),
            field("redact_response_data", "Redact response data", "bool", False),
            field("delay", "Delay", "float", 0.1),
            field("stop_on_positive", "Stop on positive", "bool", False),
        ],
        "advanced_fields": [field("strict_session", "Strict session open", "bool", False)],
        "safety_fields": [],
        "validation_rules": ["payloads"],
    },
    "uds_access_control_probe": {
        "parameter_fields": [
            field("session_flow", "Session flow", "hex_list", []),
            field("service", "Service", "hex_byte", "0x22", required=True),
            field("payload", "Payload", "payload_list", "", required=True),
            field("expected_positive_sid", "Expected positive SID", "hex_byte", ""),
            field("acceptable_nrcs", "Acceptable NRCs", "hex_list", []),
            field("check_subfn", "Check subfunction", "bool", True),
            field("redact_response_data", "Redact response data", "bool", False),
            field("threat_if_positive", "Threat if positive", "bool", True),
        ],
        "advanced_fields": [field("strict_session", "Strict session open", "bool", False)],
        "safety_fields": [],
        "validation_rules": ["access_control"],
    },
    "default": {
        "parameter_fields": [
            field("session_flow", "Session flow", "hex_list", []),
            field("delay", "Delay", "float", 0.2),
        ],
        "advanced_fields": [],
        "safety_fields": [],
        "validation_rules": [],
    },
}


def get_ui_schema_for_testcase(testcase: dict) -> dict:
    case_type = str(testcase.get("type") or "default")
    schema = copy.deepcopy(SCHEMAS.get(case_type, SCHEMAS["default"]))
    schema.setdefault("common_fields", [])
    schema.setdefault("parameter_fields", [])
    schema.setdefault("advanced_fields", [])
    schema.setdefault("safety_fields", [])
    schema.setdefault("validation_rules", [])
    return schema


def build_effective_config(base_config: dict, target_profile: dict, testcase: dict, gui_overrides: dict) -> dict:
    cfg = deep_merge(copy.deepcopy(BUILTIN_DEFAULTS), base_config or {})
    target_name = str(target_profile.get("name") or testcase.get("target") or cfg.get("default_target") or "ecu1")

    cfg.setdefault("can", {})
    cfg["can"]["channel"] = target_profile.get("channel", cfg["can"].get("channel", "can0"))
    cfg["can"]["interface"] = target_profile.get("interface", cfg["can"].get("interface", "socketcan"))
    cfg["can"]["extended_id"] = bool(target_profile.get("extended_id", cfg["can"].get("extended_id", False)))
    cfg["can"]["padding"] = _parse_or_keep_byte(target_profile.get("padding", cfg["can"].get("padding", 0)))

    cfg.setdefault("timing", {})
    if target_profile.get("timeout") not in (None, ""):
        cfg["timing"]["timeout"] = float(target_profile["timeout"])
    if target_profile.get("response_pending_timeout") not in (None, ""):
        cfg["timing"]["response_pending_timeout"] = float(target_profile["response_pending_timeout"])

    cfg["default_target"] = target_name
    cfg.setdefault("targets", {})
    target_cfg = copy.deepcopy(cfg["targets"].get(target_name, {}))
    target_cfg["txid"] = _parse_or_keep_can_id(target_profile.get("txid", target_cfg.get("txid", "0x7E0")), cfg["can"]["extended_id"])
    target_cfg["rxid"] = _parse_or_keep_can_id(target_profile.get("rxid", target_cfg.get("rxid", "0x7E8")), cfg["can"]["extended_id"])
    target_cfg["extended_id"] = bool(target_profile.get("extended_id", target_cfg.get("extended_id", cfg["can"]["extended_id"])))
    cfg["targets"][target_name] = target_cfg

    tc = normalize_testcase_metadata(testcase)
    tc["target"] = target_name
    tc = _apply_testcase_overrides(tc, gui_overrides or {})
    if "session_flow" in tc:
        tc["session_flow"] = _parse_hex_list(tc.get("session_flow"))

    if target_profile.get("session_flow") not in (None, ""):
        cfg["targets"][target_name]["session_flow"] = _parse_hex_list(target_profile.get("session_flow"))

    dry_run = bool(gui_overrides.get("_dry_run", False))
    authorized = bool(gui_overrides.get("_authorized", False))
    cfg.setdefault("safety", {})
    cfg["safety"]["authorized"] = authorized
    cfg["safety"]["dry_run"] = dry_run
    tc["_effective_parameters"] = _effective_parameters(tc)
    cfg["testcases"] = [tc]
    cfg["_gui_effective"] = {
        "test_id": test_id_label(tc),
        "internal_name": tc.get("internal_name", tc.get("name", "")),
        "testcase_type": tc.get("type", ""),
        "target": target_name,
        "tx_id": can_id_hx(int(cfg["targets"][target_name]["txid"])),
        "rx_id": can_id_hx(int(cfg["targets"][target_name]["rxid"])),
        "session_flow": _session_display(tc.get("session_flow", cfg["targets"][target_name].get("session_flow", []))),
        "safety_level": tc.get("safety_level", ""),
        "dry_run": dry_run,
        "will_transmit": not dry_run,
        "effective_parameters": tc["_effective_parameters"],
    }
    return cfg


def validate_effective_config(effective_config: dict) -> list[ValidationMessage]:
    messages: list[ValidationMessage] = []
    testcase = (effective_config.get("testcases") or [{}])[0]
    case_type = str(testcase.get("type") or "")
    can_cfg = effective_config.get("can") or {}
    target_name = str(effective_config.get("default_target") or testcase.get("target") or "")
    target = (effective_config.get("targets") or {}).get(target_name, {})
    dry_run = bool((effective_config.get("safety") or {}).get("dry_run", False))
    authorized = bool((effective_config.get("safety") or {}).get("authorized", False))

    for key in ("txid", "rxid"):
        try:
            parse_can_id(target.get(key), extended=bool(can_cfg.get("extended_id", False)))
        except Exception as exc:
            messages.append(ValidationMessage("error", key, str(exc)))
    try:
        _parse_or_keep_byte(can_cfg.get("padding", 0))
    except Exception as exc:
        messages.append(ValidationMessage("error", "padding", str(exc)))
    try:
        _parse_hex_list(testcase.get("session_flow", []))
    except Exception as exc:
        messages.append(ValidationMessage("error", "session_flow", str(exc)))

    if "seed_subfn" in testcase:
        try:
            seed_subfn = parse_byte(testcase.get("seed_subfn"))
            if seed_subfn % 2 == 0:
                messages.append(ValidationMessage("warning", "seed_subfn", "RequestSeed subfunction is normally odd."))
            if "key_subfn" in testcase:
                key_subfn = parse_byte(testcase.get("key_subfn"))
                if key_subfn != ((seed_subfn + 1) & 0xFF):
                    messages.append(ValidationMessage("warning", "key_subfn", "SendKey subfunction is normally seed_subfn + 1."))
        except Exception as exc:
            messages.append(ValidationMessage("error", "seed_subfn", str(exc)))

    if case_type.endswith("fuzzer"):
        max_items = int(testcase.get("max_items", 0) or 0)
        if max_items <= 0:
            messages.append(ValidationMessage("error", "max_items", "Fuzzing max_items must be > 0."))
        if max_items > 512:
            messages.append(ValidationMessage("error", "max_items", "max_items must be bounded to <= 512."))
        elif max_items > 128:
            messages.append(ValidationMessage("warning", "max_items", "Large fuzzing run; confirm timing and authorization."))
        try:
            if case_type == "arb_id_fuzzer":
                parse_int_range(testcase.get("txid_range", ""), item_parser=lambda x: parse_can_id(x, extended=bool(can_cfg.get("extended_id", False))), max_items=max_items or 512)
            elif case_type == "service_fuzzer":
                parse_int_range(testcase.get("services", ""), item_parser=parse_byte, max_items=max_items or 256)
            elif case_type == "subservice_fuzzer":
                parse_int_range(testcase.get("subfunctions", ""), item_parser=parse_byte, max_items=max_items or 256)
        except Exception as exc:
            messages.append(ValidationMessage("error", "range", str(exc)))
        if not dry_run and not authorized:
            messages.append(ValidationMessage("error", "authorized", "Real fuzzing/probing requires authorization."))
        if not dry_run:
            messages.append(ValidationMessage("warning", "dry_run", "Fuzzing dry-run is strongly recommended before real transmission."))

    services = _services_for_testcase(testcase)
    destructive = any(service in DESTRUCTIVE_SERVICES for service in services)
    if destructive and not dry_run:
        if not authorized:
            messages.append(ValidationMessage("error", "authorized", "Destructive service requires authorization."))
        if not bool(testcase.get("destructive_confirm", False)):
            messages.append(ValidationMessage("error", "destructive_confirm", "Destructive service is blocked unless destructive_confirm is true."))
    if dry_run:
        messages.append(ValidationMessage("info", "dry_run", "Dry-run mode will not transmit CAN frames."))
    return messages


def format_effective_config_preview(effective_config: dict) -> str:
    info = effective_config.get("_gui_effective") or {}
    params = info.get("effective_parameters") or {}
    lines = [
        f"test_id: {info.get('test_id', '')}",
        f"internal_name: {info.get('internal_name', '')}",
        f"testcase_type: {info.get('testcase_type', '')}",
        f"target: {info.get('target', '')}",
        f"tx_id/rx_id: {info.get('tx_id', '')} -> {info.get('rx_id', '')}",
        f"session_flow: {info.get('session_flow', '')}",
        f"safety_level: {info.get('safety_level', '')}",
        f"dry_run: {bool(info.get('dry_run', False))}",
        f"will_transmit_can: {bool(info.get('will_transmit', False))}",
        "effective_parameters:",
    ]
    lines.extend(f"  {key}: {json.dumps(value, ensure_ascii=False)}" for key, value in sorted(params.items()))
    return "\n".join(lines)


def _apply_testcase_overrides(testcase: dict, overrides: Mapping[str, Any]) -> dict:
    tc = copy.deepcopy(testcase)
    clean = {k: v for k, v in overrides.items() if not str(k).startswith("_") and v is not None}
    tc.update(clean)
    case_type = str(tc.get("type") or "")

    if case_type == "arb_id_fuzzer":
        tx_range = str(clean.get("arb_id_list") or "").strip()
        if not tx_range:
            start = clean.get("arb_id_start", _range_start(tc.get("txid_range"), "0x700"))
            end = clean.get("arb_id_end", _range_end(tc.get("txid_range"), "0x70F"))
            tx_range = f"{_hex_text(start, 3)}-{_hex_text(end, 3)}"
        tc["txid_range"] = tx_range
    elif case_type == "service_fuzzer":
        svc_range = str(clean.get("service_list") or "").strip()
        if not svc_range:
            svc_range = f"{_hex_text(clean.get('service_start', _range_start(tc.get('services'), '0x10')))}-{_hex_text(clean.get('service_end', _range_end(tc.get('services'), '0x3E')))}"
        tc["services"] = svc_range
    elif case_type == "subservice_fuzzer":
        sub_range = str(clean.get("subservice_list") or "").strip()
        if not sub_range:
            sub_range = f"{_hex_text(clean.get('subservice_start', _range_start(tc.get('subfunctions'), '0x01')))}-{_hex_text(clean.get('subservice_end', _range_end(tc.get('subfunctions'), '0x7F')))}"
        tc["subfunctions"] = sub_range
    elif case_type == "seed_sampler_cross_session":
        boundary = str(tc.get("session_boundary", "") or _boundary_from_config(tc))
        tc["session_boundary"] = boundary
        if boundary == "default":
            tc["boundary_session_flow"] = [parse_byte(tc.get("default_session_subfn", 0x01))]
        elif boundary == "reset":
            tc["boundary_session_flow"] = [parse_byte(tc.get("reset_subfn", 0x01))]
        elif boundary == "s3":
            tc["boundary_session_flow"] = []
            tc["delay"] = float(tc.get("inter_session_delay", tc.get("delay", 0.2)))
        elif boundary == "none":
            tc["boundary_session_flow"] = []
        if "inter_session_delay" in tc:
            tc["delay"] = float(tc["inter_session_delay"])
    elif case_type == "uds_access_control_probe":
        req = _first_request(tc)
        for key in ("service", "payload", "expected_positive_sid", "acceptable_nrcs", "check_subfn", "redact_response_data", "threat_if_positive"):
            if key in tc:
                req[key] = tc[key]
        if not req.get("expected_positive_sid") and req.get("service") not in (None, ""):
            req["expected_positive_sid"] = (parse_byte(req["service"]) + 0x40) & 0xFF
        tc["requests"] = [req]
    return tc


def _effective_parameters(tc: Mapping[str, Any]) -> Dict[str, Any]:
    keys = [
        "security_mode", "session_flow", "seed_subfn", "key_subfn", "key_policy", "key_hex",
        "attempts", "samples", "delay", "capture_window", "penalty_probe_delay",
        "session_boundary", "boundary_session_flow", "txid_range", "probe_payload",
        "services", "service", "subfunctions", "payloads", "requests", "max_items",
        "acceptable_nrcs", "check_subfn", "redact_response_data", "destructive_confirm",
    ]
    return {key: copy.deepcopy(tc[key]) for key in keys if key in tc}


def _first_request(tc: Mapping[str, Any]) -> Dict[str, Any]:
    requests = tc.get("requests")
    if isinstance(requests, list) and requests and isinstance(requests[0], Mapping):
        return copy.deepcopy(dict(requests[0]))
    payload = str(tc.get("payload") or "")
    service = tc.get("service")
    return {
        "step": str(tc.get("name", "request")),
        "service": service if service not in (None, "") else (parse_hex_bytes(payload)[0] if payload else 0x22),
        "payload": payload,
        "acceptable_nrcs": tc.get("acceptable_nrcs", []),
        "threat_if_positive": bool(tc.get("threat_if_positive", True)),
        "check_subfn": bool(tc.get("check_subfn", True)),
        "redact_response_data": bool(tc.get("redact_response_data", False)),
    }


def _services_for_testcase(tc: Mapping[str, Any]) -> list[int]:
    services: list[int] = []
    if tc.get("service") not in (None, ""):
        try:
            services.append(parse_byte(tc.get("service")))
        except Exception:
            pass
    requests = tc.get("requests")
    if isinstance(requests, list):
        for req in requests:
            if isinstance(req, Mapping):
                try:
                    services.append(parse_byte(req.get("service", parse_hex_bytes(req.get("payload", ""))[0])))
                except Exception:
                    pass
    return services


def _parse_hex_list(value: Any) -> List[int]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple)):
        return [parse_byte(v) for v in value]
    return [parse_byte(part) for part in str(value).replace(",", " ").replace(";", " ").split() if part]


def _parse_or_keep_byte(value: Any) -> int:
    return parse_byte(value)


def _parse_or_keep_can_id(value: Any, extended: bool) -> int:
    return parse_can_id(value, extended=extended)


def _hex_text(value: Any, width: int = 2) -> str:
    try:
        return f"0x{int(str(value), 16):0{width}X}"
    except Exception:
        return str(value)


def _range_start(value: Any, default: str) -> str:
    text = str(value or "")
    first = text.split(",", 1)[0].split("-", 1)[0].strip()
    return first or default


def _range_end(value: Any, default: str) -> str:
    text = str(value or "")
    first = text.split(",", 1)[0]
    if "-" in first:
        return first.split("-", 1)[1].strip() or default
    return default


def _boundary_from_config(tc: Mapping[str, Any]) -> str:
    flow = tc.get("boundary_session_flow")
    if flow in (None, "", []):
        return "none"
    try:
        values = _parse_hex_list(flow)
    except Exception:
        return "default"
    return "default" if values == [0x01] else "reset"


def _session_display(value: Any) -> str:
    try:
        return spaced(_parse_hex_list(value))
    except Exception:
        return str(value or "")
