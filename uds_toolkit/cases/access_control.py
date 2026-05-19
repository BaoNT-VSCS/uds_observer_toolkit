from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Mapping

from .base import CaseContext
from ..uds import UdsClient, UdsResult
from ..utils import parse_byte, parse_hex_bytes, spaced


@dataclass(frozen=True)
class AccessRequest:
    step: str
    payload: bytes
    service: int
    expected_positive_sid: int
    acceptable_nrcs: set[int]
    threat_if_positive: bool
    check_subfn: bool
    redact_response_data: bool
    notes: str


def _cfg(ctx: CaseContext, key: str, default: Any = None) -> Any:
    return ctx.raw_config.get(key, default)


def _load_requests(ctx: CaseContext) -> list[AccessRequest]:
    raw_requests = _cfg(ctx, "requests", [])
    if not isinstance(raw_requests, list) or not raw_requests:
        raise ValueError("uds_access_control_probe requires a non-empty requests list")

    requests: list[AccessRequest] = []
    for idx, raw in enumerate(raw_requests, start=1):
        if not isinstance(raw, Mapping):
            raise ValueError(f"request #{idx} must be a mapping")
        payload = parse_hex_bytes(raw.get("payload", ""))
        if not payload:
            raise ValueError(f"request #{idx} requires a non-empty payload")
        service = parse_byte(raw.get("service", payload[0]))
        if service != payload[0]:
            raise ValueError(f"request #{idx} service 0x{service:02X} does not match payload SID 0x{payload[0]:02X}")
        acceptable_nrcs = {parse_byte(x) for x in raw.get("acceptable_nrcs", [])}
        expected_positive_sid = parse_byte(raw.get("expected_positive_sid", (service + 0x40) & 0xFF))
        requests.append(
            AccessRequest(
                step=str(raw.get("step", f"request-{idx}")),
                payload=payload,
                service=service,
                expected_positive_sid=expected_positive_sid,
                acceptable_nrcs=acceptable_nrcs,
                threat_if_positive=bool(raw.get("threat_if_positive", False)),
                check_subfn=bool(raw.get("check_subfn", True)),
                redact_response_data=bool(raw.get("redact_response_data", False)),
                notes=str(raw.get("notes", "")),
            )
        )
    return requests


def classify_verdict(result: UdsResult, *, acceptable_nrcs: set[int], threat_if_positive: bool, expected_positive_sid: int) -> str:
    if result.exception:
        if "timeout" in result.exception.lower():
            return "INFO_NO_RESPONSE"
        return "ERROR_EXCEPTION"
    if not result.response:
        return "INFO_NO_RESPONSE"
    if result.nrc is not None:
        negative_matches_request = len(result.response) >= 2 and bool(result.request) and result.response[1] == result.request[0]
        if negative_matches_request and result.nrc in acceptable_nrcs:
            return "PASS_EXPECTED_DENIAL"
        return "INFO_UNEXPECTED_NRC"
    if result.positive and result.response and result.response[0] == expected_positive_sid:
        if threat_if_positive:
            return "FAIL_THREAT_POSITIVE"
        return "INFO_POSITIVE_RESPONSE"
    return "INFO_UNEXPECTED_RESPONSE"


def _response_display(req: AccessRequest, result: UdsResult) -> str | None:
    if not req.redact_response_data or not result.response:
        return None
    return f"<redacted len={len(result.response)}>"


def _record(ctx: CaseContext, req: AccessRequest, result: UdsResult, verdict: str, note: str | None = None) -> None:
    response_display = _response_display(req, result)
    base_note = note if note is not None else (result.note or result.exception)
    if req.notes and base_note:
        summary_note = f"{base_note}; {req.notes}"
    else:
        summary_note = base_note or req.notes
    ctx.run_logger.result(
        testcase=ctx.name,
        target=ctx.target.name,
        step=req.step,
        request=result.request,
        response=b"" if response_display is not None else result.response,
        response_display=response_display,
        status=result.status,
        nrc=result.nrc,
        note=summary_note,
        verdict=verdict,
    )


class UdsAccessControlProbe:
    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        cfg = ctx.raw_config
        if bool(cfg.get("security_access_required", False)):
            raise ValueError("uds_access_control_probe does not perform SecurityAccess; set security_access_required: false for unauthenticated probes")

        requests = _load_requests(ctx)

        session_flow = [parse_byte(x) for x in cfg.get("session_flow", ctx.target.session_flow)]
        if session_flow:
            ok, session_obs = client.open_session_flow(session_flow, strict=bool(cfg.get("strict_session", False)), delay=ctx.timing.post_session_delay)
            for step, result in session_obs:
                ctx.run_logger.result(
                    testcase=ctx.name,
                    target=ctx.target.name,
                    step=step,
                    request=result.request,
                    response=result.response,
                    status=result.status,
                    nrc=result.nrc,
                    note=result.note or result.exception,
                    verdict="",
                )
            if not ok:
                return 1

        delay = float(cfg.get("delay", ctx.timing.delay))
        for req in requests:
            result = client.request(
                req.payload,
                step=req.step,
                frame_label="AccessControl",
                check_subfn=req.check_subfn,
                redact_response=req.redact_response_data,
            )
            verdict = classify_verdict(
                result,
                acceptable_nrcs=req.acceptable_nrcs,
                threat_if_positive=req.threat_if_positive,
                expected_positive_sid=req.expected_positive_sid,
            )
            _record(ctx, req, result, verdict)
            response_text = _response_display(req, result) or spaced(result.response)
            client.log.process(f"  {req.step:<22} VERDICT {verdict} response={response_text}")
            if delay > 0:
                time.sleep(delay)
        return 0
