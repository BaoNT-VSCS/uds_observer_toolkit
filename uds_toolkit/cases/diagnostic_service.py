from __future__ import annotations

from typing import Any

from ..case_runners import DiagnosticServiceRunner
from ..evidence_schema import build_evidence_record
from ..safety import SafetyGuard
from ..testcase_model import normalize_case_model
from ..uds import UdsClient, UdsResult
from ..utils import can_id_hx, parse_byte_list, spaced
from .base import CaseContext, record_result


class DiagnosticServiceCase:
    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        runner = DiagnosticServiceRunner()
        case = normalize_case_model(ctx.raw_config)
        parameters = _parameters(ctx.raw_config)
        safety_guard = SafetyGuard.from_mapping(ctx.raw_config.get("safety_guard", {}))
        errors = runner.validate(case, parameters, safety_guard)
        if errors:
            ctx.run_logger.event(
                "diagnostic_service_config_error",
                testcase=ctx.name,
                target=ctx.target.name,
                errors=errors,
            )
            return 2

        session_flow = _session_flow(parameters, ctx)
        if session_flow:
            ok, observations = client.open_session_flow(
                session_flow,
                strict=bool(ctx.raw_config.get("strict_session", False)),
                delay=ctx.timing.post_session_delay,
            )
            for step, result in observations:
                record_result(ctx, step, result)
            if not ok:
                verdict = "INCONCLUSIVE"
                rationale = "Session flow did not complete positively; diagnostic service request was not sent."
                ctx.run_logger.event(
                    "diagnostic_service_evidence",
                    testcase=ctx.name,
                    target=ctx.target.name,
                    verdict=verdict,
                    rationale=rationale,
                    evidence_record=_evidence_record(
                        ctx,
                        parameters,
                        request_payload=spaced(runner.build_payload(case, parameters)),
                        response_payload="",
                        response_classification="session_flow_failed",
                        positive_response=False,
                        nrc="",
                        timeout_or_no_response=False,
                        verdict=verdict,
                    ),
                )
                return 1

        payload = runner.build_payload(case, parameters)
        suppress_positive = runner.suppress_positive_response_requested(payload)
        subfunction_meaning = runner.selected_subfunction_meaning(payload)
        group_of_dtc = runner.selected_group_of_dtc(payload)
        group_meaning = runner.group_of_dtc_meaning(payload)
        step_name = _step_name(payload)
        result = client.request(payload, step=step_name, frame_label=_frame_label(payload))
        verdict_result = runner.classify_response(
            positive=result.positive,
            negative=result.nrc is not None,
            response_type=_response_type(result),
            nrc=f"0x{result.nrc:02X}" if result.nrc is not None else "",
            error=result.exception,
            parameters=parameters,
            suppress_positive_response_requested=suppress_positive,
            service_id=payload[0] if payload else None,
        )
        ctx.run_logger.result(
            testcase=ctx.name,
            target=ctx.target.name,
            step=step_name,
            request=result.request,
            response=result.response,
            status=result.status,
            nrc=result.nrc,
            note=result.note or result.exception,
            verdict=verdict_result.verdict,
            evidence_note=verdict_result.rationale,
        )
        ctx.run_logger.event(
            "diagnostic_service_evidence",
            testcase=ctx.name,
            target=ctx.target.name,
            verdict=verdict_result.verdict,
            rationale=verdict_result.rationale,
            evidence_record=_evidence_record(
                ctx,
                parameters,
                request_payload=spaced(payload),
                response_payload=spaced(result.response),
                response_classification=_response_type(result),
                positive_response=result.positive,
                nrc=f"0x{result.nrc:02X}" if result.nrc is not None else "",
                timeout_or_no_response=_response_type(result) in {"timeout", "no_response"},
                suppress_positive_response_requested=suppress_positive,
                selected_subfunction=runner.selected_subfunction(payload),
                selected_subfunction_meaning=subfunction_meaning,
                selected_group_of_dtc=group_of_dtc,
                group_of_dtc_meaning=group_meaning,
                verdict=verdict_result.verdict,
            ),
        )
        return 0 if verdict_result.verdict != "ERROR" else 1


def _parameters(raw_config: dict[str, Any]) -> dict[str, Any]:
    parameters = dict(raw_config.get("parameters") or {})
    for key in (
        "session_flow",
        "service_id",
        "subfunction",
        "group_of_dtc_preset",
        "group_of_dtc",
        "raw_payload_override",
        "advanced_raw_payload_override_enabled",
        "authorization_state_note",
        "dtc_state_before_note",
        "dtc_state_after_note",
        "diagnostic_observation_note",
        "physical_observation_note",
        "dtc_update_effect_confirmed",
        "dtc_clear_effect_confirmed",
        "analyst_note",
    ):
        if key in raw_config:
            parameters[key] = raw_config[key]
    return parameters


def _session_flow(parameters: dict[str, Any], ctx: CaseContext) -> list[int]:
    value = parameters.get("session_flow")
    if value in (None, ""):
        return list(ctx.target.session_flow)
    return parse_byte_list(value)


def _response_type(result: UdsResult) -> str:
    if result.exception:
        if "Timeout" in result.exception:
            return "timeout"
        return "transport_error"
    if not result.response:
        return "no_response"
    if result.positive:
        return "positive_response"
    if result.nrc is not None:
        return "negative_response"
    return "ambiguous_response"


def _step_name(payload: bytes) -> str:
    if payload and payload[0] == 0x14:
        return "clear_diagnostic_information"
    if payload and payload[0] == 0x85:
        return "control_dtc_setting"
    return "diagnostic_service"


def _frame_label(payload: bytes) -> str:
    if payload and payload[0] == 0x14:
        return "ClearDiagnosticInformation"
    if payload and payload[0] == 0x85:
        return "ControlDTCSetting"
    return "DiagnosticService"


def _evidence_record(
    ctx: CaseContext,
    parameters: dict[str, Any],
    *,
    request_payload: str,
    response_payload: str,
    response_classification: str,
    positive_response: bool,
    nrc: str,
    timeout_or_no_response: bool,
    verdict: str,
    selected_subfunction: str = "",
    suppress_positive_response_requested: bool = False,
    selected_subfunction_meaning: str = "",
    selected_group_of_dtc: str = "",
    group_of_dtc_meaning: str = "",
) -> dict[str, Any]:
    return build_evidence_record(
        display_id=str(ctx.raw_config.get("display_id") or ctx.raw_config.get("test_id") or ""),
        canonical_id=str(ctx.raw_config.get("canonical_id") or ctx.raw_config.get("name") or ""),
        target_profile={"name": ctx.target.name, "txid": can_id_hx(ctx.target.txid), "rxid": can_id_hx(ctx.target.rxid)},
        session_flow=str(parameters.get("session_flow") or ""),
        selected_subfunction=selected_subfunction or str(parameters.get("subfunction") or ""),
        selected_subfunction_meaning=selected_subfunction_meaning,
        suppress_positive_response_requested=suppress_positive_response_requested,
        selected_group_of_dtc=selected_group_of_dtc,
        group_of_dtc_meaning=group_of_dtc_meaning,
        raw_payload_override=str(parameters.get("raw_payload_override") or ""),
        request_payload=request_payload,
        response_payload=response_payload,
        response_classification=response_classification,
        positive_response=positive_response,
        nrc=nrc,
        timeout_or_no_response=timeout_or_no_response,
        authorization_state_note=str(parameters.get("authorization_state_note") or ""),
        dtc_state_before_note=str(parameters.get("dtc_state_before_note") or ""),
        dtc_state_after_note=str(parameters.get("dtc_state_after_note") or ""),
        diagnostic_observation_note=str(parameters.get("diagnostic_observation_note") or ""),
        dtc_update_effect_confirmed=str(parameters.get("dtc_update_effect_confirmed") or "unknown"),
        dtc_clear_effect_confirmed=str(parameters.get("dtc_clear_effect_confirmed") or "unknown"),
        physical_observation_note=str(parameters.get("physical_observation_note") or ""),
        analyst_note=str(parameters.get("analyst_note") or ""),
        verdict=verdict,
        raw_log_path=str(ctx.run_logger.jsonl_path),
    ).as_dict()
