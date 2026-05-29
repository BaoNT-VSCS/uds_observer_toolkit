from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .safety import SafetyGuard, validate_safety_guard
from .testcase_model import TestCaseModel
from .utils import parse_byte, parse_hex_bytes, spaced


@dataclass(frozen=True)
class RunnerPlan:
    runner_name: str
    case_id: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    implemented: bool = False
    note: str = "Runner interface is defined; execution logic is not implemented yet."

    def as_dict(self) -> dict[str, Any]:
        return {
            "runner_name": self.runner_name,
            "case_id": self.case_id,
            "steps": list(self.steps),
            "implemented": self.implemented,
            "note": self.note,
        }


@dataclass(frozen=True)
class RunnerResult:
    verdict: str
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)


class ModularRunner(Protocol):
    runner_name: str

    def validate(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> dict[str, str]:
        ...

    def dry_run_preview(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> str:
        ...

    def plan(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerPlan:
        ...

    def run(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerResult:
        ...


class _StubRunner:
    runner_name = "stub"

    def validate(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> dict[str, str]:
        errors = validate_safety_guard(safety_guard)
        if not case.case_id:
            errors["case_id"] = "case_id is required"
        return errors

    def dry_run_preview(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> str:
        plan = self.plan(case, parameters, safety_guard)
        return "\n".join([
            f"Case: {case.case_id} - {case.title}",
            f"Runner: {self.runner_name}",
            "Execution: placeholder only; no CAN/ISO-TP/external command will be opened.",
            f"Implemented: {plan.implemented}",
            _preview_safety_line(case),
        ])

    def plan(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerPlan:
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerPlan(
                runner_name=self.runner_name,
                case_id=case.case_id,
                steps=[{"step": "validation_failed", "errors": dict(errors)}],
                note="Safety guard validation failed; no transmission is allowed.",
            )
        return RunnerPlan(
            runner_name=self.runner_name,
            case_id=case.case_id,
            steps=[
                {
                    "step": "framework_placeholder",
                    "message": "No CAN transmission is performed until this runner is implemented.",
                    "parameters": dict(parameters),
                    "safety_guard": safety_guard.as_dict(),
                }
            ],
        )

    def run(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerResult:
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerResult(
                verdict="CONFIG_ERROR",
                rationale="Safety guard validation failed; no CAN request was sent.",
                evidence={"errors": dict(errors)},
            )
        plan = self.plan(case, parameters, safety_guard)
        return RunnerResult(
            verdict="NOT_IMPLEMENTED",
            rationale=f"{self.runner_name} is a placeholder for {case.case_id}; no CAN/ISO-TP/external command was opened.",
            evidence={"plan": plan.as_dict()},
        )


class DiagnosticServiceRunner(_StubRunner):
    runner_name = "DiagnosticServiceRunner"

    def validate(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> dict[str, str]:
        if self._is_placeholder(case):
            return super().validate(case, parameters, safety_guard)
        errors = super().validate(case, parameters, safety_guard)
        try:
            payload = self.build_payload(case, parameters)
        except ValueError as exc:
            errors["request_payload"] = str(exc)
        else:
            raw_override = str(parameters.get("raw_payload_override") or "").strip()
            if not payload:
                errors["request_payload"] = "diagnostic request payload is required"
            elif raw_override:
                pass
            elif len(payload) < 2 and case.service_id.lower() in {"0x85", "85"}:
                errors["subfunction"] = "ControlDTCSetting requires a subfunction byte"
            elif self._service_id(case, parameters, payload[0]) == 0x14 and len(payload) != 4:
                errors["group_of_dtc"] = "ClearDiagnosticInformation requires service 0x14 plus exactly 3 groupOfDTC bytes"
            elif self._service_id(case, parameters, payload[0]) == 0x28 and len(payload) != 3:
                errors["request_payload"] = "CommunicationControl normally requires 28 <controlType> <communicationType>; shorter/custom payloads require advanced_raw_payload_override_enabled=true"
            elif self._service_id(case, parameters, payload[0]) == 0x11 and len(payload) != 2:
                errors["request_payload"] = "ECU Reset normally requires 11 <resetSubfunction>; custom payloads require advanced_raw_payload_override_enabled=true"
        return errors

    def dry_run_preview(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> str:
        if self._is_placeholder(case):
            return super().dry_run_preview(case, parameters, safety_guard)
        plan = self.plan(case, parameters, safety_guard)
        payload = ""
        meaning = ""
        suppress = False
        group_of_dtc = ""
        group_meaning = ""
        control_type = ""
        control_meaning = ""
        communication_type = ""
        communication_meaning = ""
        reset_subfunction = ""
        reset_meaning = ""
        try:
            payload_bytes = self.build_payload(case, parameters)
            payload = spaced(payload_bytes)
            meaning = self.selected_subfunction_meaning(payload_bytes)
            suppress = self.suppress_positive_response_requested(payload_bytes)
            group_of_dtc = self.selected_group_of_dtc(payload_bytes)
            group_meaning = self.group_of_dtc_meaning(payload_bytes)
            control_type = self.control_type(payload_bytes)
            control_meaning = self.control_type_meaning(payload_bytes)
            communication_type = self.communication_type(payload_bytes)
            communication_meaning = self.communication_type_meaning(payload_bytes)
            reset_subfunction = self.reset_subfunction(payload_bytes)
            reset_meaning = self.reset_subfunction_meaning(payload_bytes)
        except ValueError as exc:
            payload = f"<invalid: {exc}>"
        session_flow = str(parameters.get("session_flow") or "")
        lines = [
            f"Case: {case.case_id} - {case.title}",
            f"Runner: {self.runner_name}",
            "Execution: diagnostic_service dry-run preview only; no CAN/ISO-TP/external command will be opened.",
            f"Implemented: {plan.implemented}",
            f"Session flow: {session_flow or '<none>'}",
            f"Selected payload: {payload}",
            f"Selected subfunction meaning: {meaning or '<not applicable>'}",
            f"Suppress positive response requested: {suppress}",
            f"groupOfDTC: {group_of_dtc or '<not applicable>'}",
            f"groupOfDTC meaning: {group_meaning or '<not applicable>'}",
            _preview_safety_line(case),
        ]
        if case.case_id == "uds_29":
            lines.extend([
                f"controlType: {control_type or '<not available>'}",
                f"controlType meaning: {control_meaning or '<not available>'}",
                f"communicationType: {communication_type or '<not available>'}",
                f"communicationType meaning: {communication_meaning or '<not available>'}",
                f"Vehicle state: {parameters.get('vehicle_state') or '<unset>'}",
                "Assessment: no fixed NRC is assumed; verdict depends on observed behavior, disruption, and recovery evidence.",
            ])
        if case.case_id == "uds_30":
            lines.extend([
                "Service: 0x11 ECU Reset",
                f"resetSubfunction: {reset_subfunction or '<not available>'}",
                f"resetSubfunction meaning: {reset_meaning or '<not available>'}",
                f"Vehicle state: {parameters.get('vehicle_state') or '<unset>'}",
                "Assessment: no fixed NRC is assumed; verdict depends on observed behavior, interruption, and recovery evidence.",
            ])
        if self._disable_dtc_setting_requested(parameters):
            lines.append("Warning: 0x85 0x02 may suppress diagnostic trouble code updates; confirm diagnostic effect manually.")
        if self._clear_diagnostic_information_requested(case, parameters):
            lines.append("Note: this request may erase diagnostic evidence / DTC records; ECU behavior is recorded as observed.")
        if case.case_id == "uds_29" and (
            str(parameters.get("communication_control_preset") or "") in {"0x01", "0x02", "0x03"}
            or "operational" in str(parameters.get("vehicle_state") or "")
            or "controlled driving" in str(parameters.get("vehicle_state") or "")
        ):
            lines.append("Warning: disabling communication or operational/driving-state assessment must not be run on public roads.")
        if case.case_id == "uds_30" and (
            "operational" in str(parameters.get("vehicle_state") or "")
            or "controlled driving" in str(parameters.get("vehicle_state") or "")
        ):
            lines.append("Warning: ECU Reset while operational can interrupt functions; do not run on public roads.")
        raw_warning = self.raw_payload_format_warning(case, parameters)
        if raw_warning:
            lines.append(f"Warning: {raw_warning}")
        return "\n".join(lines)

    def plan(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerPlan:
        if self._is_placeholder(case):
            return super().plan(case, parameters, safety_guard)
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerPlan(
                runner_name=self.runner_name,
                case_id=case.case_id,
                steps=[{"step": "validation_failed", "errors": dict(errors)}],
                implemented=True,
                note="Diagnostic service validation failed; no transmission is allowed.",
            )
        payload = self.build_payload(case, parameters)
        steps: list[dict[str, Any]] = []
        session_flow = str(parameters.get("session_flow") or "").strip()
        if session_flow:
            steps.append({"step": "session_flow", "session_flow": session_flow})
        steps.append({
            "step": "single_diagnostic_request",
            "payload": spaced(payload),
            "selected_subfunction_meaning": self.selected_subfunction_meaning(payload),
            "suppress_positive_response_requested": self.suppress_positive_response_requested(payload),
            "selected_group_of_dtc": self.selected_group_of_dtc(payload),
            "group_of_dtc_meaning": self.group_of_dtc_meaning(payload),
            "controlType": self.control_type(payload),
            "controlType_meaning": self.control_type_meaning(payload),
            "communicationType": self.communication_type(payload),
            "communicationType_meaning": self.communication_type_meaning(payload),
            "reset_subfunction": self.reset_subfunction(payload),
            "reset_subfunction_meaning": self.reset_subfunction_meaning(payload),
            "note": "Single controlled diagnostic request; no flood or repeated transmission.",
        })
        return RunnerPlan(
            runner_name=self.runner_name,
            case_id=case.case_id,
            steps=steps,
            implemented=True,
            note="Diagnostic service runner is implemented for controlled single-shot requests.",
        )

    def run(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerResult:
        if self._is_placeholder(case):
            return super().run(case, parameters, safety_guard)
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerResult(
                verdict="CONFIG_ERROR",
                rationale="Diagnostic service validation failed; no CAN request was sent.",
                evidence={"errors": dict(errors)},
            )
        plan = self.plan(case, parameters, safety_guard)
        return RunnerResult(
            verdict="STUB",
            rationale="DiagnosticServiceRunner requires a transport-specific caller for execution.",
            evidence={"plan": plan.as_dict(), "request_payload": spaced(self.build_payload(case, parameters))},
        )

    def build_payload(self, case: TestCaseModel, parameters: dict[str, Any]) -> bytes:
        raw_override = str(parameters.get("raw_payload_override") or "").strip()
        if raw_override:
            payload = parse_hex_bytes(raw_override)
            if not payload:
                raise ValueError("raw payload override is empty")
            return payload

        service = self._service_id(case, parameters, None)
        if service == 0x14:
            return bytes([service]) + self._group_of_dtc(parameters, case.default_payload)
        if service == 0x28:
            preset = str(parameters.get("communication_control_preset") or "").strip()
            if preset == "manual":
                raise ValueError("manual CommunicationControl preset requires raw_payload_override in Advanced")
            control_type = parse_byte(preset or parameters.get("control_type") or "0x00")
            comm_source = parameters.get("manual_communication_type") if parameters.get("communication_type") == "manual" else parameters.get("communication_type")
            communication_type = parse_byte(comm_source or "0x01")
            return bytes([service, control_type, communication_type])
        if service == 0x11:
            subfunction_value = parameters.get("reset_subfunction")
            if subfunction_value == "manual":
                raise ValueError("manual ECU Reset preset requires raw_payload_override in Advanced")
            subfunction = parse_byte(subfunction_value or parameters.get("subfunction") or "0x03")
            return bytes([service, subfunction])
        subfunction_value = parameters.get("subfunction")
        if subfunction_value in (None, ""):
            default_payload = parse_hex_bytes(case.default_payload)
            if default_payload:
                return default_payload
            raise ValueError("subfunction is required when no raw payload override/default payload is configured")
        subfunction = parse_byte(subfunction_value)
        return bytes([service, subfunction])

    @staticmethod
    def classify_response(
        *,
        positive: bool,
        negative: bool,
        response_type: str,
        nrc: str = "",
        error: str = "",
        parameters: dict[str, Any] | None = None,
        suppress_positive_response_requested: bool = False,
        service_id: int | None = None,
    ) -> RunnerResult:
        parameters = parameters or {}
        if response_type in {"timeout", "no_response"}:
            if suppress_positive_response_requested:
                return RunnerResult(
                    "OBSERVATION",
                    "No positive response was received, which is expected when suppressPosRspMsgIndicationBit is set; diagnostic effect still requires manual evidence.",
                    {"suppress_positive_response_requested": True},
                )
            return RunnerResult(
                "INCONCLUSIVE",
                "Timeout/no-response is insufficient to determine whether the ECU ignored safely, addressing was wrong, or the ECU became unavailable.",
            )
        if error or response_type == "transport_error":
            return RunnerResult("ERROR", error or "Transport/tool execution error.")
        if negative or nrc:
            return RunnerResult(
                "PASS / SECURE_BEHAVIOR",
                "ECU rejected the request in the tested state with a negative response.",
                {"nrc": nrc},
            )
        if positive:
            if service_id == 0x28:
                state = str(parameters.get("vehicle_state") or "").lower()
                disruption = str(parameters.get("communication_disruption_observed") or "unknown").lower()
                physical_note = str(parameters.get("physical_observation_note") or "").lower()
                if disruption == "true" or any(word in physical_note for word in ("loss", "degrad", "interrupt", "unavailable", "reset")):
                    return RunnerResult(
                        "FINDING_CANDIDATE",
                        "ECU accepted CommunicationControl and evidence indicates communication disruption or physical impact.",
                    )
                if "operational" in state or "controlled driving" in state:
                    return RunnerResult(
                        "FINDING_CANDIDATE",
                        "ECU accepted CommunicationControl in an operational/driving-state assessment; evidence required for final severity.",
                    )
                return RunnerResult(
                    "OBSERVATION",
                    "ECU accepted CommunicationControl, but operational state and disruption evidence are insufficient for an automatic finding.",
                )
            if service_id == 0x11:
                state = str(parameters.get("vehicle_state") or "").lower()
                downtime_note = str(parameters.get("ecu_downtime_recovery_note") or "").lower()
                physical_note = str(parameters.get("physical_interruption_note") or parameters.get("physical_observation_note") or "").lower()
                if any(word in downtime_note + " " + physical_note for word in ("reset", "reboot", "downtime", "power cycle", "interrupt", "loss", "unavailable")):
                    return RunnerResult(
                        "FINDING_CANDIDATE",
                        "ECU accepted ECU Reset and evidence indicates downtime, interruption, or recovery concern.",
                    )
                if "operational" in state or "controlled driving" in state:
                    return RunnerResult(
                        "FINDING_CANDIDATE",
                        "ECU accepted ECU Reset in an operational/driving-state assessment; evidence required for final severity.",
                    )
                return RunnerResult(
                    "OBSERVATION",
                    "ECU accepted ECU Reset, but operational state and impact evidence are insufficient for an automatic finding.",
                )
            auth_note = str(parameters.get("authorization_state_note") or "").lower()
            dtc_update_effect = str(parameters.get("dtc_update_effect_confirmed") or "unknown").strip().lower()
            dtc_clear_effect = str(parameters.get("dtc_clear_effect_confirmed") or "unknown").strip().lower()
            unauthorized_markers = ("no security", "without security", "unauth", "not authorized", "no seed", "no seed/key")
            if any(marker in auth_note for marker in unauthorized_markers):
                if service_id == 0x14:
                    if dtc_clear_effect == "true":
                        return RunnerResult(
                            "FINDING_CANDIDATE",
                            "ECU accepted ClearDiagnosticInformation without documented authorization and DTC before/after notes indicate DTCs were cleared.",
                        )
                    return RunnerResult(
                        "FINDING_CANDIDATE",
                        "ECU accepted ClearDiagnosticInformation in a state documented as unauthenticated/unauthorized; DTC clear effect is not confirmed.",
                    )
                if dtc_update_effect == "true":
                    return RunnerResult(
                        "FINDING_CONFIRMED",
                        "ECU accepted ControlDTCSetting in an unauthenticated/unauthorized state and diagnostic evidence confirms DTC setting behavior changed.",
                    )
                return RunnerResult(
                    "FINDING_CANDIDATE",
                    "ECU accepted ControlDTCSetting in a state documented as unauthenticated/unauthorized; diagnostic behavior confirmation is still required.",
                )
            return RunnerResult(
                "OBSERVATION",
                "ECU returned a positive response, but authorization/session evidence is insufficient for an automatic finding.",
            )
        return RunnerResult(
            "OBSERVATION",
            "Response is ambiguous or malformed; analyst review is required.",
        )

    @staticmethod
    def _service_id(case: TestCaseModel, parameters: dict[str, Any], fallback: int | None) -> int:
        value = parameters.get("service_id") or case.service_id
        if value not in (None, ""):
            return parse_byte(value)
        if fallback is not None:
            return fallback
        default_payload = parse_hex_bytes(case.default_payload)
        if default_payload:
            return default_payload[0]
        raise ValueError("service_id is required")

    @staticmethod
    def _is_placeholder(case: TestCaseModel) -> bool:
        return case.safety_level == "framework-placeholder" or case.default_payload.startswith("<")

    @staticmethod
    def suppress_positive_response_requested(payload: bytes) -> bool:
        return len(payload) >= 2 and payload[0] == 0x85 and bool(payload[1] & 0x80)

    @staticmethod
    def selected_subfunction_meaning(payload: bytes) -> str:
        if len(payload) < 2:
            return ""
        if payload[0] == 0x28:
            return DiagnosticServiceRunner.control_type_meaning(payload)
        if payload[0] == 0x11:
            return DiagnosticServiceRunner.reset_subfunction_meaning(payload)
        if payload[0] != 0x85:
            return ""
        subfunction = payload[1]
        base = subfunction & 0x7F
        meanings = {
            0x01: "enable DTC setting",
            0x02: "disable DTC setting",
        }
        text = meanings.get(base, f"unknown subfunction 0x{base:02X}")
        if subfunction & 0x80:
            text += " with suppress positive response"
        return text

    @staticmethod
    def selected_subfunction(payload: bytes) -> str:
        if len(payload) < 2 or payload[0] not in {0x85, 0x28, 0x11}:
            return ""
        return f"0x{payload[1]:02X}"

    @staticmethod
    def control_type(payload: bytes) -> str:
        if len(payload) < 2 or payload[0] != 0x28:
            return ""
        return f"0x{payload[1]:02X}"

    @staticmethod
    def control_type_meaning(payload: bytes) -> str:
        if len(payload) < 2 or payload[0] != 0x28:
            return ""
        return {
            0x00: "enableRxAndTx",
            0x01: "enableRxAndDisableTx",
            0x02: "disableRxAndEnableTx",
            0x03: "disableRxAndTx",
        }.get(payload[1], f"custom controlType 0x{payload[1]:02X}")

    @staticmethod
    def communication_type(payload: bytes) -> str:
        if len(payload) < 3 or payload[0] != 0x28:
            return ""
        return f"0x{payload[2]:02X}"

    @staticmethod
    def communication_type_meaning(payload: bytes) -> str:
        if len(payload) < 3 or payload[0] != 0x28:
            return ""
        return {
            0x01: "normal communication messages",
            0x02: "network management communication messages",
            0x03: "normal and network management communication messages",
        }.get(payload[2], f"OEM/custom communicationType 0x{payload[2]:02X}")

    @staticmethod
    def reset_subfunction(payload: bytes) -> str:
        if len(payload) < 2 or payload[0] != 0x11:
            return ""
        return f"0x{payload[1]:02X}"

    @staticmethod
    def reset_subfunction_meaning(payload: bytes) -> str:
        if len(payload) < 2 or payload[0] != 0x11:
            return ""
        return {
            0x01: "hardReset",
            0x02: "keyOffOnReset",
            0x03: "softReset",
            0x04: "enableRapidPowerShutDown",
            0x05: "disableRapidPowerShutDown",
        }.get(payload[1], f"custom resetSubfunction 0x{payload[1]:02X}")

    @staticmethod
    def selected_group_of_dtc(payload: bytes) -> str:
        if len(payload) < 4 or payload[0] != 0x14:
            return ""
        return spaced(payload[1:4])

    @staticmethod
    def group_of_dtc_meaning(payload: bytes) -> str:
        group = DiagnosticServiceRunner.selected_group_of_dtc(payload)
        if not group:
            return ""
        if group == "FF FF FF":
            return "all DTC groups"
        return "custom groupOfDTC"

    def raw_payload_format_warning(self, case: TestCaseModel, parameters: dict[str, Any]) -> str:
        raw_override = str(parameters.get("raw_payload_override") or "").strip()
        if not raw_override:
            return ""
        try:
            payload = parse_hex_bytes(raw_override)
            service = self._service_id(case, parameters, payload[0] if payload else None)
        except ValueError as exc:
            return str(exc)
        if service == 0x14 and len(payload) != 4:
            return "normal ClearDiagnosticInformation format is 14 plus exactly 3 groupOfDTC bytes"
        if service == 0x28 and len(payload) != 3:
            return "normal CommunicationControl format is 28 <controlType> <communicationType>; this is non-standard/custom"
        if service == 0x11 and len(payload) != 2:
            return "normal ECU Reset format is 11 <resetSubfunction>; this is non-standard/custom"
        return ""

    @staticmethod
    def _disable_dtc_setting_requested(parameters: dict[str, Any]) -> bool:
        raw_override = str(parameters.get("raw_payload_override") or "").strip()
        if raw_override:
            try:
                payload = parse_hex_bytes(raw_override)
            except ValueError:
                return False
            return len(payload) >= 2 and (payload[1] & 0x7F) == 0x02
        try:
            return (parse_byte(parameters.get("subfunction", 0)) & 0x7F) == 0x02
        except ValueError:
            return False

    @staticmethod
    def _clear_diagnostic_information_requested(case: TestCaseModel, parameters: dict[str, Any]) -> bool:
        try:
            service = DiagnosticServiceRunner._service_id(case, parameters, None)
        except ValueError:
            return False
        return service == 0x14

    @staticmethod
    def _group_of_dtc(parameters: dict[str, Any], default_payload: str) -> bytes:
        preset = str(parameters.get("group_of_dtc_preset") or "all").strip()
        if preset == "custom":
            raw_group = parameters.get("group_of_dtc")
            group = parse_hex_bytes(raw_group)
            if len(group) != 3:
                raise ValueError("manual groupOfDTC must be exactly 3 bytes")
            return group
        if preset in {"all", "all_dtc_groups", ""}:
            return bytes([0xFF, 0xFF, 0xFF])
        if preset == "default":
            payload = parse_hex_bytes(default_payload)
            if len(payload) == 4 and payload[0] == 0x14:
                return payload[1:4]
        group = parse_hex_bytes(preset)
        if len(group) != 3:
            raise ValueError("groupOfDTC preset must resolve to exactly 3 bytes")
        return group


class FloodRunner(_StubRunner):
    runner_name = "FloodRunner"

    def validate(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> dict[str, str]:
        errors = super().validate(case, parameters, safety_guard)
        if case.case_id != "uds_28":
            return errors
        rate = _float_param(parameters, "send_rate_msgs_per_sec", safety_guard.max_send_rate)
        duration = _float_param(parameters, "max_duration_seconds", safety_guard.max_duration_seconds)
        max_messages = _int_param(parameters, "max_messages", safety_guard.max_messages)
        if rate <= 0:
            errors["send_rate_msgs_per_sec"] = "Send rate must be > 0 msg/s."
        if duration <= 0:
            errors["max_duration_seconds"] = "Duration must be > 0 seconds."
        if max_messages <= 0:
            errors["max_messages"] = "Max messages must be > 0."
        if rate > safety_guard.max_send_rate:
            errors["send_rate_msgs_per_sec"] = "Send rate exceeds SafetyGuard max_send_rate."
        if duration > safety_guard.max_duration_seconds:
            errors["max_duration_seconds"] = "Duration exceeds SafetyGuard max_duration_seconds."
        if max_messages > safety_guard.max_messages:
            errors["max_messages"] = "Max messages exceeds SafetyGuard max_messages."
        return errors

    def dry_run_preview(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> str:
        if case.case_id != "uds_28":
            return super().dry_run_preview(case, parameters, safety_guard)
        return _uds28_preview(case, parameters, safety_guard)

    def plan(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerPlan:
        if case.case_id != "uds_28":
            return super().plan(case, parameters, safety_guard)
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerPlan(
                runner_name=self.runner_name,
                case_id=case.case_id,
                steps=[{"step": "validation_failed", "errors": dict(errors)}],
                note="UDS-28 safety/planning validation failed; no transmission is allowed.",
            )
        rate = _float_param(parameters, "send_rate_msgs_per_sec", safety_guard.max_send_rate)
        duration = _float_param(parameters, "max_duration_seconds", safety_guard.max_duration_seconds)
        max_messages = min(_int_param(parameters, "max_messages", safety_guard.max_messages), int(rate * duration))
        return RunnerPlan(
            runner_name=self.runner_name,
            case_id=case.case_id,
            steps=[{
                "step": "uds28_bounded_execution_plan",
                "traffic_mode": str(parameters.get("traffic_mode") or "uds-targeted-isotp"),
                "arb_id_strategy": str(parameters.get("arbid_strategy") or "manual-range"),
                "generator_mode": str(parameters.get("generator_mode") or "transport-valid random"),
                "send_rate_msgs_per_sec": rate,
                "duration_seconds": duration,
                "max_messages": max_messages,
                "message": "Dry-run preview only. GUI armed execution uses the same bounded values and SafetyGuard gates.",
            }],
            note="UDS-28 is planned with bounded parameters.",
        )

    def run(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerResult:
        if case.case_id != "uds_28":
            return super().run(case, parameters, safety_guard)
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerResult(
                verdict="CONFIG_ERROR",
                rationale="UDS-28 safety/planning validation failed; no CAN request was sent.",
                evidence={"errors": dict(errors)},
            )
        plan = self.plan(case, parameters, safety_guard)
        return RunnerResult(
            verdict="NOT_IMPLEMENTED",
            rationale="UDS-28 direct runner is GUI-only in this build; CLI dry-run previews are supported and non-dry CLI is blocked before CAN open.",
            evidence={"plan": plan.as_dict()},
        )


class RobustnessRunner(_StubRunner):
    runner_name = "RobustnessRunner"

    def validate(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> dict[str, str]:
        errors = super().validate(case, parameters, safety_guard)
        if case.case_id != "uds_31":
            return errors
        try:
            payload = self.build_payload(case, parameters)
        except ValueError as exc:
            errors["request_payload"] = str(exc)
            return errors
        if not payload:
            errors["request_payload"] = "UDS-31 payload is required"
        payload_length = _int_param(parameters, "payload_length", 64)
        max_allowed = _int_param(parameters, "max_payload_length", 4095)
        if payload_length <= 0:
            errors["payload_length"] = "Payload length must be > 0."
        if payload_length > max_allowed:
            errors["payload_length"] = "Payload length exceeds configured max_payload_length."
        if len(payload) > 7 and not bool(parameters.get("isotp_enabled", True)):
            errors["isotp_enabled"] = "ISO-TP must be enabled for payloads larger than a single CAN frame."
        attempt_count = _int_param(parameters, "attempt_count", 1)
        if attempt_count <= 0:
            errors["attempt_count"] = "Attempt count must be > 0."
        if attempt_count > safety_guard.max_messages:
            errors["attempt_count"] = "Attempt count exceeds SafetyGuard max_messages."
        return errors

    def dry_run_preview(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> str:
        if case.case_id != "uds_31":
            return super().dry_run_preview(case, parameters, safety_guard)
        try:
            payload = self.build_payload(case, parameters)
            payload_text = spaced(payload[:64]) + (" ..." if len(payload) > 64 else "")
            target_service = self.target_service(parameters)
            meaning = self.target_service_meaning(target_service)
        except ValueError as exc:
            payload_text = f"<invalid: {exc}>"
            target_service = ""
            meaning = ""
        return "\n".join([
            f"Case: {case.case_id} - {case.title}",
            "Assessment scenario: UDS oversized payload / buffer robustness.",
            "UDS-31 is the test case ID, not necessarily service 0x31 RoutineControl.",
            f"Session flow: {parameters.get('session_flow') or '<none>'}",
            f"Target service: {target_service or '<invalid>'} {meaning or ''}".strip(),
            f"Payload length: {_int_param(parameters, 'payload_length', 64)}",
            f"Payload pattern: {parameters.get('payload_pattern') or 'random'}",
            f"Attempt count: {_int_param(parameters, 'attempt_count', 1)}",
            f"Final request sample: {payload_text}",
            "Operational limits: bounded single/bounded-attempt execution only.",
            "Assessment: no fixed NRC is assumed; verdict depends on safe rejection, crash/reset/no-response, and recovery evidence.",
        ])

    def plan(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerPlan:
        if case.case_id != "uds_31":
            return super().plan(case, parameters, safety_guard)
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerPlan(
                runner_name=self.runner_name,
                case_id=case.case_id,
                steps=[{"step": "validation_failed", "errors": dict(errors)}],
                implemented=True,
                note="UDS-31 validation failed; no transmission is allowed.",
            )
        payload = self.build_payload(case, parameters)
        return RunnerPlan(
            runner_name=self.runner_name,
            case_id=case.case_id,
            steps=[
                {"step": "session_flow", "session_flow": str(parameters.get("session_flow") or "")},
                {
                    "step": "bounded_oversized_payload_request",
                    "payload_sample": spaced(payload[:64]) + (" ..." if len(payload) > 64 else ""),
                    "payload_length": len(payload),
                    "attempt_count": _int_param(parameters, "attempt_count", 1),
                    "note": "Bounded attempt count; no unbounded fuzzing loop.",
                },
            ],
            implemented=True,
            note="UDS-31 runner builds bounded oversized/boundary UDS payloads.",
        )

    def run(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerResult:
        if case.case_id != "uds_31":
            return super().run(case, parameters, safety_guard)
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerResult("CONFIG_ERROR", "UDS-31 validation failed; no CAN request was sent.", {"errors": dict(errors)})
        return RunnerResult(
            "STUB",
            "RobustnessRunner requires the GUI transport caller for bounded UDS-31 execution.",
            {"plan": self.plan(case, parameters, safety_guard).as_dict(), "request_payload_sample": spaced(self.build_payload(case, parameters)[:64])},
        )

    def build_payload(self, case: TestCaseModel, parameters: dict[str, Any]) -> bytes:
        service_text = str(parameters.get("target_service") or "0x2E")
        resolved_service_text = self.target_service(parameters)
        service = int(resolved_service_text[2:], 16)
        payload_len = _int_param(parameters, "payload_length", 64)
        if payload_len <= 0:
            raise ValueError("Payload length must be > 0")
        oversized = self._pattern_bytes(parameters, payload_len)
        if service_text == "manual":
            prefix = parse_hex_bytes(parameters.get("manual_payload_prefix", ""))
            if not prefix:
                manual_service = _parse_hex_int(parameters.get("manual_service_id") or "0x22", "manual_service_id", 0xFF)
                prefix = bytes([manual_service])
            return prefix + oversized
        if service == 0x27:
            return bytes([0x27, _parse_byte_param(parameters, "subfunction", 0x02)]) + oversized
        if service == 0x2E:
            did = _parse_hex_int(parameters.get("did_hex") or "0xF190", "did_hex", 0xFFFF)
            return bytes([0x2E, (did >> 8) & 0xFF, did & 0xFF]) + oversized
        if service == 0x31:
            rid = _parse_hex_int(parameters.get("routine_identifier") or "0x0001", "routine_identifier", 0xFFFF)
            return bytes([0x31, _parse_byte_param(parameters, "subfunction", 0x01), (rid >> 8) & 0xFF, rid & 0xFF]) + oversized
        if service == 0x2F:
            did = _parse_hex_int(parameters.get("did_hex") or "0xF190", "did_hex", 0xFFFF)
            return bytes([0x2F, (did >> 8) & 0xFF, did & 0xFF, _parse_byte_param(parameters, "subfunction", 0x03)]) + oversized
        if service == 0x34:
            return bytes([0x34, _parse_byte_param(parameters, "data_format_identifier", 0x00), _parse_byte_param(parameters, "address_length_format_identifier", 0x44)]) + oversized
        if service == 0x36:
            return bytes([0x36, _parse_byte_param(parameters, "block_sequence_counter", 0x01)]) + oversized
        if service == 0x2C:
            did = _parse_hex_int(parameters.get("did_hex") or "0xF190", "did_hex", 0xFFFF)
            return bytes([0x2C, 0x02, (did >> 8) & 0xFF, did & 0xFF]) + oversized
        if service == 0x3D:
            return bytes([0x3D, _parse_byte_param(parameters, "address_length_format_identifier", 0x44)]) + oversized
        raise ValueError(f"Unsupported UDS-31 target service 0x{service:02X}")

    @staticmethod
    def target_service(parameters: dict[str, Any]) -> str:
        service_text = str(parameters.get("target_service") or "0x2E")
        if service_text == "manual":
            return f"0x{_parse_hex_int(parameters.get('manual_service_id') or '0x22', 'manual_service_id', 0xFF):02X}"
        return f"0x{_parse_hex_int(service_text, 'target_service', 0xFF):02X}"

    @staticmethod
    def target_service_meaning(service_text: str) -> str:
        return {
            "0x27": "SecurityAccess sendKey",
            "0x2E": "WriteDataByIdentifier",
            "0x31": "RoutineControl",
            "0x2F": "InputOutputControlByIdentifier",
            "0x34": "RequestDownload",
            "0x36": "TransferData",
            "0x3D": "WriteMemoryByAddress",
            "0x2C": "DynamicallyDefineDataIdentifier",
        }.get(service_text, "manual service")

    @staticmethod
    def _pattern_bytes(parameters: dict[str, Any], length: int) -> bytes:
        pattern = str(parameters.get("payload_pattern") or "random")
        if pattern == "zero-fill":
            return bytes([0x00] * length)
        if pattern == "FF-fill":
            return bytes([0xFF] * length)
        if pattern == "incremental":
            return bytes((idx & 0xFF) for idx in range(length))
        if pattern == "manual pattern":
            seed = parse_hex_bytes(parameters.get("manual_pattern_hex") or "")
            if not seed:
                raise ValueError("manual pattern requires manual_pattern_hex")
            return bytes(seed[idx % len(seed)] for idx in range(length))
        rng = __import__("random").Random(str(parameters.get("random_seed") or "uds31"))
        return bytes(rng.randrange(0, 256) for _ in range(length))


class CanPriorityFloodRunner(_StubRunner):
    runner_name = "CanPriorityFloodRunner"

    def validate(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> dict[str, str]:
        errors = super().validate(case, parameters, safety_guard)
        if case.case_id != "uds_32":
            return errors
        rate = _float_param(parameters, "send_rate_msgs_per_sec", safety_guard.max_send_rate)
        duration = _float_param(parameters, "max_duration_seconds", safety_guard.max_duration_seconds)
        max_frames = _int_param(parameters, "max_frames", safety_guard.max_messages)
        try:
            can_id = _parse_hex_int(parameters.get("can_id") or "0x000", "can_id", 0x1FFFFFFF)
        except ValueError as exc:
            errors["can_id"] = str(exc)
            can_id = 0
        if rate <= 0:
            errors["send_rate_msgs_per_sec"] = "Send rate must be > 0 msg/s."
        if duration <= 0:
            errors["max_duration_seconds"] = "Duration must be > 0 seconds."
        if max_frames <= 0:
            errors["max_frames"] = "Max frames must be > 0."
        if rate > safety_guard.max_send_rate:
            errors["send_rate_msgs_per_sec"] = "Send rate exceeds SafetyGuard max_send_rate."
        if duration > safety_guard.max_duration_seconds:
            errors["max_duration_seconds"] = "Duration exceeds SafetyGuard max_duration_seconds."
        if max_frames > safety_guard.max_messages:
            errors["max_frames"] = "Max frames exceeds SafetyGuard max_messages."
        if bool(parameters.get("is_extended_id", False)) is False and can_id > 0x7FF:
            errors["can_id"] = "Standard CAN ID must be <= 0x7FF."
        try:
            self.payload(parameters)
        except ValueError as exc:
            errors["manual_payload"] = str(exc)
        return errors

    def dry_run_preview(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> str:
        if case.case_id != "uds_32":
            base = super().dry_run_preview(case, parameters, safety_guard)
            return base + "\nScope: CAN bus-level availability/arbitration test, not a normal UDS service."
        rate = _float_param(parameters, "send_rate_msgs_per_sec", safety_guard.max_send_rate)
        duration = _float_param(parameters, "max_duration_seconds", safety_guard.max_duration_seconds)
        max_frames = min(_int_param(parameters, "max_frames", safety_guard.max_messages), int(rate * duration) if rate > 0 and duration > 0 else safety_guard.max_messages)
        delay_ms = 0 if rate <= 0 else 1000.0 / rate
        try:
            payload = spaced(self.payload(parameters))
        except ValueError as exc:
            payload = f"<invalid: {exc}>"
        return "\n".join([
            f"Case: {case.case_id} - {case.title}",
            "Assessment scenario: CAN bus-level availability/arbitration test, not a normal UDS service.",
            "Lower numeric CAN IDs have higher arbitration priority; 0x000 is highest priority in standard CAN.",
            f"CAN ID: {parameters.get('can_id') or '0x000'}",
            f"Extended ID: {bool(parameters.get('is_extended_id', False))}",
            f"Payload: {payload}",
            f"Send rate: {rate:g} msg/s",
            f"Inter-frame delay: {delay_ms:.0f} ms",
            f"Duration: {duration:g} s",
            f"Max frames: {max_frames}",
            f"Execution: {'armed bounded execution' if parameters.get('execution_mode') == 'armed_bounded_execution' else 'planning/dry-run only'}",
            "Operational limits: bounded frames only; stop on duration, max frames, bus error, or operator stop.",
            "Stop: stop on duration, max frames, bus error, or operator stop.",
            "Assessment: no fixed NRC is assumed; verdict depends on observed starvation, physical impact, and recovery evidence.",
        ])

    def plan(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerPlan:
        if case.case_id != "uds_32":
            return super().plan(case, parameters, safety_guard)
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerPlan(self.runner_name, case.case_id, [{"step": "validation_failed", "errors": dict(errors)}], True, "UDS-32 validation failed; no transmission is allowed.")
        return RunnerPlan(
            runner_name=self.runner_name,
            case_id=case.case_id,
            steps=[{
                "step": "bounded_can_priority_availability_plan",
                "can_id": str(parameters.get("can_id") or "0x000"),
                "payload": spaced(self.payload(parameters)),
                "send_rate_msgs_per_sec": _float_param(parameters, "send_rate_msgs_per_sec", safety_guard.max_send_rate),
                "duration_seconds": _float_param(parameters, "max_duration_seconds", safety_guard.max_duration_seconds),
                "max_frames": _int_param(parameters, "max_frames", safety_guard.max_messages),
            }],
            implemented=True,
            note="UDS-32 runner plans bounded CAN priority availability traffic.",
        )

    def run(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> RunnerResult:
        if case.case_id != "uds_32":
            return super().run(case, parameters, safety_guard)
        errors = self.validate(case, parameters, safety_guard)
        if errors:
            return RunnerResult("CONFIG_ERROR", "UDS-32 validation failed; no CAN frame was sent.", {"errors": dict(errors)})
        return RunnerResult(
            "NOT_IMPLEMENTED",
            "UDS-32 direct runner is GUI-only in this build; CLI dry-run previews are supported and non-dry CLI is blocked before CAN open.",
            {"plan": self.plan(case, parameters, safety_guard).as_dict()},
        )

    @staticmethod
    def payload(parameters: dict[str, Any]) -> bytes:
        pattern = str(parameters.get("payload_pattern") or "zero")
        if pattern in {"00 00 00 00 00 00 00 00", "zero", "zero-fill"}:
            return bytes([0x00] * 8)
        if pattern in {"FF FF FF FF FF FF FF FF", "ff", "FF-fill"}:
            return bytes([0xFF] * 8)
        if pattern == "incremental":
            return bytes(range(8))
        if pattern == "manual":
            payload = parse_hex_bytes(parameters.get("manual_payload") or "")
            if not 0 < len(payload) <= 8:
                raise ValueError("manual payload must contain 1..8 bytes")
            return payload
        rng = __import__("random").Random(str(parameters.get("random_seed") or "uds32"))
        return bytes(rng.randrange(0, 256) for _ in range(8))


RUNNER_INTERFACES = {
    "diagnostic_service": DiagnosticServiceRunner,
    "flood": FloodRunner,
    "robustness": RobustnessRunner,
    "can_priority_flood": CanPriorityFloodRunner,
}


def _preview_safety_line(case: TestCaseModel) -> str:
    if case.case_id == "uds_28":
        return "Operational limits: bounded DoS/availability traffic"
    if case.safety_level in {"destructive-diagnostic", "controlled-diagnostic"}:
        return "Execution: sends configured request and records ECU response"
    return "Safety: dry-run only"


def _float_param(parameters: dict[str, Any], key: str, default: float) -> float:
    try:
        return float(parameters.get(key, default))
    except (TypeError, ValueError):
        return default


def _int_param(parameters: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(float(parameters.get(key, default)))
    except (TypeError, ValueError):
        return default


def _parse_hex_int(value: Any, name: str, maximum: int) -> int:
    raw = str(value or "").strip().replace("_", "")
    if not raw:
        raise ValueError(f"{name} is required")
    try:
        parsed = int(raw, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hex") from exc
    if not 0 <= parsed <= maximum:
        raise ValueError(f"{name} must be between 0x0 and 0x{maximum:X}")
    return parsed


def _parse_byte_param(parameters: dict[str, Any], key: str, default: int) -> int:
    value = parameters.get(key)
    if value in (None, ""):
        return default
    return parse_byte(value)


def _uds28_preview(case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> str:
    traffic_mode = str(parameters.get("traffic_mode") or "uds-targeted-isotp")
    strategy = str(parameters.get("arbid_strategy") or "manual-range")
    rate = _float_param(parameters, "send_rate_msgs_per_sec", safety_guard.max_send_rate)
    duration = _float_param(parameters, "max_duration_seconds", safety_guard.max_duration_seconds)
    derived_messages = max(1, int(rate * duration)) if rate > 0 and duration > 0 else 0
    max_messages = min(_int_param(parameters, "max_messages", safety_guard.max_messages), derived_messages) if derived_messages else _int_param(parameters, "max_messages", safety_guard.max_messages)
    delay_ms = 0 if rate <= 0 else 1000.0 / rate
    tester_present = bool(parameters.get("tester_present_enabled", False)) and traffic_mode in {"uds-targeted-isotp", "mixed"}
    tester_present_interval = _float_param(parameters, "tester_present_interval_seconds", safety_guard.tester_present_interval_seconds)
    tester_present_count = int(duration // tester_present_interval) if tester_present and tester_present_interval > 0 else 0
    catalog_loaded = bool(parameters.get("catalog_file"))
    observed_count = _int_param(parameters, "observed_arbid_count", 0)
    non_existing_count = _int_param(parameters, "non_existing_sample_count", 0) if strategy == "mixed observed + non-existing" else _int_param(parameters, "gap_sample_count", 0) if strategy == "observed-range-with-gaps" else 0
    selected_count = len([item for item in str(parameters.get("selected_arbid") or "").replace(";", ",").split(",") if item.strip()])
    final_candidates = 1 if traffic_mode == "uds-targeted-isotp" else max(0, observed_count + selected_count + non_existing_count)
    if strategy == "manual-range":
        final_candidates = _int_param(parameters, "manual_range_candidate_count", final_candidates)
    generator_mode = str(parameters.get("generator_mode") or "transport-valid random")
    generator_notes = {
        "transport-valid random": "transport framing valid, payload content varies randomly",
        "UDS-shaped valid random": "valid-looking UDS structures where possible",
        "UDS-shaped invalid random": "malformed/boundary UDS payloads while transport remains valid",
        "mixed valid/invalid": "valid-looking and invalid-looking messages are mixed",
        "manual seed payload list": "analyst-provided seed payloads are repeated or mutated",
    }
    traffic_labels = {
        "uds-targeted-isotp": "UDS-targeted ISO-TP mode",
        "can-id-random-frame": "CAN-ID random frame mode",
        "mixed": "Mixed mode",
    }
    return "\n".join([
        f"Case: {case.case_id} - {case.title}",
        f"Traffic mode: {traffic_labels.get(traffic_mode, traffic_mode)}",
        f"Session flow: {parameters.get('session_flow') or '<none>'}",
        f"ArbID strategy: {strategy if traffic_mode != 'uds-targeted-isotp' else '<not used in UDS-targeted mode>'}",
        f"Catalog: {'loaded' if catalog_loaded else 'not loaded'}, observed count {observed_count}",
        f"Candidate ArbIDs: final candidate count {final_candidates}, non-existing count {non_existing_count}",
        f"Generator: {generator_mode} ({generator_notes.get(generator_mode, 'review generator settings')})",
        f"Send rate: {rate:g} msg/s",
        f"Inter-message delay: {delay_ms:.0f} ms",
        f"Duration: {duration:g} s",
        f"Max messages: {max_messages}",
        f"TesterPresent: {'enabled' if tester_present else 'disabled'}, interval {tester_present_interval:g}s, estimated count {tester_present_count} separate",
        f"Execution: {'armed bounded execution' if parameters.get('execution_mode') == 'armed_bounded_execution' else 'planning/dry-run only'}",
        _preview_safety_line(case),
        "Stop: Stop DoS button required; stop on duration, max messages, bus error, or operator stop.",
        "Assessment: no fixed NRC is assumed; verdict depends on degradation, bus stability, physical impact, and recovery.",
    ])


def make_modular_runner(kind: str) -> ModularRunner:
    try:
        return RUNNER_INTERFACES[kind]()
    except KeyError as exc:
        known = ", ".join(sorted(RUNNER_INTERFACES))
        raise ValueError(f"unknown modular runner kind '{kind}'. Known kinds: {known}") from exc
