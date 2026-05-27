from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

from .caringcaribou_bridge import build_caringcaribou_command, run_caringcaribou, wants_caringcaribou
from .canio import open_bus
from .config import CanConfig, ConfigError, TargetConfig, TimingConfig, get_targets, get_testcases, load_config
from .isotp import IsoTp
from .logging_utils import ConsoleLog, RunLogger
from .registry import make_case
from .case_runners import make_modular_runner
from .evidence_schema import build_placeholder_evidence_record
from .safety import SafetyGuard
from .testcase_model import normalize_case_model
from .testcase_metadata import metadata_for_event, normalize_testcase_metadata, sort_testcases_by_report_order, test_id_label
from .uds import UdsClient
from .utils import can_id_hx, parse_byte, spaced


class Runner:
    def __init__(self, config: Mapping[str, Any], *, console: ConsoleLog, run_logger: RunLogger, dry_run: bool = False, authorized: bool = False) -> None:
        self.config = dict(config)
        self.can_cfg = CanConfig.from_dict(self.config.get("can"))
        self.timing = TimingConfig.from_dict(self.config.get("timing"))
        self.targets = get_targets(self.config, self.can_cfg)
        self.testcases = get_testcases(self.config)
        self.console = console
        self.run_logger = run_logger
        self.dry_run = dry_run
        self.authorized = authorized or bool((self.config.get("safety") or {}).get("authorized", False))

    @classmethod
    def from_files(cls, paths: Iterable[str | Path], **kwargs: Any) -> "Runner":
        return cls(load_config(paths), **kwargs)

    def selected_cases(self, names: list[str] | None = None) -> list[dict[str, Any]]:
        if not names:
            return sort_testcases_by_report_order(self.testcases)
        wanted = set(names)
        selected = [tc for tc in self.testcases if str(tc.get("name")) in wanted]
        missing = wanted - {str(tc.get("name")) for tc in selected}
        if missing:
            raise ConfigError(f"unknown testcase(s): {', '.join(sorted(missing))}")
        return sort_testcases_by_report_order(selected)

    def run(self, names: list[str] | None = None) -> int:
        selected = self.selected_cases(names)
        if not selected:
            raise ConfigError("no testcases selected")
        if self.dry_run:
            for tc in selected:
                tc = normalize_testcase_metadata(tc)
                target_name = str(tc.get("target", self.config.get("default_target", "default")))
                label = test_id_label(tc)
                target = self.targets.get(target_name)
                session_flow = tc.get("session_flow", target.session_flow if target else [])
                session_text = spaced(bytes(parse_byte(x) for x in session_flow)) if isinstance(session_flow, list) else str(session_flow or "")
                self.console.info(
                    "\n"
                    f"===== {label} — {tc.get('title', tc.get('name'))} =====\n"
                    f"Internal name: {tc.get('internal_name', tc.get('name', ''))}\n"
                    f"Display ID: {tc.get('display_id', tc.get('test_id', label))}\n"
                    f"Canonical ID: {tc.get('canonical_id', tc.get('name', ''))}\n"
                    f"Type: {tc.get('type', '')}\n"
                    f"Target: {target_name}\n"
                    f"TX/RX: {can_id_hx(target.txid) if target else ''} -> {can_id_hx(target.rxid) if target else ''}\n"
                    f"Session flow: {session_text}\n"
                    f"Risk property: {tc.get('risk_property', '')}\n"
                    f"Pass criteria: {_criteria_text(tc.get('pass_criteria'))}\n"
                    f"Fail criteria: {_criteria_text(tc.get('fail_criteria'))}"
                )
                if str(tc.get("type")) == "uds_access_control_probe":
                    for line in self._dry_run_access_control_probe(tc):
                        self.console.info(f"  [{label}] {line}")
                elif _is_modular_case(tc):
                    self.console.info(self._modular_preview(tc, target))
            return 0

        if not self.targets:
            raise ConfigError("at least one target is required")

        rc = 0
        native_cases: list[tuple[TargetConfig, dict[str, Any]]] = []
        try:
            for tc in selected:
                target_name = str(tc.get("target", self.config.get("default_target", "default")))
                if target_name not in self.targets:
                    raise ConfigError(f"testcase '{tc['name']}' references unknown target '{target_name}'")
                target = self.targets[target_name]
                merged_tc = normalize_testcase_metadata(tc)
                if str(merged_tc.get("case_id") or "") == "uds_28":
                    if not self.authorized:
                        raise ConfigError(
                            f"testcase '{merged_tc['name']}' requires manual confirmation; use --yes-i-am-authorized or safety.authorized=true"
                        )
                    raise ConfigError(
                        f"testcase '{merged_tc['name']}' CLI non-dry execution is not enabled; use GUI Armed bounded execution. "
                        "No CAN interface was opened."
                    )
                if str(merged_tc.get("case_id") or "") == "uds_32":
                    if not self.authorized:
                        raise ConfigError(
                            f"testcase '{merged_tc['name']}' requires manual confirmation; use --yes-i-am-authorized or safety.authorized=true"
                        )
                    raise ConfigError(
                        f"testcase '{merged_tc['name']}' CLI non-dry execution is not enabled; use GUI Armed bounded execution. "
                        "No CAN interface was opened."
                    )
                if _is_modular_placeholder(merged_tc):
                    rc = max(rc, self._run_modular_placeholder_one(target, merged_tc))
                elif wants_caringcaribou(merged_tc):
                    rc = max(rc, self._run_caringcaribou_one(target, merged_tc))
                else:
                    if _is_modular_case(merged_tc):
                        errors = self._preflight_modular_case(merged_tc)
                        if errors:
                            raise ConfigError(f"testcase '{merged_tc['name']}' failed modular preflight: {errors}")
                        guard = SafetyGuard.from_mapping(merged_tc.get("safety_guard", {}))
                        if guard.manual_confirm_required and not self.authorized:
                            raise ConfigError(
                                f"testcase '{merged_tc['name']}' requires manual confirmation; use --yes-i-am-authorized or safety.authorized=true"
                            )
                    native_cases.append((target, merged_tc))
            if native_cases:
                can_mod, bus = open_bus(self.can_cfg)
                try:
                    for target, merged_tc in native_cases:
                        merged_tc["_bus"] = bus
                        merged_tc["_can_module"] = can_mod
                        merged_tc["_authorized"] = True
                        case_rc = self._run_one(bus, can_mod, target, merged_tc)
                        rc = max(rc, case_rc)
                finally:
                    try:
                        bus.shutdown()
                    except Exception:
                        pass
        finally:
            self.run_logger.close()
        return rc

    def _run_caringcaribou_one(self, target: TargetConfig, tc: dict[str, Any]) -> int:
        label = test_id_label(tc)
        session_flow = tc.get("session_flow", target.session_flow)
        if isinstance(session_flow, list):
            session_text = spaced(bytes(parse_byte(x) for x in session_flow))
        else:
            session_text = str(session_flow or "")
        context = metadata_for_event(tc)
        context.update({
            "tx_id": can_id_hx(target.txid),
            "rx_id": can_id_hx(target.rxid),
            "session_flow": session_text,
            "engine": "caringcaribou",
        })
        self.run_logger.set_testcase_context(**context)
        self.console.set_test_context(label)
        self.console.info(
            "\n"
            f"===== {tc.get('display_name', tc.get('name'))} =====\n"
            f"Internal name: {tc['name']}\n"
            f"Type: {tc.get('type', '')}\n"
            f"Engine: CaringCaribou\n"
            f"Target: {target.name}\n"
            f"TX/RX: {can_id_hx(target.txid)} -> {can_id_hx(target.rxid)}\n"
            f"Session flow: {session_text}\n"
            f"Risk property: {tc.get('risk_property', '')}\n"
            f"Pass criteria: {_criteria_text(tc.get('pass_criteria'))}\n"
            f"Fail criteria: {_criteria_text(tc.get('fail_criteria'))}"
        )
        try:
            command = build_caringcaribou_command(tc, target, self.can_cfg)
        except Exception as exc:
            self.run_logger.event("caringcaribou_config_error", testcase=tc["name"], target=target.name, error=f"{type(exc).__name__}: {exc}")
            self.console.info(f"  ABORT CaringCaribou config error: {type(exc).__name__}: {exc}")
            self.console.set_test_context("")
            self.run_logger.clear_testcase_context()
            return 2

        self.console.info(f"  CaringCaribou: {command.description}")
        self.console.info("$ " + " ".join(command.argv))
        self.run_logger.event("caringcaribou_start", testcase=tc["name"], target=target.name, command=command.argv, description=command.description)

        def on_line(line: str) -> None:
            if not line:
                return
            self.console.info(line)
            self.run_logger.event("caringcaribou_output", testcase=tc["name"], target=target.name, line=line)

        try:
            rc = run_caringcaribou(command, cwd=str(Path.cwd()), line_callback=on_line)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            self.run_logger.event("caringcaribou_exception", testcase=tc["name"], target=target.name, error=f"{type(exc).__name__}: {exc}")
            self.console.info(f"  ABORT CaringCaribou error: {type(exc).__name__}: {exc}")
            rc = 1
        self.run_logger.event("caringcaribou_finished", testcase=tc["name"], target=target.name, exit_code=rc)
        self.console.info(f"  CaringCaribou finished exit_code={rc}")
        self.console.set_test_context("")
        self.run_logger.clear_testcase_context()
        return int(rc or 0)

    def _run_one(self, bus: Any, can_mod: Any, target: TargetConfig, tc: dict[str, Any]) -> int:
        label = test_id_label(tc)
        session_flow = tc.get("session_flow", target.session_flow)
        if isinstance(session_flow, list):
            session_text = spaced(bytes(parse_byte(x) for x in session_flow))
        else:
            session_text = str(session_flow or "")
        context = metadata_for_event(tc)
        context.update({
            "tx_id": can_id_hx(target.txid),
            "rx_id": can_id_hx(target.rxid),
            "session_flow": session_text,
        })
        self.run_logger.set_testcase_context(**context)
        self.console.set_test_context(label)
        self.console.info(
            "\n"
            f"===== {tc.get('display_name', tc.get('name'))} =====\n"
            f"Internal name: {tc['name']}\n"
            f"Type: {tc.get('type', '')}\n"
            f"Target: {target.name}\n"
            f"TX/RX: {can_id_hx(target.txid)} -> {can_id_hx(target.rxid)}\n"
            f"Session flow: {session_text}\n"
            f"Risk property: {tc.get('risk_property', '')}\n"
            f"Pass criteria: {_criteria_text(tc.get('pass_criteria'))}\n"
            f"Fail criteria: {_criteria_text(tc.get('fail_criteria'))}"
        )
        ext = self.can_cfg.extended_id if target.extended_id is None else target.extended_id
        transport = IsoTp(
            bus,
            can_mod,
            txid=target.txid,
            rxid=target.rxid,
            extended_id=bool(ext),
            pad=self.can_cfg.padding,
            fc_bs=self.timing.fc_bs,
            fc_stmin=self.timing.fc_stmin,
            request_stmin=self.timing.request_stmin,
            fc_wait_timeout=self.timing.fc_wait_timeout,
            log=self.console,
        )
        client = UdsClient(
            transport,
            timeout=self.timing.timeout,
            response_pending_timeout=self.timing.response_pending_timeout,
            drain_before_request=self.timing.drain_before_request,
            log=self.console,
        )
        from .cases.base import CaseContext

        ctx = CaseContext(name=str(tc["name"]), target=target, timing=self.timing, run_logger=self.run_logger, raw_config=tc)
        case = make_case(str(tc["type"]))
        try:
            case_rc = case.run(client, ctx)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            self.run_logger.event("testcase_exception", testcase=tc["name"], target=target.name, error=f"{type(exc).__name__}: {exc}")
            self.console.info(f"  ABORT testcase error: {type(exc).__name__}: {exc}")
            return 1
        finally:
            self.console.set_test_context("")
            self.run_logger.clear_testcase_context()
        return int(case_rc or 0)

    def _run_modular_placeholder_one(self, target: TargetConfig, tc: dict[str, Any]) -> int:
        label = test_id_label(tc)
        context = metadata_for_event(tc)
        session_flow = tc.get("session_flow", target.session_flow)
        session_text = spaced(bytes(parse_byte(x) for x in session_flow)) if isinstance(session_flow, list) else str(session_flow or "")
        context.update({
            "tx_id": can_id_hx(target.txid),
            "rx_id": can_id_hx(target.rxid),
            "session_flow": session_text,
            "engine": "modular_placeholder",
        })
        self.run_logger.set_testcase_context(**context)
        self.console.set_test_context(label)
        self.console.info(
            "\n"
            f"===== {tc.get('display_name', tc.get('name'))} =====\n"
            f"Internal name: {tc['name']}\n"
            f"Type: {tc.get('type', '')}\n"
            f"Engine: modular placeholder\n"
            f"Target: {target.name}\n"
            f"TX/RX: {can_id_hx(target.txid)} -> {can_id_hx(target.rxid)}\n"
            "Execution: NOT_IMPLEMENTED / STUB; no CAN, ISO-TP, CaringCaribou, or external command is opened."
        )
        runner = make_modular_runner(_modular_runner_kind(tc))
        case_model = normalize_case_model(tc)
        safety_guard = SafetyGuard.from_mapping(tc.get("safety_guard", {}))
        parameters = dict(tc.get("parameters") or {})
        result = runner.run(case_model, parameters, safety_guard)
        evidence = build_placeholder_evidence_record(
            target_profile={"name": target.name, "txid": can_id_hx(target.txid), "rxid": can_id_hx(target.rxid)},
            session_flow=session_text,
            request_payload=str(parameters.get("request_payload") or tc.get("default_payload") or ""),
            physical_observation_note=str(parameters.get("physical_observation_note") or ""),
            verdict=result.verdict,
            raw_log_path=str(self.run_logger.jsonl_path),
        )
        self.run_logger.event(
            "modular_placeholder_result",
            testcase=tc["name"],
            target=target.name,
            verdict=result.verdict,
            rationale=result.rationale,
            evidence_record=evidence.as_dict(),
            runner_kind=_modular_runner_kind(tc),
        )
        self.console.info(f"  {result.verdict}: {result.rationale}")
        self.console.set_test_context("")
        self.run_logger.clear_testcase_context()
        return 0

    def _modular_preview(self, tc: Mapping[str, Any], target: TargetConfig | None) -> str:
        runner = make_modular_runner(_modular_runner_kind(tc))
        case_model = normalize_case_model(tc)
        safety_guard = SafetyGuard.from_mapping(tc.get("safety_guard", {}))
        parameters = _modular_parameters(tc)
        target_note = f"target={target.name}" if target else "target=<not configured>"
        return f"  [{test_id_label(tc)}] {target_note}\n" + runner.dry_run_preview(case_model, parameters, safety_guard)

    def _preflight_modular_case(self, tc: Mapping[str, Any]) -> dict[str, str]:
        runner = make_modular_runner(_modular_runner_kind(tc))
        case_model = normalize_case_model(tc)
        safety_guard = SafetyGuard.from_mapping(tc.get("safety_guard", {}))
        return runner.validate(case_model, _modular_parameters(tc), safety_guard)

    def _dry_run_access_control_probe(self, tc: Mapping[str, Any]) -> list[str]:
        from .utils import parse_byte, parse_hex_bytes, spaced

        lines: list[str] = []
        session_flow = [parse_byte(x) for x in tc.get("session_flow", [])]
        for subfn in session_flow:
            lines.append(f"session TX {spaced(bytes([0x10, subfn]))}")
        requests = tc.get("requests", [])
        if not isinstance(requests, list):
            lines.append("requests: <invalid; expected list>")
            return lines
        for idx, req in enumerate(requests, start=1):
            if not isinstance(req, Mapping):
                lines.append(f"request-{idx}: <invalid; expected mapping>")
                continue
            step = str(req.get("step", f"request-{idx}"))
            payload = parse_hex_bytes(req.get("payload", ""))
            service = parse_byte(req.get("service", payload[0] if payload else 0))
            if payload and service != payload[0]:
                lines.append(f"{step}: <invalid; service 0x{service:02X} does not match payload SID 0x{payload[0]:02X}>")
                continue
            lines.append(f"{step} service=0x{service:02X} TX {spaced(payload)}")
        return lines

    def _preflight_access_control_probe(self, tc: Mapping[str, Any]) -> None:
        from .utils import parse_byte, parse_hex_bytes

        requests = tc.get("requests", [])
        if not isinstance(requests, list) or not requests:
            raise ConfigError(f"testcase '{tc.get('name')}' requires a non-empty requests list")
        services: list[int] = []
        for idx, req in enumerate(requests, start=1):
            if not isinstance(req, Mapping):
                raise ConfigError(f"testcase '{tc.get('name')}' request #{idx} must be a mapping")
            payload = parse_hex_bytes(req.get("payload", ""))
            if not payload:
                raise ConfigError(f"testcase '{tc.get('name')}' request #{idx} requires a non-empty payload")
            service = parse_byte(req.get("service", payload[0]))
            if service != payload[0]:
                raise ConfigError(f"testcase '{tc.get('name')}' request #{idx} service 0x{service:02X} does not match payload SID 0x{payload[0]:02X}")
            services.append(service)


def _criteria_text(value: Any) -> str:
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    return str(value or "")


def _is_modular_placeholder(tc: Mapping[str, Any]) -> bool:
    return _is_modular_case(tc) and not bool(tc.get("implemented", False))


def _is_modular_case(tc: Mapping[str, Any]) -> bool:
    return str(tc.get("type") or "") in {"diagnostic_service", "flood", "robustness", "can_priority_flood"}


def _modular_runner_kind(tc: Mapping[str, Any]) -> str:
    case_type = str(tc.get("type") or "")
    if case_type in {"diagnostic_service", "flood", "robustness", "can_priority_flood"}:
        return case_type
    return "diagnostic_service"


def _modular_parameters(tc: Mapping[str, Any]) -> dict[str, Any]:
    parameters = dict(tc.get("parameters") or {})
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
        if key in tc:
            parameters[key] = tc[key]
    return parameters
