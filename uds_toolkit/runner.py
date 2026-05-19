from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

from .canio import open_bus
from .config import CanConfig, ConfigError, TargetConfig, TimingConfig, get_targets, get_testcases, load_config
from .isotp import IsoTp
from .logging_utils import ConsoleLog, RunLogger
from .registry import make_case
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
                    f"Type: {tc.get('type', '')}\n"
                    f"Target: {target_name}\n"
                    f"TX/RX: {can_id_hx(target.txid) if target else ''} -> {can_id_hx(target.rxid) if target else ''}\n"
                    f"Session flow: {session_text}\n"
                    f"Effective parameters: {tc.get('_effective_parameters', {})}\n"
                    f"Safety: {tc.get('safety_level', '')}\n"
                    "Dry run: True"
                )
                if str(tc.get("type")) == "uds_access_control_probe":
                    for line in self._dry_run_access_control_probe(tc):
                        self.console.info(f"  [{label}] {line}")
            return 0

        if any(str(tc.get("type", "")).endswith("fuzzer") for tc in selected) and not self.authorized:
            raise ConfigError("fuzzing testcases require safety.authorized: true or CLI --yes-i-am-authorized")
        for tc in selected:
            if str(tc.get("type", "")) == "uds_access_control_probe":
                self._preflight_access_control_probe(tc)


        if not self.targets:
            raise ConfigError("at least one target is required")

        can_mod, bus = open_bus(self.can_cfg)
        rc = 0
        try:
            for tc in selected:
                target_name = str(tc.get("target", self.config.get("default_target", "default")))
                if target_name not in self.targets:
                    raise ConfigError(f"testcase '{tc['name']}' references unknown target '{target_name}'")
                target = self.targets[target_name]
                merged_tc = normalize_testcase_metadata(tc)
                merged_tc["_bus"] = bus
                merged_tc["_can_module"] = can_mod
                merged_tc["_authorized"] = self.authorized
                case_rc = self._run_one(bus, can_mod, target, merged_tc)
                rc = max(rc, case_rc)
        finally:
            self.run_logger.close()
            try:
                bus.shutdown()
            except Exception:
                pass
        return rc

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
            f"Effective parameters: {tc.get('_effective_parameters', {})}\n"
            f"Safety: {tc.get('safety_level', '')}\n"
            f"Dry run: {self.dry_run}"
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
        from .cases.access_control import AUTH_REFUSAL, DESTRUCTIVE_REFUSAL, DESTRUCTIVE_SERVICES
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
        if any(service in DESTRUCTIVE_SERVICES for service in services) and not bool(tc.get("destructive_confirm", False)):
            raise ConfigError(DESTRUCTIVE_REFUSAL)
        if not self.authorized:
            raise ConfigError(AUTH_REFUSAL)
