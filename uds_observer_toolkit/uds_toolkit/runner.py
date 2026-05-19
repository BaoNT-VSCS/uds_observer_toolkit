from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

from .canio import open_bus
from .config import CanConfig, ConfigError, TargetConfig, TimingConfig, get_targets, get_testcases, load_config
from .isotp import IsoTp
from .logging_utils import ConsoleLog, RunLogger
from .registry import make_case
from .uds import UdsClient


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
            return self.testcases
        wanted = set(names)
        selected = [tc for tc in self.testcases if str(tc.get("name")) in wanted]
        missing = wanted - {str(tc.get("name")) for tc in selected}
        if missing:
            raise ConfigError(f"unknown testcase(s): {', '.join(sorted(missing))}")
        return selected

    def run(self, names: list[str] | None = None) -> int:
        selected = self.selected_cases(names)
        if not selected:
            raise ConfigError("no testcases selected")
        if self.dry_run:
            for tc in selected:
                target_name = str(tc.get("target", self.config.get("default_target", "default")))
                self.console.info(f"DRY-RUN testcase={tc['name']} type={tc['type']} target={target_name}")
            return 0

        if any(str(tc.get("type", "")).endswith("fuzzer") for tc in selected) and not self.authorized:
            raise ConfigError("fuzzing testcases require safety.authorized: true or CLI --yes-i-am-authorized")


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
                merged_tc = dict(tc)
                merged_tc["_bus"] = bus
                merged_tc["_can_module"] = can_mod
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
        self.console.info(f"\nTESTCASE {tc['name']} ({tc['type']}) target={target.name} tx={target.txid:X} rx={target.rxid:X}")
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
        return int(case_rc or 0)
