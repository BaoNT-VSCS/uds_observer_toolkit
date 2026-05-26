from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .safety import SafetyGuard, validate_safety_guard
from .testcase_model import TestCaseModel


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
            f"Safety guard: {safety_guard.as_dict()}",
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


class FloodRunner(_StubRunner):
    runner_name = "FloodRunner"


class RobustnessRunner(_StubRunner):
    runner_name = "RobustnessRunner"


class CanPriorityFloodRunner(_StubRunner):
    runner_name = "CanPriorityFloodRunner"

    def dry_run_preview(self, case: TestCaseModel, parameters: dict[str, Any], safety_guard: SafetyGuard) -> str:
        base = super().dry_run_preview(case, parameters, safety_guard)
        return base + "\nScope: CAN bus-level availability/arbitration test, not a normal UDS service."


RUNNER_INTERFACES = {
    "diagnostic_service": DiagnosticServiceRunner,
    "flood": FloodRunner,
    "robustness": RobustnessRunner,
    "can_priority_flood": CanPriorityFloodRunner,
}


def make_modular_runner(kind: str) -> ModularRunner:
    try:
        return RUNNER_INTERFACES[kind]()
    except KeyError as exc:
        known = ", ".join(sorted(RUNNER_INTERFACES))
        raise ValueError(f"unknown modular runner kind '{kind}'. Known kinds: {known}") from exc
