from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .evidence_schema import EvidenceSchema, EVIDENCE_SCHEMA_FIELDS
from .safety import SafetyGuard
from .testcase_model import TestCaseModel


SECTION11_YAML = Path(__file__).resolve().parents[1] / "testcases" / "uds_section11_robustness.yaml"


@dataclass(frozen=True)
class ParameterDefinition:
    key: str
    label: str
    kind: str = "text"
    default: Any = ""
    required: bool = False
    help: str = ""
    choices: tuple[dict[str, Any], ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ParameterDefinition":
        return cls(
            key=str(raw.get("key", "")),
            label=str(raw.get("label") or raw.get("key") or ""),
            kind=str(raw.get("kind", "text")),
            default=copy.deepcopy(raw.get("default", "")),
            required=bool(raw.get("required", False)),
            help=str(raw.get("help", "")),
            choices=tuple(dict(item) for item in raw.get("choices", []) if isinstance(item, Mapping)),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "kind": self.kind,
            "default": copy.deepcopy(self.default),
            "required": self.required,
            "help": self.help,
            "choices": [copy.deepcopy(choice) for choice in self.choices],
        }


@dataclass(frozen=True)
class ModularCaseDefinition:
    model: TestCaseModel
    runner_kind: str
    parameters: tuple[ParameterDefinition, ...] = ()
    safety_guard: SafetyGuard = field(default_factory=SafetyGuard)
    evidence_schema: EvidenceSchema = field(default_factory=EvidenceSchema)
    implemented: bool = False
    source_yaml: str = ""
    display_id: str = ""
    canonical_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_model": self.model.as_dict(),
            "runner_kind": self.runner_kind,
            "parameters": [param.as_dict() for param in self.parameters],
            "safety_guard": self.safety_guard.as_dict(),
            "evidence_schema": self.evidence_schema.as_dict(),
            "implemented": self.implemented,
            "source_yaml": self.source_yaml,
            "display_id": self.display_id,
            "canonical_id": self.canonical_id,
        }


def get_modular_case_definitions(path: str | Path = SECTION11_YAML) -> list[ModularCaseDefinition]:
    source = Path(path)
    if source.exists():
        return [_definition_from_yaml_case(raw, source) for raw in _load_yaml_cases(source)]
    # Fallback keeps the GUI usable if a packaged YAML file is accidentally absent.
    return _fallback_definitions()


def get_modular_case_registry(path: str | Path = SECTION11_YAML) -> dict[str, ModularCaseDefinition]:
    return {case.model.case_id: case for case in get_modular_case_definitions(path)}


def _load_yaml_cases(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    cases = data.get("testcases", [])
    if not isinstance(cases, list):
        raise ValueError(f"{path} must contain a testcases list")
    out: list[dict[str, Any]] = []
    for idx, item in enumerate(cases, 1):
        if not isinstance(item, dict):
            raise ValueError(f"{path} testcase #{idx} must be a mapping")
        out.append(item)
    return out


def _definition_from_yaml_case(raw: Mapping[str, Any], source: Path) -> ModularCaseDefinition:
    case_id = str(raw.get("case_id") or raw.get("test_id") or raw.get("name") or "")
    model = TestCaseModel(
        case_id=case_id,
        title=str(raw.get("title") or case_id),
        category=str(raw.get("category") or "UDS Test Cases"),
        risk_property=str(raw.get("risk_property") or ""),
        service_id=str(raw.get("service_id") or raw.get("service") or ""),
        default_payload=str(raw.get("default_payload") or ""),
        parameters=copy.deepcopy(dict(raw.get("parameters") or {})),
        preconditions=[str(item) for item in raw.get("preconditions", [])],
        safety_level=str(raw.get("safety_level") or "framework-placeholder"),
        expected_behavior=str(raw.get("expected_behavior") or ""),
        pass_criteria=[str(item) for item in raw.get("pass_criteria", [])],
        fail_criteria=[str(item) for item in raw.get("fail_criteria", [])],
        evidence_fields=[str(item) for item in raw.get("evidence_fields", EVIDENCE_SCHEMA_FIELDS)],
    )
    return ModularCaseDefinition(
        model=model,
        runner_kind=_runner_kind_from_type(str(raw.get("type") or "")),
        parameters=tuple(ParameterDefinition.from_mapping(item) for item in raw.get("ui_parameters", [])),
        safety_guard=SafetyGuard.from_mapping(raw.get("safety_guard", {})),
        evidence_schema=EvidenceSchema(tuple(model.evidence_fields or EVIDENCE_SCHEMA_FIELDS)),
        implemented=bool(raw.get("implemented", False)),
        source_yaml=(Path("testcases") / source.name).as_posix(),
        display_id=str(raw.get("display_id") or raw.get("test_id") or case_id),
        canonical_id=str(raw.get("canonical_id") or raw.get("name") or case_id),
    )


def _runner_kind_from_type(case_type: str) -> str:
    if case_type in {"diagnostic_service", "arbid_range_scan", "flood", "robustness", "can_priority_flood"}:
        return case_type
    return "diagnostic_service"


def _fallback_definitions() -> list[ModularCaseDefinition]:
    ids = [
        ("uds_26", "UDS-26 Diagnostic Service Placeholder", "diagnostic_service"),
        ("uds_27", "UDS-27 Diagnostic Service Placeholder", "diagnostic_service"),
        ("uds_28", "UDS-28 Manual Arbitration ID Range Scan", "arbid_range_scan"),
        ("uds_29", "UDS-29 CommunicationControl 0x28 While Operational", "flood"),
        ("uds_30", "UDS-30 ECU Reset 0x11 While Operational", "robustness"),
        ("uds_31", "UDS-31 Oversized Payload / Buffer Robustness", "robustness"),
        ("uds_32", "UDS-32 CAN Priority Flood / Bus Availability Placeholder", "can_priority_flood"),
    ]
    out: list[ModularCaseDefinition] = []
    for case_id, title, runner_kind in ids:
        model = TestCaseModel(
            case_id=case_id,
            title=title,
            category="UDS Test Cases",
            risk_property="Fallback placeholder metadata; YAML source was not found.",
            service_id="",
            default_payload="<placeholder>",
            parameters={"session_flow": "03", "request_payload": "", "physical_observation_note": ""},
            preconditions=["Execution is currently stubbed and performs no CAN transmission."],
            safety_level="framework-placeholder",
            expected_behavior="Fallback placeholder is visible; restore testcases/uds_section11_robustness.yaml.",
            pass_criteria=["Framework loads placeholder metadata without sending CAN frames."],
            fail_criteria=["Framework attempts transmission before implementation."],
            evidence_fields=list(EVIDENCE_SCHEMA_FIELDS),
        )
        out.append(ModularCaseDefinition(model=model, runner_kind=runner_kind, source_yaml="<fallback>"))
    return out
