from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol

from ..config import TargetConfig, TimingConfig
from ..logging_utils import RunLogger
from ..uds import UdsClient


@dataclass
class CaseContext:
    name: str
    target: TargetConfig
    timing: TimingConfig
    run_logger: RunLogger
    raw_config: Dict[str, Any]


class TestCase(Protocol):
    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        ...
