from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Protocol

from ..config import TargetConfig, TimingConfig
from ..logging_utils import RunLogger
from ..uds import UdsClient, UdsResult
from ..utils import parse_byte


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


def record_result(ctx: CaseContext, step: str, result: UdsResult) -> None:
    ctx.run_logger.result(
        testcase=ctx.name,
        target=ctx.target.name,
        step=step,
        request=result.request,
        response=result.response,
        status=result.status,
        nrc=result.nrc,
        note=result.note or result.exception,
    )


def configured_session_flow(ctx: CaseContext, key: str = "session_flow") -> list[int]:
    return [parse_byte(x) for x in ctx.raw_config.get(key, ctx.target.session_flow)]


def open_and_record_session(
    client: UdsClient,
    ctx: CaseContext,
    *,
    session_flow: list[int] | None = None,
    strict: bool | None = None,
    step_prefix: str = "",
) -> bool:
    flow = configured_session_flow(ctx) if session_flow is None else session_flow
    if not flow:
        return True
    use_strict = bool(ctx.raw_config.get("strict_session", False)) if strict is None else strict
    ok, observations = client.open_session_flow(flow, strict=use_strict, delay=ctx.timing.post_session_delay)
    for step, result in observations:
        record_result(ctx, f"{step_prefix}{step}", result)
    return ok
