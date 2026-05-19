from __future__ import annotations

import time
from collections import Counter
from typing import Any, Dict, List

from .base import CaseContext
from ..uds import UdsClient, UdsResult
from ..utils import bhex, parse_byte


def _record(ctx: CaseContext, step: str, result: UdsResult) -> None:
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


class SeedSamplerSameSession:
    """Repeated RequestSeed in the same opened diagnostic session."""

    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        cfg = ctx.raw_config
        session_flow = [parse_byte(x) for x in cfg.get("session_flow", ctx.target.session_flow)]
        if session_flow:
            ok, session_obs = client.open_session_flow(session_flow, strict=bool(cfg.get("strict_session", False)), delay=ctx.timing.post_session_delay)
            for step, result in session_obs:
                _record(ctx, step, result)
            if not ok:
                return 1

        seed_subfn = parse_byte(cfg.get("seed_subfn", 0x01))
        samples = int(cfg.get("samples", 10))
        delay = float(cfg.get("delay", ctx.timing.delay))
        seen = Counter()
        for i in range(1, samples + 1):
            result = client.request(bytes([0x27, seed_subfn]), step=f"seed-sample-{i}", frame_label="Seed")
            _record(ctx, f"seed-sample-{i}", result)
            if result.seed is not None:
                seen[bhex(result.seed)] += 1
            if delay > 0:
                time.sleep(delay)
        ctx.run_logger.event("seed_sample_summary", testcase=ctx.name, target=ctx.target.name, unique=len(seen), counts=dict(seen))
        return 0


class SeedSamplerCrossSession:
    """Request one seed per session boundary to compare cross-session seed behaviour."""

    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        cfg = ctx.raw_config
        seed_subfn = parse_byte(cfg.get("seed_subfn", 0x01))
        samples = int(cfg.get("samples", 10))
        session_flow = [parse_byte(x) for x in cfg.get("session_flow", ctx.target.session_flow)]
        boundary_flow = [parse_byte(x) for x in cfg.get("boundary_session_flow", [0x01])]
        delay = float(cfg.get("delay", ctx.timing.delay))
        seen = Counter()

        for i in range(1, samples + 1):
            if boundary_flow:
                ok, session_obs = client.open_session_flow(boundary_flow, strict=False, delay=ctx.timing.post_session_delay)
                for step, result in session_obs:
                    _record(ctx, f"boundary-{i}-{step}", result)
            if session_flow:
                ok, session_obs = client.open_session_flow(session_flow, strict=bool(cfg.get("strict_session", False)), delay=ctx.timing.post_session_delay)
                for step, result in session_obs:
                    _record(ctx, f"sample-{i}-{step}", result)
                if not ok:
                    return 1
            result = client.request(bytes([0x27, seed_subfn]), step=f"cross-seed-sample-{i}", frame_label="Seed")
            _record(ctx, f"cross-seed-sample-{i}", result)
            if result.seed is not None:
                seen[bhex(result.seed)] += 1
            if delay > 0:
                time.sleep(delay)
        ctx.run_logger.event("cross_seed_sample_summary", testcase=ctx.name, target=ctx.target.name, unique=len(seen), counts=dict(seen))
        return 0
