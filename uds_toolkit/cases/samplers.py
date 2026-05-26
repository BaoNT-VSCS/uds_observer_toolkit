from __future__ import annotations

import time
from collections import Counter

from .base import CaseContext, open_and_record_session, record_result
from ..uds import UdsClient
from ..utils import bhex, parse_byte


class SeedSamplerSameSession:
    """Repeated RequestSeed in the same opened diagnostic session."""

    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        cfg = ctx.raw_config
        if not open_and_record_session(client, ctx):
            return 1

        seed_subfn = parse_byte(cfg.get("seed_subfn", 0x01))
        samples = int(cfg.get("samples", 10))
        delay = float(cfg.get("delay", ctx.timing.delay))
        seen = Counter()
        for i in range(1, samples + 1):
            result = client.request(bytes([0x27, seed_subfn]), step=f"seed-sample-{i}", frame_label="Seed")
            record_result(ctx, f"seed-sample-{i}", result)
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
                open_and_record_session(client, ctx, session_flow=boundary_flow, strict=False, step_prefix=f"boundary-{i}-")
            if session_flow and not open_and_record_session(client, ctx, session_flow=session_flow, step_prefix=f"sample-{i}-"):
                return 1
            result = client.request(bytes([0x27, seed_subfn]), step=f"cross-seed-sample-{i}", frame_label="Seed")
            record_result(ctx, f"cross-seed-sample-{i}", result)
            if result.seed is not None:
                seen[bhex(result.seed)] += 1
            if delay > 0:
                time.sleep(delay)
        ctx.run_logger.event("cross_seed_sample_summary", testcase=ctx.name, target=ctx.target.name, unique=len(seen), counts=dict(seen))
        return 0
