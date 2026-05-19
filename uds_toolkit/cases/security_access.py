from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

from .base import CaseContext
from ..seedkey import default_send_key_subfn, resolve_key
from ..uds import UdsClient, UdsResult, parse_uds_response
from ..utils import parse_byte, parse_hex_bytes, spaced


SECURITY_MODES = {
    "key_without_seed",
    "seed_timeout_key",
    "one_seed_many_keys",
    "seed_key_exchange_loop",
    "penalty_then_seed",
    "multi_seed_response",
    "request_seed_only",
}


def _cfg(ctx: CaseContext, key: str, default: Any = None) -> Any:
    return ctx.raw_config.get(key, default)


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


class SecurityAccessCase:
    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        mode = str(_cfg(ctx, "security_mode", _cfg(ctx, "mode", "request_seed_only"))).replace("-", "_")
        if mode not in SECURITY_MODES:
            raise ValueError(f"unsupported security_access mode: {mode}")

        session_flow = [parse_byte(x) for x in _cfg(ctx, "session_flow", ctx.target.session_flow)]
        strict_session = bool(_cfg(ctx, "strict_session", False))
        observations: List[Tuple[str, UdsResult]] = []

        if session_flow:
            ok, session_obs = client.open_session_flow(session_flow, strict=strict_session, delay=ctx.timing.post_session_delay)
            observations.extend(session_obs)
            for step, result in session_obs:
                _record(ctx, step, result)
            if not ok:
                return 1

        seed_subfn = parse_byte(_cfg(ctx, "seed_subfn", 0x01))
        key_subfn = parse_byte(_cfg(ctx, "key_subfn", default_send_key_subfn(seed_subfn)))
        attempts = int(_cfg(ctx, "attempts", 1))
        delay = float(_cfg(ctx, "delay", ctx.timing.delay))
        key_delay = float(_cfg(ctx, "key_delay", 0.05))
        key_policy = str(_cfg(ctx, "key_policy", "format-random"))
        explicit_key = parse_hex_bytes(_cfg(ctx, "key_hex", "")) or None
        pattern_byte = parse_byte(_cfg(ctx, "pattern_byte", 0xAA))
        stop_on_positive_unlock = bool(_cfg(ctx, "stop_on_positive_unlock", True))

        if mode == "request_seed_only":
            result = client.request(bytes([0x27, seed_subfn]), step="request-seed", frame_label="Seed")
            _record(ctx, "request-seed", result)
            return 0 if result.response else 1

        if mode == "key_without_seed":
            key, why = resolve_key(seed=None, seed_subfn=seed_subfn, policy=key_policy, explicit_key=explicit_key, pattern_byte=pattern_byte)
            if key_delay > 0:
                time.sleep(key_delay)
            result = client.request(bytes([0x27, key_subfn]) + key, step="send-key-without-seed", frame_label="SendKey")
            _record(ctx, "send-key-without-seed", result)
            return _rc_for_mode(mode, [("send-key-without-seed", result)])

        if mode == "seed_timeout_key":
            seed_result = client.request(bytes([0x27, seed_subfn]), step="request-seed-before-timeout", frame_label="Seed")
            _record(ctx, "request-seed-before-timeout", seed_result)
            wait_s = float(_cfg(ctx, "s3_wait", 6.0))
            time.sleep(max(0.0, wait_s))
            policy = _policy_or_fallback(seed_result.seed, key_policy)
            key, why = resolve_key(seed=seed_result.seed, seed_subfn=seed_subfn, policy=policy, explicit_key=explicit_key, pattern_byte=pattern_byte)
            if key_delay > 0:
                time.sleep(key_delay)
            key_result = client.request(bytes([0x27, key_subfn]) + key, step="send-key-after-timeout", frame_label="SendKey")
            _record(ctx, "send-key-after-timeout", key_result)
            return _rc_for_mode(mode, [("request-seed-before-timeout", seed_result), ("send-key-after-timeout", key_result)])

        if mode == "one_seed_many_keys":
            seed_result = client.request(bytes([0x27, seed_subfn]), step="request-seed-once", frame_label="Seed")
            _record(ctx, "request-seed-once", seed_result)
            policy = _policy_or_fallback(seed_result.seed, key_policy)
            observations2: List[Tuple[str, UdsResult]] = [("request-seed-once", seed_result)]
            for i in range(1, attempts + 1):
                key, why = resolve_key(seed=seed_result.seed, seed_subfn=seed_subfn, policy=policy, explicit_key=explicit_key, pattern_byte=pattern_byte)
                if key_delay > 0:
                    time.sleep(key_delay)
                step = f"key-attempt-{i}"
                result = client.request(bytes([0x27, key_subfn]) + key, step=step, frame_label="SendKey")
                _record(ctx, step, result)
                observations2.append((step, result))
                if stop_on_positive_unlock and result.positive:
                    break
                if delay > 0:
                    time.sleep(delay)
            return _rc_for_mode(mode, observations2)

        if mode == "seed_key_exchange_loop":
            observations2: List[Tuple[str, UdsResult]] = []
            for i in range(1, attempts + 1):
                seed_step = f"exchange-{i}-request-seed"
                seed_result = client.request(bytes([0x27, seed_subfn]), step=seed_step, frame_label="Seed")
                _record(ctx, seed_step, seed_result)
                observations2.append((seed_step, seed_result))
                policy = _policy_or_fallback(seed_result.seed, key_policy)
                key, why = resolve_key(seed=seed_result.seed, seed_subfn=seed_subfn, policy=policy, explicit_key=explicit_key, pattern_byte=pattern_byte)
                if key_delay > 0:
                    time.sleep(key_delay)
                key_step = f"exchange-{i}-send-key"
                key_result = client.request(bytes([0x27, key_subfn]) + key, step=key_step, frame_label="SendKey")
                _record(ctx, key_step, key_result)
                observations2.append((key_step, key_result))
                if stop_on_positive_unlock and key_result.positive:
                    break
                if delay > 0:
                    time.sleep(delay)
            return _rc_for_mode(mode, observations2)

        if mode == "penalty_then_seed":
            # Reuse exchange loop as penalty trigger, then immediately request a seed.
            trigger_cfg = dict(ctx.raw_config)
            trigger_cfg["mode"] = "seed_key_exchange_loop"
            nested_ctx = CaseContext(ctx.name, ctx.target, ctx.timing, ctx.run_logger, trigger_cfg)
            SecurityAccessCase().run(client, nested_ctx)
            probe_delay = float(_cfg(ctx, "penalty_probe_delay", 0.05))
            if probe_delay > 0:
                time.sleep(probe_delay)
            probe = client.request(bytes([0x27, seed_subfn]), step="penalty-mode-request-seed-probe", frame_label="Seed")
            _record(ctx, "penalty-mode-request-seed-probe", probe)
            return 0 if probe.response else 1

        if mode == "multi_seed_response":
            capture_window = float(_cfg(ctx, "capture_window", 1.0))
            first = client.request(bytes([0x27, seed_subfn]), step="single-request-seed", frame_label="Seed")
            _record(ctx, "single-request-seed", first)
            deadline = time.monotonic() + max(0.0, capture_window)
            idx = 1
            while time.monotonic() < deadline:
                try:
                    payload = client.transport.recv_payload(timeout=min(client.timeout, max(0.0, deadline - time.monotonic())), frame_label="ExtraSeed")
                except TimeoutError:
                    break
                except Exception as exc:
                    ctx.run_logger.event("extra_capture_error", testcase=ctx.name, target=ctx.target.name, error=f"{type(exc).__name__}: {exc}")
                    break
                result = parse_uds_response(payload, bytes([0x27, seed_subfn]))
                step = f"extra-positive-seed-{idx}"
                _record(ctx, step, result)
                idx += 1
            return 0

        raise AssertionError(mode)


def _policy_or_fallback(seed: bytes | None, policy: str) -> str:
    if seed is None and policy in {"valid", "invalid-bitflip"}:
        return "format-random"
    return policy


def _rc_for_mode(mode: str, observations: List[Tuple[str, UdsResult]]) -> int:
    # Exit code is operational, not a security verdict: 0 means the testcase ran.
    # Suspicious findings are in summary.csv/events.jsonl.
    return 0 if observations else 1
