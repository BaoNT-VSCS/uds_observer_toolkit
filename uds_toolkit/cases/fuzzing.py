from __future__ import annotations

import time

from .base import CaseContext, open_and_record_session, record_result
from ..uds import UdsClient
from ..utils import can_id_hx, parse_byte, parse_can_id, parse_hex_bytes, parse_int_range, pad8


class ServiceFuzzer:
    """Basic UDS service probe for one known request/response target.

    Default probe is a one-byte request [SID]. If an ECU replies with NRC 0x11,
    the service is likely not supported in that session. Other NRCs are useful
    observations, for example 0x13 can mean the service exists but the request
    format is incomplete.
    """

    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        cfg = ctx.raw_config
        if not open_and_record_session(client, ctx):
            return 1

        services = parse_int_range(cfg.get("services", "0x10-0x3E"), item_parser=parse_byte, max_items=int(cfg.get("max_items", 256)))
        delay = float(cfg.get("delay", ctx.timing.delay))
        stop_on_positive = bool(cfg.get("stop_on_positive", False))
        for sid in services:
            result = client.request(bytes([sid]), step=f"service-{sid:02X}", frame_label="ServiceProbe", check_subfn=False)
            record_result(ctx, f"service-{sid:02X}", result)
            if stop_on_positive and result.positive:
                break
            if delay > 0:
                time.sleep(delay)
        return 0


class SubserviceFuzzer:
    """Basic sub-function probe for a known UDS service."""

    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        cfg = ctx.raw_config
        if not open_and_record_session(client, ctx):
            return 1

        service = parse_byte(cfg.get("service", 0x10))
        subfunctions = parse_int_range(cfg.get("subfunctions", "0x00-0x7F"), item_parser=parse_byte, max_items=int(cfg.get("max_items", 256)))
        delay = float(cfg.get("delay", ctx.timing.delay))
        suppress_bit = bool(cfg.get("suppress_positive_response_bit", False))
        for sub in subfunctions:
            subfn = sub | 0x80 if suppress_bit else sub
            result = client.request(bytes([service, subfn]), step=f"subfn-{service:02X}-{subfn:02X}", frame_label="SubfnProbe")
            record_result(ctx, f"subfn-{service:02X}-{subfn:02X}", result)
            if delay > 0:
                time.sleep(delay)
        return 0


class PayloadFuzzer:
    """Send explicit UDS payloads to a known target.

    This is useful for controlled regression cases where every payload is listed
    in YAML. It is intentionally not a mutational fuzzer.
    """

    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        cfg = ctx.raw_config
        if not open_and_record_session(client, ctx):
            return 1

        payloads = cfg.get("payloads", [])
        if not isinstance(payloads, list) or not payloads:
            raise ValueError("payload_fuzzer requires payloads: ['10 03', '27 01', ...]")
        delay = float(cfg.get("delay", ctx.timing.delay))
        for idx, payload_text in enumerate(payloads, start=1):
            payload = parse_hex_bytes(payload_text)
            if not payload:
                continue
            result = client.request(payload, step=f"payload-{idx}", frame_label="PayloadProbe", check_subfn=False)
            record_result(ctx, f"payload-{idx}", result)
            if delay > 0:
                time.sleep(delay)
        return 0


class ArbIdFuzzer:
    """Raw arbitration-ID discovery using an ISO-TP SingleFrame payload.

    The runner passes the already-open raw bus via ctx.raw_config['_bus'] and
    ctx.raw_config['_can_module']. This mode does not require a known rxid.
    """

    def run(self, client: UdsClient, ctx: CaseContext) -> int:
        cfg = ctx.raw_config
        bus = cfg.get("_bus")
        can_mod = cfg.get("_can_module")
        if bus is None or can_mod is None:
            raise RuntimeError("ArbIdFuzzer requires raw bus context")

        extended_id = bool(cfg.get("extended_id", ctx.target.extended_id if ctx.target else False))
        ids = parse_int_range(cfg.get("txid_range", "0x700-0x7FF"), item_parser=lambda x: parse_can_id(x, extended=extended_id), max_items=int(cfg.get("max_items", 512)))
        payload = parse_hex_bytes(cfg.get("probe_payload", "3E 00"))
        if len(payload) > 7:
            raise ValueError("arb_id_fuzzer probe_payload must fit ISO-TP SingleFrame payload <= 7 bytes")
        pad = parse_byte(cfg.get("padding", 0x00))
        frame_data = pad8([len(payload)] + list(payload), pad)
        per_id_timeout = float(cfg.get("per_id_timeout", 0.08))
        delay = float(cfg.get("delay", 0.01))
        collect_limit = int(cfg.get("collect_limit_per_id", 5))
        stop_on_first_response = bool(cfg.get("stop_on_first_response", False))

        for txid in ids:
            msg = can_mod.Message(arbitration_id=txid, data=frame_data, is_extended_id=extended_id)
            bus.send(msg)
            ctx.run_logger.event("raw_tx", testcase=ctx.name, txid=can_id_hx(txid), data=frame_data.hex().upper())
            deadline = time.monotonic() + per_id_timeout
            got = 0
            while time.monotonic() < deadline and got < collect_limit:
                rx = bus.recv(timeout=max(0.0, deadline - time.monotonic()))
                if rx is None:
                    break
                # Do not discard same-id frames blindly; some virtual interfaces echo.
                rx_data = bytes(rx.data)
                ctx.run_logger.event(
                    "arb_id_response",
                    testcase=ctx.name,
                    txid=can_id_hx(txid),
                    rxid=can_id_hx(rx.arbitration_id),
                    data=rx_data.hex().upper(),
                )
                got += 1
                if stop_on_first_response:
                    return 0
            if delay > 0:
                time.sleep(delay)
        return 0
