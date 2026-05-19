#!/usr/bin/env python3
"""
uds27_securityaccess_behavior_probe.py

Mode-based UDS SecurityAccess (0x27) behavior probe for UDS-13..UDS-19.

Purpose:
  - Observe sequence, timeout, penalty and multiple-seed-response behavior.
  - Reuse the recovered BMS SeedKey algorithm to generate format-correct 16-byte keys.
  - Support interactive operation when --src/--dst/--mode/--session-flow/--seed-subfn are omitted.

Authorized testing only. Use on an ECU, simulator, bench, or vehicle where you have explicit permission.

Typical interactive run:
  python3 uds27_securityaccess_behavior_probe.py --channel can0 --show-process

Typical non-interactive run:
  python3 uds27_securityaccess_behavior_probe.py \
    --channel can0 \
    --src 0x681 \
    --dst 0x601 \
    --mode one-seed-many-keys \
    --session-flow "03 41" \
    --seed-subfn 01 \
    --show-process

Supported BMS SecurityAccess levels:
  RequestSeed 0x01 -> SendKey 0x02
  RequestSeed 0x03 -> SendKey 0x04
  RequestSeed 0x05 -> SendKey 0x06
  RequestSeed 0x07 -> SendKey 0x08
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


VERSION = "1.1.0"


NRC_NAMES: Dict[int, str] = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x35: "invalidKey",
    0x36: "exceededNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x78: "responsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


MODE_DEFINITIONS: Sequence[Tuple[str, str, str]] = (
    ("key-without-seed", "UDS-13", "SendKey before RequestSeed"),
    ("seed-timeout-key", "UDS-14", "RequestSeed, wait, then SendKey"),
    ("one-seed-many-keys", "UDS-16", "One seed, multiple SendKey attempts"),
    ("seed-key-exchange-loop", "UDS-17", "Repeat RequestSeed and SendKey"),
    ("penalty-then-seed", "UDS-18", "Trigger penalty, then request seed"),
    ("multi-seed-response", "UDS-19", "Check multiple seed responses"),
)


MODE_CHOICES = [m[0] for m in MODE_DEFINITIONS]


@dataclass(frozen=True)
class SecretCase:
    case_id: int
    request_seed_subfn: int
    send_key_subfn: int
    local_10: int
    local_c: int
    secret: bytes


def le32(value: int) -> bytes:
    return int(value & 0xFFFFFFFF).to_bytes(4, byteorder="little", signed=False)


LOCAL_10 = 0x1022BA0A

SECRET_CASES_BY_SEED_SUBFN: Dict[int, SecretCase] = {
    0x01: SecretCase(
        case_id=1,
        request_seed_subfn=0x01,
        send_key_subfn=0x02,
        local_10=LOCAL_10,
        local_c=0xC7B43869,
        secret=le32(LOCAL_10) + le32(0xC7B43869),
    ),
    0x03: SecretCase(
        case_id=3,
        request_seed_subfn=0x03,
        send_key_subfn=0x04,
        local_10=LOCAL_10,
        local_c=0x9EE42D59,
        secret=le32(LOCAL_10) + le32(0x9EE42D59),
    ),
    0x05: SecretCase(
        case_id=5,
        request_seed_subfn=0x05,
        send_key_subfn=0x06,
        local_10=LOCAL_10,
        local_c=0x348D8274,
        secret=le32(LOCAL_10) + le32(0x348D8274),
    ),
    0x07: SecretCase(
        case_id=7,
        request_seed_subfn=0x07,
        send_key_subfn=0x08,
        local_10=LOCAL_10,
        local_c=0xB8C3A09D,
        secret=le32(LOCAL_10) + le32(0xB8C3A09D),
    ),
}


class UdsError(Exception):
    pass


@dataclass
class UdsResult:
    request: bytes
    response: bytes = b""
    positive: bool = False
    nrc: Optional[int] = None
    note: str = ""
    exception: Optional[str] = None

    def short(self) -> str:
        if self.positive:
            return f"POS {spaced(self.response)}"
        if self.nrc is not None:
            return f"NRC {hx(self.nrc)} - {NRC_NAMES.get(self.nrc, 'unknownNRC')}"
        if self.exception:
            return self.exception
        return self.note or "no-response"


@dataclass
class Observation:
    step: str
    result: UdsResult


class Log:
    def __init__(self, *, verbose: bool = False, show_process: bool = False, show_tx_can: bool = False) -> None:
        self.verbose = verbose
        self.show_process = show_process
        self.show_tx_can = show_tx_can

    def info(self, message: str) -> None:
        print(message, flush=True)

    def process(self, message: str) -> None:
        if self.show_process or self.verbose:
            print(message, flush=True)

    def sent(self, can_id: int, data: bytes) -> None:
        if self.show_tx_can:
            print(f"  CAN TX {can_id:X}#{data.hex().upper()}", flush=True)

    def recv_raw(self, can_id: int, data: bytes) -> None:
        if self.verbose:
            print(f"Recv: {can_id:X}#{data.hex().upper()}", flush=True)

    def debug(self, message: str) -> None:
        if self.verbose:
            print(message, flush=True)


def import_python_can() -> Any:
    try:
        import can  # type: ignore
    except ImportError as exc:
        print("Missing dependency: python-can. Install with: pip install python-can", file=sys.stderr)
        raise SystemExit(2) from exc
    return can


def parse_hex_int(value: str) -> int:
    text = str(value).strip().replace("_", "")
    if not text:
        raise argparse.ArgumentTypeError("empty hex value")
    try:
        return int(text, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hex value: {value}") from exc


def parse_byte(value: str) -> int:
    n = parse_hex_int(value)
    if not 0 <= n <= 0xFF:
        raise argparse.ArgumentTypeError(f"byte out of range 00..FF: {value}")
    return n


def parse_can_id(value: str) -> int:
    n = parse_hex_int(value)
    if not 0 <= n <= 0x1FFFFFFF:
        raise argparse.ArgumentTypeError(f"CAN ID out of range: {value}")
    return n


def parse_session_flow(text: str) -> List[int]:
    normalized = str(text or "").strip()
    if not normalized:
        raise ValueError("session flow cannot be empty")
    tokens = [t for t in re.split(r"[\s,;>\-]+", normalized) if t]
    flow = [parse_byte(t) for t in tokens]
    if not flow:
        raise ValueError("session flow cannot be empty")
    return flow


def parse_key_hex(text: str) -> bytes:
    normalized = re.sub(r"[\s:_\-]", "", str(text or "").strip())
    if not normalized:
        raise ValueError("empty key")
    if len(normalized) % 2:
        raise ValueError("hex key must have an even number of characters")
    return bytes.fromhex(normalized)


def bhex(data: bytes) -> str:
    return data.hex().upper()


def spaced(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def hx(value: int, width: int = 2) -> str:
    return f"0x{value:0{width}X}"


def compact_exception(exc: object) -> str:
    text = str(exc).strip()
    if not text:
        return type(exc).__name__ if not isinstance(exc, str) else "error"
    if "Network is down" in text:
        return "CAN transmit failed: Network is down"
    if "Failed to transmit" in text:
        return text.replace("Failed to transmit:", "CAN transmit failed:").split(" [Error Code", 1)[0]
    return text


def compact_status(result: "UdsResult") -> str:
    if result.positive:
        return "OK"
    if result.nrc is not None:
        return f"NRC {result.nrc:02X} {NRC_NAMES.get(result.nrc, 'unknown')}"
    if result.exception:
        return f"ERROR {result.exception}"
    return result.note or "NO RESPONSE"


def mode_code(mode: str) -> str:
    for item_mode, code, _ in MODE_DEFINITIONS:
        if item_mode == mode:
            return code
    return mode


def pad8(data: Iterable[int], pad: int) -> bytes:
    out = bytes(data)
    if len(out) > 8:
        raise ValueError("CAN payload is longer than 8 bytes")
    return out + bytes([pad & 0xFF] * (8 - len(out)))


def default_send_key_subfn(seed_subfn: int) -> int:
    return (seed_subfn + 1) & 0xFF


def case_for_seed_subfn(seed_subfn: int) -> SecretCase:
    case = SECRET_CASES_BY_SEED_SUBFN.get(seed_subfn)
    if case is None:
        supported = ", ".join(f"0x{x:02X}" for x in sorted(SECRET_CASES_BY_SEED_SUBFN))
        raise ValueError(f"unsupported BMS RequestSeed sub-function {hx(seed_subfn)}; supported: {supported}")
    return case


def compute_bms_key(seed: bytes, seed_subfn: int) -> bytes:
    case = case_for_seed_subfn(seed_subfn)
    digest20 = hmac.new(case.secret, seed, hashlib.sha1).digest()
    return digest20[:16]


class IsoTp:
    """Minimal normal-addressing ISO-TP transport over python-can."""

    def __init__(
        self,
        bus: Any,
        can_module: Any,
        txid: int,
        rxid: int,
        log: Log,
        *,
        extended_id: bool = False,
        pad: int = 0x00,
        fc_bs: int = 0x00,
        fc_stmin: int = 0x00,
        request_stmin: float = 0.0,
        fc_wait_timeout: float = 3.0,
    ) -> None:
        self.bus = bus
        self.can = can_module
        self.txid = txid
        self.rxid = rxid
        self.log = log
        self.extended_id = extended_id
        self.pad = pad & 0xFF
        self.fc_bs = fc_bs & 0xFF
        self.fc_stmin = fc_stmin & 0xFF
        self.request_stmin = max(0.0, request_stmin)
        self.fc_wait_timeout = max(0.1, fc_wait_timeout)

    def send_can(self, data: bytes) -> None:
        msg = self.can.Message(
            arbitration_id=self.txid,
            data=data,
            is_extended_id=self.extended_id,
        )
        self.bus.send(msg)
        self.log.sent(self.txid, data)

    def recv_can(self, timeout: float) -> Optional[bytes]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            msg = self.bus.recv(timeout=remaining)
            if msg is None:
                return None
            data = bytes(msg.data)
            if msg.arbitration_id == self.rxid:
                self.log.recv_raw(msg.arbitration_id, data)
                return data
            self.log.debug(f"Skip: {msg.arbitration_id:X}#{data.hex().upper()}")
        return None

    def drain(self, seconds: float = 0.15) -> int:
        deadline = time.monotonic() + max(0.0, seconds)
        drained = 0
        while time.monotonic() < deadline:
            msg = self.bus.recv(timeout=max(0.0, deadline - time.monotonic()))
            if msg is None:
                break
            drained += 1
        if drained:
            self.log.process(f"Drained {drained} stale CAN frame(s)")
        return drained

    @staticmethod
    def stmin_to_seconds(stmin: int) -> float:
        if 0x00 <= stmin <= 0x7F:
            return stmin / 1000.0
        if 0xF1 <= stmin <= 0xF9:
            return (stmin - 0xF0) / 10000.0
        return 0.0

    def send_payload(self, payload: bytes) -> None:
        if len(payload) <= 7:
            self.send_can(pad8([len(payload)] + list(payload), self.pad))
            return

        total_len = len(payload)
        self.send_can(pad8([0x10 | ((total_len >> 8) & 0x0F), total_len & 0xFF] + list(payload[:6]), self.pad))

        fc = self.wait_flow_control(timeout=self.fc_wait_timeout, label="after request FirstFrame")
        block_size = fc[1]
        stmin_s = max(self.request_stmin, self.stmin_to_seconds(fc[2]))
        offset = 6
        seq = 1
        sent_in_block = 0

        while offset < total_len:
            if stmin_s > 0:
                time.sleep(stmin_s)
            chunk = payload[offset:offset + 7]
            self.send_can(pad8([0x20 | (seq & 0x0F)] + list(chunk), self.pad))
            offset += len(chunk)
            seq = (seq + 1) & 0x0F
            sent_in_block += 1

            if block_size and sent_in_block >= block_size and offset < total_len:
                fc = self.wait_flow_control(timeout=self.fc_wait_timeout, label="between request blocks")
                block_size = fc[1]
                stmin_s = max(self.request_stmin, self.stmin_to_seconds(fc[2]))
                sent_in_block = 0

    def wait_flow_control(self, *, timeout: float, label: str) -> bytes:
        """Wait for ISO-TP FlowControl while ignoring unrelated/stale RX frames.

        Some ECUs share one response CAN ID for several diagnostic paths and can emit
        delayed ConsecutiveFrames or final responses while the tester is preparing a
        multi-frame SendKey request. Treating the first RX frame as FlowControl makes
        SendKey brittle. This helper waits until a real 0x3x FlowControl frame is
        observed, honours CTS/WAIT/OVFLW, and keeps the transport error explicit.
        """
        deadline = time.monotonic() + max(0.1, timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timeout waiting for FlowControl {label}")

            frame = self.recv_can(timeout=remaining)
            if frame is None:
                raise TimeoutError(f"timeout waiting for FlowControl {label}")

            if len(frame) < 3 or (frame[0] >> 4) != 0x3:
                self.log.debug(f"Ignore non-FlowControl while waiting {label}: {bhex(frame)}")
                continue

            fs = frame[0] & 0x0F
            if fs == 0x00:
                self.log.debug(f"FlowControl CTS {label}: {bhex(frame)}")
                return frame
            if fs == 0x01:
                self.log.process(f"  isotp                  FC.WAIT {label}")
                continue
            if fs == 0x02:
                raise UdsError(f"FlowControl overflow {label}: {bhex(frame)}")
            raise UdsError(f"unsupported FlowControl status {fs:X} {label}: {bhex(frame)}")

    def send_flow_control(self) -> None:
        self.send_can(pad8([0x30, self.fc_bs, self.fc_stmin], self.pad))

    def recv_payload(self, timeout: float, *, frame_label: str = "Response") -> bytes:
        data = self.recv_can(timeout=timeout)
        if data is None:
            raise TimeoutError("timeout waiting for ISO-TP response")
        if len(data) == 0:
            raise UdsError("empty CAN frame")

        pci_type = data[0] >> 4

        if pci_type == 0x0:
            length = data[0] & 0x0F
            return data[1:1 + length]

        if pci_type == 0x1:
            total_len = ((data[0] & 0x0F) << 8) | data[1]
            payload = bytearray(data[2:8])
            remaining = max(0, total_len - len(payload))
            total_cf = math.ceil(remaining / 7) if remaining else 0
            self.log.process(f"{frame_label} FirstFrame received; sending FlowControl")
            self.send_flow_control()

            expected_seq = 1
            got_cf = 0
            while len(payload) < total_len:
                cf = self.recv_can(timeout=timeout)
                if cf is None:
                    raise TimeoutError("timeout waiting for ConsecutiveFrame")
                if not cf or (cf[0] >> 4) != 0x2:
                    continue
                seq = cf[0] & 0x0F
                if seq != expected_seq:
                    raise UdsError(f"wrong ConsecutiveFrame SN: expected {expected_seq:X}, got {seq:X}")
                payload.extend(cf[1:8])
                got_cf += 1
                if total_cf:
                    self.log.process(f"Received chunk {got_cf}/{total_cf}")
                expected_seq = (expected_seq + 1) & 0x0F

            return bytes(payload[:total_len])

        if pci_type == 0x3:
            raise UdsError(f"unexpected FlowControl from ECU: {bhex(data)}")

        raise UdsError(f"unknown ISO-TP PCI type: {pci_type:X} in {bhex(data)}")

    def uds_request(
        self,
        payload: bytes,
        *,
        timeout: float,
        response_pending_timeout: float,
        frame_label: str = "Response",
    ) -> bytes:
        self.send_payload(payload)

        deadline = time.monotonic() + response_pending_timeout
        while True:
            remaining = max(0.0, min(timeout, deadline - time.monotonic()))
            if remaining <= 0:
                raise TimeoutError("timeout waiting for final UDS response")
            response = self.recv_payload(timeout=remaining, frame_label=frame_label)
            self.log.debug(f"RX UDS: {spaced(response)}")

            if len(response) >= 3 and response[0] == 0x7F and response[1] == payload[0] and response[2] == 0x78:
                self.log.process("ResponsePending NRC 0x78; waiting for final response")
                continue

            return response


def parse_uds_response(response: bytes, request: bytes) -> UdsResult:
    if not response:
        return UdsResult(request=request, response=response, note="empty response")

    service_id = request[0]
    subfn = request[1] if len(request) >= 2 else None

    if response[0] == 0x7F:
        nrc = response[2] if len(response) >= 3 else None
        note = "negative response"
        if len(response) >= 2 and response[1] != service_id:
            note = f"negative response for different service {hx(response[1])}"
        return UdsResult(request=request, response=response, positive=False, nrc=nrc, note=note)

    expected_sid = (service_id + 0x40) & 0xFF
    if response[0] != expected_sid:
        return UdsResult(
            request=request,
            response=response,
            positive=False,
            note=f"unexpected SID {hx(response[0])}, expected {hx(expected_sid)}",
        )

    if subfn is not None and len(response) >= 2 and response[1] != subfn:
        return UdsResult(
            request=request,
            response=response,
            positive=False,
            note=f"sub-function mismatch {hx(response[1])}, expected {hx(subfn)}",
        )

    return UdsResult(request=request, response=response, positive=True, note="positive response")


def uds_call(
    isotp: IsoTp,
    request: bytes,
    args: argparse.Namespace,
    log: Log,
    *,
    step: str,
    frame_label: str = "Response",
) -> UdsResult:
    try:
        log.process(f"  {step:<22} TX  {spaced(request)}")
        response = isotp.uds_request(
            request,
            timeout=args.timeout,
            response_pending_timeout=args.response_pending_timeout,
            frame_label=frame_label,
        )
        result = parse_uds_response(response, request)
        log.process(f"  {step:<22} RX  {spaced(response)}  {compact_status(result)}")
        return result
    except Exception as exc:
        result = UdsResult(request=request, exception=compact_exception(exc))
        log.process(f"  {step:<22} !!  {compact_status(result)}")
        return result


def open_session_flow(isotp: IsoTp, session_flow: List[int], args: argparse.Namespace, log: Log) -> Tuple[bool, List[Observation]]:
    observations: List[Observation] = []

    for session_subfn in session_flow:
        step = f"session-{session_subfn:02X}"
        result = uds_call(isotp, bytes([0x10, session_subfn]), args, log, step=step, frame_label="Session")
        observations.append(Observation(step, result))

        if result.positive:
            if args.post_session_delay > 0:
                time.sleep(args.post_session_delay)
            continue

        if result.nrc in {0x7E, 0x7F} and not args.strict_session:
            log.process(f"  session-{session_subfn:02X}              ..  continue after {compact_status(result)}")
            if args.post_session_delay > 0:
                time.sleep(args.post_session_delay)
            continue

        return False, observations

    return True, observations


def request_seed(isotp: IsoTp, seed_subfn: int, args: argparse.Namespace, log: Log, *, step: str = "request-seed") -> Tuple[Optional[bytes], UdsResult]:
    req = bytes([0x27, seed_subfn])
    result = uds_call(isotp, req, args, log, step=step, frame_label="Seed")
    if result.positive:
        seed = result.response[2:]
        log.info(f"  seed                    {bhex(seed)}  len={len(seed)}")
        return seed, result
    log.info(f"  seed                    {compact_status(result)}")
    return None, result


def resolve_key(
    *,
    seed: Optional[bytes],
    seed_subfn: int,
    key_policy: str,
    explicit_key: Optional[bytes],
    pattern_byte: int,
) -> Tuple[bytes, str]:
    if key_policy == "explicit":
        if explicit_key is None:
            raise ValueError("--key-policy explicit requires --key-hex")
        return explicit_key, "explicit key from --key-hex"

    if key_policy == "zero":
        return bytes(16), "16 zero bytes"

    if key_policy == "pattern":
        return bytes([pattern_byte & 0xFF] * 16), f"16 repeated pattern bytes {hx(pattern_byte)}"

    if key_policy == "format-random":
        fake_seed = os.urandom(16)
        key = compute_bms_key(fake_seed, seed_subfn)
        return key, f"format-correct BMS key from random fake seed {bhex(fake_seed)}"

    if key_policy == "valid":
        if seed is None:
            raise ValueError("valid key policy requires an ECU seed")
        return compute_bms_key(seed, seed_subfn), "valid BMS key from ECU seed"

    if key_policy == "invalid-bitflip":
        if seed is None:
            raise ValueError("invalid-bitflip key policy requires an ECU seed")
        key = bytearray(compute_bms_key(seed, seed_subfn))
        key[-1] ^= 0x01
        return bytes(key), "invalid key: valid BMS key with last byte flipped"

    raise ValueError(f"unsupported key policy: {key_policy}")


def send_key(
    isotp: IsoTp,
    key_subfn: int,
    key: bytes,
    args: argparse.Namespace,
    log: Log,
    *,
    step: str,
) -> UdsResult:
    if args.key_delay > 0:
        time.sleep(args.key_delay)
    return uds_call(isotp, bytes([0x27, key_subfn]) + key, args, log, step=step, frame_label="SendKey")


def mode_uses_send_key(mode: str) -> bool:
    return mode in {
        "key-without-seed",
        "seed-timeout-key",
        "one-seed-many-keys",
        "seed-key-exchange-loop",
        "penalty-then-seed",
    }


def mode_default_profile(mode: str, preset: str = "testcase") -> Dict[str, Any]:
    """Return mode-specific defaults.

    preset='testcase' keeps each UDS test case semantically correct.
    preset='unlock-check' prioritizes a quick valid-key check where a real ECU seed is available.
    """
    base: Dict[str, Any] = {
        "attempts": 1,
        "key_policy": "format-random",
        "stop_on_positive_unlock": True,
        "s3_wait": 6.0,
        "capture_window": 1.0,
        "penalty_probe_delay": 0.05,
    }

    if mode == "key-without-seed":
        base.update(attempts=1, key_policy="format-random", stop_on_positive_unlock=True)
    elif mode == "seed-timeout-key":
        base.update(attempts=1, key_policy="valid", stop_on_positive_unlock=True, s3_wait=6.0)
    elif mode == "one-seed-many-keys":
        base.update(attempts=5, key_policy="invalid-bitflip", stop_on_positive_unlock=True)
    elif mode == "seed-key-exchange-loop":
        base.update(attempts=5, key_policy="invalid-bitflip", stop_on_positive_unlock=True)
    elif mode == "penalty-then-seed":
        base.update(attempts=5, key_policy="invalid-bitflip", stop_on_positive_unlock=True, penalty_probe_delay=0.05)
    elif mode == "multi-seed-response":
        base.update(attempts=1, key_policy="format-random", stop_on_positive_unlock=False, capture_window=1.0)

    if preset == "unlock-check" and mode_uses_send_key(mode):
        # Keep UDS-13 format-correct because there is intentionally no ECU seed.
        if mode != "key-without-seed":
            base.update(attempts=1, key_policy="valid", stop_on_positive_unlock=True)

    return base


def apply_mode_defaults(args: argparse.Namespace) -> None:
    defaults = mode_default_profile(args.mode, args.preset)
    for name, value in defaults.items():
        if getattr(args, name, None) is None:
            setattr(args, name, value)


def key_policy_or_fallback(seed: Optional[bytes], policy: str) -> str:
    if seed is None and policy in {"valid", "invalid-bitflip"}:
        return "format-random"
    return policy


def run_key_without_seed(
    isotp: IsoTp,
    args: argparse.Namespace,
    log: Log,
    observations: List[Observation],
) -> None:
    key, why = resolve_key(
        seed=None,
        seed_subfn=args.seed_subfn,
        key_policy=args.key_policy,
        explicit_key=args.key_hex_bytes,
        pattern_byte=args.pattern_byte,
    )
    log.process(f"  key                     {args.key_policy}")
    result = send_key(isotp, args.key_subfn, key, args, log, step="send-key-without-seed")
    observations.append(Observation("send-key-without-seed", result))


def run_seed_timeout_key(
    isotp: IsoTp,
    args: argparse.Namespace,
    log: Log,
    observations: List[Observation],
) -> None:
    seed, seed_result = request_seed(isotp, args.seed_subfn, args, log, step="request-seed-before-timeout")
    observations.append(Observation("request-seed-before-timeout", seed_result))

    log.info(f"  wait                    {args.s3_wait:.2f}s")
    time.sleep(args.s3_wait)

    local_policy = key_policy_or_fallback(seed, args.key_policy)
    if local_policy != args.key_policy:
        log.process("  key                     fallback=format-random")

    key, why = resolve_key(
        seed=seed,
        seed_subfn=args.seed_subfn,
        key_policy=local_policy,
        explicit_key=args.key_hex_bytes,
        pattern_byte=args.pattern_byte,
    )
    log.process(f"  key                     {args.key_policy}")
    result = send_key(isotp, args.key_subfn, key, args, log, step="send-key-after-timeout")
    observations.append(Observation("send-key-after-timeout", result))


def run_one_seed_many_keys(
    isotp: IsoTp,
    args: argparse.Namespace,
    log: Log,
    observations: List[Observation],
) -> None:
    seed, seed_result = request_seed(isotp, args.seed_subfn, args, log, step="request-seed-once")
    observations.append(Observation("request-seed-once", seed_result))

    local_policy = key_policy_or_fallback(seed, args.key_policy)
    if local_policy != args.key_policy:
        log.process("  key                     fallback=format-random")

    for i in range(1, args.attempts + 1):
        key, why = resolve_key(
            seed=seed,
            seed_subfn=args.seed_subfn,
            key_policy=local_policy,
            explicit_key=args.key_hex_bytes,
            pattern_byte=args.pattern_byte,
        )
        log.process(f"  key-attempt-{i:<12} key {args.key_policy}")
        result = send_key(isotp, args.key_subfn, key, args, log, step=f"key-attempt-{i}")
        observations.append(Observation(f"key-attempt-{i}", result))
        if args.stop_on_positive_unlock and result.positive:
            log.info("  stop                    positive SendKey")
            break
        if args.delay > 0:
            time.sleep(args.delay)


def run_seed_key_exchange_loop(
    isotp: IsoTp,
    args: argparse.Namespace,
    log: Log,
    observations: List[Observation],
) -> None:
    for i in range(1, args.attempts + 1):
        seed, seed_result = request_seed(isotp, args.seed_subfn, args, log, step=f"exchange-{i}-request-seed")
        observations.append(Observation(f"exchange-{i}-request-seed", seed_result))

        local_policy = key_policy_or_fallback(seed, args.key_policy)
        if local_policy != args.key_policy:
            log.process("  key                     fallback=format-random")

        key, why = resolve_key(
            seed=seed,
            seed_subfn=args.seed_subfn,
            key_policy=local_policy,
            explicit_key=args.key_hex_bytes,
            pattern_byte=args.pattern_byte,
        )
        log.process(f"  exchange-{i:<14} key {args.key_policy}")
        key_result = send_key(isotp, args.key_subfn, key, args, log, step=f"exchange-{i}-send-key")
        observations.append(Observation(f"exchange-{i}-send-key", key_result))

        if args.stop_on_positive_unlock and key_result.positive:
            log.info("  stop                    positive SendKey")
            break

        if args.delay > 0:
            time.sleep(args.delay)


def run_penalty_then_seed(
    isotp: IsoTp,
    args: argparse.Namespace,
    log: Log,
    observations: List[Observation],
) -> None:
    log.info("PHASE 1  trigger penalty")
    if args.key_policy == "valid":
        log.info("  warning                 valid key may unlock instead of triggering penalty")

    for i in range(1, args.attempts + 1):
        seed, seed_result = request_seed(isotp, args.seed_subfn, args, log, step=f"penalty-trigger-{i}-request-seed")
        observations.append(Observation(f"penalty-trigger-{i}-request-seed", seed_result))

        local_policy = key_policy_or_fallback(seed, args.key_policy)

        key, why = resolve_key(
            seed=seed,
            seed_subfn=args.seed_subfn,
            key_policy=local_policy,
            explicit_key=args.key_hex_bytes,
            pattern_byte=args.pattern_byte,
        )
        log.process(f"  penalty-{i:<15} key {args.key_policy}")
        key_result = send_key(isotp, args.key_subfn, key, args, log, step=f"penalty-trigger-{i}-send-key")
        observations.append(Observation(f"penalty-trigger-{i}-send-key", key_result))

        if key_result.positive and args.stop_on_positive_unlock:
            log.info("  stop                    positive SendKey")
            break

        if args.delay > 0:
            time.sleep(args.delay)

    if args.penalty_probe_delay > 0:
        log.info(f"  wait                    {args.penalty_probe_delay:.2f}s")
        time.sleep(args.penalty_probe_delay)

    log.info("PHASE 2  RequestSeed during penalty")
    _, probe_result = request_seed(isotp, args.seed_subfn, args, log, step="penalty-mode-request-seed-probe")
    observations.append(Observation("penalty-mode-request-seed-probe", probe_result))


def collect_extra_seed_responses(
    isotp: IsoTp,
    args: argparse.Namespace,
    log: Log,
    *,
    seed_subfn: int,
    window: float,
) -> List[bytes]:
    responses: List[bytes] = []
    deadline = time.monotonic() + max(0.0, window)

    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            payload = isotp.recv_payload(timeout=min(args.timeout, remaining), frame_label="ExtraSeed")
        except TimeoutError:
            break
        except Exception as exc:
            log.process(f"Extra capture error: {type(exc).__name__}: {exc}")
            break

        log.process(f"Extra RX UDS: {spaced(payload)}")
        if len(payload) >= 2 and payload[0] == 0x67 and payload[1] == seed_subfn:
            responses.append(payload)

    return responses


def run_multi_seed_response(
    isotp: IsoTp,
    args: argparse.Namespace,
    log: Log,
    observations: List[Observation],
) -> None:
    request = bytes([0x27, args.seed_subfn])
    first = uds_call(isotp, request, args, log, step="single-request-seed", frame_label="Seed")
    observations.append(Observation("single-request-seed", first))

    log.info(f"  capture-window          {args.capture_window:.2f}s")
    extras = collect_extra_seed_responses(
        isotp,
        args,
        log,
        seed_subfn=args.seed_subfn,
        window=args.capture_window,
    )

    for idx, payload in enumerate(extras, start=1):
        result = parse_uds_response(payload, request)
        observations.append(Observation(f"extra-positive-seed-{idx}", result))

    positive_seed_count = int(first.positive and len(first.response) >= 2 and first.response[0] == 0x67 and first.response[1] == args.seed_subfn)
    positive_seed_count += len(extras)
    log.info(f"  positive-seed-count     {positive_seed_count}")


def classify_verdict(mode: str, observations: List[Observation], args: argparse.Namespace) -> Tuple[str, str]:
    results = [obs.result for obs in observations]

    def has_nrc(nrc: int) -> bool:
        return any(r.nrc == nrc for r in results)

    def has_positive_sendkey() -> bool:
        return any(
            obs.result.positive
            for obs in observations
            if "send-key" in obs.step or "key-attempt" in obs.step
        )

    if mode == "key-without-seed":
        sendkey_results = [obs.result for obs in observations if obs.step == "send-key-without-seed"]
        if any(r.nrc == 0x24 for r in sendkey_results):
            return "PASS/EXPECTED", "ECU rejected SendKey without prior seed using NRC 0x24 requestSequenceError"
        if any(r.positive for r in sendkey_results):
            return "FAIL/SUSPICIOUS", "ECU returned positive response to SendKey without prior seed"
        return "REVIEW", "No NRC 0x24 observed; inspect returned NRC/timeout"

    if mode == "seed-timeout-key":
        key_results = [obs.result for obs in observations if obs.step == "send-key-after-timeout"]
        if any(r.positive for r in key_results):
            return "FAIL/SUSPICIOUS", "ECU accepted SendKey after timeout/stale seed window"
        if any(r.exception for r in key_results):
            return "REVIEW/TRANSPORT", "SendKey did not complete at ISO-TP/transport level; increase --fc-wait-timeout or inspect FlowControl timing"
        return "PASS/REVIEW", "ECU did not positively accept stale SendKey; inspect exact NRC"

    if mode == "one-seed-many-keys":
        if has_positive_sendkey():
            return "UNLOCKED/REVIEW", "A SendKey attempt returned positive; verify whether --key-policy valid was used intentionally"
        if has_nrc(0x36) or has_nrc(0x37):
            return "PASS/EXPECTED", "ECU enforced attempt limit or required delay"
        if has_nrc(0x35):
            return "WEAK/REVIEW", "Only invalidKey observed; no attempt-limit/penalty NRC seen within configured attempts"
        return "REVIEW", "No clear penalty behavior observed"

    if mode == "seed-key-exchange-loop":
        if has_positive_sendkey():
            return "UNLOCKED/REVIEW", "A SendKey exchange returned positive; verify key policy and state"
        if has_nrc(0x36) or has_nrc(0x37):
            return "PASS/EXPECTED", "ECU entered penalty/attempt-limit behavior across exchanges"
        return "WEAK/REVIEW", "No 0x36/0x37 observed across configured invalid exchanges"

    if mode == "penalty-then-seed":
        probe = [obs.result for obs in observations if obs.step == "penalty-mode-request-seed-probe"]
        if probe and probe[-1].nrc == 0x37:
            return "PASS/EXPECTED", "RequestSeed during penalty returned NRC 0x37"
        if probe and probe[-1].positive:
            return "FAIL/SUSPICIOUS", "ECU returned a valid seed while expected to be in penalty mode"
        return "REVIEW", "Penalty probe did not return 0x37 or positive seed; inspect exact behavior"

    if mode == "multi-seed-response":
        positive_count = sum(
            1
            for obs in observations
            if obs.result.positive
            and len(obs.result.response) >= 2
            and obs.result.response[0] == 0x67
            and obs.result.response[1] == args.seed_subfn
        )
        if positive_count > 1:
            return "FAIL/SUSPICIOUS", f"{positive_count} positive seed responses observed for one RequestSeed"
        if positive_count == 1:
            return "PASS/EXPECTED", "Exactly one positive seed response observed"
        return "REVIEW", "No positive seed response observed"

    return "REVIEW", "Unknown mode"


def print_summary(mode: str, observations: List[Observation], args: argparse.Namespace) -> None:
    print("\nRESULT")
    print(f"  mode     {mode_code(mode)}  {mode}")
    print(f"  seed     {args.seed_subfn:02X}  key {args.key_subfn:02X}  policy {args.key_policy}")
    print("")
    print(f"{'#':>2}  {'step':<22} {'req':<20} status")
    print("-" * 72)

    for idx, obs in enumerate(observations, start=1):
        req = spaced(obs.result.request)
        print(f"{idx:>2}  {obs.step:<22} {req:<20} {compact_status(obs.result)}")

    verdict, reason = classify_verdict(mode, observations, args)
    print("\nVERDICT")
    print(f"  {verdict} - {reason}")


def prompt_text(label: str, default: Optional[str] = None) -> str:
    raw = input(f"{label}: ").strip()
    if raw:
        return raw
    return default or ""


def prompt_can_id(args: argparse.Namespace, attr_name: str, label: str, default_hex: str) -> int:
    current = getattr(args, attr_name, None)
    if current is not None:
        return current

    while True:
        raw = prompt_text(label, default_hex)
        try:
            value = parse_can_id(raw)
            setattr(args, attr_name, value)
            return value
        except Exception as exc:
            print(f"Invalid {attr_name}: {exc}", file=sys.stderr)


def prompt_mode(args: argparse.Namespace) -> str:
    if args.mode:
        return args.mode

    print("\nMode")
    for idx, (mode, tc, desc) in enumerate(MODE_DEFINITIONS, start=1):
        print(f"  {idx:<2} {tc:<7} {mode:<24} {desc}")

    while True:
        raw = input("Select mode: ").strip()
        if not raw:
            continue
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(MODE_DEFINITIONS):
                args.mode = MODE_DEFINITIONS[idx - 1][0]
                return args.mode
        if raw in MODE_CHOICES:
            args.mode = raw
            return raw
        print("Invalid mode", file=sys.stderr)


def prompt_runtime_fields(args: argparse.Namespace) -> None:
    if not args.session_flow:
        args.session_flow = prompt_text("Session flow", "03")

    if args.seed_subfn is None:
        while True:
            try:
                args.seed_subfn = parse_byte(prompt_text("RequestSeed sub-function", "01"))
                break
            except Exception as exc:
                print(f"Invalid RequestSeed sub-function: {exc}", file=sys.stderr)

    # Normal short interactive mode does not ask for SendKey sub-function.
    # It is derived automatically from RequestSeed: 01->02, 03->04, 05->06, 07->08.
    if args.key_subfn is None:
        args.key_subfn = default_send_key_subfn(args.seed_subfn)


def prompt_advanced_fields(args: argparse.Namespace) -> None:
    """Optional tuning prompts. Not used in the normal short interactive run."""
    if args.key_policy is not None:
        default_policy = args.key_policy
    else:
        default_policy = mode_default_profile(args.mode, args.preset)["key_policy"]

    if mode_uses_send_key(args.mode):
        default_key_subfn = f"{args.key_subfn:02X}"
        while True:
            try:
                args.key_subfn = parse_byte(prompt_text("SendKey sub-function", default_key_subfn))
                break
            except Exception as exc:
                print(f"Invalid SendKey sub-function: {exc}", file=sys.stderr)

        raw_policy = prompt_text(
            "Key policy",
            default_policy,
        )
        if raw_policy in {"valid", "invalid-bitflip", "format-random", "zero", "pattern", "explicit"}:
            args.key_policy = raw_policy
        else:
            print(f"Invalid key policy '{raw_policy}', using default {default_policy}", file=sys.stderr)
            args.key_policy = default_policy

    if args.mode in {"one-seed-many-keys", "seed-key-exchange-loop", "penalty-then-seed"}:
        while True:
            try:
                args.attempts = int(prompt_text("Attempts", str(args.attempts)))
                break
            except Exception as exc:
                print(f"Invalid attempts: {exc}", file=sys.stderr)

    if args.mode == "seed-timeout-key":
        while True:
            try:
                args.s3_wait = float(prompt_text("Wait before SendKey", str(args.s3_wait)))
                break
            except Exception as exc:
                print(f"Invalid wait time: {exc}", file=sys.stderr)

    if args.mode == "multi-seed-response":
        while True:
            try:
                args.capture_window = float(prompt_text("Capture window", str(args.capture_window)))
                break
            except Exception as exc:
                print(f"Invalid capture window: {exc}", file=sys.stderr)


def print_mode_defaults(args: argparse.Namespace) -> None:
    print("\nCONFIG")
    print(f"  CAN      {args.channel}  TX=0x{args.src:X}  RX=0x{args.dst:X}")
    print(f"  Mode     {mode_code(args.mode)}  {args.mode}")
    print(f"  Session  {args.session_flow}")
    print(f"  Security seed={args.seed_subfn:02X}  key={args.key_subfn:02X}")
    print(f"  Policy   {args.key_policy}")
    if args.mode in {"one-seed-many-keys", "seed-key-exchange-loop", "penalty-then-seed"}:
        print(f"  Attempts {args.attempts}")
    if args.mode == "seed-timeout-key":
        print(f"  Wait     {args.s3_wait}s")
    if args.mode == "multi-seed-response":
        print(f"  Window   {args.capture_window}s")

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uds27_securityaccess_behavior_probe.py",
        description="UDS 0x27 SecurityAccess behavior probe.",
        usage="%(prog)s --channel can0 [options]",
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    conn = parser.add_argument_group("CAN connection")
    conn.add_argument("-c", "--channel", default="can0", help="CAN channel")
    conn.add_argument("--src", "--txid", "-t", dest="src", type=parse_can_id, help="tester transmit CAN ID")
    conn.add_argument("--dst", "--rxid", "-r", dest="dst", type=parse_can_id, help="ECU response CAN ID")
    conn.add_argument("--interface", default="socketcan", help="python-can interface")
    conn.add_argument("--extended-id", action="store_true", help="use 29-bit CAN IDs")

    flow = parser.add_argument_group("UDS mode and flow")
    flow.add_argument("--mode", choices=MODE_CHOICES, help="test mode")
    flow.add_argument("--preset", choices=["testcase", "unlock-check"], default="testcase", help="mode default profile")
    flow.add_argument("--session-flow", help="diagnostic session flow")
    flow.add_argument("--seed-subfn", type=parse_byte, help="RequestSeed sub-function")
    flow.add_argument("--key-subfn", type=parse_byte, help="SendKey sub-function")
    flow.add_argument("--attempts", type=int, default=None, help="key attempts or exchanges")
    flow.add_argument("--s3-wait", type=float, default=None, help="wait before SendKey")
    flow.add_argument("--capture-window", type=float, default=None, help="extra listen window")
    flow.add_argument("--penalty-probe-delay", type=float, default=None, help="delay before penalty probe")
    flow.add_argument("--interactive-tuning", action="store_true", help="ask attempts/wait/window interactively for applicable modes")

    key = parser.add_argument_group("Key generation")
    key.add_argument(
        "--key-policy",
        choices=["valid", "invalid-bitflip", "format-random", "zero", "pattern", "explicit"],
        help="key generation policy; mode-specific default if omitted",
    )
    key.add_argument("--key-hex", help="explicit key bytes for --key-policy explicit")
    key.add_argument("--pattern-byte", type=parse_byte, default=0xAA, help="pattern byte")

    timing = parser.add_argument_group("Timing and ISO-TP")
    timing.add_argument("--timeout", type=float, default=1.0, help="response timeout")
    timing.add_argument("--response-pending-timeout", type=float, default=5.0, help="max wait after NRC 0x78")
    timing.add_argument("--post-session-delay", type=float, default=0.05, help="delay after each 0x10 session step")
    timing.add_argument("--key-delay", type=float, default=0.05, help="delay before each SendKey")
    timing.add_argument("--delay", type=float, default=0.2, help="delay between repeated attempts/exchanges")
    timing.add_argument("--request-stmin", type=float, default=0.0, help="minimum delay between outgoing ISO-TP CF frames")
    timing.add_argument("--fc-wait-timeout", type=float, default=3.0, help="max wait for ECU FlowControl while sending multi-frame requests")
    timing.add_argument("--padding", type=parse_byte, default=0x00, help="CAN padding byte")
    timing.add_argument("--fc-bs", type=parse_byte, default=0x00, help="FlowControl BlockSize sent to ECU")
    timing.add_argument("--fc-stmin", type=parse_byte, default=0x00, help="FlowControl STmin sent to ECU")
    timing.add_argument("--drain-before-run", action="store_true", help="drain stale CAN frames before opening session")

    behavior = parser.add_argument_group("Behavior")
    behavior.add_argument("--strict-session", action="store_true", help="fail on session NRC 0x7E/0x7F")
    behavior.add_argument("--stop-on-positive-unlock", action=argparse.BooleanOptionalAction, default=None, help="stop repeated key attempts if SendKey succeeds; mode default if omitted")

    log = parser.add_argument_group("Logging")
    log.add_argument("--show-process", action="store_true", help="print each UDS step")
    log.add_argument("--verbose", action="store_true", help="print raw RX frames/debug details")
    log.add_argument("--show-can", action="store_true", help="print transmitted CAN frames")
    log.add_argument("--quiet-can", action="store_true", help=argparse.SUPPRESS)
    log.add_argument("--no-summary", action="store_true", help="do not print summary table")

    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.src is None or args.dst is None:
        parser.error("internal error: src/dst must be prompted before validation")
    if not args.extended_id and (args.src > 0x7FF or args.dst > 0x7FF):
        parser.error("standard CAN IDs must be <= 0x7FF; use --extended-id for 29-bit IDs")

    for field in ["timeout", "response_pending_timeout"]:
        if getattr(args, field) <= 0:
            parser.error(f"--{field.replace('_', '-')} must be > 0")

    for field in [
        "post_session_delay",
        "key_delay",
        "delay",
        "request_stmin",
        "fc_wait_timeout",
        "s3_wait",
        "capture_window",
        "penalty_probe_delay",
    ]:
        if getattr(args, field) < 0:
            parser.error(f"--{field.replace('_', '-')} must be >= 0")

    if args.attempts <= 0:
        parser.error("--attempts must be > 0")

    if args.seed_subfn is None:
        parser.error("internal error: seed_subfn must be prompted before validation")

    if args.key_subfn is None:
        args.key_subfn = default_send_key_subfn(args.seed_subfn)

    if args.seed_subfn % 2 == 0:
        print("Warning: RequestSeed sub-function is normally odd. Even values usually mean SendKey.", file=sys.stderr)

    if args.key_subfn % 2 != 0:
        print("Warning: SendKey sub-function is normally even.", file=sys.stderr)

    try:
        case_for_seed_subfn(args.seed_subfn)
    except Exception as exc:
        parser.error(str(exc))

    if args.key_policy == "explicit" and not args.key_hex:
        parser.error("--key-policy explicit requires --key-hex")

    if args.key_hex:
        try:
            args.key_hex_bytes = parse_key_hex(args.key_hex)
        except Exception as exc:
            parser.error(f"invalid --key-hex: {exc}")
    else:
        args.key_hex_bytes = None


def open_bus(args: argparse.Namespace, log: Log) -> Tuple[Any, Any]:
    can_module = import_python_can()
    log.info(f"  connect                 {args.channel}")
    try:
        bus = can_module.interface.Bus(channel=args.channel, interface=args.interface)
    except TypeError:
        bus = can_module.interface.Bus(channel=args.channel, bustype=args.interface)
    return can_module, bus


def run_selected_mode(isotp: IsoTp, args: argparse.Namespace, log: Log) -> Tuple[int, List[Observation]]:
    observations: List[Observation] = []

    if args.drain_before_run:
        isotp.drain()

    try:
        session_flow = parse_session_flow(args.session_flow)
    except Exception as exc:
        raise ValueError(f"invalid session flow: {exc}") from exc

    ok, session_observations = open_session_flow(isotp, session_flow, args, log)
    observations.extend(session_observations)
    if not ok:
        log.info("  abort                   session flow failed")
        return 1, observations

    mode = args.mode
    if mode == "key-without-seed":
        run_key_without_seed(isotp, args, log, observations)
    elif mode == "seed-timeout-key":
        run_seed_timeout_key(isotp, args, log, observations)
    elif mode == "one-seed-many-keys":
        run_one_seed_many_keys(isotp, args, log, observations)
    elif mode == "seed-key-exchange-loop":
        run_seed_key_exchange_loop(isotp, args, log, observations)
    elif mode == "penalty-then-seed":
        run_penalty_then_seed(isotp, args, log, observations)
    elif mode == "multi-seed-response":
        run_multi_seed_response(isotp, args, log, observations)
    else:
        raise ValueError(f"unsupported mode: {mode}")

    verdict, _ = classify_verdict(mode, observations, args)
    rc = 0
    if verdict.startswith("FAIL"):
        rc = 3
    elif verdict.startswith("REVIEW") or verdict.startswith("WEAK") or verdict.startswith("UNLOCKED"):
        rc = 1
    return rc, observations


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    prompt_can_id(args, "src", "Tester TX CAN ID", "681")
    prompt_can_id(args, "dst", "ECU RX CAN ID", "601")

    prompt_mode(args)
    prompt_runtime_fields(args)
    apply_mode_defaults(args)
    if args.interactive_tuning:
        prompt_advanced_fields(args)
    print_mode_defaults(args)

    validate_args(parser, args)

    log = Log(verbose=args.verbose, show_process=args.show_process, show_tx_can=args.show_can and not args.quiet_can)

    log.info("\nRUN")

    try:
        can_module, bus = open_bus(args, log)
    except Exception as exc:
        print(f"[abort] cannot open CAN bus: {exc}", file=sys.stderr)
        return 1

    isotp = IsoTp(
        bus=bus,
        can_module=can_module,
        txid=args.src,
        rxid=args.dst,
        log=log,
        extended_id=args.extended_id,
        pad=args.padding,
        fc_bs=args.fc_bs,
        fc_stmin=args.fc_stmin,
        request_stmin=args.request_stmin,
        fc_wait_timeout=args.fc_wait_timeout,
    )

    observations: List[Observation] = []
    try:
        rc, observations = run_selected_mode(isotp, args, log)
    except KeyboardInterrupt:
        log.info("Interrupted by user")
        rc = 130
    except Exception as exc:
        print(f"[abort] {type(exc).__name__}: {exc}", file=sys.stderr)
        rc = 1
    finally:
        try:
            bus.shutdown()
        except Exception:
            pass

    if observations and not args.no_summary:
        print_summary(args.mode, observations, args)

    log.info("\nDONE" if rc == 0 else f"\nDONE rc={rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
