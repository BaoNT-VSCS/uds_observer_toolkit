#!/usr/bin/env python3
"""
UDS 0x27 same-session seed sampler, improved.

Purpose:
  Open one diagnostic-session flow once, then repeatedly send SecurityAccess
  RequestSeed inside the final active session. The script records seed frequency,
  duplicate statistics, and non-seed response statistics.

Safety boundary:
  This tool only requests seeds. It does not send keys, brute-force credentials,
  or attempt to unlock an ECU. Use only on an ECU, simulator, or bench that you
  are authorized to test.

Dependency for actual CAN execution:
  pip install python-can
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "3.0.0"

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

SEED_EMPTY_MARKER = "<EMPTY>"


class RawDefaultsHelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawDescriptionHelpFormatter,
):
    pass


def import_python_can() -> Any:
    """Lazy import so -h and --version work without python-can installed."""
    try:
        import can  # type: ignore
    except ImportError as exc:
        print("Missing dependency: python-can. Install with: pip install python-can", file=sys.stderr)
        raise SystemExit(2) from exc
    return can


def parse_hex_int(value: str) -> int:
    """Parse CAN IDs / UDS bytes. Values without 0x are treated as hex."""
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
        raise argparse.ArgumentTypeError(f"byte value out of range 0x00..0xFF: {value}")
    return n


def parse_can_id(value: str) -> int:
    n = parse_hex_int(value)
    if not 0 <= n <= 0x1FFFFFFF:
        raise argparse.ArgumentTypeError(f"CAN ID out of range: {value}")
    return n


def hx(value: int, width: int = 2) -> str:
    return f"0x{value:0{width}X}"


def can_id_hx(value: int) -> str:
    return hx(value, 8 if value > 0x7FF else 3)


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def pad8(data: Iterable[int], pad: int) -> bytes:
    payload = bytes(data)
    if len(payload) > 8:
        raise ValueError("CAN frame payload exceeds 8 bytes")
    return payload + bytes([pad & 0xFF] * (8 - len(payload)))


def parse_session_flow(text: str) -> List[int]:
    """Parse '03 41', '03,41', '0x03 -> 0x41'."""
    normalized = str(text or "").strip()
    if not normalized:
        raise ValueError("session flow cannot be empty")
    tokens = [t for t in re.split(r"[\s,;>\-]+", normalized) if t]
    flow: List[int] = []
    for token in tokens:
        try:
            flow.append(parse_byte(token))
        except argparse.ArgumentTypeError as exc:
            raise ValueError(f"invalid session subfunction '{token}': {exc}") from exc
    if not flow:
        raise ValueError("session flow cannot be empty")
    return flow


def prompt_session_flow(args: argparse.Namespace) -> List[int]:
    if args.session_flow:
        return parse_session_flow(args.session_flow)
    while True:
        raw = input("Enter the session flow to open: ").strip()
        try:
            return parse_session_flow(raw)
        except Exception as exc:
            print(f"Invalid session flow: {exc}", file=sys.stderr)


def prompt_seed_subfn(args: argparse.Namespace) -> int:
    if args.seed_subfn is not None:
        subfn = args.seed_subfn
    else:
        while True:
            raw = input("Enter RequestSeed subfunction: ").strip()
            try:
                subfn = parse_byte(raw)
                break
            except Exception as exc:
                print(f"Invalid RequestSeed subfunction: {exc}", file=sys.stderr)
    if subfn % 2 == 0:
        print(
            "[warning] RequestSeed subfunction is normally odd; even subfunctions are normally SendKey.",
            file=sys.stderr,
        )
    return subfn

def prompt_can_id(args: argparse.Namespace, attr_name: str, prompt_text: str) -> int:
    current = getattr(args, attr_name, None)
    if current is not None:
        return current

    while True:
        try:
            raw = input(prompt_text).strip()
        except EOFError:
            raise SystemExit(f"Missing required CAN ID: --{attr_name}")

        try:
            value = parse_can_id(raw)
            setattr(args, attr_name, value)
            return value
        except Exception as exc:
            print(f"Invalid {attr_name}: {exc}", file=sys.stderr)


class IsoTpMinimal:
    """Small ISO-TP helper for normal addressing over python-can.

    Implemented:
      - Single-frame and multi-frame requests.
      - Single-frame and multi-frame responses.
      - Flow Control for ECU multi-frame responses.

    Not implemented:
      - Extended/mixed ISO-TP addressing.
      - CAN FD.
      - Functional broadcast diagnostics.
    """

    def __init__(
        self,
        bus: Any,
        txid: int,
        rxid: int,
        *,
        can_module: Any,
        extended_id: bool = False,
        pad: int = 0x00,
        fc_bs: int = 0x00,
        fc_stmin: int = 0x00,
    ) -> None:
        self.bus = bus
        self.txid = txid
        self.rxid = rxid
        self.can = can_module
        self.extended_id = extended_id
        self.pad = pad & 0xFF
        self.fc_bs = fc_bs & 0xFF
        self.fc_stmin = fc_stmin & 0xFF

    def _send_can(self, data: bytes) -> None:
        msg = self.can.Message(
            arbitration_id=self.txid,
            data=data,
            is_extended_id=self.extended_id,
        )
        self.bus.send(msg)

    def _recv_can(self, timeout: float) -> Optional[Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            msg = self.bus.recv(timeout=remaining)
            if msg is None:
                return None
            if msg.arbitration_id == self.rxid:
                return msg
        return None

    def drain_rx(self, max_time: float) -> int:
        """Drain stale frames before sending a new request.

        python-can consumes all frames returned by the interface. This mirrors the
        existing receive behavior, which already discards non-matching CAN IDs.
        Keep max_time small on busy buses.
        """
        if max_time <= 0:
            return 0
        deadline = time.monotonic() + max_time
        drained = 0
        while time.monotonic() < deadline:
            msg = self.bus.recv(timeout=max(0.0, min(0.005, deadline - time.monotonic())))
            if msg is None:
                break
            drained += 1
        return drained

    def send_payload(self, payload: bytes) -> None:
        if len(payload) <= 7:
            pci = len(payload) & 0x0F
            self._send_can(pad8([pci] + list(payload), self.pad))
            return

        total_len = len(payload)
        ff0 = 0x10 | ((total_len >> 8) & 0x0F)
        ff1 = total_len & 0xFF
        self._send_can(pad8([ff0, ff1] + list(payload[:6]), self.pad))

        fc = self._recv_can(timeout=1.0)
        if fc is None or len(fc.data) < 3 or (fc.data[0] >> 4) != 0x3:
            raise TimeoutError("no Flow Control received for multi-frame request")
        if (fc.data[0] & 0x0F) != 0x0:
            raise RuntimeError(f"receiver did not ContinueToSend, FC={bytes_to_hex(bytes(fc.data))}")

        offset = 6
        sn = 1
        while offset < total_len:
            chunk = payload[offset : offset + 7]
            cf0 = 0x20 | (sn & 0x0F)
            self._send_can(pad8([cf0] + list(chunk), self.pad))
            offset += len(chunk)
            sn = (sn + 1) & 0x0F

    def send_flow_control(self) -> None:
        self._send_can(pad8([0x30, self.fc_bs, self.fc_stmin], self.pad))

    def recv_payload(self, timeout: float) -> bytes:
        msg = self._recv_can(timeout=timeout)
        if msg is None:
            raise TimeoutError("no response frame received")

        data = bytes(msg.data)
        if not data:
            raise RuntimeError("empty CAN frame received")

        pci_type = data[0] >> 4
        if pci_type == 0x0:
            length = data[0] & 0x0F
            if length > len(data) - 1:
                raise RuntimeError(f"invalid Single Frame length {length}: {bytes_to_hex(data)}")
            return data[1 : 1 + length]

        if pci_type == 0x1:
            total_len = ((data[0] & 0x0F) << 8) | data[1]
            payload = bytearray(data[2:8])
            self.send_flow_control()

            expected_sn = 1
            while len(payload) < total_len:
                cf = self._recv_can(timeout=timeout)
                if cf is None:
                    raise TimeoutError("timeout while waiting for Consecutive Frame")
                cf_data = bytes(cf.data)
                if not cf_data or (cf_data[0] >> 4) != 0x2:
                    continue
                sn = cf_data[0] & 0x0F
                if sn != expected_sn:
                    raise RuntimeError(f"wrong Consecutive Frame SN: expected {expected_sn:X}, got {sn:X}")
                payload.extend(cf_data[1:8])
                expected_sn = (expected_sn + 1) & 0x0F
            return bytes(payload[:total_len])

        if pci_type == 0x3:
            raise RuntimeError(f"unexpected Flow Control frame from ECU: {bytes_to_hex(data)}")
        raise RuntimeError(f"unknown ISO-TP PCI type {pci_type:X}: {bytes_to_hex(data)}")

    def uds_request(
        self,
        payload: bytes,
        timeout: float,
        response_pending_timeout: float,
        *,
        drain_before_s: float = 0.0,
    ) -> Tuple[bytes, int, int]:
        """Send UDS payload and return final response, NRC 0x78 count, drained frame count."""
        drained = self.drain_rx(drain_before_s)
        self.send_payload(payload)
        deadline = time.monotonic() + response_pending_timeout
        pending_count = 0

        while True:
            remaining = max(0.0, min(timeout, deadline - time.monotonic()))
            if remaining <= 0:
                raise TimeoutError("timed out waiting for final UDS response")
            response = self.recv_payload(timeout=remaining)
            if (
                len(response) >= 3
                and response[0] == 0x7F
                and response[1] == payload[0]
                and response[2] == 0x78
            ):
                pending_count += 1
                continue
            return response, pending_count, drained


def normalize_echo_subfn(value: int) -> int:
    """Compare subfunction echo while tolerating suppress-positive-response bit."""
    return value & 0x7F


def parse_uds_response(
    payload: bytes,
    requested_sid: int,
    requested_subfn: int,
) -> Tuple[str, bool, str, str, bytes, str]:
    """Return response_type, accepted, nrc_hex, nrc_name, seed, note."""
    if not payload:
        return "empty", False, "", "", b"", "empty UDS payload"

    if payload[0] == 0x7F:
        if len(payload) < 3:
            return "malformed_negative", False, "", "malformedNegativeResponse", b"", "malformed negative response"
        if payload[1] != requested_sid:
            nrc = payload[2]
            return (
                "negative_other_service",
                False,
                hx(nrc),
                NRC_NAMES.get(nrc, "unknownNRC"),
                b"",
                f"negative response belongs to SID {hx(payload[1])}, expected {hx(requested_sid)}",
            )
        nrc = payload[2]
        return "negative", False, hx(nrc), NRC_NAMES.get(nrc, "unknownNRC"), b"", "negative response"

    expected_positive_sid = (requested_sid + 0x40) & 0xFF
    if payload[0] != expected_positive_sid:
        return (
            "unexpected_sid",
            False,
            "",
            "",
            b"",
            f"unexpected response SID: got {hx(payload[0])}, expected {hx(expected_positive_sid)}",
        )

    if requested_sid in {0x10, 0x11, 0x3E}:
        if len(payload) >= 2 and normalize_echo_subfn(payload[1]) != normalize_echo_subfn(requested_subfn):
            return (
                "unexpected_subfunction",
                False,
                "",
                "",
                b"",
                f"subfunction mismatch: got {hx(payload[1])}, expected {hx(requested_subfn)}",
            )
        return "positive", True, "", "", b"", "positive response"

    if requested_sid == 0x27:
        if len(payload) < 2:
            return "malformed_positive", False, "", "", b"", "0x67 response missing security subfunction"
        if normalize_echo_subfn(payload[1]) != normalize_echo_subfn(requested_subfn):
            return (
                "unexpected_subfunction",
                False,
                "",
                "",
                b"",
                f"security subfunction mismatch: got {hx(payload[1])}, expected {hx(requested_subfn)}",
            )
        if len(payload) == 2:
            return "positive_empty_seed", True, "", "", b"", "positive 0x67 response with zero-length seed"
        return "positive_seed", True, "", "", payload[2:], "seed received"

    return "positive", True, "", "", b"", "positive response"


def uds_call(isotp: IsoTpMinimal, service_id: int, subfn: int, args: argparse.Namespace) -> Dict[str, object]:
    raw_payload = b""
    pending = 0
    drained = 0
    try:
        raw_payload, pending, drained = isotp.uds_request(
            bytes([service_id, subfn]),
            args.timeout,
            args.response_pending_timeout,
            drain_before_s=args.drain_before_request,
        )
        rtype, accepted, nrc, nrc_name, seed, note = parse_uds_response(raw_payload, service_id, subfn)
        return {
            "response_type": rtype,
            "accepted": accepted,
            "nrc": nrc,
            "nrc_name": nrc_name,
            "seed": seed,
            "pending": pending,
            "drained": drained,
            "raw_payload": raw_payload,
            "note": note,
        }
    except TimeoutError as exc:
        return {
            "response_type": "timeout",
            "accepted": False,
            "nrc": "",
            "nrc_name": "",
            "seed": b"",
            "pending": pending,
            "drained": drained,
            "raw_payload": raw_payload,
            "note": f"timeout: {exc}",
        }
    except Exception as exc:
        return {
            "response_type": "error",
            "accepted": False,
            "nrc": "",
            "nrc_name": "",
            "seed": b"",
            "pending": pending,
            "drained": drained,
            "raw_payload": raw_payload,
            "note": f"error: {exc}",
        }


def process_enabled(args: argparse.Namespace) -> bool:
    return bool(args.show_process and not args.quiet)


def response_bucket(result: Dict[str, object]) -> str:
    rtype = str(result.get("response_type") or "unknown")
    nrc = str(result.get("nrc") or "")
    nrc_name = str(result.get("nrc_name") or "")
    if rtype == "negative" and nrc:
        return f"negative:{nrc}:{nrc_name or 'unknownNRC'}"
    return rtype


def send_tester_present(isotp: IsoTpMinimal, args: argparse.Namespace) -> Dict[str, object]:
    result = uds_call(isotp, 0x3E, args.tester_present_subfn, args)
    if not bool(result.get("accepted")) and process_enabled(args):
        print(
            f"[tester-present] {response_bucket(result)} note={result.get('note')}",
            file=sys.stderr,
        )
    return result


def request_seed_with_nrc37_retry(
    isotp: IsoTpMinimal,
    args: argparse.Namespace,
    seed_subfn: int,
) -> Dict[str, object]:
    total_pending = 0
    total_drained = 0
    nrc37_retries = 0
    wait_total = 0.0
    attempts = 0
    last_result: Dict[str, object] = {}

    while True:
        attempts += 1
        result = uds_call(isotp, 0x27, seed_subfn, args)
        total_pending += int(result.get("pending", 0))
        total_drained += int(result.get("drained", 0))
        last_result = result

        should_retry_nrc37 = (
            args.retry_on_nrc37
            and result.get("response_type") == "negative"
            and result.get("nrc") == "0x37"
            and nrc37_retries < args.nrc37_max_retries
        )
        if not should_retry_nrc37:
            break

        sleep_s = args.nrc37_wait * (args.nrc37_backoff ** nrc37_retries)
        nrc37_retries += 1
        if process_enabled(args):
            print(f"[nrc37] retry {nrc37_retries}/{args.nrc37_max_retries} after {sleep_s:.3f}s")
        if sleep_s > 0:
            time.sleep(sleep_s)
            wait_total += sleep_s

    last_result["pending"] = total_pending
    last_result["drained"] = total_drained
    last_result["attempts"] = attempts
    last_result["nrc37_retries"] = nrc37_retries
    last_result["nrc37_wait_total_s"] = round(wait_total, 6)
    return last_result


def open_session_flow(isotp: IsoTpMinimal, args: argparse.Namespace, session_flow: List[int]) -> bool:
    show_process = process_enabled(args)
    if show_process:
        flow_text = " -> ".join(f"10 {subfn:02X}" for subfn in session_flow)
        print(f"[session-flow] {flow_text}")

    for idx, subfn in enumerate(session_flow, start=1):
        result = uds_call(isotp, 0x10, subfn, args)
        if bool(result.get("accepted")):
            if show_process:
                print(f"[session {idx}/{len(session_flow)}] 10 {subfn:02X} -> OK")
        else:
            raw_payload = result.get("raw_payload", b"")
            raw = bytes_to_hex(raw_payload) if isinstance(raw_payload, bytes) and raw_payload else "-"
            if show_process or not args.continue_on_session_error:
                print(
                    f"[session {idx}/{len(session_flow)}] 10 {subfn:02X} -> {response_bucket(result)} "
                    f"pending={result.get('pending')} raw={raw} note={result.get('note')}",
                    file=sys.stderr,
                )
            if not args.continue_on_session_error:
                return False

        if args.post_session_delay > 0:
            time.sleep(args.post_session_delay)

    return True


def pct(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100.0, 2)


def print_seed_counts(seed_counts: Counter[str], seed_sample_count: int) -> None:
    print("\nseed_counts:")
    if seed_sample_count <= 0:
        print("  no positive non-empty seed samples collected")
        return

    seed_width = max(8, max((len(seed) for seed in seed_counts), default=8))
    print(f"  {'seed'.ljust(seed_width)}  count  occurrence_%")
    for seed_hex, count in seed_counts.most_common():
        occurrence_rate = pct(count, seed_sample_count)
        print(f"  {seed_hex.ljust(seed_width)}  {count:5d}  {occurrence_rate:10.2f}")


def print_response_counts(response_counts: Counter[str]) -> None:
    if not response_counts:
        return
    print("\nnon_seed_response_counts:")
    for key, count in response_counts.most_common():
        print(f"  {key}: {count}")


def print_summary(
    *,
    requested_samples: int,
    seed_counts: Counter[str],
    positive_seed_samples: int,
    empty_seed_samples: int,
    non_seed_count: int,
    total_pending: int,
    total_drained: int,
) -> None:
    duplicate_seed_values = sum(1 for count in seed_counts.values() if count > 1)
    duplicate_occurrences = sum(count - 1 for count in seed_counts.values() if count > 1)
    duplicate_rate = pct(duplicate_occurrences, positive_seed_samples)
    unique_seed_count = len(seed_counts)

    print("\nsummary:")
    print(f"  requested_samples: {requested_samples}")
    print(f"  positive_seed_samples: {positive_seed_samples}")
    print(f"  unique_seed_values: {unique_seed_count}")
    print(f"  empty_seed_positive_responses: {empty_seed_samples}")
    print(f"  non_seed_responses: {non_seed_count}")
    print(f"  duplicate_seed_values: {duplicate_seed_values}")
    print(f"  duplicate_occurrences: {duplicate_occurrences}")
    print(f"  duplicate_rate: {duplicate_rate if duplicate_rate is not None else 'N/A'}%")
    print(f"  total_response_pending_0x78: {total_pending}")
    print(f"  total_drained_stale_frames: {total_drained}")


def run(args: argparse.Namespace) -> int:
    session_flow = prompt_session_flow(args)
    seed_subfn = prompt_seed_subfn(args)

    can = import_python_can()
    try:
        bus = can.interface.Bus(channel=args.channel, interface=args.interface)
    except TypeError:
        bus = can.interface.Bus(channel=args.channel, bustype=args.interface)
    except Exception as exc:
        print(f"[abort] cannot open CAN bus {args.interface}:{args.channel}: {exc}", file=sys.stderr)
        return 1

    isotp = IsoTpMinimal(
        bus,
        args.src,
        args.dst,
        can_module=can,
        extended_id=args.extended_id,
        pad=args.padding,
        fc_bs=args.fc_bs,
        fc_stmin=args.fc_stmin,
    )

    seed_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    positive_seed_samples = 0
    empty_seed_samples = 0
    non_seed_count = 0
    total_pending = 0
    total_drained = 0
    executed_samples = 0
    last_tester_present = time.monotonic()
    show_process = process_enabled(args)

    if show_process:
        print(
            f"[init] interface={args.interface} channel={args.channel} "
            f"src/txid={can_id_hx(args.src)} dst/rxid={can_id_hx(args.dst)}"
        )
        print(f"[seed-request] 27 {seed_subfn:02X}; count={args.count}; delay={args.delay}s")

    try:
        if not open_session_flow(isotp, args, session_flow):
            print("[abort] session flow was not completed", file=sys.stderr)
            return 1

        for i in range(1, args.count + 1):
            executed_samples += 1
            now = time.monotonic()
            if not args.no_tester_present and args.tester_present_interval > 0:
                if now - last_tester_present >= args.tester_present_interval:
                    tp_result = send_tester_present(isotp, args)
                    total_pending += int(tp_result.get("pending", 0))
                    total_drained += int(tp_result.get("drained", 0))
                    last_tester_present = time.monotonic()

            result = request_seed_with_nrc37_retry(isotp, args, seed_subfn)
            total_pending += int(result.get("pending", 0))
            total_drained += int(result.get("drained", 0))
            response_type = str(result.get("response_type") or "unknown")

            if response_type == "positive_seed":
                seed = result.get("seed", b"")
                if not isinstance(seed, bytes):
                    seed = b""
                seed_hex = bytes_to_hex(seed)
                positive_seed_samples += 1
                seed_counts[seed_hex] += 1
                if show_process:
                    print(f"[{i:03d}/{args.count:03d}] seed={seed_hex}")
            elif response_type == "positive_empty_seed":
                empty_seed_samples += 1
                if args.count_empty_seed_as_seed:
                    positive_seed_samples += 1
                    seed_counts[SEED_EMPTY_MARKER] += 1
                else:
                    non_seed_count += 1
                    response_counts[response_bucket(result)] += 1
                if show_process:
                    print(f"[{i:03d}/{args.count:03d}] empty-seed-positive")
            else:
                non_seed_count += 1
                response_counts[response_bucket(result)] += 1
                if show_process:
                    raw_payload = result.get("raw_payload", b"")
                    raw = bytes_to_hex(raw_payload) if isinstance(raw_payload, bytes) and raw_payload else "-"
                    print(
                        f"[{i:03d}/{args.count:03d}] no_seed type={response_bucket(result)} "
                        f"raw={raw} pending={result.get('pending')} attempts={result.get('attempts')} "
                        f"nrc37_retry={result.get('nrc37_retries')} note={result.get('note')}",
                        file=sys.stderr,
                    )

            if args.stop_on_session_lost and result.get("nrc") in {"0x7E", "0x7F"}:
                print("[stop] service/subfunction no longer supported in active session", file=sys.stderr)
                break
            if args.stop_on_sequence_error and result.get("nrc") == "0x24":
                print("[stop] requestSequenceError; ECU likely requires SendKey or state reset", file=sys.stderr)
                break

            if i != args.count and args.delay > 0:
                time.sleep(args.delay)

    except KeyboardInterrupt:
        print("\n[stop] interrupted by user; printing partial summary", file=sys.stderr)
    finally:
        try:
            bus.shutdown()
        except Exception:
            pass

    print_seed_counts(seed_counts, positive_seed_samples)
    print_response_counts(response_counts)
    print_summary(
        requested_samples=executed_samples,
        seed_counts=seed_counts,
        positive_seed_samples=positive_seed_samples,
        empty_seed_samples=empty_seed_samples,
        non_seed_count=non_seed_count,
        total_pending=total_pending,
        total_drained=total_drained,
    )
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    epilog = """examples:
  python3 uds27_seed_sampler_same_session.py --channel can0
  python3 uds27_seed_sampler_same_session.py --channel can0 --session-flow "03 41" --seed-subfn 01 --show-process

interpretation:
  This script samples repeated 0x27 RequestSeed responses inside one active session.
  It is suitable for checking same-session seed reuse, state locking, NRC 0x24, NRC 0x37, and duplicate seed behavior.
"""
    parser = argparse.ArgumentParser(
        prog="uds27_seed_sampler_same_session.py",
        usage="%(prog)s --channel can0 [--src 0x681 --dst 0x601] [options]",
        description="Sample UDS 0x27 seeds repeatedly in one active diagnostic session.",
        epilog=epilog,
        formatter_class=RawDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    conn = parser.add_argument_group("CAN / ISO-TP")
    conn.add_argument("--interface", default="socketcan", help="python-can backend/interface")
    conn.add_argument("--channel", "-c", default="can0", help="CAN channel/interface name")
    conn.add_argument("--src", "--txid", type=parse_can_id, help="tester transmit arbitration ID; prompts if omitted")
    conn.add_argument("--dst", "--rxid", type=parse_can_id, help="ECU response arbitration ID; prompts if omitted")
    conn.add_argument("--extended-id", action="store_true", help="use 29-bit CAN IDs")
    conn.add_argument("--padding", type=parse_byte, default=parse_byte("0x00"), help="CAN frame padding byte")
    conn.add_argument("--fc-bs", type=parse_byte, default=parse_byte("0x00"), help="ISO-TP Flow Control Block Size")
    conn.add_argument("--fc-stmin", type=parse_byte, default=parse_byte("0x00"), help="ISO-TP Flow Control STmin byte")

    req = parser.add_argument_group("UDS request input")
    req.add_argument("--session-flow", help="non-interactive session flow, e.g. '03 41'; prompts if omitted")
    req.add_argument("--seed-subfn", type=parse_byte, help="non-interactive RequestSeed subfunction, e.g. 01; prompts if omitted")

    timing = parser.add_argument_group("timing / retry")
    timing.add_argument("--count", "-n", type=int, default=20, help="number of RequestSeed samples")
    timing.add_argument("--delay", "-d", type=float, default=0.2, help="delay between RequestSeed samples, seconds")
    timing.add_argument("--post-session-delay", type=float, default=0.05, help="delay after each DiagnosticSessionControl request, seconds")
    timing.add_argument("--timeout", "-t", type=float, default=1.0, help="per-frame/final-response wait timeout, seconds")
    timing.add_argument("--response-pending-timeout", type=float, default=5.0, help="maximum wait for final response after NRC 0x78")
    timing.add_argument("--drain-before-request", type=float, default=0.0, help="small RX drain window before every UDS request, seconds")
    timing.add_argument("--no-tester-present", action="store_true", help="do not send TesterPresent during long runs")
    timing.add_argument("--tester-present-interval", type=float, default=2.0, help="TesterPresent interval, seconds")
    timing.add_argument("--tester-present-subfn", type=parse_byte, default=parse_byte("0x00"), help="TesterPresent subfunction")
    timing.add_argument("--retry-on-nrc37", dest="retry_on_nrc37", action="store_true", default=True, help="retry same RequestSeed sample after NRC 0x37")
    timing.add_argument("--no-retry-on-nrc37", dest="retry_on_nrc37", action="store_false", help="do not retry after NRC 0x37")
    timing.add_argument("--nrc37-wait", type=float, default=1.0, help="base wait before retrying after NRC 0x37, seconds")
    timing.add_argument("--nrc37-max-retries", type=int, default=3, help="maximum retries for one sample after NRC 0x37")
    timing.add_argument("--nrc37-backoff", type=float, default=1.5, help="multiplier applied to NRC 0x37 wait after each retry")

    behavior = parser.add_argument_group("behavior / output")
    behavior.add_argument("--continue-on-session-error", action="store_true", help="continue even if one session-opening response is negative/error")
    behavior.add_argument("--stop-on-session-lost", action="store_true", help="stop if NRC 0x7E/0x7F suggests active session no longer supports the service")
    behavior.add_argument("--stop-on-sequence-error", action="store_true", help="stop on NRC 0x24 requestSequenceError")
    behavior.add_argument("--count-empty-seed-as-seed", action="store_true", help="include positive 0x67 responses with zero-length seed in duplicate statistics")
    behavior.add_argument("--show-process", "--process", action="store_true", help="show per-sample logs")
    behavior.add_argument("--quiet", "-q", action="store_true", help="suppress process logs; final statistics are still printed")

    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.extended_id and (args.src > 0x7FF or args.dst > 0x7FF):
        parser.error("standard CAN IDs must be <= 0x7FF; use --extended-id for 29-bit IDs")
    if args.count <= 0:
        parser.error("--count must be > 0")
    for name in [
        "delay",
        "post_session_delay",
        "tester_present_interval",
        "nrc37_wait",
        "drain_before_request",
    ]:
        if getattr(args, name) < 0:
            parser.error(f"--{name.replace('_', '-')} must be >= 0")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    if args.response_pending_timeout <= 0:
        parser.error("--response-pending-timeout must be > 0")
    if args.nrc37_max_retries < 0:
        parser.error("--nrc37-max-retries must be >= 0")
    if args.nrc37_backoff <= 0:
        parser.error("--nrc37-backoff must be > 0")
    if args.session_flow:
        try:
            parse_session_flow(args.session_flow)
        except ValueError as exc:
            parser.error(f"--session-flow: {exc}")


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    prompt_can_id(args, "src", "Enter tester transmit arbitration ID: ")
    prompt_can_id(args, "dst", "Enter ECU response arbitration ID: ")
    validate_args(parser, args)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
