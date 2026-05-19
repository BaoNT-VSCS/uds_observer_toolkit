"""
UDS 0x27 first-seed cross-session sampler, improved.

Purpose:
  For each sample, establish a clear session boundary, open the configured
  diagnostic-session flow, then request exactly one SecurityAccess seed. The
  script records first-seed frequency, duplicate statistics, and failed-sample
  reasons.

Default behavior:
  Before every sample, the script sends DiagnosticSessionControl defaultSession
  (10 01). This makes the test closer to true cross-session sampling than simply
  replaying the session flow while the ECU may still be in the previous session.

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

VERSION = "3.1.0"

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



def normalize_nrc_text(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return hx(int(text, 16))
    except ValueError:
        return text


def parse_nrc_list(value: str) -> set[str]:
    items: set[str] = set()
    for part in str(value or "").split(","):
        token = part.strip()
        if token:
            items.add(normalize_nrc_text(token))
    return items


def session_control_with_retry(isotp: IsoTpMinimal, args: argparse.Namespace, subfn: int) -> Dict[str, object]:
    retry_nrcs = parse_nrc_list(args.session_retry_nrcs)
    attempts = 0
    retries = 0
    total_pending = 0
    total_drained = 0
    last_result: Dict[str, object] = {}

    while True:
        attempts += 1
        result = uds_call(isotp, 0x10, subfn, args)
        total_pending += int(result.get("pending", 0))
        total_drained += int(result.get("drained", 0))
        last_result = result

        rtype = str(result.get("response_type") or "")
        nrc = normalize_nrc_text(result.get("nrc"))
        retryable_nrc = rtype == "negative" and nrc in retry_nrcs
        retryable_timeout = rtype in {"timeout", "error"} and not args.no_retry_session_timeout
        retryable = (retryable_nrc or retryable_timeout) and retries < args.session_max_retries

        if not retryable:
            break

        wait_s = args.session_retry_wait * (args.session_retry_backoff ** retries)
        retries += 1
        if process_enabled(args):
            print(f"[session-retry] 10 {subfn:02X} retry {retries}/{args.session_max_retries} after {wait_s:.3f}s")
        if wait_s > 0:
            time.sleep(wait_s)

    last_result["attempts"] = attempts
    last_result["session_retries"] = retries
    last_result["pending"] = total_pending
    last_result["drained"] = total_drained
    return last_result


def open_session_flow_cross(isotp: IsoTpMinimal, args: argparse.Namespace, session_flow: List[int]) -> Tuple[bool, str]:
    show_process = process_enabled(args)
    if show_process:
        flow_text = " -> ".join(f"10 {subfn:02X}" for subfn in session_flow)
        print(f"[session-flow] {flow_text}")

    for idx, subfn in enumerate(session_flow, start=1):
        result = session_control_with_retry(isotp, args, subfn)
        if bool(result.get("accepted")):
            if show_process:
                attempts = int(result.get("attempts", 1) or 1)
                suffix = f" attempts={attempts}" if attempts > 1 else ""
                print(f"[session {idx}/{len(session_flow)}] 10 {subfn:02X} -> OK{suffix}")
        else:
            raw_payload = result.get("raw_payload", b"")
            raw = bytes_to_hex(raw_payload) if isinstance(raw_payload, bytes) and raw_payload else "-"
            reason = f"10 {subfn:02X}:{response_bucket(result)}"
            if show_process or not args.continue_on_session_error:
                print(
                    f"[session {idx}/{len(session_flow)}] 10 {subfn:02X} -> {response_bucket(result)} "
                    f"attempts={result.get('attempts')} pending={result.get('pending')} raw={raw} note={result.get('note')}",
                    file=sys.stderr,
                )
            active_session_nrc = result.get("nrc") in {"0x7E", "0x7F"}
            if active_session_nrc and args.continue_on_active_session_nrc:
                if args.post_session_delay > 0:
                    time.sleep(args.post_session_delay)
                continue
            if not args.continue_on_session_error:
                return False, reason

        if args.post_session_delay > 0:
            time.sleep(args.post_session_delay)

    return True, ""


def apply_session_boundary(isotp: IsoTpMinimal, args: argparse.Namespace, sample_index: int) -> Tuple[bool, str]:
    mode = args.session_boundary
    show_process = process_enabled(args)

    if args.skip_boundary_before_first and sample_index == 1:
        return True, "boundary_skipped_before_first"

    if mode == "none":
        return True, "boundary_none"

    if mode == "s3":
        if show_process:
            print(f"[boundary] wait S3 timeout {args.s3_wait:.3f}s")
        if args.s3_wait > 0:
            time.sleep(args.s3_wait)
        return True, "boundary_s3_wait"

    if mode == "default":
        result = uds_call(isotp, 0x10, args.default_session_subfn, args)
        ok = bool(result.get("accepted"))
        if show_process and not ok:
            print(f"[exit-session] 10 {args.default_session_subfn:02X} -> {response_bucket(result)}", file=sys.stderr)
        if args.post_boundary_delay > 0:
            time.sleep(args.post_boundary_delay)
        if ok or not args.strict_boundary:
            return True, f"boundary_default:{response_bucket(result)}"
        return False, f"boundary_default_failed:{response_bucket(result)}"

    if mode == "reset":
        result = uds_call(isotp, 0x11, args.reset_subfn, args)
        rtype = str(result.get("response_type") or "")
        # Many ECUs reset quickly and may not leave a final positive response on the bus.
        ok = bool(result.get("accepted")) or (rtype == "timeout" and not args.strict_boundary)
        if show_process:
            print(f"[boundary] 11 {args.reset_subfn:02X} -> {response_bucket(result)}; wait {args.reset_wait:.3f}s")
        if args.reset_wait > 0:
            time.sleep(args.reset_wait)
        if ok:
            return True, f"boundary_reset:{response_bucket(result)}"
        return False, f"boundary_reset_failed:{response_bucket(result)}"

    return False, f"unsupported_boundary:{mode}"


def record_seed_result(
    *,
    result: Dict[str, object],
    seed_counts: Counter[str],
    response_counts: Counter[str],
    args: argparse.Namespace,
) -> Tuple[int, int, int]:
    """Return positive_seed_delta, empty_seed_delta, non_seed_delta."""
    response_type = str(result.get("response_type") or "unknown")

    if response_type == "positive_seed":
        seed = result.get("seed", b"")
        if not isinstance(seed, bytes):
            seed = b""
        seed_hex = bytes_to_hex(seed)
        seed_counts[seed_hex] += 1
        return 1, 0, 0

    if response_type == "positive_empty_seed":
        if args.count_empty_seed_as_seed:
            seed_counts[SEED_EMPTY_MARKER] += 1
            return 1, 1, 0
        response_counts[response_bucket(result)] += 1
        return 0, 1, 1

    response_counts[response_bucket(result)] += 1
    return 0, 0, 1


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
    show_process = process_enabled(args)

    if show_process:
        flow_text = " -> ".join(f"10 {subfn:02X}" for subfn in session_flow)
        print(
            f"[init] interface={args.interface} channel={args.channel} "
            f"src/txid={can_id_hx(args.src)} dst/rxid={can_id_hx(args.dst)}"
        )
        print(f"[seed-request] 27 {seed_subfn:02X}; count={args.count}; delay={args.inter_session_delay}s")
        if args.session_boundary == "default":
            print(
                f"[cross-session] exit-session=10 {args.default_session_subfn:02X}; "
                f"post-exit-session-delay={args.post_boundary_delay}s"
            )
        elif args.session_boundary == "reset":
            print(f"[cross-session] boundary=11 {args.reset_subfn:02X}; reset-wait={args.reset_wait}s")
        elif args.session_boundary == "s3":
            print(f"[cross-session] boundary=S3-wait; s3-wait={args.s3_wait}s")
        else:
            print("[cross-session] boundary=none")
        print(f"[target-flow] {flow_text}")

    try:
        for i in range(1, args.count + 1):
            executed_samples += 1
            boundary_ok, boundary_note = apply_session_boundary(isotp, args, i)
            if not boundary_ok:
                non_seed_count += 1
                response_counts[boundary_note] += 1
                if show_process:
                    print(f"[{i:03d}/{args.count:03d}] seed=- result={boundary_note}", file=sys.stderr)
                if args.stop_on_boundary_error:
                    print("[stop] session boundary failed", file=sys.stderr)
                    break
                if i != args.count and args.inter_session_delay > 0:
                    time.sleep(args.inter_session_delay)
                continue

            flow_ok, flow_reason = open_session_flow_cross(isotp, args, session_flow)
            if not flow_ok:
                non_seed_count += 1
                response_counts[f"session_flow_failed:{flow_reason}"] += 1
                if show_process:
                    print(f"[{i:03d}/{args.count:03d}] seed=- result=session_flow_failed:{flow_reason}", file=sys.stderr)
                if args.stop_on_session_error:
                    print("[stop] session flow failed", file=sys.stderr)
                    break
                if i != args.count and args.inter_session_delay > 0:
                    time.sleep(args.inter_session_delay)
                continue

            result = request_seed_with_nrc37_retry(isotp, args, seed_subfn)
            total_pending += int(result.get("pending", 0))
            total_drained += int(result.get("drained", 0))

            ps, es, ns = record_seed_result(
                result=result,
                seed_counts=seed_counts,
                response_counts=response_counts,
                args=args,
            )
            positive_seed_samples += ps
            empty_seed_samples += es
            non_seed_count += ns

            if show_process:
                response_type = str(result.get("response_type") or "unknown")
                if response_type == "positive_seed":
                    seed = result.get("seed", b"")
                    seed_hex = bytes_to_hex(seed) if isinstance(seed, bytes) else "-"
                    print(f"[{i:03d}/{args.count:03d}] seed={seed_hex}")
                elif response_type == "positive_empty_seed":
                    print(f"[{i:03d}/{args.count:03d}] empty-seed-positive")
                else:
                    raw_payload = result.get("raw_payload", b"")
                    raw = bytes_to_hex(raw_payload) if isinstance(raw_payload, bytes) and raw_payload else "-"
                    print(
                        f"[{i:03d}/{args.count:03d}] seed=- type={response_bucket(result)} "
                        f"raw={raw} pending={result.get('pending')} attempts={result.get('attempts')} "
                        f"nrc37_retry={result.get('nrc37_retries')} note={result.get('note')}",
                        file=sys.stderr,
                    )

            if i != args.count and args.inter_session_delay > 0:
                time.sleep(args.inter_session_delay)

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
  # interactive IDs / session-flow / seed-subfn, with first-seed-per-session sampling
  python3 uds27_first_seed_cross_session_sampler.py --channel can0 --count 20 --inter-session-delay 0.5 --post-session-delay 0.05 --post-exit-session-delay 0.05 --retry-on-nrc37 --nrc37-wait 2.0 --nrc37-max-retries 3 --nrc37-backoff 1.5 --show-process

  # non-interactive target input
  python3 uds27_first_seed_cross_session_sampler.py --channel can0 --src 0x681 --dst 0x601 --session-flow "03 41" --seed-subfn 01

  # legacy behavior: replay the session flow without forcing a session boundary
  python3 uds27_first_seed_cross_session_sampler.py --channel can0 --src 0x681 --dst 0x601 --session-boundary none

  # stronger boundary where supported: ECU reset before each sample
  python3 uds27_first_seed_cross_session_sampler.py --channel can0 --src 0x681 --dst 0x601 --session-boundary reset --reset-wait 2.0

interpretation:
  Use this script to test whether the first seed after entering a diagnostic session repeats across fresh session entries.
  Default boundary is 10 01 before every sample; choose reset or s3 if the ECU requires a stronger boundary.
"""
    parser = argparse.ArgumentParser(
        prog="uds27_first_seed_cross_session_sampler.py",
        usage="%(prog)s --channel can0 [--src 0x681 --dst 0x601] [options]",
        description="Sample the first UDS 0x27 seed after each new diagnostic-session entry.",
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

    boundary = parser.add_argument_group("session boundary")
    boundary.add_argument(
        "--session-boundary",
        choices=["default", "reset", "s3", "none"],
        default="default",
        help="how to leave the previous session before each sample",
    )
    boundary.add_argument("--default-session-subfn", type=parse_byte, default=parse_byte("0x01"), help="subfunction for DiagnosticSessionControl defaultSession")
    boundary.add_argument("--reset-subfn", type=parse_byte, default=parse_byte("0x01"), help="subfunction for ECUReset when --session-boundary reset is used")
    boundary.add_argument("--s3-wait", type=float, default=5.0, help="sleep duration for --session-boundary s3, seconds")
    boundary.add_argument("--post-boundary-delay", "--post-exit-session-delay", dest="post_boundary_delay", type=float, default=0.1, help="delay after leaving/exiting previous session before opening the target session, seconds")
    boundary.add_argument("--reset-wait", type=float, default=1.5, help="delay after ECUReset boundary, seconds")
    boundary.add_argument("--strict-boundary", action="store_true", help="treat a failed default/reset boundary as a failed sample")
    boundary.add_argument("--skip-boundary-before-first", action="store_true", help="do not apply boundary before sample 1")
    boundary.add_argument("--stop-on-boundary-error", action="store_true", help="stop the run when boundary fails")

    timing = parser.add_argument_group("timing / retry")
    timing.add_argument("--count", "-n", type=int, default=20, help="number of first-seed samples")
    timing.add_argument("--inter-session-delay", "-d", type=float, default=0.2, help="delay between samples after seed request, seconds")
    timing.add_argument("--post-session-delay", type=float, default=0.05, help="delay after each DiagnosticSessionControl step, seconds")
    timing.add_argument("--timeout", "-t", type=float, default=1.0, help="per-frame/final-response wait timeout, seconds")
    timing.add_argument("--response-pending-timeout", type=float, default=5.0, help="maximum wait for final response after NRC 0x78")
    timing.add_argument("--drain-before-request", type=float, default=0.0, help="small RX drain window before every UDS request, seconds")
    timing.add_argument("--session-retry-nrcs", default="0x21", help="comma-separated final NRCs that retry DiagnosticSessionControl")
    timing.add_argument("--session-max-retries", type=int, default=2, help="maximum retries for each 0x10 session-control request")
    timing.add_argument("--session-retry-wait", type=float, default=0.5, help="initial wait before retrying 0x10, seconds")
    timing.add_argument("--session-retry-backoff", type=float, default=1.5, help="multiplier applied to 0x10 retry wait")
    timing.add_argument("--no-retry-session-timeout", action="store_true", help="do not retry 0x10 timeout/error responses")
    timing.add_argument("--retry-on-nrc37", dest="retry_on_nrc37", action="store_true", default=True, help="retry RequestSeed sample after NRC 0x37")
    timing.add_argument("--no-retry-on-nrc37", dest="retry_on_nrc37", action="store_false", help="do not retry after NRC 0x37")
    timing.add_argument("--nrc37-wait", type=float, default=1.0, help="base wait before retrying after NRC 0x37, seconds")
    timing.add_argument("--nrc37-max-retries", type=int, default=3, help="maximum retries for one sample after NRC 0x37")
    timing.add_argument("--nrc37-backoff", type=float, default=1.5, help="multiplier applied to NRC 0x37 wait after each retry")

    behavior = parser.add_argument_group("behavior / output")
    behavior.add_argument("--continue-on-session-error", action="store_true", help="continue session flow even if a session-opening response is negative/error")
    behavior.add_argument("--continue-on-active-session-nrc", action="store_true", help="legacy mode: ignore NRC 0x7E/0x7F during session-flow steps and continue")
    behavior.add_argument("--stop-on-session-error", action="store_true", help="stop if any non-recoverable session step fails")
    behavior.add_argument("--count-empty-seed-as-seed", action="store_true", help="include positive 0x67 responses with zero-length seed in duplicate statistics")
    behavior.add_argument("--show-process", "--process", action="store_true", help="show per-sample logs")
    behavior.add_argument("--quiet", "-q", action="store_true", help="suppress process logs; final statistics are still printed")

    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.extended_id and (args.src > 0x7FF or args.dst > 0x7FF):
        parser.error("standard CAN IDs must be <= 0x7FF; use --extended-id for 29-bit IDs")
    if args.count <= 0:
        parser.error("--count must be > 0")
    non_negative_names = [
        "inter_session_delay",
        "post_session_delay",
        "post_boundary_delay",
        "reset_wait",
        "s3_wait",
        "session_retry_wait",
        "nrc37_wait",
        "drain_before_request",
    ]
    for name in non_negative_names:
        if getattr(args, name) < 0:
            parser.error(f"--{name.replace('_', '-')} must be >= 0")
    if args.timeout <= 0:
        parser.error("--timeout must be > 0")
    if args.response_pending_timeout <= 0:
        parser.error("--response-pending-timeout must be > 0")
    if args.session_max_retries < 0:
        parser.error("--session-max-retries must be >= 0")
    if args.session_retry_backoff <= 0:
        parser.error("--session-retry-backoff must be > 0")
    if args.nrc37_max_retries < 0:
        parser.error("--nrc37-max-retries must be >= 0")
    if args.nrc37_backoff <= 0:
        parser.error("--nrc37-backoff must be > 0")
    parse_nrc_list(args.session_retry_nrcs)
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
