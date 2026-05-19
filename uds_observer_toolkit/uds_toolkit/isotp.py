from __future__ import annotations

import math
import time
from typing import Any, Optional

from .logging_utils import ConsoleLog
from .utils import bhex, pad8, spaced


class IsoTpError(RuntimeError):
    pass


class IsoTp:
    """Minimal ISO-TP normal-addressing transport over python-can.

    Supported:
      - 11-bit and 29-bit CAN identifiers.
      - Single-frame and multi-frame request/response.
      - ResponsePending 0x78 handling is implemented in UDS client, not here.

    Not supported by design:
      - Extended/mixed ISO-TP addressing.
      - CAN FD ISO-TP payload sizes.
      - Functional broadcast diagnostics as a response-collecting mode.
    """

    def __init__(
        self,
        bus: Any,
        can_module: Any,
        *,
        txid: int,
        rxid: int,
        extended_id: bool = False,
        pad: int = 0x00,
        fc_bs: int = 0x00,
        fc_stmin: int = 0x00,
        request_stmin: float = 0.0,
        fc_wait_timeout: float = 3.0,
        log: ConsoleLog | None = None,
    ) -> None:
        self.bus = bus
        self.can = can_module
        self.txid = txid
        self.rxid = rxid
        self.extended_id = bool(extended_id)
        self.pad = pad & 0xFF
        self.fc_bs = fc_bs & 0xFF
        self.fc_stmin = fc_stmin & 0xFF
        self.request_stmin = max(0.0, float(request_stmin))
        self.fc_wait_timeout = max(0.1, float(fc_wait_timeout))
        self.log = log or ConsoleLog()

    def send_can(self, data: bytes) -> None:
        msg = self.can.Message(arbitration_id=self.txid, data=data, is_extended_id=self.extended_id)
        self.bus.send(msg)
        self.log.tx_can(self.txid, data)

    def recv_can(self, timeout: float) -> Optional[bytes]:
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            msg = self.bus.recv(timeout=remaining)
            if msg is None:
                return None
            data = bytes(msg.data)
            if msg.arbitration_id == self.rxid:
                self.log.rx_can(msg.arbitration_id, data)
                return data
            self.log.debug(f"  CAN SKIP {msg.arbitration_id:X}#{data.hex().upper()}")
        return None

    def drain(self, seconds: float) -> int:
        if seconds <= 0:
            return 0
        deadline = time.monotonic() + seconds
        count = 0
        while time.monotonic() < deadline:
            msg = self.bus.recv(timeout=min(0.005, max(0.0, deadline - time.monotonic())))
            if msg is None:
                break
            count += 1
        if count:
            self.log.process(f"  drain                  {count} stale CAN frame(s)")
        return count

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
        deadline = time.monotonic() + max(0.1, timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timeout waiting for FlowControl {label}")
            frame = self.recv_can(timeout=remaining)
            if frame is None:
                raise TimeoutError(f"timeout waiting for FlowControl {label}")
            if len(frame) < 3 or (frame[0] >> 4) != 0x3:
                self.log.debug(f"  ignore non-FC while waiting {label}: {bhex(frame)}")
                continue
            fs = frame[0] & 0x0F
            if fs == 0x00:
                return frame
            if fs == 0x01:
                self.log.process(f"  isotp                  FC.WAIT {label}")
                continue
            if fs == 0x02:
                raise IsoTpError(f"FlowControl overflow {label}: {bhex(frame)}")
            raise IsoTpError(f"unsupported FlowControl status {fs:X} {label}: {bhex(frame)}")

    def send_flow_control(self) -> None:
        self.send_can(pad8([0x30, self.fc_bs, self.fc_stmin], self.pad))

    def recv_payload(self, timeout: float, *, frame_label: str = "Response") -> bytes:
        data = self.recv_can(timeout=timeout)
        if data is None:
            raise TimeoutError("timeout waiting for ISO-TP response")
        if not data:
            raise IsoTpError("empty CAN frame")
        pci_type = data[0] >> 4

        if pci_type == 0x0:
            length = data[0] & 0x0F
            if length > len(data) - 1:
                raise IsoTpError(f"invalid SingleFrame length {length} in {bhex(data)}")
            return data[1:1 + length]

        if pci_type == 0x1:
            if len(data) < 2:
                raise IsoTpError(f"truncated FirstFrame {bhex(data)}")
            total_len = ((data[0] & 0x0F) << 8) | data[1]
            payload = bytearray(data[2:8])
            remaining = max(0, total_len - len(payload))
            total_cf = math.ceil(remaining / 7) if remaining else 0
            self.log.process(f"  {frame_label:<20} FirstFrame; send FlowControl")
            self.send_flow_control()
            expected_seq = 1
            got_cf = 0
            while len(payload) < total_len:
                cf = self.recv_can(timeout=timeout)
                if cf is None:
                    raise TimeoutError("timeout waiting for ConsecutiveFrame")
                if not cf or (cf[0] >> 4) != 0x2:
                    self.log.debug(f"  ignore non-CF {bhex(cf)}")
                    continue
                seq = cf[0] & 0x0F
                if seq != expected_seq:
                    raise IsoTpError(f"wrong ConsecutiveFrame SN: expected {expected_seq:X}, got {seq:X}")
                payload.extend(cf[1:8])
                got_cf += 1
                if total_cf:
                    self.log.process(f"  {frame_label:<20} chunk {got_cf}/{total_cf}")
                expected_seq = (expected_seq + 1) & 0x0F
            return bytes(payload[:total_len])

        if pci_type == 0x3:
            raise IsoTpError(f"unexpected FlowControl from ECU: {bhex(data)}")
        raise IsoTpError(f"unknown ISO-TP PCI type {pci_type:X} in {bhex(data)}")

    def request_payload(self, payload: bytes, *, timeout: float, response_pending_timeout: float, frame_label: str = "Response") -> bytes:
        self.send_payload(payload)
        deadline = time.monotonic() + max(timeout, response_pending_timeout)
        while True:
            remaining = min(timeout, max(0.0, deadline - time.monotonic()))
            if remaining <= 0:
                raise TimeoutError("timeout waiting for final UDS response")
            response = self.recv_payload(timeout=remaining, frame_label=frame_label)
            if len(response) >= 3 and response[0] == 0x7F and response[1] == payload[0] and response[2] == 0x78:
                self.log.process("  uds                    NRC 0x78 responsePending")
                continue
            return response
