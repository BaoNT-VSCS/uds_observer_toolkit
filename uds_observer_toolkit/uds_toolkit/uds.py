from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from .isotp import IsoTp
from .logging_utils import ConsoleLog
from .nrc import nrc_name
from .utils import hx, spaced


@dataclass
class UdsResult:
    request: bytes
    response: bytes = b""
    positive: bool = False
    nrc: int | None = None
    note: str = ""
    exception: str = ""

    @property
    def status(self) -> str:
        if self.exception:
            return "EXCEPTION"
        if self.positive:
            return "POSITIVE"
        if self.nrc is not None:
            return f"NRC_{self.nrc:02X}"
        return "NEGATIVE"

    @property
    def seed(self) -> bytes | None:
        if self.positive and len(self.response) >= 2 and self.response[0] == 0x67:
            return self.response[2:]
        return None


def parse_uds_response(response: bytes, request: bytes, *, check_subfn: bool = True) -> UdsResult:
    if not response:
        return UdsResult(request=request, response=response, note="empty response")
    if not request:
        return UdsResult(request=request, response=response, note="empty request")

    service_id = request[0]
    subfn = request[1] if len(request) >= 2 else None

    if response[0] == 0x7F:
        nrc = response[2] if len(response) >= 3 else None
        note = "negative response"
        if len(response) >= 2 and response[1] != service_id:
            note = f"negative response for different service {hx(response[1])}"
        elif nrc is not None:
            note = nrc_name(nrc)
        return UdsResult(request=request, response=response, positive=False, nrc=nrc, note=note)

    expected_sid = (service_id + 0x40) & 0xFF
    if response[0] != expected_sid:
        return UdsResult(
            request=request,
            response=response,
            positive=False,
            note=f"unexpected SID {hx(response[0])}, expected {hx(expected_sid)}",
        )

    if check_subfn and subfn is not None and len(response) >= 2 and response[1] != subfn:
        return UdsResult(
            request=request,
            response=response,
            positive=False,
            note=f"sub-function mismatch {hx(response[1])}, expected {hx(subfn)}",
        )

    return UdsResult(request=request, response=response, positive=True, note="positive response")


class UdsClient:
    def __init__(
        self,
        transport: IsoTp,
        *,
        timeout: float = 1.0,
        response_pending_timeout: float = 5.0,
        drain_before_request: float = 0.0,
        log: ConsoleLog | None = None,
    ) -> None:
        self.transport = transport
        self.timeout = timeout
        self.response_pending_timeout = response_pending_timeout
        self.drain_before_request = drain_before_request
        self.log = log or ConsoleLog()

    def request(self, payload: bytes, *, step: str = "uds", frame_label: str = "Response", check_subfn: bool = True) -> UdsResult:
        try:
            if self.drain_before_request > 0:
                self.transport.drain(self.drain_before_request)
            self.log.process(f"  {step:<22} TX  {spaced(payload)}")
            response = self.transport.request_payload(
                payload,
                timeout=self.timeout,
                response_pending_timeout=self.response_pending_timeout,
                frame_label=frame_label,
            )
            result = parse_uds_response(response, payload, check_subfn=check_subfn)
            self.log.process(f"  {step:<22} RX  {spaced(response)}  {result.status} {result.note}")
            return result
        except Exception as exc:
            result = UdsResult(request=payload, exception=f"{type(exc).__name__}: {exc}")
            self.log.process(f"  {step:<22} !!  {result.exception}")
            return result

    def open_session_flow(self, session_flow: list[int], *, strict: bool = False, delay: float = 0.05) -> tuple[bool, list[tuple[str, UdsResult]]]:
        import time

        observations: list[tuple[str, UdsResult]] = []
        for subfn in session_flow:
            step = f"session-{subfn:02X}"
            result = self.request(bytes([0x10, subfn]), step=step, frame_label="Session")
            observations.append((step, result))
            if result.positive:
                if delay > 0:
                    time.sleep(delay)
                continue
            if result.nrc in {0x7E, 0x7F} and not strict:
                if delay > 0:
                    time.sleep(delay)
                continue
            return False, observations
        return True, observations
