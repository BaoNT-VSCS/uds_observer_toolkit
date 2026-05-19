from __future__ import annotations

import csv
import json
import sys
import time
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .utils import ensure_dir, spaced


class ConsoleLog:
    def __init__(self, *, verbose: bool = False, show_process: bool = False, show_can: bool = False) -> None:
        self.verbose = verbose
        self.show_process = show_process
        self.show_can = show_can

    def info(self, msg: str) -> None:
        print(msg, flush=True)

    def process(self, msg: str) -> None:
        if self.show_process or self.verbose:
            print(msg, flush=True)

    def debug(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def tx_can(self, can_id: int, data: bytes) -> None:
        if self.show_can:
            print(f"  CAN TX {can_id:X}#{data.hex().upper()}", flush=True)

    def rx_can(self, can_id: int, data: bytes) -> None:
        if self.verbose:
            print(f"  CAN RX {can_id:X}#{data.hex().upper()}", flush=True)


class RunLogger:
    """Append-only JSONL/CSV logger.

    Every run gets a timestamped directory to avoid overwriting evidence. JSONL
    keeps full structured data; CSV gives a quick spreadsheet-friendly summary.
    """

    def __init__(self, base_dir: str | Path = "runs", run_name: str | None = None) -> None:
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe = (run_name or "uds_run").replace("/", "_").replace(" ", "_")
        self.dir = ensure_dir(Path(base_dir) / f"{ts}_{safe}")
        self.jsonl_path = self.dir / "events.jsonl"
        self.csv_path = self.dir / "summary.csv"
        self._csv_rows: List[Dict[str, Any]] = []

    def event(self, event_type: str, **data: Any) -> None:
        row: Dict[str, Any] = {"ts": time.time(), "event": event_type}
        row.update(_jsonable(data))
        with self.jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    def result(
        self,
        *,
        testcase: str,
        target: str,
        step: str,
        request: bytes,
        response: bytes = b"",
        status: str = "",
        nrc: int | None = None,
        note: str = "",
        verdict: str = "",
        response_display: str | None = None,
    ) -> None:
        response_value = response_display if response_display is not None else response.hex().upper()
        self.event(
            "uds_result",
            testcase=testcase,
            target=target,
            step=step,
            request=request.hex().upper(),
            response=response_value,
            status=status,
            nrc=f"0x{nrc:02X}" if nrc is not None else "",
            note=note,
            verdict=verdict,
        )
        self._csv_rows.append({
            "testcase": testcase,
            "target": target,
            "step": step,
            "request": spaced(request),
            "response": response_display if response_display is not None else spaced(response),
            "status": status,
            "nrc": f"0x{nrc:02X}" if nrc is not None else "",
            "note": note,
            "verdict": verdict,
        })

    def close(self) -> None:
        if not self._csv_rows:
            return
        fields = ["testcase", "target", "step", "request", "response", "status", "nrc", "note", "verdict"]
        with self.csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(self._csv_rows)


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return obj.hex().upper()
    if isinstance(obj, bytearray):
        return bytes(obj).hex().upper()
    if is_dataclass(obj):
        return _jsonable(asdict(obj))
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, tuple):
        return [_jsonable(v) for v in obj]
    return obj
