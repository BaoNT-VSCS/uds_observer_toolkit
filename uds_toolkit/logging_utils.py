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
        self.test_id_label = ""

    def set_test_context(self, test_id_label: str = "") -> None:
        self.test_id_label = test_id_label

    def info(self, msg: str) -> None:
        print(msg, flush=True)

    def process(self, msg: str) -> None:
        if self.show_process or self.verbose:
            print(self._prefix(msg), flush=True)

    def debug(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def tx_can(self, can_id: int, data: bytes) -> None:
        if self.show_can:
            print(self._prefix(f"  CAN TX {can_id:X}#{data.hex().upper()}"), flush=True)

    def rx_can(self, can_id: int, data: bytes) -> None:
        if self.verbose:
            print(self._prefix(f"  CAN RX {can_id:X}#{data.hex().upper()}"), flush=True)

    def _prefix(self, msg: str) -> str:
        if not self.test_id_label:
            return msg
        return f"[{self.test_id_label}] {msg}"


class RunLogger:
    """Append-only JSONL/CSV logger.

    Every run gets a timestamped directory to avoid overwriting evidence. JSONL
    keeps full structured data; CSV gives a quick spreadsheet-friendly summary.
    """

    def __init__(self, base_dir: str | Path = "runs", run_name: str | None = None) -> None:
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe = (run_name or "uds_run").replace("/", "_").replace(" ", "_")
        self.run_id = f"{ts}_{safe}"
        self.dir = ensure_dir(Path(base_dir) / f"{ts}_{safe}")
        self.jsonl_path = self.dir / "events.jsonl"
        self.csv_path = self.dir / "summary.csv"
        self._csv_rows: List[Dict[str, Any]] = []
        self._context: Dict[str, Any] = {}

    def set_testcase_context(self, **metadata: Any) -> None:
        self._context = dict(metadata)

    def clear_testcase_context(self) -> None:
        self._context = {}

    def event(self, event_type: str, **data: Any) -> None:
        row: Dict[str, Any] = {
            "ts": time.time(),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "run_id": self.run_id,
            "event": event_type,
            "event_type": event_type,
        }
        for key, value in self._context.items():
            row.setdefault(key, value)
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
        evidence_note: str | None = None,
    ) -> None:
        response_value = response_display if response_display is not None else response.hex().upper()
        metadata = dict(self._context)
        evidence_note_value = evidence_note if evidence_note is not None else note
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
            evidence_note=evidence_note_value,
        )
        self._csv_rows.append({
            "run_id": self.run_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "test_id": metadata.get("test_id", ""),
            "test_ids": ", ".join(metadata.get("test_ids", [])) if isinstance(metadata.get("test_ids"), list) else metadata.get("test_ids", ""),
            "title": metadata.get("title", ""),
            "display_name": metadata.get("display_name", ""),
            "internal_name": metadata.get("internal_name", testcase),
            "testcase_type": metadata.get("testcase_type", metadata.get("type", "")),
            "group": metadata.get("group", ""),
            "category": metadata.get("category", ""),
            "mode": metadata.get("mode", ""),
            "risk_property": metadata.get("risk_property", ""),
            "service_id": metadata.get("service_id", ""),
            "default_payload": metadata.get("default_payload", ""),
            "pass_criteria": _join_criteria(metadata.get("pass_criteria", "")),
            "fail_criteria": _join_criteria(metadata.get("fail_criteria", "")),
            "evidence_fields": _join_criteria(metadata.get("evidence_fields", "")),
            "target": target,
            "tx_id": metadata.get("tx_id", ""),
            "rx_id": metadata.get("rx_id", ""),
            "session_flow": metadata.get("session_flow", ""),
            "effective_parameters_json": json.dumps(metadata.get("effective_parameters", {}), ensure_ascii=False, sort_keys=True),
            "step": step,
            "request": spaced(request),
            "response": response_display if response_display is not None else spaced(response),
            "status": status,
            "nrc": f"0x{nrc:02X}" if nrc is not None else "",
            "verdict": verdict,
            "evidence_note": evidence_note_value,
            "source_yaml": metadata.get("source_yaml", ""),
        })

    def close(self) -> None:
        if not self._csv_rows:
            return
        fields = [
            "run_id",
            "timestamp",
            "test_id",
            "test_ids",
            "title",
            "display_name",
            "internal_name",
            "testcase_type",
            "group",
            "category",
            "mode",
            "risk_property",
            "service_id",
            "default_payload",
            "pass_criteria",
            "fail_criteria",
            "evidence_fields",
            "target",
            "tx_id",
            "rx_id",
            "session_flow",
            "effective_parameters_json",
            "step",
            "request",
            "response",
            "status",
            "nrc",
            "verdict",
            "evidence_note",
            "source_yaml",
        ]
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


def _join_criteria(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return " | ".join(str(item) for item in value)
    return str(value or "")
