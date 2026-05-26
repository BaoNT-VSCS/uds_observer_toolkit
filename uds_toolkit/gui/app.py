#!/usr/bin/env python3
"""
UDS Reconnaissance + Security Test Assistant.

Run:
    python uds_observer_gui.py
"""
from __future__ import annotations

import csv
import html
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from PySide6.QtCore import QThread, Qt, Signal
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QScrollArea,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - startup guard
    print("Missing dependency: PySide6. Install with: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2) from exc

from uds_toolkit.nrc import NRC_NAMES
from uds_toolkit.case_runners import make_modular_runner
from uds_toolkit.evidence_schema import build_evidence_record, build_placeholder_evidence_record
from uds_toolkit.registry import modular_case_definitions
from uds_toolkit.safety import SafetyGuard, validate_safety_guard
from uds_toolkit.seedkey import default_send_key_subfn as default_key_subfn
from uds_toolkit.testcase_model import normalize_case_model
from uds_toolkit.utils import spaced


APP_TITLE = "UDS Recon + Security Test Assistant"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE_DIR = ROOT / "evidence"

VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL / FINDING"
VERDICT_POTENTIAL = "POTENTIAL FINDING"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_CONFIG = "CONFIG ERROR"
VERDICT_PASS_SECURITY_GATE = "PASS_SECURITY_GATE"
VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY = "FAIL_ACCEPTED_WITHOUT_SECURITY"
VERDICT_INCONCLUSIVE_RANGE_CHECKED_FIRST = "INCONCLUSIVE_RANGE_CHECKED_FIRST"
VERDICT_INVALID_REQUEST_FORMAT = "INVALID_REQUEST_FORMAT"
VERDICT_SERVICE_NOT_SUPPORTED = "SERVICE_NOT_SUPPORTED"
VERDICT_WRONG_SESSION = "WRONG_SESSION"
VERDICT_PARAMETER_UNSUPPORTED = "PARAMETER_UNSUPPORTED"
VERDICT_INVALID_TEST_SETUP = "INVALID_TEST_SETUP"
VERDICT_NEED_MANUAL_REVIEW = "NEED_MANUAL_REVIEW"
VERDICT_PASS_EXPECTED_DENIAL = "PASS_EXPECTED_DENIAL"
VERDICT_FAIL_PRECONDITION_BYPASS = "FAIL_PRECONDITION_BYPASS"
VERDICT_INCONCLUSIVE_NO_RESPONSE = "INCONCLUSIVE_NO_RESPONSE"
VERDICT_INCONCLUSIVE_SETUP_ERROR = "INCONCLUSIVE_SETUP_ERROR"
VERDICT_FAIL_READABLE_WITHOUT_SECURITY = "FAIL_READABLE_WITHOUT_SECURITY"
VERDICT_INCONCLUSIVE_PARAMETER_OR_DID = "INCONCLUSIVE_PARAMETER_OR_DID"

NRC_MEANINGS = {**NRC_NAMES, 0x78: "responsePending"}


def nrc_to_text(nrc: Optional[int]) -> str:
    if nrc is None:
        return ""
    return NRC_MEANINGS.get(nrc, f"unknownNRC_0x{nrc:02X}")


def timestamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def parse_hex_int(text: Any, *, name: str, minimum: int = 0, maximum: int = 0xFFFFFFFF) -> int:
    raw = str(text or "").strip().replace("_", "")
    if not raw:
        raise ValueError(f"{name} is required")
    try:
        value = int(raw, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hex") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between 0x{minimum:X} and 0x{maximum:X}")
    return value


def validate_hex_byte(text: Any, name: str) -> int:
    return parse_hex_int(text, name=name, maximum=0xFF)


def parse_hex_byte(text: Any, name: str = "hex byte") -> int:
    return validate_hex_byte(text, name)


def validate_hex_word(text: Any, name: str) -> int:
    raw = str(text or "").strip().replace("_", "")
    compact = re.sub(r"[^0-9A-Fa-f]", "", raw[2:] if raw.lower().startswith("0x") else raw)
    if len(compact) > 4:
        raise ValueError(f"{name} must be exactly 2 bytes (0x0000..0xFFFF)")
    return parse_hex_int(text, name=name, maximum=0xFFFF)


def parse_hex_payload(text: str, *, name: str = "payload", allow_empty: bool = False, strict_bytes: bool = False) -> bytes:
    raw = str(text or "").strip()
    if not raw:
        if allow_empty:
            return b""
        raise ValueError(f"{name} is required")
    tokens = [t for t in re.split(r"[\s,;:\-]+", raw) if t]
    if not tokens:
        if allow_empty:
            return b""
        raise ValueError(f"{name} is required")
    out = bytearray()
    for token in tokens:
        original = token
        token = token[2:] if token.lower().startswith("0x") else token
        if strict_bytes and len(token) == 1:
            raise ValueError(f"{name} must contain full bytes, e.g. 0C not {original}")
        if len(token) > 2:
            if len(token) % 2:
                raise ValueError(f"{name} contains odd-length hex token: {token}")
            for i in range(0, len(token), 2):
                out.append(validate_hex_byte(token[i:i + 2], name=name))
        else:
            out.append(validate_hex_byte(token, name=name))
    return bytes(out)


def parse_session_flow(text: str) -> list[bytes]:
    flows: list[bytes] = []
    for idx, line in enumerate(str(text or "").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            flows.append(parse_hex_payload(line, name=f"session_flow line {idx}"))
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
    return flows


def parse_session_subfunctions(text: str) -> list[int]:
    """Parse DiagnosticSessionControl subfunction flow.

    The UI field intentionally accepts subfunctions only, not full UDS payloads.
    Example: "03 02" means the tool sends "10 03" then "10 02".
    """
    subfunctions: list[int] = []
    raw = str(text or "").strip().replace("->", " ")
    if not raw:
        return subfunctions
    for line in raw.splitlines():
        line = line.strip().replace("->", " ")
        if not line:
            continue
        payload = parse_hex_payload(line, name="diagnostic_session_flow", strict_bytes=True)
        if payload and payload[0] == 0x10:
            raise ValueError('Session flow expects subfunctions only. Use "03", not "10 03". The tool automatically adds service 0x10.')
        subfunctions.extend(payload)
    return subfunctions


def expand_session_flow_requests(text: str) -> list[bytes]:
    return [bytes([0x10, subfn]) for subfn in parse_session_subfunctions(text)]


def format_session_flow_preview(text: str) -> str:
    subfunctions = parse_session_subfunctions(text)
    if not subfunctions:
        return "Diagnostic session flow: <none>"
    compact = " -> ".join(f"{x:02X}" for x in subfunctions)
    expanded = "; ".join(spaced(req) for req in expand_session_flow_requests(text))
    return f"Diagnostic session flow: {compact}\nExpanded session requests: {expanded}"


def safe_expand_session_flow_hex(text: str) -> list[str]:
    try:
        return [spaced(payload) for payload in expand_session_flow_requests(text)]
    except Exception as exc:
        return [f"<parse error: {exc}>"]


def format_arbid(value: int) -> str:
    return f"0x{value:X}"


def normalize_did_hex(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    match = re.search(r"(?:0x)?([0-9A-Fa-f]{4})", raw)
    if not match:
        return raw
    return f"0x{int(match.group(1), 16):04X}"


def normalize_payload_hex(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    compact = re.sub(r"(?i)\b(?:message|data|value|payload|response)\b\s*=?", " ", raw)
    compact = re.sub(r"[^0-9A-Fa-f]", "", compact)
    if not compact:
        return ""
    if len(compact) % 2:
        raise ValueError("message/data hex has odd length")
    return spaced(bytes.fromhex(compact))


def parse_did_note(note: str, *, source: str = "caringcaribou") -> ParsedDidRecord:
    raw_note = str(note or "").strip()
    did_match = re.search(r"(?i)(?<![0-9A-F])(?:0x)?([0-9A-F]{4})(?![0-9A-F])", raw_note)
    if not did_match:
        return ParsedDidRecord("", None, None, "", raw_note, source, "invalid", "no 2-byte DID token found")
    did_int = int(did_match.group(1), 16)
    did = f"0x{did_int:04X}"
    remainder = raw_note[did_match.end():]
    remainder = re.sub(r"(?i)\b(?:message|data|value|payload|response)\b\s*=?", " ", remainder)
    tokens = [token[2:] if token.lower().startswith("0x") else token for token in re.findall(r"(?i)(?:0x)?[0-9A-F]+", remainder)]
    compact = "".join(tokens)
    if not compact:
        return ParsedDidRecord(did, did_int, None, "", raw_note, source, "parsed_no_message")
    if len(compact) % 2:
        return ParsedDidRecord(did, did_int, None, "", raw_note, source, "invalid", "message/data hex has odd length")
    try:
        payload = bytes.fromhex(compact)
    except ValueError as exc:
        return ParsedDidRecord(did, did_int, None, "", raw_note, source, "invalid", str(exc))
    return ParsedDidRecord(did, did_int, len(payload), spaced(payload), raw_note, source, "parsed", length_source="parsed_from_notes")


def _row_value(row: dict[str, Any], *names: str) -> Any:
    lowered = {str(key).strip().lower().replace("_", " "): value for key, value in (row or {}).items()}
    fallback: Any = ""
    for name in names:
        key = name.strip().lower().replace("_", " ")
        if key in lowered and str(lowered[key] or "").strip():
            return lowered[key]
        if key in lowered:
            fallback = lowered[key]
    return fallback


def _parse_length_value(value: Any) -> tuple[Optional[int], str]:
    raw = str(value or "").strip()
    if not raw or raw.lower() in {"unknown", "<unknown>", "none", "null"}:
        return None, "unknown"
    try:
        parsed = int(raw, 0)
    except ValueError:
        return None, "unknown"
    return (parsed, "csv_length") if parsed >= 0 else (None, "unknown")


def _did_record_to_row(record: ParsedDidRecord) -> dict[str, Any]:
    length_text = "" if record.length is None else str(record.length)
    row = {
        "DID": record.did,
        "Length": length_text,
        "Message DID": record.message_hex,
        "Notes": record.raw_note,
        "Source": record.source,
        "Parse Status": record.parse_status,
        "Parse Error": record.parse_error,
        "did": record.did,
        "did_int": record.did_int if record.did_int is not None else "",
        "length": record.length if record.length is not None else "",
        "message_hex": record.message_hex,
        "raw_note": record.raw_note,
        "source": record.source,
        "parse_status": record.parse_status,
        "parse_error": record.parse_error,
        "duplicate_count": record.duplicate_count,
        "length_source": record.length_source,
    }
    row.update({
        "did_hex": record.did,
        "did_length_bytes": length_text,
        "did_message_hex": record.message_hex,
        "data_length_bytes": length_text,
        "data_hex": record.message_hex,
        "notes": record.raw_note,
    })
    return row


def normalize_did_catalog_row(row: dict[str, Any], *, source: str = "csv") -> dict[str, Any]:
    raw_note = str(_row_value(row, "Notes", "notes", "raw_note", "response_raw", "raw_response_hex") or "").strip()
    did_text = _row_value(row, "DID", "did", "did_hex", "identifier")
    did = normalize_did_hex(did_text)
    did_int: Optional[int] = int(did[2:], 16) if re.fullmatch(r"0x[0-9A-F]{4}", did) else None

    message_hex = ""
    message_source = "unknown"
    for key in ("Message DID", "message_hex", "did_message_hex", "data_hex", "response_data_hex"):
        value = _row_value(row, key)
        if str(value or "").strip():
            try:
                message_hex = normalize_payload_hex(value)
                message_source = "csv_message"
            except ValueError:
                message_hex = ""
            break

    length, length_source = _parse_length_value(_row_value(row, "Length", "length", "did_length_bytes", "data_length_bytes"))
    parsed_note = parse_did_note(raw_note, source="caringcaribou" if raw_note else source)
    if did_int is None and parsed_note.did_int is not None:
        did, did_int = parsed_note.did, parsed_note.did_int
    if not message_hex and parsed_note.message_hex:
        message_hex = parsed_note.message_hex
        message_source = "parsed_from_notes"
    if length is None and message_hex:
        length = len(parse_hex_payload(message_hex, name="message_hex", allow_empty=True, strict_bytes=True))
        length_source = message_source if message_source == "parsed_from_notes" else "csv_message"
    if length is None and parsed_note.length is not None:
        length = parsed_note.length
        length_source = "parsed_from_notes"

    if did_int is None:
        record = ParsedDidRecord(did or "", None, None, message_hex, raw_note, source, "invalid", "no 2-byte DID token found")
    else:
        status = "parsed" if message_hex else "parsed_no_message"
        record = ParsedDidRecord(did, did_int, length, message_hex, raw_note, parsed_note.source if raw_note else source, status, "", length_source=length_source)
    return _did_record_to_row(record)


def _did_row_score(row: dict[str, Any]) -> tuple[int, int]:
    length_known = 1 if str(row.get("length", "")).strip() else 0
    message_len = len(str(row.get("message_hex", "")).replace(" ", ""))
    return length_known, message_len


def normalize_did_catalog_rows(rows: list[dict[str, Any]], *, source: str = "csv") -> tuple[list[dict[str, Any]], dict[str, Any]]:
    by_did: dict[str, dict[str, Any]] = {}
    duplicate_counts: Counter[str] = Counter()
    invalid_rows = 0
    raw_count = len(rows)
    for row in rows:
        normalized = normalize_did_catalog_row(row, source=source)
        if normalized.get("parse_status") == "invalid" or not normalized.get("did"):
            invalid_rows += 1
            continue
        did = str(normalized["did"])
        duplicate_counts[did] += 1
        existing = by_did.get(did)
        if existing is None or _did_row_score(normalized) > _did_row_score(existing):
            by_did[did] = normalized
    normalized_rows = sorted(by_did.values(), key=lambda item: int(str(item["did"])[2:], 16))
    for row in normalized_rows:
        row["duplicate_count"] = duplicate_counts[str(row["did"])]
    summary = {
        "raw_rows": raw_count,
        "normalized_dids": len(normalized_rows),
        "known_length_dids": len([row for row in normalized_rows if str(row.get("length", "")).strip()]),
        "failed_parse_rows": invalid_rows,
        "duplicate_did_rows": sum(count - 1 for count in duplicate_counts.values() if count > 1),
    }
    return normalized_rows, summary


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass(frozen=True)
class UdsParsedResponse:
    request_sid: Optional[int]
    response_hex: str
    response_type: str
    positive_response: bool
    negative_response: bool
    nrc: Optional[int]
    nrc_meaning: str
    malformed: bool
    note: str


@dataclass(frozen=True)
class UdsExchange:
    response: Optional[bytes]
    response_type: str
    error: str = ""


@dataclass(frozen=True)
class ProbeCandidate:
    request: bytes
    dfi: int
    alfi: int
    address_length: int
    size_length: int
    memory_address: bytes
    memory_size: bytes
    annotation: str


def parse_uds_response(request: bytes, response: Optional[bytes], *, transport_status: str = "") -> UdsParsedResponse:
    if response is None:
        response_type = transport_status or "no_response"
        note = "timeout waiting for response" if response_type == "timeout" else response_type.replace("_", " ")
        return UdsParsedResponse(
            request_sid=request[0] if request else None,
            response_hex="",
            response_type=response_type,
            positive_response=False,
            negative_response=False,
            nrc=None,
            nrc_meaning="",
            malformed=False,
            note=note,
        )
    if not request:
        return UdsParsedResponse(None, spaced(response), "malformed_response", False, False, None, "", True, "empty request")
    if not response:
        return UdsParsedResponse(request[0], "", "malformed_response", False, False, None, "", True, "empty response")

    request_sid = request[0]
    if response[0] == 0x7F:
        if len(response) < 3:
            return UdsParsedResponse(request_sid, spaced(response), "malformed_response", False, False, None, "", True, "malformed negative response")
        nrc = response[2]
        if response[1] != request_sid:
            return UdsParsedResponse(
                request_sid,
                spaced(response),
                "unexpected_response_sid",
                False,
                False,
                nrc,
                nrc_to_text(nrc),
                True,
                f"unrelated negative response references SID 0x{response[1]:02X}, expected 0x{request_sid:02X}",
            )
        return UdsParsedResponse(request_sid, spaced(response), "negative_response", False, True, nrc, nrc_to_text(nrc), False, "negative response")

    expected_sid = (request_sid + 0x40) & 0xFF
    if response[0] == expected_sid:
        return UdsParsedResponse(request_sid, spaced(response), "positive_response", True, False, None, "", False, "positive response")

    return UdsParsedResponse(
        request_sid,
        spaced(response),
        "unexpected_response_sid",
        False,
        False,
        None,
        "",
        True,
        f"unexpected positive SID 0x{response[0]:02X}, expected 0x{expected_sid:02X}",
    )


def normalize_subfunction_echo(value: int) -> int:
    return value & 0x7F


def parse_security_access_response(request: bytes, response: Optional[bytes], *, transport_status: str = "") -> dict[str, Any]:
    parsed = parse_uds_response(request, response, transport_status=transport_status)
    out: dict[str, Any] = {
        "request_hex": spaced(request),
        "response_hex": spaced(response) if response else "",
        "response_type": parsed.response_type,
        "positive_response": parsed.positive_response,
        "negative_response": parsed.negative_response,
        "nrc": f"0x{parsed.nrc:02X}" if parsed.nrc is not None else "",
        "nrc_meaning": parsed.nrc_meaning,
        "note": parsed.note,
        "seed_hex": "",
        "seed_length": 0,
        "security_response_kind": "",
    }
    if request and request[0] != 0x27:
        return out
    if response and parsed.positive_response and len(response) >= 2 and response[0] == 0x67:
        echo = normalize_subfunction_echo(response[1])
        expected = normalize_subfunction_echo(request[1]) if len(request) > 1 else None
        if expected is not None and echo != expected:
            out.update({
                "response_type": "unexpected_response_sid",
                "positive_response": False,
                "note": f"SecurityAccess subfunction echo 0x{echo:02X} did not match request 0x{expected:02X}",
            })
            return out
        if len(request) >= 2 and request[1] % 2 == 1:
            seed = response[2:]
            out.update({
                "security_response_kind": "positive_seed" if seed else "positive_empty_seed",
                "seed_hex": spaced(seed),
                "seed_length": len(seed),
            })
        else:
            out["security_response_kind"] = "positive_sendkey"
    return out


def compute_duplicate_metrics(seed_hex_values: list[str]) -> dict[str, Any]:
    counts = Counter(seed_hex_values)
    duplicate_values = {seed: count for seed, count in counts.items() if count > 1}
    duplicate_occurrences = sum(count - 1 for count in duplicate_values.values())
    total = len(seed_hex_values)
    return {
        "unique_seed_values": len(counts),
        "seed_counts": dict(counts),
        "duplicate_seed_values": dict(duplicate_values),
        "duplicate_occurrences": duplicate_occurrences,
        "duplicate_rate": duplicate_occurrences / total if total else None,
    }


def _looks_monotonic(seed_hex_values: list[str]) -> bool:
    if len(seed_hex_values) < 3:
        return False
    try:
        values = [int(seed.replace(" ", ""), 16) for seed in seed_hex_values]
    except ValueError:
        return False
    deltas = [b - a for a, b in zip(values, values[1:])]
    return bool(deltas) and len(set(deltas)) == 1 and 0 < abs(deltas[0]) <= 16


def compute_seed_metrics(seed_rows: list[dict[str, Any]], requested_samples: int = 0) -> dict[str, Any]:
    positive_rows = [row for row in seed_rows if row.get("security_response_kind") == "positive_seed"]
    seed_hex_values = [str(row.get("seed_hex", "")) for row in positive_rows if row.get("seed_hex")]
    duplicate = compute_duplicate_metrics(seed_hex_values)
    failed_reasons = Counter(str(row.get("note") or row.get("response_type") or "unknown") for row in seed_rows if row not in positive_rows)
    seed_lengths = [int(row.get("seed_length") or 0) for row in positive_rows]
    metrics = {
        "requested_samples": requested_samples or len(seed_rows),
        "completed_samples": len(seed_rows),
        "positive_seed_samples": len(positive_rows),
        "failed_sample_reasons": dict(failed_reasons),
        "seed_lengths": seed_lengths,
        "first_seed_sequence": seed_hex_values,
        "monotonic_or_counter_like": _looks_monotonic(seed_hex_values),
    }
    metrics.update(duplicate)
    return metrics


def load_seed_lengths_from_csv(path: Path) -> list[int]:
    seed_lengths: list[int] = []
    with path.open("r", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            seed_hex = str(row.get("seed_hex") or row.get("seed") or "").strip()
            if seed_hex:
                seed_lengths.append(len(parse_hex_payload(seed_hex, name="seed_hex", allow_empty=True)))
    return seed_lengths


def compute_seed_length_metrics(seed_lengths: list[int], minimum: int) -> dict[str, Any]:
    return {
        "total_seed_samples": len(seed_lengths),
        "min_seed_length": min(seed_lengths) if seed_lengths else 0,
        "max_seed_length": max(seed_lengths) if seed_lengths else 0,
        "average_seed_length": sum(seed_lengths) / len(seed_lengths) if seed_lengths else 0,
        "seed_length_distribution": dict(Counter(seed_lengths)),
        "short_seed_count": len([x for x in seed_lengths if 0 < x < minimum]),
        "empty_seed_count": len([x for x in seed_lengths if x == 0]),
    }


@dataclass
class TargetProfile:
    interface: str
    channel: str
    tester_tx_id: int
    tester_rx_id: int
    extended_id: bool
    padding: int
    timeout: float
    response_pending_timeout: float
    delay: float
    request_stmin: float
    fc_wait_timeout: float
    output_dir: Path
    save_output: bool
    dry_run: bool
    authorized_disruptive: bool
    operator_notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface,
            "can_interface": self.channel,
            "tester_tx_id": {
                "value": format_arbid(self.tester_tx_id),
                "meaning": "CAN arbitration ID used by the tester to send diagnostic requests. ECU receives on this ID.",
            },
            "tester_rx_id": {
                "value": format_arbid(self.tester_rx_id),
                "meaning": "CAN arbitration ID used by the tester to receive diagnostic responses. ECU transmits on this ID.",
            },
            "caringcaribou_positional_arg_1": {
                "value": format_arbid(self.tester_tx_id),
                "meaning": "CaringCaribou UDS command first arbitration-ID argument; same as tester_tx_id.",
            },
            "caringcaribou_positional_arg_2": {
                "value": format_arbid(self.tester_rx_id),
                "meaning": "CaringCaribou UDS command second arbitration-ID argument; same as tester_rx_id.",
            },
            "direct_isotp_txid": format_arbid(self.tester_tx_id),
            "direct_isotp_rxid": format_arbid(self.tester_rx_id),
            "extended_id": self.extended_id,
            "padding": f"0x{self.padding:02X}",
            "timeout": self.timeout,
            "response_pending_timeout": self.response_pending_timeout,
            "inter_request_delay": self.delay,
            "request_stmin": self.request_stmin,
            "fc_wait_timeout": self.fc_wait_timeout,
            "output_directory": str(self.output_dir) if self.save_output else "",
            "save_output": self.save_output,
            "dry_run": self.dry_run,
            "operator_authorization_confirmed": self.authorized_disruptive,
            "operator_notes": self.operator_notes,
        }


@dataclass(frozen=True)
class Choice:
    label: str
    value: str


@dataclass(frozen=True)
class ParsedDidRecord:
    did: str
    did_int: Optional[int]
    length: Optional[int]
    message_hex: str
    raw_note: str
    source: str
    parse_status: str
    parse_error: str = ""
    duplicate_count: int = 1
    length_source: str = "unknown"


@dataclass(frozen=True)
class FieldSpec:
    id: str
    label: str
    kind: str = "text"
    default: Any = ""
    required: bool = False
    placeholder: str = ""
    choices: tuple[Choice, ...] = ()
    visible_if: Optional[Callable[[dict[str, Any]], bool]] = None
    enabled_if: Optional[Callable[[dict[str, Any]], bool]] = None


@dataclass(frozen=True)
class TestDefinition:
    id: str
    title: str
    category: str
    description: str
    runner_kind: str
    fields: tuple[FieldSpec, ...]
    display_name: str = ""
    objective: str = ""
    reference_source: str = ""
    safety_level: str = "standard"
    execution_plan: Optional[Callable[[dict[str, Any]], list[dict[str, Any]]]] = None
    parser: Optional[Callable[..., Any]] = None
    metrics: Optional[Callable[..., dict[str, Any]]] = None
    verdict_rules: Optional[Callable[..., tuple[str, str]]] = None
    summary_template: str = ""
    target_required: bool = True
    disruptive: bool = False
    build_command: Optional[Callable[[TargetProfile, dict[str, Any]], list[str]]] = None
    build_request: Optional[Callable[[dict[str, Any]], bytes]] = None
    validate: Optional[Callable[[TargetProfile, dict[str, Any]], dict[str, str]]] = None
    parse_external: Optional[Callable[[str, Path], dict[str, Any]]] = None
    evidence_fields: tuple[str, ...] = ()
    risk_property: str = ""
    service_id: str = ""
    default_payload: str = ""
    preconditions: tuple[str, ...] = ()
    pass_criteria: tuple[str, ...] = ()
    fail_criteria: tuple[str, ...] = ()
    case_model: dict[str, Any] = dataclass_field(default_factory=dict)
    runner_interface: str = ""
    safety_guard: dict[str, Any] = dataclass_field(default_factory=dict)
    evidence_schema: dict[str, Any] = dataclass_field(default_factory=dict)
    implemented: bool = True
    display_id: str = ""
    canonical_id: str = ""

    def __post_init__(self) -> None:
        if not self.display_name:
            object.__setattr__(self, "display_name", self.title)
        if not self.objective:
            object.__setattr__(self, "objective", self.description)
        if self.parser is None:
            object.__setattr__(self, "parser", self.parse_external or parse_uds_response)
        if self.verdict_rules is None:
            object.__setattr__(self, "verdict_rules", lambda *args, **kwargs: (VERDICT_INCONCLUSIVE, "No verdict rules registered."))
        if not self.summary_template:
            object.__setattr__(self, "summary_template", "default_report")
        model = normalize_case_model({
            "case_id": self.id,
            "type": _gui_case_type(self.id),
            "title": self.title,
            "category": self.category,
            "risk_property": self.risk_property,
            "service_id": self.service_id or _gui_case_service_id(self.id),
            "service": self.service_id or _gui_case_service_id(self.id),
            "default_payload": self.default_payload or _gui_case_default_payload(self.id),
            "preconditions": list(self.preconditions),
            "parameters": {field_spec.id: field_spec.default for field_spec in self.fields},
            "safety_level": self.safety_level,
            "expected_behavior": self.objective,
            "pass_criteria": list(self.pass_criteria),
            "fail_criteria": list(self.fail_criteria),
            "evidence_fields": list(self.evidence_fields),
        })
        object.__setattr__(self, "case_model", model.as_dict())
        object.__setattr__(self, "risk_property", model.risk_property)
        object.__setattr__(self, "service_id", model.service_id)
        object.__setattr__(self, "default_payload", model.default_payload)
        object.__setattr__(self, "preconditions", tuple(model.preconditions))
        object.__setattr__(self, "pass_criteria", tuple(model.pass_criteria))
        object.__setattr__(self, "fail_criteria", tuple(model.fail_criteria))


def _gui_case_type(test_id: str) -> str:
    if re.fullmatch(r"uds_1[0-9]", test_id):
        return "security_access"
    if test_id in {"uds_20", "uds_21", "uds_22", "uds_23", "uds_24", "uds_25"}:
        return "uds_access_control_probe"
    if test_id.startswith("recon_"):
        return "service_fuzzer"
    return ""


def _gui_case_service_id(test_id: str) -> str:
    if re.fullmatch(r"uds_1[0-9]", test_id):
        return "0x27"
    return {
        "uds_20": "0x11",
        "uds_21": "0x2E",
        "uds_22": "0x22",
        "uds_23": "0x34",
        "uds_24": "0x35",
        "uds_25": "0x28",
        "recon_subservices": "0x10",
    }.get(test_id, "")


def _gui_case_default_payload(test_id: str) -> str:
    if re.fullmatch(r"uds_1[0-9]", test_id):
        return "27 <seed_or_key_subfunction> [key]"
    return {
        "uds_20": "11 <reset_subfunction>",
        "uds_21": "2E <DID> <data>",
        "uds_22": "22 <DID>",
        "uds_23": "34 00 <ALFI> <memoryAddress> <memorySize>",
        "uds_24": "35 00 <ALFI> <memoryAddress> <memorySize>",
        "uds_25": "28 <controlType> <communicationType>",
        "recon_services": "<service_id>",
        "recon_did_dump": "22 <DID>",
        "recon_subservices": "<service_id> <subfunction>",
    }.get(test_id, "")


def field_visible(spec: FieldSpec, params: dict[str, Any]) -> bool:
    return spec.visible_if(params) if spec.visible_if else True


def field_enabled(spec: FieldSpec, params: dict[str, Any]) -> bool:
    return spec.enabled_if(params) if spec.enabled_if else True


def decode_alfi(alfi: int) -> tuple[int, int]:
    return alfi & 0x0F, (alfi >> 4) & 0x0F


def _alfi_lengths(alfi: int) -> tuple[int, int]:
    return decode_alfi(alfi)


def memory_transfer_service_name(service_id: int) -> str:
    if service_id == 0x34:
        return "RequestDownload"
    if service_id == 0x35:
        return "RequestUpload"
    raise ValueError("memory transfer service supports only SID 0x34 or 0x35")


def get_memory_transfer_mode(params: dict[str, Any]) -> str:
    return str(params.get("probe_mode") or "security_gate_probe")


def memory_probe_annotation(service_id: int, alfi: int, address: bytes, size: bytes) -> str:
    address_len, size_len = _alfi_lengths(alfi)
    service = memory_transfer_service_name(service_id)
    return (
        f"{service} Security Gate Probe; "
        f"DFI 0x00 = no compression / no encryption; "
        f"ALFI 0x{alfi:02X} = address length {address_len} bytes, size length {size_len} bytes; "
        f"address={spaced(address)}; size={spaced(size)}"
    )


def build_memory_security_gate_probe_requests(service_id: int) -> list[ProbeCandidate]:
    if service_id not in {0x34, 0x35}:
        raise ValueError("memory security gate probe supports only SID 0x34 or 0x35")
    candidates: list[ProbeCandidate] = []
    for alfi, address, size in (
        (0x44, bytes([0x00] * 4), bytes([0x00, 0x00, 0x00, 0x01])),
        (0x24, bytes([0x00] * 4), bytes([0x00, 0x01])),
        (0x22, bytes([0x00, 0x00]), bytes([0x00, 0x01])),
    ):
        address_len, size_len = _alfi_lengths(alfi)
        request = bytes([service_id, 0x00, alfi]) + address + size
        candidates.append(ProbeCandidate(
            request=request,
            dfi=0x00,
            alfi=alfi,
            address_length=address_len,
            size_length=size_len,
            memory_address=address,
            memory_size=size,
            annotation=memory_probe_annotation(service_id, alfi, address, size),
        ))
    return candidates


def format_probe_candidate(candidate: ProbeCandidate) -> str:
    return f"{spaced(candidate.request)} | {candidate.annotation}"


def dfi_annotation(dfi: int) -> str:
    if dfi == 0x00:
        return "DFI 0x00: no compression / no encryption"
    return f"DFI 0x{dfi:02X}: OEM-specific data format"


def alfi_annotation(alfi: int) -> str:
    address_len, size_len = decode_alfi(alfi)
    return f"ALFI 0x{alfi:02X}: address length {address_len} bytes, size length {size_len} bytes"


def validate_manual_memory_transfer_request(dfi: int, alfi: int, memory_address: bytes, memory_size: bytes) -> None:
    address_len, size_len = decode_alfi(alfi)
    if address_len <= 0 or size_len <= 0:
        raise ValueError(f"Invalid manual request: ALFI 0x{alfi:02X} requires non-zero address and size lengths.")
    if len(memory_address) != address_len or len(memory_size) != size_len:
        raise ValueError(
            f"Invalid manual request: ALFI 0x{alfi:02X} requires {address_len} address bytes and {size_len} size bytes."
        )


def build_manual_memory_transfer_request(service_id: int, dfi: int, alfi: int, memory_address: bytes, memory_size: bytes) -> ProbeCandidate:
    memory_transfer_service_name(service_id)
    validate_manual_memory_transfer_request(dfi, alfi, memory_address, memory_size)
    address_len, size_len = decode_alfi(alfi)
    request = bytes([service_id, dfi, alfi]) + memory_address + memory_size
    return ProbeCandidate(
        request=request,
        dfi=dfi,
        alfi=alfi,
        address_length=address_len,
        size_length=size_len,
        memory_address=memory_address,
        memory_size=memory_size,
        annotation=(
            f"{memory_transfer_service_name(service_id)} Advanced Manual Request; "
            f"DFI 0x{dfi:02X}; ALFI 0x{alfi:02X}; "
            f"address={spaced(memory_address)}; size={spaced(memory_size)}"
        ),
    )


def build_manual_memory_transfer_request_from_params(service_id: int, params: dict[str, Any]) -> ProbeCandidate:
    dfi = validate_hex_byte(params.get("data_format_identifier"), "data_format_identifier")
    alfi = validate_hex_byte(params.get("address_length_format_identifier"), "address_length_format_identifier")
    memory_address = parse_hex_payload(params.get("memory_address_hex", ""), name="memory_address_hex", strict_bytes=True)
    memory_size = parse_hex_payload(params.get("memory_size_hex", ""), name="memory_size_hex", strict_bytes=True)
    return build_manual_memory_transfer_request(service_id, dfi, alfi, memory_address, memory_size)


def memory_transfer_request_candidates(service_id: int, params: dict[str, Any]) -> list[ProbeCandidate]:
    mode = get_memory_transfer_mode(params)
    if mode == "security_gate_probe":
        return build_memory_security_gate_probe_requests(service_id)
    if mode == "advanced_manual_request":
        return [build_manual_memory_transfer_request_from_params(service_id, params)]
    raise ValueError("Mode must be Security Gate Probe or Advanced Manual Request")


def format_memory_transfer_preview(service_id: int, params: dict[str, Any]) -> str:
    mode = get_memory_transfer_mode(params)
    service = memory_transfer_service_name(service_id)
    mode_label = "Advanced Manual Request" if mode == "advanced_manual_request" else "Security Gate Probe"
    lines = [
        f"Mode: {mode_label}",
        f"Target SID: 0x{service_id:02X} {service}",
        "TransferData 0x36: disabled",
        "RequestTransferExit 0x37: disabled",
        "",
    ]
    if mode == "security_gate_probe":
        lines.append("Candidates:")
        for idx, candidate in enumerate(build_memory_security_gate_probe_requests(service_id), 1):
            lines.extend([
                f"{idx:02d}. {spaced(candidate.request)}",
                f"    {dfi_annotation(candidate.dfi)}",
                f"    {alfi_annotation(candidate.alfi)}",
                f"    address: {spaced(candidate.memory_address)}",
                f"    size:    {spaced(candidate.memory_size)}",
                "",
            ])
        return "\n".join(lines).rstrip()

    if mode == "advanced_manual_request":
        candidate = build_manual_memory_transfer_request_from_params(service_id, params)
        lines.extend([
            "Manual mode sends one explicit 0x34/0x35 request using DFI, ALFI, memoryAddress, and memorySize. 0x36 is still disabled by default.",
            "",
            "Manual request:",
            spaced(candidate.request),
            "",
            "Decoded:",
            dfi_annotation(candidate.dfi),
            alfi_annotation(candidate.alfi),
            f"memoryAddress: {spaced(candidate.memory_address)}",
            f"memorySize:    {spaced(candidate.memory_size)}",
        ])
        return "\n".join(lines)

    raise ValueError("Mode must be Security Gate Probe or Advanced Manual Request")


def build_memory_security_gate_probe_request(params: dict[str, Any]) -> bytes:
    service_id = parse_hex_byte(params.get("target_sid", "0x34"), "target_sid")
    return memory_transfer_request_candidates(service_id, params)[0].request


def build_uds20_request(params: dict[str, Any]) -> bytes:
    value = params.get("reset_subfunction")
    subfn = validate_hex_byte(value, "reset_subfunction")
    return bytes([0x11, subfn])


def build_uds21_request(params: dict[str, Any]) -> bytes:
    did = validate_hex_word(params.get("did_hex"), "did_hex")
    generation = str(params.get("data_generation") or ("random" if params.get("randomize_data") else "explicit"))

    def parse_length() -> int:
        raw_length = params.get("data_length_bytes") or params.get("did_length_bytes") or ""
        if not str(raw_length or "").strip():
            raise ValueError("Selected DID has unknown length. Enter DID length manually or select another DID.")
        try:
            value = int(str(raw_length).strip(), 10)
        except ValueError as exc:
            raise ValueError("data_length_bytes must be a positive decimal integer") from exc
        if value <= 0:
            raise ValueError("data_length_bytes must be a positive decimal integer")
        return value

    if generation == "explicit":
        data_text = str(params.get("data_hex") or params.get("did_message_hex") or "").strip()
        data = parse_hex_payload(data_text, name="data_hex", strict_bytes=True)
        length_text = str(params.get("data_length_bytes") or params.get("did_length_bytes") or "").strip()
        if length_text:
            length = parse_length()
            if len(data) != length:
                raise ValueError(f"data_hex length must be {length} byte(s), got {len(data)}")
    elif generation == "random":
        length = parse_length()
        fixed_payload = str(params.get("random_payload_hex") or "").strip()
        if fixed_payload:
            data = parse_hex_payload(fixed_payload, name="random_payload_hex", strict_bytes=True)
            if len(data) != length:
                raise ValueError(f"random_payload_hex length must be {length} byte(s), got {len(data)}")
        else:
            data = bytes(random.SystemRandom().randrange(0, 256) for _ in range(length))
    elif generation == "zero":
        data = bytes([0x00] * parse_length())
    elif generation == "pattern":
        pattern = parse_hex_byte(params.get("pattern_byte", "0xAA"), "pattern_byte")
        data = bytes([pattern] * parse_length())
    else:
        raise ValueError("data_generation must be random, zero, pattern, or explicit")
    return bytes([0x2E, (did >> 8) & 0xFF, did & 0xFF]) + data


def build_uds22_request(params: dict[str, Any]) -> bytes:
    did = validate_hex_word(params.get("did_hex"), "did_hex")
    return bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])


def build_uds25_request(params: dict[str, Any]) -> bytes:
    value = params.get("control_type")
    control_type = validate_hex_byte(value, "control_type")
    communication_type = validate_hex_byte(params.get("communication_type"), "communication_type")
    return build_communication_control_request(control_type, communication_type)


def build_communication_control_request(control_type: int, communication_type: int) -> bytes:
    return bytes([0x28, control_type & 0xFF, communication_type & 0xFF])


def build_communication_control_restore_request(params: dict[str, Any]) -> bytes:
    communication_type = validate_hex_byte(params.get("communication_type"), "communication_type")
    return build_communication_control_request(0x00, communication_type)


def int_param(params: dict[str, Any], key: str, default: int = 0) -> int:
    raw = str(params.get(key, default)).strip()
    if not raw:
        return default
    return int(raw, 10)


def float_param(params: dict[str, Any], key: str, default: float = 0.0) -> float:
    raw = str(params.get(key, default)).strip()
    if not raw:
        return default
    return float(raw)


def security_seed_subfn(params: dict[str, Any]) -> int:
    return parse_hex_byte(params.get("seed_subfn"), "seed_subfn")


def security_key_subfn(params: dict[str, Any]) -> int:
    raw = str(params.get("key_subfn", "")).strip()
    if raw:
        return parse_hex_byte(raw, "key_subfn")
    return default_key_subfn(security_seed_subfn(params))


def build_key_bytes(params: dict[str, Any], seed: Optional[bytes] = None) -> tuple[bytes, str]:
    policy = str(params.get("key_policy") or "format_random")
    key_length = int_param(params, "key_length", 16)
    if key_length <= 0:
        raise ValueError("key_length must be > 0")
    if policy == "explicit":
        key = parse_hex_payload(str(params.get("key_hex") or ""), name="key_hex")
        if len(key) != key_length:
            raise ValueError(f"key_hex length must be {key_length} byte(s), got {len(key)}")
        return key, "explicit key supplied by operator"
    if policy == "zero":
        return bytes([0x00] * key_length), "zero key generated"
    if policy == "pattern":
        pattern = parse_hex_byte(params.get("pattern_byte", "0xAA"), "pattern_byte")
        return bytes([pattern] * key_length), f"pattern key generated from 0x{pattern:02X}"
    if policy == "format_random":
        return bytes(random.SystemRandom().randrange(0, 256) for _ in range(key_length)), "format-random key generated"
    if policy == "invalid_bitflip":
        if not seed:
            return bytes([0xFF] * key_length), "invalid-bitflip fallback without seed"
        key = bytearray(seed[:key_length].ljust(key_length, b"\x00"))
        key[0] ^= 0x01
        return bytes(key), "invalid-bitflip key derived from observed seed format"
    if policy == "valid_algorithm_if_available":
        raise ValueError("valid_algorithm_if_available was selected, but no valid SecurityAccess algorithm is configured for this seed_subfn")
    raise ValueError(f"unsupported key_policy: {policy}")


def security_access_plan(test_id: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    plan: list[dict[str, Any]] = []
    seed_subfn = security_seed_subfn(params) if "seed_subfn" in params else 0x01
    key_subfn = security_key_subfn(params) if "key_subfn" in params or "seed_subfn" in params else default_key_subfn(seed_subfn)
    sessions = parse_session_subfunctions(params.get("session_flow", ""))
    def add_sessions() -> None:
        for subfn in sessions:
            plan.append({"step": "diagnostic_session_control", "request_hex": spaced(bytes([0x10, subfn]))})
    if test_id == "uds_10":
        count = int_param(params, "count", 10)
        boundary = str(params.get("session_boundary") or "default_session")
        for i in range(count):
            if not (i == 0 and params.get("skip_boundary_before_first")):
                if boundary == "default_session":
                    plan.append({"step": "session_boundary_default", "request_hex": spaced(bytes([0x10, parse_hex_byte(params.get("default_session_subfn", "0x01"), "default_session_subfn")]))})
                elif boundary == "ecu_reset":
                    plan.append({"step": "session_boundary_reset", "request_hex": spaced(bytes([0x11, parse_hex_byte(params.get("reset_subfn", "0x01"), "reset_subfn")]))})
                elif boundary == "s3_wait":
                    plan.append({"step": "session_boundary_s3_wait", "wait_seconds": float_param(params, "s3_wait_seconds", 5.0)})
            add_sessions()
            plan.append({"step": f"sample_{i + 1}_request_seed", "request_hex": spaced(bytes([0x27, seed_subfn]))})
        return plan
    if test_id in {"uds_11", "uds_15"}:
        add_sessions()
        count = int_param(params, "count", 20 if test_id == "uds_11" else 10)
        for i in range(count):
            plan.append({"step": f"request_seed_{i + 1}", "request_hex": spaced(bytes([0x27, seed_subfn]))})
        return plan
    if test_id == "uds_12":
        mode = str(params.get("source_mode") or "collect_same_session")
        if mode == "import_seed_csv":
            return [{"step": "import_seed_csv", "path": str(params.get("imported_seed_csv") or "")}]
        collect_id = "uds_11" if mode == "collect_same_session" else "uds_10"
        return security_access_plan(collect_id, params)
    if test_id == "uds_13":
        add_sessions()
        key, _ = build_key_bytes(params, seed=None)
        plan.append({"step": "send_key_without_seed", "request_hex": spaced(bytes([0x27, key_subfn]) + key)})
        return plan
    if test_id == "uds_14":
        add_sessions()
        plan.append({"step": "request_seed_before_stale_wait", "request_hex": spaced(bytes([0x27, seed_subfn]))})
        plan.append({"step": "stale_seed_wait", "wait_seconds": float_param(params, "stale_seed_wait_seconds", 5.0)})
        if params.get("reopen_session_before_sendkey"):
            add_sessions()
        plan.append({"step": "send_key_after_stale_wait", "request_hex": f"27 {key_subfn:02X} <key>"})
        return plan
    if test_id == "uds_16":
        add_sessions()
        plan.append({"step": "request_seed_once", "request_hex": spaced(bytes([0x27, seed_subfn]))})
        for i in range(int_param(params, "attempts", 5)):
            plan.append({"step": f"send_key_attempt_{i + 1}", "request_hex": f"27 {key_subfn:02X} <key>"})
        return plan
    if test_id == "uds_17":
        add_sessions()
        for i in range(int_param(params, "exchanges", 5)):
            plan.append({"step": f"exchange_{i + 1}_request_seed", "request_hex": spaced(bytes([0x27, seed_subfn]))})
            plan.append({"step": f"exchange_{i + 1}_send_key", "request_hex": f"27 {key_subfn:02X} <key>"})
        return plan
    if test_id == "uds_18":
        add_sessions()
        for i in range(int_param(params, "attempts_to_trigger_penalty", 5)):
            plan.append({"step": f"penalty_trigger_{i + 1}_request_seed", "request_hex": spaced(bytes([0x27, seed_subfn]))})
            plan.append({"step": f"penalty_trigger_{i + 1}_send_key", "request_hex": f"27 {key_subfn:02X} <key>"})
        plan.append({"step": "penalty_probe_request_seed", "request_hex": spaced(bytes([0x27, seed_subfn]))})
        return plan
    if test_id == "uds_19":
        add_sessions()
        plan.append({"step": "single_request_seed", "request_hex": spaced(bytes([0x27, seed_subfn]))})
        plan.append({"step": "capture_extra_seed_responses", "window_seconds": float_param(params, "capture_window_seconds", 1.0)})
        return plan
    return plan


def flow_contains_security_access(flow_text: str) -> bool:
    for payload in parse_session_flow(flow_text):
        if payload and payload[0] == 0x27:
            return True
    return False


def validate_common_flows(_: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    if "session_flow" in params:
        try:
            parse_session_subfunctions(params.get("session_flow", ""))
        except ValueError as exc:
            errors["session_flow"] = str(exc)
    return errors


def validate_security_access_test(test_id: str) -> Callable[[TargetProfile, dict[str, Any]], dict[str, str]]:
    def _validate(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
        errors: dict[str, str] = {}
        if "session_flow" in params and str(params.get("session_flow") or "").strip():
            try:
                parse_session_subfunctions(params.get("session_flow", ""))
            except ValueError as exc:
                errors["session_flow"] = str(exc)
        elif test_id != "uds_12" or params.get("source_mode") != "import_seed_csv":
            errors["session_flow"] = "diagnostic_session_flow is required, e.g. 03 or 03 02"
        if "seed_subfn" in params and (test_id != "uds_12" or params.get("source_mode") != "import_seed_csv"):
            try:
                seed = security_seed_subfn(params)
                if seed % 2 == 0:
                    errors["seed_subfn"] = "seed_subfn is normally an odd RequestSeed subfunction"
            except ValueError as exc:
                errors["seed_subfn"] = str(exc)
        if "key_subfn" in params:
            try:
                key = security_key_subfn(params)
                if key % 2 == 1:
                    errors["key_subfn"] = "key_subfn is normally an even SendKey subfunction"
            except ValueError as exc:
                errors["key_subfn"] = str(exc)
        numeric_min = {
            "count": 2,
            "attempts": 1,
            "exchanges": 1,
            "attempts_to_trigger_penalty": 1,
            "key_length": 1,
            "enforcement_expected_after_count": 1,
            "minimum_seed_length_bytes": 1,
            "recommended_seed_length_bytes": 1,
        }
        if test_id == "uds_15":
            numeric_min["count"] = 5
        for key, minimum in numeric_min.items():
            if key in params:
                try:
                    value = int_param(params, key, minimum)
                    if value < minimum:
                        errors[key] = f"{key} must be >= {minimum}"
                except ValueError as exc:
                    errors[key] = f"{key} must be a decimal integer"
        for key in (
            "delay", "post_session_delay", "tester_present_interval", "nrc37_wait",
            "stale_seed_wait_seconds", "delay_before_sendkey", "key_delay",
            "delay_between_attempts", "delay_between_exchanges", "penalty_probe_delay",
            "capture_window_seconds", "drain_before_request", "post_boundary_delay",
            "reset_wait", "s3_wait_seconds",
        ):
            if key in params:
                try:
                    if float_param(params, key, 0.0) < 0:
                        errors[key] = f"{key} must be >= 0"
                except ValueError:
                    errors[key] = f"{key} must be numeric"
        if test_id == "uds_12" and params.get("source_mode") == "import_seed_csv":
            path = Path(str(params.get("imported_seed_csv") or "").strip())
            if not str(path):
                errors["imported_seed_csv"] = "imported_seed_csv is required"
            elif not path.exists() and not target.dry_run:
                errors["imported_seed_csv"] = "imported_seed_csv does not exist"
        if "key_policy" in params:
            policy = str(params.get("key_policy") or "")
            allowed = {"explicit", "zero", "pattern", "format_random", "invalid_bitflip"}
            if policy not in allowed:
                errors["key_policy"] = f"key_policy must be one of {', '.join(sorted(allowed))}"
            if policy == "explicit":
                try:
                    build_key_bytes(params, seed=b"\x00" * max(1, int_param(params, "key_length", 16)))
                except ValueError as exc:
                    errors["key_hex"] = str(exc)
            if policy == "pattern":
                try:
                    parse_hex_byte(params.get("pattern_byte", "0xAA"), "pattern_byte")
                except ValueError as exc:
                    errors["pattern_byte"] = str(exc)
        return errors
    return _validate


def parse_acceptable_nrcs(value: Any) -> set[int]:
    raw = str(value or "").strip()
    if not raw:
        return {0x22, 0x24, 0x31, 0x33, 0x7E, 0x7F}
    raw = raw.replace("[", " ").replace("]", " ")
    return set(parse_hex_payload(raw, name="acceptable_nrcs", strict_bytes=True))


def validate_uds20(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    precondition_flow: list[int] = []
    test_flow: list[int] = []
    try:
        precondition_flow = parse_session_subfunctions(params.get("precondition_session_flow", ""))
    except ValueError as exc:
        errors["precondition_session_flow"] = str(exc)
    try:
        test_flow = parse_session_subfunctions(params.get("test_session_flow", ""))
    except ValueError as exc:
        errors["test_session_flow"] = str(exc)
    if not precondition_flow and "precondition_session_flow" not in errors:
        errors["precondition_session_flow"] = "Required/precondition session flow is required"
    if not test_flow and "test_session_flow" not in errors:
        errors["test_session_flow"] = "Test session flow is required"
    if precondition_flow and test_flow and precondition_flow == test_flow:
        errors["test_session_flow"] = "Invalid UDS-20 setup: test_session_flow must differ from precondition_session_flow."
    try:
        build_uds20_request(params)
    except ValueError as exc:
        errors["reset_subfunction"] = str(exc)
    try:
        parse_acceptable_nrcs(params.get("acceptable_nrcs"))
    except ValueError as exc:
        errors["acceptable_nrcs"] = str(exc)
    return errors


def validate_uds21(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors = validate_common_flows(target, params)
    try:
        build_uds21_request(params)
    except Exception as exc:
        message = str(exc)
        if "did_hex" in message:
            errors["did_hex"] = message
        elif "data_length" in message or "unknown length" in message:
            errors["data_length_bytes"] = message
        elif "pattern_byte" in message:
            errors["pattern_byte"] = message
        elif "data_generation" in message:
            errors["data_generation"] = message
        else:
            errors["data_hex"] = message
    return errors


def validate_uds22(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors = validate_common_flows(target, params)
    try:
        build_uds22_request(params)
    except ValueError as exc:
        errors["did_hex"] = str(exc)
    return errors


def validate_memory_security_gate_probe(sid: int) -> Callable[[TargetProfile, dict[str, Any]], dict[str, str]]:
    def _validate(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
        errors = validate_common_flows(target, params)
        mode = get_memory_transfer_mode(params)
        if mode not in {"security_gate_probe", "advanced_manual_request"}:
            errors["probe_mode"] = "Mode must be Security Gate Probe or Advanced Manual Request"
            return errors
        try:
            memory_transfer_request_candidates(sid, params)
        except ValueError as exc:
            message = str(exc)
            if "data_format" in message:
                errors["data_format_identifier"] = message
            elif "address_length_format" in message or "ALFI" in message:
                errors["address_length_format_identifier"] = message
            elif "address" in message:
                errors["memory_address_hex"] = message
            elif "size" in message:
                errors["memory_size_hex"] = message
            else:
                errors["target_sid"] = message
        return errors
    return _validate


def validate_uds25(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors = validate_common_flows(target, params)
    try:
        build_uds25_request(params)
    except ValueError as exc:
        message = str(exc)
        if "communication" in message:
            errors["communication_type"] = message
        else:
            errors["control_type"] = message
    if params.get("auto_restore"):
        try:
            build_communication_control_restore_request(params)
        except ValueError as exc:
            errors["communication_type"] = str(exc)
    return errors


def validate_subservices(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    try:
        validate_hex_byte(params.get("service_id"), "service_id")
    except ValueError as exc:
        errors["service_id"] = str(exc)
    scan_range = str(params.get("subfunction_range_or_max") or "").strip()
    if not scan_range:
        errors["subfunction_range_or_max"] = "subfunction max/range is required"
    else:
        pieces = [p.strip() for p in re.split(r"[-:]", scan_range) if p.strip()]
        try:
            for piece in pieces:
                validate_hex_byte(piece, "subfunction_range_or_max")
        except ValueError as exc:
            errors["subfunction_range_or_max"] = str(exc)
    if params.get("run_session_flow"):
        try:
            parse_session_subfunctions(params.get("session_flow", ""))
        except ValueError as exc:
            errors["session_flow"] = str(exc)
    return errors


def validate_discovery(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    try:
        bits = int(str(params.get("arb_bits") or "").strip())
        if bits <= 0:
            raise ValueError("arb_bits must be > 0")
    except ValueError as exc:
        errors["arb_bits"] = str(exc)
    try:
        delay = float(str(params.get("delay") or "").strip())
        if delay < 0:
            raise ValueError("delay must be >= 0")
    except ValueError as exc:
        errors["delay"] = str(exc)
    return errors


def validate_did_dump(target: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    try:
        min_did = validate_hex_word(params.get("min_did"), "min_did")
    except ValueError as exc:
        min_did = 0
        errors["min_did"] = str(exc)
    try:
        max_did = validate_hex_word(params.get("max_did"), "max_did")
    except ValueError as exc:
        max_did = 0xFFFF
        errors["max_did"] = str(exc)
    if "min_did" not in errors and "max_did" not in errors and min_did > max_did:
        errors["max_did"] = "max_did must be >= min_did"
    try:
        timeout_value = float(str(params.get("timeout") or "").strip())
        if timeout_value <= 0:
            raise ValueError("timeout must be > 0")
    except ValueError as exc:
        errors["timeout"] = str(exc)
    return errors


def verdict_reset(request: bytes, response: Optional[bytes], params: dict[str, Any], observations: list[dict[str, Any]]) -> tuple[str, str]:
    parsed = parse_uds_response(request, response)
    if parsed.malformed:
        return VERDICT_INCONCLUSIVE, parsed.note
    if parsed.positive_response:
        if len(response or b"") >= 2 and response[1] == request[1]:
            return VERDICT_POTENTIAL, "ECU Reset was accepted without proven preconditions; OEM requirements are unknown."
        return VERDICT_INCONCLUSIVE, "Positive response SID was present but reset subfunction echo was malformed."
    if parsed.negative_response and parsed.nrc in {0x7E, 0x7F}:
        return "NOT_TESTABLE", f"ECU Reset is not exposed in this active session: NRC 0x{parsed.nrc:02X} {parsed.nrc_meaning}."
    if parsed.negative_response and parsed.nrc in {0x22, 0x33}:
        return VERDICT_PASS, f"ECU rejected reset with defensive NRC 0x{parsed.nrc:02X} {parsed.nrc_meaning}."
    if parsed.negative_response:
        return VERDICT_INCONCLUSIVE, f"ECU returned NRC 0x{parsed.nrc:02X} {parsed.nrc_meaning}; protection cannot be concluded."
    if response is None:
        return VERDICT_INCONCLUSIVE, "No response after reset request; this may be timeout, transport loss, or reset behavior."
    return VERDICT_INCONCLUSIVE, parsed.note


def classify_uds20_reset_response(request: bytes, response: Optional[bytes], params: dict[str, Any], transport_status: str = "") -> tuple[str, str, UdsParsedResponse]:
    parsed = parse_uds_response(request, response, transport_status=transport_status)
    acceptable_nrcs = parse_acceptable_nrcs(params.get("acceptable_nrcs"))
    if response is None:
        return (
            VERDICT_INCONCLUSIVE_NO_RESPONSE,
            "No response received. Cannot confirm whether ECU denied the request or reset/communication was disrupted.",
            parsed,
        )
    if parsed.positive_response and response and len(response) >= 2 and response[0] == 0x51 and response[1] == request[1]:
        return (
            VERDICT_FAIL_PRECONDITION_BYPASS,
            "ECU accepted ECUReset outside the required precondition/session.",
            parsed,
        )
    if parsed.negative_response and parsed.nrc in acceptable_nrcs:
        return (
            VERDICT_PASS_EXPECTED_DENIAL,
            "ECUReset was denied when precondition/session was not satisfied.",
            parsed,
        )
    if parsed.negative_response and parsed.nrc == 0x78:
        return (
            VERDICT_INCONCLUSIVE_NO_RESPONSE,
            "ECU returned responsePending but no final decisive response was available.",
            parsed,
        )
    if parsed.malformed:
        return VERDICT_INCONCLUSIVE, parsed.note, parsed
    if parsed.negative_response:
        return (
            VERDICT_NEED_MANUAL_REVIEW,
            f"ECUReset was denied with NRC 0x{parsed.nrc:02X} {parsed.nrc_meaning}, which is not in acceptable_nrcs.",
            parsed,
        )
    return VERDICT_NEED_MANUAL_REVIEW, parsed.note, parsed


def verdict_wdbi(request: bytes, response: Optional[bytes], params: dict[str, Any], observations: list[dict[str, Any]]) -> tuple[str, str]:
    parsed = parse_uds_response(request, response)
    did_ok = response is not None and len(response) >= 3 and response[:3] == bytes([0x6E, request[1], request[2]])
    if parsed.malformed:
        return VERDICT_NEED_MANUAL_REVIEW, parsed.note
    if parsed.positive_response and did_ok:
        return VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY, "WriteDataByIdentifier was accepted without SecurityAccess."
    if parsed.negative_response and parsed.nrc == 0x33:
        return VERDICT_PASS_SECURITY_GATE, "ECU requires SecurityAccess for WriteDataByIdentifier."
    if parsed.negative_response and parsed.nrc == 0x31:
        return VERDICT_INCONCLUSIVE_PARAMETER_OR_DID, "DID is out of range or not writable; this does not prove access control."
    if parsed.negative_response and parsed.nrc == 0x13:
        return VERDICT_INVALID_REQUEST_FORMAT, "ECU reported invalid request length or format."
    if parsed.negative_response and parsed.nrc == 0x11:
        return VERDICT_SERVICE_NOT_SUPPORTED, "WriteDataByIdentifier is not supported."
    if parsed.negative_response and parsed.nrc in {0x7E, 0x7F}:
        return VERDICT_WRONG_SESSION, "WriteDataByIdentifier is not supported in the active diagnostic session."
    if response is None:
        return VERDICT_NEED_MANUAL_REVIEW, "No response to WriteDataByIdentifier request."
    return VERDICT_NEED_MANUAL_REVIEW, parsed.note


def verdict_rdbi(request: bytes, response: Optional[bytes], params: dict[str, Any], observations: list[dict[str, Any]]) -> tuple[str, str]:
    parsed = parse_uds_response(request, response)
    did_ok = response is not None and len(response) >= 3 and response[:3] == bytes([0x62, request[1], request[2]])
    if parsed.malformed:
        return VERDICT_NEED_MANUAL_REVIEW, parsed.note
    if parsed.positive_response and did_ok:
        return VERDICT_FAIL_READABLE_WITHOUT_SECURITY, "ReadDataByIdentifier returned data without SecurityAccess."
    if parsed.negative_response and parsed.nrc == 0x33:
        return VERDICT_PASS_SECURITY_GATE, "ECU requires SecurityAccess for ReadDataByIdentifier."
    if parsed.negative_response and parsed.nrc == 0x31:
        return VERDICT_INCONCLUSIVE_PARAMETER_OR_DID, "DID is unsupported or out of range; sensitivity cannot be evaluated."
    if parsed.negative_response and parsed.nrc == 0x13:
        return VERDICT_INVALID_REQUEST_FORMAT, "ECU reported invalid request length or format."
    if parsed.negative_response and parsed.nrc == 0x11:
        return VERDICT_SERVICE_NOT_SUPPORTED, "ReadDataByIdentifier is not supported."
    if parsed.negative_response and parsed.nrc in {0x7E, 0x7F}:
        return VERDICT_WRONG_SESSION, "ReadDataByIdentifier is not supported in the active diagnostic session."
    if response is None:
        return VERDICT_NEED_MANUAL_REVIEW, "No response to ReadDataByIdentifier request."
    return VERDICT_NEED_MANUAL_REVIEW, parsed.note


def security_access_observed_before_target(observations: list[dict[str, Any]], target_sid: int) -> bool:
    for obs in observations:
        request_hex = str(obs.get("request_hex") or "")
        try:
            payload = parse_hex_payload(request_hex, name="request_hex", allow_empty=True, strict_bytes=True)
        except ValueError:
            continue
        if not payload:
            continue
        if payload[0] == target_sid:
            return False
        if payload[0] == 0x27:
            return True
    return False


def classify_memory_transfer_probe_response(service_id: int, request: bytes, response: Optional[bytes], transport_status: str = "") -> tuple[str, str, bool, UdsParsedResponse]:
    parsed = parse_uds_response(request, response, transport_status=transport_status)
    service_name = "RequestDownload" if service_id == 0x34 else "RequestUpload"
    positive_sid = (service_id + 0x40) & 0xFF
    if parsed.positive_response and response and response[0] == positive_sid:
        return (
            VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY,
            f"ECU accepted {service_name} negotiation without SecurityAccess.",
            True,
            parsed,
        )
    if parsed.negative_response and parsed.nrc == 0x33:
        return VERDICT_PASS_SECURITY_GATE, f"ECU requires SecurityAccess for {service_name}.", True, parsed
    if parsed.negative_response and parsed.nrc == 0x31:
        return (
            VERDICT_INCONCLUSIVE_RANGE_CHECKED_FIRST,
            "Request format was processed, but address/size may be out of range; this does not prove SecurityAccess protection.",
            False,
            parsed,
        )
    if parsed.negative_response and parsed.nrc == 0x13:
        return VERDICT_INVALID_REQUEST_FORMAT, "Request length or ALFI format is invalid.", False, parsed
    if parsed.negative_response and parsed.nrc == 0x11:
        return VERDICT_SERVICE_NOT_SUPPORTED, f"{service_name} is not supported by the ECU.", True, parsed
    if parsed.negative_response and parsed.nrc == 0x7E:
        return VERDICT_WRONG_SESSION, f"{service_name} is not supported in the active diagnostic session.", True, parsed
    if parsed.negative_response and parsed.nrc == 0x7F:
        return VERDICT_WRONG_SESSION, f"{service_name} is not supported in the active diagnostic session.", True, parsed
    if response is None or parsed.malformed:
        return VERDICT_NEED_MANUAL_REVIEW, parsed.note or "No decisive response was received.", True, parsed
    return VERDICT_NEED_MANUAL_REVIEW, parsed.note, True, parsed


def classify_communication_control_response(request: bytes, response: Optional[bytes], transport_status: str = "") -> tuple[str, str, UdsParsedResponse]:
    parsed = parse_uds_response(request, response, transport_status=transport_status)
    control_type = request[1] if len(request) > 1 else None
    if parsed.positive_response and response and len(response) >= 2 and response[0] == 0x68 and response[1] in {0x01, 0x02, 0x03}:
        return (
            VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY,
            "ECU accepted CommunicationControl without SecurityAccess.",
            parsed,
        )
    if parsed.positive_response and response and len(response) >= 2 and control_type is not None and response[1] == control_type:
        return (
            VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY,
            "ECU accepted CommunicationControl without SecurityAccess.",
            parsed,
        )
    if parsed.negative_response and parsed.nrc == 0x33:
        return VERDICT_PASS_SECURITY_GATE, "ECU requires SecurityAccess for CommunicationControl.", parsed
    if parsed.negative_response and parsed.nrc == 0x31:
        return (
            VERDICT_PARAMETER_UNSUPPORTED,
            "controlType/communicationType may be unsupported or out of range; this does not prove SecurityAccess protection.",
            parsed,
        )
    if parsed.negative_response and parsed.nrc == 0x12:
        return VERDICT_PARAMETER_UNSUPPORTED, "CommunicationControl subfunction/controlType is not supported.", parsed
    if parsed.negative_response and parsed.nrc == 0x11:
        return VERDICT_SERVICE_NOT_SUPPORTED, "CommunicationControl service is not supported.", parsed
    if parsed.negative_response and parsed.nrc == 0x7E:
        return VERDICT_WRONG_SESSION, "CommunicationControl is not supported in the active diagnostic session.", parsed
    if parsed.negative_response and parsed.nrc == 0x7F:
        return VERDICT_WRONG_SESSION, "CommunicationControl is not supported in the active diagnostic session.", parsed
    if response is None or parsed.malformed:
        return (
            VERDICT_NEED_MANUAL_REVIEW,
            "No response or malformed response; this may indicate communication impact, timeout, or unsupported request.",
            parsed,
        )
    return VERDICT_NEED_MANUAL_REVIEW, parsed.note, parsed


def verdict_seed_sampling(test_id: str, metrics: dict[str, Any]) -> tuple[str, str]:
    positive = int(metrics.get("positive_seed_samples") or 0)
    requested = int(metrics.get("requested_samples") or 0)
    duplicate_occurrences = int(metrics.get("duplicate_occurrences") or 0)
    if positive < 2:
        return "INCONCLUSIVE", f"Only {positive}/{requested} valid seed samples were collected."
    if duplicate_occurrences:
        return "FAIL/SUSPICIOUS", f"{duplicate_occurrences} duplicate seed occurrence(s) observed in {positive} valid samples."
    if metrics.get("monotonic_or_counter_like"):
        return "FAIL/SUSPICIOUS", f"Seed sequence appears monotonic or counter-like across {positive} samples."
    return "PASS/OBSERVED", f"No duplicate seed values observed in {positive} valid samples; this is not cryptographic proof."


def verdict_seed_length(metrics: dict[str, Any], params: dict[str, Any]) -> tuple[str, str]:
    total = int(metrics.get("total_seed_samples") or 0)
    if total <= 0:
        return "INCONCLUSIVE", "No valid seed samples were available for length analysis."
    if int(metrics.get("empty_seed_count") or 0) > 0:
        return "FAIL/FINDING", "At least one positive SecurityAccess response contained an empty seed."
    if int(metrics.get("short_seed_count") or 0) > 0:
        return "FAIL/FINDING", f"{metrics.get('short_seed_count')} seed(s) shorter than the configured minimum were observed."
    recommended = int_param(params, "recommended_seed_length_bytes", 8)
    if int(metrics.get("min_seed_length") or 0) < recommended:
        return "PASS WITH WARNING / REVIEW", "All seeds met the minimum length but at least one was shorter than the recommended length."
    return "PASS/OBSERVED", "All observed seeds met the recommended length threshold."


def verdict_requestseed_limit(metrics: dict[str, Any], params: dict[str, Any]) -> tuple[str, str]:
    threshold = int_param(params, "enforcement_expected_after_count", 5)
    if metrics.get("nrc36_count") or metrics.get("nrc37_count"):
        return "PASS/EXPECTED", "ECU showed attempt-limit or penalty behavior using NRC 0x36/0x37."
    if metrics.get("nrc24_count"):
        return "REVIEW", "ECU returned NRC 0x24; it may require SendKey before issuing another seed."
    if metrics.get("continuous_seed_after_threshold"):
        return "FAIL/SUSPICIOUS", f"ECU continued issuing positive seeds after threshold {threshold} without enforcement."
    return "INCONCLUSIVE", "RequestSeed limit behavior could not be determined from collected responses."


def verdict_security_behavior(test_id: str, observations: list[dict[str, Any]], params: dict[str, Any], metrics: dict[str, Any]) -> tuple[str, str]:
    def has_step_positive(step_fragment: str) -> bool:
        return any(step_fragment in str(obs.get("step", "")) and obs.get("security_response_kind") == "positive_sendkey" for obs in observations)
    def has_nrc(nrc_hex: str) -> bool:
        return any(str(obs.get("nrc", "")).lower() == nrc_hex.lower() for obs in observations)
    def not_testable_nrc() -> bool:
        return has_nrc("0x7E") or has_nrc("0x7F")
    if not_testable_nrc():
        return "NOT TESTABLE", "SecurityAccess service or subfunction is not supported in the active session."
    if any(obs.get("response_type") in {"timeout", "transport_error", "no_response"} for obs in observations):
        return "INCONCLUSIVE", "At least one required UDS exchange timed out or failed at transport level."
    policy = str(params.get("key_policy") or "")
    if test_id == "uds_13":
        if has_nrc("0x24"):
            return "PASS/EXPECTED", "ECU rejected SendKey without prior RequestSeed using NRC 0x24 requestSequenceError."
        if has_step_positive("send_key_without_seed"):
            return "FAIL/SUSPICIOUS", "ECU accepted SendKey without a prior RequestSeed."
        if has_nrc("0x35"):
            return "REVIEW", "ECU rejected the key with NRC 0x35 but did not report requestSequenceError."
        return "INCONCLUSIVE", "SendKey without seed did not produce a decisive response."
    if test_id == "uds_14":
        if has_step_positive("send_key_after_stale_wait"):
            if policy == "valid_algorithm_if_available":
                return "UNLOCKED/OBSERVED", "ECU accepted SendKey after stale wait using an explicitly selected valid-key policy."
            return "FAIL/SUSPICIOUS", "ECU accepted SendKey after stale seed wait."
        if has_nrc("0x22") or has_nrc("0x24") or has_nrc("0x35") or has_nrc("0x37"):
            return "PASS/EXPECTED", "ECU rejected stale SendKey with a defensive NRC."
        if not metrics.get("seed_collected"):
            return "NOT TESTABLE", "No seed was collected before stale-key step."
        return "INCONCLUSIVE", "Stale seed behavior was not decisive."
    if test_id == "uds_16":
        if metrics.get("positive_unlock_seen"):
            return ("UNLOCKED/OBSERVED" if policy == "valid_algorithm_if_available" else "FAIL/SUSPICIOUS"), "A SendKey attempt returned positive."
        if metrics.get("nrc36_count") or metrics.get("nrc37_count"):
            return "PASS/EXPECTED", "ECU escalated invalid key attempts to NRC 0x36/0x37."
        if metrics.get("nrc35_count", 0) >= int_param(params, "attempts", 5):
            return "WEAK/REVIEW", "Only NRC 0x35 observed; no attempt-limit escalation within configured attempts."
        return "INCONCLUSIVE", "One-seed many-key attempt-limit behavior was not decisive."
    if test_id == "uds_17":
        if metrics.get("positive_unlock_seen"):
            return ("UNLOCKED/OBSERVED" if policy == "valid_algorithm_if_available" else "FAIL/SUSPICIOUS"), "A SendKey exchange returned positive."
        if metrics.get("nrc36_count") or metrics.get("nrc37_count"):
            return "PASS/EXPECTED", "ECU accumulated failed attempts and returned NRC 0x36/0x37."
        if metrics.get("continuous_no_penalty_after_threshold"):
            return "FAIL/SUSPICIOUS", "Repeated seed/key cycles did not trigger penalty escalation."
        return "INCONCLUSIVE", "Not enough completed exchanges to assess cumulative attempt limits."
    if test_id == "uds_18":
        if metrics.get("probe_nrc37"):
            return "PASS/EXPECTED", "RequestSeed during penalty returned NRC 0x37."
        if metrics.get("probe_positive_seed") and metrics.get("penalty_triggered"):
            return "FAIL/SUSPICIOUS", "ECU returned a positive seed while penalty mode was expected."
        if not metrics.get("penalty_triggered"):
            return "INCONCLUSIVE", "Penalty mode could not be triggered before RequestSeed probe."
        return "WEAK/REVIEW", "Penalty was triggered but RequestSeed probe did not return the expected NRC 0x37."
    if test_id == "uds_19":
        count = int(metrics.get("total_positive_seed_responses") or 0)
        if count == 1:
            return "PASS/OBSERVED", "Exactly one positive seed response observed for one RequestSeed."
        if count > 1:
            return "FAIL/SUSPICIOUS", f"{count} positive seed responses observed for one RequestSeed."
        return "NOT TESTABLE", "No valid positive seed response was observed."
    return "INCONCLUSIVE", "No SecurityAccess verdict rule matched."


def command_discovery(target: TargetProfile, params: dict[str, Any]) -> list[str]:
    return ["caringcaribou", "uds", "discovery", "-ab", str(params["arb_bits"]), "-d", str(params["delay"])]


def command_services(target: TargetProfile, params: dict[str, Any]) -> list[str]:
    return [
        "caringcaribou",
        "uds",
        "services",
        format_arbid(target.tester_tx_id),
        format_arbid(target.tester_rx_id),
        "-t",
        str(target.timeout),
    ]


def command_did_dump(target: TargetProfile, params: dict[str, Any]) -> list[str]:
    return [
        "caringcaribou",
        "uds",
        "dump_dids",
        format_arbid(target.tester_tx_id),
        format_arbid(target.tester_rx_id),
        "--min_did",
        str(params["min_did"]),
        "--max_did",
        str(params["max_did"]),
        "-t",
        str(params.get("timeout") or target.timeout),
    ]


def command_subservices(target: TargetProfile, params: dict[str, Any]) -> list[str]:
    return [
        "caringcaribou",
        "uds",
        "subservices",
        str(params["subfunction_range_or_max"]),
        str(params["service_id"]),
        format_arbid(target.tester_tx_id),
        format_arbid(target.tester_rx_id),
    ]


def command_argv_for(test: TestDefinition, target: TargetProfile, params: dict[str, Any]) -> list[str]:
    if test.runner_kind == "external" and test.build_command:
        return test.build_command(target, params)
    return []


def command_preview_from_argv(argv: list[str]) -> str:
    return " ".join(argv)


def parse_external_discovery(output: str, evidence_dir: Path) -> dict[str, Any]:
    candidates = sorted({f"0x{int(m, 16):X}" for m in re.findall(r"\b(?:0x)?([0-9A-Fa-f]{3,8})\b", output)})
    result = {"candidate_arbitration_ids": candidates}
    (evidence_dir / "recon_discovery.txt").write_text(output, encoding="utf-8")
    if candidates:
        (evidence_dir / "recon_discovery.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def parse_services_output(output: str, evidence_dir: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    service_names = {
        0x10: "DiagnosticSessionControl",
        0x11: "ECUReset",
        0x22: "ReadDataByIdentifier",
        0x27: "SecurityAccess",
        0x28: "CommunicationControl",
        0x2E: "WriteDataByIdentifier",
        0x34: "RequestDownload",
        0x35: "RequestUpload",
    }
    for line in output.splitlines():
        match = re.search(r"(?:service|sid)?\s*(?:0x)?([0-9A-Fa-f]{2})", line, re.IGNORECASE)
        if not match:
            continue
        sid = int(match.group(1), 16)
        rows.append({
            "service_id": f"0x{sid:02X}",
            "service_name_if_known": service_names.get(sid, "UNKNOWN"),
            "response_raw": line.strip(),
            "positive_or_negative": "negative" if "7F" in line.upper() else "positive_or_unknown",
            "notes": "",
        })
    write_csv_json(evidence_dir, "supported_services", rows)
    return {"supported_services": rows}


def parse_did_dump_output(output: str, evidence_dir: Path) -> dict[str, Any]:
    raw_rows: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        did_match = re.search(r"(?:DID\s*)?(?:0x)?([0-9A-Fa-f]{4})", line)
        if not did_match:
            raw_rows.append({"Notes": line, "source": "caringcaribou"})
            continue
        did = int(did_match.group(1), 16)
        bytes_found = [int(x, 16) for x in re.findall(r"\b([0-9A-Fa-f]{2})\b", line)]
        raw = bytes(bytes_found)
        data = b""
        positive = False
        nrc = ""
        nrc_meaning = ""
        notes = "" if raw else line.strip()
        if len(raw) >= 3 and raw[0] == 0x62 and raw[1] == ((did >> 8) & 0xFF) and raw[2] == (did & 0xFF):
            positive = True
            data = raw[3:]
        elif len(raw) >= 3 and raw[0] == 0x7F:
            nrc = f"0x{raw[2]:02X}"
            nrc_meaning = nrc_to_text(raw[2])
            notes = "negative response"
        raw_rows.append({
            "did_hex": f"0x{did:04X}",
            "did_name": "UNKNOWN",
            "raw_response_hex": spaced(raw),
            "did_message_hex": spaced(data),
            "did_length_bytes": len(data) if positive else "",
            "data_hex": spaced(data),
            "data_length_bytes": len(data) if positive else "",
            "positive_response": positive,
            "nrc": nrc,
            "nrc_meaning": nrc_meaning,
            "notes": notes,
        })
    rows, summary = normalize_did_catalog_rows(raw_rows, source="caringcaribou")
    columns = ["DID", "Length", "Message DID", "Notes", "Source", "Parse Status", "Parse Error"]
    write_csv_json(evidence_dir, "parsed_did_catalog", rows, columns=columns)
    write_csv_json(evidence_dir, "did_catalog", rows, columns=columns)
    summary["parsed_did_catalog_csv"] = str(evidence_dir / "parsed_did_catalog.csv")
    return {"did_catalog": rows, "did_parse_summary": summary}


def write_csv_json(evidence_dir: Path, stem: str, rows: list[dict[str, Any]], *, columns: Optional[list[str]] = None) -> None:
    (evidence_dir / f"{stem}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    fields = columns or (list(rows[0].keys()) if rows else [])
    if not rows:
        with (evidence_dir / f"{stem}.csv").open("w", newline="", encoding="utf-8") as fh:
            if fields:
                csv.DictWriter(fh, fieldnames=fields).writeheader()
        return
    with (evidence_dir / f"{stem}.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


SESSION_FLOW = FieldSpec(
    "session_flow",
    "Diagnostic session flow",
    "textarea",
    "03",
    False,
    "Subfunctions only: 03 or 03 02. Tool sends 10 03 then 10 02.",
)


SESSION_SUBFN_FLOW = FieldSpec(
    "session_flow",
    "Diagnostic session flow",
    "textarea",
    "03",
    True,
    "Subfunctions only: 03 or 03 41 60. Tool adds service 0x10.",
)
SEED_SUBFN = FieldSpec("seed_subfn", "RequestSeed subfunction", "text", "0x01", True, "0x01")
KEY_SUBFN = FieldSpec("key_subfn", "SendKey subfunction", "text", "", False, "auto: RequestSeed subfunction + 1", visible_if=lambda p: False)
KEY_POLICY_CHOICES = (
    Choice("random bytes", "format_random"),
    Choice("all zero", "zero"),
    Choice("fixed pattern", "pattern"),
    Choice("bitflip observed seed", "invalid_bitflip"),
    Choice("explicit key", "explicit"),
)


def key_policy_fields(choices: tuple[Choice, ...] = KEY_POLICY_CHOICES, default: str = "format_random") -> tuple[FieldSpec, ...]:
    return (
        FieldSpec("key_policy", "Key policy", "combo", default, True, choices=choices),
        FieldSpec("key_hex", "Explicit key hex", "textarea", "", False, "AA BB ...", visible_if=lambda p: p.get("key_policy") == "explicit"),
        FieldSpec("pattern_byte", "Pattern byte", "text", "0xAA", False, visible_if=lambda p: p.get("key_policy") == "pattern"),
        FieldSpec("key_length", "Key length bytes", "text", "16", True),
    )


def make_sa_test(
    *,
    test_id: str,
    title: str,
    mode: str,
    objective: str,
    fields: tuple[FieldSpec, ...],
    sends_key: bool = False,
    evidence_outputs: tuple[str, ...] = (),
) -> TestDefinition:
    return TestDefinition(
        id=test_id,
        title=f"{test_id.upper()} {title} [{mode}]",
        display_name=f"{test_id.upper()} {title}",
        category="UDS Test Cases",
        description=objective,
        objective=objective,
        reference_source="UDS Test Cases 3_10-19.pdf; SecurityAccess seed/key reference scripts",
        safety_level="sendkey" if sends_key else "authorized",
        runner_kind="security_access",
        fields=fields,
        disruptive=True,
        validate=validate_security_access_test(test_id),
        execution_plan=lambda params, tid=test_id: security_access_plan(tid, params),
        parser=parse_security_access_response,
        metrics=compute_seed_metrics,
        verdict_rules=verdict_security_behavior,
        evidence_fields=evidence_outputs or ("summary.json", "summary.md", "request_response.json", "transcript.txt", "raw_can_or_uds_log.txt", "metrics.csv"),
        summary_template="security_access_report",
    )


def build_modular_placeholder_tests() -> list[TestDefinition]:
    tests: list[TestDefinition] = []
    for case_def in modular_case_definitions():
        model = case_def.model
        fields = tuple(
            FieldSpec(
                param.key,
                param.label,
                _gui_field_kind(param.kind),
                param.default,
                param.required,
                param.help,
                tuple(Choice(str(choice.get("label", choice.get("value", ""))), str(choice.get("value", ""))) for choice in param.choices),
            )
            for param in case_def.parameters
        )
        runner_label = {
            "diagnostic_service": "DiagnosticServiceRunner",
            "flood": "FloodRunner",
            "robustness": "RobustnessRunner",
            "can_priority_flood": "CanPriorityFloodRunner",
        }.get(case_def.runner_kind, case_def.runner_kind)
        description = "\n".join([
            model.expected_behavior,
            "",
            f"Runner interface: {runner_label}",
            "Warning: this test may erase diagnostic evidence / DTC records. Manual confirmation is required." if model.safety_level == "destructive-diagnostic" else "",
            "Execution status: implemented controlled diagnostic request." if case_def.implemented else "Execution status: placeholder only. No CAN frame is transmitted for this case yet.",
        ]).strip()
        tests.append(TestDefinition(
            id=model.case_id,
            title=model.title,
            display_name=model.title,
            category=model.category,
            description=description,
            runner_kind=case_def.runner_kind if case_def.implemented else "modular_stub",
            fields=fields,
            objective=model.expected_behavior,
            reference_source="Section 11 UDS-26..32 modular framework placeholder",
            safety_level=model.safety_level,
            target_required=True,
            disruptive=(model.safety_level == "destructive-diagnostic"),
            validate=validate_modular_case(case_def),
            evidence_fields=tuple(model.evidence_fields),
            summary_template="modular_placeholder_report",
            risk_property=model.risk_property,
            service_id=model.service_id,
            default_payload=model.default_payload,
            preconditions=tuple(model.preconditions),
            pass_criteria=tuple(model.pass_criteria),
            fail_criteria=tuple(model.fail_criteria),
            runner_interface=case_def.runner_kind,
            safety_guard=case_def.safety_guard.as_dict(),
            evidence_schema=case_def.evidence_schema.as_dict(),
            implemented=case_def.implemented,
            display_id=case_def.display_id,
            canonical_id=case_def.canonical_id,
        ))
    return tests


def _gui_field_kind(kind: str) -> str:
    if kind in {"bool", "boolean"}:
        return "checkbox"
    if kind in {"textarea", "checkbox", "combo", "text"}:
        return kind
    return "text"


def validate_modular_case(case_def: Any) -> Callable[[TargetProfile, dict[str, Any]], dict[str, str]]:
    def validator(_: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
        errors = validate_modular_placeholder(_, params)
        if errors:
            return errors
        try:
            runner = make_modular_runner(case_def.runner_kind)
            guard_data = case_def.safety_guard.as_dict()
            for key in ("max_duration_seconds", "max_frame_rate", "tester_present_enabled", "tester_present_interval_seconds"):
                if key in params:
                    guard_data[key] = params[key]
            errors.update(runner.validate(case_def.model, params, SafetyGuard.from_mapping(guard_data)))
        except ValueError as exc:
            errors["runner"] = str(exc)
        return errors

    return validator


def validate_modular_placeholder(_: TargetProfile, params: dict[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    data: dict[str, Any] = {}
    for key in ("max_duration_seconds", "max_frame_rate", "tester_present_interval_seconds"):
        try:
            data[key] = float(params.get(key, ""))
        except ValueError:
            errors[key] = f"{key} must be numeric"
    data["tester_present_enabled"] = bool(params.get("tester_present_enabled", False))
    if not errors:
        errors.update(validate_safety_guard(SafetyGuard.from_mapping(data)))
    return errors


def build_registry() -> list[TestDefinition]:
    tests = [
        make_sa_test(
            test_id="uds_10",
            title="Guessable Seeds Generated Across Different Sessions",
            mode="cross-session-seed-sampling",
            objective="Determine whether first seeds across consecutive diagnostic session entries repeat, increment, or show low-entropy patterns.",
            fields=(
                SESSION_SUBFN_FLOW, SEED_SUBFN,
                FieldSpec("count", "Sample count", "text", "10", True),
                FieldSpec("session_boundary", "Session boundary", "combo", "default_session", True, choices=(
                    Choice("default_session", "default_session"), Choice("ecu_reset", "ecu_reset"), Choice("s3_wait", "s3_wait"), Choice("none", "none"),
                )),
                FieldSpec("default_session_subfn", "Default session subfunction", "text", "0x01", False, visible_if=lambda p: p.get("session_boundary") == "default_session"),
                FieldSpec("reset_subfn", "ECU reset subfunction", "text", "0x01", False, visible_if=lambda p: p.get("session_boundary") == "ecu_reset"),
                FieldSpec("s3_wait_seconds", "S3 wait seconds", "text", "5.0", False, visible_if=lambda p: p.get("session_boundary") == "s3_wait"),
                FieldSpec("post_boundary_delay", "Post-boundary delay", "text", "0.1", False),
                FieldSpec("reset_wait", "Reset wait", "text", "1.5", False),
                FieldSpec("strict_boundary", "Strict boundary", "checkbox", False),
                FieldSpec("skip_boundary_before_first", "Skip boundary before first", "checkbox", False),
                FieldSpec("stop_on_boundary_error", "Stop on boundary error", "checkbox", True),
                FieldSpec("delay_between_samples", "Delay between samples", "text", "0.2", False),
                FieldSpec("tester_present_enabled", "TesterPresent enabled", "checkbox", False),
            ),
            evidence_outputs=("seed_samples.csv", "seed_counts.csv", "metrics.csv"),
        ),
        make_sa_test(
            test_id="uds_11",
            title="Guessable Seeds Generated Within the Same Session",
            mode="same-session-seed-sampling",
            objective="Determine whether repeated RequestSeed calls inside one active session return repeated or predictable seeds.",
            fields=(
                SESSION_SUBFN_FLOW, SEED_SUBFN,
                FieldSpec("count", "Sample count", "text", "20", True),
                FieldSpec("delay", "Delay", "text", "0.2", False),
                FieldSpec("post_session_delay", "Post-session delay", "text", "0.05", False),
                FieldSpec("tester_present_enabled", "TesterPresent enabled", "checkbox", False),
                FieldSpec("tester_present_interval", "TesterPresent interval", "text", "2.0", False),
                FieldSpec("retry_on_nrc37", "Retry on NRC 0x37", "checkbox", True),
                FieldSpec("nrc37_wait", "NRC 0x37 wait", "text", "1.0", False),
                FieldSpec("nrc37_max_retries", "NRC 0x37 max retries", "text", "3", False),
                FieldSpec("stop_on_session_lost", "Stop on session lost", "checkbox", False),
                FieldSpec("stop_on_sequence_error", "Stop on sequence error", "checkbox", False),
                FieldSpec("count_empty_seed_as_seed", "Count empty seed as seed", "checkbox", False),
            ),
            evidence_outputs=("seed_samples.csv", "seed_counts.csv", "response_counts.csv", "metrics.csv"),
        ),
        make_sa_test(
            test_id="uds_12",
            title="Seed Length Deficiency",
            mode="seed-length-check",
            objective="Verify whether ECU-generated seeds meet minimum and recommended byte-length thresholds.",
            fields=(
                FieldSpec("source_mode", "Source mode", "combo", "collect_same_session", True, choices=(
                    Choice("collect_same_session", "collect_same_session"), Choice("collect_cross_session", "collect_cross_session"), Choice("import_seed_csv", "import_seed_csv"),
                )),
                FieldSpec("session_flow", "Diagnostic session flow", "textarea", "03", False, "Subfunctions only: 03 or 03 02", visible_if=lambda p: p.get("source_mode") in {"collect_same_session", "collect_cross_session"}),
                FieldSpec("seed_subfn", "RequestSeed subfunction", "text", "0x01", False, visible_if=lambda p: p.get("source_mode") in {"collect_same_session", "collect_cross_session"}),
                FieldSpec("count", "Sample count", "text", "10", True, visible_if=lambda p: p.get("source_mode") in {"collect_same_session", "collect_cross_session"}),
                FieldSpec("imported_seed_csv", "Imported seed CSV", "text", "", False, visible_if=lambda p: p.get("source_mode") == "import_seed_csv"),
                FieldSpec("minimum_seed_length_bytes", "Minimum seed length bytes", "text", "4", True),
                FieldSpec("recommended_seed_length_bytes", "Recommended seed length bytes", "text", "8", True),
            ),
            evidence_outputs=("seed_length_report.csv", "metrics.csv"),
        ),
        make_sa_test(
            test_id="uds_13",
            title="Request Sequence Error - SendKey Without Prior RequestSeed",
            mode="key-without-seed",
            objective="Verify that ECU rejects SendKey when no prior RequestSeed exists in the current sequence.",
            sends_key=True,
            fields=(SESSION_SUBFN_FLOW, SEED_SUBFN, KEY_SUBFN) + key_policy_fields(default="format_random") + (FieldSpec("delay_after_session", "Delay after session", "text", "0.05", False),),
        ),
        make_sa_test(
            test_id="uds_14",
            title="Diagnostic Session Timeout - Stale Seed Rejection",
            mode="seed-timeout-key",
            objective="Verify that a seed becomes invalid after S3/session timeout or stale-seed wait.",
            sends_key=True,
            fields=(SESSION_SUBFN_FLOW, SEED_SUBFN, KEY_SUBFN, FieldSpec("stale_seed_wait_seconds", "Stale seed wait seconds", "text", "5.0", True)) + key_policy_fields(default="invalid_bitflip") + (
                FieldSpec("delay_before_sendkey", "Delay before SendKey", "text", "0.05", False),
                FieldSpec("reopen_session_before_sendkey", "Reopen session before SendKey", "checkbox", False),
            ),
        ),
        make_sa_test(
            test_id="uds_15",
            title="Lack of Attempt Limit on Repeated RequestSeed Without SendKey",
            mode="same-session-requestseed-limit",
            objective="Verify whether ECU enforces a request limit or penalty when RequestSeed is repeated without SendKey.",
            fields=(
                SESSION_SUBFN_FLOW, SEED_SUBFN,
                FieldSpec("count", "RequestSeed count", "text", "10", True),
                FieldSpec("delay", "Delay", "text", "0.2", False),
                FieldSpec("tester_present_enabled", "TesterPresent enabled", "checkbox", False),
                FieldSpec("tester_present_interval", "TesterPresent interval", "text", "2.0", False),
                FieldSpec("enforcement_expected_after_count", "Enforcement expected after count", "text", "5", True),
                FieldSpec("retry_on_nrc37", "Retry on NRC 0x37", "checkbox", False),
                FieldSpec("stop_on_sequence_error", "Stop on sequence error", "checkbox", False),
            ),
            evidence_outputs=("requestseed_limit.csv", "response_counts.csv", "metrics.csv"),
        ),
        make_sa_test(
            test_id="uds_16",
            title="Lack of Attempt Limit - Multiple SendKey Against One Seed",
            mode="one-seed-many-keys",
            objective="Verify whether ECU enforces an attempt limit when multiple invalid SendKey requests are sent against one seed.",
            sends_key=True,
            fields=(SESSION_SUBFN_FLOW, SEED_SUBFN, KEY_SUBFN, FieldSpec("attempts", "SendKey attempts", "text", "5", True)) + key_policy_fields(default="invalid_bitflip") + (
                FieldSpec("key_delay", "Key delay", "text", "0.05", False),
                FieldSpec("delay_between_attempts", "Delay between attempts", "text", "0.2", False),
                FieldSpec("stop_on_nrc36", "Stop on NRC 0x36", "checkbox", True),
                FieldSpec("stop_on_nrc37", "Stop on NRC 0x37", "checkbox", True),
            ),
        ),
        make_sa_test(
            test_id="uds_17",
            title="Lack of Attempt Limit Across Multiple Seed-Key Exchanges",
            mode="seed-key-exchange-loop",
            objective="Verify whether failed authentication attempts accumulate across repeated RequestSeed to invalid SendKey cycles.",
            sends_key=True,
            fields=(SESSION_SUBFN_FLOW, SEED_SUBFN, KEY_SUBFN, FieldSpec("exchanges", "Seed-key exchanges", "text", "5", True)) + key_policy_fields(default="invalid_bitflip") + (
                FieldSpec("key_delay", "Key delay", "text", "0.05", False),
                FieldSpec("delay_between_exchanges", "Delay between exchanges", "text", "0.2", False),
                FieldSpec("stop_on_nrc36", "Stop on NRC 0x36", "checkbox", True),
                FieldSpec("stop_on_nrc37", "Stop on NRC 0x37", "checkbox", True),
                FieldSpec("continue_after_invalid_key", "Continue after invalid key", "checkbox", True),
            ),
        ),
        make_sa_test(
            test_id="uds_18",
            title="Seed Response During Penalty Mode",
            mode="penalty-then-seed",
            objective="Verify that ECU refuses RequestSeed while penalty mode is active.",
            sends_key=True,
            fields=(SESSION_SUBFN_FLOW, SEED_SUBFN, KEY_SUBFN, FieldSpec("attempts_to_trigger_penalty", "Attempts to trigger penalty", "text", "5", True)) + key_policy_fields(default="invalid_bitflip") + (
                FieldSpec("penalty_probe_delay", "Penalty probe delay", "text", "0.0", False),
                FieldSpec("stop_when_penalty_seen", "Stop when penalty seen", "checkbox", True),
                FieldSpec("require_penalty_before_probe", "Require penalty before probe", "checkbox", True),
            ),
        ),
        make_sa_test(
            test_id="uds_19",
            title="Multiple Positive Seed Responses for One RequestSeed",
            mode="multi-seed-response",
            objective="Verify that ECU sends exactly one positive seed response for one RequestSeed request.",
            fields=(
                SESSION_SUBFN_FLOW, SEED_SUBFN,
                FieldSpec("capture_window_seconds", "Capture window seconds", "text", "1.0", True),
                FieldSpec("timeout", "First response timeout", "text", "1.0", False),
                FieldSpec("include_same_rxid_only", "Include same RX ID only", "checkbox", True),
                FieldSpec("drain_before_request", "Drain before request", "text", "0.1", False),
            ),
        ),
        TestDefinition(
            id="recon_discovery",
            title="UDS Arbitration ID Discovery",
            category="Fuzzing",
            description="Discover candidate UDS arbitration IDs using CaringCaribou. Known request/response IDs are not required.",
            runner_kind="external",
            target_required=False,
            fields=(
                FieldSpec("arb_bits", "Arbitration bits", "text", "10", True),
                FieldSpec("delay", "Delay", "text", "0.5", True),
            ),
            build_command=command_discovery,
            validate=validate_discovery,
            parse_external=parse_external_discovery,
            evidence_fields=("candidate_arbitration_ids", "raw_output"),
        ),
        TestDefinition(
            id="recon_services",
            title="UDS Services Identification",
            category="Recon",
            description="Identify supported UDS services. CaringCaribou arbitration arguments use tester_tx_id then tester_rx_id.",
            runner_kind="external",
            fields=(),
            build_command=command_services,
            parse_external=parse_services_output,
            evidence_fields=("service_id", "service_name_if_known", "response_raw", "positive_or_negative", "notes"),
        ),
        TestDefinition(
            id="recon_did_dump",
            title="UDS DID Dump",
            category="Recon",
            description="Dump readable DIDs. CaringCaribou arbitration arguments use tester_tx_id then tester_rx_id.",
            runner_kind="external",
            fields=(
                FieldSpec("min_did", "Minimum DID", "text", "0x0000", True),
                FieldSpec("max_did", "Maximum DID", "text", "0xFFFF", True),
                FieldSpec("timeout", "DID timeout", "text", "0.1", True),
            ),
            build_command=command_did_dump,
            validate=validate_did_dump,
            parse_external=parse_did_dump_output,
            evidence_fields=("did_hex", "did_name", "raw_response_hex", "data_hex", "data_length_bytes", "positive_response", "notes"),
        ),
        TestDefinition(
            id="recon_subservices",
            title="UDS Subfunction Identification for Service",
            category="Fuzzing",
            description="Identify valid subfunctions for one UDS service. Optional session flow is sent only when enabled. CaringCaribou arbitration arguments use tester_tx_id then tester_rx_id.",
            runner_kind="external",
            fields=(
                FieldSpec("service_id", "Service ID", "text", "0x10", True, "0x10"),
                FieldSpec("subfunction_range_or_max", "Subfunction max/range", "text", "0xFF", True, "0xFF or 0x01-0x7F"),
                FieldSpec("run_session_flow", "Run session flow before scan", "checkbox", False),
                FieldSpec(
                    "session_flow",
                    "Diagnostic session flow",
                    "textarea",
                    "03",
                    False,
                    "Subfunctions only: 03 or 03 02. Tool sends 10 03 then 10 02 before scan.",
                    visible_if=lambda p: bool(p.get("run_session_flow")),
                ),
            ),
            build_command=command_subservices,
            validate=validate_subservices,
            evidence_fields=("service_id", "subfunction_range_or_max", "session_flow", "raw_output"),
        ),
        TestDefinition(
            id="uds_20",
            title="UDS-20 Missing Pre-conditions for ECU Reset",
            category="UDS Test Cases",
            description="Check whether ECUReset 0x11 is denied when the ECU is placed in a session flow that does not satisfy the required precondition/session.",
            runner_kind="direct",
            disruptive=True,
            fields=(
                FieldSpec("precondition_session_flow", "Required / precondition session flow", "textarea", "03", True, "Reference only. Subfunctions only: 03"),
                FieldSpec("test_session_flow", "Test session flow", "textarea", "01", True, "Executed before ECUReset. Subfunctions only: 01 or 02"),
                FieldSpec(
                    "reset_subfunction",
                    "Reset subfunction",
                    "combo",
                    "0x03",
                    True,
                    choices=(
                        Choice("0x01 hardReset", "0x01"),
                        Choice("0x02 keyOffOnReset", "0x02"),
                        Choice("0x03 softReset", "0x03"),
                    ),
                ),
                FieldSpec("acceptable_nrcs", "Acceptable NRCs", "text", "0x22 0x24 0x31 0x33 0x7E 0x7F", False, visible_if=lambda p: False),
            ),
            build_request=build_uds20_request,
            validate=validate_uds20,
            evidence_fields=("precondition_session_flow", "test_session_flow", "request_hex", "response_hex", "reset_subfunction", "acceptable_nrcs", "verdict", "rationale"),
        ),
        TestDefinition(
            id="uds_21",
            title="UDS-21 Unauthenticated WriteDataByIdentifier 0x2E",
            category="UDS Test Cases",
            description="Check whether a DID can be written without explicit SecurityAccess in the session flow.",
            runner_kind="direct",
            disruptive=True,
            fields=(
                SESSION_FLOW,
                FieldSpec("did_hex", "DID", "text", "0xF190", True, "0xF190"),
                FieldSpec("data_generation", "Write payload", "combo", "random", True, choices=(
                    Choice("random bytes using selected DID length", "random"),
                    Choice("zero bytes using selected DID length", "zero"),
                    Choice("repeat pattern byte using selected DID length", "pattern"),
                    Choice("explicit data_hex", "explicit"),
                )),
                FieldSpec("data_length_bytes", "DID length bytes", "text", "4", True, "Auto-filled from DID catalog / UDS-22 response", visible_if=lambda p: p.get("data_generation") in {"random", "zero", "pattern"}),
                FieldSpec("pattern_byte", "Pattern byte", "text", "0xAA", False, visible_if=lambda p: p.get("data_generation") == "pattern"),
                FieldSpec("data_hex", "Explicit write data", "textarea", "", False, "AA BB CC DD", visible_if=lambda p: p.get("data_generation") == "explicit"),
                FieldSpec("did_length_source", "DID length source", "text", "", False, visible_if=lambda p: False),
                FieldSpec("catalog_length_bytes", "Catalog length bytes", "text", "", False, visible_if=lambda p: False),
                FieldSpec("catalog_message_hex", "Catalog message", "textarea", "", False, visible_if=lambda p: False),
            ),
            build_request=build_uds21_request,
            validate=validate_uds21,
            verdict_rules=verdict_wdbi,
            evidence_fields=("selected_did", "did_length_source", "generated_payload_length", "request_hex", "response_hex", "verdict", "rationale", "security_access_observed_before_target"),
        ),
        TestDefinition(
            id="uds_22",
            title="UDS-22 ReadDataByIdentifier 0x22 without SecurityAccess",
            category="UDS Test Cases",
            description="Check whether sensitive data can be read using service 0x22 without SecurityAccess.",
            runner_kind="direct",
            fields=(
                SESSION_FLOW,
                FieldSpec("did_hex", "DID", "text", "0xF190", True, "0xF190"),
                FieldSpec("did_length_bytes", "Selected DID length", "text", "", False, "Auto-filled from DID catalog when available", enabled_if=lambda p: False),
                FieldSpec("did_message_hex", "Selected DID message", "textarea", "", False, "Auto-filled from DID catalog when available", enabled_if=lambda p: False),
                FieldSpec("did_length_source", "DID length source", "text", "", False, visible_if=lambda p: False),
                FieldSpec("catalog_length_bytes", "Catalog length bytes", "text", "", False, visible_if=lambda p: False),
                FieldSpec("sensitive_did", "Sensitive DID", "checkbox", False),
                FieldSpec("sensitivity_note", "Sensitivity note", "textarea", "", False),
            ),
            build_request=build_uds22_request,
            validate=validate_uds22,
            verdict_rules=verdict_rdbi,
            evidence_fields=("selected_did", "catalog_length", "catalog_message_hex", "request_hex", "response_hex", "verdict", "rationale", "security_access_observed_before_target"),
        ),
        TestDefinition(
            id="uds_23",
            title="UDS-23 Unauthenticated RequestDownload 0x34",
            category="UDS Test Cases",
            description="Checks whether RequestDownload 0x34 is accepted without SecurityAccess. Default mode sends fixed valid-format probe candidates only. No TransferData 0x36 is sent.",
            runner_kind="direct",
            disruptive=True,
            fields=(
                SESSION_FLOW,
                FieldSpec("probe_mode", "Mode", "combo", "security_gate_probe", True, choices=(
                    Choice("Security Gate Probe", "security_gate_probe"),
                    Choice("Advanced Manual Request", "advanced_manual_request"),
                )),
                FieldSpec("target_sid", "Target SID", "text", "0x34", False, enabled_if=lambda p: False),
                FieldSpec("data_format_identifier", "Data format identifier (DFI)", "text", "0x00", True, visible_if=lambda p: p.get("probe_mode") == "advanced_manual_request"),
                FieldSpec("address_length_format_identifier", "Address and length format identifier (ALFI)", "text", "0x44", True, visible_if=lambda p: p.get("probe_mode") == "advanced_manual_request"),
                FieldSpec("memory_address_hex", "Memory address", "text", "00 00 00 00", True, visible_if=lambda p: p.get("probe_mode") == "advanced_manual_request"),
                FieldSpec("memory_size_hex", "Memory size", "text", "00 00 00 01", True, visible_if=lambda p: p.get("probe_mode") == "advanced_manual_request"),
            ),
            build_request=build_memory_security_gate_probe_request,
            validate=validate_memory_security_gate_probe(0x34),
            evidence_fields=("test_case_id", "mode", "target_sid", "session_flow", "dfi", "alfi", "memory_address", "memory_size", "security_access_observed_before_target", "request_hex", "response_hex", "parsed_response", "verdict", "rationale", "transfer_data_sent", "request_transfer_exit_sent"),
        ),
        TestDefinition(
            id="uds_24",
            title="UDS-24 Unauthenticated RequestUpload 0x35",
            category="UDS Test Cases",
            description="Checks whether RequestUpload 0x35 is accepted without SecurityAccess. Default mode sends fixed valid-format probe candidates only. No TransferData 0x36 is sent.",
            runner_kind="direct",
            disruptive=True,
            fields=(
                SESSION_FLOW,
                FieldSpec("probe_mode", "Mode", "combo", "security_gate_probe", True, choices=(
                    Choice("Security Gate Probe", "security_gate_probe"),
                    Choice("Advanced Manual Request", "advanced_manual_request"),
                )),
                FieldSpec("target_sid", "Target SID", "text", "0x35", False, enabled_if=lambda p: False),
                FieldSpec("data_format_identifier", "Data format identifier (DFI)", "text", "0x00", True, visible_if=lambda p: p.get("probe_mode") == "advanced_manual_request"),
                FieldSpec("address_length_format_identifier", "Address and length format identifier (ALFI)", "text", "0x44", True, visible_if=lambda p: p.get("probe_mode") == "advanced_manual_request"),
                FieldSpec("memory_address_hex", "Memory address", "text", "00 00 00 00", True, visible_if=lambda p: p.get("probe_mode") == "advanced_manual_request"),
                FieldSpec("memory_size_hex", "Memory size", "text", "00 00 00 01", True, visible_if=lambda p: p.get("probe_mode") == "advanced_manual_request"),
            ),
            build_request=build_memory_security_gate_probe_request,
            validate=validate_memory_security_gate_probe(0x35),
            evidence_fields=("test_case_id", "mode", "target_sid", "session_flow", "dfi", "alfi", "memory_address", "memory_size", "security_access_observed_before_target", "request_hex", "response_hex", "parsed_response", "verdict", "rationale", "transfer_data_sent", "request_transfer_exit_sent"),
        ),
        TestDefinition(
            id="uds_25",
            title="UDS-25 Unauthenticated CommunicationControl 0x28",
            category="UDS Test Cases",
            description="Check whether CommunicationControl can be started or stopped without SecurityAccess.",
            runner_kind="direct",
            disruptive=True,
            fields=(
                SESSION_FLOW,
                FieldSpec(
                    "control_type",
                    "Control type",
                    "combo",
                    "0x01",
                    True,
                    choices=(
                        Choice("0x01 enableRxAndDisableTx", "0x01"),
                        Choice("0x02 disableRxAndEnableTx", "0x02"),
                        Choice("0x03 disableRxAndTx", "0x03"),
                    ),
                ),
                FieldSpec("communication_type", "Communication type", "text", "0x01", True),
                FieldSpec("auto_restore", "Auto restore 28 00 01", "checkbox", True),
            ),
            build_request=build_uds25_request,
            validate=validate_uds25,
            evidence_fields=("test_case_id", "target_sid", "session_flow", "security_access_observed_before_target", "request_hex", "response_hex", "restore_request_hex", "restore_response_hex", "post_check_result", "verdict", "rationale"),
        ),
    ]
    tests.extend(build_modular_placeholder_tests())
    return tests


class EvidenceWriter:
    def __init__(self, base_dir: Path, test: TestDefinition, target: TargetProfile, params: dict[str, Any]) -> None:
        self._tmp_dir: Optional[tempfile.TemporaryDirectory[str]] = None
        self.save_output = bool(target.save_output)
        if self.save_output:
            self.dir = ensure_dir(base_dir / f"{test.id}_{timestamp()}")
        else:
            self._tmp_dir = tempfile.TemporaryDirectory(prefix=f"{test.id}_")
            self.dir = Path(self._tmp_dir.name)
        self.test = test
        self.target = target
        self.params = params
        self.transcript: list[str] = []
        self.raw_output = ""
        self.command_argv = command_argv_for(test, target, params)
        self.config = {
            "test_id": test.id,
            "title": test.title,
            "category": test.category,
            "description": test.description,
            "objective": test.objective or test.description,
            "reference_source": test.reference_source,
            "safety_level": test.safety_level,
            "risk_property": test.risk_property,
            "service_id": test.service_id,
            "default_payload": test.default_payload,
            "preconditions": list(test.preconditions),
            "pass_criteria": list(test.pass_criteria),
            "fail_criteria": list(test.fail_criteria),
            "evidence_output_fields": list(test.evidence_fields),
            "case_model": test.case_model,
            "runner_interface": test.runner_interface,
            "safety_guard": test.safety_guard,
            "evidence_schema": test.evidence_schema,
            "implemented": test.implemented,
            "display_id": test.display_id or test.id.upper(),
            "canonical_id": test.canonical_id or test.id,
            "command_argv": self.command_argv,
            "command_preview": command_preview_from_argv(self.command_argv) if self.command_argv else "",
            "target_profile": target.as_dict(),
            "input_parameters": params,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        if self.save_output:
            self.write_json("config.json", self.config)

    @property
    def display_dir(self) -> str:
        return str(self.dir) if self.save_output else "<output not saved>"

    def add_transcript(self, line: str) -> None:
        self.transcript.append(line)

    def write_json(self, name: str, data: Any) -> None:
        (self.dir / name).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def write_text(self, name: str, text: str) -> None:
        (self.dir / name).write_text(text, encoding="utf-8")

    def write_csv_rows(self, name: str, rows: list[dict[str, Any]]) -> None:
        path = self.dir / name
        if not rows:
            path.write_text("", encoding="utf-8")
            return
        fields: list[str] = []
        for row in rows:
            for key in row.keys():
                if key not in fields:
                    fields.append(key)
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def finalize(self, summary: dict[str, Any]) -> None:
        if not self.save_output:
            return
        self.write_text("transcript.txt", "\n".join(self.transcript) + ("\n" if self.transcript else ""))
        self.write_text("raw_can_or_uds_log.txt", "\n".join(self.transcript) + ("\n" if self.transcript else ""))
        if self.raw_output:
            self.write_text("raw_output.txt", self.raw_output)
        self.write_json("request_response.json", {
            "request_hex": summary.get("request_hex", ""),
            "response_hex": summary.get("response_hex", ""),
            "observations": summary.get("observations", []),
        })
        if isinstance(summary.get("metrics"), dict) and summary["metrics"]:
            self.write_csv_rows("metrics.csv", [{"metric": key, "value": json.dumps(value) if isinstance(value, (dict, list)) else value} for key, value in summary["metrics"].items()])
        if isinstance(summary.get("seed_samples"), list):
            self.write_csv_rows("seed_samples.csv", summary["seed_samples"])
        if isinstance(summary.get("seed_counts"), dict):
            self.write_csv_rows("seed_counts.csv", [{"seed_hex": key, "count": value} for key, value in summary["seed_counts"].items()])
        if isinstance(summary.get("response_counts"), dict):
            self.write_csv_rows("response_counts.csv", [{"response": key, "count": value} for key, value in summary["response_counts"].items()])
        if isinstance(summary.get("requestseed_limit"), list):
            self.write_csv_rows("requestseed_limit.csv", summary["requestseed_limit"])
        if isinstance(summary.get("seed_length_report"), list):
            self.write_csv_rows("seed_length_report.csv", summary["seed_length_report"])
        self.write_json("summary.json", summary)
        self.write_text("summary.md", self._summary_markdown(summary))

    def _summary_markdown(self, summary: dict[str, Any]) -> str:
        target = summary.get("target_profile", {})
        tester_tx = target.get("tester_tx_id", {})
        tester_rx = target.get("tester_rx_id", {})
        parsed = {
            "response_type": summary.get("response_type", ""),
            "positive_response": summary.get("positive_response", False),
            "negative_response": summary.get("negative_response", False),
            "nrc": summary.get("nrc", ""),
            "nrc_meaning": summary.get("nrc_meaning", ""),
        }
        evidence_files = sorted(p.name for p in self.dir.iterdir())
        if "summary.md" not in evidence_files:
            evidence_files.append("summary.md")
        sections = [
            f"# {summary.get('test_id', self.test.id)} - {summary.get('title', self.test.title)}",
            "",
            f"**Objective:** {summary.get('objective') or self.test.description}",
            "",
            "## Criteria",
            f"- Risk property: {summary.get('risk_property') or self.test.risk_property or '<none>'}",
            f"- Service ID: `{summary.get('service_id') or self.test.service_id or '<none>'}`",
            f"- Default payload: `{summary.get('default_payload') or self.test.default_payload or '<none>'}`",
            "- Pass criteria:",
            *[f"  - {item}" for item in (summary.get("pass_criteria") or list(self.test.pass_criteria) or ["<none>"])],
            "- Fail criteria:",
            *[f"  - {item}" for item in (summary.get("fail_criteria") or list(self.test.fail_criteria) or ["<none>"])],
            "",
            "## Target IDs",
            f"- `tester_tx_id`: `{tester_tx.get('value', '')}` - {tester_tx.get('meaning', '')}",
            f"- `tester_rx_id`: `{tester_rx.get('value', '')}` - {tester_rx.get('meaning', '')}",
            f"- Direct ISO-TP mapping: `txid={target.get('direct_isotp_txid', '')}`, `rxid={target.get('direct_isotp_rxid', '')}`",
            f"- CaringCaribou mapping: first arbitration-ID argument = `{(target.get('caringcaribou_positional_arg_1') or {}).get('value', '')}`, second arbitration-ID argument = `{(target.get('caringcaribou_positional_arg_2') or {}).get('value', '')}`",
            "",
            "## Preconditions / Session Flow",
            *[f"- {item}" for item in (summary.get("preconditions") or list(self.test.preconditions))],
            str(summary.get("session_flow", "") or "<none>"),
            "",
            "## Execution Steps",
            "```json",
            json.dumps(summary.get("execution_steps", []), indent=2),
            "```",
            "",
            "## Request / Response",
            f"- Request sent: `{summary.get('request_hex', '') or '<none>'}`",
            f"- Response received: `{summary.get('response_hex', '') or '<none>'}`",
            "",
            "## Parsed Response",
            "```json",
            json.dumps(parsed, indent=2),
            "```",
            "",
            "## Verdict",
            f"- Verdict: **{summary.get('verdict', '')}**",
            f"- Rationale: {summary.get('rationale', '')}",
            "",
            "## Metrics",
            "```json",
            json.dumps(summary.get("metrics", {}), indent=2),
            "```",
        ]
        did_parse_summary = summary.get("did_parse_summary") or (summary.get("metrics") if self.test.id == "recon_did_dump" else {})
        if isinstance(did_parse_summary, dict) and did_parse_summary:
            sections.extend([
                "",
                "## DID Catalog Normalization",
                f"- Raw rows: {did_parse_summary.get('raw_rows', 0)}",
                f"- Normalized DIDs: {did_parse_summary.get('normalized_dids', 0)}",
                f"- DIDs with known length: {did_parse_summary.get('known_length_dids', 0)}",
                f"- Rows that failed parsing: {did_parse_summary.get('failed_parse_rows', 0)}",
                f"- Parsed catalog CSV: `{did_parse_summary.get('parsed_did_catalog_csv', '')}`",
            ])
        sections.extend([
            "",
            "## Operator Notes",
            str(target.get("operator_notes", "") or "<none>"),
            "",
            "## Parameters",
            "```json",
            json.dumps(summary.get("input_parameters", {}), indent=2),
            "```",
            "",
            "## Command",
            f"- argv: `{json.dumps(summary.get('command_argv', []))}`",
            f"- preview: `{summary.get('command_preview', '')}`",
            "",
            "## Safety Note",
        ])
        safety_notes = summary.get("safety_notes") or []
        if safety_notes:
            sections.extend(f"- {note}" for note in safety_notes)
        else:
            sections.append("- No additional safety notes recorded.")
        sections.extend([
            "",
            "## Limitations",
            "- Dry-run evidence describes the planned requests only and does not claim ECU behavior.",
            "- PASS/OBSERVED classifications are observations from the configured sample size, not cryptographic proof.",
            "- Transport errors, no response, unsupported services, and unexpected SIDs are treated conservatively.",
            "",
            "## Evidence Files Generated",
            *[f"- `{name}`" for name in evidence_files],
        ])
        sections.append("")
        return "\n".join(sections)


class QtConsoleLog:
    def __init__(self, emit: Callable[[str], None], target: TargetProfile) -> None:
        self.emit = emit
        self.target = target
        self.verbose = True
        self.show_process = True
        self.show_can = True

    def process(self, msg: str) -> None:
        self.emit(msg)

    def debug(self, msg: str) -> None:
        self.emit(msg)

    def info(self, msg: str) -> None:
        self.emit(msg)

    def tx_can(self, can_id: int, data: bytes) -> None:
        self.emit(f"CAN TX {can_id:X}#{data.hex().upper()}")

    def rx_can(self, can_id: int, data: bytes) -> None:
        self.emit(f"CAN RX {can_id:X}#{data.hex().upper()}")


class RunWorker(QThread):
    log_line = Signal(str)
    transcript_line = Signal(str)
    parsed_row = Signal(dict)
    finished_run = Signal(dict)

    def __init__(self, test: TestDefinition, target: TargetProfile, params: dict[str, Any], preview: str) -> None:
        super().__init__()
        self.test = test
        self.target = target
        self.params = params
        self.preview = preview
        self._stop_requested = False
        self._process: Optional[subprocess.Popen[str]] = None
        self._opened_buses: list[Any] = []

    def stop(self) -> None:
        self._stop_requested = True
        if self._process and self._process.poll() is None:
            self._process.terminate()

    def run(self) -> None:
        evidence = EvidenceWriter(self.target.output_dir, self.test, self.target, self.params)
        try:
            preflight_errors = self._preflight_errors()
            if preflight_errors:
                summary = self._error_summary(evidence, VERDICT_CONFIG, "; ".join(preflight_errors.values()))
                summary["safety_notes"] = self._safety_notes()
                evidence.finalize(summary)
                summary["evidence_dir"] = evidence.display_dir
                self.finished_run.emit(summary)
                return
            if self.target.dry_run:
                summary = self._dry_run(evidence)
            elif self.test.runner_kind == "external":
                summary = self._run_external(evidence)
            elif self.test.runner_kind == "security_access":
                summary = self._run_security_access(evidence)
            elif self.test.runner_kind == "modular_stub":
                summary = self._run_modular_stub(evidence)
            elif self.test.runner_kind == "diagnostic_service":
                summary = self._run_diagnostic_service(evidence)
            else:
                summary = self._run_direct(evidence)
        except Exception as exc:
            summary = self._error_summary(evidence, VERDICT_CONFIG, f"{type(exc).__name__}: {exc}")
        finally:
            self._shutdown_open_buses()
        summary.setdefault("safety_notes", self._safety_notes())
        evidence.finalize(summary)
        summary["evidence_dir"] = evidence.display_dir
        self.finished_run.emit(summary)

    def _shutdown_open_buses(self) -> None:
        while self._opened_buses:
            bus = self._opened_buses.pop()
            shutdown = getattr(bus, "shutdown", None)
            if not callable(shutdown):
                continue
            try:
                shutdown()
            except Exception as exc:
                self.log_line.emit(f"CAN bus shutdown warning: {type(exc).__name__}: {exc}")

    def _preflight_errors(self) -> dict[str, str]:
        errors: dict[str, str] = {}
        if self.test.validate:
            errors.update(self.test.validate(self.target, self.params))
        elif self.test.build_request:
            try:
                self.test.build_request(self.params)
            except ValueError as exc:
                errors["request"] = str(exc)
        if self.test.runner_kind in {"modular_stub", "diagnostic_service", "flood", "robustness", "can_priority_flood"}:
            try:
                guard = self._effective_safety_guard()
                errors.update(validate_safety_guard(guard))
                if self.test.runner_kind != "modular_stub" and guard.manual_confirm_required and not self.target.dry_run and not self.target.authorized_disruptive:
                    errors["manual_confirm_required"] = "Manual operator authorization is required before running this case."
            except ValueError as exc:
                errors["safety_guard"] = str(exc)
        return errors

    def _safety_notes(self) -> list[str]:
        notes: list[str] = []
        if self.test.disruptive:
            notes.append("This test uses a disruptive UDS service; run only with operator authorization.")
        if self.target.dry_run:
            notes.append("Dry run was enabled; no CAN request or external command was executed.")
        return notes

    def _base_summary(self, evidence: EvidenceWriter) -> dict[str, Any]:
        return {
            "test_id": self.test.id,
            "title": self.test.title,
            "objective": self.test.objective or self.test.description,
            "reference_source": self.test.reference_source,
            "safety_level": self.test.safety_level,
            "risk_property": self.test.risk_property,
            "service_id": self.test.service_id,
            "default_payload": self.test.default_payload,
            "preconditions": list(self.test.preconditions),
            "pass_criteria": list(self.test.pass_criteria),
            "fail_criteria": list(self.test.fail_criteria),
            "evidence_output_fields": list(self.test.evidence_fields),
            "case_model": self.test.case_model,
            "runner_interface": self.test.runner_interface,
            "safety_guard": self._effective_safety_guard().as_dict() if self.test.runner_kind in {"modular_stub", "diagnostic_service", "flood", "robustness", "can_priority_flood"} else self.test.safety_guard,
            "evidence_schema": self.test.evidence_schema,
            "implemented": self.test.implemented,
            "display_id": self.test.display_id or self.test.id.upper(),
            "canonical_id": self.test.canonical_id or self.test.id,
            "command_argv": command_argv_for(self.test, self.target, self.params),
            "command_preview": command_preview_from_argv(command_argv_for(self.test, self.target, self.params)),
            "target_profile": self.target.as_dict(),
            "input_parameters": self.params,
            "diagnostic_session_flow_subfunctions": self.params.get("session_flow", ""),
            "expanded_session_flow_requests": safe_expand_session_flow_hex(self.params.get("session_flow", "")) if "session_flow" in self.params else [],
            "request_hex": "",
            "response_hex": "",
            "response_type": "",
            "positive_response": False,
            "negative_response": False,
            "nrc": "",
            "nrc_meaning": "",
            "verdict": VERDICT_INCONCLUSIVE,
            "rationale": "",
            "timestamp": evidence.config["timestamp"],
            "observations": [],
            "safety_notes": self._safety_notes(),
        }

    def _error_summary(self, evidence: EvidenceWriter, verdict: str, rationale: str) -> dict[str, Any]:
        self.log_line.emit(rationale)
        summary = self._base_summary(evidence)
        summary.update({"verdict": verdict, "rationale": rationale})
        return summary

    def _effective_safety_guard(self) -> SafetyGuard:
        data = dict(self.test.safety_guard or {})
        for key in (
            "max_duration_seconds",
            "max_frame_rate",
            "tester_present_enabled",
            "tester_present_interval_seconds",
        ):
            if key in self.params:
                data[key] = self.params[key]
        return SafetyGuard.from_mapping(data)

    def _run_modular_stub(self, evidence: EvidenceWriter) -> dict[str, Any]:
        case_model = normalize_case_model(self.test.case_model)
        safety_guard = self._effective_safety_guard()
        runner = make_modular_runner(self.test.runner_interface or "diagnostic_service")
        result = runner.run(case_model, self.params, safety_guard)
        plan = result.evidence.get("plan", {}) if isinstance(result.evidence, dict) else {}
        self.log_line.emit(result.rationale)
        evidence.add_transcript("MODULAR FRAMEWORK PLACEHOLDER")
        evidence.add_transcript(json.dumps(plan, indent=2, sort_keys=True))
        summary = self._base_summary(evidence)
        summary.update({
            "verdict": "NOT_IMPLEMENTED / STUB",
            "rationale": result.rationale,
            "modular_runner": self.test.runner_interface,
            "execution_steps": plan.get("steps", []),
            "safety_guard": safety_guard.as_dict(),
            "evidence_schema": self.test.evidence_schema,
            "request_hex": str(self.params.get("request_payload") or ""),
            "response_hex": "",
            "physical_observation_note": str(self.params.get("physical_observation_note") or ""),
            "raw_log_path": "",
        })
        summary["placeholder_evidence_record"] = build_placeholder_evidence_record(
            target_profile=self.target.as_dict(),
            session_flow=str(self.params.get("session_flow") or ""),
            request_payload=str(self.params.get("request_payload") or ""),
            physical_observation_note=str(self.params.get("physical_observation_note") or ""),
            verdict=str(summary["verdict"]),
            raw_log_path="",
        ).as_dict()
        return summary

    def _run_diagnostic_service(self, evidence: EvidenceWriter) -> dict[str, Any]:
        case_model = normalize_case_model(self.test.case_model)
        safety_guard = self._effective_safety_guard()
        runner = make_modular_runner(self.test.runner_interface or "diagnostic_service")
        errors = runner.validate(case_model, self.params, safety_guard)
        if errors:
            return self._error_summary(evidence, VERDICT_CONFIG, json.dumps(errors, sort_keys=True))

        payload = runner.build_payload(case_model, self.params)
        suppress_positive = runner.suppress_positive_response_requested(payload)
        subfunction_meaning = runner.selected_subfunction_meaning(payload)
        observations: list[dict[str, Any]] = []
        for note in self._safety_notes():
            self.log_line.emit(f"Safety note: {note}")
            evidence.add_transcript(f"SAFETY: {note}")
        if case_model.service_id.lower() in {"0x85", "85"}:
            warning = "ControlDTCSetting may affect diagnostic evidence and logging behavior."
            self.log_line.emit(f"Safety note: {warning}")
            evidence.add_transcript(f"SAFETY: {warning}")
        if case_model.service_id.lower() in {"0x14", "14"}:
            warning = "ClearDiagnosticInformation may erase diagnostic evidence / DTC records. Manual confirmation is required."
            self.log_line.emit(f"Safety note: {warning}")
            evidence.add_transcript(f"SAFETY: {warning}")
        evidence.add_transcript("ASSERTION No SecurityAccess seed/key exchange is performed by this runner before the tested request.")

        client = self._open_uds_client()
        session_failure = self._run_session_flow_for_direct_test(client, evidence, observations)
        if session_failure:
            session_failure.update({
                "request_hex": spaced(payload),
                "response_classification": "session_flow_failed",
                "selected_subfunction": str(self.params.get("subfunction") or ""),
                "selected_subfunction_meaning": subfunction_meaning,
                "suppress_positive_response_requested": suppress_positive,
                "raw_payload_override": str(self.params.get("raw_payload_override") or ""),
                "authorization_state_note": str(self.params.get("authorization_state_note") or ""),
                "diagnostic_observation_note": str(self.params.get("diagnostic_observation_note") or ""),
                "dtc_update_effect_confirmed": str(self.params.get("dtc_update_effect_confirmed") or "unknown"),
                "physical_observation_note": str(self.params.get("physical_observation_note") or ""),
                "analyst_note": str(self.params.get("analyst_note") or ""),
            })
            session_failure["evidence_record"] = self._diagnostic_service_evidence_record(
                verdict=str(session_failure.get("verdict") or VERDICT_INCONCLUSIVE),
                request_payload=spaced(payload),
                response_payload="",
                response_classification="session_flow_failed",
                positive_response=False,
                nrc="",
                timeout_or_no_response=False,
                selected_subfunction=runner.selected_subfunction(payload),
                suppress_positive_response_requested=suppress_positive,
                selected_subfunction_meaning=subfunction_meaning,
                selected_group_of_dtc=runner.selected_group_of_dtc(payload),
                group_of_dtc_meaning=runner.group_of_dtc_meaning(payload),
                evidence=evidence,
            )
            return session_failure

        if self._stop_requested:
            return self._error_summary(evidence, VERDICT_INCONCLUSIVE, "Stop requested before diagnostic request was sent.")

        exchange = self._send_uds(client, payload)
        parsed = parse_uds_response(payload, exchange.response, transport_status=exchange.response_type)
        obs = self._observation("control_dtc_setting", payload, exchange.response, parsed, exchange.error)
        observations.append(obs)
        self.parsed_row.emit(obs)
        evidence.add_transcript(f"CONTROL_DTC_SETTING TX {spaced(payload)}")
        evidence.add_transcript(f"CONTROL_DTC_SETTING RX {obs.get('response_hex') or '<no response>'} [{obs.get('response_type')}] {obs.get('note')}")

        result = runner.classify_response(
            positive=parsed.positive_response,
            negative=parsed.negative_response,
            response_type=parsed.response_type,
            nrc=f"0x{parsed.nrc:02X}" if parsed.nrc is not None else "",
            error=exchange.error,
            parameters=self.params,
            suppress_positive_response_requested=suppress_positive,
            service_id=payload[0] if payload else None,
        )
        summary = self._base_summary(evidence)
        summary.update({
            "request_hex": spaced(payload),
            "response_hex": obs.get("response_hex", ""),
            "response_type": obs.get("response_type", ""),
            "response_classification": obs.get("response_type", ""),
            "positive_response": bool(obs.get("positive_response", False)),
            "negative_response": bool(obs.get("negative_response", False)),
            "nrc": obs.get("nrc", ""),
            "nrc_meaning": obs.get("nrc_meaning", ""),
            "suppress_positive_response_requested": suppress_positive,
            "selected_group_of_dtc": runner.selected_group_of_dtc(payload),
            "group_of_dtc_meaning": runner.group_of_dtc_meaning(payload),
            "verdict": result.verdict,
            "rationale": result.rationale,
            "observations": observations,
            "execution_steps": runner.plan(case_model, self.params, safety_guard).as_dict().get("steps", []),
            "selected_subfunction": str(self.params.get("subfunction") or ""),
            "selected_subfunction_meaning": subfunction_meaning,
            "raw_payload_override": str(self.params.get("raw_payload_override") or ""),
            "authorization_state_note": str(self.params.get("authorization_state_note") or ""),
            "dtc_state_before_note": str(self.params.get("dtc_state_before_note") or ""),
            "dtc_state_after_note": str(self.params.get("dtc_state_after_note") or ""),
            "diagnostic_observation_note": str(self.params.get("diagnostic_observation_note") or ""),
            "dtc_update_effect_confirmed": str(self.params.get("dtc_update_effect_confirmed") or "unknown"),
            "dtc_clear_effect_confirmed": str(self.params.get("dtc_clear_effect_confirmed") or "unknown"),
            "physical_observation_note": str(self.params.get("physical_observation_note") or ""),
            "analyst_note": str(self.params.get("analyst_note") or ""),
        })
        summary["evidence_record"] = self._diagnostic_service_evidence_record(
            verdict=result.verdict,
            request_payload=spaced(payload),
            response_payload=str(obs.get("response_hex") or ""),
            response_classification=str(obs.get("response_type") or ""),
            positive_response=bool(obs.get("positive_response", False)),
            nrc=str(obs.get("nrc") or ""),
            timeout_or_no_response=str(obs.get("response_type") or "") in {"timeout", "no_response"},
            selected_subfunction=runner.selected_subfunction(payload),
            suppress_positive_response_requested=suppress_positive,
            selected_subfunction_meaning=subfunction_meaning,
            selected_group_of_dtc=runner.selected_group_of_dtc(payload),
            group_of_dtc_meaning=runner.group_of_dtc_meaning(payload),
            evidence=evidence,
        )
        return summary

    def _diagnostic_service_evidence_record(
        self,
        *,
        verdict: str,
        request_payload: str,
        response_payload: str,
        response_classification: str,
        positive_response: bool,
        nrc: str,
        timeout_or_no_response: bool,
        evidence: EvidenceWriter,
        selected_subfunction: str = "",
        suppress_positive_response_requested: bool = False,
        selected_subfunction_meaning: str = "",
        selected_group_of_dtc: str = "",
        group_of_dtc_meaning: str = "",
    ) -> dict[str, Any]:
        return build_evidence_record(
            display_id=self.test.display_id or self.test.id.upper(),
            canonical_id=self.test.canonical_id or self.test.id,
            target_profile=self.target.as_dict(),
            session_flow=str(self.params.get("session_flow") or ""),
            selected_subfunction=selected_subfunction or str(self.params.get("subfunction") or ""),
            selected_subfunction_meaning=selected_subfunction_meaning,
            suppress_positive_response_requested=suppress_positive_response_requested,
            selected_group_of_dtc=selected_group_of_dtc,
            group_of_dtc_meaning=group_of_dtc_meaning,
            raw_payload_override=str(self.params.get("raw_payload_override") or ""),
            request_payload=request_payload,
            response_payload=response_payload,
            response_classification=response_classification,
            positive_response=positive_response,
            nrc=nrc,
            timeout_or_no_response=timeout_or_no_response,
            authorization_state_note=str(self.params.get("authorization_state_note") or ""),
            dtc_state_before_note=str(self.params.get("dtc_state_before_note") or ""),
            dtc_state_after_note=str(self.params.get("dtc_state_after_note") or ""),
            diagnostic_observation_note=str(self.params.get("diagnostic_observation_note") or ""),
            dtc_update_effect_confirmed=str(self.params.get("dtc_update_effect_confirmed") or "unknown"),
            dtc_clear_effect_confirmed=str(self.params.get("dtc_clear_effect_confirmed") or "unknown"),
            physical_observation_note=str(self.params.get("physical_observation_note") or ""),
            analyst_note=str(self.params.get("analyst_note") or ""),
            verdict=verdict,
            raw_log_path=str(evidence.dir / "raw_can_or_uds_log.txt") if evidence.save_output else "",
        ).as_dict()

    def _dry_run(self, evidence: EvidenceWriter) -> dict[str, Any]:
        self.log_line.emit("Dry run only. No CAN request or external command was executed.")
        for note in self._safety_notes():
            self.log_line.emit(f"Safety note: {note}")
        self.log_line.emit(self.preview)
        evidence.add_transcript(f"DRY RUN: {self.preview}")
        summary = self._base_summary(evidence)
        request = b""
        if self.test.runner_kind == "security_access" and self.test.execution_plan:
            plan = self.test.execution_plan(self.params)
            summary["execution_steps"] = plan
            evidence.add_transcript("PLANNED SECURITYACCESS STEPS")
            for step in plan:
                evidence.add_transcript(json.dumps(step, sort_keys=True))
            first_request = next((step.get("request_hex", "") for step in plan if step.get("request_hex")), "")
            summary["request_hex"] = first_request
            summary["metrics"] = {"planned_steps": len(plan), "planned_loop_count": len([s for s in plan if "request_seed" in str(s.get("step", ""))])}
            summary["seed_samples"] = []
            summary["seed_counts"] = {}
            summary["response_counts"] = {}
            if self.test.id == "uds_12":
                summary["seed_length_report"] = []
            if self.test.id == "uds_15":
                summary["requestseed_limit"] = []
        elif self.test.runner_kind == "diagnostic_service":
            case_model = normalize_case_model(self.test.case_model)
            guard = self._effective_safety_guard()
            runner = make_modular_runner(self.test.runner_interface or "diagnostic_service")
            plan = runner.plan(case_model, self.params, guard).as_dict()
            request_payload = ""
            suppress_positive = False
            subfunction_meaning = ""
            selected_subfunction = ""
            selected_group_of_dtc = ""
            group_of_dtc_meaning = ""
            try:
                payload_bytes = runner.build_payload(case_model, self.params)
                request_payload = spaced(payload_bytes)
                selected_subfunction = runner.selected_subfunction(payload_bytes)
                suppress_positive = runner.suppress_positive_response_requested(payload_bytes)
                subfunction_meaning = runner.selected_subfunction_meaning(payload_bytes)
                selected_group_of_dtc = runner.selected_group_of_dtc(payload_bytes)
                group_of_dtc_meaning = runner.group_of_dtc_meaning(payload_bytes)
            except ValueError as exc:
                request_payload = f"<invalid: {exc}>"
            summary["execution_steps"] = plan.get("steps", [])
            summary["request_hex"] = request_payload
            summary["selected_subfunction"] = selected_subfunction or str(self.params.get("subfunction") or "")
            summary["selected_subfunction_meaning"] = subfunction_meaning
            summary["suppress_positive_response_requested"] = suppress_positive
            summary["selected_group_of_dtc"] = selected_group_of_dtc
            summary["group_of_dtc_meaning"] = group_of_dtc_meaning
            summary["raw_payload_override"] = str(self.params.get("raw_payload_override") or "")
            summary["authorization_state_note"] = str(self.params.get("authorization_state_note") or "")
            summary["dtc_state_before_note"] = str(self.params.get("dtc_state_before_note") or "")
            summary["dtc_state_after_note"] = str(self.params.get("dtc_state_after_note") or "")
            summary["diagnostic_observation_note"] = str(self.params.get("diagnostic_observation_note") or "")
            summary["dtc_update_effect_confirmed"] = str(self.params.get("dtc_update_effect_confirmed") or "unknown")
            summary["dtc_clear_effect_confirmed"] = str(self.params.get("dtc_clear_effect_confirmed") or "unknown")
            summary["physical_observation_note"] = str(self.params.get("physical_observation_note") or "")
            summary["analyst_note"] = str(self.params.get("analyst_note") or "")
            summary["evidence_record"] = self._diagnostic_service_evidence_record(
                verdict="DRY_RUN / NOT_EXECUTED",
                request_payload=request_payload,
                response_payload="",
                response_classification="dry_run",
                positive_response=False,
                nrc="",
                timeout_or_no_response=False,
                selected_subfunction=selected_subfunction,
                suppress_positive_response_requested=suppress_positive,
                selected_subfunction_meaning=subfunction_meaning,
                selected_group_of_dtc=selected_group_of_dtc,
                group_of_dtc_meaning=group_of_dtc_meaning,
                evidence=evidence,
            )
        elif self.test.id in {"uds_23", "uds_24"}:
            service_id = 0x34 if self.test.id == "uds_23" else 0x35
            candidates = memory_transfer_request_candidates(service_id, self.params)
            mode = get_memory_transfer_mode(self.params)
            summary["execution_steps"] = [{"step": "session_flow", "request_hex": req} for req in safe_expand_session_flow_hex(self.params.get("session_flow", ""))]
            summary["execution_steps"].extend({
                "step": f"{mode}_{idx + 1}",
                "request_hex": spaced(candidate.request),
                "annotation": candidate.annotation,
            } for idx, candidate in enumerate(candidates))
            summary["request_hex"] = spaced(candidates[0].request)
            summary["test_case_id"] = self.test.id
            summary["mode"] = "Advanced Manual Request" if mode == "advanced_manual_request" else "Security Gate Probe"
            summary["target_sid"] = f"0x{service_id:02X}"
            summary["parsed_response"] = {}
            summary["security_access_observed_before_target"] = False
            summary["security_access_absence_statement"] = "No SecurityAccess seed/key exchange was performed before the tested request."
            summary["transfer_data_sent"] = False
            summary["transfer_data_statement"] = "TransferData 0x36 was not sent."
            summary["request_transfer_exit_sent"] = False
            summary["request_transfer_exit_statement"] = "RequestTransferExit 0x37 was not sent."
            summary.update(self._memory_security_gate_evidence(candidates[0]))
        elif self.test.id == "uds_25":
            request = build_uds25_request(self.params)
            restore = build_communication_control_restore_request(self.params)
            summary["execution_steps"] = [{"step": "session_flow", "request_hex": req} for req in safe_expand_session_flow_hex(self.params.get("session_flow", ""))]
            summary["execution_steps"].append({"step": "communication_control_target", "request_hex": spaced(request)})
            if self.params.get("auto_restore", True):
                summary["execution_steps"].append({"step": "communication_control_restore", "request_hex": spaced(restore)})
            summary["request_hex"] = spaced(request)
            summary["test_case_id"] = self.test.id
            summary["restore_request_hex"] = spaced(restore)
            summary["target_sid"] = "0x28"
            summary["parsed_response"] = {}
            summary["security_access_observed_before_target"] = False
            summary["security_access_absence_statement"] = "No SecurityAccess seed/key exchange was performed before the tested request."
            summary["post_check_result"] = "dry_run_not_executed"
        elif self.test.build_request:
            request = self.test.build_request(self.params)
            summary["request_hex"] = spaced(request)
            if self.test.id == "uds_21":
                summary["did_hex"] = f"0x{request[1]:02X}{request[2]:02X}" if len(request) >= 3 else ""
                summary["did_length_bytes"] = len(request[3:]) if len(request) > 3 else 0
                summary["generated_or_supplied_data_hex"] = spaced(request[3:]) if len(request) > 3 else ""
            if self.test.id == "uds_22":
                summary["did_hex"] = f"0x{request[1]:02X}{request[2]:02X}" if len(request) >= 3 else ""
                summary["did_length_bytes"] = self.params.get("did_length_bytes", "")
                summary["did_message_hex"] = self.params.get("did_message_hex", "")
        summary.update({
            "response_type": "dry_run",
            "verdict": "DRY_RUN / NOT_EXECUTED",
            "rationale": "Dry run completed; no ECU response was collected.",
        })
        return summary

    def _run_external(self, evidence: EvidenceWriter) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        if self.test.id == "recon_subservices" and self.params.get("run_session_flow"):
            for note in self._safety_notes():
                self.log_line.emit(f"Safety note: {note}")
                evidence.add_transcript(f"SAFETY: {note}")
            ok, flow_obs = self._execute_session_flow()
            observations.extend(flow_obs)
            if not ok:
                summary = self._base_summary(evidence)
                summary["observations"] = observations
                summary["verdict"] = VERDICT_INCONCLUSIVE
                summary["rationale"] = "Session flow failed before subfunction scan; scan was not started."
                return summary

        if not self.test.build_command:
            return self._error_summary(evidence, VERDICT_CONFIG, "No external command builder is registered.")
        cmd = command_argv_for(self.test, self.target, self.params)
        self.log_line.emit("argv: " + json.dumps(cmd))
        self.log_line.emit("$ " + command_preview_from_argv(cmd))
        evidence.add_transcript("ARGV " + json.dumps(cmd))
        evidence.add_transcript("$ " + command_preview_from_argv(cmd))
        if evidence.save_output:
            evidence.write_text("command.txt", "\n".join([
                f"timestamp: {evidence.config['timestamp']}",
                f"tool_function: {self.test.id}",
                f"title: {self.test.title}",
                f"command_line: {command_preview_from_argv(cmd)}",
                f"argv: {json.dumps(cmd)}",
                f"interface: {self.target.interface}",
                f"channel: {self.target.channel}",
                f"tester_tx_id: {format_arbid(self.target.tester_tx_id) if self.test.target_required else ''}",
                f"tester_rx_id: {format_arbid(self.target.tester_rx_id) if self.test.target_required else ''}",
                "",
            ]))
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                cwd=str(ROOT),
            )
        except FileNotFoundError:
            return self._error_summary(evidence, VERDICT_CONFIG, "caringcaribou executable was not found in PATH.")

        stdout, stderr = self._process.communicate()
        if self._stop_requested and self._process.poll() is None:
            self._process.terminate()
        stdout_lines = stdout.splitlines()
        stderr_lines = stderr.splitlines()
        for line in stdout_lines:
            self.log_line.emit(line)
            evidence.add_transcript(line)
        for line in stderr_lines:
            self.log_line.emit(line)
            evidence.add_transcript(f"STDERR {line}")
        return_code = self._process.returncode
        output = stdout + (("\n" if stdout and stderr else "") + stderr if stderr else "")
        evidence.raw_output = output
        if evidence.save_output:
            evidence.write_text("stdout.log", stdout)
            evidence.write_text("stderr.log", stderr)
            evidence.write_text("raw_output.log", output)
        parsed_extra: dict[str, Any] = {}
        if self.test.parse_external:
            parsed_extra = self.test.parse_external(output, evidence.dir)
            self._emit_external_rows(parsed_extra)
        summary = self._base_summary(evidence)
        summary["observations"] = observations
        summary["verdict"] = VERDICT_INCONCLUSIVE if return_code == 0 else VERDICT_CONFIG
        summary["rationale"] = (
            "Reconnaissance output collected; review parsed artifacts and raw output."
            if return_code == 0
            else f"External command exited with status {return_code}."
        )
        summary.update(parsed_extra)
        if isinstance(parsed_extra.get("did_parse_summary"), dict):
            summary["metrics"] = parsed_extra["did_parse_summary"]
        return summary

    def _emit_external_rows(self, parsed_extra: dict[str, Any]) -> None:
        for key in ("candidate_arbitration_ids", "supported_services", "did_catalog"):
            value = parsed_extra.get(key)
            if isinstance(value, list):
                for row in value:
                    if isinstance(row, dict):
                        self.parsed_row.emit(row)
                    else:
                        self.parsed_row.emit({key: str(row)})

    def _run_security_access(self, evidence: EvidenceWriter) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        seed_rows: list[dict[str, Any]] = []
        response_counts: Counter[str] = Counter()
        for note in self._safety_notes():
            self.log_line.emit(f"Safety note: {note}")
            evidence.add_transcript(f"SAFETY: {note}")
        test_id = self.test.id
        execution_steps = self.test.execution_plan(self.params) if self.test.execution_plan else []
        if test_id == "uds_12" and self.params.get("source_mode") == "import_seed_csv":
            seed_lengths = load_seed_lengths_from_csv(Path(str(self.params.get("imported_seed_csv") or "")))
            metrics = compute_seed_length_metrics(seed_lengths, int_param(self.params, "minimum_seed_length_bytes", 4))
            verdict, rationale = verdict_seed_length(metrics, self.params)
            summary = self._base_summary(evidence)
            summary.update({
                "verdict": verdict,
                "rationale": rationale,
                "execution_steps": execution_steps,
                "metrics": metrics,
                "seed_length_report": [{"seed_length": k, "count": v} for k, v in metrics.get("seed_length_distribution", {}).items()],
            })
            return summary
        client = self._open_uds_client()

        def send(step: str, payload: bytes, *, security: bool = False) -> dict[str, Any]:
            exchange = self._send_uds(client, payload)
            parsed = parse_uds_response(payload, exchange.response, transport_status=exchange.response_type)
            obs = self._observation(step, payload, exchange.response, parsed, exchange.error)
            if security:
                obs.update(parse_security_access_response(payload, exchange.response, transport_status=exchange.response_type))
            observations.append(obs)
            response_counts[str(obs.get("response_type") or "unknown")] += 1
            if obs.get("nrc"):
                response_counts[f"nrc:{obs['nrc']}:{obs.get('nrc_meaning', '')}"] += 1
            self.parsed_row.emit(obs)
            evidence.add_transcript(f"{step} TX {spaced(payload)}")
            evidence.add_transcript(f"{step} RX {obs.get('response_hex') or '<none>'} [{obs.get('response_type')}] {obs.get('note')}")
            return obs

        def open_sessions() -> bool:
            for subfn in parse_session_subfunctions(self.params.get("session_flow", "")):
                obs = send(f"session_0x{subfn:02X}", bytes([0x10, subfn]))
                if obs.get("negative_response") and obs.get("nrc") in {"0x7E", "0x7F"}:
                    return False
                if obs.get("response_type") in {"timeout", "transport_error", "unexpected_response_sid", "malformed_response"}:
                    return False
                time.sleep(self.target.delay)
            return True

        def finish(verdict: str, rationale: str, metrics: Optional[dict[str, Any]] = None) -> dict[str, Any]:
            metrics = metrics or {}
            first_test_obs = next((o for o in observations if str(o.get("step", "")).startswith(("sample", "request_seed", "send_key", "single", "exchange", "penalty"))), observations[-1] if observations else {})
            summary = self._base_summary(evidence)
            summary.update({
                "request_hex": first_test_obs.get("request_hex", ""),
                "response_hex": first_test_obs.get("response_hex", ""),
                "response_type": first_test_obs.get("response_type", ""),
                "positive_response": bool(first_test_obs.get("positive_response", False)),
                "negative_response": bool(first_test_obs.get("negative_response", False)),
                "nrc": first_test_obs.get("nrc", ""),
                "nrc_meaning": first_test_obs.get("nrc_meaning", ""),
                "verdict": verdict,
                "rationale": rationale,
                "observations": observations,
                "execution_steps": execution_steps,
                "metrics": metrics,
                "seed_samples": seed_rows,
                "seed_counts": metrics.get("seed_counts", {}),
                "response_counts": dict(response_counts),
            })
            if test_id == "uds_12":
                summary["seed_length_report"] = [{"seed_length": k, "count": v} for k, v in (summary["metrics"].get("seed_length_distribution") or {}).items()]
            if test_id == "uds_15":
                summary["requestseed_limit"] = observations
            return summary

        def session_failure_verdict() -> tuple[str, str]:
            if any(o.get("nrc") in {"0x7E", "0x7F"} for o in observations):
                return "NOT TESTABLE", "Configured diagnostic session is not supported; SecurityAccess test request was not sent."
            return VERDICT_INCONCLUSIVE, "Session flow did not complete positively; SecurityAccess test request was not sent."

        def request_seed(step: str) -> dict[str, Any]:
            obs = send(step, bytes([0x27, security_seed_subfn(self.params)]), security=True)
            if obs.get("security_response_kind") in {"positive_seed", "positive_empty_seed"}:
                seed_rows.append(obs)
            return obs

        def send_key(step: str, seed: Optional[bytes]) -> dict[str, Any]:
            key, note = build_key_bytes(self.params, seed=seed)
            self.log_line.emit(f"{step} key policy: {self.params.get('key_policy')} ({note})")
            return send(step, bytes([0x27, security_key_subfn(self.params)]) + key, security=True)

        if test_id == "uds_10":
            count = int_param(self.params, "count", 10)
            boundary = str(self.params.get("session_boundary") or "default_session")
            for i in range(count):
                if not (i == 0 and self.params.get("skip_boundary_before_first")):
                    if boundary == "default_session":
                        send("boundary_default_session", bytes([0x10, parse_hex_byte(self.params.get("default_session_subfn", "0x01"), "default_session_subfn")]))
                    elif boundary == "ecu_reset":
                        send("boundary_ecu_reset", bytes([0x11, parse_hex_byte(self.params.get("reset_subfn", "0x01"), "reset_subfn")]))
                        time.sleep(float_param(self.params, "reset_wait", 1.5))
                    elif boundary == "s3_wait":
                        time.sleep(float_param(self.params, "s3_wait_seconds", 5.0))
                    time.sleep(float_param(self.params, "post_boundary_delay", 0.1))
                if not open_sessions():
                    if self.params.get("stop_on_boundary_error"):
                        break
                    continue
                request_seed(f"sample_{i + 1}_request_seed")
                time.sleep(float_param(self.params, "delay_between_samples", 0.2))
            metrics = compute_seed_metrics(seed_rows, count)
            verdict, rationale = verdict_seed_sampling(test_id, metrics)
        elif test_id in {"uds_11", "uds_15"}:
            count = int_param(self.params, "count", 20 if test_id == "uds_11" else 10)
            if not open_sessions():
                verdict, rationale = session_failure_verdict()
                return finish(verdict, rationale, {"requested_samples": count, "positive_seed_samples": 0})
            for i in range(count):
                obs = request_seed(f"request_seed_{i + 1}")
                if obs.get("nrc") == "0x37" and self.params.get("retry_on_nrc37"):
                    for retry in range(int_param(self.params, "nrc37_max_retries", 3)):
                        time.sleep(float_param(self.params, "nrc37_wait", 1.0))
                        obs = request_seed(f"request_seed_{i + 1}_nrc37_retry_{retry + 1}")
                        if obs.get("nrc") != "0x37":
                            break
                if obs.get("nrc") == "0x24" and self.params.get("stop_on_sequence_error"):
                    break
                if obs.get("nrc") in {"0x7E", "0x7F"} and self.params.get("stop_on_session_lost"):
                    break
                time.sleep(float_param(self.params, "delay", 0.2))
            metrics = compute_seed_metrics(seed_rows, count)
            metrics.update({
                "executed_samples": len([o for o in observations if "request_seed" in str(o.get("step"))]),
                "empty_seed_positive_responses": len([o for o in observations if o.get("security_response_kind") == "positive_empty_seed"]),
                "non_seed_response_counts": dict(response_counts),
                "total_response_pending_0x78": response_counts.get("nrc:0x78:responsePending", 0),
                "total_drained_stale_frames": 0,
            })
            if test_id == "uds_15":
                threshold = int_param(self.params, "enforcement_expected_after_count", 5)
                metrics.update({
                    "positive_seed_count": metrics.get("positive_seed_samples", 0),
                    "nrc36_count": response_counts.get("nrc:0x36:exceededNumberOfAttempts", 0),
                    "nrc37_count": response_counts.get("nrc:0x37:requiredTimeDelayNotExpired", 0),
                    "nrc24_count": response_counts.get("nrc:0x24:requestSequenceError", 0),
                    "enforcement_nrc_seen": bool(response_counts.get("nrc:0x36:exceededNumberOfAttempts", 0) or response_counts.get("nrc:0x37:requiredTimeDelayNotExpired", 0)),
                    "first_enforcement_at_attempt": next((idx + 1 for idx, o in enumerate(observations) if o.get("nrc") in {"0x36", "0x37"}), None),
                    "continuous_seed_after_threshold": metrics.get("positive_seed_samples", 0) >= threshold and not (response_counts.get("nrc:0x36:exceededNumberOfAttempts", 0) or response_counts.get("nrc:0x37:requiredTimeDelayNotExpired", 0)),
                })
                verdict, rationale = verdict_requestseed_limit(metrics, self.params)
            else:
                verdict, rationale = verdict_seed_sampling(test_id, metrics)
                if response_counts.get("nrc:0x24:requestSequenceError", 0):
                    verdict, rationale = "REVIEW", "ECU returned NRC 0x24 after repeated RequestSeed; it may require SendKey before another seed."
                elif response_counts.get("nrc:0x37:requiredTimeDelayNotExpired", 0):
                    verdict, rationale = "REVIEW/PENALTY OBSERVED", "ECU returned NRC 0x37 during repeated RequestSeed sampling."
        elif test_id == "uds_12":
            seed_lengths: list[int] = []
            count = int_param(self.params, "count", 10)
            if self.params.get("source_mode") == "collect_cross_session":
                for i in range(count):
                    send("length_boundary_default_session", bytes([0x10, 0x01]))
                    if not open_sessions():
                        verdict, rationale = session_failure_verdict()
                        return finish(verdict, rationale, {"total_seed_samples": len(seed_rows)})
                    request_seed(f"length_cross_sample_{i + 1}")
                    time.sleep(0.05)
            else:
                if not open_sessions():
                    verdict, rationale = session_failure_verdict()
                    return finish(verdict, rationale, {"total_seed_samples": 0})
                for i in range(count):
                    request_seed(f"length_sample_{i + 1}")
                    time.sleep(0.05)
            seed_lengths = [int(row.get("seed_length") or 0) for row in seed_rows]
            minimum = int_param(self.params, "minimum_seed_length_bytes", 4)
            metrics = compute_seed_length_metrics(seed_lengths, minimum)
            verdict, rationale = verdict_seed_length(metrics, self.params)
        else:
            if not open_sessions():
                verdict, rationale = session_failure_verdict()
                return finish(verdict, rationale)
            metrics: dict[str, Any] = {}
            seed: Optional[bytes] = None
            if test_id == "uds_13":
                send_key("send_key_without_seed", None)
            elif test_id == "uds_14":
                seed_obs = request_seed("request_seed_before_stale_wait")
                seed = parse_hex_payload(seed_obs.get("seed_hex", ""), name="seed", allow_empty=True) if seed_obs.get("seed_hex") else None
                metrics["seed_collected"] = bool(seed)
                time.sleep(float_param(self.params, "stale_seed_wait_seconds", 5.0))
                if self.params.get("reopen_session_before_sendkey"):
                    open_sessions()
                time.sleep(float_param(self.params, "delay_before_sendkey", 0.05))
                send_key("send_key_after_stale_wait", seed)
            elif test_id == "uds_16":
                seed_obs = request_seed("request_seed_once")
                seed = parse_hex_payload(seed_obs.get("seed_hex", ""), name="seed", allow_empty=True) if seed_obs.get("seed_hex") else None
                for i in range(int_param(self.params, "attempts", 5)):
                    obs = send_key(f"send_key_attempt_{i + 1}", seed)
                    if obs.get("nrc") == "0x36" and self.params.get("stop_on_nrc36"):
                        break
                    if obs.get("nrc") == "0x37" and self.params.get("stop_on_nrc37"):
                        break
                    time.sleep(float_param(self.params, "delay_between_attempts", 0.2))
            elif test_id == "uds_17":
                for i in range(int_param(self.params, "exchanges", 5)):
                    seed_obs = request_seed(f"exchange_{i + 1}_request_seed")
                    seed = parse_hex_payload(seed_obs.get("seed_hex", ""), name="seed", allow_empty=True) if seed_obs.get("seed_hex") else None
                    obs = send_key(f"exchange_{i + 1}_send_key", seed)
                    if obs.get("nrc") == "0x36" and self.params.get("stop_on_nrc36"):
                        break
                    if obs.get("nrc") == "0x37" and self.params.get("stop_on_nrc37"):
                        break
                    time.sleep(float_param(self.params, "delay_between_exchanges", 0.2))
            elif test_id == "uds_18":
                penalty = False
                for i in range(int_param(self.params, "attempts_to_trigger_penalty", 5)):
                    seed_obs = request_seed(f"penalty_trigger_{i + 1}_request_seed")
                    seed = parse_hex_payload(seed_obs.get("seed_hex", ""), name="seed", allow_empty=True) if seed_obs.get("seed_hex") else None
                    obs = send_key(f"penalty_trigger_{i + 1}_send_key", seed)
                    penalty = obs.get("nrc") in {"0x36", "0x37"}
                    if penalty and self.params.get("stop_when_penalty_seen"):
                        break
                metrics["penalty_triggered"] = penalty
                if penalty or not self.params.get("require_penalty_before_probe"):
                    time.sleep(float_param(self.params, "penalty_probe_delay", 0.0))
                    probe = request_seed("penalty_mode_request_seed_probe")
                    metrics["probe_nrc37"] = probe.get("nrc") == "0x37"
                    metrics["probe_positive_seed"] = probe.get("security_response_kind") == "positive_seed"
            elif test_id == "uds_19":
                first = request_seed("single_request_seed")
                extras: list[dict[str, Any]] = []
                deadline = time.monotonic() + float_param(self.params, "capture_window_seconds", 1.0)
                while time.monotonic() < deadline:
                    extra_exchange = self._recv_extra_uds(client, max(0.01, min(0.1, deadline - time.monotonic())))
                    if extra_exchange.response is None:
                        continue
                    extra_parsed = parse_security_access_response(bytes([0x27, security_seed_subfn(self.params)]), extra_exchange.response, transport_status=extra_exchange.response_type)
                    extra_parsed["step"] = f"extra_seed_response_{len(extras) + 1}"
                    extras.append(extra_parsed)
                    observations.append(extra_parsed)
                    self.parsed_row.emit(extra_parsed)
                metrics["total_positive_seed_responses"] = int(first.get("security_response_kind") == "positive_seed") + len([e for e in extras if e.get("security_response_kind") == "positive_seed"])
                metrics["first_response"] = first.get("response_hex", "")
                metrics["extra_seed_response_count"] = len([e for e in extras if e.get("security_response_kind") == "positive_seed"])
                metrics["extra_seed_responses"] = [e.get("response_hex") for e in extras if e.get("security_response_kind") == "positive_seed"]
                metrics["unrelated_frame_count"] = len([e for e in extras if e.get("security_response_kind") != "positive_seed"])
                metrics["capture_window_seconds"] = float_param(self.params, "capture_window_seconds", 1.0)
            metrics.update({
                "invalid_key_count": len([o for o in observations if "send_key" in str(o.get("step"))]),
                "nrc35_count": len([o for o in observations if o.get("nrc") == "0x35"]),
                "nrc36_count": len([o for o in observations if o.get("nrc") == "0x36"]),
                "nrc37_count": len([o for o in observations if o.get("nrc") == "0x37"]),
                "first_penalty_attempt": next((idx + 1 for idx, o in enumerate(observations) if o.get("nrc") in {"0x36", "0x37"}), None),
                "positive_unlock_seen": any(o.get("security_response_kind") == "positive_sendkey" for o in observations),
                "positive_seed_count": len([o for o in observations if o.get("security_response_kind") == "positive_seed"]),
                "total_exchanges": int_param(self.params, "exchanges", 0) if test_id == "uds_17" else 0,
                "invalid_key_nrc35_count": len([o for o in observations if o.get("nrc") == "0x35"]),
                "continuous_no_penalty_after_threshold": test_id == "uds_17" and not any(o.get("nrc") in {"0x36", "0x37"} for o in observations),
            })
            verdict, rationale = verdict_security_behavior(test_id, observations, self.params, metrics)

        return finish(verdict, rationale, metrics)

    def _execute_session_flow(self) -> tuple[bool, list[dict[str, Any]]]:
        flow = expand_session_flow_requests(self.params.get("session_flow", ""))
        if not flow:
            return True, []
        observations: list[dict[str, Any]] = []
        client = self._open_uds_client()
        for payload in flow:
            if self._stop_requested:
                return False, observations
            exchange = self._send_uds(client, payload)
            parsed = parse_uds_response(payload, exchange.response, transport_status=exchange.response_type)
            obs = {
                "step": "session_flow",
                "request_hex": spaced(payload),
                "response_hex": spaced(exchange.response) if exchange.response else "",
                "response_type": parsed.response_type,
                "positive_response": parsed.positive_response,
                "negative_response": parsed.negative_response,
                "nrc": f"0x{parsed.nrc:02X}" if parsed.nrc is not None else "",
                "nrc_meaning": parsed.nrc_meaning,
                "note": exchange.error or parsed.note,
            }
            observations.append(obs)
            self.parsed_row.emit(obs)
            if not parsed.positive_response:
                return False, observations
            time.sleep(self.target.delay)
        return True, observations

    def _run_session_flow_for_direct_test(self, client: Any, evidence: EvidenceWriter, observations: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
        for payload in expand_session_flow_requests(self.params.get("session_flow", "")):
            exchange = self._send_uds(client, payload)
            parsed = parse_uds_response(payload, exchange.response, transport_status=exchange.response_type)
            obs = self._observation("session_flow", payload, exchange.response, parsed, exchange.error)
            observations.append(obs)
            self.parsed_row.emit(obs)
            evidence.add_transcript(f"SESSION TX {spaced(payload)}")
            evidence.add_transcript(f"SESSION RX {spaced(exchange.response) if exchange.response else '<no response>'} [{parsed.response_type}]")
            if not parsed.positive_response:
                summary = self._base_summary(evidence)
                summary["observations"] = observations
                summary["verdict"] = VERDICT_INCONCLUSIVE
                summary["rationale"] = "Session flow did not complete positively; test request was not sent."
                return summary
            time.sleep(self.target.delay)
        return None

    def _invalid_security_setup_summary(self, evidence: EvidenceWriter, observations: list[dict[str, Any]], target_sid: int) -> dict[str, Any]:
        summary = self._base_summary(evidence)
        if target_sid in {0x34, 0x35}:
            intended_request = memory_transfer_request_candidates(target_sid, self.params)[0].request
        elif target_sid == 0x28:
            intended_request = build_uds25_request(self.params)
        else:
            intended_request = b""
        extra: dict[str, Any] = {}
        if target_sid in {0x34, 0x35}:
            extra.update({
                "transfer_data_sent": False,
                "transfer_data_statement": "TransferData 0x36 was not sent.",
                "request_transfer_exit_sent": False,
                "request_transfer_exit_statement": "RequestTransferExit 0x37 was not sent.",
            })
        if target_sid == 0x28:
            extra.update({
                "restore_request_hex": spaced(build_communication_control_restore_request(self.params)),
                "restore_response_hex": "",
                "post_check_result": "not_executed_invalid_setup",
            })
        summary.update({
            "test_case_id": self.test.id,
            "target_sid": f"0x{target_sid:02X}",
            "request_hex": spaced(intended_request),
            "response_hex": "",
            "parsed_response": {},
            "security_access_observed_before_target": True,
            "security_access_absence_statement": "SecurityAccess 0x27 was observed before the tested request; unauthenticated test aborted.",
            "verdict": VERDICT_INVALID_TEST_SETUP,
            "rationale": "A TX request starting with 0x27 occurred before the target service request.",
            "observations": observations,
        })
        summary.update(extra)
        return summary

    def _memory_security_gate_evidence(self, candidate: ProbeCandidate) -> dict[str, Any]:
        return {
            "dfi": f"0x{candidate.dfi:02X}",
            "dfi_annotation": dfi_annotation(candidate.dfi),
            "alfi": f"0x{candidate.alfi:02X}",
            "alfi_annotation": alfi_annotation(candidate.alfi),
            "address_length": candidate.address_length,
            "size_length": candidate.size_length,
            "memory_address": spaced(candidate.memory_address),
            "memory_size": spaced(candidate.memory_size),
            "annotation": candidate.annotation,
        }

    def _run_memory_security_gate_probe(self, evidence: EvidenceWriter, service_id: int) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        mode = get_memory_transfer_mode(self.params)
        mode_label = "Advanced Manual Request" if mode == "advanced_manual_request" else "Security Gate Probe"
        candidates = memory_transfer_request_candidates(service_id, self.params)
        for note in self._safety_notes():
            self.log_line.emit(f"Safety note: {note}")
            evidence.add_transcript(f"SAFETY: {note}")
        evidence.add_transcript("ASSERTION No SecurityAccess seed/key exchange was performed before the tested request.")
        client = self._open_uds_client()
        session_failure = self._run_session_flow_for_direct_test(client, evidence, observations)
        if session_failure:
            session_failure.update({
                "test_case_id": self.test.id,
                "mode": mode_label,
                "target_sid": f"0x{service_id:02X}",
                "request_hex": spaced(candidates[0].request),
                "parsed_response": {},
                "security_access_observed_before_target": security_access_observed_before_target(observations, service_id),
                "security_access_absence_statement": "No SecurityAccess seed/key exchange was performed before the tested request.",
                "transfer_data_sent": False,
                "transfer_data_statement": "TransferData 0x36 was not sent.",
                "request_transfer_exit_sent": False,
                "request_transfer_exit_statement": "RequestTransferExit 0x37 was not sent.",
            })
            session_failure.update(self._memory_security_gate_evidence(candidates[0]))
            return session_failure
        if security_access_observed_before_target(observations, service_id):
            return self._invalid_security_setup_summary(evidence, observations, service_id)

        verdict = VERDICT_NEED_MANUAL_REVIEW
        rationale = "No probe candidate produced a decisive response."
        response: Optional[bytes] = None
        parsed: Optional[UdsParsedResponse] = None
        final_candidate = candidates[0]
        decisive = False
        for idx, candidate in enumerate(candidates, 1):
            step_name = f"security_gate_probe_candidate_{idx}" if mode == "security_gate_probe" else "advanced_manual_request"
            self.log_line.emit(f"Memory transfer {mode_label} request {idx}: {format_probe_candidate(candidate)}")
            evidence.add_transcript(f"REQUEST {idx} {format_probe_candidate(candidate)}")
            exchange = self._send_uds(client, candidate.request)
            response = exchange.response
            verdict, rationale, decisive, parsed = classify_memory_transfer_probe_response(
                service_id,
                candidate.request,
                response,
                exchange.response_type,
            )
            obs = self._observation(step_name, candidate.request, response, parsed, exchange.error)
            obs.update(self._memory_security_gate_evidence(candidate))
            obs["mode"] = mode_label
            observations.append(obs)
            self.parsed_row.emit(obs)
            evidence.add_transcript(f"TEST TX {spaced(candidate.request)}")
            evidence.add_transcript(f"TEST RX {spaced(response) if response else '<no response>'} [{parsed.response_type}]")
            final_candidate = candidate
            if decisive:
                break
            time.sleep(self.target.delay)

        assert parsed is not None
        summary = self._base_summary(evidence)
        summary.update({
            "test_case_id": self.test.id,
            "mode": mode_label,
            "target_sid": f"0x{service_id:02X}",
            "request_hex": spaced(final_candidate.request),
            "response_hex": spaced(response) if response else "",
            "response_type": parsed.response_type,
            "positive_response": parsed.positive_response,
            "negative_response": parsed.negative_response,
            "nrc": f"0x{parsed.nrc:02X}" if parsed.nrc is not None else "",
            "nrc_meaning": parsed.nrc_meaning,
            "parsed_sid": f"0x{response[0]:02X}" if response else "",
            "parsed_response": parsed.__dict__,
            "verdict": verdict,
            "rationale": rationale,
            "observations": observations,
            "security_access_observed_before_target": False,
            "security_access_absence_statement": "No SecurityAccess seed/key exchange was performed before the tested request.",
            "transfer_data_sent": False,
            "transfer_data_statement": "TransferData 0x36 was not sent.",
            "request_transfer_exit_sent": False,
            "request_transfer_exit_statement": "RequestTransferExit 0x37 was not sent.",
            "candidate_requests": [format_probe_candidate(candidate) for candidate in candidates] if mode == "security_gate_probe" else [],
        })
        summary.update(self._memory_security_gate_evidence(final_candidate))
        return summary

    def _run_communication_control_security_gate(self, evidence: EvidenceWriter) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        for note in self._safety_notes():
            self.log_line.emit(f"Safety note: {note}")
            evidence.add_transcript(f"SAFETY: {note}")
        evidence.add_transcript("ASSERTION No SecurityAccess seed/key exchange was performed before the tested request.")
        client = self._open_uds_client()
        session_failure = self._run_session_flow_for_direct_test(client, evidence, observations)
        if session_failure:
            session_failure.update({
                "test_case_id": self.test.id,
                "target_sid": "0x28",
                "request_hex": spaced(build_uds25_request(self.params)),
                "parsed_response": {},
                "security_access_observed_before_target": security_access_observed_before_target(observations, 0x28),
                "security_access_absence_statement": "No SecurityAccess seed/key exchange was performed before the tested request.",
                "restore_request_hex": spaced(build_communication_control_restore_request(self.params)),
                "restore_response_hex": "",
                "post_check_result": "not_executed_session_flow_failed",
            })
            return session_failure
        if security_access_observed_before_target(observations, 0x28):
            return self._invalid_security_setup_summary(evidence, observations, 0x28)

        request = build_uds25_request(self.params)
        exchange = self._send_uds(client, request)
        response = exchange.response
        verdict, rationale, parsed = classify_communication_control_response(request, response, exchange.response_type)
        obs = self._observation("communication_control_target", request, response, parsed, exchange.error)
        observations.append(obs)
        self.parsed_row.emit(obs)
        evidence.add_transcript(f"TEST TX {spaced(request)}")
        evidence.add_transcript(f"TEST RX {spaced(response) if response else '<no response>'} [{parsed.response_type}]")

        restore_request = build_communication_control_restore_request(self.params)
        restore_response: Optional[bytes] = None
        restore_parsed: Optional[UdsParsedResponse] = None
        restore_status = "not_executed"
        post_check_result = "not_configured"
        if self.params.get("auto_restore", True):
            restore_exchange = self._send_uds(client, restore_request)
            restore_response = restore_exchange.response
            restore_parsed = parse_uds_response(restore_request, restore_response, transport_status=restore_exchange.response_type)
            restore_obs = self._observation("communication_control_restore", restore_request, restore_response, restore_parsed, restore_exchange.error)
            observations.append(restore_obs)
            self.parsed_row.emit(restore_obs)
            evidence.add_transcript(f"RESTORE TX {spaced(restore_request)}")
            evidence.add_transcript(f"RESTORE RX {spaced(restore_response) if restore_response else '<no response>'} [{restore_parsed.response_type}]")
            restore_status = restore_parsed.response_type
            post_check_result = "restore_positive" if restore_parsed.positive_response else f"restore_{restore_parsed.response_type}"

        summary = self._base_summary(evidence)
        summary.update({
            "test_case_id": self.test.id,
            "target_sid": "0x28",
            "request_hex": spaced(request),
            "response_hex": spaced(response) if response else "",
            "response_type": parsed.response_type,
            "positive_response": parsed.positive_response,
            "negative_response": parsed.negative_response,
            "nrc": f"0x{parsed.nrc:02X}" if parsed.nrc is not None else "",
            "nrc_meaning": parsed.nrc_meaning,
            "parsed_sid": f"0x{response[0]:02X}" if response else "",
            "parsed_response": parsed.__dict__,
            "verdict": verdict,
            "rationale": rationale,
            "observations": observations,
            "security_access_observed_before_target": False,
            "security_access_absence_statement": "No SecurityAccess seed/key exchange was performed before the tested request.",
            "restore_request_hex": spaced(restore_request),
            "restore_response_hex": spaced(restore_response) if restore_response else "",
            "restore_response_type": restore_status,
            "restore_parsed_response": restore_parsed.__dict__ if restore_parsed else {},
            "post_check_result": post_check_result,
        })
        return summary

    def _run_uds20_reset_precondition_probe(self, evidence: EvidenceWriter) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        for note in self._safety_notes():
            self.log_line.emit(f"Safety note: {note}")
            evidence.add_transcript(f"SAFETY: {note}")
        request = build_uds20_request(self.params)
        client = self._open_uds_client()
        for payload in expand_session_flow_requests(self.params.get("test_session_flow", "")):
            exchange = self._send_uds(client, payload)
            parsed = parse_uds_response(payload, exchange.response, transport_status=exchange.response_type)
            obs = self._observation("test_session_flow", payload, exchange.response, parsed, exchange.error)
            observations.append(obs)
            self.parsed_row.emit(obs)
            evidence.add_transcript(f"TEST_SESSION TX {spaced(payload)}")
            evidence.add_transcript(f"TEST_SESSION RX {spaced(exchange.response) if exchange.response else '<no response>'} [{parsed.response_type}]")
            if not parsed.positive_response:
                summary = self._base_summary(evidence)
                summary.update({
                    "precondition_session_flow": self.params.get("precondition_session_flow", ""),
                    "test_session_flow": self.params.get("test_session_flow", ""),
                    "expanded_test_session_requests": safe_expand_session_flow_hex(self.params.get("test_session_flow", "")),
                    "request_hex": spaced(request),
                    "verdict": VERDICT_INCONCLUSIVE_SETUP_ERROR,
                    "rationale": "Could not enter the configured test session flow before sending ECUReset.",
                    "observations": observations,
                })
                return summary
            time.sleep(self.target.delay)

        exchange = self._send_uds(client, request)
        response = exchange.response
        verdict, rationale, parsed = classify_uds20_reset_response(request, response, self.params, exchange.response_type)
        obs = self._observation("ecu_reset_without_required_precondition", request, response, parsed, exchange.error)
        observations.append(obs)
        self.parsed_row.emit(obs)
        evidence.add_transcript(f"TEST TX {spaced(request)}")
        evidence.add_transcript(f"TEST RX {spaced(response) if response else '<no response>'} [{parsed.response_type}]")

        summary = self._base_summary(evidence)
        summary.update({
            "precondition_session_flow": self.params.get("precondition_session_flow", ""),
            "test_session_flow": self.params.get("test_session_flow", ""),
            "expanded_test_session_requests": safe_expand_session_flow_hex(self.params.get("test_session_flow", "")),
            "request_hex": spaced(request),
            "response_hex": spaced(response) if response else "",
            "response_type": parsed.response_type,
            "positive_response": parsed.positive_response,
            "negative_response": parsed.negative_response,
            "nrc": f"0x{parsed.nrc:02X}" if parsed.nrc is not None else "",
            "nrc_meaning": parsed.nrc_meaning,
            "reset_subfunction": f"0x{request[1]:02X}" if len(request) > 1 else "",
            "acceptable_nrcs": [f"0x{x:02X}" for x in sorted(parse_acceptable_nrcs(self.params.get("acceptable_nrcs")))],
            "verdict": verdict,
            "rationale": rationale,
            "observations": observations,
        })
        return summary

    def _run_direct(self, evidence: EvidenceWriter) -> dict[str, Any]:
        if self.test.id == "uds_20":
            return self._run_uds20_reset_precondition_probe(evidence)
        if self.test.id in {"uds_23", "uds_24"}:
            return self._run_memory_security_gate_probe(evidence, 0x34 if self.test.id == "uds_23" else 0x35)
        if self.test.id == "uds_25":
            return self._run_communication_control_security_gate(evidence)
        if not self.test.build_request or not self.test.verdict_rules:
            return self._error_summary(evidence, VERDICT_CONFIG, "Direct runner is missing request or verdict logic.")

        observations: list[dict[str, Any]] = []
        for note in self._safety_notes():
            self.log_line.emit(f"Safety note: {note}")
            evidence.add_transcript(f"SAFETY: {note}")
        request = self.test.build_request(self.params)
        client = self._open_uds_client()
        for payload in expand_session_flow_requests(self.params.get("session_flow", "")):
            exchange = self._send_uds(client, payload)
            parsed = parse_uds_response(payload, exchange.response, transport_status=exchange.response_type)
            obs = self._observation("session_flow", payload, exchange.response, parsed, exchange.error)
            observations.append(obs)
            self.parsed_row.emit(obs)
            evidence.add_transcript(f"SESSION TX {spaced(payload)}")
            evidence.add_transcript(f"SESSION RX {spaced(exchange.response) if exchange.response else '<no response>'} [{parsed.response_type}]")
            if not parsed.positive_response:
                summary = self._base_summary(evidence)
                summary["observations"] = observations
                summary["verdict"] = VERDICT_INCONCLUSIVE
                summary["rationale"] = "Session flow did not complete positively; test request was not sent."
                return summary
            time.sleep(self.target.delay)

        if self.test.id in {"uds_21", "uds_22"} and security_access_observed_before_target(observations, request[0]):
            summary = self._base_summary(evidence)
            summary.update({
                "request_hex": spaced(request),
                "response_hex": "",
                "parsed_response": {},
                "security_access_observed_before_target": True,
                "security_access_absence_statement": "SecurityAccess 0x27 was observed before the tested request; unauthenticated test aborted.",
                "verdict": VERDICT_INVALID_TEST_SETUP,
                "rationale": "A TX request starting with 0x27 occurred before the target service request.",
                "observations": observations,
            })
            return summary

        exchange = self._send_uds(client, request)
        response = exchange.response
        parsed = parse_uds_response(request, response, transport_status=exchange.response_type)
        observations.append(self._observation("test_request", request, response, parsed, exchange.error))
        self.parsed_row.emit(observations[-1])
        evidence.add_transcript(f"TEST TX {spaced(request)}")
        evidence.add_transcript(f"TEST RX {spaced(response) if response else '<no response>'} [{parsed.response_type}]")

        verdict, rationale = self.test.verdict_rules(request, response, self.params, observations)
        summary = self._base_summary(evidence)
        summary.update({
            "request_hex": spaced(request),
            "response_hex": spaced(response) if response else "",
            "response_type": parsed.response_type,
            "positive_response": parsed.positive_response,
            "negative_response": parsed.negative_response,
            "nrc": f"0x{parsed.nrc:02X}" if parsed.nrc is not None else "",
            "nrc_meaning": parsed.nrc_meaning,
            "verdict": verdict,
            "rationale": rationale,
            "observations": observations,
        })
        if self.test.id == "uds_21":
            summary["did_hex"] = f"0x{request[1]:02X}{request[2]:02X}" if len(request) >= 3 else ""
            summary["did_length_bytes"] = len(request[3:]) if len(request) > 3 else 0
            summary["generated_or_supplied_data_hex"] = spaced(request[3:]) if len(request) > 3 else ""
            summary["selected_did"] = summary["did_hex"]
            catalog_length = str(self.params.get("catalog_length_bytes") or "").strip()
            requested_length = str(self.params.get("data_length_bytes") or self.params.get("did_length_bytes") or "").strip()
            source = self.params.get("did_length_source") or "unknown"
            if catalog_length and requested_length and catalog_length != requested_length:
                source = "manual_override"
            elif requested_length and not catalog_length:
                source = "manual_override"
            summary["did_length_source"] = source
            summary["generated_payload_length"] = len(request[3:]) if len(request) > 3 else 0
            summary["parsed_response"] = parsed.__dict__
            summary["security_access_observed_before_target"] = False
            summary["security_access_absence_statement"] = "No SecurityAccess seed/key exchange was performed before the tested request."
        if self.test.id == "uds_22":
            summary["did_hex"] = f"0x{request[1]:02X}{request[2]:02X}" if len(request) >= 3 else ""
            response_data = response[3:] if response and len(response) > 3 and response[:3] == bytes([0x62, request[1], request[2]]) else b""
            response_data_hex = spaced(response_data)
            summary["response_data_hex"] = response_data_hex
            summary["did_message_hex"] = response_data_hex
            summary["data_length_bytes"] = len(response_data)
            summary["did_length_bytes"] = len(response_data)
            summary["selected_did"] = summary["did_hex"]
            summary["catalog_length"] = self.params.get("catalog_length_bytes") or self.params.get("did_length_bytes", "")
            summary["catalog_message_hex"] = self.params.get("did_message_hex", "")
            summary["parsed_response"] = parsed.__dict__
            summary["security_access_observed_before_target"] = False
            summary["security_access_absence_statement"] = "No SecurityAccess seed/key exchange was performed before the tested request."
        return summary

    def _open_uds_client(self) -> Any:
        try:
            from uds_toolkit.canio import open_bus
            from uds_toolkit.config import CanConfig
            from uds_toolkit.isotp import IsoTp
        except Exception as exc:
            raise RuntimeError(f"Unable to import project ISO-TP transport: {exc}") from exc

        can_cfg = CanConfig(
            channel=self.target.channel,
            interface=self.target.interface,
            extended_id=self.target.extended_id,
            padding=self.target.padding,
        )
        can_mod, bus = open_bus(can_cfg)
        self._opened_buses.append(bus)
        transport = IsoTp(
            bus,
            can_mod,
            txid=self.target.tester_tx_id,
            rxid=self.target.tester_rx_id,
            extended_id=self.target.extended_id,
            pad=self.target.padding,
            request_stmin=self.target.request_stmin,
            fc_wait_timeout=self.target.fc_wait_timeout,
            log=QtConsoleLog(self.log_line.emit, self.target),
        )
        return transport

    def _send_uds(self, transport: Any, payload: bytes) -> UdsExchange:
        self.transcript_line.emit(f"TX {self.target.tester_tx_id:X}: {spaced(payload)}")
        self.log_line.emit(f"UDS TX {spaced(payload)}")
        try:
            response = transport.request_payload(
                payload,
                timeout=self.target.timeout,
                response_pending_timeout=self.target.response_pending_timeout,
                frame_label="Response",
            )
        except TimeoutError:
            self.log_line.emit("UDS RX <timeout>")
            self.transcript_line.emit("RX <timeout>")
            return UdsExchange(None, "timeout", "timeout waiting for final UDS response")
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            self.log_line.emit(f"UDS RX <transport_error> {message}")
            self.transcript_line.emit(f"RX <transport_error> {message}")
            return UdsExchange(None, "transport_error", message)
        self.log_line.emit(f"UDS RX {spaced(response)}")
        self.transcript_line.emit(f"RX {self.target.tester_rx_id:X}: {spaced(response)}")
        return UdsExchange(response, "raw_response")

    def _recv_extra_uds(self, transport: Any, timeout: float) -> UdsExchange:
        try:
            response = transport.recv_payload(timeout=timeout, frame_label="Extra")
        except TimeoutError:
            return UdsExchange(None, "timeout", "no extra response before capture timeout")
        except Exception as exc:
            return UdsExchange(None, "transport_error", f"{type(exc).__name__}: {exc}")
        self.log_line.emit(f"UDS EXTRA RX {spaced(response)}")
        self.transcript_line.emit(f"RX {self.target.tester_rx_id:X}: {spaced(response)}")
        return UdsExchange(response, "raw_response")

    @staticmethod
    def _observation(step: str, request: bytes, response: Optional[bytes], parsed: UdsParsedResponse, error: str = "") -> dict[str, Any]:
        return {
            "step": step,
            "request_hex": spaced(request),
            "response_hex": spaced(response) if response else "",
            "response_type": parsed.response_type,
            "positive_response": parsed.positive_response,
            "negative_response": parsed.negative_response,
            "nrc": f"0x{parsed.nrc:02X}" if parsed.nrc is not None else "",
            "nrc_meaning": parsed.nrc_meaning,
            "note": error or parsed.note,
        }


class NoWheelComboBox(QComboBox):
    def wheelEvent(self, event: Any) -> None:
        if self.view().isVisible():
            super().wheelEvent(event)
        else:
            event.ignore()


STYLE = """
QWidget {
    background: #12161C;
    color: #D7DDE7;
    font-family: Consolas, "JetBrains Mono", monospace;
    font-size: 12px;
}
QGroupBox {
    border: 1px solid #2A3340;
    border-radius: 6px;
    margin-top: 8px;
    padding: 8px;
    background: #171C24;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #7DB3FF;
    font-weight: bold;
}
QLineEdit, QComboBox, QTextEdit, QTableWidget {
    background: #0B0F14;
    border: 1px solid #2A3340;
    border-radius: 4px;
    color: #D7DDE7;
    selection-background-color: #245B8F;
}
QLineEdit, QComboBox { padding: 4px 6px; }
QTextEdit { padding: 6px; }
QPushButton {
    background: #202938;
    border: 1px solid #39465A;
    border-radius: 4px;
    padding: 6px 10px;
    color: #D7DDE7;
}
QPushButton:hover { background: #2B5F9E; }
QPushButton:disabled { color: #697386; background: #141922; }
QPushButton#runButton { background: #10351F; border-color: #2F8F53; color: #81E6A5; font-weight: bold; }
QPushButton#stopButton { background: #3A1111; border-color: #8F2F2F; color: #FF9C9C; font-weight: bold; }
QLabel#errorLabel { color: #FF9C9C; }
QSplitter::handle { background: #2A3340; }
"""


class UdsReconGui(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.registry = build_registry()
        self.tests_by_id = {test.id: test for test in self.registry}
        self.current_test = self.registry[0]
        self.field_widgets: dict[str, QWidget] = {}
        self.error_labels: dict[str, QLabel] = {}
        self.current_errors: dict[str, str] = {}
        self.did_catalog_rows: list[dict[str, Any]] = []
        self.worker: Optional[RunWorker] = None

        self.setWindowTitle(APP_TITLE)
        self.setWindowFlags(
            self.windowFlags()
            | Qt.WindowType.WindowMinimizeButtonHint
            | Qt.WindowType.WindowMaximizeButtonHint
            | Qt.WindowType.WindowCloseButtonHint
        )
        self.setMinimumSize(980, 640)
        self.resize(1280, 760)
        self._build_ui()
        self._populate_tests()
        self._select_test(self.registry[0].id)
        self._fit_to_available_screen()

    def _fit_to_available_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        available = screen.availableGeometry()
        width = min(1440, max(self.minimumWidth(), int(available.width() * 0.92)))
        height = min(860, max(self.minimumHeight(), int(available.height() * 0.88)))
        self.resize(width, height)
        self.move(
            available.x() + max(0, (available.width() - width) // 2),
            available.y() + max(0, (available.height() - height) // 2),
        )

    def _build_ui(self) -> None:
        app = QApplication.instance()
        if app:
            app.setStyleSheet(STYLE)

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(10, 10, 10, 10)
        self.setCentralWidget(root)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_control_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setChildrenCollapsible(False)
        splitter.setSizes([760, 760])
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        root_layout.addWidget(splitter, 1)

    def _build_control_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(620)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 8, 0)

        layout.addWidget(self._build_target_profile())

        workflow = QSplitter(Qt.Orientation.Horizontal)
        workflow.addWidget(self._build_left_panel())
        workflow.addWidget(self._build_center_panel())
        workflow.setChildrenCollapsible(False)
        workflow.setSizes([360, 440])
        workflow.setStretchFactor(0, 1)
        workflow.setStretchFactor(1, 1)
        layout.addWidget(workflow, 1)
        return panel

    def _build_target_profile(self) -> QGroupBox:
        box = QGroupBox("Target Profile")
        grid = QGridLayout(box)
        self.can_interface = QLineEdit("socketcan")
        self.can_channel = QLineEdit("can0")
        self.req_id = QLineEdit("0x681")
        self.resp_id = QLineEdit("0x601")
        self.extended_id = QCheckBox("Extended ID")
        self.padding = QLineEdit("0x00")
        self.timeout = QLineEdit("1.0")
        self.response_pending_timeout = QLineEdit("5.0")
        self.delay = QLineEdit("0.05")
        self.request_stmin = QLineEdit("0.0")
        self.request_stmin.setVisible(False)
        self.fc_wait_timeout = QLineEdit("3.0")
        self.fc_wait_timeout.setVisible(False)
        self.output_dir = QLineEdit(str(DEFAULT_EVIDENCE_DIR))
        self.browse_output = QPushButton("Browse")
        self.save_output = QCheckBox("Save output")
        self.save_output.setChecked(True)
        # Kept as hidden compatibility switches for backend paths; the operator UI is live-run first.
        self.dry_run = QCheckBox("Dry run")
        self.dry_run.setChecked(False)
        self.dry_run.setVisible(False)
        self.authorized_disruptive = QCheckBox("Operator authorization confirmed")
        self.authorized_disruptive.setChecked(False)
        self.authorized_disruptive.setVisible(False)
        self.tester_tx_label = QLabel("tester_tx_id")
        self.tester_rx_label = QLabel("tester_rx_id")
        tx_tip = "CAN arbitration ID used by the tester to send diagnostic requests. ECU receives on this ID."
        rx_tip = "CAN arbitration ID used by the tester to receive diagnostic responses. ECU transmits on this ID."
        self.tester_tx_label.setToolTip(tx_tip)
        self.req_id.setToolTip(tx_tip)
        self.tester_rx_label.setToolTip(rx_tip)
        self.resp_id.setToolTip(rx_tip)

        items = [
            (QLabel("Interface"), self.can_interface),
            (QLabel("Channel"), self.can_channel),
            (self.tester_tx_label, self.req_id),
            (self.tester_rx_label, self.resp_id),
            (QLabel("Padding"), self.padding),
            (QLabel("Timeout"), self.timeout),
            (QLabel("Response pending timeout"), self.response_pending_timeout),
            (QLabel("Inter-request delay"), self.delay),
        ]
        for idx, (label, widget) in enumerate(items):
            grid.addWidget(label, idx // 3, idx % 3 * 2)
            grid.addWidget(widget, idx // 3, idx % 3 * 2 + 1)
        base_row = (len(items) + 2) // 3
        grid.addWidget(self.extended_id, base_row, 0)
        grid.addWidget(self.save_output, base_row, 1)
        grid.addWidget(QLabel("Output directory"), base_row + 1, 0)
        grid.addWidget(self.output_dir, base_row + 1, 1, 1, 4)
        grid.addWidget(self.browse_output, base_row + 1, 5)

        for widget in (
            self.can_interface, self.can_channel, self.req_id, self.resp_id, self.padding,
            self.timeout, self.response_pending_timeout, self.delay, self.request_stmin,
            self.fc_wait_timeout, self.output_dir,
        ):
            widget.textChanged.connect(self._refresh_validation_and_preview)
        for widget in (self.extended_id, self.save_output):
            widget.stateChanged.connect(self._refresh_validation_and_preview)
        self.save_output.stateChanged.connect(self._update_output_controls)
        self.browse_output.clicked.connect(self._browse_output_dir)
        self._update_output_controls()
        return box

    def _update_output_controls(self) -> None:
        enabled = self.save_output.isChecked()
        self.output_dir.setEnabled(enabled)
        self.browse_output.setEnabled(enabled)

    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(320)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 8, 0)

        self.category = NoWheelComboBox()
        self.category.addItems(["Recon", "Fuzzing", "UDS Test Cases", "UDS-26..32 Framework"])
        self.category.currentTextChanged.connect(self._populate_tests)
        self.test_dropdown = NoWheelComboBox()
        self.test_dropdown.currentIndexChanged.connect(self._test_dropdown_changed)
        self.description = QTextEdit()
        self.description.setReadOnly(True)
        self.description.setMinimumHeight(72)
        self.description.setMaximumHeight(105)
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMinimumHeight(110)
        self.run_btn = QPushButton("Run")
        self.run_btn.setObjectName("runButton")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setEnabled(False)
        self.run_btn.clicked.connect(self._run_selected)
        self.stop_btn.clicked.connect(self._stop_run)

        layout.addWidget(QLabel("Category"))
        layout.addWidget(self.category)
        layout.addWidget(QLabel("Test / function"))
        layout.addWidget(self.test_dropdown)
        layout.addWidget(QLabel("Description"))
        layout.addWidget(self.description)
        layout.addWidget(QLabel("Command / request preview"))
        layout.addWidget(self.preview, 1)
        button_row = QHBoxLayout()
        button_row.addWidget(self.run_btn)
        button_row.addWidget(self.stop_btn)
        layout.addLayout(button_row)
        return panel

    def _build_center_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(360)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 0, 0, 0)
        self.params_header = QLabel("Parameters")
        self.params_header.setWordWrap(True)
        self.params_header.setStyleSheet("font-weight: bold; color: #7DB3FF; padding: 2px 0 6px 0;")
        layout.addWidget(self.params_header)

        params_content = QWidget()
        params_content_layout = QVBoxLayout(params_content)
        params_content_layout.setContentsMargins(0, 0, 0, 0)
        self.params_group = QWidget()
        self.params_group.setMinimumWidth(330)
        self.params_layout = QFormLayout(self.params_group)
        self.params_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        self.params_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.params_layout.setHorizontalSpacing(10)
        self.params_layout.setVerticalSpacing(6)
        params_content_layout.addWidget(self.params_group)
        self.did_catalog_box = self._build_did_catalog_box()
        params_content_layout.addWidget(self.did_catalog_box)
        params_content_layout.addStretch(1)

        self.params_scroll = QScrollArea()
        self.params_scroll.setWidgetResizable(True)
        self.params_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.params_scroll.setWidget(params_content)
        layout.addWidget(self.params_scroll, 1)
        return panel

    def _build_did_catalog_box(self) -> QGroupBox:
        box = QGroupBox("DID Catalog")
        layout = QVBoxLayout(box)
        row = QHBoxLayout()
        self.load_did_btn = QPushButton("Load DID catalog")
        self.use_did_btn = QPushButton("Use selected DID")
        row.addWidget(self.load_did_btn)
        row.addWidget(self.use_did_btn)
        layout.addLayout(row)
        self.did_catalog_table = QTableWidget(0, 4)
        self.did_catalog_table.setHorizontalHeaderLabels(["DID", "Length", "Message DID", "Notes"])
        self.did_catalog_table.setMinimumHeight(90)
        self.did_catalog_table.setMaximumHeight(150)
        self.did_catalog_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.did_catalog_table)
        self.load_did_btn.clicked.connect(self._load_did_catalog)
        self.use_did_btn.clicked.connect(self._use_selected_did)
        return box

    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(560)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 0, 0, 0)
        self.live_log = QTextEdit()
        self.live_log.setReadOnly(True)
        self.transcript = QTextEdit()
        self.transcript.setReadOnly(True)

        log_header = QHBoxLayout()
        log_header.addWidget(QLabel("Live log"))
        self.clear_log_btn = QPushButton("Clear log")
        self.clear_log_btn.clicked.connect(self._clear_log_views)
        log_header.addStretch(1)
        log_header.addWidget(self.clear_log_btn)
        layout.addLayout(log_header)
        layout.addWidget(self.live_log, 3)
        layout.addWidget(QLabel("Raw CAN / UDS transcript"))
        layout.addWidget(self.transcript, 1)
        return panel

    def _populate_tests(self) -> None:
        category = self.category.currentText() if hasattr(self, "category") else "Recon"
        self.test_dropdown.blockSignals(True)
        self.test_dropdown.clear()
        for test in self.registry:
            if test.category == category:
                self.test_dropdown.addItem(test.title, test.id)
        self.test_dropdown.blockSignals(False)
        if self.test_dropdown.count():
            self._select_test(self.test_dropdown.itemData(0))

    def _test_dropdown_changed(self) -> None:
        test_id = self.test_dropdown.currentData()
        if test_id:
            self._select_test(test_id)

    def _select_test(self, test_id: str) -> None:
        self.current_test = self.tests_by_id[test_id]
        self.description.setPlainText(self.current_test.description)
        self._render_params()
        self._set_target_enabled()
        self._clear_results(keep_logs=True)
        self._refresh_validation_and_preview()

    def _set_target_enabled(self) -> None:
        enabled = self.current_test.target_required
        for widget in (self.tester_tx_label, self.req_id, self.tester_rx_label, self.resp_id):
            widget.setVisible(enabled)
        for widget in (self.req_id, self.resp_id):
            widget.setEnabled(enabled)
        note = "This mode discovers arbitration IDs and does not need known tester TX / tester RX IDs."
        self.req_id.setToolTip(note if not enabled else "CAN arbitration ID used by the tester to send diagnostic requests. ECU receives on this ID.")
        self.resp_id.setToolTip(note if not enabled else "CAN arbitration ID used by the tester to receive diagnostic responses. ECU transmits on this ID.")

    def _render_params(self) -> None:
        if hasattr(self, "params_header"):
            self.params_header.setText(f"Parameters — {self.current_test.display_name}")
        while self.params_layout.rowCount():
            self.params_layout.removeRow(0)
        self.field_widgets.clear()
        self.error_labels.clear()

        params = {field.id: field.default for field in self.current_test.fields}
        for field_spec in self.current_test.fields:
            widget = self._create_field_widget(field_spec)
            error = QLabel("")
            error.setObjectName("errorLabel")
            holder = QWidget()
            holder_layout = QVBoxLayout(holder)
            holder_layout.setContentsMargins(0, 0, 0, 0)
            holder_layout.addWidget(widget)
            holder_layout.addWidget(error)
            self.params_layout.addRow(field_spec.label, holder)
            self.field_widgets[field_spec.id] = widget
            self.error_labels[field_spec.id] = error
        self.did_catalog_box.setVisible(self.current_test.id in {"uds_21", "uds_22"})
        self._apply_field_conditions(params)

    def _create_field_widget(self, spec: FieldSpec) -> QWidget:
        if spec.kind == "checkbox":
            widget = QCheckBox()
            widget.setMinimumHeight(26)
            widget.setChecked(bool(spec.default))
            widget.stateChanged.connect(self._refresh_validation_and_preview)
            return widget
        if spec.kind == "combo":
            widget = NoWheelComboBox()
            for choice in spec.choices:
                widget.addItem(choice.label, choice.value)
            index = widget.findData(spec.default)
            if index >= 0:
                widget.setCurrentIndex(index)
            widget.setMinimumHeight(28)
            widget.currentIndexChanged.connect(self._refresh_validation_and_preview)
            return widget
        if spec.kind == "textarea":
            widget = QTextEdit()
            widget.setPlaceholderText(spec.placeholder)
            widget.setPlainText(str(spec.default or ""))
            height_by_field = {
                "session_flow": 70,
                "precondition_session_flow": 70,
                "test_session_flow": 70,
                "data_hex": 70,
                "sensitivity_note": 64,
                "did_message_hex": 64,
                "key_hex": 70,
            }
            height = height_by_field.get(spec.id, 70)
            widget.setMinimumHeight(height)
            widget.setMaximumHeight(max(height + 34, 108))
            widget.textChanged.connect(self._refresh_validation_and_preview)
            return widget
        widget = QLineEdit(str(spec.default or ""))
        widget.setMinimumHeight(28)
        widget.setPlaceholderText(spec.placeholder)
        widget.textChanged.connect(self._refresh_validation_and_preview)
        return widget

    def _collect_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {}
        for field_spec in self.current_test.fields:
            widget = self.field_widgets.get(field_spec.id)
            if widget is None:
                continue
            if isinstance(widget, QCheckBox):
                params[field_spec.id] = widget.isChecked()
            elif isinstance(widget, QComboBox):
                params[field_spec.id] = widget.currentData()
            elif isinstance(widget, QTextEdit):
                params[field_spec.id] = widget.toPlainText()
            elif isinstance(widget, QLineEdit):
                params[field_spec.id] = widget.text()
        return params

    def _collect_target(self) -> tuple[Optional[TargetProfile], dict[str, str]]:
        errors: dict[str, str] = {}
        try:
            tester_tx_id = parse_hex_int(self.req_id.text(), name="tester_tx_id", maximum=0x1FFFFFFF)
        except ValueError as exc:
            tester_tx_id = 0
            if self.current_test.target_required:
                errors["tester_tx_id"] = str(exc)
        try:
            tester_rx_id = parse_hex_int(self.resp_id.text(), name="tester_rx_id", maximum=0x1FFFFFFF)
        except ValueError as exc:
            tester_rx_id = 0
            if self.current_test.target_required:
                errors["tester_rx_id"] = str(exc)
        try:
            padding_value = parse_hex_byte(self.padding.text(), "padding")
        except ValueError as exc:
            padding_value = 0x00
            errors["padding"] = str(exc)
        try:
            timeout_value = float(self.timeout.text())
            if timeout_value <= 0:
                raise ValueError("Timeout must be > 0")
        except ValueError as exc:
            timeout_value = 1.0
            errors["timeout"] = str(exc)
        try:
            response_pending_timeout_value = float(self.response_pending_timeout.text())
            if response_pending_timeout_value <= 0:
                raise ValueError("Response pending timeout must be > 0")
        except ValueError as exc:
            response_pending_timeout_value = 5.0
            errors["response_pending_timeout"] = str(exc)
        try:
            delay_value = float(self.delay.text())
            if delay_value < 0:
                raise ValueError("Inter-request delay must be >= 0")
        except ValueError as exc:
            delay_value = 0.0
            errors["delay"] = str(exc)
        try:
            request_stmin_value = float(self.request_stmin.text())
            if request_stmin_value < 0:
                raise ValueError("Request STmin must be >= 0")
        except ValueError as exc:
            request_stmin_value = 0.0
            errors["request_stmin"] = str(exc)
        try:
            fc_wait_timeout_value = float(self.fc_wait_timeout.text())
            if fc_wait_timeout_value <= 0:
                raise ValueError("FC wait timeout must be > 0")
        except ValueError as exc:
            fc_wait_timeout_value = 3.0
            errors["fc_wait_timeout"] = str(exc)
        interface = self.can_interface.text().strip()
        if not interface:
            errors["interface"] = "interface is required"
        channel = self.can_channel.text().strip()
        if not channel:
            errors["can_channel"] = "channel is required"
        output = Path(self.output_dir.text().strip() or str(DEFAULT_EVIDENCE_DIR))
        target = TargetProfile(
            interface=interface or "socketcan",
            channel=channel or "can0",
            tester_tx_id=tester_tx_id,
            tester_rx_id=tester_rx_id,
            extended_id=self.extended_id.isChecked(),
            padding=padding_value,
            timeout=timeout_value,
            response_pending_timeout=response_pending_timeout_value,
            delay=delay_value,
            request_stmin=request_stmin_value,
            fc_wait_timeout=fc_wait_timeout_value,
            output_dir=output,
            save_output=self.save_output.isChecked(),
            dry_run=False,
            authorized_disruptive=False,
            operator_notes="",
        )
        return target, errors

    def _refresh_validation_and_preview(self) -> None:
        if not hasattr(self, "preview"):
            return
        params = self._collect_params()
        self._apply_field_conditions(params)
        target, errors = self._collect_target()

        for field_spec in self.current_test.fields:
            if not field_visible(field_spec, params):
                continue
            value = params.get(field_spec.id)
            if field_spec.required and not str(value or "").strip() and not isinstance(value, bool):
                errors[field_spec.id] = f"{field_spec.label} is required"
        if target and self.current_test.validate:
            errors.update(self.current_test.validate(target, params))

        self.current_errors = errors
        for key, label in self.error_labels.items():
            label.setText(errors.get(key, ""))

        preview_text = self._build_preview(target, params, errors)
        self.preview.setPlainText(preview_text)
        self.run_btn.setEnabled(not errors and self.worker is None)

    def _apply_field_conditions(self, params: dict[str, Any]) -> None:
        for idx, field_spec in enumerate(self.current_test.fields):
            widget = self.field_widgets.get(field_spec.id)
            if widget is None:
                continue
            visible = field_visible(field_spec, params)
            enabled = field_enabled(field_spec, params)
            label_item = self.params_layout.itemAt(idx, QFormLayout.ItemRole.LabelRole)
            field_item = self.params_layout.itemAt(idx, QFormLayout.ItemRole.FieldRole)
            if label_item and label_item.widget():
                label_item.widget().setVisible(visible)
            if field_item and field_item.widget():
                field_item.widget().setVisible(visible)
            widget.setEnabled(enabled)

    def _build_preview(self, target: Optional[TargetProfile], params: dict[str, Any], errors: dict[str, str]) -> str:
        if not target:
            return ""
        lines: list[str] = []
        if "session_flow" in params:
            try:
                session_preview = format_session_flow_preview(params.get("session_flow", ""))
                if session_preview:
                    lines.append(session_preview)
            except Exception as exc:
                lines.append(f"Session flow preview error: {exc}")
        preview = ""
        try:
            if self.current_test.id == "uds_20":
                request = build_uds20_request(params)
                expected = " / ".join(f"7F 11 {nrc:02X}" for nrc in sorted(parse_acceptable_nrcs(params.get("acceptable_nrcs"))))
                expanded_test = "; ".join(spaced(payload) for payload in expand_session_flow_requests(params.get("test_session_flow", "")))
                preview = "\n".join([
                    f"Required/precondition session flow: {str(params.get('precondition_session_flow') or '').strip()}",
                    f"Actual test session flow: {str(params.get('test_session_flow') or '').strip()}",
                    f"Expanded test session requests: {expanded_test}",
                    f"Final UDS request: {spaced(request)}",
                    f"Expected denial: {expected}",
                ])
            elif self.current_test.runner_kind == "external" and self.current_test.build_command:
                preview = command_preview_from_argv(command_argv_for(self.current_test, target, params))
            elif self.current_test.runner_kind == "security_access" and self.current_test.execution_plan:
                plan = self.current_test.execution_plan(params)
                preview = "\n".join(
                    f"{idx + 1:02d}. {step.get('step')} {step.get('request_hex', '') or ('wait=' + str(step.get('wait_seconds')) + 's' if step.get('wait_seconds') is not None else '')}"
                    for idx, step in enumerate(plan)
                )
            elif self.current_test.runner_kind in {"modular_stub", "diagnostic_service"}:
                guard = SafetyGuard.from_mapping(self.current_test.safety_guard | {
                    key: params[key] for key in (
                        "max_duration_seconds",
                        "max_frame_rate",
                        "tester_present_enabled",
                        "tester_present_interval_seconds",
                    ) if key in params
                })
                case_model = normalize_case_model(self.current_test.case_model)
                runner = make_modular_runner(self.current_test.runner_interface or "diagnostic_service")
                plan = runner.plan(case_model, params, guard).as_dict()
                preview = runner.dry_run_preview(case_model, params, guard)
                preview += "\n" + f"Evidence schema: {', '.join(self.current_test.evidence_schema.get('fields', []))}"
            elif self.current_test.id in {"uds_23", "uds_24"}:
                service_id = 0x34 if self.current_test.id == "uds_23" else 0x35
                preview = format_memory_transfer_preview(service_id, params)
            elif self.current_test.id == "uds_25":
                request = build_uds25_request(params)
                restore = build_communication_control_restore_request(params)
                preview = f"Target request: {spaced(request)}\nRestore request: {spaced(restore)}"
            elif self.current_test.build_request:
                request = self.current_test.build_request(params)
                preview = f"Final UDS request: {spaced(request)}"
        except Exception as exc:
            preview = f"Preview error: {exc}"
        if preview:
            lines.append(preview)
        if errors:
            lines.append("Fix validation errors before running:\n" + "\n".join(f"- {msg}" for msg in errors.values()))
        return "\n\n".join(lines)

    def _run_selected(self) -> None:
        self._refresh_validation_and_preview()
        if self.current_errors:
            self._append_log("Validation error: " + "; ".join(self.current_errors.values()))
            QMessageBox.warning(self, "Validation error", "\n".join(self.current_errors.values()))
            return
        target, _ = self._collect_target()
        if target is None:
            return
        if target.save_output:
            ensure_dir(target.output_dir)
        params = self._collect_params()
        self._clear_results(keep_logs=False)
        self.worker = RunWorker(self.current_test, target, params, self.preview.toPlainText())
        self.worker.log_line.connect(self._append_log)
        self.worker.transcript_line.connect(self._append_transcript)
        self.worker.parsed_row.connect(self._append_parsed_row)
        self.worker.finished_run.connect(self._run_finished)
        self.worker.finished.connect(self._worker_thread_finished)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._append_log(f"Starting {self.current_test.id}: {self.current_test.title}")
        self.worker.start()

    def _stop_run(self) -> None:
        if self.worker:
            self._append_log("Stop requested.")
            self.worker.stop()
            self.stop_btn.setEnabled(False)

    def _run_finished(self, summary: dict[str, Any]) -> None:
        self._append_log(f"Finished: {summary.get('verdict')} - {summary.get('rationale')}")
        if summary.get("request_hex"):
            self._append_log(f"Request: {summary.get('request_hex')}")
        if summary.get("response_hex"):
            self._append_log(f"Response: {summary.get('response_hex')}")
        if summary.get("evidence_dir") and summary.get("evidence_dir") != "<output not saved>":
            self._append_log(f"Evidence: {summary.get('evidence_dir')}")
        self.stop_btn.setEnabled(False)
        self._refresh_validation_and_preview()

    def _worker_thread_finished(self) -> None:
        self.worker = None
        self.stop_btn.setEnabled(False)
        self._refresh_validation_and_preview()

    def closeEvent(self, event: Any) -> None:
        if self.worker and self.worker.isRunning():
            self._append_log("Window close requested; stopping active run.")
            self.worker.stop()
            if not self.worker.wait(5000):
                event.ignore()
                QMessageBox.warning(self, "Run still active", "The active run did not stop within 5 seconds. Stop it before closing.")
                return
            self.worker = None
        super().closeEvent(event)

    def _clear_results(self, *, keep_logs: bool) -> None:
        if not keep_logs:
            self.live_log.clear()
            self.transcript.clear()

    def _append_log(self, line: str) -> None:
        for part in str(line).splitlines() or [""]:
            escaped = html.escape(part)
            lower = part.lower()
            if "positive" in lower or "pass" in lower or "unlocked/observed" in lower:
                color = "#6EE7B7"
            elif "negative" in lower or "nrc" in lower or "7f " in lower:
                color = "#FBBF24"
            elif "fail" in lower or "finding" in lower or "error" in lower or "validation" in lower:
                color = "#F87171"
            elif "can tx" in lower or "uds tx" in lower:
                color = "#93C5FD"
            elif "can rx" in lower or "uds rx" in lower:
                color = "#C4B5FD"
            else:
                color = "#E5E7EB"
            self.live_log.append(f'<span style="color:{color}; white-space:pre-wrap;">{escaped}</span>')

    def _append_transcript(self, line: str) -> None:
        self.transcript.append(str(line))

    def _append_parsed_row(self, row: dict[str, Any]) -> None:
        step = row.get("step", "")
        request = row.get("request_hex", row.get("service_id", row.get("did_hex", "")))
        response = row.get("response_hex", row.get("response_raw", row.get("raw_response_hex", "")))
        nrc = row.get("nrc", "")
        meaning = row.get("nrc_meaning", row.get("service_name_if_known", ""))
        note = row.get("note", row.get("notes", ""))
        status = "negative" if row.get("negative_response") else "positive" if row.get("positive_response") else row.get("response_type", "")
        self._append_log(f"PARSED {step} | {status} | req={request} | resp={response} | nrc={nrc} {meaning} | {note}")

    def _clear_log_views(self) -> None:
        self.live_log.clear()
        self.transcript.clear()

    def _browse_output_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select evidence output directory", self.output_dir.text())
        if path:
            self.output_dir.setText(path)

    def _load_did_catalog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Load DID catalog", self.output_dir.text(), "DID Catalog (*.json *.csv *.txt);;All files (*)")
        if not path:
            return
        catalog_path = Path(path)
        rows: list[dict[str, Any]] = []
        try:
            if catalog_path.suffix.lower() == ".json":
                data = json.loads(catalog_path.read_text(encoding="utf-8"))
                rows = data if isinstance(data, list) else data.get("did_catalog", [])
            elif catalog_path.suffix.lower() == ".csv":
                with catalog_path.open("r", newline="", encoding="utf-8") as fh:
                    rows = list(csv.DictReader(fh))
            else:
                for line in catalog_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip():
                        rows.append({"Notes": line.strip()})
        except Exception as exc:
            QMessageBox.warning(self, "DID catalog error", str(exc))
            return
        rows, summary = normalize_did_catalog_rows(rows, source="csv")
        try:
            normalized_path = catalog_path.with_name("parsed_did_catalog.csv")
            with normalized_path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=["DID", "Length", "Message DID", "Notes", "Source", "Parse Status", "Parse Error"], extrasaction="ignore")
                writer.writeheader()
                writer.writerows(rows)
            summary["parsed_did_catalog_csv"] = str(normalized_path)
        except Exception as exc:
            self._append_log(f"DID catalog normalization export warning: {type(exc).__name__}: {exc}")
        self.did_catalog_rows = rows
        self.did_catalog_table.setRowCount(0)
        for row in rows:
            idx = self.did_catalog_table.rowCount()
            self.did_catalog_table.insertRow(idx)
            self.did_catalog_table.setItem(idx, 0, QTableWidgetItem(str(row.get("did", ""))))
            self.did_catalog_table.setItem(idx, 1, QTableWidgetItem(str(row.get("length", ""))))
            self.did_catalog_table.setItem(idx, 2, QTableWidgetItem(str(row.get("message_hex", ""))))
            self.did_catalog_table.setItem(idx, 3, QTableWidgetItem(str(row.get("raw_note") or row.get("source", ""))))
        self.did_catalog_table.resizeColumnsToContents()
        self._append_log(
            f"Loaded DID catalog: {catalog_path} ({summary.get('normalized_dids', 0)} normalized DID rows, "
            f"{summary.get('known_length_dids', 0)} with known length, {summary.get('failed_parse_rows', 0)} failed parse)"
        )

    def _use_selected_did(self) -> None:
        row = self.did_catalog_table.currentRow()
        if row < 0 or row >= len(self.did_catalog_rows):
            return
        item = normalize_did_catalog_row(self.did_catalog_rows[row])
        did = str(item.get("did", "")).strip()
        length = str(item.get("length") or "").strip()
        message_hex = str(item.get("message_hex") or "").strip()
        length_source = str(item.get("length_source") or "unknown").strip()

        if did and "did_hex" in self.field_widgets and isinstance(self.field_widgets["did_hex"], QLineEdit):
            self.field_widgets["did_hex"].setText(did)

        if self.current_test.id == "uds_21":
            if "data_length_bytes" in self.field_widgets:
                widget = self.field_widgets["data_length_bytes"]
                if isinstance(widget, QLineEdit):
                    widget.setText(length)
            if "did_length_source" in self.field_widgets and isinstance(self.field_widgets["did_length_source"], QLineEdit):
                self.field_widgets["did_length_source"].setText(length_source)
            if "catalog_length_bytes" in self.field_widgets and isinstance(self.field_widgets["catalog_length_bytes"], QLineEdit):
                self.field_widgets["catalog_length_bytes"].setText(length)
            if "catalog_message_hex" in self.field_widgets and isinstance(self.field_widgets["catalog_message_hex"], QTextEdit):
                self.field_widgets["catalog_message_hex"].setPlainText(message_hex)

        if self.current_test.id == "uds_22":
            if "did_length_bytes" in self.field_widgets:
                widget = self.field_widgets["did_length_bytes"]
                if isinstance(widget, QLineEdit):
                    widget.setText(length)
            if "did_message_hex" in self.field_widgets:
                widget = self.field_widgets["did_message_hex"]
                if isinstance(widget, QTextEdit):
                    widget.setPlainText(message_hex)
            if "did_length_source" in self.field_widgets and isinstance(self.field_widgets["did_length_source"], QLineEdit):
                self.field_widgets["did_length_source"].setText(length_source)
            if "catalog_length_bytes" in self.field_widgets and isinstance(self.field_widgets["catalog_length_bytes"], QLineEdit):
                self.field_widgets["catalog_length_bytes"].setText(length)

        self._append_log(f"Selected DID {did or '<unknown>'}; length={length or '<unknown>'}; message={message_hex or '<empty>'}")
        self._refresh_validation_and_preview()


def _assert_raises(fn: Callable[[], Any], expected_text: str) -> None:
    try:
        fn()
    except Exception as exc:
        if expected_text not in str(exc):
            raise AssertionError(f"expected error containing {expected_text!r}, got {exc!r}") from exc
        return
    raise AssertionError(f"expected exception containing {expected_text!r}")


def default_params_for_test(test: TestDefinition) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for field_spec in test.fields:
        params[field_spec.id] = field_spec.default
    if test.id == "uds_21":
        params.update({"data_generation": "explicit", "data_length_bytes": "4", "data_hex": "AA BB CC DD"})
    return params


def run_self_checks() -> None:
    assert spaced(build_uds21_request({
        "did_hex": "0xF190",
        "data_generation": "explicit",
        "data_length_bytes": "4",
        "data_hex": "AA BB CC DD",
    })) == "2E F1 90 AA BB CC DD"
    assert len(build_uds21_request({
        "did_hex": "0xF190",
        "data_generation": "random",
        "data_length_bytes": "4",
        "random_seed": "1",
    })[3:]) == 4
    _assert_raises(lambda: build_uds21_request({
        "did_hex": "0xF190",
        "data_generation": "explicit",
        "data_length_bytes": "4",
        "data_hex": "AA BB",
    }), "data_hex length")
    _assert_raises(lambda: build_uds21_request({
        "did_hex": "0xF190",
        "data_generation": "explicit",
        "data_hex": "C",
    }), "full bytes")
    parsed_note = parse_did_note("0xfad3 ffff0005")
    assert parsed_note.did == "0xFAD3" and parsed_note.message_hex == "FF FF 00 05" and parsed_note.length == 4 and parsed_note.parse_status == "parsed"
    parsed_note = parse_did_note("0xFAD3 FF FF 00 05")
    assert parsed_note.did == "0xFAD3" and parsed_note.message_hex == "FF FF 00 05" and parsed_note.length == 4
    parsed_note = parse_did_note("FAD3")
    assert parsed_note.did == "0xFAD3" and parsed_note.length is None and parsed_note.parse_status == "parsed_no_message"
    parsed_note = parse_did_note("0xFAD3; message=ffff0005")
    assert parsed_note.did == "0xFAD3" and parsed_note.message_hex == "FF FF 00 05" and parsed_note.length == 4
    assert parse_did_note("bad data").parse_status == "invalid"
    normalized = normalize_did_catalog_row({"DID": "0xFAD3", "Length": "", "Message DID": "", "Notes": "0xfad3 ffff0005"})
    assert normalized["DID"] == "0xFAD3" and str(normalized["Length"]) == "4" and normalized["Message DID"] == "FF FF 00 05"
    normalized = normalize_did_catalog_row({"DID": "", "Length": "", "Message DID": "", "Notes": "0xfad3 ffff0005"})
    assert normalized["DID"] == "0xFAD3" and str(normalized["Length"]) == "4" and normalized["Message DID"] == "FF FF 00 05"
    assert spaced(build_uds21_request({
        "did_hex": "0xFAD3",
        "data_generation": "random",
        "data_length_bytes": "4",
        "random_payload_hex": "DC 41 80 88",
    })) == "2E FA D3 DC 41 80 88"

    assert spaced(build_uds22_request({"did_hex": "0xF190"})) == "22 F1 90"
    assert spaced(build_uds22_request({"did_hex": "0xFAD3"})) == "22 FA D3"

    uds23_candidates = build_memory_security_gate_probe_requests(0x34)
    assert [spaced(candidate.request) for candidate in uds23_candidates] == [
        "34 00 44 00 00 00 00 00 00 00 01",
        "34 00 24 00 00 00 00 00 01",
        "34 00 22 00 00 00 01",
    ]
    uds24_candidates = build_memory_security_gate_probe_requests(0x35)
    assert [spaced(candidate.request) for candidate in uds24_candidates] == [
        "35 00 44 00 00 00 00 00 00 00 01",
        "35 00 24 00 00 00 00 00 01",
        "35 00 22 00 00 00 01",
    ]
    assert "DFI 0x00" in uds23_candidates[0].annotation and "ALFI 0x44" in uds23_candidates[0].annotation
    assert decode_alfi(0x44) == (4, 4)
    assert decode_alfi(0x24) == (4, 2)
    manual_uds23 = build_manual_memory_transfer_request(
        0x34,
        0x00,
        0x44,
        bytes.fromhex("00 00 00 00"),
        bytes.fromhex("00 00 00 01"),
    )
    assert spaced(manual_uds23.request) == "34 00 44 00 00 00 00 00 00 00 01"
    manual_uds24 = build_manual_memory_transfer_request(
        0x35,
        0x00,
        0x44,
        bytes.fromhex("00 00 00 00"),
        bytes.fromhex("00 00 00 01"),
    )
    assert spaced(manual_uds24.request) == "35 00 44 00 00 00 00 00 00 00 01"
    _assert_raises(lambda: build_manual_memory_transfer_request(
        0x34,
        0x00,
        0x44,
        bytes.fromhex("00 00"),
        bytes.fromhex("00 00 00 01"),
    ), "requires 4 address bytes and 4 size bytes")

    assert spaced(build_uds25_request({
        "control_type": "0x01",
        "communication_type": "0x01",
    })) == "28 01 01"
    assert spaced(build_communication_control_restore_request({"communication_type": "0x01"})) == "28 00 01"

    positive = parse_uds_response(bytes.fromhex("22 F1 90"), bytes.fromhex("62 F1 90 12 34"))
    assert positive.positive_response and not positive.negative_response and not positive.malformed

    negative = parse_uds_response(bytes.fromhex("22 F1 90"), bytes.fromhex("7F 22 33"))
    assert negative.negative_response and negative.nrc == 0x33 and negative.nrc_meaning == "securityAccessDenied"

    no_response_verdict, _ = verdict_rdbi(bytes.fromhex("22 F1 90"), None, {"sensitive_did": False}, [])
    assert no_response_verdict == VERDICT_NEED_MANUAL_REVIEW

    unrelated = parse_uds_response(bytes.fromhex("22 F1 90"), bytes.fromhex("7F 10 33"))
    assert unrelated.malformed and not unrelated.negative_response
    malformed_verdict, _ = verdict_rdbi(bytes.fromhex("22 F1 90"), bytes.fromhex("7F 10 33"), {"sensitive_did": False}, [])
    assert malformed_verdict == VERDICT_NEED_MANUAL_REVIEW
    unexpected_sid_verdict, _ = verdict_rdbi(bytes.fromhex("22 F1 90"), bytes.fromhex("61 F1 90"), {"sensitive_did": False}, [])
    assert unexpected_sid_verdict == VERDICT_NEED_MANUAL_REVIEW

    potential_verdict, _ = verdict_rdbi(bytes.fromhex("22 F1 90"), bytes.fromhex("62 F1 90 12 34"), {"sensitive_did": False}, [])
    assert potential_verdict == VERDICT_FAIL_READABLE_WITHOUT_SECURITY
    uds21_verdict, _ = verdict_wdbi(bytes.fromhex("2E FA D3 DC 41 80 88"), bytes.fromhex("6E FA D3"), {}, [])
    assert uds21_verdict == VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY
    uds21_verdict, _ = verdict_wdbi(bytes.fromhex("2E FA D3 DC 41 80 88"), bytes.fromhex("7F 2E 33"), {}, [])
    assert uds21_verdict == VERDICT_PASS_SECURITY_GATE
    uds22_verdict, _ = verdict_rdbi(bytes.fromhex("22 FA D3"), bytes.fromhex("62 FA D3 01 02"), {}, [])
    assert uds22_verdict == VERDICT_FAIL_READABLE_WITHOUT_SECURITY
    uds22_verdict, _ = verdict_rdbi(bytes.fromhex("22 FA D3"), bytes.fromhex("7F 22 33"), {}, [])
    assert uds22_verdict == VERDICT_PASS_SECURITY_GATE
    assert security_access_observed_before_target([
        {"request_hex": "10 03"},
        {"request_hex": "27 01"},
        {"request_hex": "2E FA D3 DC 41 80 88"},
    ], 0x2E)
    no_response_reset, _ = verdict_reset(bytes.fromhex("11 01"), None, {}, [])
    assert no_response_reset == VERDICT_INCONCLUSIVE
    uds20_params = {"acceptable_nrcs": "0x22 0x24 0x31 0x33 0x7E 0x7F"}
    uds20_verdict, _, _ = classify_uds20_reset_response(bytes.fromhex("11 03"), bytes.fromhex("7F 11 33"), uds20_params)
    assert uds20_verdict == VERDICT_PASS_EXPECTED_DENIAL
    uds20_verdict, _, _ = classify_uds20_reset_response(bytes.fromhex("11 03"), bytes.fromhex("51 03"), uds20_params)
    assert uds20_verdict == VERDICT_FAIL_PRECONDITION_BYPASS
    uds20_verdict, _, _ = classify_uds20_reset_response(bytes.fromhex("11 03"), None, uds20_params, "timeout")
    assert uds20_verdict == VERDICT_INCONCLUSIVE_NO_RESPONSE
    memory_verdict, _, _, _ = classify_memory_transfer_probe_response(0x34, uds23_candidates[0].request, bytes.fromhex("7F 34 33"))
    assert memory_verdict == VERDICT_PASS_SECURITY_GATE
    memory_verdict, _, _, _ = classify_memory_transfer_probe_response(0x34, uds23_candidates[0].request, bytes.fromhex("74 20 00"))
    assert memory_verdict == VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY
    memory_verdict, _, decisive, _ = classify_memory_transfer_probe_response(0x34, uds23_candidates[0].request, bytes.fromhex("7F 34 31"))
    assert memory_verdict == VERDICT_INCONCLUSIVE_RANGE_CHECKED_FIRST and not decisive
    memory_verdict, _, _, _ = classify_memory_transfer_probe_response(0x35, uds24_candidates[0].request, bytes.fromhex("7F 35 11"))
    assert memory_verdict == VERDICT_SERVICE_NOT_SUPPORTED
    memory_verdict, _, _, _ = classify_memory_transfer_probe_response(0x35, uds24_candidates[0].request, bytes.fromhex("75 20 00"))
    assert memory_verdict == VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY
    memory_verdict, _, _, _ = classify_memory_transfer_probe_response(0x34, manual_uds23.request, bytes.fromhex("7F 34 33"))
    assert memory_verdict == VERDICT_PASS_SECURITY_GATE
    memory_verdict, _, _, _ = classify_memory_transfer_probe_response(0x35, manual_uds24.request, bytes.fromhex("75 20 00"))
    assert memory_verdict == VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY

    comm_verdict, _, _ = classify_communication_control_response(bytes.fromhex("28 01 01"), bytes.fromhex("68 01"))
    assert comm_verdict == VERDICT_FAIL_ACCEPTED_WITHOUT_SECURITY
    comm_verdict, _, _ = classify_communication_control_response(bytes.fromhex("28 01 01"), bytes.fromhex("7F 28 33"))
    assert comm_verdict == VERDICT_PASS_SECURITY_GATE
    comm_verdict, _, _ = classify_communication_control_response(bytes.fromhex("28 01 01"), bytes.fromhex("7F 28 31"))
    assert comm_verdict == VERDICT_PARAMETER_UNSUPPORTED
    assert security_access_observed_before_target([
        {"request_hex": "10 03"},
        {"request_hex": "27 01"},
        {"request_hex": "34 00 44 00 00 00 00 00 00 00 01"},
    ], 0x34)

    def mk_target(*, dry_run: bool, authorized: bool, output_dir: Path = DEFAULT_EVIDENCE_DIR) -> TargetProfile:
        return TargetProfile("socketcan", "can0", 0x681, 0x601, False, 0x00, 1.0, 5.0, 0.05, 0.0, 3.0, output_dir, True, dry_run, authorized)

    uds20_test = next(t for t in build_registry() if t.id == "uds_20")
    assert [field.id for field in uds20_test.fields] == ["precondition_session_flow", "test_session_flow", "reset_subfunction", "acceptable_nrcs"]
    assert sum(1 for field in uds20_test.fields if field.visible_if is None) == 3
    equal_flow_errors = validate_uds20(mk_target(dry_run=True, authorized=False), default_params_for_test(uds20_test) | {"precondition_session_flow": "03", "test_session_flow": "03"})
    assert equal_flow_errors["test_session_flow"] == "Invalid UDS-20 setup: test_session_flow must differ from precondition_session_flow."

    target_dry = mk_target(dry_run=True, authorized=False)

    registry = {t.id: t for t in build_registry()}
    for test_id in ("recon_discovery", "recon_services", "recon_did_dump", "recon_subservices"):
        test_def = registry[test_id]
        params = default_params_for_test(test_def)
        argv = command_argv_for(test_def, target_dry, params)
        assert command_preview_from_argv(argv) == " ".join(argv)

    try:
        from uds_toolkit.isotp import IsoTp
    except Exception as exc:
        raise AssertionError(f"failed to import IsoTp for mapping check: {exc}") from exc

    class FakeCan:
        class Message:
            def __init__(self, arbitration_id: int, data: bytes, is_extended_id: bool = False) -> None:
                self.arbitration_id = arbitration_id
                self.data = data
                self.is_extended_id = is_extended_id

    class FakeBus:
        def send(self, msg: Any) -> None:
            self.last_sent = msg

    transport = IsoTp(FakeBus(), FakeCan, txid=target_dry.tester_tx_id, rxid=target_dry.tester_rx_id)
    assert transport.txid == 0x681 and transport.rxid == 0x601

    registry_list = build_registry()
    ids = [test.id for test in registry_list]
    assert len(ids) == len(set(ids))
    blocked_grouped_ids = {
        "uds_27_" + "behavior" + "_probe",
        "security_access_" + "behavior" + "_probe",
        "same_session_" + "sampler",
        "first_seed_" + "sampler",
    }
    assert not any(test_id in ids for test_id in blocked_grouped_ids)
    for test_id in [f"uds_{i}" for i in range(10, 20)]:
        assert test_id in ids, f"{test_id} not registered"
    for test_id in [f"uds_{i}" for i in range(26, 33)]:
        assert test_id in ids, f"{test_id} not registered"
        reg_entry = next((test for test in registry_list if test.id == test_id), None)
        assert reg_entry is not None
        if test_id == "uds_26":
            assert reg_entry.runner_kind == "diagnostic_service"
            subfunction_field = next(field for field in reg_entry.fields if field.id == "subfunction")
            assert [choice.value for choice in subfunction_field.choices] == ["0x01", "0x02", "0x81", "0x82"]
            assert subfunction_field.default == "0x01"
            assert reg_entry.display_id == "UDS-26"
            assert reg_entry.canonical_id == "uds26_unauthenticated_control_dtc_setting"
        elif test_id == "uds_27":
            assert reg_entry.runner_kind == "diagnostic_service"
            group_field = next(field for field in reg_entry.fields if field.id == "group_of_dtc_preset")
            assert [choice.value for choice in group_field.choices] == ["all", "custom"]
            assert reg_entry.display_id == "UDS-27"
            assert reg_entry.canonical_id == "uds27_unauthenticated_clear_diagnostic_information"
            assert reg_entry.disruptive
        else:
            assert reg_entry.runner_kind == "modular_stub"
        assert reg_entry.category == "UDS-26..32 Framework"
    for test_def in registry_list:
        assert test_def.objective
        assert isinstance(test_def.fields, tuple)
        assert test_def.parser is not None
        assert test_def.verdict_rules is not None
        assert test_def.evidence_fields
        assert test_def.case_model["case_id"] == test_def.id
        assert test_def.pass_criteria
        assert test_def.fail_criteria
        assert test_def.summary_template

    reg = {t.id: t for t in registry_list}
    for test_id in ("uds_23", "uds_24"):
        mode_field = next(field for field in reg[test_id].fields if field.id == "probe_mode")
        assert [choice.label for choice in mode_field.choices] == ["Security Gate Probe", "Advanced Manual Request"]
    manual_params = default_params_for_test(reg["uds_23"]) | {
        "probe_mode": "advanced_manual_request",
        "data_format_identifier": "0x00",
        "address_length_format_identifier": "0x44",
        "memory_address_hex": "00 00 00 00",
        "memory_size_hex": "00 00 00 01",
    }
    manual_candidate = memory_transfer_request_candidates(0x34, manual_params)[0]
    assert spaced(manual_candidate.request) == "34 00 44 00 00 00 00 00 00 00 01"
    manual_worker = RunWorker(reg["uds_23"], mk_target(dry_run=True, authorized=False), manual_params, "")
    manual_evidence = manual_worker._memory_security_gate_evidence(manual_candidate)
    assert manual_evidence["dfi"] == "0x00" and manual_evidence["alfi"] == "0x44"
    assert manual_evidence["memory_address"] == "00 00 00 00" and manual_evidence["memory_size"] == "00 00 00 01"
    manual_summary = manual_worker._dry_run(EvidenceWriter(Path(tempfile.mkdtemp()), reg["uds_23"], manual_worker.target, manual_params))
    assert manual_summary["mode"] == "Advanced Manual Request"
    assert manual_summary["request_hex"] == "34 00 44 00 00 00 00 00 00 00 01"
    assert manual_summary["transfer_data_statement"] == "TransferData 0x36 was not sent."
    assert manual_summary["request_transfer_exit_statement"] == "RequestTransferExit 0x37 was not sent."
    assert len([s for s in security_access_plan("uds_10", default_params_for_test(reg["uds_10"])) if "request_seed" in s["step"]]) == 10
    uds11_plan = security_access_plan("uds_11", default_params_for_test(reg["uds_11"]))
    assert len([s for s in uds11_plan if "request_seed" in s["step"]]) == 20
    assert not any("send_key" in s["step"] for s in uds11_plan)
    seed_csv_dir = Path(tempfile.mkdtemp())
    seed_csv = seed_csv_dir / "seed_samples.csv"
    seed_csv.write_text("seed_hex\nAA BB CC DD\n01 02\n", encoding="utf-8")
    assert load_seed_lengths_from_csv(seed_csv) == [4, 2]
    length_verdict, _ = verdict_seed_length({"total_seed_samples": 2, "min_seed_length": 2, "max_seed_length": 8, "short_seed_count": 1, "empty_seed_count": 0}, {"minimum_seed_length_bytes": "4", "recommended_seed_length_bytes": "8"})
    assert length_verdict == "FAIL/FINDING"
    limit_verdict, _ = verdict_requestseed_limit({"continuous_seed_after_threshold": True, "nrc36_count": 0, "nrc37_count": 0, "nrc24_count": 0}, {"enforcement_expected_after_count": "5"})
    assert limit_verdict == "FAIL/SUSPICIOUS"
    assert any(s["step"] == "stale_seed_wait" for s in security_access_plan("uds_14", default_params_for_test(reg["uds_14"])))
    assert len([s for s in security_access_plan("uds_16", default_params_for_test(reg["uds_16"])) if "send_key_attempt" in s["step"]]) == 5
    assert len([s for s in security_access_plan("uds_17", default_params_for_test(reg["uds_17"])) if "request_seed" in s["step"]]) == 5
    assert any(s["step"] == "penalty_probe_request_seed" for s in security_access_plan("uds_18", default_params_for_test(reg["uds_18"])))
    assert any(s["step"] == "capture_extra_seed_responses" for s in security_access_plan("uds_19", default_params_for_test(reg["uds_19"])))
    uds19_verdict, _ = verdict_security_behavior("uds_19", [], {}, {"total_positive_seed_responses": 2})
    assert uds19_verdict == "FAIL/SUSPICIOUS"
    assert nrc_to_text(0x7F) == "serviceNotSupportedInActiveSession"
    assert nrc_to_text(0x7E) == "subFunctionNotSupportedInActiveSession"
    valid_policy_params = default_params_for_test(reg["uds_16"])
    valid_policy_params["key_policy"] = "valid_algorithm_if_available"
    assert "key_policy" in RunWorker(reg["uds_16"], mk_target(dry_run=True, authorized=False), valid_policy_params, "")._preflight_errors()

    report_dir = Path(tempfile.mkdtemp())
    dry_summary_target = mk_target(dry_run=True, authorized=False, output_dir=report_dir)
    dry_worker = RunWorker(registry["uds_22"], dry_summary_target, default_params_for_test(registry["uds_22"]), "UDS request: 22 F1 90")
    dry_worker.run()
    run_dir = next(report_dir.iterdir())
    summary_md = (run_dir / "summary.md").read_text(encoding="utf-8")
    assert "Verdict" in summary_md and "Rationale" in summary_md and "Request sent" in summary_md and "Response received" in summary_md
    summary_json = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary_json["verdict"] == "DRY_RUN / NOT_EXECUTED"
    assert (run_dir / "summary.md").exists() and (run_dir / "summary.json").exists()

    did_dir = Path(tempfile.mkdtemp())
    did_parsed = parse_did_dump_output("0xF190 62 F1 90 11 22 33 44", did_dir)
    did_row = did_parsed["did_catalog"][0]
    assert did_row["did_hex"] == "0xF190" and str(did_row["did_length_bytes"]) == "4" and did_row["did_message_hex"] == "11 22 33 44"
    csv_header = (did_dir / "did_catalog.csv").read_text(encoding="utf-8").splitlines()[0]
    assert csv_header.startswith("DID,Length,Message DID")

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    gui = UdsReconGui()
    gui.category.setCurrentText("UDS Test Cases")
    for expected_id in ("uds_23", "uds_24"):
        for i in range(gui.test_dropdown.count()):
            if gui.test_dropdown.itemData(i) == expected_id:
                gui.test_dropdown.setCurrentIndex(i)
                break
        assert not gui.dry_run.isChecked()
    gui.category.setCurrentText("UDS-26..32 Framework")
    assert gui.test_dropdown.count() == 7
    first_future_id = gui.test_dropdown.itemData(0)
    assert first_future_id == "uds_26"
    assert gui.tests_by_id[first_future_id].runner_kind == "diagnostic_service"
    assert "subfunction" in {field.id for field in gui.tests_by_id[first_future_id].fields}
    uds26_runner = make_modular_runner("diagnostic_service")
    uds26_case_model = normalize_case_model(registry["uds_26"].case_model)
    raw_errors = uds26_runner.validate(
        uds26_case_model,
        default_params_for_test(registry["uds_26"]) | {"raw_payload_override": "28 00"},
        SafetyGuard.from_mapping(registry["uds_26"].safety_guard),
    )
    assert "must start with service 0x85" in raw_errors["request_payload"]
    suppress_payload = uds26_runner.build_payload(uds26_case_model, default_params_for_test(registry["uds_26"]) | {"subfunction": "0x81"})
    assert spaced(suppress_payload) == "85 81"
    assert uds26_runner.suppress_positive_response_requested(suppress_payload)
    suppress_result = uds26_runner.classify_response(
        positive=False,
        negative=False,
        response_type="timeout",
        parameters=default_params_for_test(registry["uds_26"]) | {"subfunction": "0x81"},
        suppress_positive_response_requested=True,
    )
    assert suppress_result.verdict == "OBSERVATION"
    uds27_case_model = normalize_case_model(registry["uds_27"].case_model)
    uds27_params = default_params_for_test(registry["uds_27"])
    assert spaced(uds26_runner.build_payload(uds27_case_model, uds27_params)) == "14 FF FF FF"
    assert uds26_runner.selected_group_of_dtc(uds26_runner.build_payload(uds27_case_model, uds27_params)) == "FF FF FF"
    raw_uds27_errors = uds26_runner.validate(
        uds27_case_model,
        uds27_params | {"raw_payload_override": "14 FF FF FF FF", "advanced_raw_payload_override_enabled": False},
        SafetyGuard.from_mapping(registry["uds_27"].safety_guard),
    )
    assert "requires advanced_raw_payload_override_enabled=true" in raw_uds27_errors["request_payload"]
    raw_uds27_advanced = uds26_runner.validate(
        uds27_case_model,
        uds27_params | {"raw_payload_override": "14 FF FF FF FF", "advanced_raw_payload_override_enabled": True},
        SafetyGuard.from_mapping(registry["uds_27"].safety_guard),
    )
    assert raw_uds27_advanced == {}
    group_errors = uds26_runner.validate(
        uds27_case_model,
        uds27_params | {"group_of_dtc_preset": "custom", "group_of_dtc": "FF FF"},
        SafetyGuard.from_mapping(registry["uds_27"].safety_guard),
    )
    assert "exactly 3 bytes" in group_errors["request_payload"]
    uds26_dir = Path(tempfile.mkdtemp())
    uds26_target = mk_target(dry_run=True, authorized=False, output_dir=uds26_dir)
    uds26_test = registry["uds_26"]
    uds26_params = default_params_for_test(uds26_test)
    uds26_worker = RunWorker(uds26_test, uds26_target, uds26_params, "")
    uds26_worker.run()
    assert uds26_worker._process is None
    assert uds26_worker._opened_buses == []
    uds26_run_dir = next(uds26_dir.iterdir())
    uds26_summary = json.loads((uds26_run_dir / "summary.json").read_text(encoding="utf-8"))
    assert uds26_summary["request_hex"] == "85 01"
    assert uds26_summary["display_id"] == "UDS-26"
    assert uds26_summary["canonical_id"] == "uds26_unauthenticated_control_dtc_setting"
    assert uds26_summary["evidence_record"]["selected_subfunction_meaning"] == "enable DTC setting"
    assert uds26_summary["evidence_record"]["suppress_positive_response_requested"] is False
    assert uds26_summary["verdict"] == "DRY_RUN / NOT_EXECUTED"
    uds27_dir = Path(tempfile.mkdtemp())
    uds27_target = mk_target(dry_run=True, authorized=False, output_dir=uds27_dir)
    uds27_test = registry["uds_27"]
    uds27_worker = RunWorker(uds27_test, uds27_target, uds27_params, "")
    uds27_worker.run()
    assert uds27_worker._process is None
    assert uds27_worker._opened_buses == []
    uds27_run_dir = next(uds27_dir.iterdir())
    uds27_summary = json.loads((uds27_run_dir / "summary.json").read_text(encoding="utf-8"))
    assert uds27_summary["request_hex"] == "14 FF FF FF"
    assert uds27_summary["display_id"] == "UDS-27"
    assert uds27_summary["canonical_id"] == "uds27_unauthenticated_clear_diagnostic_information"
    assert uds27_summary["evidence_record"]["selected_group_of_dtc"] == "FF FF FF"
    assert uds27_summary["evidence_record"]["group_of_dtc_meaning"] == "all DTC groups"
    placeholder_dir = Path(tempfile.mkdtemp())
    placeholder_target = mk_target(dry_run=False, authorized=False, output_dir=placeholder_dir)
    placeholder_test = registry["uds_28"]
    placeholder_params = default_params_for_test(placeholder_test)
    placeholder_worker = RunWorker(placeholder_test, placeholder_target, placeholder_params, "")
    placeholder_worker.run()
    assert placeholder_worker._process is None
    assert placeholder_worker._opened_buses == []
    placeholder_run_dir = next(placeholder_dir.iterdir())
    placeholder_summary = json.loads((placeholder_run_dir / "summary.json").read_text(encoding="utf-8"))
    assert placeholder_summary["verdict"] == "NOT_IMPLEMENTED / STUB"
    assert placeholder_summary["placeholder_evidence_record"]["response_payload"] == ""


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-check":
        run_self_checks()
        print("self-checks passed")
        return 0
    app = QApplication(sys.argv)
    win = UdsReconGui()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
