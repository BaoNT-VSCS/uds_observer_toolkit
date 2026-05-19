from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List, Sequence


HEX_SEPARATORS_RE = re.compile(r"[\s,:;_\-]+")


def parse_hex_int(value: object) -> int:
    """Parse an integer where plain strings are treated as hex by default.

    Examples: 0x7E0, 7E0, "7e0", 2016 all work. This behaviour matches
    the original one-file scripts and avoids accidental decimal interpretation
    of CAN IDs such as 681/601.
    """
    if isinstance(value, int):
        return value
    text = str(value).strip().replace("_", "")
    if not text:
        raise ValueError("empty hex integer")
    base = 16
    if text.lower().startswith("0x"):
        base = 16
    return int(text, base)


def parse_byte(value: object) -> int:
    n = parse_hex_int(value)
    if not 0 <= n <= 0xFF:
        raise ValueError(f"byte out of range 0x00..0xFF: {value}")
    return n


def parse_can_id(value: object, *, extended: bool | None = None) -> int:
    n = parse_hex_int(value)
    if not 0 <= n <= 0x1FFFFFFF:
        raise ValueError(f"CAN ID out of range 0x000..0x1FFFFFFF: {value}")
    if extended is False and n > 0x7FF:
        raise ValueError(f"standard CAN ID must be <= 0x7FF: {value}; enable extended_id")
    return n


def hx(value: int, width: int = 2) -> str:
    return f"0x{value:0{width}X}"


def can_id_hx(value: int) -> str:
    return hx(value, 8 if value > 0x7FF else 3)


def bhex(data: bytes) -> str:
    return data.hex().upper()


def spaced(data: bytes | bytearray | Sequence[int]) -> str:
    return " ".join(f"{int(b) & 0xFF:02X}" for b in data)


def parse_hex_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        return bytes(parse_byte(x) for x in value)
    text = str(value or "").strip()
    if not text:
        return b""
    normalized = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(normalized) % 2:
        raise ValueError(f"hex byte string must have an even number of hex chars: {value}")
    return bytes.fromhex(normalized)


def parse_byte_list(value: object) -> List[int]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [parse_byte(v) for v in value]
    text = str(value).strip()
    if not text:
        return []
    return [parse_byte(tok) for tok in HEX_SEPARATORS_RE.split(text) if tok]


def parse_int_range(value: object, *, item_parser=parse_hex_int, max_items: int | None = None) -> List[int]:
    """Parse forms like '0x10-0x3E, 0x85, 0xA0-0xA2'.

    Ranges are inclusive. A hard max_items limit is used by fuzzers to avoid
    accidental full-bus scans from a typo.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        out: List[int] = []
        for item in value:
            out.extend(parse_int_range(item, item_parser=item_parser, max_items=max_items))
        return _limit(out, max_items)

    text = str(value).strip()
    if not text:
        return []
    out: List[int] = []
    for part in re.split(r"[\s,;]+", text):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start, end = item_parser(a), item_parser(b)
            if end < start:
                raise ValueError(f"invalid descending range: {part}")
            out.extend(range(start, end + 1))
        else:
            out.append(item_parser(part))
        _limit(out, max_items)
    return out


def _limit(items: List[int], max_items: int | None) -> List[int]:
    if max_items is not None and len(items) > max_items:
        raise ValueError(f"range expands to {len(items)} items; max allowed is {max_items}")
    return items


def ensure_dir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def pad8(data: Iterable[int], pad: int = 0x00) -> bytes:
    out = bytes(int(x) & 0xFF for x in data)
    if len(out) > 8:
        raise ValueError("CAN frame payload exceeds 8 bytes")
    return out + bytes([pad & 0xFF] * (8 - len(out)))
