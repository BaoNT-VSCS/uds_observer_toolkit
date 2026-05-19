from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretCase:
    seed_subfn: int
    key_subfn: int
    level: int
    secret: bytes


# Kept as a lab/profile provider, not as a generic OEM unlock mechanism.
# The runner only uses it when key_policy='valid' or 'invalid-bitflip' is explicitly selected.
BMS_PROFILE = {
    0x01: SecretCase(0x01, 0x02, 1, bytes.fromhex("0ABA22106938B4C7")),
    0x03: SecretCase(0x03, 0x04, 3, bytes.fromhex("0ABA2210592DE49E")),
    0x05: SecretCase(0x05, 0x06, 5, bytes.fromhex("0ABA221074828D34")),
    0x07: SecretCase(0x07, 0x08, 7, bytes.fromhex("0ABA22109DA0C3B8")),
}


def default_send_key_subfn(seed_subfn: int) -> int:
    return (seed_subfn + 1) & 0xFF


def case_for_seed_subfn(seed_subfn: int) -> SecretCase:
    try:
        return BMS_PROFILE[seed_subfn]
    except KeyError as exc:
        raise ValueError(f"no BMS seed-key profile for RequestSeed sub-function 0x{seed_subfn:02X}") from exc


def compute_bms_key(seed: bytes, seed_subfn: int) -> bytes:
    case = case_for_seed_subfn(seed_subfn)
    return hmac.new(case.secret, seed, hashlib.sha1).digest()[:16]


def resolve_key(*, seed: bytes | None, seed_subfn: int, policy: str, explicit_key: bytes | None = None, pattern_byte: int = 0xAA) -> tuple[bytes, str]:
    if policy == "explicit":
        if explicit_key is None:
            raise ValueError("key_policy=explicit requires key_hex")
        return explicit_key, "explicit key"
    if policy == "zero":
        return bytes(16), "16 zero bytes"
    if policy == "pattern":
        return bytes([pattern_byte & 0xFF] * 16), f"16 repeated 0x{pattern_byte:02X}"
    if policy == "format-random":
        import os
        fake_seed = os.urandom(16)
        return compute_bms_key(fake_seed, seed_subfn), "format-correct BMS key from random fake seed"
    if policy == "valid":
        if seed is None:
            raise ValueError("valid key policy requires ECU seed")
        return compute_bms_key(seed, seed_subfn), "valid key from ECU seed"
    if policy == "invalid-bitflip":
        if seed is None:
            raise ValueError("invalid-bitflip policy requires ECU seed")
        key = bytearray(compute_bms_key(seed, seed_subfn))
        key[-1] ^= 0x01
        return bytes(key), "valid key with last bit flipped"
    raise ValueError(f"unsupported key policy: {policy}")
