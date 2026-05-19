from __future__ import annotations

from typing import Dict, Type

from .cases.security_access import SecurityAccessCase
from .cases.samplers import SeedSamplerCrossSession, SeedSamplerSameSession
from .cases.fuzzing import ArbIdFuzzer, PayloadFuzzer, ServiceFuzzer, SubserviceFuzzer
from .cases.access_control import UdsAccessControlProbe


CASE_REGISTRY = {
    "security_access": SecurityAccessCase,
    "seed_sampler_same_session": SeedSamplerSameSession,
    "seed_sampler_cross_session": SeedSamplerCrossSession,
    "service_fuzzer": ServiceFuzzer,
    "subservice_fuzzer": SubserviceFuzzer,
    "payload_fuzzer": PayloadFuzzer,
    "arb_id_fuzzer": ArbIdFuzzer,
    "uds_access_control_probe": UdsAccessControlProbe,
}


def make_case(case_type: str):
    try:
        return CASE_REGISTRY[case_type]()
    except KeyError as exc:
        known = ", ".join(sorted(CASE_REGISTRY))
        raise ValueError(f"unknown testcase type '{case_type}'. Known types: {known}") from exc
