# UDS Observer Toolkit

GUI-first, configuration-driven toolkit for observing UDS behaviour, SecurityAccess test cases, seed sampling, bounded fuzzing, and access-control validation of UDS services.

The intended workflow is simple: run one GUI file, load YAML test cases, select the required case, and execute in dry-run or authorized test mode.

```bash
cd uds_observer_toolkit
python3 uds_observer_gui.py
```

> Safety boundary: use this toolkit only on an ECU, simulator, bench, or vehicle that you are explicitly authorized to test. Destructive or disruptive UDS services must remain blocked unless the testcase is explicitly armed and the operator confirms authorization.

---

## 1. Main Features

- Single GUI entrypoint: `uds_observer_gui.py`
- YAML-driven testcase loading and reload from the GUI
- Reusable backend runner for GUI and CLI execution
- UDS request/response observation over ISO-TP on CAN
- SecurityAccess behaviour probes for UDS service `0x27`
- Same-session and cross-session seed sampling
- Bounded fuzzing/probing for arbitration IDs, services, sub-functions, and explicit payloads
- Section 10 access-control probes for sensitive services:
  - UDS-20: ECU Reset precondition check, service `0x11`
  - UDS-21: unauthenticated WriteDataByIdentifier, service `0x2E`
  - UDS-22: read sensitive DID without SecurityAccess, service `0x22`
  - UDS-23: unauthenticated RequestDownload, service `0x34`
  - UDS-24: unauthenticated RequestUpload, service `0x35`
  - UDS-25: unauthenticated CommunicationControl, service `0x28`
- Structured output for evidence:
  - `events.jsonl`
  - `summary.csv`

---

## 2. Project Layout

```text
uds_observer_toolkit/
├─ uds_observer_gui.py                  # Thin GUI compatibility entrypoint
├─ run_udstk.py                         # Backend CLI runner used by GUI
├─ requirements.txt
├─ configs/
│  └─ default.yaml                       # CAN, ISO-TP, target, timing defaults
├─ testcases/
│  ├─ security_access.yaml               # UDS 0x27 behaviour probes
│  ├─ seed_sampling.yaml                 # Same/cross-session seed sampling
│  ├─ fuzzing_basic.yaml                 # ArbID/service/subservice/payload probes
│  ├─ uds_section10_access_control.yaml  # UDS-20 to UDS-25 access-control probes
│  └─ uds_section11_robustness.yaml      # UDS-26 to UDS-32 placeholder metadata
├─ uds_toolkit/
│  ├─ canio.py                           # python-can bus setup
│  ├─ isotp.py                           # Minimal ISO-TP transport
│  ├─ uds.py                             # UDS client and response parsing
│  ├─ runner.py                          # Config-driven orchestration
│  ├─ registry.py                        # Testcase type registry
│  ├─ case_registry.py                    # UDS-26..32 modular metadata loader
│  ├─ case_runners.py                     # Future runner interfaces / stubs
│  ├─ evidence_schema.py                  # Shared evidence field schema
│  ├─ safety.py                           # Safety guard model
│  ├─ logging_utils.py                   # JSONL/CSV output helpers
│  ├─ seedkey.py                         # Lab SeedKey profile, if enabled
│  ├─ gui/
│  │  ├─ __init__.py
│  │  ├─ __main__.py
│  │  └─ app.py                          # GUI implementation
│  └─ cases/
│     ├─ security_access.py              # SecurityAccess testcases
│     ├─ samplers.py                     # Seed sampling testcases
│     ├─ fuzzing.py                      # Bounded probing/fuzzing testcases
│     └─ access_control.py               # Section 10 access-control testcase engine
├─ runs/                                 # Timestamped execution output
└─ legacy/                               # Original scripts kept for reference
```

---

## 3. Installation

```bash
cd uds_observer_toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

For virtual CAN testing:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type can
sudo ip link set up vcan0
```

If `vcan0` already exists:

```bash
sudo ip link set up vcan0
```

---

## 4. GUI Workflow

Run the GUI:

```bash
python3 uds_observer_gui.py
```

Recommended workflow:

1. Confirm the CAN channel, interface, TX ID, RX ID, and target profile.
2. Load or reload YAML files from `configs/` and `testcases/`.
3. Select one or more test cases.
4. Run **Dry run** first to validate the sequence without transmitting CAN frames.
5. Enable **I am authorized** only inside an approved lab, bench, simulator, or owned ECU setup.
6. For disruptive services, ensure the testcase itself has `destructive_confirm: true` before real transmission.
7. Click **Run selected** or **Run all**.
8. Review output under `runs/<timestamp>/`.

---

## 5. CLI Workflow

The GUI is the primary interface. The CLI remains available for automation and regression checks.

Dry-run all loaded testcases:

```bash
python3 run_udstk.py \
  -c configs/default.yaml \
  -c testcases/security_access.yaml \
  -c testcases/seed_sampling.yaml \
  -c testcases/fuzzing_basic.yaml \
  --dry-run
```

Run one selected testcase:

```bash
python3 run_udstk.py \
  -c configs/default.yaml \
  -c testcases/security_access.yaml \
  --case sa_key_without_seed \
  --show-process
```

Run bounded fuzzing or probing:

```bash
python3 run_udstk.py \
  -c configs/default.yaml \
  -c testcases/fuzzing_basic.yaml \
  --case fuzz_services_known_target \
  --yes-i-am-authorized \
  --show-process
```

---

## 6. Configuration Model

The toolkit is split into two configuration layers.

`configs/default.yaml` defines transport and target defaults:

```yaml
can:
  interface: socketcan
  channel: vcan0
  bitrate: 500000
  extended_id: false
  pad: 0x00

timing:
  request_timeout: 1.0
  inter_request_delay: 0.10
  drain_before_request: 0.02

targets:
  ecu1:
    txid: 0x7E0
    rxid: 0x7E8
    session_flow: [0x03]
```

`testcases/*.yaml` defines executable cases:

```yaml
testcases:
  - name: read_vin_without_security
    type: uds_access_control_probe
    target: ecu1
    session_flow: [0x03]
    destructive_confirm: false
    requests:
      - step: read-vin
        service: 0x22
        payload: "22 F1 90"
        expected_positive_sid: 0x62
        acceptable_nrcs: [0x22, 0x24, 0x31, 0x33, 0x13, 0x7E, 0x7F]
        threat_if_positive: true
        check_subfn: false
        redact_response_data: true
```

Every testcase is normalized into a common V&V-oriented case model. YAML files
may declare these fields directly; missing fields are inferred where possible:

```yaml
case_id: UDS-22
title: Read sensitive DID without SecurityAccess
category: Access Control
risk_property: Sensitive DID data is disclosed without SecurityAccess.
service_id: 0x22
default_payload: "22 F1 90"
preconditions:
  - Open extended diagnostic session.
parameters:
  did_hex: 0xF190
safety_level: read-only
expected_behavior: ECU denies sensitive DID access or evidence is redacted.
pass_criteria:
  - ECU returns an expected negative response, such as NRC 0x33 or 0x31.
fail_criteria:
  - ECU returns a positive 0x62 response containing sensitive data without SecurityAccess.
evidence_fields:
  - request_hex
  - response_hex
  - nrc
  - verdict
  - rationale
```

`pass_criteria` and `fail_criteria` are mandatory for useful V&V reporting.
When older YAML only has `expected_behavior` and `threat_condition`, the toolkit
adds conservative criteria during normalization so reports still include an
explicit basis for PASS/FAIL.

Multiple YAML files can be loaded together. `testcases` lists are concatenated, not overwritten.

---

## 7. Supported Testcase Types

| Type | Purpose |
|---|---|
| `security_access` | UDS `0x27` behaviour tests such as key-without-seed, seed-timeout-key, one-seed-many-keys, penalty-then-seed, and multi-seed-response. |
| `seed_sampler_same_session` | Opens a session once and repeatedly requests seeds inside the same active session. |
| `seed_sampler_cross_session` | Re-enters a clean session boundary before each seed request. |
| `arb_id_fuzzer` | Bounded probing of CAN arbitration ID pairs. |
| `service_fuzzer` | Bounded probing of UDS service IDs. |
| `subservice_fuzzer` | Bounded probing of UDS sub-functions for a selected service. |
| `payload_fuzzer` | Sends an explicit bounded payload list. |
| `uds_access_control_probe` | Declarative access-control validation for sensitive UDS services, including UDS-20 to UDS-25. |

---

## 8. Section 10 Access-Control Testcases

The Section 10 cases check whether sensitive UDS services are accepted without Seed-Key SecurityAccess.

| Case | Service | Threat condition | Expected secure behaviour |
|---|---:|---|---|
| UDS-20 | `0x11` ECUReset | ECU accepts reset without required preconditions. | Negative response such as `0x22`, `0x24`, `0x31`, `0x33`, `0x7E`, or `0x7F`. |
| UDS-21 | `0x2E` WriteDataByIdentifier | ECU accepts write operation without SecurityAccess. | Request denied or rejected. |
| UDS-22 | `0x22` ReadDataByIdentifier | ECU discloses sensitive DID data without SecurityAccess. | Sensitive DID denied or data redacted in evidence output. |
| UDS-23 | `0x34` RequestDownload | ECU accepts download initiation without SecurityAccess. | Request denied. |
| UDS-24 | `0x35` RequestUpload | ECU accepts upload initiation without SecurityAccess. | Request denied. |
| UDS-25 | `0x28` CommunicationControl | ECU accepts communication control without authorization. | Request denied. |

Positive response mapping:

| Request service | Positive response |
|---:|---:|
| `0x11` | `0x51` |
| `0x2E` | `0x6E` |
| `0x22` | `0x62` |
| `0x34` | `0x74` |
| `0x35` | `0x75` |
| `0x28` | `0x68` |

Important parser rule: not all UDS positive responses echo a sub-function or the second request byte. For example, `0x34` and `0x35` require service-aware response parsing and should normally use `check_subfn: false`.

---

## 9. Verdict Model

Each request should produce one clear verdict.

| Verdict | Meaning |
|---|---|
| `PASS_EXPECTED_DENIAL` | ECU denied the request using an acceptable NRC. |
| `FAIL_THREAT_POSITIVE` | ECU returned a positive response where the testcase marks positive acceptance as a threat. |
| `INFO_NO_RESPONSE` | No response was observed before timeout. |
| `INFO_UNEXPECTED_NRC` | ECU returned an NRC, but it was not listed in `acceptable_nrcs`. |
| `ERROR_EXCEPTION` | Transport, parsing, or execution error occurred. |
| `BLOCKED_SAFETY_GUARD` | Toolkit refused to transmit a potentially disruptive request because the testcase was not explicitly armed. |

---

## 10. Safety Guards

Potentially disruptive services:

```text
0x11  ECUReset
0x2E  WriteDataByIdentifier
0x34  RequestDownload
0x35  RequestUpload
0x28  CommunicationControl
```

Default behaviour:

- Dry-run is allowed.
- Real transmission is blocked unless authorization is explicit.
- Real transmission of disruptive services is blocked unless `destructive_confirm: true` is set in the testcase.
- `0x22` is read-only, but sensitive responses should use `redact_response_data: true` where appropriate.

Recommended fail-safe message:

```text
Refusing to transmit potentially disruptive UDS service without destructive_confirm: true.
```

---

## 11. Output Files

Each run creates a timestamped directory:

```text
runs/YYYYMMDD_HHMMSS_udstk/
├─ events.jsonl
└─ summary.csv
```

`summary.csv` should include at least:

```text
testcase,target,step,request,response,status,nrc,note,verdict
```

For redacted requests, GUI and CSV output should avoid dumping sensitive response data. Raw evidence should only contain full response data when `redact_response_data: false`.

---

## 12. Adding a New Testcase

For most additions, do not edit Python code. Add a new YAML entry.

Example explicit payload probe:

```yaml
testcases:
  - name: custom_read_did_probe
    type: uds_access_control_probe
    target: ecu1
    session_flow: [0x03]
    destructive_confirm: false
    requests:
      - step: read-custom-did
        service: 0x22
        payload: "22 F1 91"
        expected_positive_sid: 0x62
        acceptable_nrcs: [0x22, 0x24, 0x31, 0x33, 0x13, 0x7E, 0x7F]
        threat_if_positive: true
        check_subfn: false
        redact_response_data: true
```

Add a Python testcase only when the sequence cannot be represented declaratively. In that case:

1. Add a new class under `uds_toolkit/cases/`.
2. Implement `run(client, ctx) -> int`.
3. Register the testcase type in `uds_toolkit/registry.py`.
4. Add a YAML example under `testcases/`.
5. Confirm the GUI can reload and display it.

---

## 13. Development Checks

Compile all Python files:

```bash
python3 -m py_compile $(find . -name "*.py")
```

Dry-run all default YAML files:

```bash
python3 run_udstk.py \
  -c configs/default.yaml \
  -c testcases/security_access.yaml \
  -c testcases/seed_sampling.yaml \
  -c testcases/fuzzing_basic.yaml \
  -c testcases/uds_section10_access_control.yaml \
  --dry-run
```

Expected result:

- GUI starts using `python3 uds_observer_gui.py`.
- YAML reload does not crash.
- Existing testcases remain visible.
- New Section 10 cases are visible.
- Dry-run prints payloads without transmitting frames.
- Disruptive requests are blocked unless explicitly authorized and armed.

---

## 14. Known Limits

- The ISO-TP layer is intentionally minimal.
- Classical CAN 8-byte frames are the default assumption.
- CAN FD ISO-TP is not implemented unless explicitly added later.
- Extended addressing and mixed addressing are not enabled by default.
- The toolkit observes and classifies ECU behaviour; it is not a replacement for a complete diagnostic stack or certified cybersecurity validation process.

