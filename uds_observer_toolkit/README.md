# UDS Observer Toolkit

Config-driven toolkit for observing UDS behaviour, SecurityAccess test cases, seed sampling, and bounded fuzzing/probing of arbitration IDs, services, sub-functions, and explicit payloads.

The normal workflow is GUI-first:

```bash
cd uds_observer_toolkit
pip install -r requirements.txt
python3 uds_observer_gui.py
```

From the GUI, load/reload YAML files, edit the active CAN channel/target IDs, select test cases, and run them. The GUI calls the same backend runner used by the CLI, so later test cases can still be added as YAML or Python plugins without rewriting the interface.

```text
uds_observer_toolkit/
├─ uds_observer_gui.py                # main GUI entry point
├─ run_udstk.py                       # CLI/backend entry point used by GUI
├─ configs/default.yaml               # CAN, ISO-TP timing, target IDs
├─ testcases/security_access.yaml     # 0x27 behaviour probes
├─ testcases/seed_sampling.yaml       # same/cross-session seed samplers
├─ testcases/fuzzing_basic.yaml       # arbID/service/subservice/payload probes
├─ uds_toolkit/
│  ├─ canio.py                        # python-can bus open
│  ├─ isotp.py                        # minimal ISO-TP transport
│  ├─ uds.py                          # UDS request/response parser/client
│  ├─ runner.py                       # config-driven orchestration
│  ├─ registry.py                     # testcase plugin registry
│  ├─ seedkey.py                      # lab BMS HMAC-SHA1 profile
│  └─ cases/                          # pluggable testcase classes
└─ legacy/                            # original uploaded scripts preserved
```

## Install

```bash
cd uds_observer_toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 uds_observer_gui.py
```

For virtual CAN testing:

```bash
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

## GUI workflow

1. Run `python3 uds_observer_gui.py`.
2. Confirm `channel`, `interface`, `TX ID`, `RX ID`, and `session flow`.
3. Click **Reload** after adding/editing YAML files.
4. Select one or more test cases.
5. Use **Dry run** first to validate config without sending CAN frames.
6. Tick **I am authorized** only for fuzzing/probing cases in an approved lab/test environment.
7. Click **Run selected** or **Run all**.

Each run writes a timestamped directory under `runs/` with `events.jsonl` and `summary.csv`.

## CLI remains available

Dry-run / config validation:

```bash
python3 run_udstk.py \
  -c configs/default.yaml \
  -c testcases/security_access.yaml \
  --dry-run
```

Run one testcase:

```bash
python3 run_udstk.py \
  -c configs/default.yaml \
  -c testcases/security_access.yaml \
  --case sa_key_without_seed \
  --show-process
```

Run seed sampler:

```bash
python3 run_udstk.py \
  -c configs/default.yaml \
  -c testcases/seed_sampling.yaml \
  --case seed_same_session_20 \
  --show-process
```

Run bounded fuzzing/probing. Fuzzing is blocked unless authorization is explicit:

```bash
python3 run_udstk.py \
  -c configs/default.yaml \
  -c testcases/fuzzing_basic.yaml \
  --case fuzz_services_known_target \
  --yes-i-am-authorized \
  --show-process
```

## Add a new target

Edit `configs/default.yaml` or create an overlay file:

```yaml
targets:
  bcm:
    txid: 0x7E0
    rxid: 0x7E8
    session_flow: [0x03]
```

Then assign `target: bcm` in the testcase YAML.

## Add a new testcase without editing core code

For explicit payload regression:

```yaml
testcases:
  - name: my_payload_sequence
    type: payload_fuzzer
    target: ecu1
    session_flow: [0x03]
    payloads:
      - "22 F1 90"
      - "27 01"
    delay: 0.10
```

For a new Python testcase type, add one class under `uds_toolkit/cases/` and register it in `uds_toolkit/registry.py`. The class only needs a `run(client, ctx) -> int` method.

## Output

```text
runs/YYYYMMDD_HHMMSS_udstk/
├─ events.jsonl   # complete structured event stream
└─ summary.csv    # spreadsheet-friendly UDS result table
```

## Design notes

- GUI is the primary entry point; CLI is kept for automation and regression.
- CAN ID parsing treats strings as hexadecimal by default.
- Multiple testcase YAML files can now be loaded together; `testcases` lists are concatenated.
- 29-bit CAN IDs are supported via `can.extended_id: true` or per-target `extended_id: true`.
- CAN FD ISO-TP is intentionally not implemented. The toolkit uses classical 8-byte CAN frames.
- Fuzzing is bounded by YAML ranges, `max_items`, per-request delays, and explicit authorization.
- `key_policy=valid` and `key_policy=invalid-bitflip` use the included lab BMS HMAC-SHA1 profile. Do not use these against systems you are not authorized to test.
