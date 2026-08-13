# SOC-A3 Stage 7 — Network Detection Range as Code

**Intern:** UBI-2026-0564 | **Track:** SOC_ANALYSIS | **Variant:** D2, address-plan octet 61
**Evidence marker:** UBI-A7-2EFB9C6EEA4F

## Tool / OS versions
- OS: Linux Ubuntu (see `uname -a` in setup evidence)
- Docker Engine: 29.7.2 (Community)
- containerlab: 0.77.0
- FRRouting image: quay.io/frrouting/frr:10.2.1
- Suricata image: jasonish/suricata:7.0.8
- Python: 3.14.4, pytest 9.1.1, pytest-testinfra 10.2.2

## Reproduction order
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pytest pytest-testinfra
make clean && make lab && make test
```
`make configure` (run automatically by `lab`/`test`) renders all address-bearing
files from `variant.env` + `*.tmpl` sources — this is a config-only step, no
manual file edits are required to reproduce this build.

## Structure
- `topology.clab.yml` — 10-node topology (7 zones, gateway, core, sensor)
- `configs/` — FRR (core) and nftables/bootstrap (gateway)
- `services/` — stub listeners standing in for real backend services
- `detections/` — Suricata config + custom detection rules
- `tests/` — pytest/testinfra suite, one function per control-matrix assertion
- `pcaps/` — packet/flow/trace evidence tied to specific test rows
- `fault-recovery-log.md`, `decision-log.md`, `continuity-record.md` — process documentation

