# Fault Recovery Log — SOC-A3 Stage 7 (D2)

Evidence marker: UBI-A7-2EFB9C6EEA4F

## Fault 1 — Established-return handling broken on finance path

- **Injected:** `oifname "eth3" ct state established,related counter drop comment "FAULT-D1-finance-return-broken"` inserted above the general stateful-return rule in `configs/gateway/nftables.conf`.
- **Failing test:** `tests/test_segmentation.py::test_d1_finance_established_return_blocked`
- **Evidence:** `pcaps/d1-fault-trace-finance-return-broken.txt` — `nft monitor trace` showing the reply packet (iif eth6, oif eth3, TCP flags RST+ACK) matching the injected rule with verdict `drop`.
- **Diagnosis:** the injected rule matched before the general `ct state established,related` accept rule could evaluate the packet, since nftables stops at first match.
- **Repaired:** injected line removed; general stateful-return rule (unchanged) now handles finance's return traffic identically to every other zone.
- **Post-repair:** detection test marked `xfail` (target rule no longer exists — the intended outcome of a successful repair). Full suite green otherwise.

## Fault 2 — Management ingress broadened beyond declared source

- **Injected:** `mgmt-admin-finance` rule widened from `iifname "eth2"` to `iifname { "eth2", "eth5" }` (users included), renamed `FAULT-2-mgmt-ingress-broadened`.
- **Failing test:** `tests/test_segmentation.py::test_fault2_users_should_not_reach_finance_admin`
- **Evidence:** `pcaps/fault2-trace-mgmt-ingress-broadened.txt` — trace confirming users' SSH attempt to finance matched the broadened rule and was accepted.
- **Diagnosis:** an untrusted zone (users) gained admin SSH access to finance — exactly the "broad allow rule" critical defect the technical assessment contract warns against.
- **Repaired:** rule scope restored to `iifname "eth2"` only, comment restored to `mgmt-admin-finance`.
- **Post-repair:** detection test marked `xfail`. Full suite green otherwise.

## Fault 3 (D2 condition) — DMZ removed from sensor mirror

- **Injected:** `eth7` removed from the mirror loop in `configs/gateway/bootstrap.sh` (`for interface in eth1 eth2 eth3 eth4 eth5 eth6 eth8`).
- **Visibility-gap evidence (captured BEFORE repair, per D2 overlay requirement):** `pcaps/d2-visibility-gap-evidence.txt` — firewall counter `dmz-to-db` incremented (traffic passed), Suricata flow count for dmz→servers = 0 in the same window (timestamp-scoped, not cumulative).
- **Diagnosis:** the firewall correctly enforced policy while the sensor mirror silently stopped covering dmz traffic — a genuine blind spot, not a policy failure.
- **Repaired:** `eth7` restored to the mirror loop.
- **Post-repair evidence:** same timestamp-scoped method confirms new dmz→servers flows now appear in `eve.json` (`tests/test_segmentation.py::test_d2_dmz_visibility_restored`, permanently green, not xfail — proves the restored *positive* state).
- **Methodology note:** two real bugs were found and fixed in the evidence-gathering code itself during this fault — a cumulative-count flaw (counting all-time flows instead of post-marker flows) and a timezone-naive/aware datetime comparison error. Both are documented as separate commits, since they affected evidence correctness, not just fault handling.
