# Continuity Record — SOC-A3 Stage 7

## 1. Previous-stage commit and component reused
No code or data component from Stage 5 (commit a08c2f3870003880b47d90d1f85285542f1c9e1a) or
Stage 6 (commit 1a4944c77ed34696da4bcdaa79283b248e427aa8) was directly
reused in this stage. This was checked deliberately against both prior projects' actual
components rather than assumed.

## 2. Interface consumed and backward-compatible extension
No prior-stage output files (Stage 6's sessions.parquet, clusters.json, stix-bundle.json,
detections/) were consumed as input to this project. Per brief.md, this stage's own telemetry
(pcaps/suricata/eve.json, evidence-index.csv) is instead structured to be COMPATIBLE WITH the
same evidence schema/discipline established in Stage 5/6, for whichever stage consumes this
project's output next — an outward-facing extension of the schema, not an inward consumption
of Stage 6's artifacts.

## 3. Evidence that prior raw-to-result provenance remains intact
Not applicable to raw data provenance (no prior-stage raw data was consumed). What IS carried
forward is methodology: every claim in this stage's evidence-index.csv retains a raw artifact
locator (pcap, nft trace, eve.json line, or test-results.xml entry), the same evidentiary
standard applied in Stage 5 and Stage 6.

## 4. Migration record for every incompatible change
No incompatible changes — no prior-stage schema or component was modified, since none was
consumed as a dependency. This stage is architecturally independent of Stage 5/6's actual
code and data, while intentionally continuing three specific methodological practices (see
section 6).

## 5. Component, schema, evidence, or decision record handed to the next stage (Stage 8)
- Verified allow/deny behaviors for all 30 published + 5 holdout policy assertions (`tests/`, `test-results.xml`)
- Fault-recovery evidence and methodology (`fault-recovery-log.md`)
- Candidate detection signature for spoofed-source traffic (`detections/rules/suricata.rules`, sid 1000001 — follows Stage 6's >=1,000,000 custom-range convention, though hand-authored against a control-matrix requirement rather than generated from an evidence ledger the way Stage 6's rules were)
- Packet captures and flow evidence tied to specific control-matrix rows (`pcaps/`)
- Decision log documenting every inferred/assumed design choice (`decision-log.md`)

## 6. Methodology genuinely carried forward from Stage 5/6 (not code or data)
- **Evidence-locator discipline**: every material claim cites a raw artifact + exact locator, continued unchanged from Stage 5/6's standard.
- **Decision-log discipline**: same ID / evidence / alternatives-rejected / review-trigger shape as Stage 6's decision-log.md.
- **Round-trip and genuine-distinct-source firewall testing**: Stage 6 found that same-host testing of source-IP-restricted rules is unreliable (loopback bypasses the check), and that a rule's return path must be tested separately from its initiate path. Both lessons were directly applied here: `test_d1_finance_established_return_blocked` and NET-29 test return-path behavior explicitly, not just initiate behavior; NET-28's spoofed-source test used a genuinely separate container (nping, forged source IP) rather than a same-host test.
