# Decision Log

| ID | UTC time | Decision | Evidence used | Alternatives rejected | Assumption | Owner | Review trigger |
|---|---|---|---|---|---|---|---|
| D-001 | 2026-08-07T13:33:20+01:00 | Grant users→servers tcp/443 (staff portal) | control-test-matrix.csv NET-29; address-plan.csv notes column | Zero users→servers access — rejected because it makes NET-29 unsatisfiable | "users" zone has one unnamed general-purpose internal service, inferred from parallel structure with finance/engineering entries | Babatunde | Revisit if program support clarifies intended service |
| D-002 | 2026-08-07T13:33:20+01:00 | Ports for unnamed services: payroll db=5432, payroll app=443, code service=443 | control-test-matrix.csv (service named, port unstated) | Arbitrary placeholder ports | Chose realistic real-world defaults over arbitrary numbers | Babatunde | None — low risk, documented explicitly |
| D-003 | 2026-08-07T13:33:20+01:00 | "Network devices" (NET-07/08) = the gateway's own control-plane IP, not a separate zone | control-test-matrix.csv; no 8th zone in topology or address plan | Treat as an undefined 8th zone | Gateway is the only literal "network device" in the range | Babatunde | None |
| D-004 | 2026-08-13T11:40:44+01:00 | D2 overlay condition treated as an elaboration of baseline fault #3, not a distinct 4th fault | Overlay text near-identical to brief.md's baseline fault #3 wording | Treat as a genuinely separate 4th fault | Brief says D-set "adds one fourth fault condition" but gives no distinct technical description | Babatunde | Confirm with program support if challenged during defense |
| D-005 | 2026-08-13T11:40:44+01:00 | Centralized all addressing into `variant.env` + template rendering instead of hardcoding per file | Technical assessment contract's "configuration-only address change" requirement; V1/V2 swap proof | Hand-editing each file per variant | Reduces risk of missed files during a variant swap (caught suricata.rules gap this way) | Babatunde | None |

Every consequential judgment made during this project belongs here. A conclusion in the report without a decision trail may be treated as unsupported during defense.
