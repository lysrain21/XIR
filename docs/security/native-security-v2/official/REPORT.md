# Native security conformance v2

- Case runs: 780/780
- Distinct runner/root signer: True
- Final validation: True

Each negative case was prepared through the deployed native carrier stacks. The recorded rejection transaction changed neither Gateway consumption state nor application state. Replay cases produced one initial effect and no duplicate effect.

| Route | Case | Repetitions | Rejection matches | Effects |
|---|---|---:|---:|---:|
| HL | concurrent_replay | 30 | 30 | 30 |
| HL | context_tamper | 30 | 30 | 0 |
| HL | cross_execution_splice | 30 | 30 | 0 |
| HL | evidence_tamper | 30 | 30 | 0 |
| HL | fake_verifier | 30 | 30 | 0 |
| HL | payload_tamper | 30 | 30 | 0 |
| HL | profile_inactive | 30 | 30 | 0 |
| HL | profile_substitution | 30 | 30 | 0 |
| HL | receipt_delete | 30 | 30 | 0 |
| HL | receipt_reorder | 30 | 30 | 0 |
| HL | sequential_replay | 30 | 30 | 30 |
| HL | wrong_endpoint | 30 | 30 | 0 |
| HL | wrong_registry_version | 30 | 30 | 0 |
| LH | concurrent_replay | 30 | 30 | 30 |
| LH | context_tamper | 30 | 30 | 0 |
| LH | cross_execution_splice | 30 | 30 | 0 |
| LH | evidence_tamper | 30 | 30 | 0 |
| LH | fake_verifier | 30 | 30 | 0 |
| LH | payload_tamper | 30 | 30 | 0 |
| LH | profile_inactive | 30 | 30 | 0 |
| LH | profile_substitution | 30 | 30 | 0 |
| LH | receipt_delete | 30 | 30 | 0 |
| LH | receipt_reorder | 30 | 30 | 0 |
| LH | sequential_replay | 30 | 30 | 30 |
| LH | wrong_endpoint | 30 | 30 | 0 |
| LH | wrong_registry_version | 30 | 30 | 0 |
