# Security-input classification

Every case below mutates an untrusted input while A1--A4 hold. The degradation analysis for trusted-component failure is separate.

| Input case | Target guarantee | Primary check | Runs | Matched | Effects |
|---|---|---|---:|---:|---:|
| concurrent_replay | G4_AT_MOST_ONCE_EFFECT | atomic_message_consumption | 60 | 60 | 60 |
| context_tamper | G1_AUTHENTICITY, G3_POLICY_COMPLIANCE | source_root_verification | 60 | 60 | 0 |
| cross_execution_splice | G2_TRACE_INTEGRITY | ordered_final_bundle_verification | 60 | 60 | 0 |
| evidence_tamper | G1_AUTHENTICITY, G2_TRACE_INTEGRITY | native_evidence_verification | 60 | 60 | 0 |
| fake_verifier | G1_AUTHENTICITY, G2_TRACE_INTEGRITY | prior_verifier_binding | 60 | 60 | 0 |
| payload_tamper | G1_AUTHENTICITY | destination_payload_binding | 60 | 60 | 0 |
| profile_inactive | G3_POLICY_COMPLIANCE | profile_activity_check | 60 | 60 | 0 |
| profile_substitution | G3_POLICY_COMPLIANCE | profile_resolution | 60 | 60 | 0 |
| receipt_delete | G2_TRACE_INTEGRITY | receipt_prefix_verification | 60 | 60 | 0 |
| receipt_reorder | G2_TRACE_INTEGRITY | receipt_prefix_verification | 60 | 60 | 0 |
| sequential_replay | G4_AT_MOST_ONCE_EFFECT | atomic_message_consumption | 60 | 60 | 60 |
| wrong_endpoint | G1_AUTHENTICITY, G2_TRACE_INTEGRITY | prior_verifier_binding | 60 | 60 | 0 |
| wrong_registry_version | G1_AUTHENTICITY, G3_POLICY_COMPLIANCE | root_version_verification | 60 | 60 | 0 |
