# Test Report

## Test Environment
- **OS**: Windows 10/11
- **Python**: 3.12.7
- **Date**: 2026-10-01
- **Model**: Random Forest (trained on synthetic demo data, 10,000 flows)

## Automated Test Results

```
============================================================
CYBER ATTACK DETECTION SYSTEM - TEST SUITE
============================================================

PASS: Feature schema loads with 22 features
PASS: Risk config loads with valid values
PASS: Zero attacks -> risk_score=0, status=NORMAL
PASS: Many attacks -> HIGH risk, ATTACK status
PASS: Risk scoring is deterministic
PASS: Database initializes with all tables
PASS: Database store and retrieve works
PASS: Simulated blocking works correctly
PASS: Invalid files are rejected with clear errors
PASS: Feature schema is consistent across modules

============================================================
Results: 10 passed, 0 failed out of 10 tests
============================================================
```

## End-to-End Test Result

```
=== Upload + Analysis Result ===
Status:       NORMAL
Risk Level:   LOW
Risk Score:   0
Total Flows:  50
Attack Flows: 0
Normal Flows: 50
Capture ID:   b7d1fef2-9095-4f5f-8e63-dc3aacd73057
Protocols:    {'TCP': 33, 'UDP': 17}
=== END-TO-END TEST PASSED ===
```

## Test Plan Results

| # | Test | Expected | Actual | Status |
|---|------|----------|--------|--------|
| 1 | Normal capture | Mostly Normal | All 50 flows Normal, risk=0 | PASS |
| 2 | Attack traffic capture | Attack flows detected | Requires CIC-IDS2017 PCAP slice | PENDING (needs dataset) |
| 3 | Empty or corrupt file | Readable error | "File is empty" / "Invalid file format" errors returned | PASS |
| 4 | Unsupported or non-IP capture | Readable error | "No IP packets found" error returned | PASS |
| 5 | Same file uploaded repeatedly | Identical counts | Same 50 flows, 0 attacks each time | PASS |
| 6 | End to end in browser | Full flow works | Upload -> backend -> model -> DB -> dashboard works | PASS |
| 7 | Feature schema check | Columns match | Extractor and predictor use same 22-feature schema | PASS |
| 8 | Wrong extension / valid content | Follows signature | API validates file magic bytes, not just extension | PASS |
| 9 | Oversized file | Rejected with message | 413 error with "File too large" message | PASS |
| 10 | Cleanup task | Old uploads removed | Background thread runs hourly; tested with artificial dates | PASS |
| 11 | Database reset | Recreates cleanly | Deleting .db and restarting recreates all 3 tables | PASS |
| 12 | Training reproducibility | Identical metrics | Re-running train.py gives same metrics (seed=42) | PASS |

## Notes
- The model was trained on synthetic demo data. For production, use the real CIC-IDS2017 dataset.
- The demo PCAP contains benign-looking synthetic traffic, so all flows are classified as Normal. This is expected behaviour.
- Test #2 (attack traffic) requires a slice from the CIC-IDS2017 PCAP captures, which are not included due to size.
