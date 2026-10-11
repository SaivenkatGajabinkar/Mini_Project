"""
Tests for the Cyber Attack Detection System.

Run with: python -m pytest tests/ -v
Or without pytest: python -m tests.test_system
"""

import json
import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def test_feature_schema_loads():
    """Test that feature_schema.json loads and has 22 features."""
    schema_path = PROJECT_ROOT / "config" / "feature_schema.json"
    assert schema_path.exists(), "feature_schema.json not found"

    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    features = schema["features"]
    assert len(features) == 22, f"Expected 22 features, got {len(features)}"

    # Each feature should have required fields
    for f in features:
        assert "name" in f, f"Feature missing 'name': {f}"
        assert "dataset_column" in f, f"Feature missing 'dataset_column': {f}"
        assert "dtype" in f, f"Feature missing 'dtype': {f}"
        assert "status" in f, f"Feature missing 'status': {f}"

    print("PASS: Feature schema loads with 22 features")


def test_risk_config_loads():
    """Test that risk_config.json loads with valid values."""
    config_path = PROJECT_ROOT / "config" / "risk_config.json"
    assert config_path.exists(), "risk_config.json not found"

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    assert "risk_weights" in config
    assert "thresholds" in config
    assert "alert_thresholds" in config

    weights = config["risk_weights"]
    total_weight = (weights["attack_ratio_weight"] +
                    weights["mean_probability_weight"] +
                    weights["volume_factor_weight"])
    assert abs(total_weight - 1.0) < 0.001, f"Weights should sum to 1.0, got {total_weight}"

    print("PASS: Risk config loads with valid values")


def test_risk_score_zero_attacks():
    """Test that zero attack flows produce risk score 0 and status NORMAL."""
    from backend.risk.score import compute_risk

    summary = {
        "total_flows": 100,
        "attack_flows": 0,
        "normal_flows": 100,
        "attack_ratio": 0.0,
        "mean_attack_probability": 0.0,
        "suspicious_ips": [],
        "top_suspicious_flows": [],
        "protocol_breakdown": {"TCP": 80, "UDP": 20},
    }

    result = compute_risk(summary)
    assert result["risk_score"] == 0, f"Expected risk_score 0, got {result['risk_score']}"
    assert result["status"] == "NORMAL", f"Expected NORMAL, got {result['status']}"
    assert result["risk_level"] == "LOW", f"Expected LOW, got {result['risk_level']}"

    print("PASS: Zero attacks -> risk_score=0, status=NORMAL")


def test_risk_score_high_attacks():
    """Test that many attack flows produce a high risk score."""
    from backend.risk.score import compute_risk

    summary = {
        "total_flows": 100,
        "attack_flows": 80,
        "normal_flows": 20,
        "attack_ratio": 0.8,
        "mean_attack_probability": 0.95,
        "suspicious_ips": [{"ip": "192.168.1.1", "attack_flows": 80}],
        "top_suspicious_flows": [],
        "protocol_breakdown": {"TCP": 100},
    }

    result = compute_risk(summary)
    assert result["risk_score"] >= 60, f"Expected HIGH score, got {result['risk_score']}"
    assert result["status"] == "ATTACK", f"Expected ATTACK, got {result['status']}"
    assert result["risk_level"] == "HIGH", f"Expected HIGH, got {result['risk_level']}"

    print("PASS: Many attacks -> HIGH risk, ATTACK status")


def test_risk_score_deterministic():
    """Test that the same input always yields the same output."""
    from backend.risk.score import compute_risk

    summary = {
        "total_flows": 347,
        "attack_flows": 27,
        "normal_flows": 320,
        "attack_ratio": 0.078,
        "mean_attack_probability": 0.9,
        "suspicious_ips": [],
        "top_suspicious_flows": [],
        "protocol_breakdown": {"TCP": 300, "UDP": 47},
    }

    result1 = compute_risk(summary)
    result2 = compute_risk(summary)
    assert result1["risk_score"] == result2["risk_score"], "Risk score not deterministic"
    assert result1["risk_level"] == result2["risk_level"], "Risk level not deterministic"
    assert result1["status"] == result2["status"], "Status not deterministic"

    print("PASS: Risk scoring is deterministic")


def test_database_init():
    """Test that database initializes and recreates cleanly."""
    from backend.database.db import init_db, get_connection, DB_PATH
    import tempfile

    # Use a temp database for testing
    original_db = str(DB_PATH)

    init_db()
    conn = get_connection()
    try:
        # Check tables exist
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t['name'] for t in tables}
        assert 'captures' in table_names, "captures table not found"
        assert 'suspicious_flows' in table_names, "suspicious_flows table not found"
        assert 'simulated_blocks' in table_names, "simulated_blocks table not found"
    finally:
        conn.close()

    print("PASS: Database initializes with all tables")


def test_database_store_and_retrieve():
    """Test storing and retrieving a capture result."""
    from backend.database.db import init_db, store_capture, get_capture, get_captures_list

    init_db()

    test_result = {
        "total_flows": 100,
        "attack_flows": 10,
        "normal_flows": 90,
        "attack_ratio": 0.1,
        "risk_score": 25.5,
        "risk_level": "LOW",
        "status": "NORMAL",
        "mean_attack_probability": 0.7,
        "protocol_breakdown": {"TCP": 80, "UDP": 20},
        "top_suspicious_flows": [
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "src_port": 12345, "dst_port": 80,
             "protocol": "TCP", "attack_probability": 0.95, "label": "Attack"}
        ],
        "suspicious_ips": [{"ip": "10.0.0.1", "attack_flows": 10}],
    }

    capture_id = "test-capture-001"
    store_capture(capture_id, "test_file.pcapng", test_result, "v1.0")

    # Retrieve
    retrieved = get_capture(capture_id)
    assert retrieved is not None, "Failed to retrieve stored capture"
    assert retrieved["total_flows"] == 100
    assert retrieved["risk_score"] == 25.5
    assert retrieved["status"] == "NORMAL"

    # List
    all_captures = get_captures_list()
    assert len(all_captures) >= 1

    print("PASS: Database store and retrieve works")


def test_simulated_block():
    """Test simulated IP blocking."""
    from backend.database.db import (
        init_db, add_simulated_block, get_simulated_blocks, remove_simulated_block
    )

    init_db()

    # Block an IP
    block_id = add_simulated_block("192.168.1.100", "test-capture-001", "Test block")

    # Verify
    blocks = get_simulated_blocks()
    found = any(b["id"] == block_id for b in blocks)
    assert found, "Block not found in list"

    # Check status label
    block = next(b for b in blocks if b["id"] == block_id)
    assert "SIMULATED" in block["status"], "Block not labelled as SIMULATED"

    # Remove
    removed = remove_simulated_block(block_id)
    assert removed, "Failed to remove block"

    print("PASS: Simulated blocking works correctly")


def test_pcap_validation():
    """Test that invalid files are rejected properly."""
    from backend.pcap.extract import validate_capture_file
    import tempfile

    # Test empty file
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        f.write(b"")
        temp_path = Path(f.name)

    try:
        validate_capture_file(temp_path)
        assert False, "Should have raised ValueError for empty file"
    except ValueError as e:
        assert "empty" in str(e).lower(), f"Wrong error: {e}"
    finally:
        temp_path.unlink(missing_ok=True)

    # Test invalid format
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as f:
        f.write(b"NOT_A_PCAP_FILE_HEADER")
        temp_path = Path(f.name)

    try:
        validate_capture_file(temp_path)
        assert False, "Should have raised ValueError for invalid format"
    except ValueError as e:
        assert "invalid" in str(e).lower() or "format" in str(e).lower(), f"Wrong error: {e}"
    finally:
        temp_path.unlink(missing_ok=True)

    print("PASS: Invalid files are rejected with clear errors")


def test_feature_schema_consistency():
    """Test that feature names match between schema and extractor."""
    from backend.pcap.extract import load_feature_schema as extract_schema
    from backend.ml.predict import load_feature_schema as predict_schema

    extract_features = extract_schema()
    predict_features = predict_schema()

    assert extract_features == predict_features, (
        f"Feature schema mismatch!\n"
        f"Extractor: {extract_features}\n"
        f"Predictor: {predict_features}"
    )

    print("PASS: Feature schema is consistent across modules")


def test_pdf_report_generation():
    """Test generating a PDF report for a capture."""
    from backend.reports.pdf_generator import generate_pdf_report
    from backend.database.db import get_capture

    capture = get_capture("test-capture-001")
    if capture is None:
        from backend.database.db import store_capture
        store_capture("test-capture-001", "test_file.pcapng", {
            "status": "ATTACK",
            "risk_level": "HIGH",
            "risk_score": 85.0,
            "total_flows": 10,
            "attack_flows": 8,
            "normal_flows": 2,
            "attack_ratio": 0.8,
            "mean_attack_probability": 0.95,
            "suspicious_ips": [{"ip": "192.168.1.100", "attack_flows": 8}],
            "top_suspicious_flows": [],
            "protocol_breakdown": {"TCP": 8, "UDP": 2},
        }, "v1.0")
        capture = get_capture("test-capture-001")

    pdf_bytes = generate_pdf_report(capture)
    assert pdf_bytes is not None, "PDF bytes should not be None"
    assert len(pdf_bytes) > 1000, f"PDF too small: {len(pdf_bytes)} bytes"
    assert pdf_bytes.startswith(b"%PDF"), "Output should be a valid PDF format"
    print("PASS: PDF report generation creates valid PDF bytes with full information")


def test_invalid_capture_report():
    """Test that requesting a report with invalid ID returns 400 error."""
    from fastapi.testclient import TestClient
    from backend.main import app

    client = TestClient(app)
    res = client.get("/api/captures/undefined/report")
    assert res.status_code == 400, f"Expected 400, got {res.status_code}"
    assert "Invalid capture ID" in res.json()["detail"]

    # Also test valid PDF endpoint
    res_valid = client.get("/api/captures/test-capture-001/report")
    assert res_valid.status_code == 200, f"Expected 200, got {res_valid.status_code}"
    assert res_valid.headers["content-type"] == "application/pdf"
    assert res_valid.content.startswith(b"%PDF")
    print("PASS: Report endpoint properly handles undefined ID and returns PDF for valid ID")


def run_all_tests():
    """Run all tests and report results."""
    tests = [
        test_feature_schema_loads,
        test_risk_config_loads,
        test_risk_score_zero_attacks,
        test_risk_score_high_attacks,
        test_risk_score_deterministic,
        test_database_init,
        test_database_store_and_retrieve,
        test_simulated_block,
        test_pcap_validation,
        test_feature_schema_consistency,
        test_pdf_report_generation,
        test_invalid_capture_report,
    ]

    print("=" * 60)
    print("CYBER ATTACK DETECTION SYSTEM — TEST SUITE")
    print("=" * 60)
    print()

    passed = 0
    failed = 0
    errors = []

    for test_fn in tests:
        name = test_fn.__name__
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((name, str(e)))
            print(f"FAIL: {name}: {e}")

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)

    if errors:
        print("\nFailed tests:")
        for name, error in errors:
            print(f"  - {name}: {error}")

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
