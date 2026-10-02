"""
Risk Scoring Module — Converts ML predictions into actionable risk levels.
==========================================================================

This is the THIRD STEP in the prediction pipeline:

    ML predictions  →  [THIS MODULE]  →  Risk Score + Risk Level

How it works:
The model predicts each flow as Normal or Attack, but the dashboard needs
a single overall risk assessment for the entire capture. This module
combines three factors into one risk score (0-100):

    risk_score = 100 × (w1 × attack_ratio + w2 × mean_probability + w3 × volume_factor)

Where:
    - attack_ratio: What fraction of flows are Attack? (0.0 to 1.0)
    - mean_probability: How confident is the model? (0.0 to 1.0)
    - volume_factor: How many attack flows? (capped at 1.0)
    - w1, w2, w3: Configurable weights from config/risk_config.json

The final risk level is:
    - LOW:    score < 30  (mostly normal traffic)
    - MEDIUM: 30 ≤ score < 60 (some suspicious activity)
    - HIGH:   score ≥ 60 (significant attack detected)

All thresholds and weights are configurable in config/risk_config.json
so they can be tuned without changing any code.
"""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"


def load_risk_config() -> dict:
    """Load risk scoring configuration from config/risk_config.json."""
    config_path = CONFIG_DIR / "risk_config.json"
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_risk(summary: dict, config: dict = None) -> dict:
    """
    Compute a single risk score and level from the prediction summary.

    This function answers the question:
    "Overall, how dangerous is this network capture?"

    The formula uses three weighted components:
    1. attack_ratio (weight 0.5): If most flows are attacks, score goes up.
    2. mean_probability (weight 0.3): If the model is very confident these
       are attacks, score goes up.
    3. volume_factor (weight 0.2): If there are many attack flows (up to
       50+), score goes up. This catches flood attacks.

    Special case: If there are zero attack flows, risk_score is always 0.

    Args:
        summary: Output dict from predict.summarise() containing
                 total_flows, attack_flows, attack_ratio, etc.
        config: Risk configuration dict. If None, loaded from file.

    Returns:
        The input summary dict merged with three new keys:
        - risk_score: Float 0-100
        - risk_level: 'LOW', 'MEDIUM', or 'HIGH'
        - status: 'NORMAL' or 'ATTACK'
    """
    if config is None:
        config = load_risk_config()

    # Load configurable weights from risk_config.json
    weights = config["risk_weights"]
    w1 = weights["attack_ratio_weight"]      # Default: 0.5
    w2 = weights["mean_probability_weight"]   # Default: 0.3
    w3 = weights["volume_factor_weight"]      # Default: 0.2
    vol_denom = config["volume_factor_denominator"]  # Default: 50
    thresholds = config["thresholds"]
    alert = config["alert_thresholds"]

    total_flows = summary["total_flows"]
    attack_flows = summary["attack_flows"]
    attack_ratio = summary["attack_ratio"]
    mean_prob = summary["mean_attack_probability"]

    # If no attacks were detected, risk is zero
    if attack_flows == 0:
        risk_score = 0.0
    else:
        # volume_factor scales with the number of attack flows
        # It is capped at 1.0 (when attack_flows >= vol_denom)
        # This prevents a single suspicious flow from inflating the score too much
        volume_factor = min(attack_flows / vol_denom, 1.0)

        # Weighted combination of all three risk factors
        risk_score = 100 * (w1 * attack_ratio + w2 * mean_prob + w3 * volume_factor)

    # Clamp the score between 0 and 100
    risk_score = max(0, min(100, round(risk_score, 1)))

    # Determine risk level based on score thresholds
    if risk_score < thresholds["low_max"]:
        risk_level = "LOW"
    elif risk_score < thresholds["medium_max"]:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    # Determine overall capture status: ATTACK or NORMAL
    # A capture is marked ATTACK only if both:
    # 1. Attack ratio exceeds the alert threshold (default: 5%)
    # 2. Number of attack flows exceeds the minimum count (default: 3)
    if (attack_ratio >= alert["alert_ratio"] and
            attack_flows >= alert["alert_count"]):
        status = "ATTACK"
    else:
        status = "NORMAL"

    # Return the original summary with risk assessment added
    return {
        **summary,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "status": status,
    }
