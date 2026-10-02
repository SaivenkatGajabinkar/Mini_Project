"""
ML Prediction Module — Random Forest inference pipeline.
=========================================================

This is the SECOND STEP in the prediction pipeline:

    22 features per flow  →  [THIS MODULE]  →  Normal/Attack label + probability

How it works:
1. Loads the trained Random Forest pipeline from models/ directory.
   The pipeline contains a SimpleImputer (fills NaN with median values)
   followed by the RandomForestClassifier.
2. Takes the 22-feature DataFrame (from extract.py) and runs it through
   the pipeline to get Normal (0) or Attack (1) predictions.
3. Also computes the attack probability (0.0 to 1.0) for each flow.
4. The summarise() function aggregates per-flow results into a
   capture-level summary used by the dashboard.

The model is loaded ONCE on first use and cached in memory for speed.
"""

import json
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
CONFIG_DIR = PROJECT_ROOT / "config"

# ── Module-level cache ────────────────────────────────────────────────
# The model is loaded once and reused for all predictions.
# This avoids re-reading the ~1.6 MB joblib file on every upload.
_pipeline = None
_metadata = None


def load_feature_schema():
    """
    Load the 22 feature names from config/feature_schema.json.

    This is the single source of truth for feature names across:
    - extract.py (feature extraction)
    - predict.py (model prediction)
    - train.py (model training)
    """
    schema_path = CONFIG_DIR / "feature_schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    return [f["name"] for f in schema["features"]]


def load_pipeline():
    """
    Load the trained Random Forest pipeline and model metadata.

    The pipeline is a scikit-learn Pipeline object containing:
    1. SimpleImputer(strategy='median') — handles missing/NaN values
    2. RandomForestClassifier — the actual classifier

    The metadata file contains training date, metrics, and feature names.

    Security: Only loads model files from the project's own models/ directory
    to prevent loading malicious pickle/joblib files from other locations.

    Returns:
        Tuple of (pipeline, metadata_dict)
    """
    global _pipeline, _metadata

    # Return cached pipeline if already loaded
    if _pipeline is not None:
        return _pipeline, _metadata

    model_path = MODELS_DIR / "random_forest_pipeline.joblib"
    metadata_path = MODELS_DIR / "model_metadata.json"

    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found at {model_path}. "
            "Please run training first: python -m backend.training.train"
        )

    # Security check: only load from the project's models directory
    model_path = model_path.resolve()
    if not str(model_path).startswith(str(MODELS_DIR.resolve())):
        raise ValueError("Refusing to load model from outside the models/ directory")

    # Load the trained model (SimpleImputer + RandomForest pipeline)
    _pipeline = joblib.load(model_path)

    # Load metadata (training date, metrics, feature names)
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            _metadata = json.load(f)
    else:
        _metadata = {"model_type": "Unknown", "feature_names": load_feature_schema()}

    return _pipeline, _metadata


def predict(features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Run the Random Forest model on extracted flow features.

    For each flow (row), the model outputs:
    - prediction: 0 (Normal traffic) or 1 (Attack traffic)
    - label: Human-readable 'Normal' or 'Attack' string
    - attack_probability: Confidence score between 0.0 and 1.0
      (what percentage of the 100 trees voted "Attack")

    Args:
        features_df: DataFrame from extract_features() containing the
                     22 feature columns plus metadata columns.

    Returns:
        Same DataFrame with three new columns appended:
        'prediction', 'label', 'attack_probability'.
    """
    pipeline, metadata = load_pipeline()
    feature_names = load_feature_schema()

    # Verify that all 22 required feature columns exist
    missing_features = [f for f in feature_names if f not in features_df.columns]
    if missing_features:
        raise ValueError(
            f"Feature mismatch: missing columns {missing_features}. "
            f"Expected columns: {feature_names}"
        )

    # Extract only the 22 model features in the correct order
    # (metadata columns like _src_ip are NOT passed to the model)
    X = features_df[feature_names].values

    # Run the pipeline: Imputer fills NaN → Random Forest predicts
    predictions = pipeline.predict(X)

    # Get probability estimates from the Random Forest
    # predict_proba returns [[prob_normal, prob_attack], ...] for each flow
    probabilities = pipeline.predict_proba(X)

    # Build result DataFrame with predictions added
    result = features_df.copy()
    result["prediction"] = predictions
    result["label"] = np.where(predictions == 1, "Attack", "Normal")
    # Attack probability is column index 1 (class 1 = Attack)
    result["attack_probability"] = probabilities[:, 1]

    return result


def summarise(predictions_df: pd.DataFrame) -> dict:
    """
    Aggregate per-flow predictions into a capture-level summary.

    This summary is used by:
    - The risk scoring module (to compute risk_score and risk_level)
    - The API response (returned to the frontend dashboard)
    - The database (stored for capture history)

    Returns a dict containing:
    - total_flows, attack_flows, normal_flows: basic counts
    - attack_ratio: fraction of flows classified as Attack
    - mean_attack_probability: average confidence for attack flows
    - suspicious_ips: source IPs with the most attack flows
    - top_suspicious_flows: the 10 flows with highest attack probability
    - protocol_breakdown: count of flows per protocol (TCP, UDP, etc.)
    """
    total_flows = len(predictions_df)
    attack_mask = predictions_df["prediction"] == 1
    attack_flows = int(attack_mask.sum())
    normal_flows = total_flows - attack_flows

    attack_ratio = attack_flows / total_flows if total_flows > 0 else 0

    # Calculate mean attack probability across flows flagged as Attack
    if attack_flows > 0:
        mean_attack_prob = float(predictions_df.loc[attack_mask, "attack_probability"].mean())
    else:
        mean_attack_prob = 0.0

    # Identify suspicious source IPs (IPs that sent the most attack flows)
    suspicious_ips = []
    if attack_flows > 0 and "_src_ip" in predictions_df.columns:
        attack_df = predictions_df[attack_mask]
        ip_counts = attack_df["_src_ip"].value_counts()
        for ip, count in ip_counts.items():
            suspicious_ips.append({"ip": str(ip), "attack_flows": int(count)})

    # Get top 10 most suspicious flows (highest attack probability)
    # These are shown in the dashboard's "Top Suspicious Flows" table
    top_flows = []
    if "_src_ip" in predictions_df.columns:
        sorted_df = predictions_df.sort_values("attack_probability", ascending=False).head(10)
        for _, row in sorted_df.iterrows():
            top_flows.append({
                "src_ip": str(row.get("_src_ip", "")),
                "dst_ip": str(row.get("_dst_ip", "")),
                "src_port": int(row.get("_src_port", 0)),
                "dst_port": int(row.get("_dst_port", 0)),
                "protocol": str(row.get("_protocol", "")),
                "attack_probability": round(float(row["attack_probability"]), 4),
                "label": str(row["label"])
            })

    # Count flows per protocol (TCP, UDP, ICMP, etc.)
    protocol_breakdown = {}
    if "_protocol" in predictions_df.columns:
        proto_counts = predictions_df["_protocol"].value_counts()
        protocol_breakdown = {str(k): int(v) for k, v in proto_counts.items()}

    return {
        "total_flows": total_flows,
        "attack_flows": attack_flows,
        "normal_flows": normal_flows,
        "attack_ratio": round(attack_ratio, 4),
        "mean_attack_probability": round(mean_attack_prob, 4),
        "suspicious_ips": suspicious_ips,
        "top_suspicious_flows": top_flows,
        "protocol_breakdown": protocol_breakdown,
    }
