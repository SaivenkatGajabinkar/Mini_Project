"""
Generate synthetic CIC-IDS2017-like training data for demo purposes.

This creates a CSV with the same structure as CIC-IDS2017 labelled flow data,
using realistic statistical distributions for the 22 features.

NOTE: This is synthetic data for demonstration ONLY. For real model training,
download the actual CIC-IDS2017 dataset from:
https://www.unb.ca/cic/datasets/ids-2017.html

Usage: python -m backend.training.generate_demo_data
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data" / "raw"


def load_feature_schema():
    """Load feature names and dataset columns from schema."""
    schema_path = CONFIG_DIR / "feature_schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    return schema


def generate_demo_data(n_samples: int = 10000, attack_ratio: float = 0.3):
    """
    Generate synthetic network flow data that mimics CIC-IDS2017 structure.

    Normal flows have lower packet counts, smaller payloads, regular timing.
    Attack flows show higher volumes, more SYN/RST flags, abnormal timing.
    """
    np.random.seed(42)
    schema = load_feature_schema()

    n_attack = int(n_samples * attack_ratio)
    n_normal = n_samples - n_attack

    print(f"Generating {n_samples:,} synthetic flows...")
    print(f"  Normal: {n_normal:,}, Attack: {n_attack:,}")

    # --- Normal traffic patterns ---
    normal = {
        # CIC-IDS2017 uses leading spaces in many column names
        " Flow Duration": np.random.exponential(5_000_000, n_normal),  # microseconds
        " Total Fwd Packets": np.random.poisson(8, n_normal).astype(float) + 1,
        " Total Backward Packets": np.random.poisson(6, n_normal).astype(float),
        " Total Length of Fwd Packets": np.random.exponential(2000, n_normal),
        " Total Length of Bwd Packets": np.random.exponential(5000, n_normal),
        " Fwd Packet Length Max": np.random.exponential(500, n_normal),
        " Fwd Packet Length Mean": np.random.exponential(200, n_normal),
        " Bwd Packet Length Max": np.random.exponential(1000, n_normal),
        " Bwd Packet Length Mean": np.random.exponential(400, n_normal),
        "Flow Bytes/s": np.random.exponential(50000, n_normal),
        " Flow Packets/s": np.random.exponential(100, n_normal),
        " Flow IAT Mean": np.random.exponential(500000, n_normal),
        " Flow IAT Std": np.random.exponential(300000, n_normal),
        " Flow IAT Max": np.random.exponential(2000000, n_normal),
        " Fwd IAT Mean": np.random.exponential(600000, n_normal),
        " Bwd IAT Mean": np.random.exponential(700000, n_normal),
        " SYN Flag Count": np.random.choice([0, 1, 2], n_normal, p=[0.3, 0.5, 0.2]).astype(float),
        " ACK Flag Count": np.random.poisson(5, n_normal).astype(float),
        " RST Flag Count": np.random.choice([0, 1], n_normal, p=[0.9, 0.1]).astype(float),
        " PSH Flag Count": np.random.poisson(2, n_normal).astype(float),
        " Average Packet Size": np.random.exponential(300, n_normal),
        "Init_Win_bytes_forward": np.random.choice([8192, 16384, 29200, 65535], n_normal).astype(float),
    }

    # --- Attack traffic patterns (different distributions) ---
    attack = {
        " Flow Duration": np.random.exponential(500_000, n_attack),  # shorter
        " Total Fwd Packets": np.random.poisson(50, n_attack).astype(float) + 5,
        " Total Backward Packets": np.random.poisson(3, n_attack).astype(float),
        " Total Length of Fwd Packets": np.random.exponential(15000, n_attack),
        " Total Length of Bwd Packets": np.random.exponential(500, n_attack),
        " Fwd Packet Length Max": np.random.exponential(1400, n_attack),
        " Fwd Packet Length Mean": np.random.exponential(300, n_attack),
        " Bwd Packet Length Max": np.random.exponential(200, n_attack),
        " Bwd Packet Length Mean": np.random.exponential(80, n_attack),
        "Flow Bytes/s": np.random.exponential(500000, n_attack),  # higher rate
        " Flow Packets/s": np.random.exponential(1000, n_attack),  # higher
        " Flow IAT Mean": np.random.exponential(50000, n_attack),  # faster
        " Flow IAT Std": np.random.exponential(80000, n_attack),
        " Flow IAT Max": np.random.exponential(200000, n_attack),
        " Fwd IAT Mean": np.random.exponential(30000, n_attack),
        " Bwd IAT Mean": np.random.exponential(100000, n_attack),
        " SYN Flag Count": np.random.poisson(10, n_attack).astype(float),  # many SYNs (scan)
        " ACK Flag Count": np.random.poisson(2, n_attack).astype(float),
        " RST Flag Count": np.random.poisson(3, n_attack).astype(float),  # connection resets
        " PSH Flag Count": np.random.poisson(8, n_attack).astype(float),
        " Average Packet Size": np.random.exponential(150, n_attack),
        "Init_Win_bytes_forward": np.random.choice([1024, 2048, 4096, 0], n_attack).astype(float),
    }

    # Build DataFrames
    normal_df = pd.DataFrame(normal)
    normal_df[" Label"] = "BENIGN"

    attack_df = pd.DataFrame(attack)
    # Use various attack labels like real CIC-IDS2017
    attack_labels = np.random.choice(
        ["DoS Hulk", "PortScan", "DDoS", "DoS GoldenEye", "FTP-Patator",
         "SSH-Patator", "DoS slowloris", "Bot", "Web Attack"],
        n_attack
    )
    attack_df[" Label"] = attack_labels

    # Combine and shuffle
    combined = pd.concat([normal_df, attack_df], ignore_index=True)
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)

    # Add some realistic noise
    # Sprinkle a few NaN and inf values (like real data has)
    for col in [" Flow IAT Std", "Flow Bytes/s", " Flow Packets/s"]:
        mask = np.random.random(len(combined)) < 0.005
        combined.loc[mask, col] = np.inf

    mask_nan = np.random.random(len(combined)) < 0.002
    combined.loc[mask_nan, " Bwd IAT Mean"] = np.nan

    return combined


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    output_path = DATA_DIR / "demo_training_data.csv"

    print("=" * 60)
    print("SYNTHETIC DEMO DATA GENERATOR")
    print("=" * 60)
    print()
    print("NOTE: This generates synthetic data for demonstration.")
    print("For real training, use the CIC-IDS2017 dataset from:")
    print("https://www.unb.ca/cic/datasets/ids-2017.html")
    print()

    n_samples = 10000
    if "--large" in sys.argv:
        n_samples = 50000

    df = generate_demo_data(n_samples=n_samples)

    df.to_csv(output_path, index=False)
    print(f"\nSaved {len(df):,} rows to {output_path}")
    print(f"File size: {output_path.stat().st_size / 1024:.0f} KB")

    # Show distribution
    label_counts = df[" Label"].value_counts()
    print(f"\nLabel distribution:")
    for label, count in label_counts.items():
        print(f"  {label}: {count:,}")

    print(f"\nColumns: {list(df.columns)}")
    print("\nDone! Now run: python -m backend.training.train")


if __name__ == "__main__":
    main()
