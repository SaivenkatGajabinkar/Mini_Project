"""
Training Pipeline — Random Forest Model for Cyber Attack Detection.
=====================================================================

This script trains the Random Forest classifier on CIC-IDS2017 data.
It is run ONCE (offline) before the application is used.

How training works:
1. LOAD: Reads the CIC-IDS2017 labelled flow CSV from data/ directory
2. SELECT: Picks only the 22 features defined in feature_schema.json
3. CLEAN: Removes duplicates, handles NaN/inf values, strips whitespace
4. LABEL: Converts text labels to binary: BENIGN=0 (Normal), anything else=1 (Attack)
5. SPLIT: 80% training, 20% testing (stratified to preserve class balance)
6. TRAIN: Builds a pipeline: SimpleImputer(median) → RandomForestClassifier
   - Why Random Forest? It's robust, fast, handles missing values well,
     and works without feature scaling (trees are invariant to monotonic transforms)
7. EVALUATE: Measures accuracy, precision, recall, F1, ROC-AUC on test set
8. SAVE: Writes the trained pipeline to models/random_forest_pipeline.joblib
         and metadata to models/model_metadata.json

Usage:
    python backend/training/train.py
    python -m backend.training.train
    python backend/training/train.py --sample 0.1  (use 10% for quick testing)
"""

import json
import sys
import time
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, classification_report
)

# Project root is two levels up from this file
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"


def load_feature_schema():
    """Load the single source of truth for feature names."""
    schema_path = CONFIG_DIR / "feature_schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_and_clean_data(data_dir: Path, schema: dict) -> pd.DataFrame:
    """
    Load all CIC-IDS2017 CSV files from data_dir, strip whitespace from
    headers, keep only schema columns + label, and clean the data.

    Searches both data_dir and data_dir/raw for CSV files.
    """
    # Search for CSVs in both the data dir and data/raw subdir
    search_dirs = [data_dir]
    raw_dir = data_dir / "raw"
    if raw_dir.exists():
        search_dirs.append(raw_dir)

    csv_files = []
    for d in search_dirs:
        csv_files.extend(sorted(d.glob("*.csv")))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir} or {data_dir / 'raw'}. "
            "Please download the CIC-IDS2017 labelled flow CSVs "
            "from https://www.unb.ca/cic/datasets/ids-2017.html "
            f"and place them in {data_dir}"
        )

    # Identify real CIC-IDS2017 files vs synthetic demo files
    # Real CIC-IDS2017 files have 79 columns; demo files have 23
    real_files = []
    demo_files = []
    for csv_file in csv_files:
        # Peek at header to determine file type
        try:
            header_df = pd.read_csv(csv_file, nrows=0, low_memory=False, encoding="utf-8")
            n_cols = len(header_df.columns)
            if n_cols >= 70:  # Real CIC-IDS2017 has 79 columns
                real_files.append(csv_file)
            else:
                demo_files.append(csv_file)
        except Exception as e:
            print(f"  WARNING: Could not read {csv_file.name}: {e}")

    # Prefer real CIC-IDS2017 files over demo files
    if real_files:
        files_to_use = real_files
        print(f"  Found {len(real_files)} real CIC-IDS2017 CSV file(s)")
        for f in real_files:
            print(f"    - {f.name}")
        if demo_files:
            print(f"  Skipping {len(demo_files)} synthetic demo file(s)")
    else:
        files_to_use = demo_files
        print(f"  WARNING: No real CIC-IDS2017 files found. Using {len(demo_files)} demo file(s)")

    frames = []
    for csv_file in files_to_use:
        print(f"  Loading {csv_file.name}...")
        # Read with low_memory=False to avoid mixed type warnings
        df = pd.read_csv(csv_file, low_memory=False, encoding="utf-8")
        # Strip whitespace from column names (CIC-IDS2017 has leading spaces)
        df.columns = df.columns.str.strip()
        frames.append(df)

    combined = pd.concat(frames, ignore_index=True)
    print(f"  Total rows loaded: {len(combined):,}")

    # Map dataset columns to our feature names
    feature_names = [f["name"] for f in schema["features"]]
    dataset_columns = [f["dataset_column"].strip() for f in schema["features"]]
    label_col = schema["label_column"].strip()

    # Check all required columns exist
    missing = [c for c in dataset_columns + [label_col] if c not in combined.columns]
    if missing:
        raise ValueError(
            f"Missing columns in dataset: {missing}. "
            f"Available columns: {list(combined.columns)}"
        )

    # Select only needed columns and rename to our feature names
    col_map = dict(zip(dataset_columns, feature_names))
    selected = combined[dataset_columns + [label_col]].copy()
    selected.rename(columns=col_map, inplace=True)
    selected.rename(columns={label_col: "Label"}, inplace=True)

    # Report original label distribution
    print(f"\n  Original label distribution:")
    label_dist = selected["Label"].value_counts()
    for label, count in label_dist.items():
        print(f"    {label}: {count:,}")

    # Convert features to numeric, coerce errors to NaN
    for feat in feature_names:
        selected[feat] = pd.to_numeric(selected[feat], errors="coerce")

    # Replace infinite values with NaN (Flow Bytes/s and Flow Packets/s
    # can be inf when duration is 0)
    inf_count = np.isinf(selected[feature_names].select_dtypes(include=[np.number])).sum().sum()
    selected.replace([np.inf, -np.inf], np.nan, inplace=True)
    print(f"  Infinite values replaced with NaN: {inf_count:,}")

    # Count NaN values
    nan_count = selected[feature_names].isna().sum().sum()
    print(f"  Missing values (NaN) across features: {nan_count:,}")
    print(f"  (These will be handled by median imputation in the pipeline)")

    # Remove rows where the label is missing or empty
    before_label_clean = len(selected)
    selected = selected.dropna(subset=["Label"])
    selected = selected[selected["Label"].str.strip() != ""]
    after_label_clean = len(selected)
    if before_label_clean != after_label_clean:
        print(f"  Removed {before_label_clean - after_label_clean:,} rows with missing/empty labels")

    # Remove exact duplicate rows
    before_dedup = len(selected)
    selected.drop_duplicates(inplace=True)
    after_dedup = len(selected)
    print(f"  Removed {before_dedup - after_dedup:,} duplicate rows")

    # Remove rows where ALL feature values are NaN (completely malformed rows)
    before_malformed = len(selected)
    selected = selected.dropna(subset=feature_names, how="all")
    after_malformed = len(selected)
    if before_malformed != after_malformed:
        print(f"  Removed {before_malformed - after_malformed:,} fully-NaN rows")

    # Create binary label: BENIGN -> 0 (Normal), anything else -> 1 (Attack)
    selected["BinaryLabel"] = (selected["Label"] != "BENIGN").astype(int)

    n_normal = int((selected["BinaryLabel"] == 0).sum())
    n_attack = int((selected["BinaryLabel"] == 1).sum())
    total = len(selected)

    print(f"\n  === Data Cleaning Summary ===")
    print(f"  Rows loaded:        {before_dedup + (before_label_clean - after_label_clean):,}")
    print(f"  Rows after cleaning: {total:,}")
    print(f"  Normal (BENIGN):    {n_normal:,} ({100*n_normal/total:.1f}%)")
    print(f"  Attack:             {n_attack:,} ({100*n_attack/total:.1f}%)")

    return selected, feature_names


def train_model(data_dir: Path = None, sample_fraction: float = None):
    """
    Main training function. Loads data, trains Random Forest pipeline,
    evaluates, and saves model + metadata.

    Args:
        data_dir: Path to directory containing CIC-IDS2017 CSV files.
                  Defaults to data/.
        sample_fraction: If set, subsample data for faster training (e.g., 0.1 for 10%).
    """
    if data_dir is None:
        data_dir = DATA_DIR

    schema = load_feature_schema()
    feature_names = [f["name"] for f in schema["features"]]

    print("=" * 60)
    print("CYBER ATTACK DETECTION - MODEL TRAINING")
    print("=" * 60)
    print(f"\nData directory: {data_dir}")

    # Load and clean data
    print("\n[1/5] Loading and cleaning data...")
    data, feature_names = load_and_clean_data(data_dir, schema)

    # Validate minimum sample count
    if len(data) < 100:
        raise ValueError(
            f"Only {len(data)} valid samples found. "
            "Need at least 100 samples for meaningful training."
        )

    # Optional subsampling for speed
    subsample_note = "Full dataset"
    dataset_files = []
    for d in [data_dir, data_dir / "raw"]:
        if d.exists():
            dataset_files.extend([f.name for f in d.glob("*.csv")])

    if sample_fraction and 0 < sample_fraction < 1:
        n_sample = int(len(data) * sample_fraction)
        data = data.sample(n=n_sample, random_state=42, replace=False)
        subsample_note = f"Subsampled to {sample_fraction*100:.0f}% ({n_sample:,} rows)"
        print(f"  {subsample_note}")

    X = data[feature_names].values
    y = data["BinaryLabel"].values

    # Stratified 80/20 split with fixed seed
    print("\n[2/5] Splitting data (80/20 stratified, seed=42)...")
    splitter = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(splitter.split(X, y))
    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    n_train_normal = int((y_train == 0).sum())
    n_train_attack = int((y_train == 1).sum())
    n_test_normal = int((y_test == 0).sum())
    n_test_attack = int((y_test == 1).sum())

    print(f"  Train: {len(X_train):,} rows (Normal={n_train_normal:,}, Attack={n_train_attack:,})")
    print(f"  Test:  {len(X_test):,} rows (Normal={n_test_normal:,}, Attack={n_test_attack:,})")

    # Build pipeline: Imputer + Random Forest
    # No scaling needed for Random Forest (tree-based, invariant to monotonic transforms)
    print("\n[3/5] Training Random Forest pipeline...")
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight="balanced",  # Handle class imbalance
            random_state=42,
            n_jobs=-1,
            verbose=0
        ))
    ])

    start_time = time.time()
    pipeline.fit(X_train, y_train)
    train_time = time.time() - start_time
    print(f"  Training completed in {train_time:.1f}s")

    # Evaluate
    print("\n[4/5] Evaluating model...")
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]  # Attack probability

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred)

    print(f"\n  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f} (Attack class)")
    print(f"  Recall:    {recall:.4f} (Attack class)")
    print(f"  F1 Score:  {f1:.4f} (Attack class)")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]:,}  FP={cm[0][1]:,}")
    print(f"    FN={cm[1][0]:,}  TP={cm[1][1]:,}")
    print(f"\n  Attack Recall (sensitivity): {recall:.4f}")
    print(f"    ({cm[1][1]:,} attacks detected out of {cm[1][0]+cm[1][1]:,} actual attacks)")
    if cm[1][0] > 0:
        print(f"    ({cm[1][0]:,} attacks were MISSED by the model)")

    # Feature importances
    rf = pipeline.named_steps["classifier"]
    importances = rf.feature_importances_
    feat_imp = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    print(f"\n  Feature Importances (all 22):")
    for name, imp in feat_imp:
        print(f"    {name}: {imp:.4f}")

    # Save model and metadata
    print("\n[5/5] Saving model and metadata...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    model_path = MODELS_DIR / "random_forest_pipeline.joblib"
    joblib.dump(pipeline, model_path)
    print(f"  Model saved to {model_path}")

    # Metadata
    import sklearn
    metadata = {
        "model_type": "RandomForestClassifier",
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "scikit_learn_version": sklearn.__version__,
        "python_version": sys.version,
        "training_date": datetime.now().isoformat(),
        "random_seed": 42,
        "dataset_note": subsample_note,
        "dataset_files": dataset_files,
        "total_rows_used": len(data),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "train_normal": n_train_normal,
        "train_attack": n_train_attack,
        "test_normal": n_test_normal,
        "test_attack": n_test_attack,
        "training_time_seconds": round(train_time, 1),
        "metrics": {
            "accuracy": round(accuracy, 4),
            "precision_attack": round(precision, 4),
            "recall_attack": round(recall, 4),
            "f1_attack": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "confusion_matrix": {
                "TN": int(cm[0][0]), "FP": int(cm[0][1]),
                "FN": int(cm[1][0]), "TP": int(cm[1][1])
            }
        },
        "feature_importances": {name: round(float(imp), 4) for name, imp in feat_imp},
        "pipeline_steps": [
            "SimpleImputer(strategy=median)",
            "RandomForestClassifier(n_estimators=100, max_depth=20, class_weight=balanced)"
        ]
    }

    metadata_path = MODELS_DIR / "model_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"  Metadata saved to {metadata_path}")

    # Save classification report to reports/
    report_text = classification_report(y_test, y_pred, target_names=["Normal", "Attack"])
    report_path = REPORTS_DIR / "classification_report.txt"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("CYBER ATTACK DETECTION - Classification Report\n")
        f.write(f"Date: {datetime.now().isoformat()}\n")
        f.write(f"Dataset: {subsample_note}\n")
        f.write(f"Dataset files: {', '.join(dataset_files)}\n")
        f.write(f"Train/Test Split: 80/20 stratified, seed=42\n\n")
        f.write(report_text)
        f.write(f"\nConfusion Matrix:\n")
        f.write(f"  TN={cm[0][0]:,}  FP={cm[0][1]:,}\n")
        f.write(f"  FN={cm[1][0]:,}  TP={cm[1][1]:,}\n")
        f.write(f"\nROC-AUC: {roc_auc:.4f}\n")
        f.write(f"\nAttack Recall: {recall:.4f}\n")
        f.write(f"  Attacks detected: {cm[1][1]:,} / {cm[1][0]+cm[1][1]:,}\n")
        f.write(f"  Attacks missed:   {cm[1][0]:,}\n")
        f.write(f"\nData Split:\n")
        f.write(f"  Train: {len(X_train):,} (Normal={n_train_normal:,}, Attack={n_train_attack:,})\n")
        f.write(f"  Test:  {len(X_test):,} (Normal={n_test_normal:,}, Attack={n_test_attack:,})\n")
        f.write(f"\nFeature Importances:\n")
        for name, imp in feat_imp:
            f.write(f"  {name}: {imp:.4f}\n")
    print(f"  Report saved to {report_path}")

    # Save detailed metrics report as markdown
    metrics_path = REPORTS_DIR / "metrics_report.md"
    with open(metrics_path, "w", encoding="utf-8") as f:
        f.write("# Model Evaluation Metrics\n\n")
        f.write(f"**Date**: {datetime.now().isoformat()}\n\n")
        f.write(f"**Dataset**: {subsample_note}\n\n")
        f.write(f"**Files**: {', '.join(dataset_files)}\n\n")
        f.write("## Classification Metrics\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| Accuracy | {accuracy:.4f} |\n")
        f.write(f"| Precision (Attack) | {precision:.4f} |\n")
        f.write(f"| Recall (Attack) | {recall:.4f} |\n")
        f.write(f"| F1 Score (Attack) | {f1:.4f} |\n")
        f.write(f"| ROC-AUC | {roc_auc:.4f} |\n")
        f.write("\n## Confusion Matrix\n\n")
        f.write("| | Predicted Normal | Predicted Attack |\n")
        f.write("|---|---|---|\n")
        f.write(f"| **Actual Normal** | TN = {cm[0][0]:,} | FP = {cm[0][1]:,} |\n")
        f.write(f"| **Actual Attack** | FN = {cm[1][0]:,} | TP = {cm[1][1]:,} |\n")
        f.write("\n## Class Distribution\n\n")
        f.write("| Set | Normal | Attack | Total |\n")
        f.write("|-----|--------|--------|-------|\n")
        f.write(f"| Train | {n_train_normal:,} | {n_train_attack:,} | {len(X_train):,} |\n")
        f.write(f"| Test | {n_test_normal:,} | {n_test_attack:,} | {len(X_test):,} |\n")
        f.write(f"| Total | {n_train_normal+n_test_normal:,} | {n_train_attack+n_test_attack:,} | {len(data):,} |\n")
        f.write("\n## Feature Importances\n\n")
        f.write("| Rank | Feature | Importance |\n")
        f.write("|------|---------|------------|\n")
        for rank, (name, imp) in enumerate(feat_imp, 1):
            f.write(f"| {rank} | {name} | {imp:.4f} |\n")
        f.write("\n## Model Configuration\n\n")
        f.write("- **Algorithm**: Random Forest Classifier\n")
        f.write("- **n_estimators**: 100\n")
        f.write("- **max_depth**: 20\n")
        f.write("- **min_samples_split**: 5\n")
        f.write("- **min_samples_leaf**: 2\n")
        f.write("- **class_weight**: balanced\n")
        f.write("- **random_state**: 42\n")
        f.write("- **Preprocessing**: SimpleImputer(strategy=median)\n")
        f.write(f"- **Training time**: {train_time:.1f}s\n")
    print(f"  Metrics report saved to {metrics_path}")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)

    return pipeline, metadata


if __name__ == "__main__":
    # Allow an optional --sample flag for faster testing
    sample = None
    if "--sample" in sys.argv:
        idx = sys.argv.index("--sample")
        if idx + 1 < len(sys.argv):
            sample = float(sys.argv[idx + 1])

    train_model(sample_fraction=sample)
