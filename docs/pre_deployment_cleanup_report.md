# Pre-Deployment Cleanup Report

**Project**: CyberShield — Network Attack & Intrusion Detection System  
**Date**: October 11, 2026  
**Status**: Pre-Cleanup Assessment & Architectural Classification  

---

## 1. Executive Summary

This report provides a comprehensive pre-deployment inventory and audit of the CyberShield codebase. The inspection identified all core runtime dependencies, development scripts, datasets, and transient artifacts to prepare the repository for production deployment and academic viva examination.

**Key Findings:**
- The runtime application is self-contained with zero external cloud dependencies.
- The machine learning model (`random_forest_pipeline.joblib`) is intact, validated, and matches the 22-feature schema.
- All core backend, frontend, database, and report generation modules are verified and functional.
- Four temporary root scripts containing hardcoded local user paths were identified for safe removal.
- All 9 packages listed in `requirements.txt` are actively used in the codebase.

---

## 2. Current Project Structure

```
Mini_Project/
├── .gitattributes
├── .gitignore
├── .python-version
├── README.md
├── requirements.txt
├── setup_env.ps1
├── capture_report.py                   # [Temporary script]
├── generate_danger_pcap.py             # [Redundant root script]
├── generate_ppt_screenshots.py         # [Temporary script]
├── test_playwright_screenshots.py      # [Temporary script]
├── cyber_attacks.db                    # [Local development SQLite DB]
├── backend/
│   ├── __init__.py
│   ├── main.py                         # [Runtime: FastAPI entry point]
│   ├── database/
│   │   ├── __init__.py
│   │   └── db.py                       # [Runtime: SQLite DB layer]
│   ├── ml/
│   │   ├── __init__.py
│   │   └── predict.py                  # [Runtime: Flow prediction]
│   ├── pcap/
│   │   ├── __init__.py
│   │   └── extract.py                  # [Runtime: Scapy feature extractor]
│   ├── reports/
│   │   ├── __init__.py
│   │   └── pdf_generator.py            # [Runtime: PDF report generator]
│   ├── risk/
│   │   ├── __init__.py
│   │   └── score.py                    # [Runtime: Risk calculation]
│   └── training/
│       ├── __init__.py
│       ├── generate_attack_pcap.py     # [Training/Dev tool]
│       ├── generate_demo_data.py       # [Training data generator]
│       ├── generate_demo_pcap.py       # [Training/Dev PCAP generator]
│       └── train.py                    # [Offline model training]
├── config/
│   ├── feature_schema.json             # [Runtime: 22-feature specification]
│   └── risk_config.json                # [Runtime: Risk scoring weights]
├── data/
│   ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv  # [Training dataset, 77MB]
│   ├── attack_port_scan.pcap           # [Sample test PCAP]
│   ├── attack_sample.pcap              # [Sample test PCAP]
│   ├── danger_attack.pcap              # [Sample test PCAP]
│   ├── demo_capture.pcap               # [Sample test PCAP]
│   ├── processed/                      # [Empty directory]
│   └── raw/
│       └── demo_training_data.csv      # [Training dataset, 3MB]
├── docs/
│   ├── architecture.md                 # [System documentation]
│   ├── pre_deployment_cleanup_report.md# [This report]
│   ├── pre_deployment_final_report.md  # [Final deployment report]
│   └── test_report.md                  # [Testing report]
├── frontend/
│   ├── app.js                          # [Runtime: Dashboard logic]
│   ├── index.html                      # [Runtime: UI markup]
│   └── styles.css                      # [Runtime: Theme & styling]
├── models/
│   ├── model_metadata.json             # [Runtime: Model metrics/info]
│   └── random_forest_pipeline.joblib   # [Runtime: Serialized ML pipeline]
├── reports/
│   ├── classification_report.txt       # [Evaluation report]
│   └── metrics_report.md               # [Model performance report]
├── tests/
│   ├── __init__.py
│   ├── test_e2e_upload.py              # [Integration test]
│   └── test_system.py                  # [Automated test suite]
└── uploads/                            # [Runtime PCAP storage, .gitignored]
```

---

## 3. Classification of Files

### 3.1. Definitely Required at Runtime (Production)
These files are strictly required for the application to boot, serve traffic, classify packet flows, and produce security reports:

| File | Purpose |
|---|---|
| `backend/main.py` | FastAPI application, CORS, upload handlers, API routes, static file serving |
| `backend/database/db.py` | SQLite schema creation, capture history, simulated blocklist |
| `backend/ml/predict.py` | Model pipeline loader, flow inference, prediction summary aggregation |
| `backend/pcap/extract.py` | Scapy packet reader, TCP/UDP/ICMP reassembly, 22-feature extraction |
| `backend/reports/pdf_generator.py` | ReportLab PDF security audit document generation |
| `backend/risk/score.py` | Weighted risk scoring formula, severity level calculation |
| `config/feature_schema.json` | 22 network flow statistical features schema |
| `config/risk_config.json` | Risk scoring weights and alert thresholds |
| `models/random_forest_pipeline.joblib` | Trained scikit-learn Random Forest model binary |
| `models/model_metadata.json` | Model version, training date, classification metrics |
| `frontend/index.html` | Dashboard HTML layout, SOC navigation tabs |
| `frontend/styles.css` | CyberShield SOC visual theme, dark mode styling |
| `frontend/app.js` | Dashboard logic, chart rendering, API client, PDF download handler |
| `requirements.txt` | Python runtime dependencies |
| `.python-version` | Python runtime environment version (3.12) |
| `README.md` | Deployment setup and execution documentation |

### 3.2. Required Only for Model Training (Development / Offline)
These files are needed for retraining the Random Forest model or generating synthetic data, but are not invoked during live user sessions:

| File | Purpose |
|---|---|
| `backend/training/train.py` | Random Forest model training script, CV evaluation, model export |
| `backend/training/generate_demo_data.py` | Generates balanced synthetic flow dataset |
| `backend/training/generate_demo_pcap.py` | Generates benign test PCAP for baseline validation |
| `backend/training/generate_attack_pcap.py` | Generates synthetic attack PCAPs for model validation |
| `data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Original CIC-IDS2017 DDoS dataset (77 MB) |
| `data/raw/demo_training_data.csv` | Synthetic flow training data (3 MB) |
| `reports/classification_report.txt` | Text export of precision, recall, and F1 scores |
| `reports/metrics_report.md` | Markdown report summarizing training evaluation |

*Decision: Keep in local workspace for academic reproducibility; ensure large CSVs remain excluded from git deployment.*

### 3.3. Required Only for Development / Testing
These files ensure system stability and developer onboarding:

| File | Purpose |
|---|---|
| `tests/test_system.py` | 12-test automated verification suite |
| `tests/test_e2e_upload.py` | Quick command-line PCAP upload test |
| `setup_env.ps1` | PowerShell environment setup script |
| `data/*.pcap` | Curated sample PCAP files (`danger_attack.pcap`, `attack_sample.pcap`, etc.) |

---

## 4. Unnecessary & Safe-to-Remove Files

The following files are identified as temporary, redundant, or developer scratch files that are safe to remove without affecting system functionality:

| File | Reason for Removal | Status |
|---|---|---|
| `capture_report.py` | One-off Playwright screenshot script with hardcoded local paths | **SAFE TO REMOVE** |
| `generate_ppt_screenshots.py` | One-off slide screenshot capture script with hardcoded local paths | **SAFE TO REMOVE** |
| `test_playwright_screenshots.py` | One-off Playwright screenshot script with hardcoded local paths | **SAFE TO REMOVE** |
| `generate_danger_pcap.py` | Redundant copy of `backend/training/generate_attack_pcap.py` | **SAFE TO REMOVE** |
| `data/processed/` | Empty directory | **SAFE TO REMOVE** |
| `uploads/*.pcap` | Transient uploaded test captures from prior runs (auto-created at runtime) | **SAFE TO REMOVE** |
| `__pycache__/` | Python compiled bytecode directories across all modules | **SAFE TO REMOVE** |

---

## 5. Dependency Audit (`requirements.txt`)

All 9 listed packages in `requirements.txt` were verified against active imports:

| Package | Used By | Required |
|---|---|---|
| `fastapi>=0.115.0` | `backend/main.py` (Core web framework) | Yes |
| `uvicorn>=0.30.0` | Server runner / Render start command | Yes |
| `scikit-learn==1.7.0` | `backend/ml/predict.py`, `backend/training/train.py` | Yes |
| `pandas>=2.2.0` | `backend/pcap/extract.py`, `backend/ml/predict.py` | Yes |
| `numpy>=1.26.0` | `backend/pcap/extract.py`, `backend/ml/predict.py` | Yes |
| `joblib>=1.4.0` | `backend/ml/predict.py`, `backend/training/train.py` | Yes |
| `scapy>=2.6.0` | `backend/pcap/extract.py` (Packet inspection) | Yes |
| `python-multipart>=0.0.12` | `backend/main.py` (Multipart PCAP uploads) | Yes |
| `reportlab>=4.0.0` | `backend/reports/pdf_generator.py` (PDF report engine) | Yes |

*Result: Zero unused dependencies. No packages need removal.*

---

## 6. Environment & Secret Audit

- **Secrets / Passwords**: No API keys, passwords, or secret credentials found.
- **Hardcoded Local Paths**: The only personal Windows paths detected (`C:\Users\saive\...`) are located exclusively inside the 3 temporary screenshot scripts (`capture_report.py`, `generate_ppt_screenshots.py`, `test_playwright_screenshots.py`). Removing these scripts completely cleans the codebase of hardcoded paths.
- **Application Paths**: All core modules (`backend/main.py`, `backend/database/db.py`, `backend/pcap/extract.py`, `backend/risk/score.py`) use robust relative path resolution via `Path(__file__).resolve().parent`.

---

## 7. Action Plan

1. **Part 3**: Remove confirmed unwanted root scripts (`capture_report.py`, `generate_danger_pcap.py`, `generate_ppt_screenshots.py`, `test_playwright_screenshots.py`), clean `uploads/` test artifacts, and clean `__pycache__`.
2. **Part 5 - 11**: Add comprehensive, viva-friendly educational comments explaining the ML pipeline, PCAP extraction, risk scoring, API routes, and frontend interactions.
3. **Part 14**: Verify `.gitignore` to ensure private/generated files are excluded.
4. **Part 16**: Run the automated test suite to ensure 100% functionality preservation.
5. **Part 19**: Produce `docs/pre_deployment_final_report.md`.
