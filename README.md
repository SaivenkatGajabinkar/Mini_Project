# 🛡️ CyberShield — Detection of Cyber Attack in Network Using Machine Learning

A web-based system that analyses Wireshark network captures (.pcapng) using a Random Forest classifier to detect malicious network traffic, compute risk scores, and display results on an interactive dashboard.

## Architecture

```
Wireshark Capture (.pcapng)
        │
        ▼
  Validate file (magic bytes, size)
        │
        ▼
  Extract network flows (Scapy)
        │
        ▼
  Compute 22 features per flow
        │
        ▼
  Random Forest prediction (Normal/Attack)
        │
        ▼
  Risk score + Level (LOW/MEDIUM/HIGH)
        │
        ▼
  SQLite storage + Web Dashboard
```

### Two Separate Processes

| | Training (offline, once) | Prediction (per upload) |
|---|---|---|
| **Input** | CIC-IDS2017 labelled flow CSV | User's .pcapng file |
| **Output** | Saved model pipeline + metrics | Per-flow labels, risk score, report |
| **When** | Before first use | Each time a file is uploaded |

## Quick Start

### 1. Setup

```bash
cd Mini_Project
python -m venv .venv

# Windows
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Train the Model

**Option A — Quick Demo (no download needed):**
```bash
python -m backend.training.generate_demo_data
python -m backend.training.train
```

**Option B — Real Dataset:**
Download the CIC-IDS2017 labelled flow CSV files from:
https://www.unb.ca/cic/datasets/ids-2017.html

Place the CSV files in `data/raw/`, then:
```bash
python -m backend.training.train
```

Optional: Generate a test PCAP file for upload testing:
```bash
python -m backend.training.generate_demo_pcap
```

### 3. Run the Dashboard

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open http://localhost:8000 in your browser.

### 4. Use the System

1. **Upload** a .pcapng or .pcap file from Wireshark
2. **View** the analysis: risk score, suspicious IPs, flow breakdown
3. **Block** suspicious IPs (simulated — no real network changes)
4. **Download** an HTML report for documentation
5. **Review** history of all past analyses

## Project Structure

```
Mini_Project/
├── README.md
├── requirements.txt
├── .gitignore
├── config/
│   ├── feature_schema.json    # 22 features (single source of truth)
│   └── risk_config.json       # Risk formula weights and thresholds
├── docs/
│   ├── feature_schema.md      # Feature documentation
│   └── decision_report.md     # Technical decisions and rationale
├── data/raw/                  # CIC-IDS2017 CSVs (not committed)
├── models/
│   ├── random_forest_pipeline.joblib  # Trained model
│   └── model_metadata.json           # Training details and metrics
├── reports/                   # Training metrics and reports
├── backend/
│   ├── main.py                # FastAPI application
│   ├── training/train.py      # Training pipeline
│   ├── pcap/extract.py        # PCAPNG → flow features
│   ├── ml/predict.py          # Model prediction + summary
│   ├── risk/score.py          # Risk scoring
│   └── database/db.py         # SQLite storage
├── frontend/
│   ├── index.html             # Dashboard HTML
│   ├── app.js                 # Frontend logic
│   └── styles.css             # Premium dark theme
├── uploads/                   # Uploaded captures (auto-cleaned)
└── tests/                     # Test suite
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | System health and model status |
| POST | `/api/analyze` | Upload and analyse a capture |
| GET | `/api/captures` | List all capture history |
| GET | `/api/captures/{id}` | Full result for one capture |
| GET | `/api/captures/{id}/report` | Downloadable HTML report |
| POST | `/api/block` | Simulate blocking an IP |
| GET | `/api/blocked` | List simulated blocks |
| DELETE | `/api/blocked/{id}` | Remove a simulated block |

## Feature Schema (22 Features)

The model uses 22 numeric features per network flow:

- **Timing**: Flow Duration, Flow IAT Mean/Std/Max, Fwd/Bwd IAT Mean
- **Volume**: Total Fwd/Bwd Packets, Total Length of Fwd/Bwd Packets
- **Size**: Fwd/Bwd Packet Length Max/Mean, Average Packet Size
- **Rate**: Flow Bytes/s, Flow Packets/s
- **TCP Flags**: SYN/ACK/RST/PSH Flag Count
- **TCP**: Init_Win_bytes_forward

## Risk Scoring

```
risk_score = 100 × (0.5 × attack_ratio + 0.3 × mean_probability + 0.2 × volume_factor)
```

- **LOW**: score < 30
- **MEDIUM**: 30 ≤ score < 60
- **HIGH**: score ≥ 60

All constants are configurable in `config/risk_config.json`.

## Dataset

**CIC-IDS2017** from the Canadian Institute for Cybersecurity, University of New Brunswick.
- URL: https://www.unb.ca/cic/datasets/ids-2017.html
- Contains labelled network flow data with BENIGN and various attack types
- Captures from a 2017 lab network over 5 days

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | 0.115.0 | Web API framework |
| uvicorn | 0.30.6 | ASGI server |
| scikit-learn | 1.5.2 | Random Forest classifier, pipeline |
| pandas | 2.2.3 | Data manipulation |
| numpy | 1.26.4 | Numerical operations |
| joblib | 1.4.2 | Model serialization |
| scapy | 2.6.1 | PCAP/PCAPNG packet parsing |
| python-multipart | 0.0.12 | File upload handling |

## Limitations

1. **Domain shift**: CIC-IDS2017 was recorded in 2017. Modern traffic (QUIC, HTTP/3, cloud sync) may look different from training data, causing false alarms on normal captures.
2. **Binary only**: The model says Normal or Attack, not the type of attack.
3. **Per-flow decisions**: Capture-level status is a summary rule on top of flow predictions, not a separate model.
4. **Optimistic benchmarks**: Random train/test splits on this dataset tend to overstate real-world performance.
5. **Extractor fidelity**: Feature extraction may not perfectly match CICFlowMeter's internal rules.
6. **Scope**: Offline analysis of uploaded captures; no live monitoring, no real blocking.

## Security

- Files validated by magic bytes, not just extension
- Uploads stored under random UUID filenames
- Model loaded only from project's own `models/` directory
- All HTML output is escaped to prevent XSS
- All SQL queries use parameterised statements
- IP blocking is simulated only — no firewall/network changes
- Old uploads automatically deleted after 24 hours

## License

This is a B.Tech mini-project for educational purposes.
