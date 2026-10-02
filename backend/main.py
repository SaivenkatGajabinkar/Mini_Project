"""
FastAPI Backend — Cyber Attack Detection System.
=================================================

This is the main application file that ties the entire system together.

The complete pipeline when a user uploads a PCAPNG file:

    1. User uploads a .pcapng/.pcap file through the dashboard
    2. /api/analyze endpoint validates the file (extension + magic bytes)
    3. extract.py reads packets and groups them into network flows
    4. predict.py runs the trained Random Forest model on each flow
    5. score.py computes the overall risk score (0-100)
    6. db.py stores the results in SQLite for history
    7. JSON response is sent back to the frontend dashboard

The backend also serves the frontend HTML/CSS/JS files directly,
so only one server needs to run (no separate frontend server).

Start with: uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
"""

import json
import uuid
import shutil
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UPLOADS_DIR = PROJECT_ROOT / "uploads"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
CONFIG_DIR = PROJECT_ROOT / "config"

# ── Lazy Module Loading ──────────────────────────────────────────────
# Scapy takes ~2 seconds to import, so we delay importing the modules
# that depend on it until they are actually needed. This makes the
# server start up instantly instead of waiting for Scapy.
_extract_module = None
_predict_module = None
_risk_module = None
_db_module = None


def _get_extract():
    global _extract_module
    if _extract_module is None:
        from backend.pcap import extract
        _extract_module = extract
    return _extract_module


def _get_predict():
    global _predict_module
    if _predict_module is None:
        from backend.ml import predict
        _predict_module = predict
    return _predict_module


def _get_risk():
    global _risk_module
    if _risk_module is None:
        from backend.risk import score
        _risk_module = score
    return _risk_module


def _get_db():
    global _db_module
    if _db_module is None:
        from backend.database import db
        _db_module = db
    return _db_module


def _load_risk_config():
    config_path = CONFIG_DIR / "risk_config.json"
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle: runs on startup and shutdown.

    On startup:
    1. Create the uploads/ directory if it doesn't exist
    2. Initialize the SQLite database (creates tables on first run)
    3. Start a background thread to auto-delete old uploads (every hour)
    4. Pre-load the Random Forest model into memory for fast predictions
    """
    # Ensure uploads directory exists for saving uploaded capture files
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize the database (creates tables if this is the first run)
    db = _get_db()
    db.init_db()

    # Start background cleanup: deletes uploaded files older than 24 hours
    # This prevents the uploads/ folder from growing indefinitely
    db.start_cleanup_task(interval_seconds=3600)

    # Load the trained ML model into memory so predictions are fast
    # (loading the ~1.6 MB model from disk takes ~0.5s, so we do it once)
    try:
        predict = _get_predict()
        predict.load_pipeline()
        print("ML model loaded successfully")
    except FileNotFoundError:
        print("WARNING: ML model not found. Train the model first with:")
        print("  python -m backend.training.train")

    yield  # Server is running — handle requests

    # Shutdown (nothing to clean up currently)


app = FastAPI(
    title="Cyber Attack Detection System",
    description="Detection of Cyber Attack in Network Using Machine Learning",
    version="1.0.0",
    lifespan=lifespan,
)


# ══════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

@app.get("/api/health")
async def health_check():
    """Liveness check and model status."""
    predict = _get_predict()
    try:
        _, metadata = predict.load_pipeline()
        model_loaded = True
        model_version = metadata.get("training_date", "unknown")
        metrics = metadata.get("metrics", {})
    except FileNotFoundError:
        model_loaded = False
        model_version = None
        metrics = {}

    return {
        "status": "healthy",
        "model_loaded": model_loaded,
        "model_version": model_version,
        "metrics": metrics,
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/api/analyze")
async def analyze_capture(file: UploadFile = File(...)):
    """
    Main analysis endpoint — the heart of the application.

    This runs the complete pipeline:
    Upload → Validate → Extract Features → ML Predict → Risk Score → Store → Return

    The user uploads a Wireshark .pcapng or .pcap file, and gets back
    a complete analysis with risk score, suspicious IPs, and per-flow labels.
    """
    # ── Step 1: Validate the file extension ──
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in (".pcapng", ".pcap"):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type '{ext}'. Only .pcapng and .pcap files are accepted."
        )

    # ── Step 2: Check file size limit (from risk_config.json) ──
    risk_config = _load_risk_config()
    max_size_mb = risk_config.get("max_upload_size_mb", 50)
    max_size_bytes = max_size_mb * 1024 * 1024

    # ── Step 3: Save the uploaded file with a random UUID name ──
    # Using UUID prevents filename collisions and path traversal attacks
    capture_id = str(uuid.uuid4())
    upload_path = UPLOADS_DIR / f"{capture_id}{ext}"

    try:
        # Read and validate size while saving
        total_size = 0
        with open(upload_path, "wb") as f:
            while True:
                chunk = await file.read(8192)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > max_size_bytes:
                    # Clean up oversized file
                    f.close()
                    upload_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Maximum size is {max_size_mb} MB."
                    )
                f.write(chunk)

        if total_size == 0:
            upload_path.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        # ── Step 4: Extract network flow features from the PCAP file ──
        # This converts raw packets into the 22 numerical features the model expects
        extract = _get_extract()
        try:
            features_df = extract.extract_features(upload_path, max_size_mb=max_size_mb)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        # ── Step 5: Run the Random Forest model on each flow ──
        # Each flow gets a Normal/Attack label and an attack probability score
        predict = _get_predict()
        try:
            predictions_df = predict.predict(features_df)
        except FileNotFoundError:
            raise HTTPException(
                status_code=503,
                detail="ML model not loaded. Please train the model first."
            )

        # ── Step 6: Aggregate per-flow predictions into a capture summary ──
        summary = predict.summarise(predictions_df)

        # ── Step 7: Compute overall risk score (0-100) and risk level ──
        risk = _get_risk()
        result = risk.compute_risk(summary)

        # ── Step 8: Get model version for the response ──
        _, metadata = predict.load_pipeline()
        model_version = metadata.get("training_date", "unknown")

        # ── Step 9: Store the result in SQLite for capture history ──
        db = _get_db()
        db.store_capture(capture_id, file.filename, result, model_version)

        return {
            "capture_id": capture_id,
            "filename": file.filename,
            "status": result["status"],
            "risk_level": result["risk_level"],
            "risk_score": result["risk_score"],
            "total_flows": result["total_flows"],
            "attack_flows": result["attack_flows"],
            "normal_flows": result["normal_flows"],
            "attack_ratio": result["attack_ratio"],
            "mean_attack_probability": result["mean_attack_probability"],
            "suspicious_ips": result["suspicious_ips"],
            "top_suspicious_flows": result["top_suspicious_flows"],
            "protocol_breakdown": result["protocol_breakdown"],
            "model_version": model_version,
            "analysed_at": datetime.now().isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        # Clean up on unexpected error
        upload_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/api/captures")
async def list_captures():
    """Get history of all analyzed captures, newest first."""
    db = _get_db()
    captures = db.get_captures_list()
    return {"captures": captures}


@app.get("/api/captures/{capture_id}")
async def get_capture(capture_id: str):
    """Get full result for a single capture."""
    db = _get_db()
    result = db.get_capture(capture_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return result


@app.get("/api/captures/{capture_id}/report")
async def get_capture_report(capture_id: str):
    """Generate and return an HTML report for a capture."""
    db = _get_db()
    result = db.get_capture(capture_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Capture not found")

    # Generate simple HTML report
    suspicious_flows_html = ""
    for flow in result.get("top_suspicious_flows", []):
        suspicious_flows_html += f"""
        <tr>
            <td>{_escape(str(flow.get('src_ip', '')))}</td>
            <td>{_escape(str(flow.get('dst_ip', '')))}</td>
            <td>{flow.get('src_port', 0)}</td>
            <td>{flow.get('dst_port', 0)}</td>
            <td>{_escape(str(flow.get('protocol', '')))}</td>
            <td>{flow.get('attack_probability', 0):.4f}</td>
            <td>{_escape(str(flow.get('label', '')))}</td>
        </tr>"""

    suspicious_ips_html = ""
    for ip_info in result.get("suspicious_ips", []):
        suspicious_ips_html += f"""
        <tr>
            <td>{_escape(str(ip_info.get('ip', '')))}</td>
            <td>{ip_info.get('attack_flows', 0)}</td>
        </tr>"""

    protocol_html = ""
    for proto, count in result.get("protocol_breakdown", {}).items():
        protocol_html += f"<tr><td>{_escape(str(proto))}</td><td>{count}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Analysis Report - {_escape(str(result.get('original_name', 'Unknown')))}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #1a1a2e; background: #f8f9fa; }}
        h1 {{ color: #16213e; border-bottom: 3px solid #0f3460; padding-bottom: 10px; }}
        h2 {{ color: #0f3460; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #dee2e6; padding: 10px 14px; text-align: left; }}
        th {{ background: #0f3460; color: white; }}
        tr:nth-child(even) {{ background: #f1f3f5; }}
        .status {{ display: inline-block; padding: 6px 16px; border-radius: 20px; font-weight: bold; color: white; }}
        .status.ATTACK {{ background: #e74c3c; }}
        .status.NORMAL {{ background: #2ecc71; }}
        .risk.HIGH {{ color: #e74c3c; }}
        .risk.MEDIUM {{ color: #f39c12; }}
        .risk.LOW {{ color: #2ecc71; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .summary-card h3 {{ margin: 0 0 5px 0; font-size: 14px; color: #666; }}
        .summary-card .value {{ font-size: 28px; font-weight: bold; color: #16213e; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #666; font-size: 12px; }}
        @media print {{ body {{ margin: 20px; }} }}
    </style>
</head>
<body>
    <h1>🛡️ Cyber Attack Detection Report</h1>
    <p><strong>File:</strong> {_escape(str(result.get('original_name', 'Unknown')))}</p>
    <p><strong>Analyzed:</strong> {_escape(str(result.get('uploaded_at', '')))}</p>
    <p><strong>Capture ID:</strong> {_escape(capture_id)}</p>

    <h2>Summary</h2>
    <div class="summary-grid">
        <div class="summary-card">
            <h3>Status</h3>
            <span class="status {result.get('status', 'NORMAL')}">{result.get('status', 'NORMAL')}</span>
        </div>
        <div class="summary-card">
            <h3>Risk Level</h3>
            <span class="risk {result.get('risk_level', 'LOW')}" style="font-size:28px;font-weight:bold;">{result.get('risk_level', 'LOW')}</span>
        </div>
        <div class="summary-card">
            <h3>Risk Score</h3>
            <div class="value">{result.get('risk_score', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>Total Flows</h3>
            <div class="value">{result.get('total_flows', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>Attack Flows</h3>
            <div class="value" style="color:#e74c3c;">{result.get('attack_flows', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>Normal Flows</h3>
            <div class="value" style="color:#2ecc71;">{result.get('normal_flows', 0)}</div>
        </div>
    </div>

    <h2>Protocol Breakdown</h2>
    <table>
        <tr><th>Protocol</th><th>Flow Count</th></tr>
        {protocol_html if protocol_html else '<tr><td colspan="2">No protocol data</td></tr>'}
    </table>

    <h2>Suspicious IPs</h2>
    <table>
        <tr><th>IP Address</th><th>Attack Flows</th></tr>
        {suspicious_ips_html if suspicious_ips_html else '<tr><td colspan="2">No suspicious IPs detected</td></tr>'}
    </table>

    <h2>Top Suspicious Flows</h2>
    <table>
        <tr><th>Source IP</th><th>Dest IP</th><th>Src Port</th><th>Dst Port</th><th>Protocol</th><th>Attack Prob.</th><th>Label</th></tr>
        {suspicious_flows_html if suspicious_flows_html else '<tr><td colspan="7">No suspicious flows detected</td></tr>'}
    </table>

    <h2>Notes</h2>
    <ul>
        <li>Attack type is not classified — the model outputs binary Normal/Attack labels only.</li>
        <li>Risk score formula: 100 × (0.5 × attack_ratio + 0.3 × mean_probability + 0.2 × volume_factor)</li>
        <li>Model version: {_escape(str(result.get('model_version', 'unknown')))}</li>
    </ul>

    <div class="footer">
        <p>Generated by Cyber Attack Detection System | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>This report is for educational and demonstration purposes.</p>
    </div>
</body>
</html>"""

    return HTMLResponse(content=html)


@app.post("/api/block")
async def block_ip(data: dict):
    """
    Simulate blocking a suspicious IP address.

    IMPORTANT: This is a SIMULATION only — no real firewall rules are created.
    In a real production system, this would call iptables (Linux) or
    Windows Firewall APIs to create actual blocking rules.
    """
    ip = data.get("ip")
    capture_id = data.get("capture_id", "")
    note = data.get("note", "")

    if not ip:
        raise HTTPException(status_code=400, detail="IP address is required")

    db = _get_db()
    block_id = db.add_simulated_block(ip, capture_id, note)

    return {
        "id": block_id,
        "ip": ip,
        "capture_id": capture_id,
        "status": "BLOCKED (SIMULATED)",
        "message": f"IP {ip} has been blocked (SIMULATED). This is a simulation only — no network changes were made."
    }


@app.get("/api/blocked")
async def list_blocked():
    """List all simulated blocks. Always labelled SIMULATED."""
    db = _get_db()
    blocks = db.get_simulated_blocks()
    return {"blocks": blocks}


@app.delete("/api/blocked/{block_id}")
async def unblock_ip(block_id: int):
    """Remove a simulated block."""
    db = _get_db()
    removed = db.remove_simulated_block(block_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Block not found")
    return {"message": "Simulated block removed", "id": block_id}


def _escape(text: str) -> str:
    """Escape HTML special characters to prevent XSS."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


# ══════════════════════════════════════════════════════════════════════
# FRONTEND SERVING
# The frontend (HTML/CSS/JS) is served directly by FastAPI.
# No separate web server or Node.js is needed.
# ══════════════════════════════════════════════════════════════════════

# Serve frontend static files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
async def serve_frontend():
    """Serve the main frontend page."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return HTMLResponse(
        content="<h1>Cyber Attack Detection System</h1>"
        "<p>Frontend not found. Place index.html in the frontend/ directory.</p>"
    )


@app.get("/{path:path}")
async def serve_static_files(path: str):
    """Serve other frontend static files."""
    # Prevent path traversal
    safe_path = Path(path).name
    file_path = FRONTEND_DIR / safe_path
    if file_path.exists() and file_path.is_file():
        return FileResponse(str(file_path))
    raise HTTPException(status_code=404, detail="Not found")
