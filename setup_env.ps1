python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\pip install playwright
.\.venv\Scripts\playwright install chromium
.\.venv\Scripts\python -m backend.training.generate_demo_data
.\.venv\Scripts\python -m backend.training.train
.\.venv\Scripts\python -m backend.training.generate_demo_pcap
