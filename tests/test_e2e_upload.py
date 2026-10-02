"""Quick end-to-end test: upload demo PCAP and print result."""
import urllib.request
import json
import os

PCAP_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "demo_capture.pcap")
API_URL = "http://localhost:8000/api/analyze"

body = open(PCAP_PATH, "rb").read()
boundary = b"----BOUNDARY9876543210"

data = (
    b"------BOUNDARY9876543210\r\n"
    b'Content-Disposition: form-data; name="file"; filename="demo.pcap"\r\n'
    b"Content-Type: application/octet-stream\r\n\r\n"
    + body
    + b"\r\n------BOUNDARY9876543210--\r\n"
)

req = urllib.request.Request(
    API_URL,
    data=data,
    headers={"Content-Type": "multipart/form-data; boundary=----BOUNDARY9876543210"},
)

try:
    r = urllib.request.urlopen(req)
    result = json.loads(r.read().decode())
    print("=== Upload + Analysis Result ===")
    print(f"Status:       {result['status']}")
    print(f"Risk Level:   {result['risk_level']}")
    print(f"Risk Score:   {result['risk_score']}")
    print(f"Total Flows:  {result['total_flows']}")
    print(f"Attack Flows: {result['attack_flows']}")
    print(f"Normal Flows: {result['normal_flows']}")
    print(f"Capture ID:   {result['capture_id']}")
    if result.get("suspicious_ips"):
        print(f"Suspicious IPs: {[ip['ip'] for ip in result['suspicious_ips']]}")
    if result.get("protocol_breakdown"):
        print(f"Protocols:    {result['protocol_breakdown']}")
    print("=== END-TO-END TEST PASSED ===")
except urllib.error.HTTPError as e:
    print(f"HTTP Error {e.code}: {e.read().decode()}")
except Exception as e:
    print(f"Error: {e}")
