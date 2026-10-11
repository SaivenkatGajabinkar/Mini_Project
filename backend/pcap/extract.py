"""
PCAPNG/PCAP to Network Flow Feature Extraction Module.
=======================================================

This is the FIRST STEP in the prediction pipeline:

    PCAPNG/PCAP file  →  [THIS MODULE]  →  22 features per flow  →  ML model

How it works:
1. Validates the uploaded capture file (checks magic bytes, size limit).
2. Reads all packets from the file using Scapy.
3. Groups packets into bidirectional network flows using the 5-tuple:
   (source IP, destination IP, source port, destination port, protocol).
4. For each flow, computes the same 22 numerical features that the
   Random Forest model was trained on (from CIC-IDS2017 dataset).
5. Returns a DataFrame where each row is one flow with 22 feature columns
   plus metadata columns (IPs, ports, protocol, timestamp).

The 22 features are defined in config/feature_schema.json (single source of truth).
The extraction approach mimics CICFlowMeter's feature definitions but uses
Scapy for packet parsing instead of Java.
"""

import json
from pathlib import Path
from collections import defaultdict
from typing import Optional

import numpy as np
import pandas as pd

# Lazy import scapy to speed up module loading
# (Scapy takes ~2 seconds to import, so we only load it when actually needed)
_scapy_loaded = False
_rdpcap = None
_IP = None
_TCP = None
_UDP = None


def _load_scapy():
    """Lazy-load Scapy modules to avoid slow import on startup."""
    global _scapy_loaded, _rdpcap, _IP, _TCP, _UDP
    if not _scapy_loaded:
        # Suppress Scapy warnings
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        from scapy.all import rdpcap, IP, TCP, UDP
        _rdpcap = rdpcap
        _IP = IP
        _TCP = TCP
        _UDP = UDP
        _scapy_loaded = True


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"

# ── File format magic bytes ──────────────────────────────────────────
# Used to validate that uploaded files are genuine packet captures,
# not just renamed text files or malware.
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'   # PCAPNG Section Header Block
PCAP_MAGIC_BE = b'\xa1\xb2\xc3\xd4'  # Classic PCAP (big-endian)
PCAP_MAGIC_LE = b'\xd4\xc3\xb2\xa1'  # Classic PCAP (little-endian)

# ── Flow aggregation settings ────────────────────────────────────────
# These match CICFlowMeter defaults so our features are compatible
# with the CIC-IDS2017 training data.
FLOW_TIMEOUT = 120      # seconds — max idle time before a flow expires
ACTIVITY_TIMEOUT = 5    # seconds — gap that splits active/idle periods


def load_feature_schema():
    """Load the 22 feature names from the single source of truth."""
    schema_path = CONFIG_DIR / "feature_schema.json"
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    return [f["name"] for f in schema["features"]]


def validate_capture_file(filepath: Path, max_size_mb: float = 50) -> str:
    """
    Validate a capture file by checking extension, size, and magic bytes.

    This prevents processing of non-capture files, oversized files,
    or potentially malicious uploads.

    Returns:
        'pcapng' or 'pcap' indicating the detected file type.

    Raises:
        ValueError: If validation fails with a user-friendly message.
    """
    if not filepath.exists():
        raise ValueError(f"File not found: {filepath}")

    # Reject files that are too large (prevents memory issues)
    size_mb = filepath.stat().st_size / (1024 * 1024)
    if size_mb > max_size_mb:
        raise ValueError(
            f"File too large: {size_mb:.1f} MB (limit: {max_size_mb} MB)"
        )

    if filepath.stat().st_size == 0:
        raise ValueError("File is empty")

    # Check the first 4 bytes (magic number) to identify file format.
    # This is more reliable than checking the file extension alone.
    with open(filepath, "rb") as f:
        header = f.read(4)

    if header == PCAPNG_MAGIC:
        return "pcapng"
    elif header in (PCAP_MAGIC_BE, PCAP_MAGIC_LE):
        return "pcap"
    else:
        raise ValueError(
            f"Invalid file format. Expected PCAPNG or PCAP capture file. "
            f"Got header bytes: {header.hex()}"
        )


def _get_flow_key(pkt) -> Optional[tuple]:
    """
    Extract the 5-tuple flow key from a packet.

    A flow key identifies a network connection:
    (source IP, destination IP, source port, destination port, protocol)

    For non-TCP/UDP packets (e.g., ICMP), ports are set to 0.
    """
    if not pkt.haslayer(_IP):
        return None

    ip = pkt[_IP]
    src_ip = ip.src
    dst_ip = ip.dst
    proto = ip.proto  # 6=TCP, 17=UDP

    src_port = 0
    dst_port = 0

    if pkt.haslayer(_TCP):
        src_port = pkt[_TCP].sport
        dst_port = pkt[_TCP].dport
    elif pkt.haslayer(_UDP):
        src_port = pkt[_UDP].sport
        dst_port = pkt[_UDP].dport
    else:
        # Non-TCP/UDP (ICMP, etc.) — use protocol number, no ports
        pass

    return (src_ip, dst_ip, src_port, dst_port, proto)


def _compute_flow_features(flow_packets, flow_key) -> dict:
    """
    Compute the 22 features for a single network flow.

    Each flow has two directions:
    - Forward: packets from the flow initiator (first packet's source)
    - Backward: packets going back to the initiator

    The 22 features capture:
    - Flow timing (duration, inter-arrival times)
    - Packet volume (counts in each direction)
    - Packet sizes (total, max, mean in each direction)
    - Flow rates (bytes/second, packets/second)
    - TCP flags (SYN, ACK, RST, PSH counts)
    - TCP window size (initial forward window)

    These match the CIC-IDS2017 feature definitions used during training.
    """
    src_ip, dst_ip, src_port, dst_port, proto = flow_key

    # Separate packets into forward (src→dst) and backward (dst→src) lists
    fwd_packets = []
    bwd_packets = []

    timestamps = []
    fwd_timestamps = []
    bwd_timestamps = []

    init_win_fwd = -1  # Will be set from first forward TCP packet

    for pkt in flow_packets:
        if not pkt.haslayer(_IP):
            continue

        ip = pkt[_IP]
        ts = float(pkt.time)
        timestamps.append(ts)

        # Packet payload size (not including headers)
        pkt_len = len(ip.payload) if ip.payload else 0

        # Determine direction: compare with the flow's established src/dst
        if ip.src == src_ip and ip.dst == dst_ip:
            # Forward packet (same direction as the first packet)
            fwd_packets.append(pkt_len)
            fwd_timestamps.append(ts)

            # Capture initial TCP window size from first forward packet
            # This is a useful feature because attack tools often use
            # small or unusual window sizes
            if init_win_fwd == -1 and pkt.haslayer(_TCP):
                init_win_fwd = pkt[_TCP].window
        else:
            # Backward packet (response direction)
            bwd_packets.append(pkt_len)
            bwd_timestamps.append(ts)

    if not timestamps:
        return None

    timestamps.sort()
    fwd_timestamps.sort()
    bwd_timestamps.sort()

    # ── Feature 1: Flow Duration (microseconds) ──
    flow_duration = (timestamps[-1] - timestamps[0]) * 1e6 if len(timestamps) > 1 else 0

    # ── Features 2-3: Packet counts ──
    total_fwd = len(fwd_packets)
    total_bwd = len(bwd_packets)

    # ── Features 4-5: Total payload lengths ──
    total_len_fwd = sum(fwd_packets)
    total_len_bwd = sum(bwd_packets)

    # ── Features 6-7: Forward packet size statistics ──
    fwd_len_max = max(fwd_packets) if fwd_packets else 0
    fwd_len_mean = np.mean(fwd_packets) if fwd_packets else 0

    # ── Features 8-9: Backward packet size statistics ──
    bwd_len_max = max(bwd_packets) if bwd_packets else 0
    bwd_len_mean = np.mean(bwd_packets) if bwd_packets else 0

    # ── Features 10-11: Flow rates ──
    duration_sec = flow_duration / 1e6
    total_bytes = total_len_fwd + total_len_bwd
    total_pkts = total_fwd + total_bwd

    # Avoid division by zero: if duration is 0, rate is 0
    # (this matches how CIC-IDS2017 handles zero-duration flows)
    flow_bytes_s = total_bytes / duration_sec if duration_sec > 0 else 0
    flow_pkts_s = total_pkts / duration_sec if duration_sec > 0 else 0

    # ── Features 12-16: Inter-Arrival Times (IATs) ──
    # IAT = time gap between consecutive packets in the flow
    def calc_iats(ts_list):
        if len(ts_list) < 2:
            return []
        return [ts_list[i+1] - ts_list[i] for i in range(len(ts_list) - 1)]

    flow_iats = calc_iats(timestamps)
    fwd_iats = calc_iats(fwd_timestamps)
    bwd_iats = calc_iats(bwd_timestamps)

    # Convert IATs to microseconds to match CIC-IDS2017 convention
    flow_iats_us = [iat * 1e6 for iat in flow_iats]
    fwd_iats_us = [iat * 1e6 for iat in fwd_iats]
    bwd_iats_us = [iat * 1e6 for iat in bwd_iats]

    flow_iat_mean = np.mean(flow_iats_us) if flow_iats_us else 0
    flow_iat_std = np.std(flow_iats_us) if flow_iats_us else 0
    flow_iat_max = max(flow_iats_us) if flow_iats_us else 0
    fwd_iat_mean = np.mean(fwd_iats_us) if fwd_iats_us else 0
    bwd_iat_mean = np.mean(bwd_iats_us) if bwd_iats_us else 0

    # ── Features 17-20: TCP flag counts ──
    # These are important for detecting attacks:
    # - High SYN count → possible SYN flood attack
    # - High RST count → port scanning or rejected connections
    # - High PSH count → data exfiltration attempts
    syn_count = 0
    ack_count = 0
    rst_count = 0
    psh_count = 0

    for pkt in flow_packets:
        if pkt.haslayer(_TCP):
            flags = pkt[_TCP].flags
            if flags.S: syn_count += 1
            if flags.A: ack_count += 1
            if flags.R: rst_count += 1
            if flags.P: psh_count += 1

    # ── Feature 21: Average Packet Size ──
    all_sizes = fwd_packets + bwd_packets
    avg_pkt_size = np.mean(all_sizes) if all_sizes else 0

    # ── Feature 22: Initial TCP Window Size (forward) ──
    # Attack tools often use small/unusual window sizes
    init_win_fwd_val = init_win_fwd if init_win_fwd >= 0 else 0

    # Protocol name for metadata (not a model feature)
    proto_map = {6: "TCP", 17: "UDP"}
    proto_name = proto_map.get(proto, str(proto))

    return {
        # The 22 schema features in the EXACT order matching feature_schema.json
        "Flow Duration": flow_duration,
        "Total Fwd Packets": total_fwd,
        "Total Backward Packets": total_bwd,
        "Total Length of Fwd Packets": total_len_fwd,
        "Total Length of Bwd Packets": total_len_bwd,
        "Fwd Packet Length Max": fwd_len_max,
        "Fwd Packet Length Mean": fwd_len_mean,
        "Bwd Packet Length Max": bwd_len_max,
        "Bwd Packet Length Mean": bwd_len_mean,
        "Flow Bytes/s": flow_bytes_s,
        "Flow Packets/s": flow_pkts_s,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Fwd IAT Mean": fwd_iat_mean,
        "Bwd IAT Mean": bwd_iat_mean,
        "SYN Flag Count": syn_count,
        "ACK Flag Count": ack_count,
        "RST Flag Count": rst_count,
        "PSH Flag Count": psh_count,
        "Average Packet Size": avg_pkt_size,
        "Init_Win_bytes_forward": init_win_fwd_val,
        # Metadata columns (prefixed with '_', NOT fed to the model)
        "_src_ip": src_ip,
        "_dst_ip": dst_ip,
        "_src_port": src_port,
        "_dst_port": dst_port,
        "_protocol": proto_name,
        "_timestamp": timestamps[0] if timestamps else 0,
    }


def extract_features(filepath, max_size_mb: float = 50) -> pd.DataFrame:
    """
    Extract network flow features from a PCAPNG or PCAP file.

    This is the main entry point called by the API when a user uploads a file.

    Pipeline:
        1. Validate file format (magic bytes check)
        2. Read all packets using Scapy
        3. Group packets into bidirectional flows (using 5-tuple keys)
        4. Compute 22 features for each flow
        5. Return a DataFrame ready for the ML model

    Args:
        filepath: Path to the capture file (.pcap or .pcapng).
        max_size_mb: Maximum allowed file size in MB.

    Returns:
        DataFrame with 22 feature columns + metadata columns
        (prefixed with '_' for IPs, ports, protocol, timestamp).

    Raises:
        ValueError: If the file is invalid, corrupt, or yields no flows.
    """
    filepath = Path(filepath)
    _load_scapy()

    # Step 1: Validate the uploaded file
    file_type = validate_capture_file(filepath, max_size_mb)

    # Step 2: Read all packets from the capture file
    try:
        packets = _rdpcap(str(filepath))
    except Exception as e:
        raise ValueError(f"Failed to read capture file: {e}")

    if len(packets) == 0:
        raise ValueError("Capture file contains no packets")

    # Step 3: Group packets into bidirectional flows
    # A flow is bidirectional: packets from A→B and B→A belong to the same flow
    flows = defaultdict(list)
    flow_keys = {}  # canonical key → (src, dst, sport, dport, proto)

    ip_packet_count = 0
    for pkt in packets:
        if not pkt.haslayer(_IP):
            continue

        ip_packet_count += 1
        key = _get_flow_key(pkt)
        if key is None:
            continue

        src_ip, dst_ip, src_port, dst_port, proto = key

        # Create canonical key for bidirectional matching:
        # Check both forward and reverse directions to find existing flow
        forward_key = (src_ip, dst_ip, src_port, dst_port, proto)
        reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)

        if forward_key in flow_keys:
            canonical = forward_key
        elif reverse_key in flow_keys:
            canonical = reverse_key
        else:
            # New flow — first packet defines the forward direction
            canonical = forward_key
            flow_keys[canonical] = canonical

        flows[canonical].append(pkt)

    if ip_packet_count == 0:
        raise ValueError(
            "No IP packets found in capture. The file may contain "
            "non-IP traffic or use an unsupported link type."
        )

    if len(flows) == 0:
        raise ValueError("No network flows could be extracted from the capture")

    # Step 4: Compute the 22 features for each flow
    feature_names = load_feature_schema()
    all_features = []

    for flow_key, flow_pkts in flows.items():
        features = _compute_flow_features(flow_pkts, flow_key)
        if features is not None:
            all_features.append(features)

    if not all_features:
        raise ValueError("Feature computation yielded no valid flows")

    df = pd.DataFrame(all_features)

    # Sort by timestamp for deterministic, chronological order
    df.sort_values("_timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    return df
