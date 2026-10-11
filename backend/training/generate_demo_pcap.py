"""
Generate a small demo PCAP file for testing the upload flow.

Creates a valid PCAP file with synthetic network packets (TCP and UDP)
that can be uploaded through the dashboard.

Usage: python -m backend.training.generate_demo_pcap
"""

import struct
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def create_demo_pcap(output_path: str, n_packets: int = 50):
    """
    Create a valid PCAP file with synthetic TCP and UDP packets.
    Uses raw binary PCAP format (no external dependencies needed).
    """
    # PCAP Global Header
    # magic, version_major, version_minor, thiszone, sigfigs, snaplen, network
    global_header = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic number (little-endian)
        2, 4,         # version 2.4
        0,            # timezone (UTC)
        0,            # sig figs
        65535,        # snap length
        1             # network type (Ethernet)
    )

    packets = []
    base_time = int(time.time()) - 60  # start 60 seconds ago

    # Generate some realistic IP addresses
    src_ips = [
        (192, 168, 1, 10),
        (192, 168, 1, 20),
        (10, 0, 0, 5),
    ]
    dst_ips = [
        (93, 184, 216, 34),   # example.com
        (142, 250, 80, 46),   # google
        (151, 101, 1, 69),    # reddit
        (192, 168, 1, 1),     # gateway
    ]

    for i in range(n_packets):
        ts = base_time + i * 0.05  # 50ms between packets
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        src_ip = src_ips[i % len(src_ips)]
        dst_ip = dst_ips[i % len(dst_ips)]

        # Alternate between TCP and UDP
        is_tcp = (i % 3 != 0)
        proto = 6 if is_tcp else 17

        src_port = 40000 + (i % 100)
        dst_port = 80 if is_tcp else 53

        # Build raw packet

        # Ethernet header (14 bytes)
        eth_dst = b'\x00\x11\x22\x33\x44\x55'
        eth_src = b'\x66\x77\x88\x99\xAA\xBB'
        eth_type = struct.pack(">H", 0x0800)  # IPv4
        eth_header = eth_dst + eth_src + eth_type

        # Payload (some random bytes)
        payload = bytes([i % 256] * (20 + i % 40))

        if is_tcp:
            # TCP header (20 bytes minimum)
            tcp_flags = 0x18  # PSH + ACK
            if i % 10 == 0:
                tcp_flags = 0x02  # SYN
            elif i % 15 == 0:
                tcp_flags = 0x04  # RST
            elif i % 7 == 0:
                tcp_flags = 0x10  # ACK only

            tcp_header = struct.pack(">HHIIBBHHH",
                src_port, dst_port,
                1000 + i,          # seq number
                2000 + i,          # ack number
                0x50,              # data offset (5 words = 20 bytes)
                tcp_flags,         # flags
                65535,             # window
                0,                 # checksum (0 = not computed)
                0                  # urgent pointer
            )
            transport_header = tcp_header
        else:
            # UDP header (8 bytes)
            udp_len = 8 + len(payload)
            udp_header = struct.pack(">HHHH",
                src_port, dst_port,
                udp_len,
                0  # checksum
            )
            transport_header = udp_header

        # IP header (20 bytes)
        ip_total_len = 20 + len(transport_header) + len(payload)
        ip_header = struct.pack(">BBHHHBBH4s4s",
            0x45,              # version (4) + IHL (5)
            0,                 # DSCP/ECN
            ip_total_len,      # total length
            i + 1,             # identification
            0x4000,            # flags + fragment offset (Don't Fragment)
            64,                # TTL
            proto,             # protocol
            0,                 # checksum (0 = not computed)
            bytes(src_ip),     # source IP
            bytes(dst_ip)      # dest IP
        )

        full_packet = eth_header + ip_header + transport_header + payload

        # PCAP packet header
        pkt_header = struct.pack("<IIII",
            ts_sec,
            ts_usec,
            len(full_packet),   # captured length
            len(full_packet)    # original length
        )

        packets.append(pkt_header + full_packet)

    # Write PCAP file
    with open(output_path, "wb") as f:
        f.write(global_header)
        for pkt_data in packets:
            f.write(pkt_data)

    return n_packets


def main():
    output_dir = PROJECT_ROOT / "data"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / "demo_capture.pcap"
    n = create_demo_pcap(str(output_path), n_packets=50)

    print(f"Created demo PCAP with {n} packets at {output_path}")
    print(f"File size: {output_path.stat().st_size} bytes")
    print("\nYou can upload this file through the dashboard to test the analysis flow.")
    print("The file uses PCAP format (not PCAPNG) with synthetic TCP/UDP traffic.")


if __name__ == "__main__":
    main()
