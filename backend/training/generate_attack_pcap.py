"""
Generate a test PCAP file that simulates DDoS attack traffic patterns.

This creates a PCAP with realistic DDoS-like network patterns:
- Many rapid SYN flood packets from multiple sources to one target
- Very high packet rate, low inter-arrival times
- Small packets, many connections, abnormal flag patterns

This is a TEST FILE for demonstration only. 
No real network is attacked. No real traffic is generated.

Usage: python backend/training/generate_attack_pcap.py
"""

import sys
import struct
import random
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data"


def generate_ddos_pcap(output_path, n_packets=2000):
    """
    Generate a PCAP file with DDoS-like traffic patterns.
    
    Creates SYN flood patterns: many small TCP SYN packets sent
    very rapidly from multiple spoofed source IPs to a single target.
    """
    
    # PCAP global header (little-endian)
    # magic, version_major, version_minor, thiszone, sigfigs, snaplen, network(LINKTYPE_ETHERNET=1)
    pcap_header = struct.pack('<IHHiIII', 
        0xa1b2c3d4,  # magic number
        2, 4,         # version
        0, 0,         # timezone, sigfigs
        65535,        # snaplen
        1             # Ethernet link type
    )
    
    packets = []
    
    # Target server (victim of DDoS)
    target_ip = "203.0.113.50"  # TEST-NET-3, safe for documentation
    target_port = 80
    target_mac = b'\x00\x50\x56\xc0\x00\x01'
    
    # Attacker sources (multiple spoofed IPs - using documentation ranges)
    attacker_ips = [f"198.51.100.{i}" for i in range(1, 51)]  # 50 spoofed sources
    attacker_mac = b'\x00\x0c\x29\xaa\xbb\xcc'
    
    base_timestamp = 1609459200.0  # Jan 1, 2021 00:00:00 UTC
    
    def ip_to_bytes(ip_str):
        parts = [int(p) for p in ip_str.split('.')]
        return bytes(parts)
    
    def build_syn_packet(src_ip, dst_ip, src_port, dst_port, seq_num):
        """Build a raw Ethernet + IP + TCP SYN packet."""
        # Ethernet header (14 bytes)
        eth = target_mac + attacker_mac + b'\x08\x00'
        
        # IP header (20 bytes)
        ip_total_len = 20 + 20  # IP header + TCP header (no payload for SYN)
        ip_id = random.randint(1, 65535)
        ip_header = struct.pack('>BBHHHBBH4s4s',
            0x45,           # version=4, IHL=5
            0x00,           # DSCP/ECN
            ip_total_len,   # total length
            ip_id,          # identification
            0x4000,         # flags (Don't Fragment) + fragment offset
            64,             # TTL
            6,              # protocol (TCP)
            0,              # checksum (0 for simplicity)
            ip_to_bytes(src_ip),
            ip_to_bytes(dst_ip)
        )
        
        # TCP header (20 bytes) - SYN flag set
        tcp_flags = 0x02  # SYN only
        tcp_header = struct.pack('>HHIIBBHHH',
            src_port,       # source port
            dst_port,       # destination port
            seq_num,        # sequence number
            0,              # acknowledgment number
            0x50,           # data offset (5 words = 20 bytes)
            tcp_flags,      # flags: SYN
            1024,           # window size (small, typical of attack tools)
            0,              # checksum
            0               # urgent pointer
        )
        
        return eth + ip_header + tcp_header
    
    def build_syn_ack_packet(src_ip, dst_ip, src_port, dst_port):
        """Build a SYN-ACK response (some may come back from target)."""
        eth = attacker_mac + target_mac + b'\x08\x00'
        
        ip_total_len = 20 + 20
        ip_header = struct.pack('>BBHHHBBH4s4s',
            0x45, 0x00, ip_total_len,
            random.randint(1, 65535), 0x4000,
            64, 6, 0,
            ip_to_bytes(src_ip),
            ip_to_bytes(dst_ip)
        )
        
        tcp_flags = 0x12  # SYN+ACK
        tcp_header = struct.pack('>HHIIBBHHH',
            src_port, dst_port,
            random.randint(1, 2**31), 1,
            0x50, tcp_flags,
            29200, 0, 0
        )
        
        return eth + ip_header + tcp_header
    
    def build_rst_packet(src_ip, dst_ip, src_port, dst_port):
        """Build a RST packet (connection reset, common in floods)."""
        eth = target_mac + attacker_mac + b'\x08\x00'
        
        ip_total_len = 20 + 20
        ip_header = struct.pack('>BBHHHBBH4s4s',
            0x45, 0x00, ip_total_len,
            random.randint(1, 65535), 0x4000,
            64, 6, 0,
            ip_to_bytes(src_ip),
            ip_to_bytes(dst_ip)
        )
        
        tcp_flags = 0x04  # RST
        tcp_header = struct.pack('>HHIIBBHHH',
            src_port, dst_port,
            random.randint(1, 2**31), 0,
            0x50, tcp_flags,
            0, 0, 0
        )
        
        return eth + ip_header + tcp_header
    
    random.seed(42)
    current_time = base_timestamp
    
    for i in range(n_packets):
        src_ip = random.choice(attacker_ips)
        src_port = random.randint(1024, 65535)
        
        # 80% SYN floods, 10% RST, 10% SYN-ACK responses
        roll = random.random()
        if roll < 0.80:
            pkt_data = build_syn_packet(src_ip, target_ip, src_port, target_port, 
                                        random.randint(1, 2**31))
        elif roll < 0.90:
            pkt_data = build_rst_packet(src_ip, target_ip, src_port, target_port)
        else:
            pkt_data = build_syn_ack_packet(target_ip, src_ip, target_port, src_port)
        
        # Very small inter-arrival time (DDoS = rapid fire)
        # Normal traffic: 10-500ms between packets
        # DDoS: 0.01-2ms between packets
        current_time += random.uniform(0.00001, 0.002)
        
        ts_sec = int(current_time)
        ts_usec = int((current_time - ts_sec) * 1e6)
        
        # PCAP packet header: ts_sec, ts_usec, incl_len, orig_len
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(pkt_data), len(pkt_data))
        packets.append(pkt_header + pkt_data)
    
    # Write PCAP file
    with open(output_path, 'wb') as f:
        f.write(pcap_header)
        for pkt in packets:
            f.write(pkt)
    
    print(f"  Generated {n_packets} DDoS attack packets")
    print(f"  Attack type: SYN Flood")
    print(f"  Target: {target_ip}:{target_port}")
    print(f"  Sources: {len(attacker_ips)} spoofed IPs")
    print(f"  Duration: {current_time - base_timestamp:.2f} seconds")
    print(f"  Packet rate: ~{n_packets / (current_time - base_timestamp):.0f} pkt/s")
    print(f"  File size: {os.path.getsize(output_path) / 1024:.1f} KB")


def generate_normal_pcap(output_path, n_packets=200):
    """
    Generate a PCAP file with normal-looking web browsing traffic.
    Slower pace, proper handshakes, data exchange, FIN teardown.
    """
    
    pcap_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    packets = []
    
    client_ip = "192.168.1.100"
    server_ip = "93.184.216.34"  # example.com
    client_mac = b'\x00\x50\x56\xc0\x00\x02'
    server_mac = b'\x00\x50\x56\xc0\x00\x03'
    
    base_timestamp = 1609459200.0
    
    def ip_to_bytes(ip_str):
        parts = [int(p) for p in ip_str.split('.')]
        return bytes(parts)
    
    def build_tcp_packet(src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port, 
                         flags, payload_size=0, window=65535):
        eth = dst_mac + src_mac + b'\x08\x00'
        
        ip_total_len = 20 + 20 + payload_size
        ip_header = struct.pack('>BBHHHBBH4s4s',
            0x45, 0x00, ip_total_len,
            random.randint(1, 65535), 0x4000,
            64, 6, 0,
            ip_to_bytes(src_ip), ip_to_bytes(dst_ip)
        )
        
        tcp_header = struct.pack('>HHIIBBHHH',
            src_port, dst_port,
            random.randint(1, 2**31), random.randint(1, 2**31),
            0x50, flags, window, 0, 0
        )
        
        payload = b'\x00' * payload_size
        return eth + ip_header + tcp_header + payload
    
    random.seed(123)
    current_time = base_timestamp
    
    # Simulate several normal web browsing sessions
    for session in range(10):
        client_port = random.randint(49152, 65535)
        server_port = random.choice([80, 443])
        
        # SYN
        pkt = build_tcp_packet(client_ip, server_ip, client_mac, server_mac,
                              client_port, server_port, 0x02, window=65535)
        ts_sec = int(current_time); ts_usec = int((current_time - ts_sec) * 1e6)
        packets.append(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)
        current_time += random.uniform(0.01, 0.05)
        
        # SYN-ACK
        pkt = build_tcp_packet(server_ip, client_ip, server_mac, client_mac,
                              server_port, client_port, 0x12, window=29200)
        ts_sec = int(current_time); ts_usec = int((current_time - ts_sec) * 1e6)
        packets.append(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)
        current_time += random.uniform(0.01, 0.05)
        
        # ACK
        pkt = build_tcp_packet(client_ip, server_ip, client_mac, server_mac,
                              client_port, server_port, 0x10, window=65535)
        ts_sec = int(current_time); ts_usec = int((current_time - ts_sec) * 1e6)
        packets.append(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)
        current_time += random.uniform(0.1, 1.0)
        
        # Data exchange (PSH+ACK with payload, simulating HTTP)
        for _ in range(random.randint(3, 8)):
            payload_sz = random.randint(100, 1400)
            pkt = build_tcp_packet(client_ip, server_ip, client_mac, server_mac,
                                  client_port, server_port, 0x18, payload_size=payload_sz)
            ts_sec = int(current_time); ts_usec = int((current_time - ts_sec) * 1e6)
            packets.append(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)
            current_time += random.uniform(0.05, 0.5)
            
            # Server response
            resp_sz = random.randint(200, 1400)
            pkt = build_tcp_packet(server_ip, client_ip, server_mac, client_mac,
                                  server_port, client_port, 0x18, payload_size=resp_sz)
            ts_sec = int(current_time); ts_usec = int((current_time - ts_sec) * 1e6)
            packets.append(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)
            current_time += random.uniform(0.05, 0.5)
        
        # FIN
        pkt = build_tcp_packet(client_ip, server_ip, client_mac, server_mac,
                              client_port, server_port, 0x11)
        ts_sec = int(current_time); ts_usec = int((current_time - ts_sec) * 1e6)
        packets.append(struct.pack('<IIII', ts_sec, ts_usec, len(pkt), len(pkt)) + pkt)
        current_time += random.uniform(0.5, 3.0)  # pause between sessions
    
    with open(output_path, 'wb') as f:
        f.write(pcap_header)
        for pkt in packets:
            f.write(pkt)
    
    print(f"  Generated {len(packets)} normal browsing packets")
    print(f"  Sessions: 10 web browsing sessions")
    print(f"  Duration: {current_time - base_timestamp:.2f} seconds")
    print(f"  File size: {os.path.getsize(output_path) / 1024:.1f} KB")


if __name__ == "__main__":
    print("=" * 60)
    print("TEST PCAP FILE GENERATOR")
    print("For demonstration purposes only")
    print("=" * 60)
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate DDoS attack PCAP
    attack_path = OUTPUT_DIR / "test_ddos_attack.pcap"
    print(f"\n[1/2] Generating DDoS ATTACK test file...")
    generate_ddos_pcap(attack_path, n_packets=2000)
    print(f"  Saved to: {attack_path}")
    
    # Generate normal traffic PCAP
    normal_path = OUTPUT_DIR / "test_normal_traffic.pcap"
    print(f"\n[2/2] Generating NORMAL traffic test file...")
    generate_normal_pcap(normal_path, n_packets=200)
    print(f"  Saved to: {normal_path}")
    
    print(f"\n{'=' * 60}")
    print("DEMO INSTRUCTIONS:")
    print("1. Start the server:  python -m uvicorn backend.main:app")
    print("2. Open http://127.0.0.1:8000")
    print("3. Upload 'test_normal_traffic.pcap'  → Should show NORMAL, LOW risk")
    print("4. Upload 'test_ddos_attack.pcap'     → Should show ATTACK, HIGH risk")
    print("=" * 60)
