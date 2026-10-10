import struct
import time
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

def create_attack_pcap(output_path: str):
    global_header = struct.pack(
        "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
    )

    packets = []
    base_time = int(time.time()) - 60

    # Suspicious IP
    src_ip = (185, 220, 101, 45) # "malicious" IP
    dst_ip = (192, 168, 1, 10)   # target internal server
    
    src_port = 44444
    dst_port = 80
    proto = 6 # TCP

    # Generate 60 packets for a single flow to mimic high attack volume
    for i in range(60):
        ts = base_time + i * 0.001 # 1ms between packets (very fast = high packets/s)
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        eth_dst = b'\x00\x11\x22\x33\x44\x55'
        eth_src = b'\x66\x77\x88\x99\xAA\xBB'
        eth_type = struct.pack(">H", 0x0800)
        eth_header = eth_dst + eth_src + eth_type

        # Large payload to get high Fwd Packet Length Mean/Max and Total Length
        payload = b'A' * 1400

        # TCP Flags: Many SYNs, PSHs, RSTs
        tcp_flags = 0x02 # SYN
        if i % 3 == 0:
            tcp_flags = 0x18 # PSH + ACK
        elif i % 5 == 0:
            tcp_flags = 0x04 # RST

        init_win_bytes = 1024 # Small window size

        tcp_header = struct.pack(">HHIIBBHHH",
            src_port, dst_port,
            1000 + i,          
            2000 + i,          
            0x50,              
            tcp_flags,         
            init_win_bytes,    
            0,                 
            0                  
        )
        transport_header = tcp_header

        ip_total_len = 20 + len(transport_header) + len(payload)
        ip_header = struct.pack(">BBHHHBBH4s4s",
            0x45,              
            0,                 
            ip_total_len,      
            i + 1,             
            0x4000,            
            64,                
            proto,             
            0,                 
            bytes(src_ip),     
            bytes(dst_ip)      
        )

        full_packet = eth_header + ip_header + transport_header + payload
        pkt_header = struct.pack("<IIII", ts_sec, ts_usec, len(full_packet), len(full_packet))

        packets.append(pkt_header + full_packet)
        
    # Also add a few normal flows just to have contrast
    for i in range(10):
        ts = base_time + i * 0.1
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        eth_header = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\x08\x00'
        payload = b'Normal data'
        tcp_header = struct.pack(">HHIIBBHHH", 50000, 443, 100, 200, 0x50, 0x10, 65535, 0, 0)
        
        ip_total_len = 20 + len(tcp_header) + len(payload)
        ip_header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, ip_total_len, i + 100, 0x4000, 64, 6, 0, bytes([10,0,0,5]), bytes([142,250,80,46]))

        full_packet = eth_header + ip_header + tcp_header + payload
        pkt_header = struct.pack("<IIII", ts_sec, ts_usec, len(full_packet), len(full_packet))
        packets.append(pkt_header + full_packet)

    with open(output_path, "wb") as f:
        f.write(global_header)
        for pkt_data in packets:
            f.write(pkt_data)

def main():
    output_dir = PROJECT_ROOT / "data"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "attack_sample.pcap"
    create_attack_pcap(str(output_path))
    print(f"Created attack PCAP at {output_path}")

if __name__ == "__main__":
    main()
