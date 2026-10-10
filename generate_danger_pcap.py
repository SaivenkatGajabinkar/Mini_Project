import struct
import time
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

def create_attack_pcap(output_path: str):
    global_header = struct.pack(
        "<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
    )

    packets = []
    base_time = int(time.time()) - 60

    # Danger IP
    src_ip = (203, 0, 113, 42) # Danger IP Example
    dst_ip = (192, 168, 1, 100) # Target server
    
    src_port = 44444
    dst_port = 80
    proto = 6 # TCP

    # Generate 60 packets for a single flow to mimic high attack volume
    for i in range(60):
        ts = base_time + i * 0.001
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        eth_dst = b'\x00\x11\x22\x33\x44\x55'
        eth_src = b'\x66\x77\x88\x99\xAA\xBB'
        eth_type = struct.pack(">H", 0x0800)
        eth_header = eth_dst + eth_src + eth_type

        payload = b'DANGER_PAYLOAD' * 100

        # TCP Flags: Many SYNs, PSHs, RSTs
        tcp_flags = 0x02 # SYN
        if i % 3 == 0:
            tcp_flags = 0x18 # PSH + ACK
        elif i % 5 == 0:
            tcp_flags = 0x04 # RST

        init_win_bytes = 1024

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

    with open(output_path, "wb") as f:
        f.write(global_header)
        for pkt_data in packets:
            f.write(pkt_data)

def main():
    output_dir = PROJECT_ROOT / "data"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "danger_attack.pcap"
    create_attack_pcap(str(output_path))
    print(f"Created danger attack PCAP at {output_path}")

if __name__ == "__main__":
    main()
