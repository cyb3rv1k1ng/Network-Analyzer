from scapy.all import TCP, IP
from collections import defaultdict
import time
from src.alert import alert_suspicious_activity

packet_counter = defaultdict(list)  # Track timestamps of packets per IP

def analyze_packets(packet_queue, config):
    suspicious_ports = config.get("suspicious_ports", [])
    threshold = config.get("alert_threshold", 10)

    while True:
        pkt = packet_queue.get()
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_port = pkt[TCP].dport

            # Check suspicious ports
            if dst_port in suspicious_ports:
                alert_suspicious_activity(f"Suspicious port connection detected: {src_ip} -> Port {dst_port}")

            # Flood detection
            current_time = time.time()
            packet_counter[src_ip].append(current_time)
            # Remove old timestamps (>10 seconds ago)
            packet_counter[src_ip] = [t for t in packet_counter[src_ip] if current_time - t <= 10]

            if len(packet_counter[src_ip]) > threshold:
                alert_suspicious_activity(f"Potential DoS attack from {src_ip}: {len(packet_counter[src_ip])} packets in 10 seconds!")
