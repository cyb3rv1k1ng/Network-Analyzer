from scapy.all import sniff
from queue import Queue

def packet_sniffer(packet_queue: Queue, interface: str, capture_filter: str):
    def enqueue_packet(pkt):
        packet_queue.put(pkt)
    
    sniff(iface=interface, filter=capture_filter, prn=enqueue_packet, store=False)
