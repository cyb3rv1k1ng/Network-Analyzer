import threading
from queue import Queue
from src.capture import packet_sniffer
from src.analyze import analyze_packets
from src.utils import load_config

def main():
    config = load_config()
    interface = config.get("interface", "eth0")
    capture_filter = config.get("capture_filter", "ip")
    
    packet_queue = Queue()

    capture_thread = threading.Thread(target=packet_sniffer, args=(packet_queue, interface, capture_filter))
    analyze_thread = threading.Thread(target=analyze_packets, args=(packet_queue, config))

    capture_thread.start()
    analyze_thread.start()

    capture_thread.join()
    analyze_thread.join()

if __name__ == "__main__":
    main()
