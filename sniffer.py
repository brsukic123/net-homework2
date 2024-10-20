import threading
from scapy.all import sniff

class PacketSniffer:
    def __init__(self):
        self.sniffing = False
        self.thread = None

    def start(self, interface, filter_condition, update_callback):
        if not self.sniffing:
            self.sniffing = True
            self.thread = threading.Thread(target=self.sniff_packets, args=(interface, filter_condition, update_callback))
            self.thread.start()

    def stop(self):
        if self.sniffing:
            self.sniffing = False
            if self.thread:
                self.thread.join()

    def sniff_packets(self, interface, filter_condition, update_callback):
        sniff(iface=interface, filter=filter_condition, prn=lambda pkt: update_callback(pkt), stop_filter=lambda x: not self.sniffing)
