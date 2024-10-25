import threading
from scapy.all import sniff
from PyQt5 import QtWidgets
from ui_mainwindow import Ui_MainWindow

class PacketSniffer():
    def __init__(self):
        self.sniffing = False
        self.thread = None
        #self.lock = threading.Lock()

    def start_sniffing(self,select_interface, filter_condition, update_callback):
        #获取用户选择的网卡和输入的过滤条件
        if not self.sniffing:
            self.sniffing = True
            self.thread = threading.Thread(target=self.sniff_packets, args=(select_interface, filter_condition, update_callback))
            self.thread.setDaemon(True)
            self.thread.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            # if self.thread:
            #     self.thread.join(timeout=1)
            #self.sniffer.stop()



    def sniff_packets(self, select_interface, filter_condition, update_callback):
        sniff(iface=select_interface, filter=filter_condition, prn=lambda pkt: update_callback(pkt), stop_filter=lambda x: not self.sniffing)
