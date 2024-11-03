import threading
from scapy.all import sniff,get_working_ifaces
from PyQt5 import QtWidgets,QtCore
from ui_mainwindow import Ui_MainWindow

# class PacketSniffer():
#     def __init__(self):
#         self.sniffing = False
#         self.thread = None
#         #self.lock = threading.Lock()

#     def start_sniffing(self,select_interface, filter_condition, update_callback):
#         #获取用户选择的网卡和输入的过滤条件
#         if not self.sniffing:
#             self.sniffing = True
#             self.thread = threading.Thread(target=self.sniff_packets, args=(select_interface, filter_condition, update_callback))
#             self.thread.setDaemon(True)
#             self.thread.start()

#     def stop_sniffing(self):
#         if self.sniffing:
#             self.sniffing = False
#             if self.thread:
#                 self.thread.join(timeout=1)
#             self.sniffer.stop()



#     def sniff_packets(self, select_interface, filter_condition, update_callback):
#         sniff(iface=select_interface, filter=filter_condition, prn=lambda pkt: update_callback(pkt), stop_filter=lambda x: not self.sniffing)

class PacketSnifferThread(QtCore.QThread):
    packetCaptured = QtCore.pyqtSignal(object)  # 定义信号，用于传递捕获的数据包

    def __init__(self, select_interface, filter_condition):
        super().__init__()
        self.select_interface = select_interface
        self.filter_condition = filter_condition
        self.sniffing = True

    # def run(self):
    #     # 使用 Scapy 嗅探数据包并通过信号发送给主线程
    #     sniff(
    #         iface=self.select_interface,
    #         filter=self.filter_condition,
    #         prn=lambda pkt: self.packetCaptured.emit(pkt),
    #         stop_filter=lambda x: not self.sniffing
    #     )

    def run(self):
        sniff(
            iface=self.select_interface,
            filter=self.filter_condition,
            prn=lambda pkt: self.process_packet(pkt),
            stop_filter=lambda x: not self.sniffing
        )

    def process_packet(self, pkt):
        if self.sniffing:
            self.packetCaptured.emit(pkt)

    def stop(self):
        self.sniffing = False  