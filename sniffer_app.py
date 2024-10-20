from PyQt5 import QtWidgets
from scapy.all import*
from sniffer import PacketSniffer
from ui_mainwindow import Ui_MainWindow


show_interfaces()#显示网卡

class SnifferApp(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self) #UI
        self.sniffer = PacketSniffer() #初始化嗅探器实例
        
        self.packetCounter = 0  # 用于记录数据包编号
        self.packetListWidget.setSortingEnabled(True)

        # 填充网卡选择下拉框
        self.interfaceComboBox.addItems(get_if_list())

        self.packetListWidget.itemClicked.connect(self.show_packet_details)

    def start_sniffing(self):
        interface = self.interfaceComboBox.currentText()  # 获取当前选中的网卡
        filter_condition = self.filterInput.text()  # 获取过滤条件
        self.sniffer.start(interface, filter_condition, self.update_packet_list)
        self.statusBar().showMessage(f"Sniffing on {interface}")

    def stop_sniffing(self):
        self.sniffer.stop()
        self.statusBar().showMessage("Sniffing stopped")

    def update_packet_list(self, packet):
        # 处理并显示数据包信息
        self.packetCounter += 1
        packet_time = packet.time  # 获取捕获时间
        packet_src = packet[0][1].src  # 获取源地址
        packet_dst = packet[0][1].dst  # 获取目标地址
        packet_proto = packet[0][1].proto  # 获取协议
        packet_len = len(packet)  # 获取数据包长度

        # 在数据包列表中添加新行
        row_position = self.packetListWidget.rowCount()
        self.packetListWidget.insertRow(row_position)
        self.packetListWidget.setItem(row_position, 0, QtWidgets.QTableWidgetItem(str(self.packetCounter)))
        self.packetListWidget.setItem(row_position, 1, QtWidgets.QTableWidgetItem(str(packet_time)))
        self.packetListWidget.setItem(row_position, 2, QtWidgets.QTableWidgetItem(str(packet_src)))
        self.packetListWidget.setItem(row_position, 3, QtWidgets.QTableWidgetItem(str(packet_dst)))
        self.packetListWidget.setItem(row_position, 4, QtWidgets.QTableWidgetItem(str(packet_proto)))
        self.packetListWidget.setItem(row_position, 5, QtWidgets.QTableWidgetItem(str(packet_len)))

    def show_packet_details(self, item):
        # 显示选中数据包的详细信息
        selected_row = item.row()
        packet_info = [self.packetListWidget.item(selected_row, i).text() for i in range(self.packetListWidget.columnCount())]
        # TODO: 实现显示详细信息的逻辑
        