import sys
import threading
from PyQt5 import QtWidgets
from scapy.all import get_if_list
from sniffer import PacketSniffer
from ui_mainwindow import Ui_MainWindow
from sniffer_app import*

if __name__ == "__main__":

    app = QtWidgets.QApplication(sys.argv)
    window = SnifferApp()
    
    window.setWindowTitle("网络嗅探器")
    window.show()
    
    sys.exit(app.exec_())
