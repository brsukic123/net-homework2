from PyQt5 import QtWidgets, QtCore

class Ui_MainWindow:
    def setupUi(self, MainWindow):

        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)

        # 创建中央窗口
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        MainWindow.setCentralWidget(self.centralwidget)
        self.layout = QtWidgets.QVBoxLayout(self.centralwidget)  # 主布局为垂直布局

        # 创建一个新的布局，包含网卡选择框和filter框
        self.interfaceAndFilterLayout = QtWidgets.QHBoxLayout()  # 水平布局

        # 添加网卡选择的控件
        self.interfaceLabel = QtWidgets.QLabel("网卡选择:")
        self.interfaceAndFilterLayout.addWidget(self.interfaceLabel)

        self.interfaceComboBox = QtWidgets.QComboBox()
        self.interfaceComboBox.setMinimumWidth(300)  
        self.interfaceComboBox.setMinimumHeight(30)  
        self.interfaceComboBox.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        self.interfaceAndFilterLayout.addWidget(self.interfaceComboBox)

        # 添加过滤器相关的控件
        self.filterLayout = QtWidgets.QHBoxLayout()  # 水平布局，用于放置filter和按钮

        self.filterLabel = QtWidgets.QLabel("捕获过滤:")
        self.filterLayout.addWidget(self.filterLabel)

        self.filterInput = QtWidgets.QLineEdit()
        self.filterInput.setMinimumWidth(300)  
        self.filterInput.setMinimumHeight(30)  
        self.filterInput.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        self.filterLayout.addWidget(self.filterInput)

        # 添加 Start 和 Stop 按钮，放置在过滤器右侧
        self.startButton = QtWidgets.QPushButton("开始")
        self.stopButton = QtWidgets.QPushButton("结束")
        self.startButton.setMinimumWidth(100)  # 固定按钮宽度
        self.stopButton.setMinimumWidth(100)

        # 将按钮添加到filter框的右侧
        self.filterLayout.addWidget(self.startButton)
        self.filterLayout.addWidget(self.stopButton)

        # 将filter的水平布局添加到整体水平布局中
        self.interfaceAndFilterLayout.addLayout(self.filterLayout)

        # 将interface和filter布局添加到主布局中
        self.layout.addLayout(self.interfaceAndFilterLayout)

        # Packet List 窗格
        self.packetListWidget = QtWidgets.QTableWidget()
        self.packetListWidget.setColumnCount(6)
        self.packetListWidget.setHorizontalHeaderLabels(["No", "Time", "Source", "Destination", "Protocol", "Length"])
        self.layout.addWidget(self.packetListWidget)

        # Packet Details 窗格
        self.packetDetailsTextEdit = QtWidgets.QTextEdit()
        self.packetDetailsTextEdit.setPlaceholderText("Packet Details will be shown here...")
        self.layout.addWidget(self.packetDetailsTextEdit)

        # Packet in Binary 窗格
        self.packetBinaryTextEdit = QtWidgets.QTextEdit()
        self.packetBinaryTextEdit.setPlaceholderText("Packet in Binary will be shown here...")
        self.layout.addWidget(self.packetBinaryTextEdit)

        MainWindow.setWindowTitle("网络嗅探器")

