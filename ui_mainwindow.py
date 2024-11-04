from PyQt5 import QtWidgets, QtCore

class Ui_MainWindow:
    def setupUi(self, MainWindow):

        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1200, 1000)

        # 创建菜单栏
        self.menuBar = MainWindow.menuBar()
        self.fileMenu = self.menuBar.addMenu("文件")  
        # 添加保存动作
        self.saveAction = QtWidgets.QAction("保存", MainWindow)
        self.fileMenu.addAction(self.saveAction)
        # 添加退出动作
        self.exitAction = QtWidgets.QAction("退出", MainWindow)
        self.fileMenu.addAction(self.exitAction)
        # 创建分析菜单
        self.analysisMenu = self.menuBar.addMenu("分析")  # 新增分析菜单
        self.analyzeAction = QtWidgets.QAction("分析当前数据包", MainWindow)
        self.analysisMenu.addAction(self.analyzeAction)
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
        self.interfaceComboBox.setMinimumWidth(500)  
        self.interfaceComboBox.setMinimumHeight(30)  
        self.interfaceComboBox.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        self.interfaceAndFilterLayout.addWidget(self.interfaceComboBox)

        # 添加过滤器相关的控件
        self.filterLayout = QtWidgets.QHBoxLayout()  # 水平布局，用于放置filter和按钮

        self.filterLabel = QtWidgets.QLabel("捕获过滤:")
        self.filterLayout.addWidget(self.filterLabel)

        self.filterInput = QtWidgets.QLineEdit()
        self.filterInput.setMinimumWidth(500)  
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
        self.packetListWidget.setHorizontalHeaderLabels([ "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.layout.addWidget(self.packetListWidget)

        # Packet Details 窗格
        self.packetDetailsTreeWidget = QtWidgets.QTreeWidget()
        self.packetDetailsTreeWidget.setHeaderLabels(["Layer", "Details"])  # 设置表头
        self.layout.addWidget(self.packetDetailsTreeWidget)

        # Packet in hex 窗格
        self.packetHexTextEdit = QtWidgets.QTextEdit()
        self.packetHexTextEdit.setPlaceholderText("Packet in hex will be shown here...")
        self.layout.addWidget(self.packetHexTextEdit)

        MainWindow.setWindowTitle("网络嗅探器")

