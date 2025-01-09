from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, 
                           QTabWidget, QPushButton, QLabel,
                           QLineEdit, QGridLayout, QTextEdit,
                           QFileDialog, QHBoxLayout, QComboBox,
                           QGroupBox, QCheckBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QTextCharFormat, QColor, QTextCursor, QIcon
from sippts.sipexten import SipExten
from sippts.lib.color import Color
from sippts.gui.uitools import UiTools
from sippts.gui.log_manager import LogManager

import os
import sys
from io import StringIO
import re
from PyQt6.QtWidgets import QApplication


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sip攻击小工具GUI by zhn")
        self.setMinimumSize(800, 600)
        
        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # 创建主布局
        layout = QVBoxLayout()
        main_widget.setLayout(layout)
        
        # 创建选项卡
        tabs = QTabWidget()
        layout.addWidget(tabs)
        
        # 创建日志管理器
        self.log_manager = LogManager()
        
        # 添加各个功能模块的选项卡
        tabs.addTab(self.create_scan_tab(), "扫描")
        tabs.addTab(self.create_exten_tab(), "分机探测") 
        tabs.addTab(self.create_crack_tab(), "密码破解")
        tabs.addTab(self.create_flood_tab(), "压力测试")
        tabs.addTab(self.create_dump_tab(), "数据包分析")
        tabs.addTab(self.create_leak_tab(), "SIP Digest Leak")  # 添加新标签页
        tabs.addTab(self.create_dcrack_tab(), "离线破解")
        tabs.addTab(self.create_rtpbleed_tab(), "RTP Bleed")
        tabs.addTab(self.create_rtpbleedinject_tab(), "RTP Inject")  # 添加新标签页
        tabs.addTab(self.create_send_tab(), "SIP发送")
        
        # ANSI颜色代码映射到Qt颜色
        self.color_map = {
            '\033[0;31;20m': QColor("#FF0000"),  # 红色
            '\033[1;31;20m': QColor("#FF0000"),  # 亮红色
            '\033[0;32;20m': QColor("#00FF00"),  # 绿色
            '\033[1;32;20m': QColor("#00FF00"),  # 亮绿色
            '\033[0;33;20m': QColor("#FFFF00"),  # 黄色
            '\033[1;33;20m': QColor("#FFFF00"),  # 亮黄色
            '\033[0;34;20m': QColor("#0000FF"),  # 蓝色
            '\033[1;34;20m': QColor("#0000FF"),  # 亮蓝色
            '\033[0;35;20m': QColor("#FF00FF"),  # 品红
            '\033[1;35;20m': QColor("#FF00FF"),  # 亮品红
            '\033[0;36;20m': QColor("#00FFFF"),  # 青色
            '\033[1;36;20m': QColor("#00FFFF"),  # 亮青色
            '\033[0;37;20m': QColor("#FFFFFF"),  # 白色
            '\033[1;37;20m': QColor("#FFFFFF"),  # 亮白色
        }
        
    def setup_logging(self, text_widget):
        """设置日志输出到指定的文本框"""
        text_widget.clear()
        # 设置最大行数限制为1000行
        # text_widget.document().setMaximumBlockCount(500)
        
        # 先断开之前的连接
        if hasattr(self.log_manager, 'log_signal'):
            try:
                self.log_manager.log_signal.disconnect()
            except:
                pass
        # 建立新的连接
        self.log_manager.log_signal.connect(lambda text: self.append_log(text_widget, text))
        
    def append_log(self, text_widget, text):
        """添加日志到文本框""" 
        cursor = text_widget.textCursor()
        
        # 分割ANSI转义序列
        parts = re.split(r'(\x1B\[[0-9;]*m)', text)
        
        current_format = QTextCharFormat()
        current_format.setForeground(QColor("#FFFFFF"))  # 默认白色
        
        for part in parts:
            if part.startswith('\033['):
                # 这是一个颜色代码
                if part in self.color_map:
                    current_format = QTextCharFormat()
                    current_format.setForeground(self.color_map[part])
            else:
                # 这是实际文本
                cursor.insertText(part, current_format)
        
        # 滚动到底部
        text_widget.setTextCursor(cursor)
        text_widget.verticalScrollBar().setValue(
            text_widget.verticalScrollBar().maximum()
        )
        
    def create_scan_tab(self):
        """创建扫描模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        # 第一行
        layout.addWidget(QLabel("目标 IP/网段:"), row, 0)
        self.scan_ip_input = QLineEdit()
        self.scan_ip_input.setPlaceholderText("例如: mysipserver.com | 192.168.0.10 | 192.168.0.0/24")
        self.scan_ip_input.setMinimumWidth(300)
        layout.addWidget(self.scan_ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.scan_port_input = QLineEdit()
        self.scan_port_input.setText("5060")
        self.scan_port_input.setPlaceholderText("例如: 5060 | 5070,5080 | 5060-5080")
        self.scan_port_input.setMinimumWidth(300)
        layout.addWidget(self.scan_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("IP列表文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        file_layout = QHBoxLayout()
        
        self.scan_file_input = QLineEdit()
        self.scan_file_input.setPlaceholderText("包含多个IP或网段的文件路径")
        self.scan_file_input.setMinimumWidth(240)
        self.scan_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/iplist.txt")
        file_layout.addWidget(self.scan_file_input)
        
        # 添加选择文件按钮
        file_btn = QPushButton("选择")
        file_btn.setFixedWidth(60)
        file_btn.clicked.connect(self.choose_ip_file)
        file_layout.addWidget(file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(file_layout, row, 1)
        
        layout.addWidget(QLabel("协议:"), row, 2)
        self.scan_proto_input = QComboBox()
        self.scan_proto_input.addItems(["UDP", "TCP", "TLS", "ALL"])
        self.scan_proto_input.setCurrentText("UDP")
        self.scan_proto_input.setMinimumWidth(300)
        layout.addWidget(self.scan_proto_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.scan_proxy_input = QLineEdit()
        self.scan_proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.scan_proxy_input.setMinimumWidth(300)
        layout.addWidget(self.scan_proxy_input, row, 1)
        
        layout.addWidget(QLabel("扫描方法:"), row, 2)
        self.scan_method_input = QComboBox()
        self.scan_method_input.addItems(["OPTIONS", "REGISTER", "INVITE"])
        self.scan_method_input.setCurrentText("OPTIONS")
        self.scan_method_input.setMinimumWidth(300)
        layout.addWidget(self.scan_method_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("域名:"), row, 0)
        self.scan_domain_input = QLineEdit()
        self.scan_domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.scan_domain_input.setMinimumWidth(300)
        layout.addWidget(self.scan_domain_input, row, 1)
        
        layout.addWidget(QLabel("Contact域名:"), row, 2)
        self.scan_contact_domain_input = QLineEdit()
        self.scan_contact_domain_input.setPlaceholderText("Contact头域名或IP, 例如: 10.0.1.2")
        self.scan_contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.scan_contact_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From名称:"), row, 0)
        self.scan_from_name_input = QLineEdit()
        self.scan_from_name_input.setPlaceholderText("例如: Bob")
        self.scan_from_name_input.setMinimumWidth(300)
        layout.addWidget(self.scan_from_name_input, row, 1)
        
        layout.addWidget(QLabel("From用户:"), row, 2)
        self.scan_from_user_input = QLineEdit()
        self.scan_from_user_input.setText("3009")
        self.scan_from_user_input.setPlaceholderText("From头的用户名")
        self.scan_from_user_input.setMinimumWidth(300)
        layout.addWidget(self.scan_from_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From域名:"), row, 0)
        self.scan_from_domain_input = QLineEdit()
        self.scan_from_domain_input.setPlaceholderText("From头的域名")
        self.scan_from_domain_input.setMinimumWidth(300)
        layout.addWidget(self.scan_from_domain_input, row, 1)
        
        layout.addWidget(QLabel("To名称:"), row, 2)
        self.scan_to_name_input = QLineEdit()
        self.scan_to_name_input.setPlaceholderText("例如: Alice")
        self.scan_to_name_input.setMinimumWidth(300)
        layout.addWidget(self.scan_to_name_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To用户:"), row, 0)
        self.scan_to_user_input = QLineEdit()
        self.scan_to_user_input.setText("100")
        self.scan_to_user_input.setPlaceholderText("To头的用户名")
        self.scan_to_user_input.setMinimumWidth(300)
        layout.addWidget(self.scan_to_user_input, row, 1)
        
        layout.addWidget(QLabel("To域名:"), row, 2)
        self.scan_to_domain_input = QLineEdit()
        self.scan_to_domain_input.setPlaceholderText("To头的域名")
        self.scan_to_domain_input.setMinimumWidth(300)
        layout.addWidget(self.scan_to_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("User-Agent:"), row, 0)
        self.scan_ua_input = QLineEdit()
        self.scan_ua_input.setText("pplsip")
        self.scan_ua_input.setPlaceholderText("User-Agent头的值")
        self.scan_ua_input.setMinimumWidth(300)
        layout.addWidget(self.scan_ua_input, row, 1)
        
        layout.addWidget(QLabel("线程数:"), row, 2)
        self.scan_threads_input = QLineEdit()
        self.scan_threads_input.setText("100")
        self.scan_threads_input.setPlaceholderText("扫描使用的线程数")
        self.scan_threads_input.setMinimumWidth(300)
        layout.addWidget(self.scan_threads_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("超时(秒):"), row, 0)
        self.scan_timeout_input = QLineEdit()
        self.scan_timeout_input.setText("5")
        self.scan_timeout_input.setPlaceholderText("Socket超时时间(秒)")
        self.scan_timeout_input.setMinimumWidth(300)
        layout.addWidget(self.scan_timeout_input, row, 1)
        
        layout.addWidget(QLabel("详细程度:"), row, 2)
        self.scan_verbose_input = QComboBox()
        self.scan_verbose_input.addItems(["0", "1", "2"])
        self.scan_verbose_input.setCurrentText("0")
        self.scan_verbose_input.setMinimumWidth(300)
        layout.addWidget(self.scan_verbose_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        output_file_layout = QHBoxLayout()
        
        self.scan_output_file_input = QLineEdit()
        self.scan_output_file_input.setPlaceholderText("保存扫描结果的文件路径")
        self.scan_output_file_input.setMinimumWidth(240)
        output_file_layout.addWidget(self.scan_output_file_input)
        
        # 添加选择文件按钮
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)
        output_file_btn.clicked.connect(self.choose_output_file)
        output_file_layout.addWidget(output_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_file_layout, row, 1)
        
        layout.addWidget(QLabel("IP输出文件:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        output_ip_file_layout = QHBoxLayout()
        
        self.scan_output_ip_file_input = QLineEdit()
        self.scan_output_ip_file_input.setPlaceholderText("保存发现的IP的文件路径")
        self.scan_output_ip_file_input.setMinimumWidth(240)
        output_ip_file_layout.addWidget(self.scan_output_ip_file_input)
        
        # 添加选择文件按钮
        output_ip_file_btn = QPushButton("选择")
        output_ip_file_btn.setFixedWidth(60)
        output_ip_file_btn.clicked.connect(self.choose_output_ip_file)
        output_ip_file_layout.addWidget(output_ip_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_ip_file_layout, row, 3)
         
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.scan_start_btn = QPushButton("开始扫描")
        self.scan_start_btn.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_start_btn)
        
        # 停止按钮
        self.scan_stop_btn = QPushButton("停止扫描")
        self.scan_stop_btn.clicked.connect(self.stop_module)
        self.scan_stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.scan_stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.scan_result_text = QTextEdit()
        self.scan_result_text.setReadOnly(True)
        self.scan_result_text.setFontFamily("Courier New")
        self.scan_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.scan_result_text, row, 0, 1, 4)
        
        return widget
        
    def start_scan(self):
        """开始扫描"""
        # 清空之前的结果
        self.scan_result_text.clear()
        
        # 创建扫描器实例
        from sippts.sipscan import SipScan
        self.mod = SipScan()
        
        # 设置所有参数
        UiTools.set_option_scan(self.mod, "ip", self.scan_ip_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "rport", self.scan_port_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "file", self.scan_file_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "proto", self.scan_proto_input.currentText(), False, True)
        UiTools.set_option_scan(self.mod, "proxy", self.scan_proxy_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "method", self.scan_method_input.currentText(), False, True)
        UiTools.set_option_scan(self.mod, "domain", self.scan_domain_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "contact_domain", self.scan_contact_domain_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "from_name", self.scan_from_name_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "from_user", self.scan_from_user_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "from_domain", self.scan_from_domain_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "to_name", self.scan_to_name_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "to_user", self.scan_to_user_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "to_domain", self.scan_to_domain_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "ua", self.scan_ua_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "threads", self.scan_threads_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "timeout", self.scan_timeout_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "verbose", self.scan_verbose_input.currentText(), False, True)
        UiTools.set_option_scan(self.mod, "output_file", self.scan_output_file_input.text(), False, True)
        UiTools.set_option_scan(self.mod, "output_ip_file", self.scan_output_ip_file_input.text(), False, True)
        
        # 切换按钮状态
        self.scan_start_btn.setEnabled(False)
        self.scan_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.scan_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_scan_finished)
        
        # 启动线程
        self.worker.start()
        
    def create_exten_tab(self):
        """创建分机探测模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setText("192.168.4.200")
        self.ip_input.setPlaceholderText("目标主机IP地址")
        self.ip_input.setMinimumWidth(300)
        layout.addWidget(self.ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.port_input = QLineEdit()
        self.port_input.setText("5060")
        self.port_input.setPlaceholderText("目标端口，例如: 5060")
        self.port_input.setMinimumWidth(300)
        layout.addWidget(self.port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("分机范围:"), row, 0)
        self.exten_input = QLineEdit()
        self.exten_input.setText("3000-3100")
        self.exten_input.setPlaceholderText("例如: 100 | 100,102,105 | 100-200")
        self.exten_input.setMinimumWidth(300)
        layout.addWidget(self.exten_input, row, 1)
        
        layout.addWidget(QLabel("协议:"), row, 2)
        self.proto_input = QComboBox()
        self.proto_input.addItems(["UDP", "TCP", "TLS"])
        self.proto_input.setCurrentText("UDP")
        self.proto_input.setMinimumWidth(300)
        layout.addWidget(self.proto_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.proxy_input.setMinimumWidth(300)
        layout.addWidget(self.proxy_input, row, 1)
        
        layout.addWidget(QLabel("分机前缀:"), row, 2)
        self.prefix_input = QLineEdit()
        self.prefix_input.setPlaceholderText("用于认证的分机前缀")
        self.prefix_input.setMinimumWidth(300)
        layout.addWidget(self.prefix_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("扫描方法:"), row, 0)
        self.method_input = QComboBox()
        self.method_input.addItems(["OPTIONS", "REGISTER", "INVITE"])
        self.method_input.setCurrentText("REGISTER")
        self.method_input.setMinimumWidth(300)
        layout.addWidget(self.method_input, row, 1)
        
        layout.addWidget(QLabel("域名:"), row, 2)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.domain_input.setMinimumWidth(300)
        layout.addWidget(self.domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("Contact域名:"), row, 0)
        self.contact_domain_input = QLineEdit()
        self.contact_domain_input.setPlaceholderText("Contact头域名或IP, 例如: 10.0.1.2")
        self.contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.contact_domain_input, row, 1)
        
        layout.addWidget(QLabel("From用户:"), row, 2)
        self.from_user_input = QLineEdit()
        self.from_user_input.setText("100")
        self.from_user_input.setPlaceholderText("From头的用户名")
        self.from_user_input.setMinimumWidth(300)
        layout.addWidget(self.from_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("User-Agent:"), row, 0)
        self.ua_input = QLineEdit()
        self.ua_input.setText("pplsip")
        self.ua_input.setPlaceholderText("User-Agent头的值")
        self.ua_input.setMinimumWidth(300)
        layout.addWidget(self.ua_input, row, 1)
        
        layout.addWidget(QLabel("线程数:"), row, 2)
        self.threads_input = QLineEdit()
        self.threads_input.setText("500")
        self.threads_input.setPlaceholderText("扫描使用的线程数")
        self.threads_input.setMinimumWidth(300)
        layout.addWidget(self.threads_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("超时(秒):"), row, 0)
        self.timeout_input = QLineEdit()
        self.timeout_input.setText("5")
        self.timeout_input.setPlaceholderText("Socket超时时间(秒)")
        self.timeout_input.setMinimumWidth(300)
        layout.addWidget(self.timeout_input, row, 1)
        
        layout.addWidget(QLabel("详细程度:"), row, 2)
        self.verbose_input = QComboBox()
        self.verbose_input.addItems(["0", "1", "2"])
        self.verbose_input.setCurrentText("0")
        self.verbose_input.setMinimumWidth(300)
        layout.addWidget(self.verbose_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("过滤响应码:"), row, 0)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("过滤指定响应码，例如: 200")
        self.filter_input.setMinimumWidth(300)
        layout.addWidget(self.filter_input, row, 1)
        
        layout.addWidget(QLabel("输出文件:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        output_file_layout = QHBoxLayout()
        
        self.output_file_input = QLineEdit()
        self.output_file_input.setPlaceholderText("保存扫描结果的文件路径")
        self.output_file_input.setMinimumWidth(240)
        output_file_layout.addWidget(self.output_file_input)
        
        # 添加选择文件按钮
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)
        output_file_btn.clicked.connect(self.choose_exten_output_file)
        output_file_layout.addWidget(output_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_file_layout, row, 3)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.exten_start_btn = QPushButton("开始扫描")
        self.exten_start_btn.clicked.connect(self.start_exten)
        button_layout.addWidget(self.exten_start_btn)
        
        # 停止按钮
        self.exten_stop_btn = QPushButton("停止扫描")
        self.exten_stop_btn.clicked.connect(self.stop_module)
        self.exten_stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.exten_stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setFontFamily("Courier New")
        self.result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.result_text, row, 0, 1, 4)
        
        return widget
        
    def start_exten(self):
        """开始分机探测"""
        # 清空之前的结果
        self.result_text.clear()
        
        # 创建探测器实例
        from sippts.sipexten import SipExten
        self.mod = SipExten()
        
        # 设置所有参数
        UiTools.set_option_exten(self.mod, "ip", self.ip_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "rport", self.port_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "exten", self.exten_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "proto", self.proto_input.currentText(), False, True)
        UiTools.set_option_exten(self.mod, "proxy", self.proxy_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "prefix", self.prefix_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "method", self.method_input.currentText(), False, True)
        UiTools.set_option_exten(self.mod, "domain", self.domain_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "contact_domain", self.contact_domain_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "from_user", self.from_user_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "ua", self.ua_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "threads", self.threads_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "timeout", self.timeout_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "verbose", self.verbose_input.currentText(), False, True)
        UiTools.set_option_exten(self.mod, "filter", self.filter_input.text(), False, True)
        UiTools.set_option_exten(self.mod, "output_file", self.output_file_input.text(), False, True)
        
        # 切换按钮状态
        self.exten_start_btn.setEnabled(False)
        self.exten_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_exten_finished)
        
        # 启动线程
        self.worker.start()
        
    def create_crack_tab(self):
        """创建密码破解模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP/网段:"), row, 0)
        self.crack_ip_input = QLineEdit()
        self.crack_ip_input.setText("192.168.4.200")
        self.crack_ip_input.setPlaceholderText("目标IP地址或网段，例如: 192.168.0.0/24")
        self.crack_ip_input.setMinimumWidth(300)
        layout.addWidget(self.crack_ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.crack_port_input = QLineEdit()
        self.crack_port_input.setText("5060")
        self.crack_port_input.setPlaceholderText("目标端口，例如: 5060")
        self.crack_port_input.setMinimumWidth(300)
        layout.addWidget(self.crack_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("分机范围:"), row, 0)
        self.crack_exten_input = QLineEdit()
        self.crack_exten_input.setText("3001-3020")
        self.crack_exten_input.setPlaceholderText("例如: 100 | 100,102,105 | 100-200")
        self.crack_exten_input.setMinimumWidth(300)
        layout.addWidget(self.crack_exten_input, row, 1)
        
        layout.addWidget(QLabel("协议:"), row, 2)
        self.crack_proto_input = QComboBox()
        self.crack_proto_input.addItems(["UDP", "TCP", "TLS"])
        self.crack_proto_input.setCurrentText("UDP")
        self.crack_proto_input.setMinimumWidth(300)
        layout.addWidget(self.crack_proto_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.crack_proxy_input = QLineEdit()
        self.crack_proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.crack_proxy_input.setMinimumWidth(300)
        layout.addWidget(self.crack_proxy_input, row, 1)
        
        layout.addWidget(QLabel("分机前缀:"), row, 2)
        self.crack_prefix_input = QLineEdit()
        self.crack_prefix_input.setPlaceholderText("用于认证的分机前缀")
        self.crack_prefix_input.setMinimumWidth(300)
        layout.addWidget(self.crack_prefix_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("认证用户:"), row, 0)
        self.crack_authuser_input = QLineEdit()
        self.crack_authuser_input.setPlaceholderText("认证用户名(默认使用分机号)")
        self.crack_authuser_input.setMinimumWidth(300)
        layout.addWidget(self.crack_authuser_input, row, 1)
        
        layout.addWidget(QLabel("分机长度:"), row, 2)
        self.crack_ext_len_input = QLineEdit()
        self.crack_ext_len_input.setPlaceholderText("分机号长度，用0补齐")
        self.crack_ext_len_input.setMinimumWidth(300)
        layout.addWidget(self.crack_ext_len_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("域名:"), row, 0)
        self.crack_domain_input = QLineEdit()
        self.crack_domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.crack_domain_input.setMinimumWidth(300)
        layout.addWidget(self.crack_domain_input, row, 1)
        
        layout.addWidget(QLabel("Contact域名:"), row, 2)
        self.crack_contact_domain_input = QLineEdit()
        self.crack_contact_domain_input.setText("192.168.4.66")
        self.crack_contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.crack_contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.crack_contact_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("密码字典:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        wordlist_layout = QHBoxLayout()
        
        self.crack_wordlist_input = QLineEdit()
        self.crack_wordlist_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/passwordlist.txt")
        self.crack_wordlist_input.setPlaceholderText("密码字典文件路径")
        self.crack_wordlist_input.setMinimumWidth(240)
        wordlist_layout.addWidget(self.crack_wordlist_input)
        
        # 添加选择文件按钮
        wordlist_btn = QPushButton("选择")
        wordlist_btn.setFixedWidth(60)
        wordlist_btn.clicked.connect(self.choose_wordlist_file)
        wordlist_layout.addWidget(wordlist_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(wordlist_layout, row, 1)
        
        layout.addWidget(QLabel("User-Agent:"), row, 2)
        self.crack_ua_input = QLineEdit()
        self.crack_ua_input.setText("pplsip")
        self.crack_ua_input.setPlaceholderText("User-Agent头的值")
        self.crack_ua_input.setMinimumWidth(300)
        layout.addWidget(self.crack_ua_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("线程数:"), row, 0)
        self.crack_threads_input = QLineEdit()
        self.crack_threads_input.setText("100")
        self.crack_threads_input.setPlaceholderText("破解使用的线程数")
        self.crack_threads_input.setMinimumWidth(300)
        layout.addWidget(self.crack_threads_input, row, 1)
        
        layout.addWidget(QLabel("超时(秒):"), row, 2)
        self.crack_timeout_input = QLineEdit()
        self.crack_timeout_input.setText("5")
        self.crack_timeout_input.setPlaceholderText("Socket超时时间(秒)")
        self.crack_timeout_input.setMinimumWidth(300)
        layout.addWidget(self.crack_timeout_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("详细程度:"), row, 0)
        self.crack_verbose_input = QComboBox()
        self.crack_verbose_input.addItems(["0", "1", "2"])
        self.crack_verbose_input.setCurrentText("0")
        self.crack_verbose_input.setMinimumWidth(300)
        layout.addWidget(self.crack_verbose_input, row, 1)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.crack_start_btn = QPushButton("开始破解")
        self.crack_start_btn.clicked.connect(self.start_crack)
        button_layout.addWidget(self.crack_start_btn)
        
        # 停止按钮
        self.crack_stop_btn = QPushButton("停止破解")
        self.crack_stop_btn.clicked.connect(self.stop_module)
        self.crack_stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.crack_stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.crack_result_text = QTextEdit()
        self.crack_result_text.setReadOnly(True)
        self.crack_result_text.setFontFamily("Courier New")
        self.crack_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.crack_result_text, row, 0, 1, 4)
        
        return widget

    def choose_wordlist_file(self):
        """打开密码字典文件选择对话框"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择密码字典文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            self.crack_wordlist_input.setText(file_name)

    def start_crack(self):
        """开始密码破解"""
        # 清空之前的结果
        self.crack_result_text.clear()
        
        # 创建破解器实例
        from sippts.siprcrack import SipRemoteCrack
        self.mod = SipRemoteCrack()
        
        # 设置所有参数
        UiTools.set_option_rcrack(self.mod, "ip", self.crack_ip_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "rport", self.crack_port_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "exten", self.crack_exten_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "proto", self.crack_proto_input.currentText(), False, True)
        UiTools.set_option_rcrack(self.mod, "proxy", self.crack_proxy_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "prefix", self.crack_prefix_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "authuser", self.crack_authuser_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "ext_len", self.crack_ext_len_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "domain", self.crack_domain_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "contact_domain", self.crack_contact_domain_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "wordlist", self.crack_wordlist_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "user_agent", self.crack_ua_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "threads", self.crack_threads_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "timeout", self.crack_timeout_input.text(), False, True)
        UiTools.set_option_rcrack(self.mod, "verbose", self.crack_verbose_input.currentText(), False, True)
        
        # 切换按钮状态
        self.crack_start_btn.setEnabled(False)
        self.crack_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.crack_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_crack_finished)
        
        # 启动线程
        self.worker.start()
        
    def create_dcrack_tab(self):
        """创建离线密码破解模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("输入文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        input_file_layout = QHBoxLayout()
        
        self.dcrack_file_input = QLineEdit()
        self.dcrack_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/sipdump.txt")
        self.dcrack_file_input.setPlaceholderText("包含SIP认证信息的文件路径")
        self.dcrack_file_input.setMinimumWidth(240)
        input_file_layout.addWidget(self.dcrack_file_input)
        
        # 添加选择文件按钮
        input_file_btn = QPushButton("选择")
        input_file_btn.setFixedWidth(60)
        input_file_btn.clicked.connect(self.choose_dcrack_input_file)
        input_file_layout.addWidget(input_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(input_file_layout, row, 1)
        
        layout.addWidget(QLabel("密码字典:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        wordlist_layout = QHBoxLayout()
        
        self.dcrack_wordlist_input = QLineEdit()
        self.dcrack_wordlist_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/passwordlist.txt")
        self.dcrack_wordlist_input.setPlaceholderText("密码字典文件路径")
        self.dcrack_wordlist_input.setMinimumWidth(240)
        wordlist_layout.addWidget(self.dcrack_wordlist_input)
        
        # 添加选择文件按钮
        wordlist_btn = QPushButton("选择")
        wordlist_btn.setFixedWidth(60)
        wordlist_btn.clicked.connect(self.choose_dcrack_wordlist_file)
        wordlist_layout.addWidget(wordlist_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(wordlist_layout, row, 3)
        
        row += 1
        layout.addWidget(QLabel("用户名:"), row, 0)
        self.dcrack_username_input = QLineEdit()
        self.dcrack_username_input.setPlaceholderText("指定要破解的用户名(可选)")
        self.dcrack_username_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_username_input, row, 1)
        
        layout.addWidget(QLabel("暴力破解:"), row, 2)
        self.dcrack_bruteforce_input = QComboBox()
        self.dcrack_bruteforce_input.addItems(["0", "1"])
        self.dcrack_bruteforce_input.setCurrentText("0")
        self.dcrack_bruteforce_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_bruteforce_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("字符集:"), row, 0)
        self.dcrack_charset_input = QComboBox()
        self.dcrack_charset_input.addItems(["digits", "hexdigits", "octdigits", "punctuation", "printable", "whitespace", "ascii_letters", "ascii_lowercase", "ascii_uppercase"])
        self.dcrack_charset_input.setCurrentText("digits")
        self.dcrack_charset_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_charset_input, row, 1)
        
        layout.addWidget(QLabel("最小长度:"), row, 2)
        self.dcrack_min_input = QLineEdit()
        self.dcrack_min_input.setText("6")
        self.dcrack_min_input.setPlaceholderText("暴力破解的最小密码长度")
        self.dcrack_min_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_min_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("最大长度:"), row, 0)
        self.dcrack_max_input = QLineEdit()
        self.dcrack_max_input.setText("6")
        self.dcrack_max_input.setPlaceholderText("暴力破解的最大密码长度")
        self.dcrack_max_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_max_input, row, 1)
        
        layout.addWidget(QLabel("线程数:"), row, 2)
        self.dcrack_threads_input = QLineEdit()
        self.dcrack_threads_input.setText("10")
        self.dcrack_threads_input.setPlaceholderText("破解使用的线程数")
        self.dcrack_threads_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_threads_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("密码前缀:"), row, 0)
        self.dcrack_prefix_input = QLineEdit()
        self.dcrack_prefix_input.setPlaceholderText("密码前缀(可选)")
        self.dcrack_prefix_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_prefix_input, row, 1)
        
        layout.addWidget(QLabel("密码后缀:"), row, 2)
        self.dcrack_suffix_input = QLineEdit()
        self.dcrack_suffix_input.setPlaceholderText("密码后缀(可选)")
        self.dcrack_suffix_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_suffix_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("详细程度:"), row, 0)
        self.dcrack_verbose_input = QComboBox()
        self.dcrack_verbose_input.addItems(["0", "1"])
        self.dcrack_verbose_input.setCurrentText("0")
        self.dcrack_verbose_input.setMinimumWidth(300)
        layout.addWidget(self.dcrack_verbose_input, row, 1)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.dcrack_start_btn = QPushButton("开始破解")
        self.dcrack_start_btn.clicked.connect(self.start_dcrack)
        button_layout.addWidget(self.dcrack_start_btn)
        
        # 停止按钮
        self.dcrack_stop_btn = QPushButton("停止破解")
        self.dcrack_stop_btn.clicked.connect(self.stop_module)
        self.dcrack_stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.dcrack_stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.dcrack_result_text = QTextEdit()
        self.dcrack_result_text.setReadOnly(True)
        self.dcrack_result_text.setFontFamily("Courier New")
        self.dcrack_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.dcrack_result_text, row, 0, 1, 4)
        
        return widget

    def choose_dcrack_input_file(self):
        """打开输入文件选择对话框"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择SIP认证信息文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            self.dcrack_file_input.setText(file_name)

    def choose_dcrack_wordlist_file(self):
        """打开密码字典文件选择对话框"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择密码字典文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            self.dcrack_wordlist_input.setText(file_name)

    def start_dcrack(self):
        """开始离线密码破解"""
        # 清空之前的结果
        self.dcrack_result_text.clear()
        
        # 创建破解器实例
        from sippts.sipdigestcrack import SipDigestCrack
        self.mod = SipDigestCrack()
        
        # 设置所有参数
        UiTools.set_option_dcrack(self.mod, "file", self.dcrack_file_input.text(), False, True)
        UiTools.set_option_dcrack(self.mod, "wordlist", self.dcrack_wordlist_input.text(), False, True)
        UiTools.set_option_dcrack(self.mod, "username", self.dcrack_username_input.text(), False, True)
        UiTools.set_option_dcrack(self.mod, "bruteforce", self.dcrack_bruteforce_input.currentText(), False, True)
        UiTools.set_option_dcrack(self.mod, "charset", self.dcrack_charset_input.currentText(), False, True)
        UiTools.set_option_dcrack(self.mod, "min", self.dcrack_min_input.text(), False, True)
        UiTools.set_option_dcrack(self.mod, "max", self.dcrack_max_input.text(), False, True)
        UiTools.set_option_dcrack(self.mod, "threads", self.dcrack_threads_input.text(), False, True)
        UiTools.set_option_dcrack(self.mod, "prefix", self.dcrack_prefix_input.text(), False, True)
        UiTools.set_option_dcrack(self.mod, "suffix", self.dcrack_suffix_input.text(), False, True)
        UiTools.set_option_dcrack(self.mod, "verbose", self.dcrack_verbose_input.currentText(), False, True)
        
        # 切换按钮状态
        self.dcrack_start_btn.setEnabled(False)
        self.dcrack_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.dcrack_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_dcrack_finished)
        
        # 启动线程
        self.worker.start()

    def choose_ip_file(self):
        """打开文件选择对话框"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择IP列表文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            self.scan_file_input.setText(file_name)
    
    def choose_output_file(self):
        """打开输出文件保存对话框"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择扫描结果保存位置",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.txt
            if not file_name.endswith('.txt'):
                file_name += '.txt'
            self.scan_output_file_input.setText(file_name)

    def choose_output_ip_file(self):
        """打开IP输出文件保存对话框"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择IP列表保存位置",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.txt
            if not file_name.endswith('.txt'):
                file_name += '.txt'
            self.scan_output_ip_file_input.setText(file_name)

    def choose_exten_output_file(self):
        """打开输出文件保存对话框"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择扫描结果保存位置",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.txt
            if not file_name.endswith('.txt'):
                file_name += '.txt'
            self.output_file_input.setText(file_name)

    def create_dump_tab(self):
        """创建数据包分析模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("输入文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        input_file_layout = QHBoxLayout()
        
        self.dump_file_input = QLineEdit()
        self.dump_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/test.pcap")
        self.dump_file_input.setPlaceholderText("要分析的PCAP文件路径")
        self.dump_file_input.setMinimumWidth(300)  # 设置最小宽度
        input_file_layout.addWidget(self.dump_file_input)
        
        # 添加选择文件按钮
        input_file_btn = QPushButton("选择")
        input_file_btn.setFixedWidth(60)  # 固定按钮宽度
        input_file_btn.clicked.connect(self.choose_dump_input_file)
        input_file_layout.addWidget(input_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(input_file_layout, row, 1)
        
        layout.addWidget(QLabel("输出文件:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        output_file_layout = QHBoxLayout()
        
        self.dump_output_file_input = QLineEdit()
        self.dump_output_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/sipdump.txt")
        self.dump_output_file_input.setPlaceholderText("分析结果保存路径")
        self.dump_output_file_input.setMinimumWidth(300)  # 设置最小宽度
        output_file_layout.addWidget(self.dump_output_file_input)
        
        # 添加选择文件按钮
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)  # 固定按钮宽度
        output_file_btn.clicked.connect(self.choose_dump_output_file)
        output_file_layout.addWidget(output_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_file_layout, row, 3)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.dump_start_btn = QPushButton("开始分析")
        self.dump_start_btn.clicked.connect(self.start_dump)
        button_layout.addWidget(self.dump_start_btn)
        
        # 停止按钮
        self.dump_stop_btn = QPushButton("停止分析")
        self.dump_stop_btn.clicked.connect(self.stop_module)
        self.dump_stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.dump_stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.dump_result_text = QTextEdit()
        self.dump_result_text.setReadOnly(True)
        self.dump_result_text.setFontFamily("Courier New")
        self.dump_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.dump_result_text, row, 0, 1, 4)
        
        return widget

    def choose_dump_input_file(self):
        """打开PCAP文件选择对话框"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择PCAP文件",
            "",
            "PCAP文件 (*.pcap *.pcapng);;所有文件 (*.*)"
        )
        if file_name:
            self.dump_file_input.setText(file_name)

    def choose_dump_output_file(self):
        """打开输出文件保存对话框"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择分析结果保存位置",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.txt
            if not file_name.endswith('.txt'):
                file_name += '.txt'
            self.dump_output_file_input.setText(file_name)

    def start_dump(self):
        """开始数据包分析"""
        # 清空之前的结果
        self.dump_result_text.clear()
        
        # 创建分析器实例
        from sippts.sipdump import SipDump
        self.mod = SipDump()
        
        # 设置所有参数
        UiTools.set_option_dump(self.mod, "file", self.dump_file_input.text(), False, True)
        UiTools.set_option_dump(self.mod, "output_file", self.dump_output_file_input.text(), False, True)
        
        # 切换按钮状态
        self.dump_start_btn.setEnabled(False)
        self.dump_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.dump_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_dump_finished)
        
        # 启动线程
        self.worker.start()
        
        
    def create_flood_tab(self):
        """创建压力测试模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.flood_ip_input = QLineEdit()
        self.flood_ip_input.setText("192.168.4.200")
        self.flood_ip_input.setPlaceholderText("目标主机IP地址")
        self.flood_ip_input.setMinimumWidth(300)
        layout.addWidget(self.flood_ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.flood_port_input = QLineEdit()
        self.flood_port_input.setText("5060")
        self.flood_port_input.setPlaceholderText("目标端口，例如: 5060")
        self.flood_port_input.setMinimumWidth(300)
        layout.addWidget(self.flood_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("协议:"), row, 0)
        self.flood_proto_input = QComboBox()
        self.flood_proto_input.addItems(["UDP", "TCP", "TLS"])
        self.flood_proto_input.setCurrentText("UDP")
        self.flood_proto_input.setMinimumWidth(300)
        layout.addWidget(self.flood_proto_input, row, 1)
        
        layout.addWidget(QLabel("请求方法:"), row, 2)
        self.flood_method_input = QComboBox()
        self.flood_method_input.addItems(["REGISTER", "INVITE", "OPTIONS"])
        self.flood_method_input.setCurrentText("REGISTER")
        self.flood_method_input.setMinimumWidth(300)
        layout.addWidget(self.flood_method_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.flood_proxy_input = QLineEdit()
        self.flood_proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.flood_proxy_input.setMinimumWidth(300)
        layout.addWidget(self.flood_proxy_input, row, 1)
        
        layout.addWidget(QLabel("域名:"), row, 2)
        self.flood_domain_input = QLineEdit()
        self.flood_domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.flood_domain_input.setMinimumWidth(300)
        layout.addWidget(self.flood_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("Contact域名:"), row, 0)
        self.flood_contact_domain_input = QLineEdit()
        self.flood_contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.flood_contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.flood_contact_domain_input, row, 1)
        
        layout.addWidget(QLabel("From用户:"), row, 2)
        self.flood_from_user_input = QLineEdit()
        self.flood_from_user_input.setText("100")
        self.flood_from_user_input.setPlaceholderText("From头的用户名")
        self.flood_from_user_input.setMinimumWidth(300)
        layout.addWidget(self.flood_from_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From名称:"), row, 0)
        self.flood_from_name_input = QLineEdit()
        self.flood_from_name_input.setPlaceholderText("From头的显示名称")
        self.flood_from_name_input.setMinimumWidth(300)
        layout.addWidget(self.flood_from_name_input, row, 1)
        
        layout.addWidget(QLabel("From域名:"), row, 2)
        self.flood_from_domain_input = QLineEdit()
        self.flood_from_domain_input.setPlaceholderText("From头的域名")
        self.flood_from_domain_input.setMinimumWidth(300)
        layout.addWidget(self.flood_from_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To用户:"), row, 0)
        self.flood_to_user_input = QLineEdit()
        self.flood_to_user_input.setText("100")
        self.flood_to_user_input.setPlaceholderText("To头的用户名")
        self.flood_to_user_input.setMinimumWidth(300)
        layout.addWidget(self.flood_to_user_input, row, 1)
        
        layout.addWidget(QLabel("To名称:"), row, 2)
        self.flood_to_name_input = QLineEdit()
        self.flood_to_name_input.setPlaceholderText("To头的显示名称")
        self.flood_to_name_input.setMinimumWidth(300)
        layout.addWidget(self.flood_to_name_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To域名:"), row, 0)
        self.flood_to_domain_input = QLineEdit()
        self.flood_to_domain_input.setPlaceholderText("To头的域名")
        self.flood_to_domain_input.setMinimumWidth(300)
        layout.addWidget(self.flood_to_domain_input, row, 1)
        
        layout.addWidget(QLabel("User-Agent:"), row, 2)
        self.flood_ua_input = QLineEdit()
        self.flood_ua_input.setText("pplsip")
        self.flood_ua_input.setPlaceholderText("User-Agent头的值")
        self.flood_ua_input.setMinimumWidth(300)
        layout.addWidget(self.flood_ua_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("认证信息:"), row, 0)
        self.flood_digest_input = QLineEdit()
        self.flood_digest_input.setPlaceholderText("认证信息(可选)")
        self.flood_digest_input.setMinimumWidth(300)
        layout.addWidget(self.flood_digest_input, row, 1)
        
        layout.addWidget(QLabel("恶意数据:"), row, 2)
        self.flood_bad_input = QComboBox()
        self.flood_bad_input.addItems(["0", "1"])
        self.flood_bad_input.setCurrentText("0")
        self.flood_bad_input.setMinimumWidth(300)
        layout.addWidget(self.flood_bad_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("字符集:"), row, 0)
        self.flood_charset_input = QComboBox()
        self.flood_charset_input.addItems(["printable", "digits", "ascii_letters", "ascii_lowercase", "ascii_uppercase", "hexdigits", "octdigits", "punctuation", "whitespace"])
        self.flood_charset_input.setCurrentText("printable")
        self.flood_charset_input.setMinimumWidth(300)
        layout.addWidget(self.flood_charset_input, row, 1)
        
        layout.addWidget(QLabel("最小长度:"), row, 2)
        self.flood_min_input = QLineEdit()
        self.flood_min_input.setText("0")
        self.flood_min_input.setPlaceholderText("恶意数据的最小长度")
        self.flood_min_input.setMinimumWidth(300)
        layout.addWidget(self.flood_min_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("最大长度:"), row, 0)
        self.flood_max_input = QLineEdit()
        self.flood_max_input.setText("1000")
        self.flood_max_input.setPlaceholderText("恶意数据的最大长度")
        self.flood_max_input.setMinimumWidth(300)
        layout.addWidget(self.flood_max_input, row, 1)
        
        layout.addWidget(QLabel("请求数量:"), row, 2)
        self.flood_requests_input = QLineEdit()
        self.flood_requests_input.setText("0")
        self.flood_requests_input.setPlaceholderText("0表示无限制")
        self.flood_requests_input.setMinimumWidth(300)
        layout.addWidget(self.flood_requests_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("线程数:"), row, 0)
        self.flood_threads_input = QLineEdit()
        self.flood_threads_input.setText("100")
        self.flood_threads_input.setPlaceholderText("压测使用的线程数")
        self.flood_threads_input.setMinimumWidth(300)
        layout.addWidget(self.flood_threads_input, row, 1)
        
        layout.addWidget(QLabel("详细程度:"), row, 2)
        self.flood_verbose_input = QComboBox()
        self.flood_verbose_input.addItems(["0", "1"])
        self.flood_verbose_input.setCurrentText("0")
        self.flood_verbose_input.setMinimumWidth(300)
        layout.addWidget(self.flood_verbose_input, row, 3)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.flood_start_btn = QPushButton("开始压测")
        self.flood_start_btn.clicked.connect(self.start_flood)
        button_layout.addWidget(self.flood_start_btn)
        
        # 停止按钮
        self.flood_stop_btn = QPushButton("停止压测")
        self.flood_stop_btn.clicked.connect(self.stop_module)
        self.flood_stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.flood_stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.flood_result_text = QTextEdit()
        self.flood_result_text.setReadOnly(True)
        self.flood_result_text.setFontFamily("Courier New")
        self.flood_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.flood_result_text, row, 0, 1, 4)
        
        return widget

    def start_flood(self):
        """开始压力测试"""
        # 清空之前的结果
        self.flood_result_text.clear()
        
        # 创建压测器实例
        from sippts.sipflood import SipFlood
        self.mod = SipFlood()
        
        # 设置所有参数
        UiTools.set_option_flood(self.mod, "ip", self.flood_ip_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "rport", self.flood_port_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "proto", self.flood_proto_input.currentText(), False, True)
        UiTools.set_option_flood(self.mod, "method", self.flood_method_input.currentText(), False, True)
        UiTools.set_option_flood(self.mod, "proxy", self.flood_proxy_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "domain", self.flood_domain_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "contact_domain", self.flood_contact_domain_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "from_user", self.flood_from_user_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "from_name", self.flood_from_name_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "from_domain", self.flood_from_domain_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "to_user", self.flood_to_user_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "to_name", self.flood_to_name_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "to_domain", self.flood_to_domain_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "ua", self.flood_ua_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "digest", self.flood_digest_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "bad", self.flood_bad_input.currentText(), False, True)
        UiTools.set_option_flood(self.mod, "charset", self.flood_charset_input.currentText(), False, True)
        UiTools.set_option_flood(self.mod, "min", self.flood_min_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "max", self.flood_max_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "requests", self.flood_requests_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "threads", self.flood_threads_input.text(), False, True)
        UiTools.set_option_flood(self.mod, "verbose", self.flood_verbose_input.currentText(), False, True)
        
        # 切换按钮状态
        self.flood_start_btn.setEnabled(False)
        self.flood_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.flood_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.flood_worker = ModuleWorker(self.mod)
        self.flood_worker.finished.connect(self.on_flood_finished)
              
        # 启动线程
        self.flood_worker.start()
        
    def stop_module(self):
        """停止压力测试"""
        if hasattr(self, 'mod'):
            self.mod.stop()
            # 按钮状态会在线程结束时通过 on_flood_finished 恢复

    def on_scan_finished(self):
        """扫描完成处理"""
        # 恢复按钮状态
        self.scan_start_btn.setEnabled(True)
        self.scan_stop_btn.setEnabled(False)

    def on_exten_finished(self):
        """分机探测完成处理"""
        # 恢复按钮状态
        self.exten_start_btn.setEnabled(True)
        self.exten_stop_btn.setEnabled(False)

    def on_crack_finished(self):
        """密码破解完成处理"""
        # 恢复按钮状态
        self.crack_start_btn.setEnabled(True)
        self.crack_stop_btn.setEnabled(False)

    def on_dcrack_finished(self):
        """离线密码破解完成处理"""
        # 恢复按钮状态
        self.dcrack_start_btn.setEnabled(True)
        self.dcrack_stop_btn.setEnabled(False)

    def on_flood_finished(self):
        """压力测试完成处理"""
        # 恢复按钮状态
        self.flood_start_btn.setEnabled(True)
        self.flood_stop_btn.setEnabled(False)

    def on_dump_finished(self):
        """数据包分析完成处理"""
        # 恢复按钮状态
        self.dump_start_btn.setEnabled(True)
        self.dump_stop_btn.setEnabled(False)

    def create_rtpbleed_tab(self):
        """创建RTP Bleed测试模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.rtpbleed_ip_input = QLineEdit()
        self.rtpbleed_ip_input.setText("192.168.4.200")
        self.rtpbleed_ip_input.setPlaceholderText("目标主机IP地址")
        self.rtpbleed_ip_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleed_ip_input, row, 1)
        
        layout.addWidget(QLabel("起始端口:"), row, 2)
        self.rtpbleed_start_port_input = QLineEdit()
        self.rtpbleed_start_port_input.setText("10042")
        self.rtpbleed_start_port_input.setPlaceholderText("RTP端口范围起始值")
        self.rtpbleed_start_port_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleed_start_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("结束端口:"), row, 0)
        self.rtpbleed_end_port_input = QLineEdit()
        self.rtpbleed_end_port_input.setText("10043")
        self.rtpbleed_end_port_input.setPlaceholderText("RTP端口范围结束值")
        self.rtpbleed_end_port_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleed_end_port_input, row, 1)
        
        layout.addWidget(QLabel("尝试次数:"), row, 2)
        self.rtpbleed_loops_input = QLineEdit()
        self.rtpbleed_loops_input.setText("200")
        self.rtpbleed_loops_input.setPlaceholderText("每个端口的尝试次数")
        self.rtpbleed_loops_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleed_loops_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("负载类型:"), row, 0)
        self.rtpbleed_payload_input = QComboBox()
        self.rtpbleed_payload_input.addItems([
            "0 PCMU (audio)", "3 GSM (audio)", "4 G723 (audio)", "5 DVI4 (audio)",
            "6 DVI4 (audio)", "7 LPC (audio)", "8 PCMA (audio)", "9 G722 (audio)",
            "10 L16 (audio)", "11 L16 (audio)", "12 QCELP (audio)", "13 CN (audio)",
            "14 MPA (audio)", "15 G728 (audio)", "16 DVI4 (audio)", "17 DVI4 (audio)",
            "18 G729 (audio)", "25 CELLB (video)", "26 JPEG (video)", "28 nv (video)",
            "31 H261 (video)", "32 MPV (video)", "33 MP2T (audio/video)", "34 H263 (video)"
        ])
        self.rtpbleed_payload_input.setCurrentText("0 PCMU (audio)")
        self.rtpbleed_payload_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleed_payload_input, row, 1)
        
        layout.addWidget(QLabel("延迟时间:"), row, 2)
        self.rtpbleed_delay_input = QLineEdit()
        self.rtpbleed_delay_input.setText("10")
        self.rtpbleed_delay_input.setPlaceholderText("尝试间隔(微秒)")
        self.rtpbleed_delay_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleed_delay_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        output_file_layout = QHBoxLayout()
        self.rtpbleed_output_file_input = QLineEdit()
        self.rtpbleed_output_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/rtpbleed.txt")
        self.rtpbleed_output_file_input.setPlaceholderText("结果保存文件路径")
        self.rtpbleed_output_file_input.setMinimumWidth(240)
        output_file_layout.addWidget(self.rtpbleed_output_file_input)
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)
        output_file_btn.clicked.connect(self.choose_rtpbleed_output_file)
        output_file_layout.addWidget(output_file_btn)
        layout.addLayout(output_file_layout, row, 1, 1, 3)
        
        row += 1
        button_layout = QHBoxLayout()
        self.rtpbleed_start_btn = QPushButton("开始测试")
        self.rtpbleed_start_btn.clicked.connect(self.start_rtpbleed)
        button_layout.addWidget(self.rtpbleed_start_btn)
        self.rtpbleed_stop_btn = QPushButton("停止测试")
        self.rtpbleed_stop_btn.clicked.connect(self.stop_module)
        self.rtpbleed_stop_btn.setEnabled(False)
        button_layout.addWidget(self.rtpbleed_stop_btn)
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        row += 1
        self.rtpbleed_result_text = QTextEdit()
        self.rtpbleed_result_text.setReadOnly(True)
        self.rtpbleed_result_text.setFontFamily("Courier New")
        self.rtpbleed_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.rtpbleed_result_text, row, 0, 1, 4)
        
        return widget

    def choose_rtpbleed_output_file(self):
        """打开输出文件保存对话框"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择结果保存位置",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.txt
            if not file_name.endswith('.txt'):
                file_name += '.txt'
            self.rtpbleed_output_file_input.setText(file_name)

    def start_rtpbleed(self):
        """开始RTP Bleed测试"""
        # 清空之前的结果
        self.rtpbleed_result_text.clear()
        
        # 创建测试器实例
        from sippts.rtpbleed import RTPBleed
        self.mod = RTPBleed()
        
        # 设置所有参数
        UiTools.set_option_rtpbleed(self.mod, "ip", self.rtpbleed_ip_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.mod, "start", self.rtpbleed_start_port_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.mod, "end", self.rtpbleed_end_port_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.mod, "payload", self.rtpbleed_payload_input.currentText(), False, True)
        UiTools.set_option_rtpbleed(self.mod, "loops", self.rtpbleed_loops_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.mod, "delay", self.rtpbleed_delay_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.mod, "output_file", self.rtpbleed_output_file_input.text(), False, True)
        
        # 切换按钮状态
        self.rtpbleed_start_btn.setEnabled(False)
        self.rtpbleed_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.rtpbleed_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_rtpbleed_finished)
        
        # 启动线程
        self.worker.start()

    def on_rtpbleed_finished(self):
        """RTP Bleed测试完成处理"""
        # 恢复按钮状态
        self.rtpbleed_start_btn.setEnabled(True)
        self.rtpbleed_stop_btn.setEnabled(False)

    def create_rtpbleedinject_tab(self):
        """创建RTP Bleed Inject测试模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.rtpbleedinject_ip_input = QLineEdit()
        self.rtpbleedinject_ip_input.setText("192.168.4.200")
        self.rtpbleedinject_ip_input.setPlaceholderText("目标主机IP地址")
        self.rtpbleedinject_ip_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleedinject_ip_input, row, 1)
        
        layout.addWidget(QLabel("目标端口:"), row, 2)
        self.rtpbleedinject_port_input = QLineEdit()
        self.rtpbleedinject_port_input.setText("10042")
        self.rtpbleedinject_port_input.setPlaceholderText("目标RTP端口")
        self.rtpbleedinject_port_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleedinject_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("负载类型:"), row, 0)
        self.rtpbleedinject_payload_input = QComboBox()
        # 添加所有支持的负载类型
        self.rtpbleedinject_payload_input.addItems([
            "0 PCMU (audio)",
            "3 GSM (audio)",
            "4 G723 (audio)",
            "5 DVI4 (audio)",
            "6 DVI4 (audio)",
            "7 LPC (audio)",
            "8 PCMA (audio)",
            "9 G722 (audio)",
            "10 L16 (audio)",
            "11 L16 (audio)",
            "12 QCELP (audio)",
            "13 CN (audio)",
            "14 MPA (audio)",
            "15 G728 (audio)",
            "16 DVI4 (audio)",
            "17 DVI4 (audio)",
            "18 G729 (audio)",
            "25 CELLB (video)",
            "26 JPEG (video)",
            "28 nv (video)",
            "31 H261 (video)",
            "32 MPV (video)",
            "33 MP2T (audio/video)",
            "34 H263 (video)"
        ])
        self.rtpbleedinject_payload_input.setCurrentText("0 PCMU (audio)")
        self.rtpbleedinject_payload_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleedinject_payload_input, row, 1)
        
        layout.addWidget(QLabel("WAV文件:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        wav_file_layout = QHBoxLayout()
        
        self.rtpbleedinject_file_input = QLineEdit()
        self.rtpbleedinject_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/test.wav")
        self.rtpbleedinject_file_input.setPlaceholderText("要注入的WAV音频文件路径")
        self.rtpbleedinject_file_input.setMinimumWidth(240)
        wav_file_layout.addWidget(self.rtpbleedinject_file_input)
        
        # 添加选择文件按钮
        wav_file_btn = QPushButton("选择")
        wav_file_btn.setFixedWidth(60)
        wav_file_btn.clicked.connect(self.choose_rtpbleedinject_wav_file)
        wav_file_layout.addWidget(wav_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(wav_file_layout, row, 3)
        
        row += 1
        layout.addWidget(QLabel("循环发送:"), row, 0)
        self.rtpbleedinject_loop_input = QComboBox()
        self.rtpbleedinject_loop_input.addItems(["否", "是"])
        self.rtpbleedinject_loop_input.setCurrentText("否")
        self.rtpbleedinject_loop_input.setMinimumWidth(300)
        layout.addWidget(self.rtpbleedinject_loop_input, row, 1)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.rtpbleedinject_start_btn = QPushButton("开始注入")
        self.rtpbleedinject_start_btn.clicked.connect(self.start_rtpbleedinject)
        button_layout.addWidget(self.rtpbleedinject_start_btn)
        
        # 停止按钮
        self.rtpbleedinject_stop_btn = QPushButton("停止注入")
        self.rtpbleedinject_stop_btn.clicked.connect(self.stop_module)
        self.rtpbleedinject_stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.rtpbleedinject_stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.rtpbleedinject_result_text = QTextEdit()
        self.rtpbleedinject_result_text.setReadOnly(True)
        self.rtpbleedinject_result_text.setFontFamily("Courier New")
        self.rtpbleedinject_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.rtpbleedinject_result_text, row, 0, 1, 4)
        
        return widget

    def choose_rtpbleedinject_wav_file(self):
        """打开WAV文件选择对话框"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择WAV音频文件",
            "",
            "WAV文件 (*.wav);;所有文件 (*.*)"
        )
        if file_name:
            self.rtpbleedinject_file_input.setText(file_name)

    def start_rtpbleedinject(self):
        """开始RTP Bleed Inject测试"""
        # 清空之前的结果
        self.rtpbleedinject_result_text.clear()
        
        # 创建测试器实例
        from sippts.rtpbleedinject import RTPBleedInject
        self.mod = RTPBleedInject()
        
        # 设置所有参数
        UiTools.set_option_rtpbleedinject(self.mod, "ip", self.rtpbleedinject_ip_input.text(), False, True)
        UiTools.set_option_rtpbleedinject(self.mod, "port", self.rtpbleedinject_port_input.text(), False, True)
        UiTools.set_option_rtpbleedinject(self.mod, "payload", self.rtpbleedinject_payload_input.currentText(), False, True)
        UiTools.set_option_rtpbleedinject(self.mod, "file", self.rtpbleedinject_file_input.text(), False, True)
        UiTools.set_option_rtpbleedinject(self.mod, "loop", self.rtpbleedinject_loop_input.currentText(), False, True)
        
        # 切换按钮状态
        self.rtpbleedinject_start_btn.setEnabled(False)
        self.rtpbleedinject_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.rtpbleedinject_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_rtpbleedinject_finished)
        
        # 启动线程
        self.worker.start()

    def on_rtpbleedinject_finished(self):
        """RTP Bleed Inject测试完成处理"""
        # 恢复按钮状态
        self.rtpbleedinject_start_btn.setEnabled(True)
        self.rtpbleedinject_stop_btn.setEnabled(False)

    def create_leak_tab(self):
        """创建SIP Digest Leak测试模块界面"""
        widget = QWidget()
        layout = QGridLayout()
        widget.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.leak_ip_input = QLineEdit()
        self.leak_ip_input.setPlaceholderText("目标主机IP地址")
        self.leak_ip_input.setText("192.168.4.105")
        self.leak_ip_input.setMinimumWidth(300)
        layout.addWidget(self.leak_ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.leak_port_input = QLineEdit()
        self.leak_port_input.setText("5060")
        self.leak_port_input.setPlaceholderText("目标端口")
        self.leak_port_input.setMinimumWidth(300)
        layout.addWidget(self.leak_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("IP列表文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        file_layout = QHBoxLayout()
        
        self.leak_file_input = QLineEdit()
        self.leak_file_input.setPlaceholderText("包含多个IP的文件路径")
        self.leak_file_input.setMinimumWidth(240)
        file_layout.addWidget(self.leak_file_input)
        
        # 添加选择文件按钮
        file_btn = QPushButton("选择")
        file_btn.setFixedWidth(60)
        file_btn.clicked.connect(self.choose_leak_input_file)
        file_layout.addWidget(file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(file_layout, row, 1)
        
        layout.addWidget(QLabel("协议:"), row, 2)
        self.leak_proto_input = QComboBox()
        self.leak_proto_input.addItems(["UDP", "TCP", "TLS"])
        self.leak_proto_input.setCurrentText("UDP")
        self.leak_proto_input.setMinimumWidth(300)
        layout.addWidget(self.leak_proto_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.leak_proxy_input = QLineEdit()
        self.leak_proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.leak_proxy_input.setMinimumWidth(300)
        layout.addWidget(self.leak_proxy_input, row, 1)
        
        layout.addWidget(QLabel("认证模式:"), row, 2)
        self.leak_auth_input = QComboBox()
        self.leak_auth_input.addItems(["www", "proxy"])
        self.leak_auth_input.setCurrentText("www")
        self.leak_auth_input.setMinimumWidth(300)
        layout.addWidget(self.leak_auth_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("域名:"), row, 0)
        self.leak_domain_input = QLineEdit()
        self.leak_domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.leak_domain_input.setMinimumWidth(300)
        layout.addWidget(self.leak_domain_input, row, 1)
        
        layout.addWidget(QLabel("Contact域名:"), row, 2)
        self.leak_contact_domain_input = QLineEdit()
        self.leak_contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.leak_contact_domain_input.setText("192.168.4.202")
        self.leak_contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.leak_contact_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From名称:"), row, 0)
        self.leak_from_name_input = QLineEdit()
        self.leak_from_name_input.setPlaceholderText("例如: Bob")
        self.leak_from_name_input.setMinimumWidth(300)
        layout.addWidget(self.leak_from_name_input, row, 1)
        
        layout.addWidget(QLabel("From用户:"), row, 2)
        self.leak_from_user_input = QLineEdit()
        self.leak_from_user_input.setText("100")
        self.leak_from_user_input.setPlaceholderText("From头的用户名")
        self.leak_from_user_input.setMinimumWidth(300)
        layout.addWidget(self.leak_from_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From域名:"), row, 0)
        self.leak_from_domain_input = QLineEdit()
        self.leak_from_domain_input.setPlaceholderText("From头的域名")
        self.leak_from_domain_input.setMinimumWidth(300)
        layout.addWidget(self.leak_from_domain_input, row, 1)
        
        layout.addWidget(QLabel("To名称:"), row, 2)
        self.leak_to_name_input = QLineEdit()
        self.leak_to_name_input.setPlaceholderText("例如: Alice")
        self.leak_to_name_input.setMinimumWidth(300)
        layout.addWidget(self.leak_to_name_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To用户:"), row, 0)
        self.leak_to_user_input = QLineEdit()
        self.leak_to_user_input.setText("3004")
        self.leak_to_user_input.setPlaceholderText("To头的用户名")
        self.leak_to_user_input.setMinimumWidth(300)
        layout.addWidget(self.leak_to_user_input, row, 1)
        
        layout.addWidget(QLabel("To域名:"), row, 2)
        self.leak_to_domain_input = QLineEdit()
        self.leak_to_domain_input.setPlaceholderText("To头的域名")
        self.leak_to_domain_input.setMinimumWidth(300)
        layout.addWidget(self.leak_to_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("用户代理:"), row, 0)
        self.leak_ua_input = QLineEdit()
        self.leak_ua_input.setText("pplsip")
        self.leak_ua_input.setPlaceholderText("User-Agent头的值")
        self.leak_ua_input.setMinimumWidth(300)
        layout.addWidget(self.leak_ua_input, row, 1)
        
        layout.addWidget(QLabel("本地IP:"), row, 2)
        self.leak_local_ip_input = QLineEdit()
        self.leak_local_ip_input.setPlaceholderText("本地IP地址(可选)")
        self.leak_local_ip_input.setMinimumWidth(300)
        layout.addWidget(self.leak_local_ip_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        output_file_layout = QHBoxLayout()
        
        self.leak_output_file_input = QLineEdit()
        self.leak_output_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/sipdigestleak.txt")
        self.leak_output_file_input.setPlaceholderText("认证信息保存文件路径")
        self.leak_output_file_input.setMinimumWidth(240)
        output_file_layout.addWidget(self.leak_output_file_input)
        
        # 添加选择文件按钮
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)
        output_file_btn.clicked.connect(self.choose_leak_output_file)
        output_file_layout.addWidget(output_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_file_layout, row, 1)
        
        layout.addWidget(QLabel("日志文件:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        log_file_layout = QHBoxLayout()
        
        self.leak_log_file_input = QLineEdit()
        self.leak_log_file_input.setPlaceholderText("日志文件路径(可选)")
        self.leak_log_file_input.setMinimumWidth(240)
        log_file_layout.addWidget(self.leak_log_file_input)
        
        # 添加选择文件按钮
        log_file_btn = QPushButton("选择")
        log_file_btn.setFixedWidth(60)
        log_file_btn.clicked.connect(self.choose_leak_log_file)
        log_file_layout.addWidget(log_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(log_file_layout, row, 3)
        
        row += 1
        layout.addWidget(QLabel("详细程度:"), row, 0)
        self.leak_verbose_input = QComboBox()
        self.leak_verbose_input.addItems(["0", "1"])
        self.leak_verbose_input.setCurrentText("0")
        self.leak_verbose_input.setMinimumWidth(300)
        layout.addWidget(self.leak_verbose_input, row, 1)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.leak_start_btn = QPushButton("开始测试")
        self.leak_start_btn.clicked.connect(self.start_leak)
        button_layout.addWidget(self.leak_start_btn)
        
        # 停止按钮
        self.leak_stop_btn = QPushButton("停止测试")
        self.leak_stop_btn.clicked.connect(self.stop_module)
        self.leak_stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.leak_stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.leak_result_text = QTextEdit()
        self.leak_result_text.setReadOnly(True)
        self.leak_result_text.setFontFamily("Courier New")
        self.leak_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.leak_result_text, row, 0, 1, 4)
        
        return widget

    def choose_leak_input_file(self):
        """打开输入文件选择对话框"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择IP列表文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            self.leak_file_input.setText(file_name)

    def choose_leak_output_file(self):
        """打开输出文件保存对话框"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择认证信息保存位置",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.txt
            if not file_name.endswith('.txt'):
                file_name += '.txt'
            self.leak_output_file_input.setText(file_name)

    def choose_leak_log_file(self):
        """打开日志文件保存对话框"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择日志文件保存位置",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.txt
            if not file_name.endswith('.txt'):
                file_name += '.txt'
            self.leak_log_file_input.setText(file_name)

    def start_leak(self):
        """开始SIP Digest Leak测试"""
        # 清空之前的结果
        self.leak_result_text.clear()
        
        # 创建测试器实例
        from sippts.sipdigestleak import SipDigestLeak
        self.mod = SipDigestLeak()
        
        # 设置所有参数
        UiTools.set_option_leak(self.mod, "ip", self.leak_ip_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "rport", self.leak_port_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "file", self.leak_file_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "proto", self.leak_proto_input.currentText(), False, True)
        UiTools.set_option_leak(self.mod, "proxy", self.leak_proxy_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "auth", self.leak_auth_input.currentText(), False, True)
        UiTools.set_option_leak(self.mod, "domain", self.leak_domain_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "contact_domain", self.leak_contact_domain_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "from_name", self.leak_from_name_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "from_user", self.leak_from_user_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "from_domain", self.leak_from_domain_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "to_name", self.leak_to_name_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "to_user", self.leak_to_user_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "to_domain", self.leak_to_domain_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "ua", self.leak_ua_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "local_ip", self.leak_local_ip_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "output_file", self.leak_output_file_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "log_file", self.leak_log_file_input.text(), False, True)
        UiTools.set_option_leak(self.mod, "verbose", self.leak_verbose_input.currentText(), False, True)
        
        # 切换按钮状态
        self.leak_start_btn.setEnabled(False)
        self.leak_stop_btn.setEnabled(True)
        
        # 设置日志输出
        self.setup_logging(self.leak_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_leak_finished)
        
        # 启动线程
        self.worker.start()

    def on_leak_finished(self):
        """SIP Digest Leak测试完成处理"""
        # 恢复按钮状态
        self.leak_start_btn.setEnabled(True)
        self.leak_stop_btn.setEnabled(False)

    def create_send_tab(self):
        """创建SIP发送标签页"""
        widget = QWidget()
        layout = QGridLayout(widget)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.send_ip_input = QLineEdit()
        self.send_ip_input.setPlaceholderText("目标主机IP地址")
        self.send_ip_input.setText("192.168.4.105")
        self.send_ip_input.setMinimumWidth(300)
        layout.addWidget(self.send_ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.send_port_input = QLineEdit()
        self.send_port_input.setText("5060")
        self.send_port_input.setPlaceholderText("目标端口")
        self.send_port_input.setMinimumWidth(300)
        layout.addWidget(self.send_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("本地端口:"), row, 0)
        self.send_lport_input = QLineEdit()
        self.send_lport_input.setPlaceholderText("本地端口(可选)")
        self.send_lport_input.setMinimumWidth(300)
        layout.addWidget(self.send_lport_input, row, 1)

        layout.addWidget(QLabel("本地IP:"), row, 2)
        self.send_local_ip_input = QLineEdit()
        self.send_local_ip_input.setPlaceholderText("本地IP地址(可选)")
        self.send_local_ip_input.setMinimumWidth(300)
        layout.addWidget(self.send_local_ip_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("模板文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        file_layout = QHBoxLayout()
        
        self.send_template_input = QLineEdit()
        self.send_template_input.setPlaceholderText("SIP消息模板文件路径")
        self.send_template_input.setMinimumWidth(240)
        file_layout.addWidget(self.send_template_input)
        
        # 添加选择文件按钮
        file_btn = QPushButton("选择")
        file_btn.setFixedWidth(60)
        file_btn.clicked.connect(self.choose_send_template_file)
        file_layout.addWidget(file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(file_layout, row, 1)
        
        layout.addWidget(QLabel("协议:"), row, 2)
        self.send_proto_input = QComboBox()
        self.send_proto_input.addItems(["UDP", "TCP", "TLS"])
        self.send_proto_input.setCurrentText("UDP")
        self.send_proto_input.setMinimumWidth(300)
        layout.addWidget(self.send_proto_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.send_proxy_input = QLineEdit()
        self.send_proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.send_proxy_input.setMinimumWidth(300)
        layout.addWidget(self.send_proxy_input, row, 1)
        
        layout.addWidget(QLabel("方法:"), row, 2)
        self.send_method_input = QComboBox()
        self.send_method_input.addItems([
            "REGISTER", "SUBSCRIBE", "NOTIFY", "PUBLISH", "MESSAGE",
            "INVITE", "OPTIONS", "ACK", "CANCEL", "BYE", "PRACK",
            "INFO", "REFER", "UPDATE"
        ])
        self.send_method_input.setCurrentText("INVITE")
        self.send_method_input.setMinimumWidth(300)
        layout.addWidget(self.send_method_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("域名:"), row, 0)
        self.send_domain_input = QLineEdit()
        self.send_domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.send_domain_input.setMinimumWidth(300)
        layout.addWidget(self.send_domain_input, row, 1)
        
        layout.addWidget(QLabel("Contact域名:"), row, 2)
        self.send_contact_domain_input = QLineEdit()
        self.send_contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.send_contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.send_contact_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From名称:"), row, 0)
        self.send_from_name_input = QLineEdit()
        self.send_from_name_input.setPlaceholderText("例如: Bob")
        self.send_from_name_input.setMinimumWidth(300)
        layout.addWidget(self.send_from_name_input, row, 1)
        
        layout.addWidget(QLabel("From用户:"), row, 2)
        self.send_from_user_input = QLineEdit()
        self.send_from_user_input.setText("100")
        self.send_from_user_input.setPlaceholderText("From头的用户名")
        self.send_from_user_input.setMinimumWidth(300)
        layout.addWidget(self.send_from_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From域名:"), row, 0)
        self.send_from_domain_input = QLineEdit()
        self.send_from_domain_input.setPlaceholderText("From头的域名")
        self.send_from_domain_input.setMinimumWidth(300)
        layout.addWidget(self.send_from_domain_input, row, 1)

        layout.addWidget(QLabel("From标签:"), row, 2)
        self.send_from_tag_input = QLineEdit()
        self.send_from_tag_input.setPlaceholderText("From头的标签值")
        self.send_from_tag_input.setMinimumWidth(300)
        layout.addWidget(self.send_from_tag_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To名称:"), row, 0)
        self.send_to_name_input = QLineEdit()
        self.send_to_name_input.setPlaceholderText("例如: Alice")
        self.send_to_name_input.setMinimumWidth(300)
        layout.addWidget(self.send_to_name_input, row, 1)
        
        layout.addWidget(QLabel("To用户:"), row, 2)
        self.send_to_user_input = QLineEdit()
        self.send_to_user_input.setText("100")
        self.send_to_user_input.setPlaceholderText("To头的用户名")
        self.send_to_user_input.setMinimumWidth(300)
        layout.addWidget(self.send_to_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To域名:"), row, 0)
        self.send_to_domain_input = QLineEdit()
        self.send_to_domain_input.setPlaceholderText("To头的域名")
        self.send_to_domain_input.setMinimumWidth(300)
        layout.addWidget(self.send_to_domain_input, row, 1)

        layout.addWidget(QLabel("To标签:"), row, 2)
        self.send_to_tag_input = QLineEdit()
        self.send_to_tag_input.setPlaceholderText("To头的标签值")
        self.send_to_tag_input.setMinimumWidth(300)
        layout.addWidget(self.send_to_tag_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("认证用户:"), row, 0)
        self.send_auth_user_input = QLineEdit()
        self.send_auth_user_input.setPlaceholderText("认证用户名")
        self.send_auth_user_input.setMinimumWidth(300)
        layout.addWidget(self.send_auth_user_input, row, 1)
        
        layout.addWidget(QLabel("认证密码:"), row, 2)
        self.send_auth_pass_input = QLineEdit()
        self.send_auth_pass_input.setPlaceholderText("认证密码")
        self.send_auth_pass_input.setMinimumWidth(300)
        layout.addWidget(self.send_auth_pass_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("User-Agent:"), row, 0)
        self.send_ua_input = QLineEdit()
        self.send_ua_input.setText("pplsip")
        self.send_ua_input.setPlaceholderText("User-Agent头的值")
        self.send_ua_input.setMinimumWidth(300)
        layout.addWidget(self.send_ua_input, row, 1)

        layout.addWidget(QLabel("超时时间(秒):"), row, 2)
        self.send_timeout_input = QLineEdit()
        self.send_timeout_input.setText("5")
        self.send_timeout_input.setPlaceholderText("请求超时时间")
        self.send_timeout_input.setMinimumWidth(300)
        layout.addWidget(self.send_timeout_input, row, 3)

        row += 1
        layout.addWidget(QLabel("P-Preferred-Identity:"), row, 0)
        self.send_ppi_input = QLineEdit()
        self.send_ppi_input.setPlaceholderText("P-Preferred-Identity头的值")
        self.send_ppi_input.setMinimumWidth(300)
        layout.addWidget(self.send_ppi_input, row, 1)

        layout.addWidget(QLabel("P-Asserted-Identity:"), row, 2)
        self.send_pai_input = QLineEdit()
        self.send_pai_input.setPlaceholderText("P-Asserted-Identity头的值")
        self.send_pai_input.setMinimumWidth(300)
        layout.addWidget(self.send_pai_input, row, 3)

        row += 1
        layout.addWidget(QLabel("Branch:"), row, 0)
        self.send_branch_input = QLineEdit()
        self.send_branch_input.setPlaceholderText("Via头的branch参数")
        self.send_branch_input.setMinimumWidth(300)
        layout.addWidget(self.send_branch_input, row, 1)

        layout.addWidget(QLabel("Call-ID:"), row, 2)
        self.send_callid_input = QLineEdit()
        self.send_callid_input.setPlaceholderText("Call-ID头的值")
        self.send_callid_input.setMinimumWidth(300)
        layout.addWidget(self.send_callid_input, row, 3)

        row += 1
        layout.addWidget(QLabel("CSeq:"), row, 0)
        self.send_cseq_input = QLineEdit()
        self.send_cseq_input.setText("1")
        self.send_cseq_input.setPlaceholderText("CSeq头的序号值")
        self.send_cseq_input.setMinimumWidth(300)
        layout.addWidget(self.send_cseq_input, row, 1)

        layout.addWidget(QLabel("自定义头部:"), row, 2)
        self.send_header_input = QLineEdit()
        self.send_header_input.setPlaceholderText("自定义SIP头部")
        self.send_header_input.setMinimumWidth(300)
        layout.addWidget(self.send_header_input, row, 3)

        row += 1
        # SDP相关选项
        sdp_group = QGroupBox("SDP选项")
        sdp_layout = QHBoxLayout()
        
        self.send_sdp_check = QCheckBox("包含SDP")
        self.send_sdp_check.setChecked(False)
        sdp_layout.addWidget(self.send_sdp_check)
        
        self.send_sdes_check = QCheckBox("包含SDES")
        self.send_sdes_check.setChecked(False)
        sdp_layout.addWidget(self.send_sdes_check)
        
        sdp_group.setLayout(sdp_layout)
        layout.addWidget(sdp_group, row, 0, 1, 2)

        # 其他选项
        other_group = QGroupBox("其他选项")
        other_layout = QHBoxLayout()
        
        self.send_nocontact_check = QCheckBox("不包含Contact头")
        self.send_nocontact_check.setChecked(False)
        other_layout.addWidget(self.send_nocontact_check)
        
        self.send_verbose_check = QCheckBox("详细输出")
        self.send_verbose_check.setChecked(False)
        other_layout.addWidget(self.send_verbose_check)
        
        other_group.setLayout(other_layout)
        layout.addWidget(other_group, row, 2, 1, 2)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        output_layout = QHBoxLayout()
        
        self.send_output_input = QLineEdit()
        self.send_output_input.setPlaceholderText("输出文件路径")
        self.send_output_input.setMinimumWidth(240)
        output_layout.addWidget(self.send_output_input)
        
        # 添加选择文件按钮
        output_btn = QPushButton("选择")
        output_btn.setFixedWidth(60)
        output_btn.clicked.connect(self.choose_send_output_file)
        output_layout.addWidget(output_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_layout, row, 1, 1, 3)
        
        row += 1
        # 创建结果显示区域
        self.send_result_text = QTextEdit()
        self.send_result_text.setReadOnly(True)
        self.send_result_text.setFontFamily("Courier New")
        self.send_result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                color: white;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.send_result_text, row, 0, 1, 4)
        
        row += 1
        # 创建按钮布局
        button_layout = QHBoxLayout()
        
        self.send_start_btn = QPushButton("开始发送")
        self.send_start_btn.clicked.connect(self.start_send)
        button_layout.addWidget(self.send_start_btn)
        
        self.send_stop_btn = QPushButton("停止")
        self.send_stop_btn.clicked.connect(self.stop_module)
        self.send_stop_btn.setEnabled(False)
        button_layout.addWidget(self.send_stop_btn)
        
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        return widget

    def choose_send_template_file(self):
        """选择SIP消息模板文件"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "选择SIP消息模板文件",
            "",
            "所有文件 (*.*)"
        )
        if filename:
            self.send_template_input.setText(filename)
            
    def choose_send_output_file(self):
        """选择输出文件"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "选择输出文件",
            "",
            "所有文件 (*.*)"
        )
        if filename:
            self.send_output_input.setText(filename)
            
    def start_send(self):
        # 创建测试器实例
        from sippts.sipsend import SipSend
        self.mod = SipSend()
        """开始发送SIP消息"""
        self.send_start_btn.setEnabled(False)
        self.send_stop_btn.setEnabled(True)
                
        # 设置参数
        UiTools.set_option_send(self.mod, "ip", self.send_ip_input.text(), False, False)
        UiTools.set_option_send(self.mod, "rport", self.send_port_input.text(), False, False)
        UiTools.set_option_send(self.mod, "proto", self.send_proto_input.currentText(), False, False)
        UiTools.set_option_send(self.mod, "proxy", self.send_proxy_input.text(), False, False)
        UiTools.set_option_send(self.mod, "method", self.send_method_input.currentText(), False, False)
        UiTools.set_option_send(self.mod, "domain", self.send_domain_input.text(), False, False)
        UiTools.set_option_send(self.mod, "contact_domain", self.send_contact_domain_input.text(), False, False)
        UiTools.set_option_send(self.mod, "from_user", self.send_from_user_input.text(), False, False)
        UiTools.set_option_send(self.mod, "from_name", self.send_from_name_input.text(), False, False)
        UiTools.set_option_send(self.mod, "from_domain", self.send_from_domain_input.text(), False, False)
        UiTools.set_option_send(self.mod, "to_user", self.send_to_user_input.text(), False, False)
        UiTools.set_option_send(self.mod, "to_name", self.send_to_name_input.text(), False, False)
        UiTools.set_option_send(self.mod, "to_domain", self.send_to_domain_input.text(), False, False)
        UiTools.set_option_send(self.mod, "ua", self.send_ua_input.text(), False, False)
        UiTools.set_option_send(self.mod, "user", self.send_auth_user_input.text(), False, False)
        UiTools.set_option_send(self.mod, "pass", self.send_auth_pass_input.text(), False, False)
        UiTools.set_option_send(self.mod, "template", self.send_template_input.text(), False, False)
        UiTools.set_option_send(self.mod, "output_file", self.send_output_input.text(), False, False)
        UiTools.set_option_send(self.mod, "timeout", self.send_timeout_input.text(), False, False)
        UiTools.set_option_send(self.mod, "ppi", self.send_ppi_input.text(), False, False)
        UiTools.set_option_send(self.mod, "pai", self.send_pai_input.text(), False, False)
        UiTools.set_option_send(self.mod, "branch", self.send_branch_input.text(), False, False)
        UiTools.set_option_send(self.mod, "callid", self.send_callid_input.text(), False, False)
        UiTools.set_option_send(self.mod, "cseq", self.send_cseq_input.text(), False, False)
        UiTools.set_option_send(self.mod, "header", self.send_header_input.text(), False, False)
        UiTools.set_option_send(self.mod, "to_tag", self.send_to_tag_input.text(), False, False)
        UiTools.set_option_send(self.mod, "from_tag", self.send_from_tag_input.text(), False, False)
        
        # 设置SDP选项
        if self.send_sdp_check.isChecked():
            UiTools.set_option_send(self.mod, "sdp", "1", False, False)
        if self.send_sdes_check.isChecked():
            UiTools.set_option_send(self.mod, "sdes", "1", False, False)
            
        # 设置其他选项
        if self.send_nocontact_check.isChecked():
            self.mod.nocontact = 1
        if self.send_verbose_check.isChecked():
            UiTools.set_option_send(self.mod, "verbose", "1", False, False)
        
        # 设置日志输出
        self.setup_logging(self.send_result_text)
        sys.stdout = self.log_manager
        
        # 创建工作线程
        self.worker = ModuleWorker(self.mod)
        self.worker.finished.connect(self.on_send_finished)
        
        # 启动线程
        self.worker.start()
        
    def on_send_finished(self):
        """发送完成的回调函数"""
        self.send_start_btn.setEnabled(True)
        self.send_stop_btn.setEnabled(False)

# 添加一个通用的工作线程类
class ModuleWorker(QThread):
    finished = pyqtSignal()  # 完成信号
    
    def __init__(self, mod):
        super().__init__()
        self.mod = mod
    
    def run(self):
        try:
            # 执行模块
            self.mod.start()
        finally:
            self.finished.emit()

def run_gui():
    """启动GUI应用"""
    app = QApplication(sys.argv)
    
    # 设置应用程序图标
    icon_path = os.path.join(os.path.dirname(__file__), "resources", "icon.ico")
    if os.path.exists(icon_path):
        icon = QIcon(icon_path)
        # 设置更大的图标尺寸
        app.setWindowIcon(icon)
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    run_gui()