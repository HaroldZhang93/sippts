from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, 
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.sipdigestleak import SipDigestLeak

class LeakTab(BaseTab):
    """SIP Digest Leak测试模块标签页"""
    
    def __init__(self, main_window):
        super().__init__(main_window)
        
        # 初始化UI
        self.setup_ui()
    
    def setup_ui(self):
        """设置UI界面"""
        # 创建主布局
        layout = QGridLayout()
        self.setLayout(layout)
        
        # 设置列宽比例
        layout.setColumnStretch(0, 1)  # 标签列
        layout.setColumnStretch(1, 4)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 4)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("目标主机IP地址")
        self.ip_input.setText("192.168.100.10")
        self.ip_input.setMinimumWidth(300)
        layout.addWidget(self.ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.port_input = QLineEdit()
        self.port_input.setText("5060")
        self.port_input.setPlaceholderText("目标端口")
        self.port_input.setMinimumWidth(300)
        layout.addWidget(self.port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("IP列表文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        file_layout = QHBoxLayout()
        
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("包含多个IP的文件路径")
        self.file_input.setMinimumWidth(240)
        file_layout.addWidget(self.file_input)
        
        # 添加选择文件按钮
        file_btn = QPushButton("选择")
        file_btn.setFixedWidth(60)
        file_btn.clicked.connect(self.choose_input_file)
        file_layout.addWidget(file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(file_layout, row, 1)
        
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
        
        layout.addWidget(QLabel("认证模式:"), row, 2)
        self.auth_input = QComboBox()
        self.auth_input.addItems(["www", "proxy"])
        self.auth_input.setCurrentText("www")
        self.auth_input.setMinimumWidth(300)
        layout.addWidget(self.auth_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("域名:"), row, 0)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.domain_input.setMinimumWidth(300)
        layout.addWidget(self.domain_input, row, 1)
        
        layout.addWidget(QLabel("Contact域名:"), row, 2)
        self.contact_domain_input = QLineEdit()
        self.contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.contact_domain_input.setText("20.50.1.10")
        self.contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.contact_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From名称:"), row, 0)
        self.from_name_input = QLineEdit()
        self.from_name_input.setPlaceholderText("例如: Bob")
        self.from_name_input.setMinimumWidth(300)
        layout.addWidget(self.from_name_input, row, 1)
        
        layout.addWidget(QLabel("From用户:"), row, 2)
        self.from_user_input = QLineEdit()
        self.from_user_input.setText("100")
        self.from_user_input.setPlaceholderText("From头的用户名")
        self.from_user_input.setMinimumWidth(300)
        layout.addWidget(self.from_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From域名:"), row, 0)
        self.from_domain_input = QLineEdit()
        self.from_domain_input.setPlaceholderText("From头的域名")
        self.from_domain_input.setMinimumWidth(300)
        layout.addWidget(self.from_domain_input, row, 1)
        
        layout.addWidget(QLabel("To名称:"), row, 2)
        self.to_name_input = QLineEdit()
        self.to_name_input.setPlaceholderText("例如: Alice")
        self.to_name_input.setMinimumWidth(300)
        layout.addWidget(self.to_name_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To用户:"), row, 0)
        self.to_user_input = QLineEdit()
        self.to_user_input.setText("+861088889003")
        self.to_user_input.setPlaceholderText("To头的用户名")
        self.to_user_input.setMinimumWidth(300)
        layout.addWidget(self.to_user_input, row, 1)
        
        layout.addWidget(QLabel("To域名:"), row, 2)
        self.to_domain_input = QLineEdit()
        self.to_domain_input.setPlaceholderText("To头的域名")
        self.to_domain_input.setMinimumWidth(300)
        layout.addWidget(self.to_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("用户代理:"), row, 0)
        self.ua_input = QLineEdit()
        self.ua_input.setText("pplsip")
        self.ua_input.setPlaceholderText("User-Agent头的值")
        self.ua_input.setMinimumWidth(300)
        layout.addWidget(self.ua_input, row, 1)
        
        layout.addWidget(QLabel("本地IP:"), row, 2)
        self.local_ip_input = QLineEdit()
        self.local_ip_input.setPlaceholderText("本地IP地址(可选)")
        self.local_ip_input.setText("20.50.1.10")
        self.local_ip_input.setMinimumWidth(300)
        layout.addWidget(self.local_ip_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        output_file_layout = QHBoxLayout()
        
        self.output_file_input = QLineEdit()
        self.output_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/sipdigestleak.txt")
        self.output_file_input.setPlaceholderText("认证信息保存文件路径")
        self.output_file_input.setMinimumWidth(240)
        output_file_layout.addWidget(self.output_file_input)
        
        # 添加选择文件按钮
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)
        output_file_btn.clicked.connect(self.choose_output_file)
        output_file_layout.addWidget(output_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_file_layout, row, 1)
        
        layout.addWidget(QLabel("日志文件:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        log_file_layout = QHBoxLayout()
        
        self.log_file_input = QLineEdit()
        self.log_file_input.setPlaceholderText("日志文件路径(可选)")
        self.log_file_input.setMinimumWidth(240)
        log_file_layout.addWidget(self.log_file_input)
        
        # 添加选择文件按钮
        log_file_btn = QPushButton("选择")
        log_file_btn.setFixedWidth(60)
        log_file_btn.clicked.connect(self.choose_log_file)
        log_file_layout.addWidget(log_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(log_file_layout, row, 3)
        
        row += 1
        layout.addWidget(QLabel("详细程度:"), row, 0)
        self.verbose_input = QComboBox()
        self.verbose_input.addItems(["0", "1"])
        self.verbose_input.setCurrentText("0")
        self.verbose_input.setMinimumWidth(300)
        layout.addWidget(self.verbose_input, row, 1)
        
        layout.addWidget(QLabel("伪造IP:"), row, 2)
        self.spoof_ip_input = QLineEdit()
        self.spoof_ip_input.setPlaceholderText("伪造的源IP地址(可选)")
        self.spoof_ip_input.setText("20.50.1.10")
        self.spoof_ip_input.setMinimumWidth(300)
        layout.addWidget(self.spoof_ip_input, row, 3)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.start_btn = QPushButton("开始测试")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = QPushButton("停止测试")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.create_result_text(layout, row)
    
    def choose_input_file(self):
        """选择输入文件"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择IP列表文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            self.file_input.setText(file_name)
    
    def choose_output_file(self):
        """选择输出文件"""
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
            self.output_file_input.setText(file_name)
    
    def choose_log_file(self):
        """选择日志文件"""
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
            self.log_file_input.setText(file_name)
    
    def start_module(self):
        """启动SIP Digest Leak测试模块"""
        # 清空结果文本
        self.result_text.clear()
        
        # 创建模块实例
        from sippts.gui.uitools import UiTools
        self.module_instance = SipDigestLeak()
        
        # 设置参数
        UiTools.set_option_leak(self.module_instance, "ip", self.ip_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "rport", self.port_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "file", self.file_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "proto", self.proto_input.currentText(), False, True)
        UiTools.set_option_leak(self.module_instance, "proxy", self.proxy_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "auth", self.auth_input.currentText(), False, True)
        UiTools.set_option_leak(self.module_instance, "domain", self.domain_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "contact_domain", self.contact_domain_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "from_name", self.from_name_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "from_user", self.from_user_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "from_domain", self.from_domain_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "to_name", self.to_name_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "to_user", self.to_user_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "to_domain", self.to_domain_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "ua", self.ua_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "local_ip", self.local_ip_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "spoof_ip", self.spoof_ip_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "output_file", self.output_file_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "log_file", self.log_file_input.text(), False, True)
        UiTools.set_option_leak(self.module_instance, "verbose", self.verbose_input.currentText(), False, True)
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        ) 