from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, 
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.siprcrack import SipRemoteCrack

class CrackTab(BaseTab):
    """SIP密码破解模块标签页"""
    
    def __init__(self, main_window):
        super().__init__(main_window)
        
        # 初始化UI
        self.setup_ui()
        
        # 从配置加载输入值
        self.load_input_values()
    
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
        layout.addWidget(QLabel("目标 IP/网段:"), row, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setObjectName("ip_input")
        self.ip_input.setText("20.50.1.10")
        self.ip_input.setPlaceholderText("目标IP地址或网段，例如: 192.168.0.0/24")
        self.ip_input.setMinimumWidth(300)
        layout.addWidget(self.ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.port_input = QLineEdit()
        self.port_input.setObjectName("port_input")
        self.port_input.setText("5060")
        self.port_input.setPlaceholderText("目标端口，例如: 5060")
        self.port_input.setMinimumWidth(300)
        layout.addWidget(self.port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("分机范围:"), row, 0)
        self.exten_input = QLineEdit()
        self.exten_input.setObjectName("exten_input")
        self.exten_input.setText("9001-9005")
        self.exten_input.setPlaceholderText("例如: 100 | 100,102,105 | 100-200")
        self.exten_input.setMinimumWidth(300)
        layout.addWidget(self.exten_input, row, 1)
        
        layout.addWidget(QLabel("协议:"), row, 2)
        self.proto_input = QComboBox()
        self.proto_input.setObjectName("proto_input")
        self.proto_input.addItems(["UDP", "TCP", "TLS"])
        self.proto_input.setCurrentText("UDP")
        self.proto_input.setMinimumWidth(300)
        layout.addWidget(self.proto_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.proxy_input = QLineEdit()
        self.proxy_input.setObjectName("proxy_input")
        self.proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.proxy_input.setMinimumWidth(300)
        layout.addWidget(self.proxy_input, row, 1)
        
        layout.addWidget(QLabel("分机前缀:"), row, 2)
        self.prefix_input = QLineEdit()
        self.prefix_input.setObjectName("prefix_input")
        self.prefix_input.setPlaceholderText("用于认证的分机前缀")
        self.prefix_input.setMinimumWidth(300)
        self.prefix_input.setText("+86108888")
        layout.addWidget(self.prefix_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("认证用户:"), row, 0)
        self.authuser_input = QLineEdit()
        self.authuser_input.setObjectName("authuser_input")
        self.authuser_input.setPlaceholderText("认证用户名(默认使用分机号)")
        self.authuser_input.setMinimumWidth(300)
        layout.addWidget(self.authuser_input, row, 1)
        
        layout.addWidget(QLabel("分机长度:"), row, 2)
        self.ext_len_input = QLineEdit()
        self.ext_len_input.setObjectName("ext_len_input")
        self.ext_len_input.setPlaceholderText("分机号长度，用0补齐")
        self.ext_len_input.setMinimumWidth(300)
        layout.addWidget(self.ext_len_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("域名:"), row, 0)
        self.domain_input = QLineEdit()
        self.domain_input.setObjectName("domain_input")
        self.domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.domain_input.setMinimumWidth(300)
        self.domain_input.setText("dra.ims.sdt")
        layout.addWidget(self.domain_input, row, 1)
        
        layout.addWidget(QLabel("Contact域名:"), row, 2)
        self.contact_domain_input = QLineEdit()
        self.contact_domain_input.setObjectName("contact_domain_input")
        self.contact_domain_input.setText("192.168.100.99")
        self.contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.contact_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("密码字典:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        wordlist_layout = QHBoxLayout()
        
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setObjectName("wordlist_input")
        self.wordlist_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/passwordlist.txt")
        self.wordlist_input.setPlaceholderText("密码字典文件路径")
        self.wordlist_input.setMinimumWidth(240)
        wordlist_layout.addWidget(self.wordlist_input)
        
        # 添加选择文件按钮
        wordlist_btn = QPushButton("选择")
        wordlist_btn.setFixedWidth(60)
        wordlist_btn.clicked.connect(self.choose_wordlist_file)
        wordlist_layout.addWidget(wordlist_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(wordlist_layout, row, 1)
        
        layout.addWidget(QLabel("User-Agent:"), row, 2)
        self.ua_input = QLineEdit()
        self.ua_input.setObjectName("ua_input")
        self.ua_input.setText("pplsip")
        self.ua_input.setPlaceholderText("User-Agent头的值")
        self.ua_input.setMinimumWidth(300)
        layout.addWidget(self.ua_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("线程数:"), row, 0)
        self.threads_input = QLineEdit()
        self.threads_input.setObjectName("threads_input")
        self.threads_input.setText("100")
        self.threads_input.setPlaceholderText("破解使用的线程数")
        self.threads_input.setMinimumWidth(300)
        layout.addWidget(self.threads_input, row, 1)
        
        layout.addWidget(QLabel("超时(秒):"), row, 2)
        self.timeout_input = QLineEdit()
        self.timeout_input.setObjectName("timeout_input")
        self.timeout_input.setText("5")
        self.timeout_input.setPlaceholderText("Socket超时时间(秒)")
        self.timeout_input.setMinimumWidth(300)
        layout.addWidget(self.timeout_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("详细程度:"), row, 0)
        self.verbose_input = QComboBox()
        self.verbose_input.setObjectName("verbose_input")
        self.verbose_input.addItems(["0", "1", "2"])
        self.verbose_input.setCurrentText("0")
        self.verbose_input.setMinimumWidth(300)
        layout.addWidget(self.verbose_input, row, 1)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.start_btn = QPushButton("开始破解")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = QPushButton("停止破解")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.create_result_text(layout, row)
    
    def choose_wordlist_file(self):
        """选择密码字典文件"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择密码字典文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            self.wordlist_input.setText(file_name)
    
    def start_module(self):
        """启动SIP密码破解模块"""
        # 保存当前输入值
        self.save_input_values()
        
        # 清空结果文本
        self.result_text.clear()
        
        # 创建模块实例
        from sippts.gui.uitools import UiTools
        self.module_instance = SipRemoteCrack()
        
        # 设置参数
        UiTools.set_option_rcrack(self.module_instance, "ip", self.ip_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "rport", self.port_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "exten", self.exten_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "proto", self.proto_input.currentText(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "proxy", self.proxy_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "prefix", self.prefix_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "auth_user", self.authuser_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "len", self.ext_len_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "domain", self.domain_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "contact_domain", self.contact_domain_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "wordlist", self.wordlist_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "ua", self.ua_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "threads", self.threads_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "timeout", self.timeout_input.text(), False, True)
        UiTools.set_option_rcrack(self.module_instance, "verbose", self.verbose_input.currentText(), False, True)
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        ) 