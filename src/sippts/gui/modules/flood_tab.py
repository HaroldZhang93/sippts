from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, 
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.sipflood import SipFlood

class FloodTab(BaseTab):
    """SIP洪水攻击模块标签页"""
    
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
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setObjectName("ip_input")
        self.ip_input.setText("192.168.100.10")
        self.ip_input.setPlaceholderText("目标主机IP地址")
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
        layout.addWidget(QLabel("协议:"), row, 0)
        self.proto_input = QComboBox()
        self.proto_input.setObjectName("proto_input")
        self.proto_input.addItems(["UDP", "TCP", "TLS"])
        self.proto_input.setCurrentText("UDP")
        self.proto_input.setMinimumWidth(300)
        layout.addWidget(self.proto_input, row, 1)
        
        layout.addWidget(QLabel("请求方法:"), row, 2)
        self.method_input = QComboBox()
        self.method_input.setObjectName("method_input")
        self.method_input.addItems(["REGISTER", "INVITE", "OPTIONS"])
        self.method_input.setCurrentText("REGISTER")
        self.method_input.setMinimumWidth(300)
        layout.addWidget(self.method_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.proxy_input = QLineEdit()
        self.proxy_input.setObjectName("proxy_input")
        self.proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.proxy_input.setMinimumWidth(300)
        layout.addWidget(self.proxy_input, row, 1)
        
        layout.addWidget(QLabel("域名:"), row, 2)
        self.domain_input = QLineEdit()
        self.domain_input.setObjectName("domain_input")
        self.domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.domain_input.setMinimumWidth(300)
        self.domain_input.setText("dra.ims.sdt")
        layout.addWidget(self.domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("Contact域名:"), row, 0)
        self.contact_domain_input = QLineEdit()
        self.contact_domain_input.setObjectName("contact_domain_input")
        self.contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.contact_domain_input.setMinimumWidth(300)
        layout.addWidget(self.contact_domain_input, row, 1)
        
        layout.addWidget(QLabel("From用户:"), row, 2)
        self.from_user_input = QLineEdit()
        self.from_user_input.setObjectName("from_user_input")
        self.from_user_input.setText("100")
        self.from_user_input.setPlaceholderText("From头的用户名")
        self.from_user_input.setMinimumWidth(300)
        layout.addWidget(self.from_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From名称:"), row, 0)
        self.from_name_input = QLineEdit()
        self.from_name_input.setObjectName("from_name_input")
        self.from_name_input.setPlaceholderText("From头的显示名称")
        self.from_name_input.setMinimumWidth(300)
        layout.addWidget(self.from_name_input, row, 1)
        
        layout.addWidget(QLabel("From域名:"), row, 2)
        self.from_domain_input = QLineEdit()
        self.from_domain_input.setObjectName("from_domain_input")
        self.from_domain_input.setPlaceholderText("From头的域名")
        self.from_domain_input.setMinimumWidth(300)
        layout.addWidget(self.from_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To用户:"), row, 0)
        self.to_user_input = QLineEdit()
        self.to_user_input.setObjectName("to_user_input")
        self.to_user_input.setText("100")
        self.to_user_input.setPlaceholderText("To头的用户名")
        self.to_user_input.setMinimumWidth(300)
        layout.addWidget(self.to_user_input, row, 1)
        
        layout.addWidget(QLabel("To名称:"), row, 2)
        self.to_name_input = QLineEdit()
        self.to_name_input.setObjectName("to_name_input")
        self.to_name_input.setPlaceholderText("To头的显示名称")
        self.to_name_input.setMinimumWidth(300)
        layout.addWidget(self.to_name_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To域名:"), row, 0)
        self.to_domain_input = QLineEdit()
        self.to_domain_input.setObjectName("to_domain_input")
        self.to_domain_input.setPlaceholderText("To头的域名")
        self.to_domain_input.setMinimumWidth(300)
        layout.addWidget(self.to_domain_input, row, 1)
        
        layout.addWidget(QLabel("User-Agent:"), row, 2)
        self.ua_input = QLineEdit()
        self.ua_input.setObjectName("ua_input")
        self.ua_input.setText("pplsip")
        self.ua_input.setPlaceholderText("User-Agent头的值")
        self.ua_input.setMinimumWidth(300)
        layout.addWidget(self.ua_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("认证信息:"), row, 0)
        self.digest_input = QLineEdit()
        self.digest_input.setObjectName("digest_input")
        self.digest_input.setPlaceholderText("认证信息(可选)")
        self.digest_input.setMinimumWidth(300)
        layout.addWidget(self.digest_input, row, 1)
        
        layout.addWidget(QLabel("恶意数据:"), row, 2)
        self.bad_input = QComboBox()
        self.bad_input.setObjectName("bad_input")
        self.bad_input.addItems(["0", "1"])
        self.bad_input.setCurrentText("0")
        self.bad_input.setMinimumWidth(300)
        layout.addWidget(self.bad_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("字符集:"), row, 0)
        self.charset_input = QComboBox()
        self.charset_input.setObjectName("charset_input")
        self.charset_input.addItems(["printable", "digits", "ascii_letters", "ascii_lowercase", "ascii_uppercase", "hexdigits", "octdigits", "punctuation", "whitespace"])
        self.charset_input.setCurrentText("printable")
        self.charset_input.setMinimumWidth(300)
        layout.addWidget(self.charset_input, row, 1)
        
        layout.addWidget(QLabel("最小长度:"), row, 2)
        self.min_input = QLineEdit()
        self.min_input.setObjectName("min_input")
        self.min_input.setText("0")
        self.min_input.setPlaceholderText("恶意数据的最小长度")
        self.min_input.setMinimumWidth(300)
        layout.addWidget(self.min_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("最大长度:"), row, 0)
        self.max_input = QLineEdit()
        self.max_input.setObjectName("max_input")
        self.max_input.setText("1000")
        self.max_input.setPlaceholderText("恶意数据的最大长度")
        self.max_input.setMinimumWidth(300)
        layout.addWidget(self.max_input, row, 1)
        
        layout.addWidget(QLabel("请求数量:"), row, 2)
        self.requests_input = QLineEdit()
        self.requests_input.setObjectName("requests_input")
        self.requests_input.setText("0")
        self.requests_input.setPlaceholderText("0表示无限制")
        self.requests_input.setMinimumWidth(300)
        layout.addWidget(self.requests_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("线程数:"), row, 0)
        self.threads_input = QLineEdit()
        self.threads_input.setObjectName("threads_input")
        self.threads_input.setText("100")
        self.threads_input.setPlaceholderText("压测使用的线程数")
        self.threads_input.setMinimumWidth(300)
        layout.addWidget(self.threads_input, row, 1)
        
        layout.addWidget(QLabel("详细程度:"), row, 2)
        self.verbose_input = QComboBox()
        self.verbose_input.setObjectName("verbose_input")
        self.verbose_input.addItems(["0", "1"])
        self.verbose_input.setCurrentText("0")
        self.verbose_input.setMinimumWidth(300)
        layout.addWidget(self.verbose_input, row, 3)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.start_btn = QPushButton("开始压测")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = QPushButton("停止压测")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.create_result_text(layout, row)
    
    def start_module(self):
        """启动SIP洪水攻击模块"""
        # 保存当前输入值
        self.save_input_values()
        
        # 清空结果文本
        self.result_text.clear()
        
        # 创建模块实例
        from sippts.gui.uitools import UiTools
        self.module_instance = SipFlood()
        
        # 设置参数
        UiTools.set_option_flood(self.module_instance, "ip", self.ip_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "rport", self.port_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "proto", self.proto_input.currentText(), False, True)
        UiTools.set_option_flood(self.module_instance, "method", self.method_input.currentText(), False, True)
        UiTools.set_option_flood(self.module_instance, "proxy", self.proxy_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "domain", self.domain_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "contact_domain", self.contact_domain_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "from_user", self.from_user_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "from_name", self.from_name_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "from_domain", self.from_domain_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "to_user", self.to_user_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "to_name", self.to_name_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "to_domain", self.to_domain_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "ua", self.ua_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "digest", self.digest_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "bad", self.bad_input.currentText(), False, True)
        UiTools.set_option_flood(self.module_instance, "charset", self.charset_input.currentText(), False, True)
        UiTools.set_option_flood(self.module_instance, "min", self.min_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "max", self.max_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "requests", self.requests_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "threads", self.threads_input.text(), False, True)
        UiTools.set_option_flood(self.module_instance, "verbose", self.verbose_input.currentText(), False, True)
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        ) 