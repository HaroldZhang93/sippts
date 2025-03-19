from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, QCheckBox, QGroupBox,
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.sipsend import SipSend

class SendTab(BaseTab):
    """SIP消息发送模块标签页"""
    
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
        layout.setColumnStretch(1, 2)  # 输入框列
        layout.setColumnStretch(2, 1)  # 标签列
        layout.setColumnStretch(3, 2)  # 输入框列
        
        # 基本参数
        row = 0
        layout.addWidget(QLabel("目标 IP:"), row, 0)
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("目标主机IP地址")
        self.ip_input.setText("192.168.100.144")
        self.ip_input.setMinimumWidth(200)
        layout.addWidget(self.ip_input, row, 1)
        
        layout.addWidget(QLabel("端口:"), row, 2)
        self.port_input = QLineEdit()
        self.port_input.setText("5060")
        self.port_input.setPlaceholderText("目标端口")
        self.port_input.setMinimumWidth(200)
        layout.addWidget(self.port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("本地端口:"), row, 0)
        self.lport_input = QLineEdit()
        self.lport_input.setPlaceholderText("本地端口(可选)")
        self.lport_input.setMinimumWidth(200)
        layout.addWidget(self.lport_input, row, 1)

        layout.addWidget(QLabel("本地IP:"), row, 2)
        self.local_ip_input = QLineEdit()
        self.local_ip_input.setPlaceholderText("本地IP地址(可选)")
        self.local_ip_input.setMinimumWidth(200)
        layout.addWidget(self.local_ip_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("伪造源IP:"), row, 0)
        self.spoof_ip_input = QLineEdit()
        self.spoof_ip_input.setPlaceholderText("伪造的源IP地址(需要管理员权限)")
        self.spoof_ip_input.setText("20.50.1.10")
        self.spoof_ip_input.setMinimumWidth(200)
        layout.addWidget(self.spoof_ip_input, row, 1)
        
        # 添加提示标签
        spoof_tip = QLabel("注意: IP欺骗仅适用于UDP协议，需要管理员权限")
        spoof_tip.setStyleSheet("color: #FF5555; font-size: 10px;")
        layout.addWidget(spoof_tip, row, 2, 1, 2)
        
        row += 1
        layout.addWidget(QLabel("模板文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        file_layout = QHBoxLayout()
        
        self.template_input = QLineEdit()
        self.template_input.setPlaceholderText("SIP消息模板文件路径")
        self.template_input.setMinimumWidth(140)
        file_layout.addWidget(self.template_input)
        
        # 添加选择文件按钮
        file_btn = QPushButton("选择")
        file_btn.setFixedWidth(60)
        file_btn.clicked.connect(self.choose_template_file)
        file_layout.addWidget(file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(file_layout, row, 1)
        
        layout.addWidget(QLabel("协议:"), row, 2)
        self.proto_input = QComboBox()
        self.proto_input.addItems(["UDP", "TCP", "TLS"])
        self.proto_input.setCurrentText("UDP")
        self.proto_input.setMinimumWidth(200)
        layout.addWidget(self.proto_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("代理:"), row, 0)
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:5070")
        self.proxy_input.setMinimumWidth(200)
        layout.addWidget(self.proxy_input, row, 1)
        
        layout.addWidget(QLabel("方法:"), row, 2)
        self.method_input = QComboBox()
        self.method_input.addItems([
            "REGISTER", "SUBSCRIBE", "NOTIFY", "PUBLISH", "MESSAGE",
            "INVITE", "OPTIONS", "ACK", "CANCEL", "BYE", "PRACK",
            "INFO", "REFER", "UPDATE"
        ])
        self.method_input.setCurrentText("REGISTER")
        self.method_input.setMinimumWidth(200)
        layout.addWidget(self.method_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("域名:"), row, 0)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("SIP域名或IP (默认: 目标IP)")
        self.domain_input.setMinimumWidth(200)
        self.domain_input.setText("dra.ims.sdt")
        layout.addWidget(self.domain_input, row, 1)
        
        layout.addWidget(QLabel("Contact域名:"), row, 2)
        self.contact_domain_input = QLineEdit()
        self.contact_domain_input.setPlaceholderText("Contact头域名或IP")
        self.contact_domain_input.setMinimumWidth(200)
        layout.addWidget(self.contact_domain_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From名称:"), row, 0)
        self.from_name_input = QLineEdit()
        self.from_name_input.setPlaceholderText("例如: Bob")
        self.from_name_input.setMinimumWidth(200)
        layout.addWidget(self.from_name_input, row, 1)
        
        layout.addWidget(QLabel("From用户:"), row, 2)
        self.from_user_input = QLineEdit()
        self.from_user_input.setText("+861088889005")
        self.from_user_input.setPlaceholderText("From头的用户名")
        self.from_user_input.setMinimumWidth(200)
        layout.addWidget(self.from_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("From域名:"), row, 0)
        self.from_domain_input = QLineEdit()
        self.from_domain_input.setPlaceholderText("From头的域名")
        self.from_domain_input.setMinimumWidth(200)
        self.from_domain_input.setText("dra.ims.sdt")
        layout.addWidget(self.from_domain_input, row, 1)

        layout.addWidget(QLabel("From标签:"), row, 2)
        self.from_tag_input = QLineEdit()
        self.from_tag_input.setPlaceholderText("From头的标签值")
        self.from_tag_input.setMinimumWidth(200)
        layout.addWidget(self.from_tag_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To名称:"), row, 0)
        self.to_name_input = QLineEdit()
        self.to_name_input.setPlaceholderText("例如: Alice")
        self.to_name_input.setMinimumWidth(200)
        layout.addWidget(self.to_name_input, row, 1)
        
        layout.addWidget(QLabel("To用户:"), row, 2)
        self.to_user_input = QLineEdit()
        self.to_user_input.setText("+861088889005")
        self.to_user_input.setPlaceholderText("To头的用户名")
        self.to_user_input.setMinimumWidth(200)
        layout.addWidget(self.to_user_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("To域名:"), row, 0)
        self.to_domain_input = QLineEdit()
        self.to_domain_input.setPlaceholderText("To头的域名")
        self.to_domain_input.setMinimumWidth(200)
        self.to_domain_input.setText("dra.ims.sdt")
        layout.addWidget(self.to_domain_input, row, 1)

        layout.addWidget(QLabel("To标签:"), row, 2)
        self.to_tag_input = QLineEdit()
        self.to_tag_input.setPlaceholderText("To头的标签值")
        self.to_tag_input.setMinimumWidth(200)
        layout.addWidget(self.to_tag_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("认证用户:"), row, 0)
        self.auth_user_input = QLineEdit()
        self.auth_user_input.setPlaceholderText("认证用户名")
        self.auth_user_input.setMinimumWidth(200)
        self.auth_user_input.setText("+861088889005")
        layout.addWidget(self.auth_user_input, row, 1)
        
        layout.addWidget(QLabel("认证密码:"), row, 2)
        self.auth_pass_input = QLineEdit()
        self.auth_pass_input.setPlaceholderText("认证密码")
        self.auth_pass_input.setMinimumWidth(200)
        self.auth_pass_input.setText("123456")
        layout.addWidget(self.auth_pass_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("User-Agent:"), row, 0)
        self.ua_input = QLineEdit()
        self.ua_input.setText("pplsip")
        self.ua_input.setPlaceholderText("User-Agent头的值")
        self.ua_input.setMinimumWidth(200)
        layout.addWidget(self.ua_input, row, 1)

        layout.addWidget(QLabel("超时时间(秒):"), row, 2)
        self.timeout_input = QLineEdit()
        self.timeout_input.setText("5")
        self.timeout_input.setPlaceholderText("请求超时时间")
        self.timeout_input.setMinimumWidth(200)
        layout.addWidget(self.timeout_input, row, 3)

        row += 1
        layout.addWidget(QLabel("P-Preferred-Identity:"), row, 0)
        self.ppi_input = QLineEdit()
        self.ppi_input.setPlaceholderText("P-Preferred-Identity头的值")
        self.ppi_input.setMinimumWidth(200)
        layout.addWidget(self.ppi_input, row, 1)

        layout.addWidget(QLabel("P-Asserted-Identity:"), row, 2)
        self.pai_input = QLineEdit()
        self.pai_input.setPlaceholderText("P-Asserted-Identity头的值")
        self.pai_input.setMinimumWidth(200)
        layout.addWidget(self.pai_input, row, 3)

        row += 1
        layout.addWidget(QLabel("Branch:"), row, 0)
        self.branch_input = QLineEdit()
        self.branch_input.setPlaceholderText("Via头的branch参数")
        self.branch_input.setMinimumWidth(200)
        layout.addWidget(self.branch_input, row, 1)

        layout.addWidget(QLabel("Call-ID:"), row, 2)
        self.callid_input = QLineEdit()
        self.callid_input.setPlaceholderText("Call-ID头的值")
        self.callid_input.setMinimumWidth(200)
        layout.addWidget(self.callid_input, row, 3)

        row += 1
        layout.addWidget(QLabel("CSeq:"), row, 0)
        self.cseq_input = QLineEdit()
        self.cseq_input.setText("1")
        self.cseq_input.setPlaceholderText("CSeq头的序号值")
        self.cseq_input.setMinimumWidth(200)
        layout.addWidget(self.cseq_input, row, 1)

        layout.addWidget(QLabel("自定义头部:"), row, 2)
        self.header_input = QLineEdit()
        self.header_input.setPlaceholderText("自定义SIP头部")
        self.header_input.setMinimumWidth(200)
        layout.addWidget(self.header_input, row, 3)

        row += 1
        # SDP相关选项
        sdp_group = QGroupBox("SDP选项")
        sdp_layout = QHBoxLayout()
        
        self.sdp_check = QCheckBox("包含SDP")
        self.sdp_check.setChecked(False)
        sdp_layout.addWidget(self.sdp_check)
        
        self.sdes_check = QCheckBox("包含SDES")
        self.sdes_check.setChecked(False)
        sdp_layout.addWidget(self.sdes_check)
        
        sdp_group.setLayout(sdp_layout)
        layout.addWidget(sdp_group, row, 0, 1, 2)

        # 其他选项
        other_group = QGroupBox("其他选项")
        other_layout = QHBoxLayout()
        
        self.nocontact_check = QCheckBox("不包含Contact头")
        self.nocontact_check.setChecked(False)
        other_layout.addWidget(self.nocontact_check)
        
        self.verbose_check = QCheckBox("详细输出")
        self.verbose_check.setChecked(False)
        other_layout.addWidget(self.verbose_check)
        
        other_group.setLayout(other_layout)
        layout.addWidget(other_group, row, 2, 1, 2)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        output_layout = QHBoxLayout()
        
        self.output_input = QLineEdit()
        self.output_input.setPlaceholderText("输出文件路径")
        self.output_input.setMinimumWidth(140)
        output_layout.addWidget(self.output_input)
        
        # 添加选择文件按钮
        output_btn = QPushButton("选择")
        output_btn.setFixedWidth(60)
        output_btn.clicked.connect(self.choose_output_file)
        output_layout.addWidget(output_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_layout, row, 1, 1, 3)
        
        row += 1
        # 创建结果显示区域
        self.create_result_text(layout, row)
        
        row += 1
        # 创建按钮布局
        button_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("开始发送")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        
        layout.addLayout(button_layout, row, 0, 1, 4)
    
    def choose_template_file(self):
        """选择SIP消息模板文件"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "选择SIP消息模板文件",
            "",
            "所有文件 (*.*)"
        )
        if filename:
            self.template_input.setText(filename)
            
    def choose_output_file(self):
        """选择输出文件"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "选择输出文件",
            "",
            "所有文件 (*.*)"
        )
        if filename:
            self.output_input.setText(filename)
    
    def start_module(self):
        """启动SIP消息发送模块"""
        # 清空结果文本
        self.result_text.clear()
        
        # 创建模块实例
        from sippts.gui.uitools import UiTools
        self.module_instance = SipSend()
        
        # 设置参数
        UiTools.set_option_send(self.module_instance, "ip", self.ip_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "rport", self.port_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "lport", self.lport_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "local_ip", self.local_ip_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "proto", self.proto_input.currentText(), False, False)
        UiTools.set_option_send(self.module_instance, "proxy", self.proxy_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "method", self.method_input.currentText(), False, False)
        UiTools.set_option_send(self.module_instance, "domain", self.domain_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "contact_domain", self.contact_domain_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "from_user", self.from_user_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "from_name", self.from_name_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "from_domain", self.from_domain_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "from_tag", self.from_tag_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "to_user", self.to_user_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "to_name", self.to_name_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "to_domain", self.to_domain_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "to_tag", self.to_tag_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "ua", self.ua_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "user", self.auth_user_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "pass", self.auth_pass_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "template", self.template_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "output_file", self.output_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "timeout", self.timeout_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "ppi", self.ppi_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "pai", self.pai_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "branch", self.branch_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "callid", self.callid_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "cseq", self.cseq_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "header", self.header_input.text(), False, False)
        UiTools.set_option_send(self.module_instance, "spoof_ip", self.spoof_ip_input.text(), False, False)
        
        # 设置SDP选项
        if self.sdp_check.isChecked():
            UiTools.set_option_send(self.module_instance, "sdp", "1", False, False)
        if self.sdes_check.isChecked():
            UiTools.set_option_send(self.module_instance, "sdes", "1", False, False)
            
        # 设置其他选项
        if self.nocontact_check.isChecked():
            self.module_instance.nocontact = 1
        if self.verbose_check.isChecked():
            UiTools.set_option_send(self.module_instance, "verbose", "1", False, False)
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        ) 