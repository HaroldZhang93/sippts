from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, 
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.rtpbleed import RTPBleed

class RTPBleedTab(BaseTab):
    """RTP Bleed测试模块标签页"""
    
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
        self.ip_input.setText("192.168.4.200")
        self.ip_input.setPlaceholderText("目标主机IP地址")
        self.ip_input.setMinimumWidth(300)
        layout.addWidget(self.ip_input, row, 1)
        
        layout.addWidget(QLabel("起始端口:"), row, 2)
        self.start_port_input = QLineEdit()
        self.start_port_input.setText("10042")
        self.start_port_input.setPlaceholderText("RTP端口范围起始值")
        self.start_port_input.setMinimumWidth(300)
        layout.addWidget(self.start_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("结束端口:"), row, 0)
        self.end_port_input = QLineEdit()
        self.end_port_input.setText("10043")
        self.end_port_input.setPlaceholderText("RTP端口范围结束值")
        self.end_port_input.setMinimumWidth(300)
        layout.addWidget(self.end_port_input, row, 1)
        
        layout.addWidget(QLabel("尝试次数:"), row, 2)
        self.loops_input = QLineEdit()
        self.loops_input.setText("200")
        self.loops_input.setPlaceholderText("每个端口的尝试次数")
        self.loops_input.setMinimumWidth(300)
        layout.addWidget(self.loops_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("负载类型:"), row, 0)
        self.payload_input = QComboBox()
        self.payload_input.addItems([
            "0 PCMU (audio)", "3 GSM (audio)", "4 G723 (audio)", "5 DVI4 (audio)",
            "6 DVI4 (audio)", "7 LPC (audio)", "8 PCMA (audio)", "9 G722 (audio)",
            "10 L16 (audio)", "11 L16 (audio)", "12 QCELP (audio)", "13 CN (audio)",
            "14 MPA (audio)", "15 G728 (audio)", "16 DVI4 (audio)", "17 DVI4 (audio)",
            "18 G729 (audio)", "25 CELLB (video)", "26 JPEG (video)", "28 nv (video)",
            "31 H261 (video)", "32 MPV (video)", "33 MP2T (audio/video)", "34 H263 (video)"
        ])
        self.payload_input.setCurrentText("0 PCMU (audio)")
        self.payload_input.setMinimumWidth(300)
        layout.addWidget(self.payload_input, row, 1)
        
        layout.addWidget(QLabel("延迟时间:"), row, 2)
        self.delay_input = QLineEdit()
        self.delay_input.setText("10")
        self.delay_input.setPlaceholderText("尝试间隔(微秒)")
        self.delay_input.setMinimumWidth(300)
        layout.addWidget(self.delay_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        output_file_layout = QHBoxLayout()
        self.output_file_input = QLineEdit()
        self.output_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/rtpbleed.txt")
        self.output_file_input.setPlaceholderText("结果保存文件路径")
        self.output_file_input.setMinimumWidth(240)
        output_file_layout.addWidget(self.output_file_input)
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)
        output_file_btn.clicked.connect(self.choose_output_file)
        output_file_layout.addWidget(output_file_btn)
        layout.addLayout(output_file_layout, row, 1, 1, 3)
        
        row += 1
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始测试")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        self.stop_btn = QPushButton("停止测试")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        row += 1
        self.create_result_text(layout, row)
    
    def choose_output_file(self):
        """选择输出文件"""
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
            self.output_file_input.setText(file_name)
    
    def start_module(self):
        """启动RTP Bleed测试模块"""
        # 清空结果文本
        self.result_text.clear()
        
        # 创建模块实例
        from sippts.gui.uitools import UiTools
        self.module_instance = RTPBleed()
        
        # 设置参数
        UiTools.set_option_rtpbleed(self.module_instance, "ip", self.ip_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.module_instance, "start", self.start_port_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.module_instance, "end", self.end_port_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.module_instance, "payload", self.payload_input.currentText(), False, True)
        UiTools.set_option_rtpbleed(self.module_instance, "loops", self.loops_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.module_instance, "delay", self.delay_input.text(), False, True)
        UiTools.set_option_rtpbleed(self.module_instance, "output_file", self.output_file_input.text(), False, True)
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        ) 