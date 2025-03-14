from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, 
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.gui.common.file_utils import choose_file
from sippts.rtpbleedinject import RTPBleedInject

class RTPBleedInjectTab(BaseTab):
    """RTP注入模块标签页"""
    
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
        
        row = 0
        
        # 目标IP
        layout.addWidget(QLabel("目标IP:"), row, 0)
        self.target_ip_input = QLineEdit()
        self.target_ip_input.setText("192.168.100.99")
        self.target_ip_input.setPlaceholderText("例如: 192.168.1.100")
        self.target_ip_input.setMinimumWidth(300)
        layout.addWidget(self.target_ip_input, row, 1)
        
        # 目标端口
        layout.addWidget(QLabel("目标端口:"), row, 2)
        self.target_port_input = QLineEdit()
        self.target_port_input.setText("10042")
        self.target_port_input.setPlaceholderText("例如: 5004")
        self.target_port_input.setMinimumWidth(300)
        layout.addWidget(self.target_port_input, row, 3)
        
        row += 1
        # 负载类型
        layout.addWidget(QLabel("负载类型:"), row, 0)
        self.payload_input = QComboBox()
        # 添加所有支持的负载类型
        self.payload_input.addItems([
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
        self.payload_input.setCurrentText("0 PCMU (audio)")
        self.payload_input.setMinimumWidth(300)
        layout.addWidget(self.payload_input, row, 1)
        
        # WAV文件
        layout.addWidget(QLabel("WAV文件:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        wav_file_layout = QHBoxLayout()
        
        self.wav_file_input = QLineEdit()
        self.wav_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/test.wav")
        self.wav_file_input.setPlaceholderText("要注入的WAV音频文件路径")
        self.wav_file_input.setMinimumWidth(240)
        wav_file_layout.addWidget(self.wav_file_input)
        
        # 添加选择文件按钮
        wav_file_btn = QPushButton("选择")
        wav_file_btn.setFixedWidth(60)
        wav_file_btn.clicked.connect(self.choose_wav_file)
        wav_file_layout.addWidget(wav_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(wav_file_layout, row, 3)
        
        row += 1
        # 循环发送
        layout.addWidget(QLabel("循环发送:"), row, 0)
        self.loop_input = QComboBox()
        self.loop_input.addItems(["否", "是"])
        self.loop_input.setCurrentText("否")
        self.loop_input.setMinimumWidth(300)
        layout.addWidget(self.loop_input, row, 1)
        
        # 强制注入
        layout.addWidget(QLabel("强制注入:"), row, 2)
        self.force_input = QComboBox()
        self.force_input.addItems(["否", "是"])
        self.force_input.setCurrentText("否")
        self.force_input.setMinimumWidth(300)
        layout.addWidget(self.force_input, row, 3)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.start_btn = QPushButton("开始注入")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = QPushButton("停止注入")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.create_result_text(layout, row)
    
    def choose_wav_file(self):
        """选择WAV音频文件"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择WAV音频文件",
            "",
            "WAV文件 (*.wav);;所有文件 (*.*)"
        )
        if file_name:
            self.wav_file_input.setText(file_name)
    
    def start_module(self):
        """启动RTP注入模块"""
        # 获取参数
        target_ip = self.target_ip_input.text().strip()
        target_port = self.target_port_input.text().strip()
        payload = self.payload_input.currentText()
        wav_file = self.wav_file_input.text().strip()
        loop = self.loop_input.currentText() == "是"
        force = self.force_input.currentText() == "是"
        
        # 参数验证
        if not target_ip:
            self.append_log("错误: 目标IP不能为空")
            return
        
        if not target_port:
            self.append_log("错误: 目标端口不能为空")
            return
        
        if not wav_file:
            self.append_log("错误: 请选择WAV音频文件")
            return
        
        # 创建模块实例
        from sippts.gui.uitools import UiTools
        self.module_instance = RTPBleedInject()
        
        # 设置参数
        UiTools.set_option_rtpbleedinject(self.module_instance, "ip", target_ip, False, True)
        UiTools.set_option_rtpbleedinject(self.module_instance, "port", target_port, False, True)
        UiTools.set_option_rtpbleedinject(self.module_instance, "payload", payload, False, True)
        UiTools.set_option_rtpbleedinject(self.module_instance, "file", wav_file, False, True)
        UiTools.set_option_rtpbleedinject(self.module_instance, "loop", self.loop_input.currentText(), False, True)
        UiTools.set_option_rtpbleedinject(self.module_instance, "force", self.force_input.currentText(), False, True)
        
        # 清空结果文本
        self.result_text.clear()
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        ) 