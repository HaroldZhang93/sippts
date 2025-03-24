from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, 
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.rtpbleed import RTPBleed, RTP_PAYLOAD_TYPES

class RTPBleedTab(BaseTab):
    """RTP Bleed检测模块标签页"""
    
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
        self.ip_input.setText("192.168.4.200")
        self.ip_input.setPlaceholderText("目标主机IP地址")
        self.ip_input.setMinimumWidth(300)
        layout.addWidget(self.ip_input, row, 1)
        
        layout.addWidget(QLabel("起始端口:"), row, 2)
        self.start_port_input = QLineEdit()
        self.start_port_input.setObjectName("start_port_input")
        self.start_port_input.setText("10042")
        self.start_port_input.setPlaceholderText("起始RTP端口")
        self.start_port_input.setMinimumWidth(300)
        layout.addWidget(self.start_port_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("结束端口:"), row, 0)
        self.end_port_input = QLineEdit()
        self.end_port_input.setObjectName("end_port_input")
        self.end_port_input.setText("10043")
        self.end_port_input.setPlaceholderText("结束RTP端口")
        self.end_port_input.setMinimumWidth(300)
        layout.addWidget(self.end_port_input, row, 1)
        
        layout.addWidget(QLabel("循环次数:"), row, 2)
        self.loops_input = QLineEdit()
        self.loops_input.setObjectName("loops_input")
        self.loops_input.setText("200")
        self.loops_input.setPlaceholderText("每个端口的尝试次数")
        self.loops_input.setMinimumWidth(300)
        layout.addWidget(self.loops_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("RTP负载类型:"), row, 0)
        self.payload_input = QComboBox()
        self.payload_input.setObjectName("payload_input")
        self.payload_input.addItems(list(RTP_PAYLOAD_TYPES.keys()))
        self.payload_input.setCurrentText("0 PCMU (audio)")
        self.payload_input.setMinimumWidth(300)
        layout.addWidget(self.payload_input, row, 1)
        
        layout.addWidget(QLabel("延迟(微秒):"), row, 2)
        self.delay_input = QLineEdit()
        self.delay_input.setObjectName("delay_input")
        self.delay_input.setText("10")
        self.delay_input.setPlaceholderText("尝试之间的延迟(微秒)")
        self.delay_input.setMinimumWidth(300)
        layout.addWidget(self.delay_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("输出文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        output_file_layout = QHBoxLayout()
        
        self.output_file_input = QLineEdit()
        self.output_file_input.setObjectName("output_file_input")
        self.output_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/rtpbleed.txt")
        self.output_file_input.setPlaceholderText("结果保存文件路径")
        self.output_file_input.setMinimumWidth(240)
        output_file_layout.addWidget(self.output_file_input)
        
        # 添加选择文件按钮
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)
        output_file_btn.clicked.connect(self.choose_output_file)
        output_file_layout.addWidget(output_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_file_layout, row, 1)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.start_btn = QPushButton("开始检测")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = QPushButton("停止检测")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.create_result_text(layout, row)
    
    def choose_output_file(self):
        """选择输出文件"""
        file_name, _ = QFileDialog.getSaveFileName(
            self,
            "选择输出文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            # 如果用户没有输入扩展名，自动添加.txt
            if not file_name.endswith('.txt'):
                file_name += '.txt'
            self.output_file_input.setText(file_name)
    
    def start_module(self):
        """启动RTP Bleed检测模块"""
        # 保存当前输入值
        self.save_input_values()
        
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