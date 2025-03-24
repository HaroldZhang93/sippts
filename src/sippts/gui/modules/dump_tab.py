from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, 
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.sipdump import SipDump

class DumpTab(BaseTab):
    """SIP数据包分析模块标签页"""
    
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
        layout.addWidget(QLabel("输入文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        input_file_layout = QHBoxLayout()
        
        self.file_input = QLineEdit()
        self.file_input.setObjectName("file_input")
        self.file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/test.pcap")
        self.file_input.setPlaceholderText("要分析的PCAP文件路径")
        self.file_input.setMinimumWidth(300)  # 设置最小宽度
        input_file_layout.addWidget(self.file_input)
        
        # 添加选择文件按钮
        input_file_btn = QPushButton("选择")
        input_file_btn.setFixedWidth(60)  # 固定按钮宽度
        input_file_btn.clicked.connect(self.choose_input_file)
        input_file_layout.addWidget(input_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(input_file_layout, row, 1)
        
        layout.addWidget(QLabel("输出文件:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        output_file_layout = QHBoxLayout()
        
        self.output_file_input = QLineEdit()
        self.output_file_input.setObjectName("output_file_input")
        self.output_file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/sipdump.txt")
        self.output_file_input.setPlaceholderText("分析结果保存路径")
        self.output_file_input.setMinimumWidth(300)  # 设置最小宽度
        output_file_layout.addWidget(self.output_file_input)
        
        # 添加选择文件按钮
        output_file_btn = QPushButton("选择")
        output_file_btn.setFixedWidth(60)  # 固定按钮宽度
        output_file_btn.clicked.connect(self.choose_output_file)
        output_file_layout.addWidget(output_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(output_file_layout, row, 3)
        
        # 添加按钮布局
        row += 1
        button_layout = QHBoxLayout()
        
        # 开始按钮
        self.start_btn = QPushButton("开始分析")
        self.start_btn.clicked.connect(self.start_module)
        button_layout.addWidget(self.start_btn)
        
        # 停止按钮
        self.stop_btn = QPushButton("停止分析")
        self.stop_btn.clicked.connect(self.main_window.stop_module)
        self.stop_btn.setEnabled(False)  # 初始状态禁用
        button_layout.addWidget(self.stop_btn)
        
        # 将按钮布局添加到主布局
        layout.addLayout(button_layout, row, 0, 1, 4)
        
        # 使用QTextEdit显示结果
        row += 1
        self.create_result_text(layout, row)
    
    def choose_input_file(self):
        """选择PCAP文件"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择PCAP文件",
            "",
            "PCAP文件 (*.pcap *.pcapng);;所有文件 (*.*)"
        )
        if file_name:
            self.file_input.setText(file_name)
    
    def choose_output_file(self):
        """选择输出文件"""
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
            self.output_file_input.setText(file_name)
    
    def start_module(self):
        """启动SIP数据包分析模块"""
        # 保存当前输入值
        self.save_input_values()
        
        # 清空结果文本
        self.result_text.clear()
        
        # 创建模块实例
        from sippts.gui.uitools import UiTools
        self.module_instance = SipDump()
        
        # 设置参数
        UiTools.set_option_dump(self.module_instance, "file", self.file_input.text(), False, True)
        UiTools.set_option_dump(self.module_instance, "output_file", self.output_file_input.text(), False, True)
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        ) 