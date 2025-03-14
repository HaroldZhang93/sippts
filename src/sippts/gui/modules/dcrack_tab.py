from PyQt5.QtWidgets import (
    QLabel, QLineEdit, QComboBox, QPushButton, 
    QHBoxLayout, QVBoxLayout, QGridLayout, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt

from sippts.gui.common.base_tab import BaseTab
from sippts.sipdigestcrack import SipDigestCrack

class DCrackTab(BaseTab):
    """SIP离线密码破解模块标签页"""
    
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
        layout.addWidget(QLabel("输入文件:"), row, 0)
        
        # 创建水平布局来放置输入框和按钮
        input_file_layout = QHBoxLayout()
        
        self.file_input = QLineEdit()
        self.file_input.setText("C:/workspace/IMS/Test Tools/sippts/sippts/sipdump.txt")
        self.file_input.setPlaceholderText("包含SIP认证信息的文件路径")
        self.file_input.setMinimumWidth(240)
        input_file_layout.addWidget(self.file_input)
        
        # 添加选择文件按钮
        input_file_btn = QPushButton("选择")
        input_file_btn.setFixedWidth(60)
        input_file_btn.clicked.connect(self.choose_input_file)
        input_file_layout.addWidget(input_file_btn)
        
        # 将水平布局添加到网格布局中
        layout.addLayout(input_file_layout, row, 1)
        
        layout.addWidget(QLabel("密码字典:"), row, 2)
        
        # 创建水平布局来放置输入框和按钮
        wordlist_layout = QHBoxLayout()
        
        self.wordlist_input = QLineEdit()
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
        layout.addLayout(wordlist_layout, row, 3)
        
        row += 1
        layout.addWidget(QLabel("用户名:"), row, 0)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("指定要破解的用户名(可选)")
        self.username_input.setMinimumWidth(300)
        layout.addWidget(self.username_input, row, 1)
        
        layout.addWidget(QLabel("暴力破解:"), row, 2)
        self.bruteforce_input = QComboBox()
        self.bruteforce_input.addItems(["0", "1"])
        self.bruteforce_input.setCurrentText("0")
        self.bruteforce_input.setMinimumWidth(300)
        layout.addWidget(self.bruteforce_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("字符集:"), row, 0)
        self.charset_input = QComboBox()
        self.charset_input.addItems(["digits", "hexdigits", "octdigits", "punctuation", "printable", "whitespace", "ascii_letters", "ascii_lowercase", "ascii_uppercase"])
        self.charset_input.setCurrentText("digits")
        self.charset_input.setMinimumWidth(300)
        layout.addWidget(self.charset_input, row, 1)
        
        layout.addWidget(QLabel("最小长度:"), row, 2)
        self.min_input = QLineEdit()
        self.min_input.setText("6")
        self.min_input.setPlaceholderText("暴力破解的最小密码长度")
        self.min_input.setMinimumWidth(300)
        layout.addWidget(self.min_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("最大长度:"), row, 0)
        self.max_input = QLineEdit()
        self.max_input.setText("6")
        self.max_input.setPlaceholderText("暴力破解的最大密码长度")
        self.max_input.setMinimumWidth(300)
        layout.addWidget(self.max_input, row, 1)
        
        layout.addWidget(QLabel("线程数:"), row, 2)
        self.threads_input = QLineEdit()
        self.threads_input.setText("10")
        self.threads_input.setPlaceholderText("破解使用的线程数")
        self.threads_input.setMinimumWidth(300)
        layout.addWidget(self.threads_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("密码前缀:"), row, 0)
        self.prefix_input = QLineEdit()
        self.prefix_input.setPlaceholderText("密码前缀(可选)")
        self.prefix_input.setMinimumWidth(300)
        layout.addWidget(self.prefix_input, row, 1)
        
        layout.addWidget(QLabel("密码后缀:"), row, 2)
        self.suffix_input = QLineEdit()
        self.suffix_input.setPlaceholderText("密码后缀(可选)")
        self.suffix_input.setMinimumWidth(300)
        layout.addWidget(self.suffix_input, row, 3)
        
        row += 1
        layout.addWidget(QLabel("详细程度:"), row, 0)
        self.verbose_input = QComboBox()
        self.verbose_input.addItems(["0", "1"])
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
    
    def choose_input_file(self):
        """选择输入文件"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "选择SIP认证信息文件",
            "",
            "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_name:
            self.file_input.setText(file_name)
    
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
        """启动SIP离线密码破解模块"""
        # 清空结果文本
        self.result_text.clear()
        
        # 创建模块实例
        from sippts.gui.uitools import UiTools
        self.module_instance = SipDigestCrack()
        
        # 设置参数
        UiTools.set_option_dcrack(self.module_instance, "file", self.file_input.text(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "wordlist", self.wordlist_input.text(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "username", self.username_input.text(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "bruteforce", self.bruteforce_input.currentText(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "charset", self.charset_input.currentText(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "min", self.min_input.text(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "max", self.max_input.text(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "threads", self.threads_input.text(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "prefix", self.prefix_input.text(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "suffix", self.suffix_input.text(), False, True)
        UiTools.set_option_dcrack(self.module_instance, "verbose", self.verbose_input.currentText(), False, True)
        
        # 更新UI状态
        self.on_module_started()
        
        # 启动模块
        self.main_window.run_module(
            self.module_instance, 
            self.on_module_finished
        ) 