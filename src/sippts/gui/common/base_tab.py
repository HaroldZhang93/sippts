from PyQt5.QtWidgets import QWidget, QTextEdit
from PyQt5.QtCore import pyqtSignal

class BaseTab(QWidget):
    """所有功能模块标签页的基类"""
    
    # 信号定义
    module_started = pyqtSignal()  # 模块开始运行时发出
    module_finished = pyqtSignal()  # 模块完成运行时发出
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.module_instance = None
        self.result_text = None  # 结果文本控件
        self.start_btn = None  # 开始按钮
        self.stop_btn = None  # 停止按钮
        
    def setup_ui(self):
        """设置UI界面，子类必须实现此方法"""
        raise NotImplementedError("子类必须实现setup_ui方法")
    
    def start_module(self):
        """启动模块，子类必须实现此方法"""
        raise NotImplementedError("子类必须实现start_module方法")
    
    def create_result_text(self, layout, row, col_span=4):
        """创建结果文本框"""
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setFontFamily("Courier New")
        self.result_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                font-size: 20px;
            }
        """)
        layout.addWidget(self.result_text, row, 0, 1, col_span)
        
        # 设置行的拉伸因子
        layout.setRowStretch(row, 1)
        
        return self.result_text
    
    def on_module_finished(self):
        """模块执行完成后的回调"""
        if self.start_btn:
            self.start_btn.setEnabled(True)
        if self.stop_btn:
            self.stop_btn.setEnabled(False)
        self.module_finished.emit()
    
    def on_module_started(self):
        """模块开始执行时的回调"""
        if self.start_btn:
            self.start_btn.setEnabled(False)
        if self.stop_btn:
            self.stop_btn.setEnabled(True)
        self.module_started.emit()
    
    def on_module_stopped(self):
        """模块被停止时的回调"""
        if self.start_btn:
            self.start_btn.setEnabled(True)
        if self.stop_btn:
            self.stop_btn.setEnabled(False)
        
    def append_log(self, text):
        """向结果文本控件添加日志"""
        if self.result_text:
            self.result_text.append(text)
            # 滚动到底部
            cursor = self.result_text.textCursor()
            cursor.movePosition(cursor.End)
            self.result_text.setTextCursor(cursor) 