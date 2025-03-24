from PyQt5.QtWidgets import QWidget, QTextEdit, QLineEdit, QComboBox
from PyQt5.QtCore import pyqtSignal
from sippts.gui.common.config_manager import ConfigManager

class BaseTab(QWidget):
    """所有功能模块标签页的基类"""
    
    # 信号定义
    module_started = pyqtSignal()  # 模块开始运行时发出
    module_finished = pyqtSignal()  # 模块完成运行时发出
    
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.config_manager = ConfigManager()
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
    
    def save_input_values(self, save_immediately=False):
        """保存输入框的值到配置文件
        
        Args:
            save_immediately: 是否立即保存到文件，默认为False
        """
        config_data = {}
        
        # 遍历标签页中的所有QLineEdit控件
        for widget in self.findChildren(QLineEdit):
            if hasattr(widget, 'objectName') and widget.objectName():
                config_data[widget.objectName()] = widget.text()
        
        # 遍历标签页中的所有QComboBox控件
        for widget in self.findChildren(QComboBox):
            if hasattr(widget, 'objectName') and widget.objectName():
                config_data[widget.objectName()] = widget.currentText()
        
        # 保存配置
        tab_name = self.__class__.__name__
        self.config_manager.save_tab_config(tab_name, config_data, save_immediately)
    
    def load_input_values(self):
        """从配置文件加载输入框的值"""
        tab_name = self.__class__.__name__
        config_data = self.config_manager.get_tab_config(tab_name)
        
        if not config_data:
            return
        
        # 加载QLineEdit控件的值
        for widget in self.findChildren(QLineEdit):
            if hasattr(widget, 'objectName') and widget.objectName() and widget.objectName() in config_data:
                widget.setText(config_data[widget.objectName()])
        
        # 加载QComboBox控件的值
        for widget in self.findChildren(QComboBox):
            if hasattr(widget, 'objectName') and widget.objectName() and widget.objectName() in config_data:
                index = widget.findText(config_data[widget.objectName()])
                if index >= 0:
                    widget.setCurrentIndex(index) 