import logging
from PyQt5.QtWidgets import QTextEdit

class TextEditHandler(logging.Handler):
    """将日志输出到QTextEdit控件的处理器"""
    
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        
    def emit(self, record):
        msg = self.format(record)
        self.text_widget.append(msg)
        # 滚动到底部
        cursor = self.text_widget.textCursor()
        cursor.movePosition(cursor.End)
        self.text_widget.setTextCursor(cursor)

def setup_logging(text_widget, logger_name='sippts'):
    """设置日志系统，将日志输出到指定的文本控件"""
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    
    # 清除现有的处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 添加文本控件处理器
    handler = TextEditHandler(text_widget)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger 