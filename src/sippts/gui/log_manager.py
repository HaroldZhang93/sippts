from PyQt6.QtCore import QObject, pyqtSignal

class LogManager(QObject):
    log_signal = pyqtSignal(str)  # 日志信号
    
    def __init__(self):
        super().__init__()
        
    def write(self, text):
        """发送日志信号"""
        self.log_signal.emit(str(text))
    
    def flush(self):
        """实现flush方法以兼容sys.stdout"""
        pass 