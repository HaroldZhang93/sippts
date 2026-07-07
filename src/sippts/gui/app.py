import sys
from PyQt5.QtWidgets import QApplication
from sippts.gui.main_window_new import MainWindow
from sippts.gui import theme as T

def run_gui():
    """启动GUI应用"""
    app = QApplication(sys.argv)
    T.apply_theme(app)  # 应用暗蓝 HUD 全局主题
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
    
if __name__ == "__main__":
    run_gui()
