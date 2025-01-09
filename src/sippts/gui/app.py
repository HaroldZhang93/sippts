import sys
from PyQt6.QtWidgets import QApplication
from sippts.gui.main_window import MainWindow

def run_gui():
    """启动GUI应用"""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec()) 
    
if __name__ == "__main__":
    run_gui()
