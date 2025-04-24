import sys
import re
import traceback
import os
import warnings
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QMessageBox
from PyQt5.QtCore import QThread, pyqtSignal, QObject, QEvent
from PyQt5.QtGui import QTextCharFormat, QColor, QTextCursor, QIcon

# 忽略PyQt5相关的废弃警告
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 导入模块标签页
from sippts.gui.modules.rtphijack_tab import RTPHijackTab
from sippts.gui.modules.rtpbleedinject_tab import RTPBleedInjectTab
from sippts.gui.modules.rtpbleed_tab import RTPBleedTab
from sippts.gui.modules.scan_tab import ScanTab
from sippts.gui.modules.exten_tab import ExtenTab
from sippts.gui.modules.crack_tab import CrackTab
from sippts.gui.modules.dcrack_tab import DCrackTab
from sippts.gui.modules.dump_tab import DumpTab
from sippts.gui.modules.flood_tab import FloodTab
from sippts.gui.modules.leak_tab import LeakTab
from sippts.gui.modules.send_tab import SendTab
from sippts.gui.modules.sniff_tab import SniffTab
from sippts.gui.modules.arpspoof_tab import ArpSpoofTab

class LogManager(QObject):
    """日志管理器，用于重定向标准输出到UI"""
    log_signal = pyqtSignal(str)  # 日志信号
    
    def __init__(self):
        super().__init__()
        
    def write(self, text):
        """发送日志信号"""
        self.log_signal.emit(str(text))
    
    def flush(self):
        """实现flush方法以兼容sys.stdout"""
        pass

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIPPTS - SIP Penetration Testing Tools")
        self.setMinimumSize(800, 600)
        self.setGeometry(100, 100, 1920, 1080)
        
        # 创建主标签页控件
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # 当前活动的模块工作线程
        self.current_worker = None
        
        # 创建日志管理器
        self.log_manager = LogManager()
        
        # 初始化颜色映射
        self.init_color_map()
        
        # 初始化各个功能标签页
        self.init_tabs()
        
    def init_color_map(self):
        """初始化ANSI颜色代码到Qt颜色的映射"""
        self.color_map = {
            # 基本ANSI颜色代码
            '\033[0m': QTextCharFormat(),  # 重置
            '\033[30m': self.create_format(QColor("#000000")),  # 黑色
            '\033[31m': self.create_format(QColor("#FF0000")),  # 红色
            '\033[32m': self.create_format(QColor("#00FF00")),  # 绿色
            '\033[33m': self.create_format(QColor("#FFFF00")),  # 黄色
            '\033[34m': self.create_format(QColor("#0000FF")),  # 蓝色
            '\033[35m': self.create_format(QColor("#FF00FF")),  # 紫色
            '\033[36m': self.create_format(QColor("#00FFFF")),  # 青色
            '\033[37m': self.create_format(QColor("#FFFFFF")),  # 白色
            
            # 亮色ANSI颜色代码
            '\033[1;30m': self.create_format(QColor("#808080")),  # 亮黑色
            '\033[1;31m': self.create_format(QColor("#FF5555")),  # 亮红色
            '\033[1;32m': self.create_format(QColor("#55FF55")),  # 亮绿色
            '\033[1;33m': self.create_format(QColor("#FFFF55")),  # 亮黄色
            '\033[1;34m': self.create_format(QColor("#5555FF")),  # 亮蓝色
            '\033[1;35m': self.create_format(QColor("#FF55FF")),  # 亮紫色
            '\033[1;36m': self.create_format(QColor("#55FFFF")),  # 亮青色
            '\033[1;37m': self.create_format(QColor("#FFFFFF")),  # 亮白色
            
            # sippts.lib.color模块中定义的颜色代码
            '\033[1;31;20m': self.create_format(QColor("#FF5555")),  # BRED
            '\033[0;31;20m': self.create_format(QColor("#FF0000")),  # RED
            '\033[1;30;41m': self.create_format(QColor("#000000"), QColor("#FF0000")),  # BRED_BLACK
            '\033[0;30;41m': self.create_format(QColor("#000000"), QColor("#FF0000")),  # RED_BLACK
            '\033[1;32;20m': self.create_format(QColor("#55FF55")),  # BGREEN
            '\033[0;32;20m': self.create_format(QColor("#00FF00")),  # GREEN
            '\033[1;30;42m': self.create_format(QColor("#000000"), QColor("#00FF00")),  # BGREEN_BLACK
            '\033[0;30;42m': self.create_format(QColor("#000000"), QColor("#00FF00")),  # GREEN_BLACK
            '\033[1;33;20m': self.create_format(QColor("#FFFF55")),  # BYELLOW
            '\033[0;33;20m': self.create_format(QColor("#FFFF00")),  # YELLOW
            '\033[1;34;20m': self.create_format(QColor("#5555FF")),  # BBLUE
            '\033[0;34;20m': self.create_format(QColor("#0000FF")),  # BLUE
            '\033[1;35;20m': self.create_format(QColor("#FF55FF")),  # BMAGENTA
            '\033[0;35;20m': self.create_format(QColor("#FF00FF")),  # MAGENTA
            '\033[1;36;20m': self.create_format(QColor("#55FFFF")),  # BCYAN
            '\033[0;36;20m': self.create_format(QColor("#00FFFF")),  # CYAN
            '\033[1;37;20m': self.create_format(QColor("#FFFFFF")),  # BWHITE
            '\033[0;37;20m': self.create_format(QColor("#FFFFFF")),  # WHITE
        }
    
    def create_format(self, foreground_color, background_color=None):
        """创建带有指定颜色的文本格式"""
        fmt = QTextCharFormat()
        fmt.setForeground(foreground_color)
        if background_color:
            fmt.setBackground(background_color)
        return fmt
        
    def init_tabs(self):
        """初始化所有功能标签页"""
        # 创建并添加各个功能标签页
        
        # SIP扫描模块
        self.scan_tab = ScanTab(self)
        self.tabs.addTab(self.scan_tab, "SIP扫描")
        
        # SIP分机枚举模块
        self.exten_tab = ExtenTab(self)
        self.tabs.addTab(self.exten_tab, "分机枚举")
        
        # SIP密码破解模块
        self.crack_tab = CrackTab(self)
        self.tabs.addTab(self.crack_tab, "密码破解")
        
        # SIP数据包分析模块
        self.dump_tab = DumpTab(self)
        self.tabs.addTab(self.dump_tab, "数据分析")
        
        # SIP洪水攻击模块
        self.flood_tab = FloodTab(self)
        self.tabs.addTab(self.flood_tab, "压力测试")
        
        # SIP Digest Leak测试模块
        self.leak_tab = LeakTab(self)
        self.tabs.addTab(self.leak_tab, "Digest泄露")
        
        # SIP离线密码破解模块
        self.dcrack_tab = DCrackTab(self)
        self.tabs.addTab(self.dcrack_tab, "离线破解")
        
        # SIP消息发送模块
        self.send_tab = SendTab(self)
        self.tabs.addTab(self.send_tab, "消息伪造")
        
        # SIP嗅探模块
        self.sniff_tab = SniffTab(self)
        self.tabs.addTab(self.sniff_tab, "SIP嗅探")
        
        # RTP Bleed测试模块
        self.rtpbleed_tab = RTPBleedTab(self)
        self.tabs.addTab(self.rtpbleed_tab, "RTP Bleed")
        
        # RTP注入模块
        self.rtpbleedinject_tab = RTPBleedInjectTab(self)
        self.tabs.addTab(self.rtpbleedinject_tab, "RTP注入")
        
        # RTP劫持模块
        self.rtphijack_tab = RTPHijackTab(self)
        self.tabs.addTab(self.rtphijack_tab, "RTP劫持")
        
        # ARP欺骗模块
        self.arpspoof_tab = ArpSpoofTab(self)
        self.tabs.addTab(self.arpspoof_tab, "ARP欺骗")
        
        # 其他模块将在这里添加
        # self.exten_tab = ExtenTab(self)
        # self.tabs.addTab(self.exten_tab, "分机枚举")
        # 
        # 等等...
    
    def setup_logging(self, text_widget):
        """设置日志输出到指定的文本框"""
        text_widget.clear()
        
        # 先断开之前的连接
        if hasattr(self.log_manager, 'log_signal'):
            try:
                self.log_manager.log_signal.disconnect()
            except:
                pass
        # 建立新的连接
        self.log_manager.log_signal.connect(lambda text: self.append_log(text_widget, text))
    
    def append_log(self, text_widget, text):
        """添加日志到文本框""" 
        cursor = text_widget.textCursor()
        
        # 分割ANSI转义序列
        parts = re.split(r'(\x1B\[[0-9;]*m)', text)
        
        current_format = QTextCharFormat()
        current_format.setForeground(QColor("#FFFFFF"))  # 默认白色
        
        for part in parts:
            if part.startswith('\033['):
                # 这是一个颜色代码
                if part in self.color_map:
                    current_format = self.color_map[part]
                else:
                    # 如果找不到精确匹配，尝试找到最接近的颜色代码
                    for code in self.color_map:
                        if part.startswith(code[:5]):  # 匹配前5个字符
                            current_format = self.color_map[code]
                            break
            else:
                # 这是文本内容
                cursor.insertText(part, current_format)
        
        # 滚动到底部
        text_widget.setTextCursor(cursor)
        text_widget.ensureCursorVisible()
    
    def stop_module(self):
        """停止当前运行的模块"""
        if self.current_worker and self.current_worker.isRunning():
            # 获取当前活动的标签页
            current_tab = self.tabs.currentWidget()
            
            # 如果当前标签页有module_instance属性，调用其stop方法
            if hasattr(current_tab, 'module_instance') and current_tab.module_instance:
                try:
                    current_tab.module_instance.stop()
                    time.sleep(1)
                except Exception as e:
                    print(f"停止模块时出错: {str(e)}")
                    traceback.print_exc()
            
            # 停止工作线程
            self.current_worker.terminate()
            self.current_worker.wait()
            self.current_worker = None
            
            # 通知当前活动的标签页模块已停止
            if hasattr(current_tab, 'on_module_stopped'):
                current_tab.on_module_stopped()
    
    def run_module(self, module_instance, on_finished_callback):
        """运行指定的模块实例"""
        try:
            # 如果有正在运行的模块，先停止它
            self.stop_module()
            
            # 获取当前活动的标签页
            current_tab = self.tabs.currentWidget()
            
            # 设置日志输出
            if hasattr(current_tab, 'result_text') and current_tab.result_text:
                # 清空结果文本
                # current_tab.result_text.clear()
                
                # 设置日志输出
                self.setup_logging(current_tab.result_text)
                sys.stdout = self.log_manager
                
                # 创建工作线程
                self.current_worker = ModuleWorker(module_instance)
                self.current_worker.finished.connect(on_finished_callback)
                
                # 连接错误信号
                self.current_worker.error.connect(lambda msg: current_tab.result_text.append(msg))
                
                # 启动线程
                self.current_worker.start()
        except Exception as e:
            # 处理异常
            error_msg = f"运行模块时出错: {str(e)}"
            print(error_msg)
            traceback.print_exc()
            
            # 如果有结果文本框，显示错误信息
            if hasattr(current_tab, 'result_text') and current_tab.result_text:
                current_tab.result_text.append(error_msg)
                current_tab.result_text.append(traceback.format_exc())
            
            # 调用完成回调，恢复UI状态
            if on_finished_callback:
                on_finished_callback()
    
    def closeEvent(self, event):
        """窗口关闭事件处理函数，用于保存配置"""
        # 停止当前运行的模块
        self.stop_module()
        
        # 保存所有标签页的配置
        self.save_all_tab_configurations()
        
        # 接受关闭事件
        event.accept()
    
    def save_all_tab_configurations(self):
        """保存所有标签页的配置"""
        try:
            # 遍历所有标签页并调用其save_input_values方法
            # 但不立即保存到文件
            for i in range(self.tabs.count()):
                tab = self.tabs.widget(i)
                if hasattr(tab, 'save_input_values'):
                    tab.save_input_values(save_immediately=False)
            
            # 所有标签页配置收集完毕后，统一保存一次
            # 由于ConfigManager是单例模式，任何标签页的config_manager都是同一个实例
            # 所以我们可以使用任意一个标签页的config_manager
            from sippts.gui.common.config_manager import ConfigManager
            config_manager = ConfigManager()
            config_manager.save_config()
                    
            print("所有配置已保存")
        except Exception as e:
            print(f"保存配置时出错: {str(e)}")
            traceback.print_exc()


class ModuleWorker(QThread):
    finished = pyqtSignal()  # 完成信号
    error = pyqtSignal(str)  # 错误信号
    
    def __init__(self, mod):
        super().__init__()
        self.mod = mod
    
    def run(self):
        """线程运行函数"""
        try:
            # 执行模块的start方法
            self.mod.start()
        except Exception as e:
            # 发送错误信号
            error_msg = f"模块执行时出错: {str(e)}"
            print(error_msg)
            traceback.print_exc()
            self.error.emit(error_msg)
        finally:
            # 无论是否发生异常，都发送完成信号
            self.finished.emit()


def run_gui():
    """运行GUI应用程序"""
    app = QApplication(sys.argv)
    
    # 设置全局异常处理
    sys._excepthook = sys.excepthook
    
    def exception_hook(exctype, value, traceback_obj):
        """全局异常处理函数"""
        # 打印异常信息到控制台
        sys._excepthook(exctype, value, traceback_obj)
        
        # 格式化异常信息
        tb_lines = traceback.format_exception(exctype, value, traceback_obj)
        tb_text = ''.join(tb_lines)
        
        # 显示错误对话框
        error_box = QMessageBox()
        error_box.setIcon(QMessageBox.Critical)
        error_box.setWindowTitle("错误")
        error_box.setText("程序发生未处理的异常")
        error_box.setInformativeText(str(value))
        error_box.setDetailedText(tb_text)
        error_box.setStandardButtons(QMessageBox.Ok)
        error_box.exec_()
    
    # 设置全局异常钩子
    sys.excepthook = exception_hook
    icon_path = os.path.join(os.path.dirname(__file__), "resources", "icon.ico")
    if os.path.exists(icon_path):
        icon = QIcon(icon_path)
        # 设置更大的图标尺寸
        app.setWindowIcon(icon)
    try:
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"启动应用程序时出错: {str(e)}")
        traceback.print_exc()
        # 显示错误对话框
        error_box = QMessageBox()
        error_box.setIcon(QMessageBox.Critical)
        error_box.setWindowTitle("启动错误")
        error_box.setText("程序启动时发生错误")
        error_box.setInformativeText(str(e))
        error_box.setDetailedText(traceback.format_exc())
        error_box.setStandardButtons(QMessageBox.Ok)
        error_box.exec_()
        sys.exit(1)


if __name__ == "__main__":
    run_gui() 