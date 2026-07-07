import sys
import re
import traceback
import os
import warnings
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QMessageBox,
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
)
from PyQt5.QtCore import QThread, pyqtSignal, QObject, QEvent, QTimer, QTime, Qt
from PyQt5.QtGui import QTextCharFormat, QColor, QTextCursor, QIcon

# 忽略PyQt5相关的废弃警告
warnings.filterwarnings("ignore", category=DeprecationWarning)

# 主题与仪表盘
from sippts.gui import theme as T
from sippts.gui.common.data_store import (
    DataStore, parse_found_line, parse_exten_line, parse_cred_line
)
from sippts.gui.modules.dashboard_tab import DashboardTab
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
        self.setWindowTitle("IMS 安全测试平台")
        self.setMinimumSize(800, 600)
        self.setGeometry(100, 100, 1920, 1080)

        # 创建主标签页控件
        self.tabs = QTabWidget()

        # 构建带 HUD 顶栏的中央容器
        central = QWidget()
        central_layout = QVBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)
        central_layout.addWidget(self._build_hud_header())
        central_layout.addWidget(self.tabs)
        self.setCentralWidget(central)
        
        # 当前活动的模块工作线程
        self.current_worker = None
        
        # 创建日志管理器
        self.log_manager = LogManager()
        
        # 初始化颜色映射
        self.init_color_map()
        
        # 初始化各个功能标签页
        self.init_tabs()
        
    def _build_hud_header(self):
        """构建顶部 HUD 标题栏：LOGO + 标题 + 实时时钟 + 在线状态。"""
        header = QFrame()
        header.setObjectName("hudHeader")
        header.setFixedHeight(58)
        lay = QHBoxLayout(header)
        lay.setContentsMargins(20, 0, 20, 0)
        lay.setSpacing(14)

        title = QLabel("IMS")
        title.setObjectName("hudTitle")
        lay.addWidget(title)
        title_a = QLabel("安全测试平台")
        title_a.setObjectName("hudTitleAccent")
        lay.addWidget(title_a)

        lay.addStretch()

        self.hud_clock = QLabel("--:--:--")
        self.hud_clock.setObjectName("hudClock")
        lay.addWidget(self.hud_clock)

        status = QLabel("● ONLINE · SIP/RTP")
        status.setObjectName("hudStatus")
        status.setStyleSheet(f"color:{T.OK};")
        lay.addWidget(status)

        # 时钟
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start(1000)
        self._update_clock()
        return header

    def _update_clock(self):
        self.hud_clock.setText(QTime.currentTime().toString("HH:mm:ss"))

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

        # 总览仪表盘
        self.dashboard_tab = DashboardTab(self)
        self.tabs.addTab(self.dashboard_tab, "总览")

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
        
        # 统一为各模块的开始/停止按钮打上主题角色（命中全局 QSS）
        self._apply_button_roles()

    def _apply_button_roles(self):
        """为所有标签页的开始/停止按钮设置 objectName，使其命中主题样式。"""
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            for attr, role in (("start_btn", "primaryBtn"), ("stop_btn", "dangerBtn")):
                btn = getattr(tab, attr, None)
                if btn is not None:
                    btn.setObjectName(role)
                    btn.style().unpolish(btn)
                    btn.style().polish(btn)

    def setup_logging(self, text_widget):
        """设置日志输出到指定的文本框"""
        text_widget.clear()
        self._ow = False  # 重置“回车覆盖”标志，新一轮输出从干净状态开始

        # 先断开之前的连接
        if hasattr(self.log_manager, 'log_signal'):
            try:
                self.log_manager.log_signal.disconnect()
            except:
                pass
        # 建立新的连接
        self.log_manager.log_signal.connect(lambda text: self.append_log(text_widget, text))
    
    def _insert_ansi(self, cursor, text):
        """把含 ANSI 颜色码的文本按颜色插入到 cursor 处。"""
        if text == "":
            return
        parts = re.split(r'(\x1B\[[0-9;]*m)', text)
        current_format = QTextCharFormat()
        current_format.setForeground(QColor(T.TERM_FG))  # 默认终端字色（青白）
        for part in parts:
            if part.startswith('\033['):
                if part in self.color_map:
                    current_format = self.color_map[part]
                else:
                    for code in self.color_map:
                        if part.startswith(code[:5]):
                            current_format = self.color_map[code]
                            break
            elif part:
                cursor.insertText(part, current_format)

    def append_log(self, text_widget, text):
        r"""添加日志到文本框，正确处理 \r（回车覆盖当前行）与 \n（换行）。

        扫描/破解等模块用 `print(..., end='\r')` 在同一行滚动刷新进度。
        终端语义：\r 仅把光标移回行首（不删除），随后的文本覆盖本行；\n 才换行。
        由于 print 可能把正文与 '\r' 拆成两次写入，必须用一个跨调用保持的
        “待覆盖”标志（self._ow）来还原单行滚动，而不能简单按单次写入折叠。
        """
        cursor = text_widget.textCursor()
        cursor.movePosition(QTextCursor.End)

        for tok in re.split(r'([\r\n])', text):
            if tok == '':
                continue
            if tok == '\n':
                cursor.movePosition(QTextCursor.End)
                cursor.insertText('\n')
                self._ow = False
            elif tok == '\r':
                self._ow = True            # 仅标记：下一段文本覆盖当前行
            else:
                cursor.movePosition(QTextCursor.End)
                if getattr(self, "_ow", False):
                    # 覆盖：清空当前行后从行首写入
                    cursor.movePosition(QTextCursor.StartOfBlock, QTextCursor.KeepAnchor)
                    cursor.removeSelectedText()
                    self._ow = False
                self._insert_ansi(cursor, tok)

        cursor.movePosition(QTextCursor.End)
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
            
            # 停止扫描数据监视
            self._stop_scan_monitor()

            # 停止工作线程
            self.current_worker.terminate()
            self.current_worker.wait()
            self.current_worker = None

            # 通知当前活动的标签页模块已停止
            if hasattr(current_tab, 'on_module_stopped'):
                current_tab.on_module_stopped()

    # ---------------- 模块数据监视（喂给总览仪表盘） ----------------
    # 模块类名 -> (kind, 启动时清空范围；None 表示累计不清空)
    # 扫描/枚举为“替换式”（新一轮替换旧结果）；两个破解模块共用 creds 且累计去重。
    MONITORED = {
        "SipScan": ("scan", "hosts"),
        "SipExten": ("exten", "extensions"),
        "SipRemoteCrack": ("rcrack", None),
        "SipDigestCrack": ("dcrack", None),
    }

    def _start_scan_monitor(self, mod):
        """开始轮询正在运行的模块实例，把新结果按类型送入 DataStore。"""
        kind, scope = self.MONITORED[type(mod).__name__]
        ds = DataStore()
        if scope:
            ds.reset(scope)
        ds.scan_started.emit(kind)
        self._scan_mod = mod
        self._scan_kind = kind
        if getattr(self, "_scan_poll", None) is None:
            self._scan_poll = QTimer(self)
            self._scan_poll.timeout.connect(self._poll_scan_data)
        self._scan_poll.start(400)

    def _poll_scan_data(self):
        mod = getattr(self, "_scan_mod", None)
        if mod is None:
            return
        ds = DataStore()
        kind = getattr(self, "_scan_kind", "scan")
        try:
            lines = list(getattr(mod, "found", []))  # 拷贝快照，避免与工作线程并发修改
        except Exception:
            lines = []
        for line in lines:
            if kind == "scan":
                host = parse_found_line(line)
                if host:
                    ds.add_host(host)
            elif kind == "exten":
                ext = parse_exten_line(line)
                if ext:
                    ds.add_extension(ext)
            elif kind == "rcrack":
                cred = parse_cred_line(line, "远程爆破")
                if cred:
                    ds.add_cred(cred)
            elif kind == "dcrack":
                cred = parse_cred_line(line, "离线破解")
                if cred:
                    ds.add_cred(cred)
        if kind == "scan":
            try:
                ds.set_cve_count(len(getattr(mod, "cve", [])))
            except Exception:
                pass

    def _stop_scan_monitor(self):
        if getattr(self, "_scan_mod", None) is None:
            return
        if getattr(self, "_scan_poll", None) is not None:
            self._scan_poll.stop()
        self._poll_scan_data()  # 尽力做最后一次捕获
        DataStore().scan_finished.emit(getattr(self, "_scan_kind", "scan"))
        self._scan_mod = None

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
                self.current_worker.finished.connect(self._stop_scan_monitor)

                # 连接错误信号
                self.current_worker.error.connect(lambda msg: current_tab.result_text.append(msg))

                # 启动线程
                self.current_worker.start()

                # 受支持的模块：启动数据监视，把实时结果送入总览仪表盘
                if type(module_instance).__name__ in self.MONITORED:
                    self._start_scan_monitor(module_instance)
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

    # 应用暗蓝 HUD 全局主题
    T.apply_theme(app)

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