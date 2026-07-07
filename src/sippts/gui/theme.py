# -*- coding: utf-8 -*-
"""暗蓝 HUD 安全控制台主题（赛博青强调色）。

集中定义全局配色与一套 QSS 样式表，在 QApplication 级别应用后级联到所有控件。
颜色常量同时供主窗口、终端区、QtChart 图表复用，保证整体视觉一致。
"""

# ============ 设计 Token（与 docs/ui-prototype.html 同色板） ============
BG = "#0A1018"            # 背景底色
BG2 = "#0D1726"          # 二级背景
PANEL = "#111E2E"        # 面板/卡片
PANEL_BORDER = "#1F3D55"  # 面板描边（青调）
ACCENT = "#00E5D0"       # 主强调青
ACCENT2 = "#00B4D8"      # 次强调
ACCENT_HI = "#2FF3E0"    # hover 亮青
TEXT = "#E2EDF4"         # 主文字
MUTED = "#7E97AC"        # 次文字/提示
INPUT_BG = "#0D1A28"     # 输入框背景
INPUT_BORDER = "#244157"  # 输入框边框
TERM_BG = "#060C12"      # 终端区背景
TERM_FG = "#CFE8E5"      # 终端默认字
OK = "#3DDC97"           # 成功
WARN = "#FFB703"         # 警告
ERR = "#FF5C72"          # 错误

UI_FONT = '"Microsoft YaHei UI", "Segoe UI", sans-serif'
MONO_FONT = '"Consolas", "JetBrains Mono", "Courier New", monospace'


# ============ 全局 QSS ============
APP_QSS = f"""
* {{
    font-family: {UI_FONT};
    font-size: 14px;
    color: {TEXT};
    outline: none;
}}

QMainWindow, QWidget {{
    background-color: {BG};
}}

/* ---- HUD 顶栏 ---- */
QWidget#hudHeader {{
    background-color: {BG2};
    border-bottom: 1px solid {PANEL_BORDER};
}}
QLabel#hudLogo {{
    background-color: {ACCENT};
    color: #042022;
    font-size: 16px;
    font-weight: 800;
    border-radius: 7px;
    padding: 4px 6px;
}}
QLabel#hudTitle {{
    font-size: 17px;
    font-weight: 700;
    letter-spacing: 1px;
}}
QLabel#hudTitleAccent {{
    font-size: 17px;
    font-weight: 700;
    color: {ACCENT};
}}
QLabel#hudClock {{
    color: {ACCENT2};
    font-family: {MONO_FONT};
    font-size: 13px;
    letter-spacing: 1px;
}}
QLabel#hudStatus {{
    color: {MUTED};
    font-family: {MONO_FONT};
    font-size: 12px;
    letter-spacing: 1px;
}}

/* ---- Tab ---- */
QTabWidget::pane {{
    border: none;
    background-color: {BG};
    top: -1px;
}}
QTabBar {{
    background-color: {BG};
    qproperty-drawBase: 0;
}}
QTabBar::tab {{
    background: transparent;
    color: {MUTED};
    padding: 10px 18px;
    margin-right: 2px;
    border: none;
    border-bottom: 2px solid transparent;
    font-size: 13px;
}}
QTabBar::tab:hover {{
    color: {TEXT};
}}
QTabBar::tab:selected {{
    color: {ACCENT};
    border-bottom: 2px solid {ACCENT};
}}

/* ---- GroupBox 面板 ---- */
QGroupBox {{
    background-color: {PANEL};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
    margin-top: 14px;
    padding: 14px 12px 12px 12px;
    font-size: 13px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 6px;
    color: {ACCENT};
    font-weight: 600;
}}

/* ---- 标签 ---- */
QLabel {{
    background: transparent;
    color: {TEXT};
}}

/* ---- 输入框 ---- */
QLineEdit, QPlainTextEdit {{
    background-color: {INPUT_BG};
    color: {TEXT};
    border: 1px solid {INPUT_BORDER};
    border-radius: 5px;
    padding: 7px 9px;
    selection-background-color: {ACCENT2};
    selection-color: #04222A;
}}
QLineEdit:focus, QPlainTextEdit:focus {{
    border: 1px solid {ACCENT};
}}
QLineEdit:disabled {{
    color: {MUTED};
    background-color: #0A1420;
}}

/* ---- 下拉框 ---- */
QComboBox {{
    background-color: {INPUT_BG};
    color: {TEXT};
    border: 1px solid {INPUT_BORDER};
    border-radius: 5px;
    padding: 6px 9px;
    min-height: 18px;
}}
QComboBox:focus {{
    border: 1px solid {ACCENT};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox::down-arrow {{
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid {ACCENT};
    margin-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG2};
    color: {TEXT};
    border: 1px solid {PANEL_BORDER};
    selection-background-color: {ACCENT2};
    selection-color: #04222A;
    outline: none;
}}

/* ---- 复选框 ---- */
QCheckBox {{
    color: {TEXT};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {INPUT_BORDER};
    border-radius: 4px;
    background-color: {INPUT_BG};
}}
QCheckBox::indicator:hover {{
    border: 1px solid {ACCENT};
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border: 1px solid {ACCENT};
}}

/* ---- 按钮 ---- */
QPushButton {{
    background-color: transparent;
    color: {ACCENT};
    border: 1px solid {INPUT_BORDER};
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: 600;
    letter-spacing: .5px;
}}
QPushButton:hover {{
    border: 1px solid {ACCENT};
    color: {ACCENT_HI};
}}
QPushButton:disabled {{
    color: {MUTED};
    border: 1px solid #1A2A3A;
}}
/* 主按钮（开始类）：青色填充 */
QPushButton#primaryBtn {{
    background-color: {ACCENT};
    color: #042022;
    border: none;
}}
QPushButton#primaryBtn:hover {{
    background-color: {ACCENT_HI};
}}
QPushButton#primaryBtn:disabled {{
    background-color: #1C3A44;
    color: {MUTED};
}}
/* 危险按钮（停止类）：红色描边 */
QPushButton#dangerBtn {{
    background-color: transparent;
    color: {ERR};
    border: 1px solid {ERR};
}}
QPushButton#dangerBtn:hover {{
    background-color: rgba(255, 92, 114, 30);
    color: {ERR};
}}
QPushButton#dangerBtn:disabled {{
    color: {MUTED};
    border: 1px solid #3A2530;
}}

/* ---- 列表 ---- */
QListWidget {{
    background-color: {INPUT_BG};
    color: {TEXT};
    border: 1px solid {INPUT_BORDER};
    border-radius: 5px;
    outline: none;
}}
QListWidget::item:selected {{
    background-color: {ACCENT2};
    color: #04222A;
}}

/* ---- 表格 ---- */
QTableWidget, QTableView {{
    background-color: {PANEL};
    alternate-background-color: {BG2};
    color: {TEXT};
    gridline-color: {PANEL_BORDER};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
    font-family: {MONO_FONT};
    font-size: 13px;
    selection-background-color: rgba(0, 229, 208, 40);
    selection-color: {TEXT};
}}
QHeaderView::section {{
    background-color: {BG2};
    color: {ACCENT2};
    border: none;
    border-bottom: 1px solid {PANEL_BORDER};
    padding: 8px 10px;
    font-weight: 600;
}}
QTableCornerButton::section {{
    background-color: {BG2};
    border: none;
}}

/* ---- 进度条 ---- */
QProgressBar {{
    background-color: {INPUT_BG};
    border: 1px solid {INPUT_BORDER};
    border-radius: 5px;
    text-align: center;
    color: {TEXT};
    height: 16px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 4px;
}}

/* ---- 终端输出（result_text 通过 objectName 命中） ---- */
QTextEdit#termOutput {{
    background-color: {TERM_BG};
    color: {TERM_FG};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
    font-family: {MONO_FONT};
    font-size: 14px;
    padding: 8px;
}}

/* ---- 滚动条 ---- */
QScrollBar:vertical {{
    background: {BG};
    width: 10px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {INPUT_BORDER};
    border-radius: 5px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{
    background: {ACCENT2};
}}
QScrollBar:horizontal {{
    background: {BG};
    height: 10px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background: {INPUT_BORDER};
    border-radius: 5px;
    min-width: 24px;
}}
QScrollBar::handle:horizontal:hover {{
    background: {ACCENT2};
}}
QScrollBar::add-line, QScrollBar::sub-line {{
    width: 0; height: 0;
}}
QScrollBar::add-page, QScrollBar::sub-page {{
    background: transparent;
}}

/* ---- 卡片容器（仪表盘用，objectName=card / cardTitle） ---- */
QFrame#card {{
    background-color: {PANEL};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
}}
QLabel#cardTitle {{
    color: {ACCENT};
    font-size: 12px;
    font-weight: 600;
    letter-spacing: .5px;
}}
QLabel#kpiLabel {{
    color: {MUTED};
    font-size: 12px;
}}
QLabel#kpiNum {{
    font-family: {MONO_FONT};
    font-size: 30px;
    font-weight: 700;
}}

/* ---- KPI 进度条（仪表盘 KPI 卡底部细条，chunk 颜色由各卡内联设置） ---- */
QProgressBar#kpiBar {{
    background-color: {INPUT_BG};
    border: 1px solid {INPUT_BORDER};
    border-radius: 3px;
    max-height: 6px;
    min-height: 6px;
    text-align: center;
}}
QProgressBar#kpiBar::chunk {{
    border-radius: 2px;
    background-color: {ACCENT};
}}

/* ---- 阶段进度条（5 段，state 属性切换） ---- */
QLabel#phaseSeg {{
    color: {MUTED};
    background-color: {BG};
    padding: 9px 6px;
    border-right: 1px solid {PANEL_BORDER};
    border-bottom: 2px solid transparent;
    font-size: 12px;
}}
QLabel#phaseSeg[state="active"] {{
    color: {ACCENT};
    background-color: rgba(0, 229, 208, 16);
    border-bottom: 2px solid {ACCENT};
}}
QLabel#phaseSeg[state="done"] {{
    color: {OK};
    border-bottom: 2px solid {OK};
}}
QFrame#phaseBar {{
    background-color: {BG};
    border: 1px solid {PANEL_BORDER};
    border-radius: 8px;
}}

/* ---- 事件流 scanline ---- */
QLabel#scanline {{
    color: {MUTED};
    font-family: {MONO_FONT};
    font-size: 12px;
}}

/* ---- 探测吞吐（发现速率）数字 ---- */
QLabel#throughputNum {{
    color: {ACCENT};
    font-family: {MONO_FONT};
    font-size: 22px;
    font-weight: 700;
}}
QLabel#throughputUnit {{
    color: {MUTED};
    font-size: 11px;
}}

/* ---- 告警 Toast 浮层 ---- */
QFrame#toast {{
    background-color: rgba(20, 12, 16, 245);
    border: 1px solid {ERR};
    border-left: 4px solid {ERR};
    border-radius: 8px;
}}
QLabel#toastTitle {{
    color: {ERR};
    font-weight: 700;
    font-size: 13px;
}}
QLabel#toastBody {{
    color: {MUTED};
    font-family: {MONO_FONT};
    font-size: 12px;
}}

/* ---- 消息框 ---- */
QMessageBox {{
    background-color: {BG2};
}}
"""


def apply_theme(app):
    """对整个 QApplication 应用 HUD 主题。"""
    app.setStyleSheet(APP_QSS)
