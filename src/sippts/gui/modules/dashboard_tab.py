# -*- coding: utf-8 -*-
"""总览仪表盘 Tab：QtCharts + QPainter 雷达，数据来自多个核心模块的实时结果。

数据由 common.data_store.DataStore 单例驱动：MainWindow 轮询正在运行的扫描/枚举/
破解实例，把结构化结果喂入 DataStore，本仪表盘订阅信号更新各面板。
覆盖模块：SIP扫描(主机)、分机枚举(分机)、远程/离线密码破解(凭证)。
"""

import math
import time

from PyQt5.QtWidgets import (
    QWidget, QFrame, QLabel, QGridLayout, QVBoxLayout, QHBoxLayout, QScrollArea,
    QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy, QProgressBar,
    QTextEdit, QGraphicsOpacityEffect
)
from PyQt5.QtCore import (
    Qt, QTimer, QPointF, QRectF, QMargins, QPropertyAnimation, QEasingCurve, QPoint
)
from PyQt5.QtGui import (
    QColor, QPainter, QPen, QBrush, QConicalGradient, QFont, QRadialGradient
)
from PyQt5.QtChart import (
    QChart, QChartView, QLineSeries, QAreaSeries, QValueAxis,
    QPieSeries, QBarSeries, QBarSet, QBarCategoryAxis
)

from sippts.gui import theme as T
from sippts.gui.common.data_store import DataStore


def _qc(hexstr, alpha=255):
    c = QColor(hexstr)
    c.setAlpha(alpha)
    return c


def make_card(title=None, min_h=None):
    frame = QFrame()
    frame.setObjectName("card")
    if min_h:
        frame.setMinimumHeight(min_h)
    outer = QVBoxLayout(frame)
    outer.setContentsMargins(14, 12, 14, 12)
    outer.setSpacing(8)
    if title:
        lbl = QLabel("▌ " + title)
        lbl.setObjectName("cardTitle")
        outer.addWidget(lbl)
    return frame, outer


# ============================================================ 雷达
class RadarWidget(QWidget):
    """探测雷达：旋转扫描扇区；每发现一个目标点亮一个会渐隐的 blip。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(220, 220)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._angle = 0.0
        self._blips = []
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._spin)
        self._timer.start(33)

    def ping(self):
        seed = (len(self._blips) * 137 + int(self._angle)) % 360
        rr = 0.35 + ((seed * 7) % 60) / 100.0
        self._blips.append({"ang": float(seed), "rr": rr, "life": 255})

    def _spin(self):
        self._angle = (self._angle + 2.2) % 360
        for b in self._blips:
            b["life"] -= 4
        self._blips = [b for b in self._blips if b["life"] > 0]
        self.update()

    def clear_blips(self):
        self._blips = []
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w / 2, h / 2
        radius = min(w, h) / 2 - 6

        bg = QRadialGradient(cx, cy, radius)
        bg.setColorAt(0, _qc(T.ACCENT, 22))
        bg.setColorAt(1, _qc(T.BG, 0))
        p.setBrush(QBrush(bg))
        p.setPen(QPen(_qc(T.PANEL_BORDER), 1))
        p.drawEllipse(QPointF(cx, cy), radius, radius)

        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(_qc(T.PANEL_BORDER), 1))
        for r in (radius * 0.33, radius * 0.66, radius):
            p.drawEllipse(QPointF(cx, cy), r, r)
        p.drawLine(QPointF(cx - radius, cy), QPointF(cx + radius, cy))
        p.drawLine(QPointF(cx, cy - radius), QPointF(cx, cy + radius))

        grad = QConicalGradient(cx, cy, -self._angle)
        grad.setColorAt(0.0, _qc(T.ACCENT, 130))
        grad.setColorAt(0.12, _qc(T.ACCENT, 30))
        grad.setColorAt(0.2, _qc(T.ACCENT, 0))
        grad.setColorAt(1.0, _qc(T.ACCENT, 0))
        p.setBrush(QBrush(grad))
        p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(cx, cy), radius, radius)

        rad = math.radians(self._angle)
        p.setPen(QPen(_qc(T.ACCENT, 200), 1.5))
        p.drawLine(QPointF(cx, cy),
                   QPointF(cx + radius * math.cos(rad), cy - radius * math.sin(rad)))

        for b in self._blips:
            a = max(0, min(255, b["life"]))
            bx = cx + radius * b["rr"] * math.cos(math.radians(b["ang"]))
            by = cy - radius * b["rr"] * math.sin(math.radians(b["ang"]))
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(_qc(T.ACCENT, a)))
            p.drawEllipse(QPointF(bx, by), 4, 4)
            p.setBrush(QBrush(_qc(T.ACCENT, a // 4)))
            p.drawEllipse(QPointF(bx, by), 9, 9)
        p.end()


# ============================================================ KPI 卡
class KPICard(QFrame):
    def __init__(self, label, color, suffix="", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._suffix = suffix
        self._color = color
        self._cur = 0
        self._target = 0
        self._max = 1  # 滚动最大值：进度条以本轮见过的最大值为分母
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(8)
        cap = QLabel(label)
        cap.setObjectName("kpiLabel")
        self.num = QLabel("0")
        self.num.setObjectName("kpiNum")
        self.num.setStyleSheet(f"color:{color};")
        self.bar = QProgressBar()
        self.bar.setObjectName("kpiBar")
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setStyleSheet(
            "QProgressBar#kpiBar::chunk{border-radius:2px;background-color:%s;}" % color)
        lay.addWidget(cap)
        lay.addWidget(self.num)
        lay.addWidget(self.bar)
        self._t = QTimer(self)
        self._t.timeout.connect(self._step)

    def set_value(self, v):
        self._target = int(v)
        self._max = max(self._max, self._target, 1)
        self.bar.setValue(int(self._target / self._max * 100))
        if not self._t.isActive():
            self._t.start(30)

    def reset_scale(self):
        self._max = 1

    def _step(self):
        if self._cur == self._target:
            self._t.stop()
            return
        diff = self._target - self._cur
        step = max(1, abs(diff) // 6) * (1 if diff > 0 else -1)
        self._cur += step
        if (step > 0 and self._cur > self._target) or (step < 0 and self._cur < self._target):
            self._cur = self._target
        self.num.setText(f"{self._cur:,}{self._suffix}")


# ============================================================ 威胁指数仪表盘
class GaugeWidget(QWidget):
    """半圆威胁指数：背景弧 + 进度弧 + 指针 + 中心分数（QPainter 自绘）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._score = 0

    def set_score(self, s):
        self._score = max(0, min(100, int(s)))
        self.update()

    def _band(self):
        if self._score < 33:
            return T.OK, "安全"
        if self._score < 66:
            return T.WARN, "存在风险"
        return T.ERR, "高危"

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        cx = w / 2
        r = min((w - 36) / 2, h - 46)
        cy = (h + r) / 2 - 6
        rect = QRectF(cx - r, cy - r, 2 * r, 2 * r)
        col, label = self._band()

        # 背景弧（上半圆：0°→180°）
        pen = QPen(_qc(T.INPUT_BG), 11)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 0, 180 * 16)
        # 进度弧：从左端(180°)向右扫
        pen = QPen(_qc(col), 11)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 180 * 16, -int(180 * self._score / 100) * 16)

        # 指针
        ang = math.radians(180 - 180 * self._score / 100)
        nx = cx + (r - 8) * math.cos(ang)
        ny = cy - (r - 8) * math.sin(ang)
        pen = QPen(_qc(col), 3)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawLine(QPointF(cx, cy), QPointF(nx, ny))
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(_qc(col)))
        p.drawEllipse(QPointF(cx, cy), 5, 5)

        # 中心分数 + 标签
        p.setPen(QPen(_qc(col)))
        f = QFont("Consolas")
        f.setPointSize(20)
        f.setBold(True)
        p.setFont(f)
        p.drawText(QRectF(cx - r, cy - r * 0.62, 2 * r, r * 0.6),
                   Qt.AlignCenter, str(self._score))
        p.setPen(QPen(_qc(T.MUTED)))
        f2 = QFont(T.UI_FONT.split(",")[0].strip('"'))
        f2.setPointSize(10)
        p.setFont(f2)
        p.drawText(QRectF(cx - r, cy + 4, 2 * r, 20), Qt.AlignCenter, label)
        p.end()


# ============================================================ 阶段进度条
class PhaseBar(QFrame):
    """5 段审计阶段：由当前运行模块 + 已有数据诚实推导 active/done 状态。"""

    PHASES = [
        ("scan", "资产扫描"), ("exten", "分机枚举"), ("crack", "口令破解"),
        ("vuln", "漏洞研判"), ("report", "生成报告"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("phaseBar")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self._segs = {}
        for i, (k, label) in enumerate(self.PHASES):
            seg = QLabel(f"{i + 1:02d}  {label}")
            seg.setObjectName("phaseSeg")
            seg.setAlignment(Qt.AlignCenter)
            seg.setProperty("state", "idle")
            if i == len(self.PHASES) - 1:
                seg.setStyleSheet("border-right:none;")
            lay.addWidget(seg, 1)
            self._segs[k] = seg
        self._running = None

    def _set(self, key, state):
        seg = self._segs[key]
        if seg.property("state") == state:
            return
        seg.setProperty("state", state)
        seg.style().unpolish(seg)
        seg.style().polish(seg)

    def set_running(self, phase_key):
        """phase_key ∈ {scan, exten, crack, vuln, report} 或 None（空闲）。"""
        self._running = phase_key

    def update_states(self, has):
        """has: dict 各阶段是否已有数据，如 {'scan':True,'exten':False,...}。"""
        active = self._running
        for k, _ in self.PHASES:
            if k == active:
                self._set(k, "active")
            elif has.get(k):
                self._set(k, "done")
            else:
                self._set(k, "idle")


# ============================================================ 发现速率 sparkline
class Sparkline(QWidget):
    """近 N 个采样点的折线（QPainter 自绘）。"""

    def __init__(self, color, n=40, parent=None):
        super().__init__(parent)
        self._color = color
        self._pts = [0] * n
        self.setMinimumHeight(48)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def push(self, v):
        self._pts.append(max(0, int(v)))
        self._pts.pop(0)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        peak = max(4, *self._pts) if self._pts else 4
        n = len(self._pts)
        pen = QPen(_qc(self._color), 1.6)
        p.setPen(pen)
        prev = None
        for i, v in enumerate(self._pts):
            x = w * i / (n - 1)
            y = h - 4 - (h - 8) * v / peak
            if prev is not None:
                p.drawLine(QPointF(prev[0], prev[1]), QPointF(x, y))
            prev = (x, y)
        p.end()


# ============================================================ 告警 Toast
class ToastWidget(QFrame):
    """右上角滑入、数秒后淡出的红色告警卡。"""

    def __init__(self, title, body, parent=None):
        super().__init__(parent)
        self.setObjectName("toast")
        self.setFixedWidth(300)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(3)
        t = QLabel("⚠ " + title)
        t.setObjectName("toastTitle")
        b = QLabel(body)
        b.setObjectName("toastBody")
        b.setWordWrap(True)
        lay.addWidget(t)
        lay.addWidget(b)
        self._eff = QGraphicsOpacityEffect(self)
        self._eff.setOpacity(1.0)
        self.setGraphicsEffect(self._eff)
        self.adjustSize()

    def slide_in(self, target_pos):
        start = QPoint(target_pos.x() + 40, target_pos.y())
        self.move(start)
        self.show()
        self.raise_()
        self._anim = QPropertyAnimation(self, b"pos", self)
        self._anim.setDuration(280)
        self._anim.setStartValue(start)
        self._anim.setEndValue(target_pos)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.start()

    def fade_out(self, on_done):
        self._fade = QPropertyAnimation(self._eff, b"opacity", self)
        self._fade.setDuration(450)
        self._fade.setStartValue(1.0)
        self._fade.setEndValue(0.0)
        self._fade.finished.connect(on_done)
        self._fade.start()


# ============================================================ 图表工具
def _style_chart(chart):
    chart.setBackgroundVisible(False)
    chart.setMargins(QMargins(2, 2, 2, 2))
    chart.legend().hide()
    chart.setAnimationOptions(QChart.SeriesAnimations)


def _style_axis(axis):
    axis.setLabelsColor(_qc(T.MUTED))
    axis.setGridLineColor(_qc(T.PANEL_BORDER))
    axis.setLinePenColor(_qc(T.PANEL_BORDER))
    f = QFont("Consolas")
    f.setPointSize(8)
    axis.setLabelsFont(f)


def _mk_table(headers, stretch_cols):
    tbl = QTableWidget(0, len(headers))
    tbl.setHorizontalHeaderLabels(headers)
    tbl.verticalHeader().setVisible(False)
    tbl.setEditTriggers(QTableWidget.NoEditTriggers)
    tbl.setSelectionBehavior(QTableWidget.SelectRows)
    tbl.setAlternatingRowColors(True)
    hdr = tbl.horizontalHeader()
    hdr.setSectionResizeMode(QHeaderView.Stretch)
    for c in stretch_cols:
        hdr.setSectionResizeMode(c, QHeaderView.ResizeToContents)
    return tbl


# ============================================================ 主仪表盘
class DashboardTab(QWidget):
    def __init__(self, main_window=None):
        super().__init__()
        self.main_window = main_window
        self.ds = DataStore()
        self._toasts = []          # 活动 Toast 列表（顶层浮层）
        self._last_cve = 0         # 漏洞数去重，仅增量时告警
        self._build()
        self._connect_store()

    # -------------------- 构建 --------------------
    def _build(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.viewport().setStyleSheet("background: transparent;")
        content = QWidget()
        root = QGridLayout(content)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(14)

        # 阶段进度条
        self.phase_bar = PhaseBar()
        root.addWidget(self.phase_bar, 0, 0, 1, 2)

        # KPI
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(14)
        self.kpi_hosts = KPICard("发现主机", T.ACCENT)
        self.kpi_ext = KPICard("发现分机", T.ACCENT2)
        self.kpi_cred = KPICard("破解凭证", T.OK)
        self.kpi_cve = KPICard("发现漏洞", T.ERR)
        for k in (self.kpi_hosts, self.kpi_ext, self.kpi_cred, self.kpi_cve):
            kpi_row.addWidget(k)
        kpi_wrap = QWidget()
        kpi_wrap.setLayout(kpi_row)
        root.addWidget(kpi_wrap, 1, 0, 1, 2)

        radar_card, radar_lay = make_card("实时探测雷达", min_h=260)
        self.radar = RadarWidget()
        radar_lay.addWidget(self.radar, alignment=Qt.AlignCenter)
        root.addWidget(radar_card, 2, 0)
        root.addWidget(self._build_donut(), 2, 1)
        root.addWidget(self._build_trend(), 3, 0)
        root.addWidget(self._build_bars(), 3, 1)
        root.addWidget(self._build_event_log(), 4, 0)
        root.addWidget(self._build_gauge_throughput(), 4, 1)
        root.addWidget(self._build_host_table(), 5, 0, 1, 2)
        root.addWidget(self._build_findings_table(), 6, 0, 1, 2)

        root.setColumnStretch(0, 1)
        root.setColumnStretch(1, 1)

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _build_donut(self):
        card, lay = make_card("协议分布（主机+分机）", min_h=260)
        body = QHBoxLayout()
        self._pie = QPieSeries()
        self._pie.setHoleSize(0.6)
        self._pie.setPieSize(0.85)
        self._proto_order = [("UDP", T.ACCENT), ("TCP", T.ACCENT2), ("TLS", T.WARN)]
        self._slices = {}
        for name, col in self._proto_order:
            sl = self._pie.append(name, 0)
            sl.setColor(_qc(col))
            sl.setBorderColor(_qc(T.PANEL))
            sl.setBorderWidth(2)
            sl.setLabelVisible(False)
            self._slices[name] = sl
        chart = QChart()
        chart.addSeries(self._pie)
        _style_chart(chart)
        view = QChartView(chart)
        view.setRenderHint(QPainter.Antialiasing)
        view.setStyleSheet("background: transparent;")
        body.addWidget(view, 2)

        self._legend_labels = {}
        legend = QVBoxLayout()
        legend.addStretch()
        for name, col in self._proto_order:
            row = QLabel(self._legend_text(name, col, 0))
            legend.addWidget(row)
            self._legend_labels[name] = (row, col)
        legend.addStretch()
        lwrap = QWidget()
        lwrap.setLayout(legend)
        body.addWidget(lwrap, 1)
        lay.addLayout(body)
        return card

    def _legend_text(self, name, col, val):
        return (f'<span style="color:{col}">●</span> '
                f'<span style="color:{T.TEXT}">{name}</span> '
                f'<span style="color:{T.MUTED}">{val}</span>')

    def _build_trend(self):
        card, lay = make_card("发现趋势（实时累计）", min_h=220)
        self._trend_pts = [0] * 24
        self._line = QLineSeries()
        self._lower = QLineSeries()
        for i in range(len(self._trend_pts)):
            self._lower.append(i, 0)
        self._refresh_line()
        self._area = QAreaSeries(self._line, self._lower)
        self._area.setColor(_qc(T.ACCENT, 60))
        pen = QPen(_qc(T.ACCENT))
        pen.setWidth(2)
        self._area.setPen(pen)
        chart = QChart()
        chart.addSeries(self._area)
        _style_chart(chart)
        self._ax = QValueAxis()
        self._ax.setRange(0, len(self._trend_pts) - 1)
        self._ax.setLabelFormat("%d")
        self._ax.setTickCount(7)
        _style_axis(self._ax)
        self._ay = QValueAxis()
        self._ay.setRange(0, 10)
        self._ay.setTickCount(5)
        self._ay.setLabelFormat("%d")
        _style_axis(self._ay)
        chart.addAxis(self._ax, Qt.AlignBottom)
        chart.addAxis(self._ay, Qt.AlignLeft)
        self._area.attachAxis(self._ax)
        self._area.attachAxis(self._ay)
        view = QChartView(chart)
        view.setRenderHint(QPainter.Antialiasing)
        view.setStyleSheet("background: transparent;")
        lay.addWidget(view)
        self._trend_timer = QTimer(self)
        self._trend_timer.timeout.connect(self._sample_trend)
        self._trend_timer.start(1500)
        return card

    def _refresh_line(self):
        self._line.clear()
        for i, v in enumerate(self._trend_pts):
            self._line.append(i, v)

    def _sample_trend(self):
        self._trend_pts.append(self.ds.total_findings())
        self._trend_pts.pop(0)
        self._ay.setRange(0, max(10, max(self._trend_pts) + 2))
        self._refresh_line()

    def _build_bars(self):
        card, lay = make_card("响应状态分布", min_h=220)
        self._bar_cats = ["200", "401/407", "403/404", "其他"]
        self._bar_cols = [T.OK, T.WARN, T.ACCENT2, T.ERR]
        series = QBarSeries()
        series.setBarWidth(0.7)
        self._barsets = []
        for i, col in enumerate(self._bar_cols):
            bs = QBarSet(self._bar_cats[i])
            for _ in range(len(self._bar_cats)):
                bs.append(0)
            bs.setColor(_qc(col))
            bs.setBorderColor(_qc(col))
            series.append(bs)
            self._barsets.append(bs)
        chart = QChart()
        chart.addSeries(series)
        _style_chart(chart)
        axx = QBarCategoryAxis()
        axx.append(self._bar_cats)
        _style_axis(axx)
        f = QFont("Microsoft YaHei UI")
        f.setPointSize(8)
        axx.setLabelsFont(f)
        self._bar_y = QValueAxis()
        self._bar_y.setRange(0, 10)
        self._bar_y.setTickCount(4)
        self._bar_y.setLabelFormat("%d")
        _style_axis(self._bar_y)
        chart.addAxis(axx, Qt.AlignBottom)
        chart.addAxis(self._bar_y, Qt.AlignLeft)
        series.attachAxis(axx)
        series.attachAxis(self._bar_y)
        view = QChartView(chart)
        view.setRenderHint(QPainter.Antialiasing)
        view.setStyleSheet("background: transparent;")
        lay.addWidget(view)
        return card

    def _build_event_log(self):
        card, lay = make_card("实时事件流", min_h=240)
        self._evlog = QTextEdit()
        self._evlog.setObjectName("termOutput")
        self._evlog.setReadOnly(True)
        self._evlog.setLineWrapMode(QTextEdit.NoWrap)
        self._evlog.document().setMaximumBlockCount(200)  # 自动裁剪最旧行
        lay.addWidget(self._evlog)
        self._scanline = QLabel("待命中…")
        self._scanline.setObjectName("scanline")
        lay.addWidget(self._scanline)
        # scanline 转圈
        self._spin_chars = "|/-\\"
        self._spin_i = 0
        self._spin_timer = QTimer(self)
        self._spin_timer.timeout.connect(self._spin_scanline)
        return card

    def _build_gauge_throughput(self):
        card, lay = make_card("威胁指数", min_h=240)
        self.gauge = GaugeWidget()
        lay.addWidget(self.gauge, 1)
        # 发现速率
        rate_title = QLabel("▌ 发现速率")
        rate_title.setObjectName("cardTitle")
        lay.addWidget(rate_title)
        row = QHBoxLayout()
        self._rate_num = QLabel("0")
        self._rate_num.setObjectName("throughputNum")
        unit = QLabel("项/秒")
        unit.setObjectName("throughputUnit")
        row.addWidget(self._rate_num)
        row.addWidget(unit)
        row.addStretch()
        self._rate_total = QLabel("累计 0")
        self._rate_total.setObjectName("throughputUnit")
        row.addWidget(self._rate_total)
        lay.addLayout(row)
        self.spark = Sparkline(T.ACCENT2)
        lay.addWidget(self.spark)
        # 每秒采样发现增量
        self._last_total = 0
        self._rate_timer = QTimer(self)
        self._rate_timer.timeout.connect(self._sample_rate)
        self._rate_timer.start(1000)
        return card

    def _build_host_table(self):
        card, lay = make_card("扫描主机（实时刷新）", min_h=190)
        self._htbl = _mk_table(
            ["IP 地址", "端口", "协议", "设备指纹", "响应", "鉴权", "状态"], [0])
        lay.addWidget(self._htbl)
        self._host_hint = QLabel("等待扫描数据…  在「SIP扫描」页发起扫描后实时出现")
        self._host_hint.setStyleSheet(f"color:{T.MUTED};")
        self._host_hint.setAlignment(Qt.AlignCenter)
        lay.addWidget(self._host_hint)
        return card

    def _build_findings_table(self):
        card, lay = make_card("分机 & 凭证发现（实时刷新）", min_h=190)
        self._ftbl = _mk_table(
            ["类型", "目标 IP", "端口", "协议", "分机/用户", "口令/响应", "来源"], [0])
        lay.addWidget(self._ftbl)
        self._find_hint = QLabel("等待数据…  在「分机枚举」或「密码破解/离线破解」页操作后实时出现")
        self._find_hint.setStyleSheet(f"color:{T.MUTED};")
        self._find_hint.setAlignment(Qt.AlignCenter)
        lay.addWidget(self._find_hint)
        return card

    # -------------------- 数据订阅 --------------------
    def _connect_store(self):
        self.ds.host_found.connect(self._on_host)
        self.ds.exten_found.connect(self._on_exten)
        self.ds.cred_found.connect(self._on_cred)
        self.ds.cve_updated.connect(self._on_cve)
        self.ds.cleared.connect(self._on_cleared)
        self.ds.scan_started.connect(self._on_scan_started)
        self.ds.scan_finished.connect(self._on_scan_finished)

    def _on_cleared(self, scope):
        if scope in ("hosts", "all"):
            self._htbl.setRowCount(0)
            self._host_hint.setVisible(True)
            self.kpi_cve.set_value(0)
            self.kpi_hosts.reset_scale()
            self._last_cve = 0
        if scope in ("extensions", "creds", "all"):
            self._rebuild_findings_table()
            self.kpi_ext.reset_scale()
            self.kpi_cred.reset_scale()
        if scope == "all":
            self.radar.clear_blips()
            self._trend_pts = [0] * 24
            self._refresh_line()
            self._evlog.clear()
        self._refresh_aggregates()

    def _on_host(self, host):
        self._host_hint.setVisible(False)
        self.radar.ping()
        self._add_host_row(host)
        self._log_event(T.OK, f"[OK] {host['ip']}:{host['port']}/{host['proto']}  "
                              f"{host['fp'] or host['ua'] or '-'}  <{host['response']}>")
        self._refresh_aggregates()

    def _on_exten(self, ext):
        self._find_hint.setVisible(False)
        self.radar.ping()
        self._add_finding_row("分机", ext["ip"], ext["port"], ext["proto"],
                              ext["exten"], ext["response"], "枚举", T.ACCENT2)
        noauth = "  ⚠ 无需鉴权" if ext.get("auth") == "none" else ""
        self._log_event(T.ACCENT2, f"[EXT] {ext['ip']} 分机 {ext['exten']} "
                                   f"存在 <{ext['response']}>{noauth}")
        self._refresh_aggregates()

    def _on_cred(self, cred):
        self._find_hint.setVisible(False)
        self.radar.ping()
        self._add_finding_row("凭证", cred["ip"], cred["port"], cred["proto"],
                              cred["user"], cred["pwd"], cred["source"], T.ERR)
        self._log_event(T.ERR, f"[HIT] {cred['ip']} 分机 {cred['user']} "
                               f"口令破解成功 → {cred['pwd']}  ({cred['source']})")
        self._show_toast("凭证破解", f"{cred['ip']} · {cred['user']} / {cred['pwd']}")
        self._refresh_aggregates()

    def _on_cve(self, n):
        self.kpi_cve.set_value(n)
        if n > self._last_cve:
            self._log_event(T.ERR, f"[VULN] 命中 {n} 个已知漏洞（CVE）")
            self._show_toast("漏洞告警", f"已发现 {n} 个已知漏洞，请研判")
        self._last_cve = n
        self._refresh_aggregates()

    def _refresh_aggregates(self):
        self.kpi_hosts.set_value(len(self.ds.hosts))
        self.kpi_ext.set_value(len(self.ds.extensions))
        self.kpi_cred.set_value(len(self.ds.creds))
        dist = self.ds.proto_distribution()
        for name, col in self._proto_order:
            self._slices[name].setValue(dist.get(name, 0))
            row, c = self._legend_labels[name]
            row.setText(self._legend_text(name, c, dist.get(name, 0)))
        rdist = self.ds.response_distribution()
        peak = 10
        for i, cat in enumerate(self._bar_cats):
            v = rdist.get(cat, 0)
            self._barsets[i].replace(i, v)
            peak = max(peak, v + 2)
        self._bar_y.setRange(0, peak)
        # 威胁指数
        score = min(100, len(self.ds.hosts) * 2 + len(self.ds.extensions) * 2
                    + len(self.ds.creds) * 10 + self.ds.cve_count * 16)
        self.gauge.set_score(score)
        # 阶段 done 状态随数据刷新
        self._refresh_phases()

    def _refresh_phases(self):
        has = {
            "scan": len(self.ds.hosts) > 0,
            "exten": len(self.ds.extensions) > 0,
            "crack": len(self.ds.creds) > 0,
            "vuln": self.ds.cve_count > 0,
            "report": self.ds.total_findings() > 0,
        }
        self.phase_bar.update_states(has)

    # -------------------- 行操作 --------------------
    def _add_host_row(self, host):
        self._htbl.insertRow(0)
        cells = [host["ip"], host["port"], host["proto"],
                 host["fp"] or host["ua"] or "—", host["response"], host["auth"]]
        for c, val in enumerate(cells):
            item = QTableWidgetItem(str(val))
            if c == 3:
                item.setForeground(_qc(T.ACCENT))
            self._htbl.setItem(0, c, item)
        alive = host["response"].startswith(("200", "401", "407"))
        st = QTableWidgetItem("● " + ("存活" if alive else "响应"))
        st.setForeground(_qc(T.OK if alive else T.WARN))
        self._htbl.setItem(0, 6, st)
        while self._htbl.rowCount() > 200:
            self._htbl.removeRow(self._htbl.rowCount() - 1)

    def _add_finding_row(self, kind, ip, port, proto, who, val, source, kind_color):
        self._ftbl.insertRow(0)
        cells = [kind, ip, port, proto, who, val, source]
        for c, cv in enumerate(cells):
            item = QTableWidgetItem(str(cv))
            if c == 0:
                item.setForeground(_qc(kind_color))
            elif c == 4:
                item.setForeground(_qc(T.ACCENT))
            elif c == 5 and kind == "凭证":
                item.setForeground(_qc(T.ERR))
            self._ftbl.setItem(0, c, item)
        while self._ftbl.rowCount() > 300:
            self._ftbl.removeRow(self._ftbl.rowCount() - 1)

    def _rebuild_findings_table(self):
        self._ftbl.setRowCount(0)
        for ext in self.ds.extensions:
            self._add_finding_row("分机", ext["ip"], ext["port"], ext["proto"],
                                  ext["exten"], ext["response"], "枚举", T.ACCENT2)
        for cred in self.ds.creds:
            self._add_finding_row("凭证", cred["ip"], cred["port"], cred["proto"],
                                  cred["user"], cred["pwd"], cred["source"], T.ERR)
        self._find_hint.setVisible(self._ftbl.rowCount() == 0)

    # -------------------- 阶段 / scanline --------------------
    _KIND2PHASE = {"scan": "scan", "exten": "exten", "rcrack": "crack", "dcrack": "crack"}

    def _on_scan_started(self, kind):
        self.phase_bar.set_running(self._KIND2PHASE.get(kind))
        self._refresh_phases()
        names = {"scan": "资产扫描", "exten": "分机枚举",
                 "rcrack": "远程口令破解", "dcrack": "离线口令破解"}
        self._log_event(T.ACCENT, f"[*] 开始{names.get(kind, kind)} …")
        self._scanline.setText("[|] 探测中 …")
        if not self._spin_timer.isActive():
            self._spin_timer.start(120)

    def _on_scan_finished(self, kind):
        self.phase_bar.set_running(None)
        self._refresh_phases()
        self._spin_timer.stop()
        if kind == "scan":
            self._scanline.setText(
                f"[✓] 扫描完成：发现 {len(self.ds.hosts)} 台主机")
        else:
            self._scanline.setText("[✓] 任务完成")
        self._log_event(T.OK, "[✓] 当前任务结束")

    def _spin_scanline(self):
        self._spin_i = (self._spin_i + 1) % len(self._spin_chars)
        self._scanline.setText(f"[{self._spin_chars[self._spin_i]}] 探测中 …")

    # -------------------- 发现速率 --------------------
    def _sample_rate(self):
        total = self.ds.total_findings()
        rate = max(0, total - self._last_total)
        self._last_total = total
        self.spark.push(rate)
        self._rate_num.setText(str(rate))
        self._rate_total.setText(f"累计 {total}")

    # -------------------- 事件流 --------------------
    def _log_event(self, color, text):
        ts = time.strftime("%H:%M:%S")
        esc = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        html = (f'<span style="color:{T.MUTED}">{ts}</span> '
                f'<span style="color:{color}">{esc}</span>')
        self._evlog.append(html)
        sb = self._evlog.verticalScrollBar()
        sb.setValue(sb.maximum())

    # -------------------- 告警 Toast --------------------
    def _show_toast(self, title, body):
        toast = ToastWidget(title, body, self)
        self._toasts.append(toast)
        self._reposition_toasts()
        idx = self._toasts.index(toast)
        toast.slide_in(self._toast_pos(toast, idx))
        QTimer.singleShot(4200, lambda: self._dismiss_toast(toast))

    def _dismiss_toast(self, toast):
        if toast not in self._toasts:
            return

        def done():
            if toast in self._toasts:
                self._toasts.remove(toast)
            toast.deleteLater()
            self._reposition_toasts()

        toast.fade_out(done)

    def _toast_pos(self, toast, idx):
        x = self.width() - toast.width() - 24
        y = 24
        for t in self._toasts[:idx]:
            y += t.height() + 10
        return QPoint(x, y)

    def _reposition_toasts(self):
        y = 24
        for t in self._toasts:
            x = self.width() - t.width() - 24
            t.move(QPoint(x, y))
            y += t.height() + 10

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._reposition_toasts()
