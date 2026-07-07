# SIPPTS / IMS 安全测试平台 —— 项目面试通关文档（含代码示例）

> 用途：面试中完整、自信地讲清这个项目。涵盖整体架构、技术栈、数据流向、前后端设计、
> UI 控件、关键难点，**每个要点都配真实代码片段 + 讲解话术**。
> 用法：先背熟「一分钟电梯陈述」「整体架构」「GUI 数据流」，再按面试官追问深入对应章节，
> 对着代码讲「为什么这么写、解决了什么问题」。

---

## 0. 一分钟电梯陈述（开场白）

> 「这是一个面向 **VoIP / SIP 协议**的安全审计工具平台。底层是一套 Python 写的 SIP 渗透测试
> 引擎（扫描、分机枚举、密码破解、抓包分析、RTP/ARP 攻击等十几个模块），原本只有命令行。
> 我在它之上做了一个 **PyQt5 桌面 GUI**：把每个 CLI 能力封装成一个功能 Tab，并新增了一个用
> **QtCharts** 实现的『总览仪表盘』，把扫描/枚举/破解结果实时可视化（KPI、雷达、协议环形图、
> 趋势折线、结果表）。架构核心是 **GUI 复用 CLI 核心类、零侵入**：通过重定向标准输出捕获日志、
> 通过定时轮询模块结果列表喂给一个单例数据中心，再用 Qt 信号槽驱动界面刷新。整体是分层 +
> 事件驱动设计。」

一句话定位：**「SIP 协议安全审计工具的桌面化与可视化：前端 PyQt5 + QtChart，后端是多线程 SIP 协议引擎，二者通过 stdout 重定向 + 单例数据总线松耦合。」**

---

## 1. 项目背景与功能

- **SIP（Session Initiation Protocol）**：VoIP/IMS 网络里建立、修改、终止通话会话的信令协议
  （文本协议，类似 HTTP；方法有 REGISTER / INVITE / OPTIONS / ACK / BYE / CANCEL）。
  语音流走 **RTP**，控制走 **RTCP**，媒体协商用 **SDP**。
- 工具用途：**审计 SIP 服务器/话机/PBX（Asterisk、FreePBX、Grandstream 等）的安全性**。
- 它基于开源项目 [Pepelux/sippts](https://github.com/Pepelux/sippts) 二次开发（分支 `gui-sippts`），
  我主要做了 **GUI + 可视化仪表盘 + 两个新模块（RTP 劫持、增强 ARP 欺骗）**。

### 功能模块（= GUI 的 14 个 Tab）
| Tab | 模块类 | 作用 |
|---|---|---|
| 总览 | `DashboardTab` | 实时可视化仪表盘（新增） |
| SIP扫描 | `SipScan` | 多线程扫 SIP 服务/设备 + 指纹 + CVE 提示 |
| 分机枚举 | `SipExten` | 枚举 PBX 分机号、是否需鉴权 |
| 密码破解 | `SipRemoteCrack` | 远程在线爆破分机口令 |
| 数据分析 | `SipDump`/`SipPcapDump` | 从 PCAP 提取 SIP Digest 认证 |
| 压力测试 | `SipFlood` | 洪水包（DoS 测试） |
| Digest泄露 | `SipDigestLeak` | 利用 SIP Digest Leak 漏洞 |
| 离线破解 | `SipDigestCrack` | 对抓到的 Digest 字典/暴力破解 |
| 消息伪造 | `SipSend` | 构造发送自定义 SIP 报文 |
| SIP嗅探 | `SipSniff` | 网卡抓 SIP 流量 |
| RTP Bleed / RTP注入 | `RTPBleed`/`RTPBleedInject` | 检测/利用 RTP Bleed |
| RTP劫持 | `RTPHijack` | 劫持 RTP 媒体流（新增） |
| ARP欺骗 | `ArpSpoof` | ARP 中间人（增强） |

---

## 2. 技术栈与框架

| 层 | 技术 | 说明 |
|---|---|---|
| 语言 | **Python 3.12** | 全部代码 |
| 桌面框架 | **PyQt5 (Qt 5.15)** | 信号槽、QWidget、QSS |
| 图表 | **PyQtChart (QtChart)** | 折线/面积/环形/柱状 |
| 自绘 | **QPainter** | 雷达扫描动画 |
| 网络 | 原生 **socket**（UDP/TCP/TLS）自拼 SIP 报文 | 不用第三方 SIP 栈 |
| 抓包 | **scapy**、**pyshark**（依赖系统 `tshark`） | 嗅探、PCAP 解析 |
| 并发 | **threading / ThreadPoolExecutor**（核心）、**QThread**（GUI） | |
| 打包 | **PyInstaller**（`sippts.spec`）→ 单文件 exe | |

> 高频追问「为什么不用现成 SIP 库？」——渗透工具需要**精确构造畸形/自定义报文**，
> 现成协议栈会自动「纠正」，反而做不了攻击测试，所以用字符串手拼（`functions.create_message`）。

---

## 3. 整体架构（分层）

```
 入口层:  bin/sippts(CLI)   bin/sippts-gui(REPL)   gui/app.py(GUI)
            │                                        │
 参数层:  lib/params.py(argparse→位置元组)           │
            │  属性注入+start()                       │ 复用同一批核心类
            └───────────────┬────────────────────────┘
 核心引擎层: src/sippts/*.py   SipScan/SipExten/SipSniff/ArpSpoof...
            （统一契约：实例化→设属性→start()/stop()）
            │
 公共能力层: src/sippts/lib/functions.py（SIP报文构造/解析/Digest/指纹/CVE）
                              color.py(ANSI颜色)  data/cve.csv
 前端GUI层:  gui/  MainWindow / BaseTab / 各Tab / theme.py(QSS)
                   DashboardTab(QtChart+雷达) / data_store.py(数据总线)
```

**设计模式**：分层架构 + 命令模式（每模块一个命令类）+ 单例（ConfigManager、DataStore）+
观察者/发布订阅（Qt 信号槽）+ 模板方法（BaseTab）。

---

## 4. 数据流向（最常被追问，配代码）

### 4.1 CLI 路径
```
命令行 → params.get_sippts_args()（argparse 解析为位置元组）
       → bin/sippts 按命令名解包元组、赋值给实例属性 → s.start()
       → ThreadPoolExecutor 并发收发 socket
       → functions.create_message() 拼报文 / parse_message() 解析
       → print(带 ANSI 颜色) 输出到终端
```

### 4.2 GUI 路径（核心亮点，**重点讲**）

**第 1 步：Tab 收集表单 → 构造模块实例**（`scan_tab.py`）
```python
def start_module(self):
    self.module_instance = SipScan()                      # 1. 无参实例化核心类
    # 2. 把界面控件的值写到实例属性上（UiTools 做映射）
    UiTools.set_option_scan(self.module_instance, "ip", self.ip_input.text(), False, True)
    UiTools.set_option_scan(self.module_instance, "rport", self.port_input.text(), False, True)
    # ... 其余字段同理
    self.on_module_started()                              # 3. 禁用"开始"、启用"停止"
    self.main_window.run_module(                          # 4. 交给主窗口去跑
        self.module_instance, self.on_module_finished)
```

**第 2 步：主窗口起子线程 + 重定向输出 + 起数据轮询**（`main_window_new.py`）
```python
def run_module(self, module_instance, on_finished_callback):
    self.stop_module()                                    # 先停掉上一个
    current_tab = self.tabs.currentWidget()
    self.setup_logging(current_tab.result_text)           # 绑定日志信号到这个终端控件
    sys.stdout = self.log_manager                         # ① 关键：重定向标准输出

    self.current_worker = ModuleWorker(module_instance)   # ② 包一个 QThread
    self.current_worker.finished.connect(on_finished_callback)
    self.current_worker.finished.connect(self._stop_scan_monitor)
    self.current_worker.start()                           # 子线程里跑 mod.start()

    if type(module_instance).__name__ in self.MONITORED:  # ③ 受监控模块→起数据轮询
        self._start_scan_monitor(module_instance)
```

**第 3 步：模块的 print 被转成 Qt 信号**（`LogManager` 假扮 stdout 文件对象）
```python
class LogManager(QObject):
    log_signal = pyqtSignal(str)          # 一条日志一个信号
    def write(self, text):                # print 最终调用的就是 stdout.write
        self.log_signal.emit(str(text))
    def flush(self):                      # 兼容 stdout 接口
        pass
```
```python
class ModuleWorker(QThread):              # 在子线程跑阻塞的 start()，不卡 UI
    finished = pyqtSignal()
    error = pyqtSignal(str)
    def __init__(self, mod):
        super().__init__(); self.mod = mod
    def run(self):
        try:
            self.mod.start()
        except Exception as e:
            self.error.emit(f"模块执行时出错: {e}")
        finally:
            self.finished.emit()          # 无论成败都通知主线程恢复 UI
```
> 讲解：**子线程不直接碰 UI**，而是发信号，主线程的槽函数（`append_log`）来更新界面——
> 这是 Qt 官方的跨线程安全方式（队列连接）。

**第 4 步：数据桥——定时轮询模块的 `found` 列表喂给数据总线**
```python
MONITORED = {                              # 类名 → (kind, 启动清空范围)
    "SipScan": ("scan", "hosts"),
    "SipExten": ("exten", "extensions"),
    "SipRemoteCrack": ("rcrack", None),    # None=累计不清空
    "SipDigestCrack": ("dcrack", None),
}

def _poll_scan_data(self):                 # QTimer 每 400ms 调一次
    mod = self._scan_mod
    lines = list(getattr(mod, "found", []))   # 快照，避免与子线程并发修改
    for line in lines:
        if self._scan_kind == "scan":
            host = parse_found_line(line)      # 'ip###port###proto###resp###ua###type###fp'
            if host:
                DataStore().add_host(host)     # 去重后存入单例 + 发信号
```
> 讲解：核心模块只会往 `self.found` 里 append 字符串、不会主动通知 GUI（它是为 CLI 写的）。
> 所以我**不改核心代码**，而是用 QTimer **外部轮询 + 按 key 去重**，最省事可靠。

**第 5 步：仪表盘订阅信号刷新**（`dashboard_tab.py`）
```python
def _connect_store(self):
    self.ds.host_found.connect(self._on_host)      # 来一台主机刷一次
    self.ds.exten_found.connect(self._on_exten)
    self.ds.cred_found.connect(self._on_cred)
    self.ds.cleared.connect(self._on_cleared)

def _on_host(self, host):
    self.radar.ping()                # 雷达点亮一个 blip
    self._add_host_row(host)         # 结果表插一行
    self._refresh_aggregates()       # KPI/环形图/柱状图重算
```

**一句话总结两条「桥」**：
1. **日志桥** = `sys.stdout` 重定向到 `LogManager` → `print` 变信号 → 终端着色显示；
2. **数据桥** = `QTimer` 轮询 `found` → 解析去重 → `DataStore` 单例 → 信号 → 仪表盘。
**核心引擎对 GUI 完全无感知（解耦）。**

---

## 5. 前端架构（PyQt5）

### 5.1 窗口结构
```
QMainWindow
└─ central QWidget (QVBoxLayout)
   ├─ QFrame#hudHeader：标题 + 实时时钟(QTimer) + ● ONLINE
   └─ QTabWidget（14 个 Tab）
      ├─ DashboardTab（总览）
      └─ ScanTab / ExtenTab / ...（均继承 BaseTab）
```

### 5.2 BaseTab —— 模板方法 + 自动配置持久化
```python
class BaseTab(QWidget):
    def setup_ui(self):      raise NotImplementedError   # 子类必须实现（模板方法）
    def start_module(self):  raise NotImplementedError

    def create_result_text(self, layout, row, col_span=4):
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setObjectName("termOutput")     # 命中全局 QSS 主题
        self.result_text.setLineWrapMode(QTextEdit.NoWrap)  # 终端风格不折行
        layout.addWidget(self.result_text, row, 0, 1, col_span)

    def save_input_values(self, save_immediately=False):
        config = {}
        for w in self.findChildren(QLineEdit):           # 自动遍历所有命名控件
            if w.objectName():
                config[w.objectName()] = w.text()
        for w in self.findChildren(QComboBox):
            if w.objectName():
                config[w.objectName()] = w.currentText()
        # QCheckBox 同理 → 按"Tab类名"存进 gui_config.json
        self.config_manager.save_tab_config(self.__class__.__name__, config, save_immediately)
```
> 讲解：基类定义骨架（模板方法），子类只填 `setup_ui`/`start_module`；配置持久化**零样板**——
> 只要控件设了 `objectName`，关窗时自动保存、开窗时自动回填。

### 5.3 常用 UI 控件清单（可能被逐个问"这控件干嘛"）
| 控件 | 用途 |
|---|---|
| `QTabWidget`/`QTabBar` | 顶部功能切换 |
| `QGridLayout`(4 列:标签:输入:标签:输入) | 表单主布局 |
| `QHBoxLayout`/`QVBoxLayout` | 行/列、按钮行、文件选择行 |
| `QGroupBox` | 参数分组面板 |
| `QLabel` | 标签/提示/KPI 数字/HUD 标题 |
| `QLineEdit` | 文本输入（设 objectName 才持久化） |
| `QComboBox` | 下拉（协议、方法、详细度） |
| `QCheckBox` | 开关项 |
| `QPushButton` | 开始`#primaryBtn`/停止`#dangerBtn`/选择文件 |
| `QTextEdit#termOutput` | 黑色终端日志（只读、等宽、NoWrap） |
| `QFileDialog` | 选 PCAP/字典/输出文件 |
| `QTableWidget` | 仪表盘结果表 |
| `QScrollArea` | 包裹仪表盘可滚动 |
| `QChartView/QChart` | QtChart 图表 |
| 自定义 `RadarWidget(QWidget)` | QPainter 画雷达 |
| `QMessageBox` | 全局异常弹窗 |
| `QProgressBar` | 进度条 |

### 5.4 视觉主题（theme.py）—— 一份全局 QSS
```python
APP_QSS = f"""
QTabBar::tab:selected {{ color: {ACCENT}; border-bottom: 2px solid {ACCENT}; }}
QLineEdit:focus       {{ border: 1px solid {ACCENT}; }}        /* 聚焦变青 */
QPushButton#primaryBtn{{ background-color: {ACCENT}; color: #042022; }}  /* 开始钮青填充 */
QPushButton#dangerBtn {{ color: {ERR}; border: 1px solid {ERR}; }}      /* 停止钮红描边 */
QTextEdit#termOutput  {{ background-color: {TERM_BG}; color: {TERM_FG};
                          font-family: {MONO_FONT}; }}
"""
def apply_theme(app):
    app.setStyleSheet(APP_QSS)        # 在 QApplication 级别注入，自动级联所有控件
```
> 讲解：原项目没有任何全局样式，全是系统默认灰。我**集中加一套全局 QSS**，用 `objectName`
> （`#id` 选择器）区分按钮变体——一处定义、全局换肤，不用改 13 个 Tab。
> 局限：玻璃模糊/霓虹辉光 QSS 做不了（用青描边+深色层次近似）；**QtChart 不认 QSS**，图表样式得代码里设。

按钮角色是**集中批量设置**的（DRY）：
```python
def _apply_button_roles(self):
    for i in range(self.tabs.count()):
        tab = self.tabs.widget(i)
        for attr, role in (("start_btn", "primaryBtn"), ("stop_btn", "dangerBtn")):
            btn = getattr(tab, attr, None)
            if btn is not None:
                btn.setObjectName(role)
                btn.style().unpolish(btn); btn.style().polish(btn)  # 重新应用样式
```

### 5.5 仪表盘亮点代码

**自定义雷达（QPainter + QTimer 动画）**
```python
class RadarWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._angle = 0.0
        self._timer = QTimer(self); self._timer.timeout.connect(self._spin)
        self._timer.start(33)                  # ~30fps

    def _spin(self):
        self._angle = (self._angle + 2.2) % 360
        self.update()                          # 触发 paintEvent 重绘

    def paintEvent(self, _):
        p = QPainter(self); p.setRenderHint(QPainter.Antialiasing)
        # 同心圆 + 十字 + 圆锥渐变扫描扇区（随 _angle 旋转）+ 渐隐 blip
        grad = QConicalGradient(cx, cy, -self._angle)
        grad.setColorAt(0.0, _qc(T.ACCENT, 130)); grad.setColorAt(0.2, _qc(T.ACCENT, 0))
        p.setBrush(QBrush(grad)); p.drawEllipse(...)
```

**KPI 数字滚动动画**
```python
def set_value(self, v):
    self._target = int(v)
    if not self._t.isActive(): self._t.start(30)
def _step(self):
    diff = self._target - self._cur
    self._cur += max(1, abs(diff)//6) * (1 if diff>0 else -1)   # 缓动逼近
    self.num.setText(f"{self._cur:,}")
```

---

## 6. 后端 / 核心引擎设计

### 6.1 统一契约（属性注入，不是构造函数传参）
```python
# CLI 用法（bin/sippts 把 argparse 元组解包后逐项赋值）：
s = SipScan()
s.ip = ip; s.rport = rport; s.proto = proto; s.threads = nthreads
# ... 几十个属性
s.start()        # 运行；s.stop() 中止
```
> 好处：CLI 和 GUI 都能给同一套类赋值后 `start()`，最大化复用。
> 代价：参数全靠约定，**没有类型/必填校验**（可改进点，见 §10）。

### 6.2 并发模型
```python
# 核心模块：线程池并发探测大量 IP/端口（I/O 密集）
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=nthreads) as executor:
    for target in targets:
        executor.submit(self.scan_host, target)
```
- **GUI**：模块 `start()` 放进 `ModuleWorker(QThread)` 子线程，避免阻塞 UI 主线程；
  数据/日志通过**信号**回主线程更新。

### 6.3 SIP 协议处理（lib/functions.py 是"弹药库"）

**响应解析**（正则抽状态码/UA/头部）
```python
def parse_message(buffer):
    data = {"response_code": "", "response_text": "", "ua": "", "type": "Unknown"}
    for header in buffer.split("\r\n"):
        m = re.search(r"^SIP\/[0-9|\.]+\s([0-9]+)\s(.+)", header)   # 如 "SIP/2.0 401 Unauthorized"
        if m:
            data["response_code"] = m.group(1)    # 401
            data["response_text"] = m.group(2)    # Unauthorized
        # 解析 From/To/User-Agent/Via... 略
    return data
```
> 扫描/枚举就是看 `response_code`：200=存在、401/407=存在但要鉴权、404=不存在。

**Digest 认证计算**（口令破解的核心）
```python
def calculateHash(username, realm, pwd, method, uri, nonce, algorithm, cnonce, nc, qop, ...):
    # 标准 HTTP Digest 算法：
    ha1 = getHash(algorithm, f"{username}:{realm}:{pwd}")   # HA1 = MD5(user:realm:pass)
    ha2 = getHash(algorithm, f"{method}:{uri}")             # HA2 = MD5(method:uri)
    if qop in ("auth", "auth-int") and cnonce:
        b = f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"
    else:
        b = f"{ha1}:{nonce}:{ha2}"                          # response = MD5(HA1:nonce:HA2)
    return getHash(algorithm, b)
```
> 讲解：SIP 鉴权用 HTTP Digest（realm + nonce + MD5）。服务器回 401 带挑战(nonce)，
> 客户端用上式算 response 再发。**破解**就是抓到挑战后，本地拿字典里每个口令套这个公式算
> response，和抓到的真实 response 比对，命中即口令正确（离线破解），或直接发 REGISTER 看是否回
> 200（在线爆破）。

其它：`fingerprinting()`+`check_model()`+`data/cve.csv` 做设备指纹与 CVE 匹配；
`enable/disable_ip_route()` 在 ARP 欺骗时开关系统 IP 转发（跨平台）。

---

## 7. 关键设计难点 / 亮点（**重点讲，配代码**）

### 7.1 GUI 复用 CLI 核心、零侵入
两条桥（§4.2）：stdout 重定向拿日志 + QTimer 轮询 `found` 拿数据。价值：低耦合、易维护、与上游同步成本低。

### 7.2 终端回车（`\r`）流式渲染（我修过的真实 bug）
**现象**：扫描进度用 `print(..., end="\r")` 在终端**同一行滚动刷新**，GUI 里却堆成几十行。
**原因**：`print` 常把正文和 `\r` 拆成两次写入；GUI 原来不处理 `\r`，每次都新起一行。
**修复**：实现终端语义——`\r` 只标记"待覆盖"（跨调用保持的 `self._ow`），下段文本来时清空当前行重写。
```python
def append_log(self, text_widget, text):
    cursor = text_widget.textCursor(); cursor.movePosition(QTextCursor.End)
    for tok in re.split(r'([\r\n])', text):
        if   tok == '\n':
            cursor.movePosition(QTextCursor.End); cursor.insertText('\n'); self._ow = False
        elif tok == '\r':
            self._ow = True                       # 仅标记，不删除（关键）
        elif tok:
            cursor.movePosition(QTextCursor.End)
            if self._ow:                          # 待覆盖：清空当前行后从行首重写
                cursor.movePosition(QTextCursor.StartOfBlock, QTextCursor.KeepAnchor)
                cursor.removeSelectedText(); self._ow = False
            self._insert_ansi(cursor, tok)        # 解析 ANSI 颜色后插入
```
> 讲解：考察对**终端控制字符 / 流式输出 / 状态机**的理解。难点是 `\r` 与正文分两次到达，
> 必须用跨调用标志，不能按单次写入折叠（否则单独到来的 `\r` 会把刚写的行清空）。

### 7.3 单例陷阱：QObject 重复 `__init__` 会断开信号
```python
class DataStore(QObject):
    _instance = None
    host_found = pyqtSignal(dict)
    def __new__(cls):
        if cls._instance is None:
            inst = super().__new__(cls)
            QObject.__init__(inst)          # 只初始化一次
            inst._init_state()
            cls._instance = inst
        return cls._instance
    def __init__(self):                     # 必须是 no-op！
        pass                                # 否则每次 DataStore() 都重跑 QObject.__init__，
                                            # 静默断开所有已连接的信号 → 仪表盘收不到更新
```
> 讲解：体现对 **Python 对象创建流程（`__new__` vs `__init__`）** 和 Qt 底层的理解。
> 我当时的现象是：聚合数据对、但表格不刷新——定位到每次 `DataStore()` 调用都把信号连接清空了。

### 7.4 QtChart 序列所有权陷阱（段错误 0xC0000005）
```python
# 错误：line 既作为 area 的上边界、又单独 addSeries → 双重所有权 → 崩溃
self._area = QAreaSeries(self._line, self._lower)
chart.addSeries(self._area)
chart.addSeries(self._line)        # ❌ 段错误！

# 正确：只加 area，靠它的边框笔画线；更新数据时 in-place 改点
self._area = QAreaSeries(self._line, self._lower)
self._area.setPen(QPen(_qc(T.ACCENT), 2))   # 上边界即青色折线
chart.addSeries(self._area)                  # ✅
```
> 讲解：体现踩坑排查能力——崩溃码 0xC0000005（access violation），二分定位到双重所有权。

### 7.5 其它亮点
- 全局 QSS 主题 + `objectName` 角色（§5.4）；配置持久化零样板（§5.2）。

---

## 8. 高频面试问题 & 参考答案

### Python / 并发
- **Q：有 GIL，多线程还有用吗？** A：本项目是 **I/O 密集**（大量 socket 等响应），I/O 阻塞时释放 GIL，
  多线程能显著提速；`ThreadPoolExecutor` 同时探测成百上千 IP/端口。
- **Q：GUI 为何用 QThread？** A：`start()` 是阻塞长任务，跑主线程会卡死 UI；放子线程，靠信号回主线程更新。
- **Q：跨线程更新 UI 安全吗？** A：Qt 规定 UI 只能主线程操作；子线程通过信号-槽（队列连接）投递到主线程槽更新，是官方线程安全方式。
- **Q：`__new__` 和 `__init__` 区别？**（结合 §7.3 答）A：`__new__` 创建实例、`__init__` 初始化；
  单例若不把 `__init__` 设空，每次调用都会重新初始化已有实例。

### PyQt / 前端
- **Q：信号槽是什么？** A：观察者模式实现，`emit` 信号→连接的槽被调用，支持跨线程、解耦收发方。
  本项目用于日志流、数据更新、按钮事件、worker 完成通知。
- **Q：QSS？** A：Qt 样式表，语法仿 CSS，支持伪状态(hover/focus/disabled)；我用全局 QSS + `#id` 选择器换肤。
- **Q：QtChart 为何不用 QSS？** A：QtChart 不走 QSS，用 QPen/QBrush/QColor 代码设。
- **Q：自定义控件怎么画？** A：继承 QWidget 重写 `paintEvent` 用 QPainter 画；QTimer 改参数触发 `update()` 成动画（雷达就是这么做的）。

### 架构 / 设计
- **Q：用了哪些设计模式？** A：分层、命令模式、单例、观察者、模板方法（举 BaseTab/DataStore/信号槽为例）。
- **Q：前后端怎么解耦？** A：核心引擎不知 GUI 存在；GUI 靠 stdout 重定向 + 轮询 found + DataStore 单向接入。
- **Q：新增一个模块要改哪些地方？** A：①写核心类（守统一契约）②CLI 在 params.py+bin/sippts 加分支
  ③GUI 写一个继承 BaseTab 的 Tab、init_tabs 注册 ④进仪表盘则在 MONITORED 注册 + 写解析器 + DataStore 加分支。

### SIP / 安全
- **Q：SIP 常见方法？** A：REGISTER/INVITE/OPTIONS/ACK/BYE/CANCEL；媒体走 RTP，协商用 SDP。
- **Q：分机枚举/爆破原理？** A：发 REGISTER/OPTIONS 看返回码区分存在与否、是否需鉴权；爆破带不同口令算 Digest 发 REGISTER，回 200 即正确（§6.3 代码）。
- **Q：SIP Digest 怎么破解？** A：HTTP Digest（realm+nonce+MD5），抓挑战与响应后离线字典碰撞（§6.3 `calculateHash`）。
- **Q：RTP Bleed / ARP 欺骗？** A：RTP Bleed 是设备把 RTP 发给任意来源，可窃听/注入语音；ARP 欺骗做二层中间人配合嗅探/劫持。

---

## 9. "项目是 AI 生成"的应对策略

> 原则：**不谈"谁敲的代码"，只谈"我对系统的理解、我做的设计决策、我解决的 bug"**。
> 你确实走完了需求→设计→联调→排错全过程，把这些讲透就站得住。

- **Q：这块怎么实现的，讲讲？** → 选最熟的 3 个深入：①日志桥(§4.2 代码)②`\r` 终端模拟(§7.2)
  ③DataStore 单例+轮询(§7.3/§4.2)。都有清晰"问题→原因→方案"。
- **Q：为什么这样设计？** → 用"约束驱动"答：要复用上游 CLI 类、零侵入、低风险 → 所以选 stdout 重定向 + 轮询而非改核心加回调。
- **Q：遇到什么难点/怎么调的？** → 讲三个崩溃/异常的定位过程（段错误码、最小复现、二分定位），**强调排查思路**。
- **Q：有什么不足？** → 见 §10，主动说显成熟。

---

## 10. 已知不足 & 改进方向（主动说）

- **属性注入无校验** → 引入 dataclass/pydantic 做参数模型与校验。
- **CLI 位置元组**：改 params 要同步改 bin/sippts 解包，易错 → 改 dict/命名对象。
- **数据靠轮询**：扫描末尾 `found` 会被核心 `sort+clear`，极端下最后 <400ms 结果可能漏采 → 改解析 verbose 流或给核心加回调钩子。
- **仅扫描/枚举/破解进仪表盘**：嗅探/RTP/flood 等事件型未接 → 加"事件流"面板。
- **MONITORED 用字符串类名强耦合** → 改注册表/接口。
- **无单测/CI** → 给 `parse_message`、`calculateHash` 等纯函数补测试最划算。
- **打包体积大**（全量收集 PyQt5/scapy/lxml）。

---

## 11. 关键文件速查（被问"代码在哪"时秒答）

| 关注点 | 文件 |
|---|---|
| GUI 主窗口/顶栏/日志渲染/数据轮询 | `src/sippts/gui/main_window_new.py` |
| Tab 基类（模板方法+持久化） | `src/sippts/gui/common/base_tab.py` |
| 全局主题 QSS | `src/sippts/gui/theme.py` |
| 仪表盘（QtChart+雷达） | `src/sippts/gui/modules/dashboard_tab.py` |
| 数据总线单例 | `src/sippts/gui/common/data_store.py` |
| 配置持久化单例 | `src/sippts/gui/common/config_manager.py` |
| 控件值→模块属性映射 | `src/sippts/gui/uitools.py` |
| 核心引擎（每命令一类） | `src/sippts/*.py`（如 `sipscan.py`） |
| SIP 报文/解析/Digest/指纹/CVE | `src/sippts/lib/functions.py` |
| CLI 参数解析 | `src/sippts/lib/params.py` + `bin/sippts` |
| 打包 | `sippts.spec` / `runtime_hook.py` |

---

## 12. 运行 / 构建命令

```bash
pip3 install .                         # 装依赖（PyQt5 + PyQtChart + scapy/pyshark...）
cd src/sippts/gui && python3 app.py    # 启动图形界面
sippts scan -i 192.168.0.0/24          # 纯命令行用法
pyinstaller sippts.spec                # 打包成单文件 exe（IMS攻击软件）
```
> 注意：`pyshark` 需系统装 Wireshark/`tshark`；抓包/ARP/RTP 类需管理员权限与真实网络环境。

---

## 13. 30 秒收尾陈述

> 「这个项目让我完整实践了**桌面应用的分层架构与事件驱动设计**：用 PyQt5 信号槽把多线程后端与 UI
> 解耦，用 stdout 重定向和单例数据总线在不改既有引擎的前提下接入可视化，用 QtChart/QPainter 做了
> 实时仪表盘。过程中我定位并修复了几个有代表性的问题——终端回车的流式渲染、Qt 单例信号失效、
> QtChart 序列所有权导致的崩溃——让我对 Python 对象模型、Qt 线程/绘制机制有了更深理解。
> 同时我清楚它的边界（参数无校验、靠轮询、缺测试），也知道下一步怎么演进。」
