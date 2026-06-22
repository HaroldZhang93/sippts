# 仪表盘 demo 效果落地设计（PyQt5）

日期：2026-06-22
分支：gui-sippts
参考原型：`docs/ui-demo.html`
目标文件：`src/sippts/gui/modules/dashboard_tab.py`、`src/sippts/gui/theme.py`

## 背景

`docs/ui-demo.html` 是一份录屏用的纯前端演示，展示了一个 SIP 安全审计仪表盘。
现有 `dashboard_tab.py`（PyQt5 + QtChart）已实现其中：KPI 计数卡、QPainter 雷达、
协议环形图、发现趋势面积图、响应状态柱状图、主机表、分机&凭证表，并通过
`common/data_store.py:DataStore` 单例订阅核心模块的实时结果。

本设计在**不改动任何核心 CLI 模块**的前提下，补齐 demo 相对现有仪表盘多出的元素。

## 框架决策

继续使用 **PyQt5**（全工程一致，含 QtChart 与打包 spec）。不迁移 PySide6。

## 数据来源

所有新元素订阅同一个 `DataStore` 单例，零侵入核心模块。可用信号：
- `host_found` / `exten_found` / `cred_found` / `cve_updated` / `cleared(scope)`
- `scan_started(kind)` / `scan_finished(kind)`，`kind ∈ {scan, exten, rcrack, dcrack}`

## 新增元素

### 1. 威胁指数半圆仪表盘 `GaugeWidget`（真实数据）
QPainter 自绘半圆背景弧 + 进度弧 + 指针 + 中心分数文字。
分数 = `主机×2 + 分机×2 + 凭证×10 + 漏洞×16`，封顶 100；绿(<33)/琥珀(<66)/红 三段着色。
在 `_refresh_aggregates()` 末尾调用 `set_score(...)` 实时更新。

### 2. 告警 Toast 浮层 `ToastManager` / `ToastWidget`（真实信号）
`DashboardTab` 顶层子控件，右上角定位；`QPropertyAnimation` 滑入 + `QGraphicsOpacityEffect`
淡出，`QTimer.singleShot(~4.2s)` 自动消失。触发：
- `cve_updated` 漏洞数增加（用 `_last_cve_count` 去重）→ 弹「漏洞告警」
- `cred_found` → 弹「凭证破解」
`DashboardTab.resizeEvent` 重新定位活动 toast。

### 3. 实时事件流终端 `EventLogWidget`（真实数据）
卡片内嵌只读 `QTextEdit`（objectName=`termOutput` 复用终端样式），订阅四个发现信号，
按 demo 格式输出带时间戳的彩色行（`[OK]`/`[EXT]`/`[HIT]`/`[VULN]`），上限 ~200 行。
底部 `scanline`：`QLabel` + `QTimer`，在 `scan_started`→`scan_finished` 期间循环 `|/-\`
转圈，结束显示「✓ 扫描完成」。

### 4. KPI 进度条（代理数据）
给现有 `KPICard` 底部加细 `QProgressBar`。无固定分母，采用**滚动最大值**
（bar = 当前值 / 本轮见过最大值，带下限），保证比例直观且不虚构上限。

### 5. 阶段进度条 `PhaseBar`（诚实推导）
5 段：资产扫描 / 分机枚举 / 口令破解 / 漏洞研判 / 生成报告。
由 `scan_started(kind)` 映射当前活动阶段（scan→①，exten→②，rcrack/dcrack→③），
有漏洞数据时点亮④；已有数据的前序阶段标记 done；空闲显示待命。
QSS 属性选择器按 `state ∈ {idle, active, done}` 切换配色。

### 6. 探测吞吐 sparkline `ThroughputWidget` / `Sparkline`（真实采样）
标题由 demo 的「pkt/s」**改为「发现速率」**。每 ~1s 采样 `DataStore.total_findings()`
增量，维护近 40 个样本，QPainter 自绘折线；上方 `QLabel` 显示当前速率。

## 取舍（已与用户确认）

- (a) 不实现 demo 的「扫描进度 0/254」假计数器；保留现有 4 个 KPI（主机/分机/凭证/漏洞）+ 进度条。
- (b) 吞吐图标签由「pkt/s」改为「发现速率」，基于真实发现增量采样，不伪造数据包速率。

## 布局（`DashboardTab._build()` 网格重排）

```
row0: PhaseBar              (整行)
row1: KPI 行（4 卡 + 进度条） (整行)
row2: 雷达        | 协议环形图
row3: 发现趋势    | 响应状态柱状图
row4: 实时事件流  | 威胁指数仪表盘 + 发现速率 sparkline（右列堆叠）
row5: 主机表               (整行)
row6: 分机&凭证表          (整行)
Toast: 顶层浮层，不入网格
```

## 不改动

核心模块、`run_module`/监控轮询、现有雷达/环形/趋势/柱状/两张表全部保留；
新元素仅在 `DashboardTab._build()` 加卡片、在信号回调加少量调用。

## 验证

- `python -c "import sippts.gui.modules.dashboard_tab"` 无导入错误。
- 启动 GUI，仪表盘正常显示所有新卡片；在 SIP 扫描/枚举/破解页操作后，
  事件流、仪表盘分数、阶段条、Toast、KPI 进度条、发现速率均随真实数据更新。
