# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this is

A fork of [Pepelux/sippts](https://github.com/Pepelux/sippts) — a Python toolkit for auditing VoIP servers/devices over the SIP protocol. This fork (branch `gui-sippts`) adds a **Chinese-localized PyQt5 desktop GUI** on top of the original CLI, plus two modules not in upstream: `rtphijack` (RTP stream hijacking) and an extended `arpspoof`. Commit messages and most GUI strings are in Chinese.

## Commands

```bash
# Install (editable) — real dep list is setup.py install_requires (see Dependencies note)
pip3 install .

# Run the CLI
sippts <command> -h           # e.g. sippts scan -i 192.168.0.0/24
python3 bin/sippts <command>  # equivalent without install

# Run the interactive console (Cmd-based REPL, separate from the CLI)
sippts-gui                     # or: python3 bin/sippts-gui

# Run the graphical GUI
cd src/sippts/gui && python3 app.py

# Build a standalone Windows executable (output name: "IMS攻击软件", console=True)
pyinstaller sippts.spec
```

There is **no test suite, linter, or CI config** in this repo. The root `*.pcap`, `*.wav`, `*.txt` files are sample/fixture data for manually exercising the dump/sniff/rtp modules.

### Dependencies
GUI uses **PyQt5** (5.15.x) plus **PyQtChart** (`PyQt5.QtChart`, used by the dashboard). Both are declared in `setup.py` `install_requires`; `sippts.spec` bundles them as hidden imports. The rest: netifaces, scapy, pyshark, websocket-client, IPy, requests, asterisk-ami, etc. `pyshark` requires `tshark` (Wireshark) on PATH. (Note: `pyproject.toml` still references a `requirements.txt` for dynamic deps that does not exist — the real dependency list is `setup.py`.)

## Architecture

### CLI core modules (`src/sippts/*.py`)
Each command maps to one standalone class — `sipscan.py:SipScan`, `sipexten.py:SipExten`, `arpspoof.py:ArpSpoof`, `rtphijack.py:RTPHijack`, etc. They follow a **uniform attribute-injection contract**, not a constructor-args one:

1. Instantiate with no args: `s = SipScan()`
2. Set each option as a plain attribute: `s.ip = ...; s.rport = ...`
3. Call `s.start()` to run; call `s.stop()` to abort.

Modules print **ANSI-colorized output directly to stdout** (colors defined in `lib/color.py`) and use `threading` / `ThreadPoolExecutor` internally for concurrency.

### CLI plumbing (`bin/sippts` + `src/sippts/lib/`)
- `lib/params.py:get_sippts_args()` parses argv and returns a **positional tuple** whose shape depends on the subcommand.
- `bin/sippts` is a large `if/elif` over `params[0]` (the command name) that unpacks that tuple and assigns each value onto the module instance, then calls `s.start()`. **When adding/changing a CLI option you must update both `params.py` (the tuple) and the matching unpack block in `bin/sippts` — the tuple is positional, so order matters.**
- `lib/functions.py` holds shared helpers (default IP/gateway detection per-OS, CVE loading). `lib/logos.py`, `lib/videos.py`, `lib/color.py` are presentation.
- CVE data ships in `src/sippts/data/cve.csv`.

### GUI (`src/sippts/gui/`)
PyQt5 app that **reuses the same CLI core module classes** rather than shelling out.

- `app.py` → imports `main_window_new.py:MainWindow` (the active window; `main_window.py` is an older variant — prefer `main_window_new.py`).
- `MainWindow.init_tabs()` registers one tab per feature. Each tab subclasses `common/base_tab.py:BaseTab`.
- A tab's `start_module()`: instantiates the core module class (e.g. `SipScan()`), populates its attributes via the `gui/uitools.py:UiTools.set_option_<command>(...)` helpers (these mirror the CLI option set per command), calls `self.on_module_started()`, then hands off to `MainWindow.run_module()`.
- `run_module()` runs the module's `start()` inside a `ModuleWorker(QThread)` and **redirects `sys.stdout` to `LogManager`**, a `QObject` that emits each write as a signal. So the GUI captures module output purely by stdout redirection — modules need no GUI awareness.
- `MainWindow.append_log()` renders that stream into the tab's `result_text` widget. It does two non-obvious things and **both must be preserved**: (1) `_insert_ansi()` splits ANSI escape sequences and maps them to Qt `QTextCharFormat` colors (`init_color_map()`); (2) it emulates a terminal — `\r` moves to line start and marks the line for overwrite (via the cross-call `self._ow` flag, reset in `setup_logging()`), `\n` starts a new line. This is required because modules print rolling progress with `print(..., end="\r")`, often splitting the text and the `\r` into separate writes; without the flag-based overwrite, every progress tick becomes a new line. The `termOutput` area is set to `NoWrap` (`BaseTab.create_result_text`) so space-padded progress lines / ASCII tables aren't folded into multiple visual lines.
- Stop flow: `MainWindow.stop_module()` calls the module instance's `stop()`, then terminates the worker thread.

### Visual theme (HUD dark theme)
`gui/theme.py` holds the **暗蓝 HUD 安全控制台** theme: color constants (`ACCENT`, `BG`, `PANEL`, `TERM_FG`, …) + a global QSS string `APP_QSS` + `apply_theme(app)`. The theme is applied once at `QApplication` level in **both** `app.py:run_gui()` and `main_window_new.py:run_gui()`, and cascades to all tabs — there is no per-tab styling to maintain. Styling targets widget types plus a few `objectName`s: `primaryBtn`/`dangerBtn` (start/stop buttons — assigned centrally in `MainWindow._apply_button_roles()`, not per tab), `termOutput` (the `BaseTab` result area), `hudHeader`/`hudLogo`/`hudTitle`/`hudClock` (the top HUD bar built in `MainWindow._build_hud_header()`), and `card`/`cardTitle`/`kpiNum` (dashboard). When adding a tab, the start/stop button roles are applied automatically as long as the buttons are exposed as `self.start_btn`/`self.stop_btn`. The ANSI→Qt color map in `init_color_map()` still drives module stdout coloring; only the default foreground was retuned to `theme.TERM_FG`.

The first tab is `modules/dashboard_tab.py:DashboardTab` — a live overview built with **QtCharts** (`QChart`/`QChartView` line+area trend, pie/donut protocol split, bar chart) plus a custom `QPainter` `RadarWidget`, KPI count-up cards, and a live `QTableWidget`. QtChart styling is done programmatically (QPen/QBrush/QColor from `theme`), since QtChart does not honor QSS. **Pitfall:** a `QLineSeries` used as a `QAreaSeries` boundary is owned by the area series — do not also `addSeries()` it (double-ownership → segfault); update its points in place for live data. The HTML design reference / prototype lives at `docs/ui-prototype.html`.

**Dashboard data wiring** (`gui/common/data_store.py:DataStore`): a singleton `QObject` signal bus that decouples the GUI's core CLI modules from the dashboard. The core modules are untouched — instead, when a monitored module is launched, `MainWindow._start_scan_monitor()` starts a `QTimer` (`_poll_scan_data`, 400ms) that snapshots the running module's `self.found` list, parses each entry, and pushes new findings (deduped) into `DataStore`. Which modules are monitored and how their `found` lines are parsed is the `MainWindow.MONITORED` registry (class name → kind, reset-scope):
- `SipScan` → `add_host` (`ip###port###proto###response###ua###type###fp`, also reads `mod.cve`); replaces `hosts` each run.
- `SipExten` → `add_extension` (`ip###port###proto###exten###response###ua`); replaces `extensions` each run.
- `SipRemoteCrack` / `SipDigestCrack` → `add_cred` (5-field `ip###port###proto###user###pwd` / 4-field `ipsrc###ipdst###user###pwd`); **accumulate** into shared `creds` (reset-scope `None`, deduped by ip:user) so both crack modules contribute.

`DataStore` tracks `hosts`/`extensions`/`creds`(+`cve_count`) and emits `host_found`/`exten_found`/`cred_found`/`cve_updated`/`cleared(scope)`. The dashboard (`DashboardTab`) subscribes and updates KPIs (主机/分机/凭证/漏洞), the radar (a blip per finding), the protocol donut + response-code bars (hosts+extensions combined), the cumulative trend, the host table, and the extensions/credentials table; it's wrapped in a `QScrollArea`. Monitor stops on worker finish or `stop_module()`. **Singleton pitfall:** `DataStore.__init__` must be a no-op — otherwise every `DataStore()` call re-runs `QObject.__init__` and silently drops all existing signal connections. To wire a new module in, add it to `MONITORED`, give a parser in `data_store.py`, and a branch in `_poll_scan_data`.

### GUI config persistence
`common/config_manager.py:ConfigManager` is a **singleton** writing `src/sippts/gui/gui_config.json`. `BaseTab.save_input_values()` / `load_input_values()` auto-persist every named widget (`QLineEdit`/`QComboBox`/`QCheckBox` with an `objectName()`) keyed by tab class name. Set `objectName()` on a widget for it to be saved/restored. Config is flushed on window close via `save_all_tab_configurations()`.

### Adding a GUI tab
1. Create `gui/modules/<name>_tab.py` subclassing `BaseTab`; implement `setup_ui()` and `start_module()`.
2. In `start_module()`, build the core module instance, set attributes (add a `set_option_<name>` to `uitools.py` if following the pattern), call `on_module_started()`, then `self.main_window.run_module(self.module_instance, self.on_module_finished)`.
3. Register it in `main_window_new.py:init_tabs()` with `self.tabs.addTab(...)`.

### Packaging (`sippts.spec`, `runtime_hook.py`)
PyInstaller spec collects all `sippts` submodules + PyQt5 + scapy/pyshark/lxml as hidden imports, bundles `data/`, Qt translations, and lxml data files. `runtime_hook.py` sets `sys._MEIPASS`, ensures `tshark` is on PATH, and creates a temp dir (`SIPPTS_TEMP`) at runtime. `build/` and `dist/` are gitignored build artifacts.
