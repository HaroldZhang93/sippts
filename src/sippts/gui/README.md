# SIPPTS GUI 模块化结构

## 目录结构

```
src/sippts/gui/
├── app.py                  # 应用程序入口点
├── main_window_new.py      # 新的主窗口实现
├── common/                 # 通用工具和基类
│   ├── __init__.py
│   ├── base_tab.py         # 所有功能标签页的基类
│   ├── file_utils.py       # 文件操作工具
│   └── log_manager.py      # 日志管理器
└── modules/                # 功能模块
    ├── __init__.py
    ├── rtpbleedinject_tab.py  # RTP注入模块
    └── ... (其他功能模块)
```

## 如何添加新的功能模块

1. 在 `modules` 目录下创建新的模块文件，例如 `scan_tab.py`
2. 新模块应继承自 `BaseTab` 类
3. 实现必要的方法：`setup_ui()` 和 `start_module()`
4. 在 `main_window_new.py` 的 `init_tabs()` 方法中导入并添加新模块

示例：

```python
# 在 modules/scan_tab.py 中
from sippts.gui.common.base_tab import BaseTab

class ScanTab(BaseTab):
    def __init__(self, main_window):
        super().__init__(main_window)
        self.setup_ui()
    
    def setup_ui(self):
        # 实现UI界面
        pass
    
    def start_module(self):
        # 实现模块启动逻辑
        pass
```

```python
# 在 main_window_new.py 中
from sippts.gui.modules.scan_tab import ScanTab

# 在 init_tabs() 方法中添加
self.scan_tab = ScanTab(self)
self.tabs.addTab(self.scan_tab, "SIP扫描")
```

## 迁移计划

1. 将原 `main_window.py` 中的所有功能模块逐一迁移到 `modules` 目录下
2. 完成所有模块迁移后，将 `main_window_new.py` 重命名为 `main_window.py`
3. 更新 `app.py` 以使用新的主窗口实现

## 优势

- 代码组织更清晰，每个功能模块独立维护
- 更容易添加新功能
- 更好的代码复用性
- 更容易进行单元测试
- 更好的团队协作 