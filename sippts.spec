# -*- mode: python ; coding: utf-8 -*-

import sys
import os
import shutil
from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

# 创建运行时钩子，确保正确设置环境变量和工作目录
with open('runtime_hook.py', 'w', encoding='utf-8') as f:
    f.write('''# -*- coding: utf-8 -*-
import os
import sys
import tempfile

# 设置临时目录
if not hasattr(sys, '_MEIPASS'):
    sys._MEIPASS = os.path.abspath('.')

# 确保可以找到tshark
os.environ['PATH'] = os.path.dirname(sys.executable) + os.pathsep + os.environ.get('PATH', '')

# 创建临时目录用于运行时文件
def get_temp_dir():
    temp_dir = os.path.join(tempfile.gettempdir(), 'sippts_temp')
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    return temp_dir

os.environ['SIPPTS_TEMP'] = get_temp_dir()
''')

# 收集所有需要的模块和数据
hiddenimports = []
hiddenimports.extend(collect_submodules('sippts'))
hiddenimports.extend(collect_submodules('PyQt5.QtCore'))
hiddenimports.extend(collect_submodules('PyQt5.QtGui'))
hiddenimports.extend(collect_submodules('PyQt5.QtWidgets'))
hiddenimports.extend(['netifaces', 'pyshark', 'scapy', 're', 'socket', 'asyncio', 'subprocess', 'platform', 'lxml', 'lxml.etree', 'lxml.objectify'])

# 排除matplotlib_inline模块，它在打包过程中导致问题
excludes = [
    'tkinter', 'matplotlib', 'notebook', 'scipy', 'pandas', 'PIL', 
    'PyQt6', 'PySide6', 'PySide2',
    # 排除不需要的Qt模块以减小体积
    'PyQt5.QtWebEngine', 'PyQt5.QtWebEngineCore', 'PyQt5.QtWebEngineWidgets',
    'PyQt5.QtWebChannel', 'PyQt5.QtWebSockets',
    'PyQt5.QtDesigner', 'PyQt5.QtHelp', 'PyQt5.QtLocation',
    'PyQt5.QtMultimedia', 'PyQt5.QtMultimediaWidgets',
    'PyQt5.QtNfc', 'PyQt5.QtQuick', 'PyQt5.QtQuick3D', 'PyQt5.QtQuickWidgets',
    'PyQt5.QtRemoteObjects', 'PyQt5.QtSensors', 'PyQt5.QtSerialPort',
    'PyQt5.QtSql', 'PyQt5.QtXmlPatterns',
    # 排除导致问题的模块
    'matplotlib_inline', 'IPython'
]

# 收集所有数据文件
datas = []
binaries = []

# 创建一个临时目录来存放所有必要的DLL文件
temp_dll_dir = os.path.join(os.getcwd(), 'temp_dlls')
if not os.path.exists(temp_dll_dir):
    os.makedirs(temp_dll_dir)

# 添加lxml相关的DLL文件
try:
    import lxml
    import lxml.etree
    lxml_path = os.path.dirname(lxml.__file__)
    
    # 添加lxml目录下的所有DLL文件
    for file in os.listdir(lxml_path):
        if file.endswith('.dll') or file.endswith('.pyd'):
            dll_path = os.path.join(lxml_path, file)
            # 复制到临时目录
            shutil.copy2(dll_path, temp_dll_dir)
            # 添加到binaries
            binaries.append((dll_path, '.'))
    
    # 添加lxml的includes目录
    includes_path = os.path.join(lxml_path, 'includes')
    if os.path.exists(includes_path):
        for root, dirs, files in os.walk(includes_path):
            for file in files:
                if file.endswith('.h') or file.endswith('.c'):
                    file_path = os.path.join(root, file)
                    rel_dir = os.path.relpath(root, lxml_path)
                    datas.append((file_path, os.path.join('lxml', rel_dir)))
except Exception as e:
    print(f"无法添加lxml依赖: {str(e)}")

# 添加sippts相关数据
sippts_datas = [
    ('sippts.png', '.'),
    ('src/sippts/gui/resources/icon.ico', 'sippts/gui/resources'),
    ('src/sippts/data', 'sippts/data'),
    ('passwordlist.txt', '.'),  # 添加密码列表
    ('test.wav', '.'),  # 添加测试音频文件
]

# 尝试添加tshark相关文件（如果存在）
wireshark_paths = [
    'C:\\Program Files\\Wireshark',
    'C:\\Program Files (x86)\\Wireshark',
    'C:\\Wireshark'
]

for path in wireshark_paths:
    if os.path.exists(path):
        tshark_exe = os.path.join(path, 'tshark.exe')
        if os.path.exists(tshark_exe):
            binaries.append((tshark_exe, '.'))
            # 添加tshark依赖的DLL文件
            for file in os.listdir(path):
                if file.endswith('.dll'):
                    dll_path = os.path.join(path, file)
                    # 复制到临时目录
                    shutil.copy2(dll_path, temp_dll_dir)
                    # 添加到binaries
                    binaries.append((dll_path, '.'))
            break

# 添加PyQt5的翻译文件
try:
    import PyQt5
    pyqt_path = os.path.dirname(PyQt5.__file__)
    translations_path = os.path.join(pyqt_path, 'Qt5', 'translations')
    if os.path.exists(translations_path):
        for file in os.listdir(translations_path):
            if file.startswith('qt_') and file.endswith('.qm'):
                datas.append((os.path.join(translations_path, file), 'PyQt5/Qt5/translations'))
except Exception:
    pass

datas.extend(sippts_datas)

# 添加系统DLL
system32_path = os.path.join(os.environ['SystemRoot'], 'System32')
required_dlls = ['libxml2.dll', 'libxslt.dll', 'zlib1.dll', 'iconv.dll']
for dll in required_dlls:
    dll_path = os.path.join(system32_path, dll)
    if os.path.exists(dll_path):
        # 复制到临时目录
        try:
            shutil.copy2(dll_path, temp_dll_dir)
        except Exception as e:
            print(f"无法复制系统DLL {dll}: {str(e)}")
        # 添加到binaries
        binaries.append((dll_path, '.'))

# 尝试从Python安装目录找到必要的DLL
python_dll_path = os.path.dirname(sys.executable)
python_dlls = ['libxml2.dll', 'libxslt.dll', 'zlib1.dll', 'iconv.dll']
for dll in python_dlls:
    dll_path = os.path.join(python_dll_path, dll)
    if os.path.exists(dll_path):
        # 复制到临时目录
        shutil.copy2(dll_path, temp_dll_dir)
        # 添加到binaries
        binaries.append((dll_path, '.'))

# 将临时目录中的所有DLL添加到PATH环境变量
os.environ['PATH'] = temp_dll_dir + os.pathsep + os.environ['PATH']

a = Analysis(
    ['src/sippts/gui/main_window_new.py'],  # 修改为main_window_new.py作为主程序入口
    pathex=[os.path.abspath('.'), temp_dll_dir],  # 添加临时DLL目录到搜索路径
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['runtime_hook.py'],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='IMS攻击软件',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='src/sippts/gui/resources/icon.ico',  # 应用图标
) 