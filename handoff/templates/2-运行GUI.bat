@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set "PKG_ROOT=%~dp0"
set "ENV_DIR=%PKG_ROOT%runtime\pyenv"
set "SRC_DIR=%PKG_ROOT%source\sippts"

if not exist "%ENV_DIR%\python.exe" (
    echo [错误] 尚未安装 Python 环境, 请先运行  1-安装环境.bat
    pause
    exit /b 1
)

REM 把 Wireshark 加入 PATH (pyshark 需要 tshark)
if exist "%ProgramFiles%\Wireshark\tshark.exe" set "PATH=%ProgramFiles%\Wireshark;%PATH%"

REM 激活自包含环境
set "PATH=%ENV_DIR%;%ENV_DIR%\Scripts;%ENV_DIR%\Library\bin;%ENV_DIR%\Library\usr\bin;%PATH%"

REM 以仓库根目录作为工作目录, 保证资源文件(密码字典/音频/图标)相对路径可用
cd /d "%SRC_DIR%"

echo 正在启动 SIPPTS 图形界面...
"%ENV_DIR%\python.exe" src\sippts\gui\app.py
if errorlevel 1 (
    echo.
    echo [提示] 程序退出并返回错误, 上方为详细日志.
    pause
)
