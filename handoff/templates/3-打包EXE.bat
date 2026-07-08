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

if exist "%ProgramFiles%\Wireshark\tshark.exe" set "PATH=%ProgramFiles%\Wireshark;%PATH%"
set "PATH=%ENV_DIR%;%ENV_DIR%\Scripts;%ENV_DIR%\Library\bin;%ENV_DIR%\Library\usr\bin;%PATH%"

cd /d "%SRC_DIR%"

echo ============================================================
echo    使用 PyInstaller 打包 (输出: dist\IMS攻击软件.exe)
echo ============================================================
"%ENV_DIR%\python.exe" -m PyInstaller sippts.spec --noconfirm
if errorlevel 1 (
    echo.
    echo [错误] 打包失败, 请查看以上日志.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo    打包完成! 可执行文件位于:
echo    %SRC_DIR%\dist\
echo ============================================================
pause
