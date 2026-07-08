@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ============================================================
echo    SIPPTS 离线环境 一键安装
echo ============================================================
echo.

set "PKG_ROOT=%~dp0"
set "ENV_DIR=%PKG_ROOT%runtime\pyenv"
set "ENV_ARCHIVE=%PKG_ROOT%env\base_env.zip"
set "SRC_DIR=%PKG_ROOT%source\sippts"

REM ---------- 1) 解压 Python 环境 ----------
if exist "%ENV_DIR%\python.exe" (
    echo [1/4] Python 环境已存在, 跳过解压: %ENV_DIR%
) else (
    if not exist "%ENV_ARCHIVE%" (
        echo [错误] 找不到环境压缩包: %ENV_ARCHIVE%
        goto :error
    )
    echo [1/4] 正在解压 Python 环境 ^(约 10GB, 需要几分钟, 请耐心等待^)...
    mkdir "%ENV_DIR%" 2>nul
    tar -xf "%ENV_ARCHIVE%" -C "%ENV_DIR%"
    if errorlevel 1 (
        echo [错误] 解压失败, 请确认磁盘剩余空间充足 ^(至少 15GB^).
        goto :error
    )
)

REM ---------- 2) 修复 conda 前缀路径 (conda-unpack) ----------
echo [2/4] 正在修复环境路径 ^(conda-unpack^)...
if exist "%ENV_DIR%\Scripts\conda-unpack.exe" (
    "%ENV_DIR%\Scripts\conda-unpack.exe"
    if errorlevel 1 echo [警告] conda-unpack 返回非零, 通常仍可使用, 继续...
) else (
    echo [警告] 未找到 conda-unpack.exe, 跳过 ^(通常仍可运行^).
)

REM ---------- 3) 修复 sippts 源码路径 (editable .pth) ----------
echo [3/4] 正在把 sippts 指向源码目录: %SRC_DIR%\src
for /f "delims=" %%P in ('dir /b /s "%ENV_DIR%\Lib\site-packages\__editable__*sippts*.pth" 2^>nul') do (
    >"%%P" echo %SRC_DIR%\src
    echo        已更新: %%P
)

REM ---------- 4) 安装抓包驱动 (Wireshark + Npcap) ----------
echo [4/4] 准备安装抓包驱动 Wireshark + Npcap ^(pyshark / scapy 抓包功能依赖^).
if exist "%ProgramFiles%\Wireshark\tshark.exe" (
    echo        检测到已安装 Wireshark, 跳过.
) else (
    echo        即将启动安装向导, 需要【管理员权限】, 请务必勾选 "Install Npcap".
    pause
    for %%F in ("%PKG_ROOT%drivers\Wireshark-*-x64.exe") do (
        start "" /wait "%%F"
    )
)

echo.
echo ============================================================
echo    安装完成!
echo      - 运行软件  : 双击  2-运行GUI.bat
echo      - 打包 EXE  : 双击  3-打包EXE.bat
echo ============================================================
pause
exit /b 0

:error
echo.
echo 安装失败, 请查看以上错误信息.
pause
exit /b 1
