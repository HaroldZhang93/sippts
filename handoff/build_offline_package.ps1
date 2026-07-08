<#
================================================================
  SIPPTS 离线交接包 构建脚本  (在【联网的源机器】上运行)
================================================================
  作用：把本机 conda base 环境 + 项目源码 + 抓包驱动(Wireshark/Npcap)
        打包成一个可拷贝到离线 Win10 机器的自包含文件夹。

  用法（在本仓库根目录，PowerShell 中执行）：
      powershell -ExecutionPolicy Bypass -File handoff\build_offline_package.ps1

  可选参数：
      -OutputRoot <目录>   指定输出根目录（默认 ..\_offline_dist）
      -SkipEnv             跳过 conda 环境打包（调试脚本用）
      -SkipDriver          跳过 Wireshark 下载（无网络 / 已手动准备驱动时用）
================================================================
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$SkipEnv,
    [switch]$SkipDriver
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"   # 关闭进度条，Invoke-WebRequest 更快

# ---- 路径与常量（按当前源机器实际情况写死，如迁移到别的机器请修改） ----
$RepoRoot     = Split-Path -Parent $PSScriptRoot                  # 仓库根目录 = handoff 的上一级
$CondaPrefix  = "C:\Users\JDS\anaconda3"                           # 要打包的 conda base 环境
$WiresharkUrl = "https://www.wireshark.org/download/win64/Wireshark-latest-x64.exe"
$PkgName      = "SIPPTS离线交接包"

if (-not $OutputRoot) {
    $OutputRoot = Join-Path (Split-Path -Parent $RepoRoot) "_offline_dist"
}
$PkgDir = Join-Path $OutputRoot $PkgName

function Write-Step($msg) { Write-Host "`n==== $msg ====" -ForegroundColor Cyan }

Write-Host "仓库根目录 : $RepoRoot"
Write-Host "conda 环境 : $CondaPrefix"
Write-Host "输出目录   : $PkgDir"

# ---- 准备目录结构 ----
New-Item -ItemType Directory -Force -Path $PkgDir | Out-Null
foreach ($sub in "env","source","drivers") {
    New-Item -ItemType Directory -Force -Path (Join-Path $PkgDir $sub) | Out-Null
}

# ---- [1/4] conda-pack 打包 base 环境 ----
if (-not $SkipEnv) {
    Write-Step "[1/4] 打包 base 环境 (conda-pack, 约 10GB, 可能耗时 10~30 分钟)"
    $envOut = Join-Path $PkgDir "env\base_env.zip"
    conda pack -p "$CondaPrefix" -o "$envOut" --format zip -j -1 --ignore-editable-packages --force
    if ($LASTEXITCODE -ne 0) { throw "conda-pack 失败 (exit $LASTEXITCODE)" }
    $sizeGB = [math]::Round((Get-Item $envOut).Length / 1GB, 2)
    Write-Host "  -> 环境包生成完成: $envOut ($sizeGB GB)"
} else {
    Write-Step "[1/4] 跳过 conda 环境打包 (-SkipEnv)"
}

# ---- [2/4] 复制项目源码（排除构建产物 / git / 缓存） ----
Write-Step "[2/4] 复制项目源码"
$srcDest = Join-Path $PkgDir "source\sippts"
robocopy "$RepoRoot" "$srcDest" /E /R:1 /W:1 `
    /XD ".git" "build" "dist" "temp_dlls" "__pycache__" ".vscode" ".devcontainer" `
    /XF "*.pyc" `
    /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy 复制源码失败 (exit $LASTEXITCODE)" }
Write-Host "  -> 源码已复制到: $srcDest"

# ---- [3/4] 下载 Wireshark 离线安装包（自带 Npcap） ----
if (-not $SkipDriver) {
    Write-Step "[3/4] 下载 Wireshark 离线安装包 (含 Npcap, 约 98MB)"
    $wsOut = Join-Path $PkgDir "drivers\Wireshark-latest-x64.exe"
    Invoke-WebRequest -Uri $WiresharkUrl -OutFile $wsOut
    $wsMB = [math]::Round((Get-Item $wsOut).Length / 1MB, 1)
    Write-Host "  -> 已下载: $wsOut ($wsMB MB)"
} else {
    Write-Step "[3/4] 跳过 Wireshark 下载 (-SkipDriver)"
    Write-Host "  !! 请手动把 Wireshark-*-x64.exe 放入 $PkgDir\drivers\ 目录" -ForegroundColor Yellow
}

# ---- [4/4] 复制目标机一键脚本与说明 ----
Write-Step "[4/4] 复制目标机脚本与使用说明"
Copy-Item (Join-Path $PSScriptRoot "templates\*") -Destination $PkgDir -Force -Recurse
Write-Host "  -> 已复制: 1-安装环境.bat / 2-运行GUI.bat / 3-打包EXE.bat / 使用说明.txt"

# ---- 完成 ----
Write-Host "`n================================================================" -ForegroundColor Green
Write-Host " 构建完成!" -ForegroundColor Green
Write-Host " 交接包目录: $PkgDir"
Write-Host " 下一步: 把整个『$PkgName』文件夹拷到U盘/移动硬盘, 交给同事,"
Write-Host "         在目标机上依次运行 1-安装环境.bat -> 2-运行GUI.bat"
Write-Host "================================================================" -ForegroundColor Green
