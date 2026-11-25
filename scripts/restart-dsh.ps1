# 重启 DSH / Restart DeepSeek Harness
#
# 为什么需要独立进程 / Why this runs detached:
#
# 插件跑在 DSH 进程内部，无法安全地重启自己。这个脚本由 Start-Process 以
# 独立进程启动，因此杀掉 DSH 不会连带杀掉它自身。
#
# The plugin lives inside the DSH process and cannot restart itself. This script
# is launched as a detached process, so killing DSH does not kill it.
#
# 顺序 / Order:
#   1. 等待数秒，让正在进行的回复落盘
#   2. 关闭所有 DSH 进程
#   3. 清理当前会话的历史明文（此时 Host 已停止，日志不会并发追加）
#   4. 重新启动 DSH
#
# 日志写到 %TEMP%\dsh-restart.log，界面消失期间可查看进度。

param(
  [int]$DelaySeconds = 3,
  [string]$ActiveSession = 'session-769227a1-bc3f-4f48-bd73-534b0d127121',
  [switch]$SkipScrub
)

$ErrorActionPreference = 'Continue'
$logPath = Join-Path $env:TEMP 'dsh-restart.log'

function Write-Log([string]$Message) {
  $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Message
  Add-Content -Path $logPath -Value $line -Encoding UTF8
}

Set-Content -Path $logPath -Value '' -Encoding UTF8
Write-Log '重启序列开始'

$exe = 'C:\Users\XGuai-S\AppData\Local\Programs\DeepSeek Harness\DeepSeek Harness.exe'
if (-not (Test-Path -LiteralPath $exe)) {
  Write-Log "找不到 DSH 可执行文件: $exe"
  exit 2
}

# 1. 等待，让正在进行的回复结束并落盘。
Write-Log "等待 $DelaySeconds 秒，让当前回复落盘"
Start-Sleep -Seconds $DelaySeconds

# 2. 关闭所有 DSH 进程。
$targets = Get-Process -Name 'DeepSeek Harness' -ErrorAction SilentlyContinue
if ($null -eq $targets -or $targets.Count -eq 0) {
  Write-Log '没有找到运行中的 DSH 进程'
} else {
  Write-Log ("关闭 {0} 个 DSH 进程: {1}" -f $targets.Count, ($targets.Id -join ', '))
  foreach ($proc in $targets) {
    try { $proc.CloseMainWindow() | Out-Null } catch { }
  }
  # 给主窗口几秒优雅退出时间。
  Start-Sleep -Seconds 2
  $remaining = Get-Process -Name 'DeepSeek Harness' -ErrorAction SilentlyContinue
  if ($null -ne $remaining -and $remaining.Count -gt 0) {
    Write-Log ("强制结束 {0} 个残留进程" -f $remaining.Count)
    foreach ($proc in $remaining) {
      try { Stop-Process -Id $proc.Id -Force -ErrorAction Stop } catch {
        Write-Log ("结束进程 {0} 失败: {1}" -f $proc.Id, $_.Exception.Message)
      }
    }
  }
}

# 确认进程确实退出，否则并发写会损坏会话日志。
$deadline = (Get-Date).AddSeconds(15)
while ((Get-Process -Name 'DeepSeek Harness' -ErrorAction SilentlyContinue) -ne $null -and (Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 500
}
$stillRunning = Get-Process -Name 'DeepSeek Harness' -ErrorAction SilentlyContinue
if ($null -ne $stillRunning -and $stillRunning.Count -gt 0) {
  Write-Log '进程未能在 15 秒内退出，跳过清理以免损坏日志'
} elseif (-not $SkipScrub) {
  # 3. 清理当前会话的历史明文。Host 已停止，日志不会并发追加。
  Write-Log '清理当前会话历史明文'
  $node = $env:DSH_NODE_EXECUTABLE
  $script = 'C:\Users\XGuai-S\Downloads\a\dsh-sensitive-guard\scripts\scrub-session.mjs'
  $sessionDir = "C:\Users\XGuai-S\.dsh\sessions\--C-Users-XGuai-S-Downloads-a--\$ActiveSession"

  if ([string]::IsNullOrWhiteSpace($node) -or -not (Test-Path -LiteralPath $node)) {
    Write-Log "找不到 node 运行时，跳过清理（DSH_NODE_EXECUTABLE=$node）"
  } elseif (-not (Test-Path -LiteralPath $sessionDir)) {
    Write-Log "找不到会话目录，跳过清理: $sessionDir"
  } else {
    # 不重定向 stdout：受限环境下管道会 EPERM，改为让脚本自己退出码表达结果。
    try {
      $scrub = Start-Process -FilePath $node -ArgumentList @(
        $script, '--session', $sessionDir
      ) -Wait -PassThru -WindowStyle Hidden
      Write-Log ("清理退出码: {0}" -f $scrub.ExitCode)
    } catch {
      Write-Log ("清理启动失败: {0}" -f $_.Exception.Message)
    }
  }
} else {
  Write-Log '按参数跳过清理'
}

# 4. 重新启动 DSH。
Write-Log '重新启动 DSH'
try {
  Start-Process -FilePath $exe
  Write-Log '启动指令已发出'
} catch {
  Write-Log ("启动失败: {0}" -f $_.Exception.Message)
}

Write-Log '重启序列结束'