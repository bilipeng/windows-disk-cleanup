# =====================================================================
# Start-Cleanup.ps1 - interactive wizard for users without an AI agent.
# Runs the read-only scans, shows a numbered list, writes an approved
# plan only after explicit selection, previews, then optionally executes.
# =====================================================================
[CmdletBinding()]
param(
  [ValidateSet('Deep', 'Both')]
  [string]$Mode = 'Deep',
  [string]$QuarantineRoot = '',
  [string]$ReportDir = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$scriptDir = $PSScriptRoot

function Read-Choice([string]$Prompt, [string]$Default = '') {
  if ($Default) { $v = Read-Host ($Prompt + ' [' + $Default + ']') } else { $v = Read-Host $Prompt }
  if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
  return $v.Trim()
}

function Format-GB([long]$Bytes) { return [math]::Round(($Bytes / 1GB), 2) }

$isAdmin = $false
try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

Write-Host '==============================================================================='
Write-Host '  Windows Disk Cleanup - 交互式向导'
Write-Host '==============================================================================='
Write-Host '  本向导只读扫描，列出可清理项；你选择后才会生成计划。'
Write-Host '  删除前还会再做一次预览并要求最终确认。'
Write-Host ''
if (-not $isAdmin) {
  Write-Warning '当前不是管理员：ProgramData 和其他用户目录可能扫描不完整。'
  $elev = Read-Choice '是否以管理员身份重新启动以获得完整扫描？(y/N)' 'y'
  if ($elev -match '^(y|Y)') {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), '-Mode', $Mode)
    if ($QuarantineRoot) { $argList += @('-QuarantineRoot', ('"' + $QuarantineRoot + '"')) }
    if ($ReportDir) { $argList += @('-ReportDir', ('"' + $ReportDir + '"')) }
    try {
      Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($argList -join ' ')
      exit 0
    } catch {
      Write-Warning ('提权失败，继续以当前权限运行：' + $_.Exception.Message)
    }
  }
  Write-Host ''
}

if (-not $ReportDir) {
  $ReportDir = Join-Path $env:USERPROFILE 'disk-cleanup-reports'
}
if (-not (Test-Path -LiteralPath $ReportDir)) {
  New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

# ---------------------------------------------------------------------
# 1) scans
# ---------------------------------------------------------------------
$auditFile = Join-Path $ReportDir ('audit-' + $stamp + '.json')
$deepFile = Join-Path $ReportDir ('deepscan-' + $stamp + '.json')

if ($Mode -eq 'Both') {
  Write-Host '[1/3] 正在执行孤儿审计（只读）...'
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'Invoke-DiskAudit.ps1') -OutFile $auditFile
  if ($LASTEXITCODE -ne 0) { Write-Warning '审计脚本返回非零退出码，继续使用已有结果。' }
}
if ($Mode -eq 'Deep' -or $Mode -eq 'Both') {
  Write-Host '[2/3] 正在执行深度扫描（只读，可能需要数分钟）...'
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'Invoke-DeepScan.ps1') -OutFile $deepFile
  if ($LASTEXITCODE -ne 0) { Write-Warning '深度扫描返回非零退出码，继续使用已有结果。' }
}

if (-not (Test-Path -LiteralPath $deepFile)) {
  Write-Warning '没有深度扫描结果，无法生成缓存清单。退出。'
  exit 1
}

$deep = [System.IO.File]::ReadAllText($deepFile, [System.Text.Encoding]::UTF8) | ConvertFrom-Json

# ---------------------------------------------------------------------
# 2b) human/chat-assistant friendly Markdown report
# ---------------------------------------------------------------------
$md = New-Object System.Collections.Generic.List[string]
$md.Add('# Windows 磁盘清理报告')
$md.Add('')
$md.Add('- 生成时间: ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
$md.Add('- 扫描根: ' + $deep.Root)
$md.Add('- 管理员模式: ' + $deep.Admin)
$md.Add(('- 卷已用: {0} GB / 空闲: {1} GB' -f (Format-GB ([long]$deep.DriveUsedBytes)), (Format-GB ([long]$deep.DriveFreeBytes))))
$md.Add(('- 覆盖率: {0}%（已解释 {1} GB；不可读路径 {2} 处）' -f $deep.Coverage.CoveragePercent, (Format-GB ([long]$deep.Coverage.AccountedBytes)), @($deep.Errors).Count))
$md.Add('')
$md.Add('## 缓存与开发缓存（按大小排序，前 30）')
$md.Add('')
$md.Add('| 大小(GB) | 评分 | 桶 | 路径 |')
$md.Add('|---|---|---|---|')
foreach ($c in (@($deep.CacheItems) | Sort-Object Bytes -Descending | Select-Object -First 30)) {
  $md.Add(('| {0} | {1} | {2} | `{3}` |' -f (Format-GB ([long]$c.Bytes)), $c.Score, $c.Bucket, $c.Path))
}
$md.Add('')
$md.Add('## 垃圾文件目录')
$md.Add('')
$md.Add('| 大小(GB) | 文件数 | 路径 |')
$md.Add('|---|---|---|')
foreach ($j in @($deep.JunkDirs)) {
  $md.Add(('| {0} | {1} | `{2}` |' -f (Format-GB ([long]$j.Bytes)), $j.Count, $j.Path))
}
$md.Add('')
$md.Add('## 大文件（>500 MB，前 20）')
$md.Add('')
$md.Add('| 大小(GB) | 年龄(天) | 路径 |')
$md.Add('|---|---|---|')
foreach ($l in (@($deep.LargeFiles) | Sort-Object Bytes -Descending | Select-Object -First 20)) {
  $md.Add(('| {0} | {1} | `{2}` |' -f (Format-GB ([long]$l.Bytes)), $l.AgeDays, $l.Path))
}
$md.Add('')
$md.Add('## 系统可回收空间（仅报告）')
$md.Add('')
foreach ($s in @($deep.SystemItems)) {
  $sz = 'n/a'
  if ($s.Bytes -ne $null) { $sz = (Format-GB ([long]$s.Bytes)).ToString() + ' GB' }
  $md.Add(('- **{0}**: {1} — {2}' -f $s.Item, $sz, $s.Note))
}
$md.Add('')
$md.Add('## 捆绑软件信号')
$md.Add('')
foreach ($b in (@($deep.BundleSignals) | Sort-Object Score -Descending | Select-Object -First 15)) {
  $md.Add(('- 评分 {0} · {1} · {2} — `{3}`' -f $b.Score, $b.Kind, $b.Name, $b.Path))
}
$md.Add('')
$md.Add('## 安装残留')
$md.Add('')
foreach ($r in (@($deep.Residue) | Select-Object -First 15)) {
  $md.Add(('- {0} · {1} — `{2}`' -f $r.Kind, $r.Name, $r.Path))
}
$md.Add('')
$md.Add('## 扫描错误与不可读路径')
$md.Add('')
foreach ($e in @($deep.Errors)) {
  $md.Add(('- [{0}] `{1}` — {2}' -f $e.Stage, $e.Path, $e.Error))
}
$md.Add('')
$md.Add('> 大小为逻辑估算；硬链接可能重复计数；实际释放量以执行后实测为准。')
$reportMd = Join-Path $ReportDir ('report-' + $stamp + '.md')
[System.IO.File]::WriteAllText($reportMd, ($md -join [Environment]::NewLine), (New-Object System.Text.UTF8Encoding $true))
Write-Host ('Markdown 报告已生成: ' + $reportMd)

# ---------------------------------------------------------------------
# 2) build candidate list
# ---------------------------------------------------------------------
$candidates = New-Object System.Collections.Generic.List[object]
foreach ($c in @($deep.CacheItems)) {
  if ($c.Bucket -eq 'C') { continue }
  if ($c.DataFingerprint) { continue }
  $candidates.Add([PSCustomObject]@{
    Path = $c.Path; Bytes = [long]$c.Bytes; Score = [int]$c.Score; Bucket = $c.Bucket
    AgeDays = [int]$c.AgeDays; Kind = $c.Kind; Source = 'cache'
  }) | Out-Null
}
foreach ($j in @($deep.JunkDirs)) {
  $candidates.Add([PSCustomObject]@{
    Path = $j.Path; Bytes = [long]$j.Bytes; Score = 50; Bucket = 'B'
    AgeDays = 0; Kind = 'JunkFiles'; Source = 'junk'
  }) | Out-Null
}
$candidates = @($candidates | Sort-Object Bytes -Descending)

Write-Host ''
Write-Host '[3/3] 扫描完成。可清理候选如下：'
Write-Host ''
Write-Host ('  {0,4}  {1,9}  {2,3}  {3,-4}  {4}' -f '#', '大小', '分', '桶', '路径')
$i = 0
foreach ($c in $candidates) {
  $i++
  $gb = (Format-GB $c.Bytes).ToString() + ' GB'
  Write-Host ('  {0,4}  {1,9}  {2,3}  {3,-4}  {4}' -f $i, $gb, $c.Score, $c.Bucket, $c.Path)
}
Write-Host ''
Write-Host ('  A 桶合计: {0} GB   B 桶合计: {1} GB' -f `
  (Format-GB ((($candidates | Where-Object { $_.Bucket -eq 'A' }) | Measure-Object Bytes -Sum).Sum)), `
  (Format-GB ((($candidates | Where-Object { $_.Bucket -eq 'B' }) | Measure-Object Bytes -Sum).Sum)))
Write-Host ''
Write-Host '  选择方式：输入编号（逗号分隔，如 1,3,5）；a=A 桶全部；b=A+B 全部；q=退出'
$choice = Read-Choice '你的选择' 'a'

if ($choice -eq 'q' -or $choice -eq 'Q') { Write-Host '已退出，未做任何修改。'; exit 0 }

$selected = @()
if ($choice -eq 'a' -or $choice -eq 'A') {
  $selected = @($candidates | Where-Object { $_.Bucket -eq 'A' })
} elseif ($choice -eq 'b' -or $choice -eq 'B') {
  $selected = @($candidates)
} else {
  foreach ($part in ($choice -split ',')) {
    $n = 0
    if ([int]::TryParse($part.Trim(), [ref]$n)) {
      if ($n -ge 1 -and $n -le $candidates.Count) { $selected += $candidates[$n - 1] }
    }
  }
  $selected = @($selected | Sort-Object Path -Unique)
}
if ($selected.Count -eq 0) { Write-Host '未选择任何目标，退出。'; exit 0 }

# ---------------------------------------------------------------------
# 3) quarantine root
# ---------------------------------------------------------------------
if (-not $QuarantineRoot) {
  $driveName = (Get-CimInstance Win32_OperatingSystem).SystemDrive.TrimEnd(':')
  $other = @(Get-PSDrive -PSProvider FileSystem | Where-Object {
    $_.Name -ne $driveName -and $_.Free -gt 20GB
  } | Sort-Object Free -Descending)
  if ($other.Count -gt 0) {
    $defaultQ = $other[0].Name + ':\_cleanup_quarantine'
  } else {
    $defaultQ = (Join-Path $env:USERPROFILE '_cleanup_quarantine')
  }
  $QuarantineRoot = Read-Choice '隔离目录（建议放在另一个磁盘）' $defaultQ
}

# ---------------------------------------------------------------------
# 4) plan + dry run
# ---------------------------------------------------------------------
$planId = 'plan-wizard-' + (Get-Date -Format 'yyyyMMddHHmmss')
$targets = @()
foreach ($s in $selected) {
  $targets += [PSCustomObject]@{
    Path = $s.Path
    Operation = 'Quarantine'
    EstimatedLogicalSizeBytes = $s.Bytes
    Justification = ('wizard ' + $s.Kind + '; score=' + $s.Score + '; bucket=' + $s.Bucket)
    RiskLevel = $(if ($s.Bucket -eq 'A') { 'Low' } else { 'Medium' })
    Bucket = $s.Bucket
    ApprovalStatus = 'Approved'
    ApprovedOperation = 'Quarantine'
    RequiresConfirmation = $true
    Reversible = $true
  }
}
$plan = [PSCustomObject]@{
  PlanId = $planId
  Version = '1.0'
  CreatedAt = (Get-Date).ToString('o')
  SystemDrive = $deep.Root.TrimEnd('\')
  UserProfile = $env:USERPROFILE
  AuditMode = $(if ($isAdmin) { 'Admin' } else { 'CurrentUser-Incomplete' })
  ScanScope = 'CurrentUser'
  ScanRoots = @($deep.Root)
  Baseline = [PSCustomObject]@{ FreeGB = (Format-GB ([long]$deep.DriveFreeBytes)) }
  Candidates = @()
  SpecialConsumers = @($deep.SystemItems)
  CrossCheck = [PSCustomObject]@{}
  RawUninstallRecords = @()
  Observability = [PSCustomObject]@{ Source = 'wizard'; Coverage = $deep.Coverage }
  Targets = @($targets)
}
$planFile = Join-Path $ReportDir ('plan-' + $stamp + '.json')
[System.IO.File]::WriteAllText($planFile, ($plan | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding $true))

Write-Host ''
Write-Host '---------------- 预览（尚未修改任何文件）----------------'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'Invoke-DiskCleanup.ps1') `
  -PlanFile $planFile -DryRun -QuarantineRoot $QuarantineRoot

Write-Host ''
$confirm = Read-Choice '确认执行隔离吗？(y/N)' 'n'
if ($confirm -notmatch '^(y|Y|yes|YES)$') {
  Write-Host ''
  Write-Host ('已取消。计划文件保留在: ' + $planFile)
  exit 0
}

# ---------------------------------------------------------------------
# 5) execute
# ---------------------------------------------------------------------
Write-Host ''
Write-Host '开始执行...'
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'Invoke-DiskCleanup.ps1') `
  -PlanFile $planFile -Execute -QuarantineRoot $QuarantineRoot

Write-Host ''
Write-Host ('报告目录: ' + $ReportDir)
Write-Host '恢复方法见隔离目录下的 restore-manifest.json。'
