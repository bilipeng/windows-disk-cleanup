# =====================================================================
# Invoke-DeepScan.ps1 - full-volume resource audit.
# READ-ONLY. Produces a JSON report + Chinese summary + a plan draft.
#
# Tracks:
#   T0 volume census + coverage accounting
#   T2 cache directories (generic signatures + data fingerprint exclusion)
#   T3 junk files (.tmp/.log/.dmp/.old/... older than N days)
#   T4 large files (> threshold)
#   T6 developer / package caches
#   T5 system reclaimable areas (report only)
#   T7 bundled-software signals (signature / path / hidden task)
#   T8 installation residue (report only)
# =====================================================================
[CmdletBinding()]
param(
  [string]$Root = '',
  [string]$OutFile = '',
  [int]$MinCacheMB = 50,
  [int]$MinJunkAgeDays = 14,
  [int]$MinJunkDirMB = 20,
  [int]$LargeFileMB = 500,
  [int]$MaxCacheItems = 300,
  [int]$MaxLargeFiles = 100,
  [switch]$SkipDism,
  [switch]$RequestElevation
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$script:Errors = New-Object System.Collections.Generic.List[object]
$script:ReparseSkips = 0
$script:PlaceholderExcluded = 0

function Add-Err([string]$Path, [string]$Stage, [string]$Msg) {
  if ($script:Errors.Count -lt 500) {
    $script:Errors.Add([PSCustomObject]@{ Path = $Path; Stage = $Stage; Error = $Msg })
  }
}

function Get-IsElevated {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wpr = New-Object Security.Principal.WindowsPrincipal($id)
    return $wpr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}
$IsAdmin = Get-IsElevated

if (-not $Root) {
  $os = Get-CimInstance Win32_OperatingSystem
  $Root = $os.SystemDrive.TrimEnd('\') + '\'
}
$Root = $Root.TrimEnd('\') + '\'

if (-not $IsAdmin -and $RequestElevation) {
  $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'),
    '-Root', ('"' + $Root + '"'), '-MinCacheMB', $MinCacheMB, '-MinJunkAgeDays', $MinJunkAgeDays,
    '-LargeFileMB', $LargeFileMB)
  if ($OutFile) { $argList += @('-OutFile', ('"' + $OutFile + '"')) }
  try {
    Write-Host 'Requesting elevation (approve the UAC prompt for a complete deep scan)...'
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ($argList -join ' ')
    exit 0
  } catch {
    Write-Warning ('Elevation not granted: ' + $_.Exception.Message)
  }
}

. (Join-Path $PSScriptRoot 'DeepScan.Common.ps1')

$MinCacheBytes = [long]$MinCacheMB * 1MB
$MinJunkDirBytes = [long]$MinJunkDirMB * 1MB
$LargeFileBytes = [long]$LargeFileMB * 1MB

$driveLetter = $Root.Substring(0, 2)
$driveObj = Get-PSDrive -Name ($driveLetter -replace ':', '')
$usedBytes = [long]$driveObj.Used
$freeBytes = [long]$driveObj.Free

Write-Host ('Deep scan root: ' + $Root)
Write-Host ('Mode: ' + $(if ($IsAdmin) { 'Admin' } else { 'CurrentUser (INCOMPLETE)' }))
Write-Host ''

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
function Measure-DirBytes([string]$Path) {
  $total = [long]0
  $stack = New-Object System.Collections.Generic.Stack[string]
  $stack.Push($Path)
  while ($stack.Count -gt 0) {
    $dir = $stack.Pop()
    try {
      $di = New-Object System.IO.DirectoryInfo($dir)
      foreach ($fsi in $di.EnumerateFileSystemInfos()) {
        if ($fsi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $script:ReparseSkips++; continue }
        if ($fsi -is [System.IO.DirectoryInfo]) { $stack.Push($fsi.FullName) }
        else {
          if ($fsi.Attributes -band [System.IO.FileAttributes]::Offline) { $script:PlaceholderExcluded++; continue }
          $total += $fsi.Length
        }
      }
    } catch {
      Add-Err $dir 'MeasureDir' $_.Exception.Message
    }
  }
  return $total
}

function Get-DirAgeDays([string]$Path) {
  try { return [int]((Get-Date) - (Get-Item -LiteralPath $Path -Force).LastWriteTime).TotalDays }
  catch { return 0 }
}

function Test-IsSystemPath([string]$Path) {
  $p = $Path.ToLowerInvariant()
  $sys = @(
    ($Root + 'windows'),
    ($Root + 'program files\windowsapps'),
    ($Root + 'system volume information'),
    ($Root + '$recycle.bin'),
    ($Root + 'recovery')
  )
  foreach ($s in $sys) { if ($p.StartsWith($s.ToLowerInvariant())) { return $true } }
  return $false
}

function Get-RelTop([string]$Full) {
  if (-not $Full.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase)) { return 'other' }
  $rel = $Full.Substring($Root.Length)
  $seg = ($rel -split '[\\/]')[0]
  if ([string]::IsNullOrWhiteSpace($seg)) { return 'other' }
  return $seg
}

# When scanning a subdirectory rather than a whole volume, the coverage
# denominator must be that subtree's own size, not the drive's used bytes.
$isVolumeRoot = ($Root.TrimEnd('\') -match '^[A-Za-z]:$')
if (-not $isVolumeRoot) {
  $usedBytes = Measure-DirBytes $Root
  $freeBytes = 0
  # reset counters/errors gathered by the pre-measure pass
  $script:ReparseSkips = 0
  $script:PlaceholderExcluded = 0
  $script:Errors.Clear()
}

# ---------------------------------------------------------------------
# T0/T2/T3/T4/T6: one volume walk
# ---------------------------------------------------------------------
$cacheItems = New-Object System.Collections.Generic.List[object]
$largeFiles = New-Object System.Collections.Generic.List[object]
$junkByDir = @{}
$topSizes = @{}
$accountedBytes = [long]0
$fileCount = [long]0
$reportedCache = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)

# directories measured as a whole and not descended (system, huge)
$measureOnly = @(
  ($Root + 'Windows\WinSxS'),
  ($Root + 'Windows\System32\DriverStore'),
  ($Root + 'Program Files\WindowsApps'),
  ($Root + 'System Volume Information'),
  ($Root + '$Recycle.Bin')
)

$walkStack = New-Object System.Collections.Generic.Stack[string]
$walkStack.Push($Root)
$dirsSeen = [long]0

while ($walkStack.Count -gt 0) {
  $dir = $walkStack.Pop()
  $dirsSeen++
  if (($dirsSeen % 2000) -eq 0) {
    Write-Progress -Activity 'Deep scan' -Status ('dirs: ' + $dirsSeen + '  files: ' + $fileCount) -PercentComplete -1
  }
  if (($dirsSeen % 20000) -eq 0) {
    Write-Host ('  ... scanned {0} dirs, {1} files, {2:N1} GB accounted' -f $dirsSeen, $fileCount, ($accountedBytes / 1GB))
  }
  try {
    $di = New-Object System.IO.DirectoryInfo($dir)
    $entries = $di.EnumerateFileSystemInfos()
  } catch {
    Add-Err $dir 'Enumerate' $_.Exception.Message
    continue
  }
  foreach ($fsi in $entries) {
    try {
      if ($fsi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $script:ReparseSkips++; continue }

      if ($fsi -is [System.IO.DirectoryInfo]) {
        $full = $fsi.FullName
        $lower = $full.ToLowerInvariant()

        $skipDescend = $false
        foreach ($mo in $measureOnly) {
          if ($lower -eq $mo.ToLowerInvariant()) { $skipDescend = $true; break }
        }
        if ($skipDescend) {
          $sz = Measure-DirBytes $full
          $accountedBytes += $sz
          if (-not $reportedCache.Contains($full)) {
            $reportedCache.Add($full) | Out-Null
          }
          continue
        }

        $isCache = Test-CacheDirName $fsi.Name
        $isDev = Test-DevCachePath $lower
        $isSystemTree = $lower.StartsWith(($Root + 'Windows').ToLowerInvariant()) -or
                        $lower.StartsWith((Join-Path $Root '$Recycle.Bin').ToLowerInvariant())

        if ((-not $isSystemTree) -and ($isCache -or $isDev) -and -not $reportedCache.Contains($full)) {
          $sz = Measure-DirBytes $full
          if ($sz -ge $MinCacheBytes) {
            $dataHit = Test-DataFingerprintInDir $full
            $ageDays = Get-DirAgeDays $full
            $score = Get-EvidenceScore -CacheSignature:$isCache -DevCache:$isDev `
              -DataFingerprint:$dataHit -AgeDays:$ageDays -Bytes:$sz -Signed:$true
            $cacheItems.Add([PSCustomObject]@{
              Path = $full
              Bytes = $sz
              AgeDays = $ageDays
              DataFingerprint = $dataHit
              CacheSignature = $isCache
              DevCache = $isDev
              Score = $score
              Bucket = (Get-BucketFromScore $score)
              Kind = $(if ($isDev) { 'DevCache' } else { 'Cache' })
            }) | Out-Null
          }
          $accountedBytes += $sz
          $reportedCache.Add($full) | Out-Null
          continue
        }

        $walkStack.Push($full)
      }
      else {
        $len = [long]$fsi.Length
        if ($fsi.Attributes -band [System.IO.FileAttributes]::Offline) {
          $script:PlaceholderExcluded++
          continue
        }
        $accountedBytes += $len
        $fileCount++
        $top = Get-RelTop $fsi.FullName
        if (-not $topSizes.ContainsKey($top)) { $topSizes[$top] = [long]0 }
        $topSizes[$top] += $len

        $isRootSpecial = ($dir.TrimEnd('\') -eq $Root.TrimEnd('\')) -and ($fsi.Name -match '^(pagefile\.sys|hiberfil\.sys|swapfile\.sys)$')
        if ((-not $isRootSpecial) -and (-not (Test-IsSystemPath $fsi.FullName))) {
          if ($len -ge $LargeFileBytes) {
            $largeFiles.Add([PSCustomObject]@{
              Path = $fsi.FullName; Bytes = $len
              AgeDays = [int]((Get-Date) - $fsi.LastWriteTime).TotalDays
            }) | Out-Null
          }
          if (Test-JunkFileName $fsi.Name) {
            if ((Get-Date) - $fsi.LastWriteTime -gt [TimeSpan]::FromDays($MinJunkAgeDays)) {
              if (-not $junkByDir.ContainsKey($dir)) {
                $junkByDir[$dir] = [PSCustomObject]@{ Bytes = [long]0; Count = 0 }
              }
              $junkByDir[$dir].Bytes += $len
              $junkByDir[$dir].Count += 1
            }
          }
        }
      }
    } catch {
      Add-Err $fsi.FullName 'Inspect' $_.Exception.Message
    }
  }
}
Write-Progress -Activity 'Deep scan' -Completed

# junk directories worth reporting
$junkDirs = @()
foreach ($k in $junkByDir.Keys) {
  if ($junkByDir[$k].Bytes -ge $MinJunkDirBytes) {
    $junkDirs += [PSCustomObject]@{
      Path = $k; Bytes = $junkByDir[$k].Bytes; Count = $junkByDir[$k].Count
      Bucket = 'B'
    }
  }
}

# ---------------------------------------------------------------------
# T5: system reclaimable areas (report only)
# ---------------------------------------------------------------------
$systemItems = @()

function Add-SysItem([string]$Name, [string]$Path, [string]$Note, [switch]$IsFile) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $bytes = [long]0
  if ($IsFile) {
    try { $bytes = (Get-Item -LiteralPath $Path -Force).Length } catch { Add-Err $Path 'SystemSize' $_.Exception.Message }
  } else {
    $bytes = Measure-DirBytes $Path
  }
  $script:systemItems += [PSCustomObject]@{ Item = $Name; Path = $Path; Bytes = $bytes; Note = $Note; AutoClean = $false }
}

$systemItems = @()
Add-SysItem 'Windows Update cache' (Join-Path $Root 'Windows\SoftwareDistribution\Download') 'Downloaded update packages; Windows re-downloads when needed.' -IsFile:$false
Add-SysItem 'Delivery Optimization' (Join-Path $Root 'Windows\SoftwareDistribution\DeliveryOptimization') 'Update delivery cache.' -IsFile:$false
Add-SysItem 'Windows Error Reporting' (Join-Path $Root 'ProgramData\Microsoft\Windows\WER') 'Crash/error reports.' -IsFile:$false
Add-SysItem 'LiveKernelReports' (Join-Path $Root 'Windows\LiveKernelReports') 'Kernel dump files.' -IsFile:$false
Add-SysItem 'User CrashDumps' (Join-Path $env:LOCALAPPDATA 'CrashDumps') 'Application crash dumps.' -IsFile:$false
Add-SysItem 'CBS logs' (Join-Path $Root 'Windows\Logs\CBS') 'Component servicing logs.' -IsFile:$false
Add-SysItem 'MEMORY.DMP' (Join-Path $Root 'Windows\MEMORY.DMP') 'Full memory dump (if any).' -IsFile:$true
Add-SysItem 'Minidumps' (Join-Path $Root 'Windows\Minidump') 'Small crash dumps.' -IsFile:$false
Add-SysItem 'Windows Search index' (Join-Path $Root 'ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb') 'Search index database; rebuilt by Windows.' -IsFile:$true
Add-SysItem 'Prefetch' (Join-Path $Root 'Windows\Prefetch') 'Prefetch data; regenerated.' -IsFile:$false
Add-SysItem 'Recycle Bin' (Join-Path $Root '$Recycle.Bin') 'Deleted files still occupying space.' -IsFile:$false
Add-SysItem 'hiberfil.sys' (Join-Path $Root 'hiberfil.sys') 'Hibernation file; powercfg /h off frees it.' -IsFile:$true
Add-SysItem 'pagefile.sys' (Join-Path $Root 'pagefile.sys') 'Paging file; size is system-managed.' -IsFile:$true
Add-SysItem 'swapfile.sys' (Join-Path $Root 'swapfile.sys') 'Swap file for UWP apps.' -IsFile:$true

$dismText = ''
if (-not $SkipDism -and $IsAdmin) {
  try {
    Write-Host 'Running DISM /AnalyzeComponentStore (this may take a minute)...'
    $dismText = (DISM /Online /Cleanup-Image /AnalyzeComponentStore 2>&1 | Out-String)
    $systemItems += [PSCustomObject]@{
      Item = 'WinSxS (DISM analyze)'; Path = (Join-Path $Root 'Windows\WinSxS')
      Bytes = $null; Note = ($dismText -replace '\r?\n', ' ').Trim(); AutoClean = $false
    }
  } catch {
    Add-Err 'DISM' 'AnalyzeComponentStore' $_.Exception.Message
  }
}

$vssText = ''
try {
  $vssText = (vssadmin list shadowstorage /for=$driveLetter 2>&1 | Out-String)
  $systemItems += [PSCustomObject]@{
    Item = 'Shadow storage'; Path = $null; Bytes = $null
    Note = (($vssText -split '\r?\n' | Where-Object { $_ -match '\S' }) -join ' ').Trim(); AutoClean = $false
  }
} catch {
  Add-Err 'vssadmin' 'ShadowStorage' $_.Exception.Message
}

# ---------------------------------------------------------------------
# T7: bundled-software signals
# ---------------------------------------------------------------------
$bundle = @()
$suspiciousPathRx = '(?i)\\(temp|tmp|appdata\\local\\temp|appdata\\roaming|cache|crashpad)\\'

function Add-Bundle([string]$Kind, [string]$Name, [string]$Detail, [string]$Path) {
  $score = 40
  if ($Path -match $suspiciousPathRx) { $score += 25 }
  # A random-looking ProgramData vendor folder raises suspicion, but known
  # vendors (Microsoft, Google, ...) must not be penalised by this rule.
  if ($Path -match '(?i)programdata\\([^\\]+)\\') {
    $seg = $Matches[1]
    $knownVendor = $seg -match '(?i)^(microsoft|google|adobe|apple|nvidia|intel|amd|tencent|baidu|alibaba|oracle|vmware|realtek|common|package|windows|mozilla|jetbrains|docker|hp|dell|lenovo|asus|samsung|huawei|xiaomi)$'
    if (-not $knownVendor) { $score += 15 }
  }
  if (-not $Path) { $score += 10 }
  if ($Name -match '(?i)(cleaner|clean|update|updater|helper|assistant|accelerat|守护|加速|清理|优化)') { $score += 10 }
  if ($score -gt 100) { $score = 100 }
  $script:bundle += [PSCustomObject]@{
    Kind = $Kind; Name = $Name; Detail = $Detail; Path = $Path; Score = $score
    Bucket = (Get-BucketFromScore $score)
  }
}

foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
  $pn = [string]$svc.PathName
  if (-not $pn) { continue }
  $exe = $pn -replace '^"([^"]+)".*', '$1'
  if ($exe -eq $pn) { $exe = ($pn -split '\s+')[0] }
  $exe = [Environment]::ExpandEnvironmentVariables($exe)
  if (-not ($exe -match '^[A-Za-z]:\\')) { continue }
  if ($exe -match '(?i)\\windows\\system32\\') { continue }
  $suspicious = ($exe -match $suspiciousPathRx)
  if ($svc.State -eq 'Running' -or $suspicious) {
    $detail = 'state=' + $svc.State + '; start=' + $svc.StartMode
    Add-Bundle 'Service' $svc.Name $detail $exe
  }
}

foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
  $hidden = $false
  try { $hidden = [bool]$t.Settings.Hidden } catch {}
  foreach ($act in @($t.Actions)) {
    if (-not $act -or -not $act.Execute) { continue }
    $ex = [Environment]::ExpandEnvironmentVariables([string]$act.Execute)
    if ($ex -match '(?i)\\windows\\system32\\') { continue }
    if ($hidden -or ($ex -match $suspiciousPathRx)) {
      Add-Bundle 'ScheduledTask' $t.TaskName ('hidden=' + $hidden) $ex
    }
  }
}

foreach ($rk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
  $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
  if (-not $props) { continue }
  foreach ($p in $props.PSObject.Properties) {
    if ($p.Name -like 'PS*') { continue }
    $v = [string]$p.Value
    $ex = $v -replace '^"([^"]+)".*', '$1'
    if ($ex -eq $v) { $ex = ($v -split '\s+')[0] }
    $ex = [Environment]::ExpandEnvironmentVariables($ex)
    if ($ex -match $suspiciousPathRx) {
      Add-Bundle 'Autorun' $p.Name $rk $ex
    }
  }
}

# ---------------------------------------------------------------------
# T8: installation residue (report only)
# ---------------------------------------------------------------------
$residue = @()
$uninstRoots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
foreach ($h in $uninstRoots) {
  if (-not (Test-Path $h)) { continue }
  foreach ($key in (Get-ChildItem $h -ErrorAction SilentlyContinue)) {
    $disp = $key.GetValue('DisplayName')
    $loc = [string]$key.GetValue('InstallLocation')
    if ($disp -and $loc) {
      $clean = $loc.Trim().Trim('"').Trim()
      if ($clean -and -not (Test-Path -LiteralPath $clean -ErrorAction SilentlyContinue)) {
        $residue += [PSCustomObject]@{ Kind = 'UninstallKey'; Name = $disp; Path = $clean; Note = 'InstallLocation missing' }
      }
    }
  }
}
foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
  $pn = [string]$svc.PathName
  if (-not $pn) { continue }
  $exe = $pn -replace '^"([^"]+)".*', '$1'
  if ($exe -eq $pn) { $exe = ($pn -split '\s+')[0] }
  $exe = [Environment]::ExpandEnvironmentVariables($exe)
  if (($exe -match '^[A-Za-z]:\\') -and -not (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) {
    $residue += [PSCustomObject]@{ Kind = 'Service'; Name = $svc.Name; Path = $exe; Note = 'executable missing' }
  }
}

# ---------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------
$coverage = Get-CoverageInfo $usedBytes $accountedBytes $script:Errors.Count

# ---------------------------------------------------------------------
# Plan draft
# ---------------------------------------------------------------------
$planTargets = @()
foreach ($c in ($cacheItems | Sort-Object Bytes -Descending)) {
  if ($c.Bucket -eq 'C') { continue }
  if ($c.DataFingerprint) { continue }
  $planTargets += [PSCustomObject]@{
    Path = $c.Path
    Operation = 'Quarantine'
    EstimatedLogicalSizeBytes = $c.Bytes
    Justification = ('deep-scan ' + $c.Kind + '; score=' + $c.Score + '; age=' + $c.AgeDays + 'd')
    RiskLevel = $(if ($c.Score -ge 80) { 'Low' } else { 'Medium' })
    Bucket = $c.Bucket
    ApprovalStatus = 'Pending'
    ApprovedOperation = ''
    RequiresConfirmation = $true
    Reversible = $true
  }
}
foreach ($j in ($junkDirs | Sort-Object Bytes -Descending)) {
  $planTargets += [PSCustomObject]@{
    Path = $j.Path
    Operation = 'Quarantine'
    EstimatedLogicalSizeBytes = $j.Bytes
    Justification = ('junk files older than ' + $MinJunkAgeDays + ' days; count=' + $j.Count)
    RiskLevel = 'Medium'
    Bucket = 'B'
    ApprovalStatus = 'Pending'
    ApprovedOperation = ''
    RequiresConfirmation = $true
    Reversible = $true
  }
}

$report = [PSCustomObject]@{
  GeneratedAt = (Get-Date).ToString('o')
  Root = $Root
  Admin = $IsAdmin
  DriveUsedBytes = $usedBytes
  DriveFreeBytes = $freeBytes
  Coverage = $coverage
  Counts = [PSCustomObject]@{ Dirs = $dirsSeen; Files = $fileCount; ReparseSkips = $script:ReparseSkips; PlaceholdersExcluded = $script:PlaceholderExcluded }
  TopLevel = [PSCustomObject]$topSizes
  CacheItems = @($cacheItems | Sort-Object Bytes -Descending | Select-Object -First $MaxCacheItems)
  JunkDirs = @($junkDirs | Sort-Object Bytes -Descending)
  LargeFiles = @($largeFiles | Sort-Object Bytes -Descending | Select-Object -First $MaxLargeFiles)
  SystemItems = @($systemItems)
  BundleSignals = @($bundle | Sort-Object Score -Descending)
  Residue = @($residue | Select-Object -First 100)
  Errors = @($script:Errors | Select-Object -First 100)
  Targets = @($planTargets)
  Note = 'Sizes are logical estimates. Hardlinks may double-count; OneDrive placeholders are excluded; reparse points are not followed. Actual freed space must be measured after execution.'
}

$json = $report | ConvertTo-Json -Depth 10
if ($OutFile) {
  [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding $true))
  Write-Host ('Deep-scan JSON written to: ' + $OutFile)
}

function FmtGB([long]$b) { return [math]::Round(($b / 1GB), 2) }

Write-Host ''
Write-Host '==============================================================================='
Write-Host '  Deep Scan (READ-ONLY)'
Write-Host '==============================================================================='
Write-Host ('[1] Baseline / coverage')
if ($isVolumeRoot) {
  Write-Host ('  Root {0}   Used {1} GB   Free {2} GB' -f $Root, (FmtGB $usedBytes), (FmtGB $freeBytes))
} else {
  Write-Host ('  Root {0}   Subtree size {1} GB (subdirectory scan)' -f $Root, (FmtGB $usedBytes))
}
Write-Host ('  Accounted {0} GB   Coverage {1}%   Gap {2} GB   Unreadable paths {3}' -f `
  (FmtGB $accountedBytes), $coverage.CoveragePercent, (FmtGB ([math]::Abs($coverage.GapBytes))), $coverage.UnreadablePaths)
if ($coverage.GapBytes -lt 0) {
  Write-Host '  Note: logical accounting exceeds used bytes because hardlinks are counted per reference; coverage is treated as 100%.'
}
if (-not $coverage.Complete) {
  Write-Host '  WARNING: coverage gap is large; the report is INCOMPLETE (permissions, hardlinks or unreadable areas).'
}
Write-Host ('  Dirs {0}   Files {1}   Reparse skipped {2}   Placeholders excluded {3}' -f $dirsSeen, $fileCount, $script:ReparseSkips, $script:PlaceholderExcluded)
Write-Host ''
Write-Host ('[2] Cache / dev-cache directories (top 20 of ' + $cacheItems.Count + ')')
$cacheItems | Sort-Object Bytes -Descending | Select-Object -First 20 | ForEach-Object {
  Write-Host ('  {0,7} GB  score={1,3}  {2}  {3}' -f (FmtGB $_.Bytes), $_.Score, $_.Bucket, $_.Path)
}
Write-Host ''
Write-Host ('[3] Junk files by directory (top 15 of ' + $junkDirs.Count + ')')
$junkDirs | Sort-Object Bytes -Descending | Select-Object -First 15 | ForEach-Object {
  Write-Host ('  {0,7} GB  files={1,6}  {2}' -f (FmtGB $_.Bytes), $_.Count, $_.Path)
}
Write-Host ''
Write-Host ('[4] Large files (> ' + $LargeFileMB + ' MB, top 15)')
$largeFiles | Sort-Object Bytes -Descending | Select-Object -First 15 | ForEach-Object {
  Write-Host ('  {0,7} GB  age={1,5}d  {2}' -f (FmtGB $_.Bytes), $_.AgeDays, $_.Path)
}
Write-Host ''
Write-Host '[5] System reclaimable (report only)'
foreach ($s in $systemItems) {
  $sz = 'n/a'
  if ($s.Bytes -ne $null) { $sz = (FmtGB ([long]$s.Bytes)).ToString() + ' GB' }
  Write-Host ('  {0,-32} {1,10}  {2}' -f $s.Item, $sz, $s.Note)
}
Write-Host ''
Write-Host ('[6] Bundled-software signals (' + $bundle.Count + ')')
$bundle | Sort-Object Score -Descending | Select-Object -First 15 | ForEach-Object {
  Write-Host ('  score={0,3}  {1,-14} {2}  {3}' -f $_.Score, $_.Kind, $_.Name, $_.Path)
}
Write-Host ''
Write-Host ('[7] Installation residue (' + $residue.Count + ')')
$residue | Select-Object -First 15 | ForEach-Object {
  Write-Host ('  {0,-12} {1}  ->  {2}' -f $_.Kind, $_.Name, $_.Path)
}
Write-Host ''
Write-Host ('[8] Errors (' + $script:Errors.Count + ')')
$script:Errors | Select-Object -First 10 | ForEach-Object {
  Write-Host ('  [' + $_.Stage + '] ' + $_.Path + ' :: ' + $_.Error)
}
Write-Host ''
Write-Host ('[9] Plan draft: ' + $planTargets.Count + ' targets, all Pending')
if ($OutFile) { Write-Host ('  JSON: ' + $OutFile) }
