# =====================================================================
# Invoke-DiskCleanup.ps1 - DryRun preview and/or authorized execution.
# Never scans. Validates the plan independently, re-verifies every target,
# quarantines by default, and writes an audit log.
# =====================================================================
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$PlanFile,
  [switch]$DryRun,
  [switch]$Execute,
  [string]$QuarantineRoot = '',
  [int]$QuarantineRetentionDays = 7,
  [string]$AuditLogPath = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$script:ExecErrors = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------
# Load the plan
# ---------------------------------------------------------------
if (-not (Test-Path -LiteralPath $PlanFile)) {
  Write-Error ("Plan file not found: " + $PlanFile)
  exit 1
}
try {
  # Read as explicit UTF-8: PowerShell 5.1's Get-Content can fall back to the
  # ANSI code page for files without a BOM, which corrupts non-ASCII JSON.
  $planText = [System.IO.File]::ReadAllText($PlanFile, [System.Text.Encoding]::UTF8)
  $plan = $planText | ConvertFrom-Json
} catch {
  Write-Error ("Plan file is not valid JSON: " + $_.Exception.Message)
  exit 1
}

$validationErrors = New-Object System.Collections.Generic.List[string]
if ($null -eq $plan.PSObject.Properties['PlanId']) { $validationErrors.Add('Missing PlanId') }
if ($null -eq $plan.PSObject.Properties['Version']) { $validationErrors.Add('Missing Version') }
if ($null -eq $plan.PSObject.Properties['SystemDrive']) { $validationErrors.Add('Missing SystemDrive') }
if ($null -eq $plan.PSObject.Properties['Targets']) { $validationErrors.Add('Missing Targets') }

$effectiveDryRun = $true
if ($Execute -and -not $DryRun) { $effectiveDryRun = $false }

Write-Host '==============================================================================='
Write-Host '  Windows Disk Cleanup - executor'
Write-Host ('  PlanId: ' + $plan.PlanId)
$modeText = 'DryRun (preview only)'
if (-not $effectiveDryRun) { $modeText = 'EXECUTE (live changes)' }
if (-not $Execute) { $modeText = $modeText + ' [default; pass -Execute to perform changes]' }
Write-Host ('  Mode: ' + $modeText)
Write-Host ('  Audit mode of source scan: ' + $plan.AuditMode)
Write-Host ('  Targets: ' + @($plan.Targets).Count)
Write-Host '==============================================================================='

if ($validationErrors.Count -gt 0) {
  Write-Warning 'Plan structure validation failed:'
  foreach ($e in $validationErrors) { Write-Host ('  - ' + $e) }
  exit 1
}

# ---------------------------------------------------------------
# Independent safety checks (do not trust labels in the plan)
# ---------------------------------------------------------------
$sysDrive = [string]$plan.SystemDrive
$sysRoot = $sysDrive.TrimEnd('\') + '\'
$userProfile = [string]$plan.UserProfile

$allowedOps = @('CleanCacheSubdirs', 'Quarantine', 'Delete', 'StopService', 'RemoveScheduledTask', 'RemoveAutorun')
$protectedFragments = @('pagefile.sys', 'swapfile.sys', 'hiberfil.sys', 'usoshared',
  'windows master store', 'system volume information')

function Test-ProtectedPath([string]$p) {
  $lp = $p.ToLowerInvariant()
  foreach ($frag in $protectedFragments) {
    if ($lp.Contains($frag)) { return $true }
  }
  $protectedExact = @(
    ($sysRoot.TrimEnd('\') + '\Windows'),
    ($sysRoot.TrimEnd('\') + '\Program Files'),
    ($sysRoot.TrimEnd('\') + '\Program Files (x86)'),
    ($sysRoot.TrimEnd('\') + '\ProgramData'),
    ($sysRoot.TrimEnd('\') + '\Users'),
    ($sysRoot.TrimEnd('\') + '\Windows.old'),
    ($sysRoot.TrimEnd('\') + '\Recovery'),
    ($sysRoot.TrimEnd('\') + '\System Volume Information')
  )
  if ($userProfile) {
    $protectedExact += @(
      ($userProfile.TrimEnd('\') + '\AppData'),
      ($userProfile.TrimEnd('\') + '\AppData\Local'),
      ($userProfile.TrimEnd('\') + '\AppData\Roaming'),
      ($userProfile.TrimEnd('\') + '\AppData\LocalLow'),
      $userProfile.TrimEnd('\')
    )
  }
  $norm = ($p.TrimEnd('\') -replace '/', '\').ToLowerInvariant()
  foreach ($pe in $protectedExact) {
    if ($norm -eq $pe.TrimEnd('\').ToLowerInvariant()) { return $true }
  }
  foreach ($x in ($sysRoot, $sysDrive + '\')) {
    if ($norm -eq $x.TrimEnd('\').ToLowerInvariant()) { return $true }
  }
  return $false
}

function Get-FreeBytes([string]$fd) {
  try {
    $psd = Get-PSDrive -Name ($fd -replace ':', '') -ErrorAction Stop
    return [long]$psd.Free
  } catch {
    return [long]-1
  }
}

function Get-LogicalSize([string]$Path) {
  $total = [long]0
  $errs = $null
  $files = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue -ErrorVariable +errs
  if ($errs) {
    foreach ($e in $errs) {
      $msg = 'size calculation failed'
      if ($e.Exception) { $msg = $e.Exception.Message }
      $script:ExecErrors.Add([PSCustomObject]@{ Path = $Path; Stage = 'SizeCalculation'; Error = $msg })
    }
  }
  foreach ($f in $files) {
    if ($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
    $total += $f.Length
  }
  return $total
}

$cacheSubNames = @('cache', 'cachedata', 'code cache', 'gpucache', 'dawnwebgpucache',
  'dawngraphitecache', 'service worker', 'cachestorage', 'crashpad', 'logs', 'log',
  'temp', 'tmp', 'thumbnail', 'thumbcache', 'component_crx_cache', 'shaders',
  'dxcache', 'glcache', 'httpcache', 'blobstorage', 'sharedcache', 'filemsg',
  'richvideo', 'inputtemp', 'media', 'filestorage', 'downloaded', 'report', 'crashreports')
function Test-CacheSub([string]$Name) {
  $n = $Name.ToLowerInvariant()
  foreach ($c in $cacheSubNames) { if ($n -eq $c -or $n -like $c) { return $true } }
  return $false
}

$freeBefore = Get-FreeBytes $sysDrive
$validation = New-Object System.Collections.Generic.List[object]
$ready = New-Object System.Collections.Generic.List[object]
$skipped = New-Object System.Collections.Generic.List[object]

foreach ($t in @($plan.Targets)) {
  if (-not $t) { continue }
  $p = [string]$t.Path
  $op = [string]$t.ApprovedOperation
  if ([string]::IsNullOrWhiteSpace($op)) { $op = [string]$t.Operation }
  $problems = New-Object System.Collections.Generic.List[string]

  if ([string]::IsNullOrWhiteSpace($p)) { $problems.Add('Empty path') }
  elseif (-not ($p -match '^[A-Za-z]:\\')) { $problems.Add('Not an absolute drive path: ' + $p) }
  if ($p -match '\.\.') { $problems.Add('Path traversal detected: ' + $p) }
  if ($p -and (Test-ProtectedPath $p)) { $problems.Add('Protected path: ' + $p) }
  if ([string]$t.ApprovalStatus -ne 'Approved') {
    $problems.Add('Not approved (ApprovalStatus=' + [string]$t.ApprovalStatus + ')')
  }
  if ($allowedOps -notcontains $op) { $problems.Add('Unsupported operation: ' + $op) }
  $reportOnlyOps = @('StopService', 'RemoveScheduledTask', 'RemoveAutorun')
  if ($reportOnlyOps -contains $op) {
    $problems.Add('Operation ' + $op + ' is report-only in v1.0; service/task/autorun configuration must be changed manually')
  }

  $exists = $false
  if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) {
    $exists = $true
    try {
      $item = Get-Item -LiteralPath $p -Force -ErrorAction Stop
      if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        $problems.Add('Target is a reparse point: ' + $p)
      }
    } catch {
      $problems.Add('Cannot stat target: ' + $_.Exception.Message)
    }
  }

  $record = [PSCustomObject]@{
    Path = $p
    Operation = $op
    Bucket = $t.Bucket
    EstimatedLogicalSizeBytes = $t.EstimatedLogicalSizeBytes
    RiskLevel = $t.RiskLevel
    Reversible = $t.Reversible
    Exists = $exists
    Problems = @($problems)
    Decision = 'Pending'
  }
  if ($problems.Count -gt 0) {
    $record.Decision = 'Rejected'
    $skipped.Add($record)
  } elseif (-not $exists) {
    $record.Decision = 'Skipped'
    $record.Problems = @('Target no longer exists (changed since scan)')
    $skipped.Add($record)
  } else {
    $record.Decision = 'Ready'
    $ready.Add($record)
  }
  $validation.Add($record)
}

# ---------------------------------------------------------------
# Report validation results
# ---------------------------------------------------------------
Write-Host ''
Write-Host '[Validation]'
foreach ($v in $validation) {
  $line = '  ' + $v.Decision.PadRight(8) + ' ' + $v.Operation.PadRight(18) + ' ' + $v.Path
  if ($v.Decision -eq 'Rejected') {
    Write-Host $line -ForegroundColor Yellow
    foreach ($pr in $v.Problems) { Write-Host ('             -> ' + $pr) }
  } else {
    Write-Host $line
  }
}

# ---------------------------------------------------------------
# DryRun
# ---------------------------------------------------------------
if ($effectiveDryRun) {
  Write-Host ''
  Write-Host '[DryRun] Planned operations (nothing has been changed):'
  $estimated = [long]0
  foreach ($r in $ready) {
    $estimated += [long]$r.EstimatedLogicalSizeBytes
    Write-Host ('  ' + $r.Operation.PadRight(18) + ' {0,8} GB  {1}' -f [math]::Round(([long]$r.EstimatedLogicalSizeBytes / 1GB), 2), $r.Path)
  }
  Write-Host ''
  Write-Host ('  Ready: {0}   Skipped/Rejected: {1}   Estimated logical size: {2} GB' -f $ready.Count, $skipped.Count, [math]::Round(($estimated / 1GB), 2))
  Write-Host '  NOTE: DryRun success does NOT grant execution authorization.'
  Write-Host '  Re-run with -Execute (and a quarantine volume) to perform changes.'
  Write-Host '==============================================================================='
  exit 0
}

# ---------------------------------------------------------------
# Execute
# ---------------------------------------------------------------
$quarRoot = $QuarantineRoot
if ([string]::IsNullOrWhiteSpace($quarRoot)) {
  $quarRoot = Join-Path $env:TEMP ('disk-cleanup-quarantine-' + [string]$plan.PlanId)
}
$quarDir = Join-Path $quarRoot ([string]$plan.PlanId)

$isCrossVolume = $true
if ($quarRoot -match '^[A-Za-z]:') {
  $qQualifier = (Split-Path $quarRoot -Qualifier)
  $isCrossVolume = -not ($qQualifier -eq $sysDrive)
}
if (-not $isCrossVolume) {
  Write-Warning ('Quarantine root is on the same volume as ' + $sysDrive + '. Moving files there will NOT free space on ' + $sysDrive + '. Point -QuarantineRoot at another volume for real space recovery.')
}

if (-not (Test-Path -LiteralPath $quarDir)) {
  New-Item -ItemType Directory -Path $quarDir -Force | Out-Null
}

$completed = New-Object System.Collections.Generic.List[object]
$failed = New-Object System.Collections.Generic.List[object]
$logicalDeleted = [long]0
$quarantinedBytes = [long]0
$manifest = New-Object System.Collections.Generic.List[object]

foreach ($r in $ready) {
  $p = $r.Path
  Write-Host ('  [Executing] ' + $r.Operation + ' ' + $p)
  try {
    if (-not (Test-Path -LiteralPath $p -ErrorAction Stop)) {
      throw 'Target disappeared before execution'
    }
    switch ($r.Operation) {
      'CleanCacheSubdirs' {
        $subDirs = @(Get-ChildItem -LiteralPath $p -Directory -Force -ErrorAction SilentlyContinue)
        $bytesRemoved = [long]0
        foreach ($sd in $subDirs) {
          if (-not (Test-CacheSub $sd.Name)) { continue }
          if ($sd.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
          $bytesRemoved += (Get-LogicalSize $sd.FullName)
          Remove-Item -LiteralPath $sd.FullName -Recurse -Force -ErrorAction Stop
        }
        $logicalDeleted += $bytesRemoved
        $completed.Add([PSCustomObject]@{ Path = $p; Operation = $r.Operation; LogicalBytes = $bytesRemoved })
        Write-Host ('             removed cache subdirs, {0} MB logical' -f [math]::Round($bytesRemoved / 1MB, 1))
      }
      'Quarantine' {
        $targetName = [System.IO.Path]::GetFileName($p.TrimEnd('\'))
        $stamp = (Get-Date -Format 'yyyyMMddHHmmss')
        $dest = Join-Path $quarDir ($stamp + '__' + $targetName)
        $size = Get-LogicalSize $p
        # Pre-flight lock check: never start a move that cannot finish.
        $lockedFiles = New-Object System.Collections.Generic.List[string]
        foreach ($file in (Get-ChildItem -LiteralPath $p -Recurse -Force -File -ErrorAction SilentlyContinue)) {
          try {
            $fs = [System.IO.File]::Open($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $fs.Close()
          } catch {
            $lockedFiles.Add($file.FullName)
          }
        }
        if ($lockedFiles.Count -gt 0) {
          throw ('Pre-flight failed: ' + $lockedFiles.Count + ' file(s) are in use (e.g. ' + $lockedFiles[0] + '). Nothing was moved; close the application and retry.')
        }
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        $moved = New-Object System.Collections.Generic.List[object]
        try {
          # Move top-level items one by one so a locked file cannot leave a
          # half-moved directory behind. Any failure rolls everything back.
          foreach ($ch in @(Get-ChildItem -LiteralPath $p -Force -ErrorAction Stop)) {
            if ($ch.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
              throw ('Refusing to move reparse point: ' + $ch.FullName)
            }
            Move-Item -LiteralPath $ch.FullName -Destination (Join-Path $dest $ch.Name) -Force -ErrorAction Stop
            $moved.Add($ch)
          }
          $remain = @(Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue)
          if ($remain.Count -gt 0) {
            throw ('Original directory still has ' + $remain.Count + ' item(s) after moving')
          }
          Remove-Item -LiteralPath $p -Force -ErrorAction Stop
        } catch {
          $errMsg = $_.Exception.Message
          $rollbackFailures = 0
          foreach ($m in $moved) {
            $src = Join-Path $dest $m.Name
            $dst = Join-Path $p $m.Name
            if (Test-Path -LiteralPath $src) {
              try { Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop }
              catch { $rollbackFailures++ }
            }
          }
          if (-not (Test-Path -LiteralPath $p)) {
            New-Item -ItemType Directory -Path $p -Force | Out-Null
          }
          $left = @(Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue)
          if (($left.Count -eq 0) -and (Test-Path -LiteralPath $dest)) {
            Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
          }
          if ($rollbackFailures -gt 0) {
            throw ('Quarantine failed; rollback incomplete (' + $rollbackFailures + ' item(s) still under ' + $dest + '): ' + $errMsg)
          }
          throw ('Quarantine failed; all moved items rolled back, original unchanged: ' + $errMsg)
        }
        $logicalDeleted += $size
        $quarantinedBytes += $size
        $manifest.Add([PSCustomObject]@{
          OriginalPath = $p
          QuarantinePath = $dest
          MovedAt = (Get-Date).ToString('o')
          LogicalBytes = $size
          ItemCount = $moved.Count
          Items = @($moved | ForEach-Object { $_.Name })
          RestoreMethod = 'Move-Item -LiteralPath "' + $dest + '" -Destination "' + $p + '" (original directory was removed after a complete move; ensure the original path does not already exist)'
        })
        $completed.Add([PSCustomObject]@{ Path = $p; Operation = $r.Operation; LogicalBytes = $size; QuarantinePath = $dest })
        Write-Host ('             quarantined to ' + $dest + ' (' + $moved.Count + ' top-level items)')
      }
      'Delete' {
        $size = Get-LogicalSize $p
        Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
        $logicalDeleted += $size
        $completed.Add([PSCustomObject]@{ Path = $p; Operation = $r.Operation; LogicalBytes = $size })
        Write-Host ('             deleted, {0} MB logical' -f [math]::Round($size / 1MB, 1))
      }
      'StopService' {
        $name = [System.IO.Path]::GetFileName($p)
        Stop-Service -Name $name -Force -ErrorAction Stop
        $completed.Add([PSCustomObject]@{ Path = $p; Operation = $r.Operation; LogicalBytes = 0 })
        Write-Host ('             service stopped: ' + $name)
      }
      'RemoveScheduledTask' {
        $name = [System.IO.Path]::GetFileName($p.TrimEnd('\'))
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
        $completed.Add([PSCustomObject]@{ Path = $p; Operation = $r.Operation; LogicalBytes = 0 })
        Write-Host ('             scheduled task removed: ' + $name)
      }
      'RemoveAutorun' {
        $keyPath = Split-Path $p -Parent
        $valueName = Split-Path $p -Leaf
        Remove-ItemProperty -Path $keyPath -Name $valueName -ErrorAction Stop
        $completed.Add([PSCustomObject]@{ Path = $p; Operation = $r.Operation; LogicalBytes = 0 })
        Write-Host ('             autorun value removed: ' + $valueName)
      }
      default {
        throw ('Unsupported operation at execution time: ' + $r.Operation)
      }
    }
  } catch {
    $failed.Add([PSCustomObject]@{ Path = $p; Operation = $r.Operation; Error = $_.Exception.Message })
    Write-Warning ('             FAILED: ' + $_.Exception.Message)
  }
}

# ---------------------------------------------------------------
# Post-execution verification
# ---------------------------------------------------------------
$freeAfter = Get-FreeBytes $sysDrive
$delta = [long]-1
if ($freeBefore -ge 0 -and $freeAfter -ge 0) { $delta = $freeAfter - $freeBefore }

Write-Host ''
Write-Host '==============================================================================='
Write-Host '[9] Execution and measured results'
Write-Host ('  Free before: {0} GB' -f [math]::Round($freeBefore / 1GB, 2))
Write-Host ('  Free after:  {0} GB' -f [math]::Round($freeAfter / 1GB, 2))
if ($delta -ge 0) {
  Write-Host ('  Measured delta: {0} GB' -f [math]::Round($delta / 1GB, 2))
} else {
  Write-Host '  Measured delta: unavailable'
}
Write-Host ('  Logical size touched: {0} GB (logical estimate; hardlinks may double-count)' -f [math]::Round($logicalDeleted / 1GB, 2))
if ($quarantinedBytes -gt 0) {
  Write-Host ('  Quarantined: {0} GB at {1}' -f [math]::Round($quarantinedBytes / 1GB, 2), $quarDir)
  if (-not $isCrossVolume) {
    Write-Host '  NOTE: quarantine is on the SAME volume, so this space has NOT been freed yet.'
  }
  Write-Host ('  Retention: {0} days. Expired items are reminder-only; permanent purge requires explicit approval.' -f $QuarantineRetentionDays)
}
Write-Host ('  Completed: {0}   Failed: {1}   Skipped/Rejected: {2}   Path errors: {3}' -f $completed.Count, $failed.Count, $skipped.Count, $script:ExecErrors.Count)
if ($failed.Count -gt 0) {
  Write-Host '  Failures:'
  foreach ($f in $failed) { Write-Host ('    ' + $f.Path + ' -> ' + $f.Error) }
}
Write-Host '  Logical size does not equal actual freed space. Use the measured delta as the real figure.'

# ---------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($AuditLogPath)) {
  $AuditLogPath = Join-Path $env:TEMP ('disk-cleanup-audit-' + [string]$plan.PlanId + '.json')
}
if ($manifest.Count -gt 0) {
  $manifestPath = Join-Path $quarDir 'restore-manifest.json'
  $manifest.ToArray() | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
  Write-Host ('  Restore manifest: ' + $manifestPath)
}
$auditLog = [PSCustomObject]@{
  PlanId = $plan.PlanId
  ExecutedAt = (Get-Date).ToString('o')
  SystemDrive = $sysDrive
  FreeBeforeBytes = $freeBefore
  FreeAfterBytes = $freeAfter
  MeasuredDeltaBytes = $delta
  LogicalTouchedBytes = $logicalDeleted
  QuarantinedBytes = $quarantinedBytes
  QuarantineDir = $quarDir
  QuarantineSameVolume = (-not $isCrossVolume)
  Validation = $validation.ToArray()
  Completed = $completed.ToArray()
  Failed = $failed.ToArray()
  Skipped = $skipped.ToArray()
  QuarantineManifest = $manifest.ToArray()
  ScanAndSizeErrors = $script:ExecErrors.ToArray()
}
$auditLog | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $AuditLogPath -Encoding UTF8
Write-Host ('  Audit log: ' + $AuditLogPath)
Write-Host '==============================================================================='
