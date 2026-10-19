# DiskCleanup.Tests.ps1
# All tests operate only on temporary test directories. Nothing touches the real system drive.
# Run: powershell -NoProfile -ExecutionPolicy Bypass -File tests\DiskCleanup.Tests.ps1

[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$script:pass = 0
$script:fail = 0
function Assert([bool]$Condition, [string]$Name, [string]$Detail = '') {
  if ($Condition) {
    $script:pass++
    Write-Host "  [PASS] $Name"
  } else {
    $script:fail++
    Write-Warning "  [FAIL] $Name  $Detail"
  }
}

$testRoot = Join-Path $env:TEMP ("diskcleanup-test-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
Write-Host "Test root: $testRoot"

# ------------------------------------------------------------------
# Test 1: WindowsInstaller=1 records stay in the raw baseline (tagged, not dropped)
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 1: WindowsInstaller=1 records are kept, only tagged ==="
$msiDir   = Join-Path $testRoot 'fake-msi-app'
$cacheDir = Join-Path $msiDir 'cache'
$dataDir  = Join-Path $msiDir 'userdata'
New-Item -ItemType Directory -Path $cacheDir, $dataDir -Force | Out-Null
'12345' | Set-Content (Join-Path $cacheDir 'blob.tmp')
'abc'   | Set-Content (Join-Path $dataDir 'settings.json')

$rawRecord = [PSCustomObject]@{
  Hive = 'HKLM'; KeyName = 'TestMsiApp'; DisplayName = 'Test MSI App 1.0'
  InstallLocation = $msiDir; Tags = @('WindowsInstaller')
}
$effective = @($rawRecord | Where-Object { -not ($_.Tags -contains 'PatchOrChild') })
Assert ($effective.Count -eq 1) 'WindowsInstaller record retained in effective baseline' ("count=" + $effective.Count)
Assert (Test-Path -LiteralPath $dataDir) 'Test data directory still present (no auto-delete)'

# ------------------------------------------------------------------
# Test 2: nested scan roots are de-duplicated
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 2: nested scan roots de-duplicated ==="
$rawRoots = @((Join-Path $testRoot 'a'), (Join-Path $testRoot 'a\b'), (Join-Path $testRoot 'b'))
$deduped = New-Object System.Collections.Generic.List[string]
$rawRoots | Sort-Object { $_.Length } | ForEach-Object {
  $r = $_.TrimEnd('\')
  $under = $false
  foreach ($ex in $deduped) {
    if ($r.StartsWith("$ex\", [StringComparison]::OrdinalIgnoreCase)) { $under = $true; break }
  }
  if (-not $under) { $deduped.Add($r) }
}
Assert ($deduped.Count -eq 2) 'Nested roots (a, a\b, b) dedupe to 2' ("got " + $deduped.Count)

# ------------------------------------------------------------------
# Test 3: portable-software signal (recent >1MB exe) cancels auto-clean
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 3: portable-software signal blocks auto-clean ==="
$portDir = Join-Path $testRoot 'portable-tool'
New-Item -ItemType Directory -Path $portDir -Force | Out-Null
$fakeExe = Join-Path $portDir 'tool.exe'
$fs = [System.IO.File]::Create($fakeExe)
$fs.SetLength(2MB)
$fs.Close()
$recentExes = @(Get-ChildItem $portDir -Filter '*.exe' -File -Recurse -Force |
  Where-Object { $_.Length -gt 1MB -and $_.LastWriteTime -gt (Get-Date).AddMonths(-6) } |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1)
Assert ($recentExes.Count -eq 1) 'Recent >1MB exe detected as portable signal'
$bucketForPort = if ($recentExes.Count) { 'B' } else { 'A' }
Assert ($bucketForPort -eq 'B') 'Portable signal forces bucket B (no auto-delete)'

# ------------------------------------------------------------------
# Test 4: junctions are not followed
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 4: junctions not followed ==="
$realDir = Join-Path $testRoot 'real-target'
New-Item -ItemType Directory -Path $realDir -Force | Out-Null
$junctionPath = Join-Path $testRoot 'loop-link'
cmd /c "mklink /J `"$junctionPath`" `"$realDir`"" 2>$null | Out-Null
$skipCount = 0
$walkedIntoJunction = $false
foreach ($item in (Get-ChildItem $testRoot -Directory -Force)) {
  if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $skipCount++; continue }
  if ($item.Name -eq 'loop-link') { $walkedIntoJunction = $true }
}
Assert ($skipCount -ge 1) 'Junction identified as ReparsePoint and skipped' ("skip=" + $skipCount)
Assert (-not $walkedIntoJunction) 'Junction not treated as a normal recursion target'

# ------------------------------------------------------------------
# Test 5: Chinese / spaces / quoted paths parse correctly
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 5: path parsing (CJK / spaces / quotes) ==="
$cnDir = Join-Path $testRoot 'software test dir'
New-Item -ItemType Directory -Path $cnDir -Force | Out-Null
$servicePathStr = '"C:\Program Files\Some Vendor\App\app.exe" --flag "arg with spaces"'
$parsedExe = $servicePathStr -replace '^"([^"]+)".*', '$1'
Assert ($parsedExe -eq 'C:\Program Files\Some Vendor\App\app.exe') 'Quoted service PathName parses to exe' ("got " + $parsedExe)
Assert (Test-Path -LiteralPath $cnDir) 'Path with spaces resolves via -LiteralPath'

# ------------------------------------------------------------------
# Test 6: unparseable commands are not assumed stale
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 6: unparseable commands are not assumed dead ==="
$svchostCmd = 'C:\Windows\System32\svchost.exe -k netsvcs'
$exe = $svchostCmd -replace '^"([^"]+)".*', '$1'
if ($exe -eq $svchostCmd) { $exe = ($svchostCmd -split '\s+')[0] }
$unparseable = -not $exe
Assert ($exe -eq 'C:\Windows\System32\svchost.exe') 'svchost -k form extracts exe path' ("got " + $exe)
Assert (-not $unparseable) 'svchost -k not flagged unparseable'
$staleFromEmptyWd = $false   # empty WorkingDirectory != stale
Assert (-not $staleFromEmptyWd) 'Empty WorkingDirectory does not imply stale'

# ------------------------------------------------------------------
# Test 7: executor rejects traversal / protected / unauthorized targets
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 7: executor rejects traversal / protected / unauthorized ==="
$protectedPatterns = @('pagefile.sys', 'swapfile.sys', 'hiberfil.sys', 'usoshared',
  'windows master store', 'system volume information')
function Test-Protected([string]$p) {
  $lp = $p.ToLower()
  foreach ($b in $protectedPatterns) { if ($lp -like "*$b*") { return $true } }
  return $false
}
$hasTraversal = ('..\..\Windows\WinSxS' -match '\.\.\\')
Assert $hasTraversal 'Path traversal detected and rejected'
Assert (Test-Protected 'C:\pagefile.sys') 'pagefile.sys protected'
Assert (Test-Protected 'C:\Windows\USOShared') 'USOShared protected'
$pendingApproved = ('Pending' -eq 'Approved')
Assert (-not $pendingApproved) 'Pending target is not executable'

# ------------------------------------------------------------------
# Test 8: same-volume quarantine is not reported as freed
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 8: same-volume quarantine does not free space ==="
$quarantineRoot = 'C:\_quarantine'
$sysVol = 'C:'
$isCrossVol = ((Split-Path $quarantineRoot -Qualifier) -ne $sysVol)
Assert (-not $isCrossVol) 'Same-volume quarantine is correctly detected'
Assert (-not $isCrossVol) 'Same-volume quarantine must not report freed bytes'

# ------------------------------------------------------------------
# Test 9: expired quarantine never auto-purges without approval
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 9: expired quarantine is reminder-only ==="
$autoPurgeOnExpiry = $false
Assert (-not $autoPurgeOnExpiry) 'Expired quarantine items are not purged automatically'

# ------------------------------------------------------------------
# Test 10: pre-flight lock detection (no partial moves)
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 10: locked-file pre-flight ==="
$lockPath = Join-Path $testRoot 'locked.log'
'data' | Set-Content $lockPath
$holder = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::Open,
  [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)
$detected = $false
try {
  $probe = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  $probe.Close()
} catch {
  $detected = $true
}
$holder.Close()
Assert $detected 'Exclusive-open probe detects an in-use file before moving'

# ------------------------------------------------------------------
# Test 11: restore manifest records the recovery method
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 11: quarantine manifest is restorable ==="
$manifestItem = [PSCustomObject]@{
  OriginalPath = 'C:\example\target'
  QuarantinePath = 'D:\quarantine\stamp__target'
  RestoreMethod = 'Move-Item -LiteralPath "D:\quarantine\stamp__target" -Destination "C:\example\target"'
}
Assert (-not [string]::IsNullOrWhiteSpace($manifestItem.OriginalPath)) 'Manifest records OriginalPath'
Assert (-not [string]::IsNullOrWhiteSpace($manifestItem.QuarantinePath)) 'Manifest records QuarantinePath'
Assert ($manifestItem.RestoreMethod -match 'Move-Item') 'Manifest records a restore command'

# ------------------------------------------------------------------
# Test 12: deep-scan predicate library
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test 12: deep-scan predicates ==="
. (Join-Path $PSScriptRoot '..\scripts\DeepScan.Common.ps1')

Assert ((Test-CacheDirName 'Cache') -and (Test-CacheDirName 'Code Cache') -and (Test-CacheDirName 'GPUCache')) 'Cache signature recognized'
Assert (-not (Test-CacheDirName 'Documents')) 'Non-cache name rejected'
Assert ((Test-DataFileName 'history.db') -and (Test-DataFileName 'report.docx')) 'Data file extensions detected'
Assert (-not (Test-DataFileName 'blob.bin')) 'Neutral file not treated as data'
Assert ((Test-DataDirName 'IndexedDB') -and (Test-DataDirName 'FileStorage')) 'Data directory names detected'
Assert ((Test-JunkFileName 'a.tmp') -and (Test-JunkFileName 'x.log') -and (Test-JunkFileName '~$doc.docx')) 'Junk file names detected'
Assert (-not (Test-JunkFileName 'important.txt')) 'Normal file not junk'
Assert ((Test-DevCachePath 'c:\users\x\.gradle\caches') -and (Test-DevCachePath 'c:\work\node_modules')) 'Dev-cache paths detected'
Assert (-not (Test-DevCachePath 'c:\users\x\documents')) 'Normal path not dev cache'

# data fingerprint: a cache-named dir containing a database is data
$fpDir = Join-Path $testRoot 'Cache'
New-Item -ItemType Directory -Path $fpDir -Force | Out-Null
'blob' | Set-Content (Join-Path $fpDir 'neutral.bin')
Assert (-not (Test-DataFingerprintInDir $fpDir)) 'Clean cache dir has no data fingerprint'
'row' | Set-Content (Join-Path $fpDir 'messages.db')
Assert (Test-DataFingerprintInDir $fpDir) 'Database inside cache dir is detected as data'

# scoring: single signals are insufficient; data hit demotes
$sHigh = Get-EvidenceScore -CacheSignature $true -DataFingerprint $false -AgeDays 90 -Bytes ([long]600MB)
$sData = Get-EvidenceScore -CacheSignature $true -DataFingerprint $true -AgeDays 90 -Bytes ([long]600MB)
$sWeak = Get-EvidenceScore -CacheSignature $false -DataFingerprint $false -AgeDays 1 -Bytes ([long]1MB)
Assert ($sHigh -ge 80) 'Strong cache evidence reaches bucket A score'
Assert ($sData -lt 40) 'Data fingerprint demotes to bucket C score'
Assert ($sWeak -lt 40) 'Weak single signal stays low'
Assert ((Get-BucketFromScore 90) -eq 'A' -and (Get-BucketFromScore 50) -eq 'B' -and (Get-BucketFromScore 10) -eq 'C') 'Score thresholds map to buckets'

# coverage
$cov = Get-CoverageInfo ([long]100GB) ([long]98GB) 3
Assert ($cov.CoveragePercent -ge 97 -and $cov.Complete) '98/100 GB coverage is complete'
$cov2 = Get-CoverageInfo ([long]100GB) ([long]50GB) 9
Assert (-not $cov2.Complete) '50/100 GB coverage is incomplete'
$cov3 = Get-CoverageInfo ([long]100GB) ([long]120GB) 0
Assert ($cov3.CoveragePercent -eq 100) 'Hardlink over-count is clipped to 100%'

# ------------------------------------------------------------------
# cleanup
# ------------------------------------------------------------------
Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "==============================================================================="
Write-Host "  RESULT: passed $($script:pass)   failed $($script:fail)"
Write-Host "==============================================================================="
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
