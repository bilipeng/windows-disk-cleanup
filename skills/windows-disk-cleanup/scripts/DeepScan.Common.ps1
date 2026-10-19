# =====================================================================
# DeepScan.Common.ps1 - pure helper functions for the deep scan.
# Dot-source this file; it performs no I/O on its own.
# =====================================================================

# --- cache directory signatures (generic semantics, not brand names) ---
$script:CacheDirNames = @(
  'cache', 'caches', 'cachedata', 'cache data',
  'code cache', 'gpucache', 'gpu cache', 'shadercache', 'shader cache',
  'dawnwebgpucache', 'dawngraphitecache', 'dawnd3d12cache',
  'service worker', 'cachestorage', 'cache storage',
  'crashpad', 'crashreports', 'crash reports', 'crashdumps', 'crash dumps',
  'logs', 'log', 'tmp', 'temp',
  'thumbnail', 'thumbnails', 'thumbcache', 'iconcache', 'icon cache',
  'component_crx_cache', 'dxcache', 'glcache', 'httpcache', 'webcache',
  'blobstorage', 'blob storage', 'sharedcache', 'filecache', 'fontcache',
  'mediacache', 'media cache', 'video cache', 'image cache',
  'update cache', 'updates cache', 'installer cache', 'download cache'
)
function Test-CacheDirName([string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $n = $Name.Trim().ToLowerInvariant()
  foreach ($c in $script:CacheDirNames) {
    if ($n -eq $c) { return $true }
  }
  # well-known compound suffixes such as "Cache_Data", "CacheStorage2"
  if ($n -match '^cache([_-]?\d+)?$') { return $true }
  if ($n -match '^gpu[_-]?cache\d*$') { return $true }
  if ($n -match '^code[_-]?cache\d*$') { return $true }
  return $false
}

# --- data fingerprints: presence means "this is user data, do not auto-clean" ---
$script:DataFileExtensions = @(
  '.db', '.sqlite', '.sqlite3', '.db-wal', '.db-shm', '.mdb', '.accdb',
  '.pst', '.ost', '.eml', '.msg',
  '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
  '.psd', '.ai', '.indd', '.blend', '.uasset', '.umap', '.unity', '.fbx', '.max',
  '.sln', '.csproj', '.vcxproj', '.iml',
  '.kdbx', '.key', '.pem', '.pfx'
)
$script:DataDirNames = @(
  'indexeddb', 'local storage', 'partitions', 'msg', 'msgs', 'filestorage',
  'projects', 'workspace', '.git', '.idea', '.vscode'
)
function Test-DataFileName([string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $n = $Name.ToLowerInvariant()
  foreach ($e in $script:DataFileExtensions) {
    if ($n.EndsWith($e)) { return $true }
  }
  return $false
}
function Test-DataDirName([string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $n = $Name.Trim().ToLowerInvariant()
  return ($script:DataDirNames -contains $n)
}

# Sample a directory (depth <= 2, max files) for data fingerprints.
function Test-DataFingerprintInDir([string]$Path, [int]$MaxFiles = 400, [int]$MaxDepth = 2) {
  $seen = 0
  $stack = New-Object System.Collections.Generic.Stack[object]
  $stack.Push([PSCustomObject]@{ Dir = $Path; Depth = 0 })
  while ($stack.Count -gt 0) {
    $cur = $stack.Pop()
    try {
      $di = New-Object System.IO.DirectoryInfo($cur.Dir)
      foreach ($fsi in $di.EnumerateFileSystemInfos()) {
        if ($fsi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
        if ($fsi -is [System.IO.DirectoryInfo]) {
          if (Test-DataDirName $fsi.Name) { return $true }
          if ($cur.Depth -lt $MaxDepth) {
            $stack.Push([PSCustomObject]@{ Dir = $fsi.FullName; Depth = ($cur.Depth + 1) })
          }
        } else {
          $seen++
          if (Test-DataFileName $fsi.Name) { return $true }
          if ($seen -ge $MaxFiles) { return $false }
        }
      }
    } catch {
      continue
    }
  }
  return $false
}

# --- junk files ---
$script:JunkExtensions = @(
  '.tmp', '.temp', '.log', '.dmp', '.mdmp', '.old', '.bak', '.chk',
  '.crdownload', '.part', '.swp', '.swo', '.~lock'
)
function Test-JunkFileName([string]$Name) {
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
  $n = $Name.ToLowerInvariant()
  foreach ($e in $script:JunkExtensions) {
    if ($n.EndsWith($e)) { return $true }
  }
  # Office/lock style temporary names: "~$document.docx", "~WRL0001.tmp"
  if ($n -match '^~\$') { return $true }
  if ($n -match '^~wrl\d+\.tmp$') { return $true }
  return $false
}
function Test-JunkAge([datetime]$LastWrite, [int]$MinAgeDays) {
  return ($LastWrite -lt (Get-Date).AddDays(-1 * $MinAgeDays))
}

# --- scoring ---
# Any single signal is insufficient by design. Returns 0..100.
function Get-EvidenceScore {
  param(
    [bool]$CacheSignature = $false,
    [bool]$DataFingerprint = $false,
    [int]$AgeDays = 0,
    [long]$Bytes = 0,
    [bool]$InstalledRelated = $false,
    [bool]$ActiveProcess = $false,
    [bool]$Signed = $true,
    [bool]$DevCache = $false
  )
  if ($ActiveProcess) { return 0 }
  $score = 30
  if ($CacheSignature) { $score += 30 }
  if ($DevCache) { $score += 25 }
  if ($DataFingerprint) { $score -= 45 }
  if ($AgeDays -ge 30) { $score += 10 }
  if ($Bytes -ge 500MB) { $score += 10 }
  if ($InstalledRelated) { $score -= 10 }
  if (-not $Signed) { $score -= 10 }
  if ($score -lt 0) { $score = 0 }
  if ($score -gt 100) { $score = 100 }
  return $score
}
function Get-BucketFromScore([int]$Score) {
  if ($Score -ge 80) { return 'A' }
  if ($Score -ge 40) { return 'B' }
  return 'C'
}

# --- coverage ---
function Get-CoverageInfo([long]$UsedBytes, [long]$AccountedBytes, [int]$UnreadablePaths) {
  $gap = $UsedBytes - $AccountedBytes
  $pct = 0
  if ($UsedBytes -gt 0) { $pct = [math]::Round(($AccountedBytes / $UsedBytes) * 100, 2) }
  if ($pct -gt 100) { $pct = 100 }
  return [PSCustomObject]@{
    UsedBytes = $UsedBytes
    AccountedBytes = $AccountedBytes
    GapBytes = $gap
    CoveragePercent = $pct
    UnreadablePaths = $UnreadablePaths
    Complete = (($pct -ge 95.0) -and ($pct -le 100))
  }
}

# --- dev cache semantics ---
# Matches by path segment combinations, not by product brand.
function Test-DevCachePath([string]$LowerPath) {
  $patterns = @(
    '\\node_modules$',
    '\\\.gradle\\caches$', '\\\.gradle\\wrapper\\dists$',
    '\\\.m2\\repository$',
    '\\\.nuget\\packages$',
    '\\pip\\cache$', '\\pip\\http$',
    '\\npm-cache$', '\\npm-cache\\_cacache$',
    '\\pnpm-store$', '\\pnpm-cache$',
    '\\yarn\\cache$', '\\yarn\\berry\\cache$',
    '\\uv\\cache$',
    '\\cargo\\registry$', '\\cargo\\git$',
    '\\go\\pkg\\mod$',
    '\\conda\\pkgs$', '\\anaconda3\\pkgs$', '\\miniconda3\\pkgs$',
    '\\\.cache\\pip$', '\\\.cache\\uv$',
    '\\\.next\\cache$', '\\\.parcel-cache$', '\\\.turbo$'
  )
  foreach ($p in $patterns) { if ($LowerPath -match $p) { return $true } }

  # Build-output directories are only regenerable when a project manifest
  # sits beside them; otherwise "build"/"dist"/"target" may be user output.
  if ($LowerPath -match '\\(target|build|dist)$') {
    $parent = Split-Path $LowerPath -Parent
    $manifests = @('package.json', 'cargo.toml', 'build.gradle', 'build.gradle.kts',
      'pom.xml', 'cmakelists.txt', 'makefile', 'pyproject.toml', 'setup.py', 'go.mod')
    foreach ($m in $manifests) {
      if (Test-Path -LiteralPath (Join-Path $parent $m) -ErrorAction SilentlyContinue) { return $true }
    }
    $proj = @(Get-ChildItem -LiteralPath $parent -Filter '*.csproj' -File -ErrorAction SilentlyContinue)
    if ($proj.Count -gt 0) { return $true }
    return $false
  }
  return $false
}
