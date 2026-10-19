# =====================================================================
# Invoke-DiskAudit.ps1 - READ-ONLY audit for Windows system drive.
# Powershell 5.1 compatible. Deletes / moves / modifies nothing.
# =====================================================================
[CmdletBinding()]
param(
  [ValidateSet('CurrentUser', 'AllUsers')]
  [string]$Scope = 'CurrentUser',
  [string]$OutFile = '',
  [string[]]$ExtraScanRoots = @(),
  [switch]$RequestElevation
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ScanErrors = New-Object System.Collections.Generic.List[object]
$ReparseSkips = 0
$PlaceholderExcluded = 0

function Add-ScanError([string]$Path, [string]$Reason, [string]$Stage) {
  $script:ScanErrors.Add([PSCustomObject]@{ Path = $Path; Reason = $Reason; Stage = $Stage })
}

# Extract the executable path from a command line.
# Handles: quoted paths, unquoted paths containing spaces, env vars, and
# interpreter forms such as "cmd.exe /c ...". Returns $null when the string
# cannot be reliably parsed, so callers can mark it Unparseable instead of stale.
function Get-ExeFromCommand([string]$CommandLine) {
  if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
  $s = [Environment]::ExpandEnvironmentVariables([string]$CommandLine).Trim()
  if ($s.Length -eq 0) { return $null }
  if ($s.StartsWith('"')) {
    $end = $s.IndexOf('"', 1)
    if ($end -gt 1) { return $s.Substring(1, $end - 1) }
    return $null
  }
  $m = [regex]::Match($s, '^(?<exe>.+?\.exe)(\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
  if ($m.Success) { return $m.Groups['exe'].Value }
  $first = ($s -split '\s+')[0]
  if ($first -match '\.exe$') { return $first }
  if ($first -match '^[A-Za-z]:\\') { return $first }
  return $null
}

# =====================================================================
# A. Baseline (dynamic system drive)
# =====================================================================
$osInfo = Get-CimInstance Win32_OperatingSystem
$sysDrive = $osInfo.SystemDrive.TrimEnd('\')
$sysRoot = $sysDrive + '\'
$windir = $env:SystemRoot
$pfDir = Join-Path $sysRoot 'Program Files'
$pf86Dir = Join-Path $sysRoot 'Program Files (x86)'
$pdDir = Join-Path $sysRoot 'ProgramData'
$userDir = $env:USERPROFILE
$localDir = $env:LOCALAPPDATA
$roamDir = Join-Path $userDir 'AppData\Roaming'
$lowDir = Join-Path $userDir 'AppData\LocalLow'
$tempDir = $env:TEMP

function Get-IsElevated {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wpr = New-Object Security.Principal.WindowsPrincipal($id)
    return $wpr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}
$IsAdmin = Get-IsElevated

# ---- manual elevation path -------------------------------------------
# When the user wants a complete audit but the session is not elevated,
# -RequestElevation relaunches this script through UAC. The user must
# approve the prompt; nothing is elevated silently.
if (-not $IsAdmin -and $RequestElevation) {
  $argParts = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'))
  $argParts += @('-Scope', $Scope)
  if ($OutFile) { $argParts += @('-OutFile', ('"' + $OutFile + '"')) }
  foreach ($r in $ExtraScanRoots) { $argParts += @('-ExtraScanRoots', ('"' + $r + '"')) }
  $argString = $argParts -join ' '
  try {
    Write-Host 'Requesting elevation (approve the UAC prompt to run a complete audit)...'
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argString
    exit 0
  } catch {
    Write-Warning ('Elevation was not granted: ' + $_.Exception.Message)
    Write-Warning 'Continuing with an INCOMPLETE non-admin audit.'
  }
}
elseif (-not $IsAdmin) {
  Write-Host 'Hint: run again with -RequestElevation to get a UAC prompt for a complete audit,'
  Write-Host ('      or start an elevated shell and run: powershell -File "' + $PSCommandPath + '" -Scope ' + $Scope)
}

function Probe-SpecialFile([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    return [PSCustomObject]@{ Path = $Path; Exists = $false; SizeBytes = $null; Readable = $null }
  }
  try {
    $len = (Get-Item -LiteralPath $Path -Force).Length
    return [PSCustomObject]@{ Path = $Path; Exists = $true; SizeBytes = $len; Readable = $true }
  } catch {
    return [PSCustomObject]@{ Path = $Path; Exists = $true; SizeBytes = $null; Readable = $false }
  }
}

$specialFiles = [PSCustomObject]@{
  Hiberfil = Probe-SpecialFile (Join-Path $sysRoot 'hiberfil.sys')
  Pagefile = Probe-SpecialFile (Join-Path $sysRoot 'pagefile.sys')
  Swapfile = Probe-SpecialFile (Join-Path $sysRoot 'swapfile.sys')
}

$driveObj = Get-PSDrive -Name ($sysDrive -replace ':', '')
$totalBytes = [long]0
if ($driveObj.PSObject.Properties['Used']) { $totalBytes = [long]$driveObj.Used + [long]$driveObj.Free }
$baseline = [PSCustomObject]@{
  OSVersion = $osInfo.Version
  OSCaption = $osInfo.Caption
  SystemDrive = $sysDrive
  TotalGB = [math]::Round($totalBytes / 1GB, 1)
  FreeGB = [math]::Round($driveObj.Free / 1GB, 1)
  IsAdmin = $IsAdmin
  Scope = $Scope
  SpecialFiles = $specialFiles
}

if (-not $IsAdmin) {
  Write-Warning "Non-admin mode: C:\ProgramData, other users' profiles and some system paths cannot be fully enumerated. Report is INCOMPLETE. Re-run elevated for a full audit."
}

# =====================================================================
# B. Installed-program baseline (raw records kept; only tagged)
# =====================================================================
$uninstHives = @(
  @{ H = 'HKLM'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' },
  @{ H = 'HKLM-32'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' },
  @{ H = 'HKCU'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
)

$rawUninst = @()
foreach ($h in $uninstHives) {
  if (-not (Test-Path $h.Path)) { continue }
  try {
    $items = Get-ChildItem $h.Path -ErrorAction Stop
  } catch {
    Add-ScanError $h.Path $_.Exception.Message 'UninstallKeyEnumeration'
    continue
  }
  foreach ($p in $items) {
    $disp = $null
    try { $disp = $p.GetValue('DisplayName') } catch {}
    if (-not $disp) { continue }
    $sysComp = $null; $msiFlag = $null; $parentKey = $null; $installLoc = $null
    try {
      $sysComp = $p.GetValue('SystemComponent')
      $msiFlag = $p.GetValue('WindowsInstaller')
      $parentKey = $p.GetValue('ParentKeyName')
      $installLoc = $p.GetValue('InstallLocation')
    } catch {}
    $tags = @()
    if ($sysComp -eq 1) { $tags += 'SystemComponent' }
    if ($msiFlag -eq 1) { $tags += 'WindowsInstaller' }
    if ($parentKey) { $tags += 'PatchOrChild' }
    if ($disp -match '^(Update for |Security Update |Hotfix |KB\d{6,})') { $tags += 'UpdateOrKB' }
    $rawUninst += [PSCustomObject]@{
      Hive = $h.H
      KeyName = $p.PSChildName
      DisplayName = $disp
      InstallLocation = $installLoc
      Tags = $tags
    }
  }
}

# Effective apps = records usable for keyword evidence. Records are NOT removed from raw.
$effectiveApps = @($rawUninst | Where-Object {
  -not ($_.Tags -contains 'PatchOrChild') -and -not ($_.Tags -contains 'UpdateOrKB')
})
$displayNames = @($effectiveApps | ForEach-Object { $_.DisplayName } | Where-Object { $_ } | Sort-Object -Unique)

$StopTokens = @('driver','manager','player','helper','update','service','services','setup',
  'installer','install','runtime','library','libraries','framework','redistributable','vcredist',
  'tool','tools','agent','support','assistant','utility','suite','edition','version','client',
  'server','common','shared','component','components','sdk','dll','x64','x86','64bit','32bit','windows')

$tokenSet = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
foreach ($dn in $displayNames) {
  $norm = $dn -replace '\(.*?\)', '' -replace '\s+v?\d+(\.\d+)+', '' -replace '[^\w\s]', ' '
  $norm = ($norm -replace '\s+', ' ').Trim()
  if ($norm.Length -ge 5) { [void]$tokenSet.Add($norm) }
  foreach ($w in ($norm -split '\s+')) {
    if ($w.Length -ge 4 -and ($StopTokens -notcontains $w)) { [void]$tokenSet.Add($w) }
  }
}

# =====================================================================
# C. Candidate discovery
# =====================================================================
$installLocSet = New-Object System.Collections.Generic.List[string]
foreach ($loc in ($rawUninst | ForEach-Object { $_.InstallLocation } | Where-Object { $_ })) {
  $clean = ([string]$loc) -replace '^"', '' -replace '"$', ''
  if ($clean -and (Test-Path -LiteralPath $clean)) {
    try {
      $normLoc = (Resolve-Path -LiteralPath $clean).Path.TrimEnd('\')
      if (-not $installLocSet.Contains($normLoc)) { $installLocSet.Add($normLoc) }
    } catch {
      Add-ScanError $clean $_.Exception.Message 'InstallLocationResolve'
    }
  }
}

$rawRoots = @($userDir, $localDir, $roamDir, $lowDir, $pdDir, $pfDir, $pf86Dir, $tempDir) + $ExtraScanRoots
if ($Scope -eq 'AllUsers') {
  $usersRoot = Join-Path $sysRoot 'Users'
  try {
    $allProfiles = @(Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction Stop |
      Where-Object { $_.Name -notmatch '^(Public|Default|Default User|All Users)$' })
  } catch {
    $allProfiles = @()
    Add-ScanError $usersRoot $_.Exception.Message 'EnumerateUserProfiles'
  }
  foreach ($prof in $allProfiles) {
    $rawRoots += @(
      (Join-Path $prof.FullName 'AppData\Local'),
      (Join-Path $prof.FullName 'AppData\Roaming'),
      (Join-Path $prof.FullName 'AppData\LocalLow')
    )
  }
}

$scanRoots = New-Object System.Collections.Generic.List[string]
$rawRoots | Sort-Object { $_.Length } | ForEach-Object {
  $r = $_.TrimEnd('\')
  if (-not (Test-Path -LiteralPath $r)) { return }
  $underOther = $false
  foreach ($existing in $scanRoots) {
    if ($r.StartsWith($existing + '\', [StringComparison]::OrdinalIgnoreCase)) { $underOther = $true; break }
  }
  if (-not $underOther) { $scanRoots.Add($r) }
}

$procPaths = @()
try {
  $procPaths = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path |
    Where-Object { $_ })
} catch {
  Add-ScanError '<processes>' $_.Exception.Message 'EnumerateProcessPaths'
}

$cacheSubNames = @('cache','cachedata','code cache','gpucache','dawnwebgpucache','dawngraphitecache',
  'dawngl cache','service worker','cachestorage','crashpad','logs','log','temp','tmp','thumbnail',
  'thumbcache','component_crx_cache','shaders','dxcache','glcache','httpcache','blobstorage',
  'sharedcache','filemsg','richvideo','inputtemp','media','filestorage','downloaded','report',
  'crashreports')
$dataSubNames = @('indexeddb','local storage','databases','history','logins','login data','cookies',
  'wechat files','msg','wxwork','partitions','project','projects','workspace','model','models',
  'chat','chats','sessions','settings','config')

function Test-CacheSubName([string]$Name) {
  $n = $Name.ToLowerInvariant()
  foreach ($c in $cacheSubNames) { if ($n -eq $c -or $n -like $c) { return $true } }
  return $false
}
function Test-DataSubName([string]$Name) {
  $n = $Name.ToLowerInvariant()
  foreach ($d in $dataSubNames) { if ($n -eq $d -or $n -like $d) { return $true } }
  return $false
}

function Test-OwnedByApp([string]$DirName) {
  foreach ($t in $tokenSet) {
    if ($t.Length -ge 4 -and $DirName.IndexOf($t, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
  }
  return $false
}

$protectedPrefixes = @(
  (Join-Path $sysRoot 'Windows'),
  (Join-Path $sysRoot 'Windows.old'),
  (Join-Path $sysRoot 'PerfLogs'),
  (Join-Path $sysRoot 'Recovery'),
  (Join-Path $sysRoot 'System Volume Information')
)
function Test-ProtectedPath([string]$p) {
  $lp = $p.ToLowerInvariant()
  foreach ($x in $protectedPrefixes) {
    $xl = $x.ToLowerInvariant()
    if ($lp -eq $xl -or $lp.StartsWith($xl + '\')) { return $true }
  }
  $names = @('usoshared', 'windows master store')
  foreach ($n in $names) { if ($lp -like "*$n*") { return $true } }
  return $false
}

function Get-DirLogicalSize([string]$Path) {
  $s = [long]0
  $errs = $null
  $files = Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue -ErrorVariable +errs
  if ($errs) {
    foreach ($e in $errs) {
      $msg = 'size calculation failed'
      if ($e.Exception) { $msg = $e.Exception.Message }
      Add-ScanError $Path $msg 'SizeCalculation'
    }
  }
  foreach ($f in $files) {
    if ($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
    if ($f.Attributes -band [System.IO.FileAttributes]::Offline) {
      $script:PlaceholderExcluded++
      continue
    }
    $s += $f.Length
  }
  return $s
}

$candidates = New-Object System.Collections.Generic.List[object]
$candidateSeen = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)

foreach ($root in $scanRoots) {
  try {
    $children = Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction Stop
  } catch {
    Add-ScanError $root $_.Exception.Message 'RootEnumeration'
    continue
  }
  foreach ($child in $children) {
    $full = $child.FullName
    if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
      $script:ReparseSkips++
      continue
    }
    if ($child.Attributes -band [System.IO.FileAttributes]::Offline) { continue }
    if (Test-ProtectedPath $full) { continue }

    $norm = $full.TrimEnd('\')
    if ($candidateSeen.Contains($norm)) { continue }

    $sizeBytes = Get-DirLogicalSize $full
    if ($sizeBytes -lt 50MB) { continue }
    [void]$candidateSeen.Add($norm)

    $ev = New-Object System.Collections.Generic.List[string]

    $owned = Test-OwnedByApp $child.Name
    if ($owned) { $ev.Add('Name matches an installed-program keyword') }

    $underInstall = $false
    foreach ($il in $installLocSet) {
      if ($full.StartsWith($il + '\', [StringComparison]::OrdinalIgnoreCase) -or
          $full.Equals($il, [StringComparison]::OrdinalIgnoreCase)) { $underInstall = $true; break }
    }
    if ($underInstall) { $ev.Add('Lies under a valid InstallLocation') }

    $activeProc = @($procPaths | Where-Object { $_ -and $_.StartsWith($full + '\', [StringComparison]::OrdinalIgnoreCase) })
    if ($activeProc.Count -gt 0) { $ev.Add('Running process inside this directory: ' + $activeProc[0]) }

    $portableExe = $null
    try {
      $recent = Get-ChildItem -LiteralPath $full -Filter '*.exe' -File -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 1MB -and $_.LastWriteTime -gt (Get-Date).AddMonths(-6) } |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
      if ($recent) {
        $portableExe = $recent
        $ev.Add('Portable-software signal: recent >1MB exe (' + $recent.Name + ')')
      }
    } catch {
      Add-ScanError $full $_.Exception.Message 'PortableSignalScan'
    }

    $ev.Add('LastWrite: ' + $child.LastWriteTime.ToString('yyyy-MM-dd'))

    $subCache = @{}
    $subData = @{}
    $subOther = @{}
    try {
      $firstLevel = Get-ChildItem -LiteralPath $full -Directory -Force -ErrorAction SilentlyContinue
      foreach ($sd in $firstLevel) {
        if ($sd.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
        $sgb = [math]::Round((Get-DirLogicalSize $sd.FullName) / 1GB, 3)
        if ($sgb -lt 0.01) { continue }
        if (Test-DataSubName $sd.Name) { $subData[$sd.Name] = $sgb }
        elseif (Test-CacheSubName $sd.Name) { $subCache[$sd.Name] = $sgb }
        else { $subOther[$sd.Name] = $sgb }
      }
    } catch {
      Add-ScanError $full $_.Exception.Message 'SubdirectoryClassification'
    }
    $ev.Add('Subdirs cache: ' + (($subCache.Keys | Sort-Object) -join ','))
    $ev.Add('Subdirs data: ' + (($subData.Keys | Sort-Object) -join ','))
    if ($subOther.Keys.Count -gt 0) { $ev.Add('Subdirs other: ' + (($subOther.Keys | Sort-Object) -join ',')) }

    $bucket = 'B'
    $confidence = 'Low'
    $risk = 'High'
    $reversible = $false
    $requires = $true
    $action = 'NeedsConfirmation'

    if ($activeProc.Count -gt 0) {
      $bucket = 'C'; $confidence = 'High'; $risk = 'High'; $reversible = $false; $requires = $false
      $action = 'None'
      $ev.Add('Active application directory - modification forbidden')
    }
    elseif ($subData.Keys.Count -gt 0) {
      $bucket = 'B'; $confidence = 'Medium'; $risk = 'High'; $reversible = $false
      $action = 'ConfirmCacheOnly'
      $ev.Add('Contains data-type subdirectories; only identified cache subdirs may be cleaned')
    }
    elseif ($portableExe) {
      $bucket = 'B'; $confidence = 'Medium'; $risk = 'High'; $reversible = $false
      $action = 'ManualVerify'
      $ev.Add('Portable-software signal - automatic-clean eligibility revoked')
    }
    elseif ($owned -or $underInstall) {
      $bucket = 'B'; $confidence = 'Medium'; $risk = 'Medium'; $reversible = $false
      $action = 'ConfirmCacheOnly'
      $ev.Add('Still related to an installed program; cache-only after confirmation')
    }
    elseif (($subOther.Keys.Count -eq 0) -and ($subCache.Keys.Count -gt 0)) {
      $bucket = 'A'; $confidence = 'Medium'; $risk = 'Low'; $reversible = $true
      $action = 'CleanCacheSubdirs'
      $ev.Add('Only regenerable cache subdirs; still requires authorization this round')
    }
    else {
      $bucket = 'B'; $confidence = 'Low'; $risk = 'High'; $reversible = $false
      $action = 'UnknownVerify'
      $ev.Add('Purpose unknown (Unknown) - automatic cleaning forbidden')
    }

    $dataClass = 'Mixed'
    if ($subData.Keys.Count -gt 0) { $dataClass = 'Data' }
    elseif (($subCache.Keys.Count -gt 0) -and ($subOther.Keys.Count -eq 0)) { $dataClass = 'Cache' }

    $candidates.Add([PSCustomObject]@{
      Path = $full
      EstimatedLogicalSizeBytes = $sizeBytes
      Evidence = @($ev)
      Confidence = $confidence
      RiskLevel = $risk
      DataClassification = $dataClass
      Bucket = $bucket
      RecommendedAction = $action
      RequiresConfirmation = $requires
      Reversible = $reversible
      LastWrite = $child.LastWriteTime.ToString('o')
    })
  }
}

# =====================================================================
# D. Cross-check residue (report only)
# =====================================================================
$services = @()
try {
  foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
    $pn = [string]$svc.PathName
    if (-not $pn) { continue }
    $exe = Get-ExeFromCommand $pn
    $thirdParty = ($pn -match '^[A-Z]:\\(Users|Program)') -and -not ($pn -match '(?i)\\Windows\\system32\\')
    if (-not $thirdParty) { continue }
    $exeExists = $null
    if ($exe -and ($exe -match '^[A-Z]:\\')) {
      $exeExists = Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue
    }
    $services += [PSCustomObject]@{
      Name = $svc.Name; Display = $svc.DisplayName; State = $svc.State; StartMode = $svc.StartMode
      Path = $pn; ExeParsed = $exe; ExeExists = $exeExists; Unparseable = (-not $exe)
    }
  }
} catch {
  Add-ScanError '<services>' $_.Exception.Message 'ServiceEnumeration'
}

$tasks = @()
try {
  foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    $actions = @($t.Actions | Where-Object { $_ -and $_.Execute })
    if ($actions.Count -eq 0) { continue }
    foreach ($act in $actions) {
      $exec = [Environment]::ExpandEnvironmentVariables([string]$act.Execute)
      $execClean = Get-ExeFromCommand ([string]$act.Execute)
      $wd = [string]$act.WorkingDirectory
      $wdExp = ''
      if ($wd) { $wdExp = [Environment]::ExpandEnvironmentVariables($wd) }
      $stale = $false
      $note = ''
      $unparseable = [string]::IsNullOrWhiteSpace($execClean)
      if (-not $unparseable -and $execClean -match '^[A-Z]:\\') {
        if (-not (Test-Path -LiteralPath $execClean -ErrorAction SilentlyContinue)) {
          $stale = $true; $note = 'Executable not found'
        }
      }
      if (-not $stale -and $wdExp) {
        if (-not (Test-Path -LiteralPath $wdExp -ErrorAction SilentlyContinue)) {
          $stale = $true; $note = 'WorkingDirectory not found'
        }
      }
      if ($stale -or $unparseable) {
        if ($unparseable) { $note = 'Command unparseable - not assumed stale' }
        $tasks += [PSCustomObject]@{
          Name = $t.TaskName; State = $t.State; Execute = $exec; WD = $wd; Stale = $stale
          Unparseable = $unparseable; Note = $note
        }
      }
    }
  }
} catch {
  Add-ScanError '<scheduledtasks>' $_.Exception.Message 'ScheduledTaskEnumeration'
}

$autoruns = @()
$runKeys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($rk in $runKeys) {
  $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
  if (-not $props) { continue }
  foreach ($prop in $props.PSObject.Properties) {
    if ($prop.Name -like 'PS*') { continue }
    $val = [string]$prop.Value
    $exe = Get-ExeFromCommand $val
    $unparseable = [string]::IsNullOrWhiteSpace($exe)
    $stale = $false
    if (-not $unparseable -and ($val -match '^[A-Z]:\\|%')) {
      if (-not (Test-Path -LiteralPath $exe -ErrorAction SilentlyContinue)) { $stale = $true }
    }
    $autoruns += [PSCustomObject]@{
      Key = $rk; Name = $prop.Name; Value = $val; Stale = $stale; Unparseable = $unparseable
    }
  }
}

$uninstOrphans = @()
foreach ($u in $rawUninst) {
  $loc = [string]$u.InstallLocation
  if ([string]::IsNullOrWhiteSpace($loc)) { continue }
  $cleanLoc = $loc.Trim().Trim('"').Trim()
  if ([string]::IsNullOrWhiteSpace($cleanLoc)) { continue }
  if (-not (Test-Path -LiteralPath $cleanLoc -ErrorAction SilentlyContinue)) {
    $uninstOrphans += [PSCustomObject]@{
      Hive = $u.Hive; KeyName = $u.KeyName; DisplayName = $u.DisplayName
      InstallLocation = $cleanLoc
    }
  }
}

# =====================================================================
# E. Special large consumers (report only)
# =====================================================================
$special = @()

$winOld = Join-Path $sysRoot 'Windows.old'
if (Test-Path -LiteralPath $winOld) {
  $wo = Get-DirLogicalSize $winOld
  $special += [PSCustomObject]@{
    Item = 'Windows.old'; SizeBytes = $wo; AutoClean = $false
    Note = 'Previous-Windows rollback data. Deleting removes rollback. Use Settings > System > Storage cleanup instead; this tool never recursively deletes it.'
  }
}

$vhdxes = @()
$dockerVhdx1 = Join-Path $localDir 'Docker\wsl\disk\ext4.vhdx'
$dockerVhdx2 = Join-Path $localDir 'Docker\wsl\data\ext4.vhdx'
if (Test-Path -LiteralPath $dockerVhdx1) { $vhdxes += (Get-Item -LiteralPath $dockerVhdx1 -Force) }
if (Test-Path -LiteralPath $dockerVhdx2) { $vhdxes += (Get-Item -LiteralPath $dockerVhdx2 -Force) }
try {
  $pkgs = Join-Path $localDir 'Packages'
  if (Test-Path -LiteralPath $pkgs) {
    $vhdxes += @(Get-ChildItem -LiteralPath $pkgs -Recurse -Filter 'ext4.vhdx' -Force -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -match 'LocalState' })
  }
} catch {
  Add-ScanError (Join-Path $localDir 'Packages') $_.Exception.Message 'WslVhdxScan'
}
foreach ($v in ($vhdxes | Sort-Object FullName -Unique)) {
  $special += [PSCustomObject]@{
    Item = 'VHDX'; Path = $v.FullName; SizeBytes = $v.Length; AutoClean = $false
    Note = 'WSL/Docker virtual disk (grow-only). Compacting requires separate confirmation: wsl --shutdown then Optimize-VHD -Mode Full, or docker system prune. Not touched here.'
  }
}

try {
  $vss = vssadmin list shadowstorage /for=$sysDrive 2>$null
  $vssText = ($vss -join ' ')
  $special += [PSCustomObject]@{
    Item = 'ShadowStorage'; SizeBytes = $null; AutoClean = $false
    Note = 'Restore points / shadow storage. Freeing it is a separate system-maintenance flow: vssadmin delete shadows /for=' + $sysDrive + ' /oldest (keeps newest); /all destroys every restore point.'
    Raw = ($vss | Select-Object -First 12)
  }
} catch {
  Add-ScanError '<vssadmin>' $_.Exception.Message 'ShadowStorageQuery'
}

try {
  $referenced = New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)
  foreach ($h in $uninstHives) {
    if (-not (Test-Path $h.Path)) { continue }
    foreach ($p in (Get-ChildItem $h.Path -ErrorAction SilentlyContinue)) {
      $lp = $p.GetValue('LocalPackage')
      if ($lp) { [void]$referenced.Add(([IO.Path]::GetFullPath($lp)).ToLowerInvariant()) }
    }
  }
  $installerDir = Join-Path $winDir 'Installer'
  if (Test-Path -LiteralPath $installerDir) {
    $mspFiles = @(Get-ChildItem -LiteralPath $installerDir -Filter '*.msp' -File -ErrorAction SilentlyContinue)
    $orphanMsp = @($mspFiles | Where-Object { -not $referenced.Contains($_.FullName.ToLowerInvariant()) })
    if ($orphanMsp.Count -gt 0) {
      $mspBytes = [long]0
      foreach ($m in $orphanMsp) { $mspBytes += $m.Length }
      $special += [PSCustomObject]@{
        Item = 'WindowsInstallerOrphanMSP'; Count = $orphanMsp.Count; SizeBytes = $mspBytes; AutoClean = $false
        Note = 'Suspected unreferenced MSP files. Deleting them can break repair/modify of installed products. Report only.'
      }
    }
  }
} catch {
  Add-ScanError '<windows\installer>' $_.Exception.Message 'InstallerMspScan'
}

# =====================================================================
# F. Cleanup-plan draft (everything Pending)
# =====================================================================
$now = (Get-Date).ToString('o')
$planId = 'plan-' + (Get-Date -Format 'yyyyMMddHHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

$draftTargets = @()
foreach ($c in ($candidates | Where-Object { $_.Bucket -eq 'A' -or $_.Bucket -eq 'B' })) {
  $op = 'Quarantine'
  if ($c.RecommendedAction -eq 'CleanCacheSubdirs' -or $c.RecommendedAction -eq 'ConfirmCacheOnly') {
    $op = 'CleanCacheSubdirs'
  }
  $draftTargets += [PSCustomObject]@{
    Path = $c.Path
    Operation = $op
    EstimatedLogicalSizeBytes = $c.EstimatedLogicalSizeBytes
    Justification = ($c.Evidence -join ' | ')
    RiskLevel = $c.RiskLevel
    Bucket = $c.Bucket
    ApprovalStatus = 'Pending'
    ApprovedOperation = ''
    RequiresConfirmation = $c.RequiresConfirmation
    Reversible = $c.Reversible
  }
}

$plan = [PSCustomObject]@{
  PlanId = $planId
  Version = '1.0'
  CreatedAt = $now
  SystemDrive = $sysDrive
  UserProfile = $userDir
  AuditMode = $(if ($IsAdmin) { 'Admin' } else { 'CurrentUser-Incomplete' })
  ScanScope = $Scope
  ScanRoots = $scanRoots.ToArray()
  Baseline = $baseline
  Candidates = @($candidates | Sort-Object EstimatedLogicalSizeBytes -Descending)
  SpecialConsumers = @($special)
  CrossCheck = [PSCustomObject]@{
    Services = @($services)
    ScheduledTasks = @($tasks)
    Autoruns = @($autoruns)
    UninstallOrphans = @($uninstOrphans)
  }
  RawUninstallRecords = @($rawUninst)
  Targets = @($draftTargets)
  Observability = [PSCustomObject]@{
    ScanErrorCount = $ScanErrors.Count
    ScanErrors = @($ScanErrors | Select-Object -First 50)
    ReparseSkipped = $ReparseSkips
    PlaceholderExcluded = $PlaceholderExcluded
    SizeNote = 'All sizes are LOGICAL estimates: hardlinks double-counted, OneDrive/cloud placeholders excluded, reparse points not followed. Actual freed space must be measured after execution.'
  }
}

# =====================================================================
# G. Output
# =====================================================================
foreach ($e in $ScanErrors) {
  Write-Warning ('Scan error [' + $e.Stage + '] ' + $e.Path + ': ' + $e.Reason)
}

if ($OutFile) {
  $json = $plan | ConvertTo-Json -Depth 12
  [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding $true))
  Write-Host "Audit JSON written to: $OutFile"
}

function Fmt-GB([long]$b) { return [math]::Round(($b / 1GB), 2) }

$A = @($plan.Candidates | Where-Object { $_.Bucket -eq 'A' })
$B = @($plan.Candidates | Where-Object { $_.Bucket -eq 'B' })
$Ck = @($plan.Candidates | Where-Object { $_.Bucket -eq 'C' })

Write-Host ''
Write-Host '==============================================================================='
Write-Host '  Windows Disk Audit  (Phase 1: READ-ONLY, nothing modified)'
Write-Host '==============================================================================='
Write-Host ''
Write-Host '[1] Baseline and scan coverage'
Write-Host ('  System drive {0}   Total {1} GB   Free {2} GB   {3}' -f $baseline.SystemDrive, $baseline.TotalGB, $baseline.FreeGB, $baseline.OSCaption)
$modeText = 'CurrentUser (INCOMPLETE)'
if ($IsAdmin) { $modeText = 'Admin (complete)' }
Write-Host ('  Mode: {0}, Scope={1}' -f $modeText, $plan.ScanScope)
Write-Host ('  Reparse points skipped: {0}   Cloud placeholders excluded: {1}   Scan errors: {2}' -f $ReparseSkips, $PlaceholderExcluded, $ScanErrors.Count)
Write-Host ''
Write-Host '[6] Special space consumers (report only)'
foreach ($s in $plan.SpecialConsumers) {
  $label = $s.Item
  if ($s.PSObject.Properties['Path']) { $label = $s.Item + ' ' + $s.Path }
  $sizeText = 'n/a'
  if ($s.SizeBytes -ne $null) { $sizeText = (Fmt-GB ([long]$s.SizeBytes)).ToString() + ' GB' }
  Write-Host ('  {0,-60} {1,10}   {2}' -f $label, $sizeText, $s.Note)
}
Write-Host ''
Write-Host ('[2] Bucket A - low-risk candidates (regenerable cache; still needs authorization): {0}' -f $A.Count)
foreach ($c in $A) {
  Write-Host ('   {0,7} GB  {1}' -f (Fmt-GB ([long]$c.EstimatedLogicalSizeBytes)), $c.Path)
}
Write-Host ''
Write-Host ('[3] Bucket B - needs confirmation: {0}' -f $B.Count)
foreach ($c in $B) {
  Write-Host ('   {0,7} GB  {1}   action={2}' -f (Fmt-GB ([long]$c.EstimatedLogicalSizeBytes)), $c.Path, $c.RecommendedAction)
}
Write-Host ''
Write-Host ('[4] Bucket C - protected (never modified): {0}' -f $Ck.Count)
foreach ($c in $Ck) {
  Write-Host ('   {0,7} GB  {1}' -f (Fmt-GB ([long]$c.EstimatedLogicalSizeBytes)), $c.Path)
}
Write-Host ''
Write-Host '[5] Cross-check residue'
$staleTaskCount = @($tasks | Where-Object { $_.Stale }).Count
$staleRunCount = @($autoruns | Where-Object { $_.Stale }).Count
Write-Host ('  Third-party services: {0}   Stale scheduled tasks: {1}   Stale autoruns: {2}   Uninstall orphans: {3}' -f $services.Count, $staleTaskCount, $staleRunCount, $uninstOrphans.Count)
Write-Host ''
Write-Host '[7] Errors and skipped paths (first 10)'
if ($ScanErrors.Count -eq 0) { Write-Host '  none' }
foreach ($e in ($ScanErrors | Select-Object -First 10)) {
  Write-Host ('   [' + $e.Stage + '] ' + $e.Path + ' - ' + $e.Reason)
}
Write-Host ''
Write-Host ('[8] Dry-run plan draft: {0} targets, all ApprovalStatus=Pending' -f $draftTargets.Count)
Write-Host ''
Write-Host '  Next: review this report, confirm Bucket B items individually,'
Write-Host '  write approved targets to plan.json (see schemas/cleanup-plan.schema.json),'
Write-Host '  then run Invoke-DiskCleanup.ps1 -PlanFile plan.json -DryRun.'
if ($OutFile) { Write-Host ('  Audit JSON: ' + $OutFile) }
