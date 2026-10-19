# windows-disk-cleanup

A safety-first Windows disk audit and cleanup skill for Claude Code.

Read-only by default, per-target authorization, transactional quarantine with
rollback, and coverage accounting so "no findings" never means "didn't scan".

## Features

- **Orphan audit** — finds leftovers of uninstalled software by comparing
  AppData / ProgramData / Program Files against the installed-program registry.
- **Deep scan** — full-volume census with coverage accounting plus seven
  independent tracks:
  - caches (generic signatures + data-fingerprint exclusion)
  - junk files (`.tmp/.log/.dmp/.old/...`, age-gated)
  - large files
  - developer / package caches
  - system reclaimable areas (Windows Update, WER, dumps, shadow storage, ...)
  - bundled-software signals (hidden tasks, suspicious paths, unsigned updaters)
  - installation residue (missing install locations, dead services)
- **Evidence scoring** — a single signal never marks anything deletable.
- **Transactional quarantine** — pre-flight lock check, per-item move,
  rollback on failure, restore manifest.
- **Manual elevation** — `-RequestElevation` raises a UAC prompt instead of
  silently running with an incomplete view.

## Install

From a Claude Code terminal session:

```
/plugin install windows-disk-cleanup --marketplace bilipeng/windows-disk-cleanup
```

Manual install (copy the skill into your personal skills folder):

```bash
git clone https://github.com/bilipeng/windows-disk-cleanup
cp -r windows-disk-cleanup/skills/windows-disk-cleanup ~/.claude/skills/
```

On Windows PowerShell:

```powershell
git clone https://github.com/bilipeng/windows-disk-cleanup
Copy-Item -Recurse .\windows-disk-cleanup\skills\windows-disk-cleanup $env:USERPROFILE\.claude\skills\
```

## Usage

Ask Claude:

- "audit my C drive"
- "find leftovers from uninstalled software"
- "deep scan my disk and tell me what is taking space"
- "C 盘清理 / 磁盘清理 / 清理残留"

Or run the scripts directly (Administrator PowerShell recommended):

```powershell
# 1) read-only orphan audit
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DiskAudit.ps1 -OutFile audit.json

# 2) read-only deep scan (caches, junk, large files, coverage)
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DeepScan.ps1 -OutFile deepscan.json

# 3) preview an approved plan (no changes)
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DiskCleanup.ps1 -PlanFile plan.json -DryRun

# 4) execute (quarantine to another volume)
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DiskCleanup.ps1 -PlanFile plan.json -Execute -QuarantineRoot D:\_cleanup_quarantine
```

## Safety model

- Audit and deep scan are **read-only**; they never delete, move or modify.
- Deletion happens only through `Invoke-DiskCleanup.ps1`, only for targets
  explicitly marked `ApprovalStatus=Approved`, and only after its own
  independent validation (protected paths, traversal, reparse points).
- Quarantine is transactional: a pre-flight lock check prevents partial moves,
  and a failed move rolls back everything already moved.
- Same-volume quarantine does not free space and is reported as such.
- WeChat/WXWork chat databases, browser profiles, IDE project state, and any
  directory containing data fingerprints are never auto-cleaned.
- Windows.old, WinSxS, shadow storage, WSL/Docker VHDX and hibernation follow
  separate, explicitly confirmed procedures.

## Tests

```powershell
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\tests\DiskCleanup.Tests.ps1
```

The suite covers path parsing, junction handling, protected paths, quarantine
rollback, evidence scoring, cache signatures, data fingerprints and coverage
accounting. All tests operate on temporary directories only.

## Requirements

- Windows 10 / 11
- Windows PowerShell 5.1 or later
- Administrator privileges for a complete audit (the scripts state clearly when
  the report is incomplete)

## Known limitations

- Sizes are logical estimates; hardlinks may double-count and Windows
  placeholders are excluded. Actual freed space must be measured after running.
- Text-based heuristics can misclassify unusual layouts; every candidate is
  reported with its evidence so a human can decide.
- Bundled-software signals are indicators, not verdicts.
- `build/target/dist` directories are treated as regenerable only when a
  project manifest sits beside them, and still require confirmation.

## License

MIT
