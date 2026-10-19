# AGENTS.md — instructions for Codex and other coding agents

This repository provides a **read-only-first Windows disk audit and cleanup
toolkit**. The logic is plain PowerShell; any agent that can run shell commands
can use it. The full methodology is in
`skills/windows-disk-cleanup/SKILL.md`.

## When the user asks about disk space

Follow this order. Do not skip steps.

1. **Check elevation.** If not elevated, tell the user the scan will be
   incomplete and offer to relaunch elevated (`-RequestElevation` on the audit
   script launches a UAC prompt).

2. **Run the read-only scans.**

   ```powershell
   powershell -ExecutionPolicy Bypass -File skills/windows-disk-cleanup/scripts/Invoke-DiskAudit.ps1 -OutFile audit.json
   powershell -ExecutionPolicy Bypass -File skills/windows-disk-cleanup/scripts/Invoke-DeepScan.ps1 -OutFile deepscan.json
   ```

3. **Report findings, not actions.** Summarize:
   - coverage percentage and unreadable paths,
   - bucket A / B / C totals,
   - the largest cache items with their evidence score,
   - junk files, large files, system reclaimable areas,
   - bundled-software signals and installation residue.
   State clearly when coverage is incomplete.

4. **Ask the user which targets to approve.** Never infer approval from
   "clean my disk". Approval must name specific paths. For mixed cache/data
   applications, ask "cache only or data too?" and default to cache only.

5. **Build an approved plan** (`ApprovalStatus=Approved`,
   `ApprovedOperation=Quarantine` or `CleanCacheSubdirs`) following
   `skills/windows-disk-cleanup/schemas/cleanup-plan.schema.json`.

6. **DryRun first.**

   ```powershell
   powershell -ExecutionPolicy Bypass -File skills/windows-disk-cleanup/scripts/Invoke-DiskCleanup.ps1 -PlanFile plan.json -DryRun
   ```

7. **Execute only after explicit confirmation**, preferably quarantining to a
   different volume:

   ```powershell
   powershell -ExecutionPolicy Bypass -File skills/windows-disk-cleanup/scripts/Invoke-DiskCleanup.ps1 -PlanFile plan.json -Execute -QuarantineRoot D:\_cleanup_quarantine
   ```

8. **Report measured results.** Compare free space before and after; do not
   claim that logical sizes equal freed space. List failures (locked files,
   permission denied) honestly.

## Hard rules

- Never delete files outside the executor; never bypass the plan.
- Never treat a directory name, brand, file age, or a missing registry entry
  as sufficient proof that something can be deleted.
- Never auto-clean directories containing data fingerprints (`.db`, `.sqlite`,
  documents, project files, chat databases).
- Never modify services, scheduled tasks or autoruns; they are report-only.
- Never touch `pagefile.sys`, `swapfile.sys`, `USOShared`,
  `System Volume Information`, or the Windows component store directly.
- Same-volume quarantine does not free space — say so.

## Non-interactive use

`Start-Cleanup.ps1` is an interactive wizard for humans. Agents should call the
three scripts directly, as above.
