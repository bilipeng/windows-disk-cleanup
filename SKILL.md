---
name: windows-disk-cleanup
description: "Windows 系统盘空间审计与安全清理。只读扫描（孤儿残留 + 缓存/垃圾/大文件/开发缓存/捆绑软件/安装残留 + 覆盖率），用户逐项授权后生成计划，DryRun 预览，事务式隔离可恢复。触发词：C 盘清理、磁盘清理、清理垃圾、卸载残留、空间不足。"
---

# Windows Disk Cleanup（根级入口）

本仓库同时是 Claude Code 插件与通用技能仓库。完整方法论见
`skills/windows-disk-cleanup/SKILL.md`，脚本位于
`skills/windows-disk-cleanup/scripts/`。

## 快速使用

```powershell
# 交互式向导（无需 AI，适合手动使用）
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Start-Cleanup.ps1

# 或分别运行
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DiskAudit.ps1 -OutFile audit.json
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DeepScan.ps1 -OutFile deepscan.json
```

## 核心规则

1. 审计与深度扫描只读，不修改任何东西。
2. 删除只通过 `Invoke-DiskCleanup.ps1`，且仅针对 `ApprovalStatus=Approved` 的目标。
3. 必须 DryRun 预览并经用户确认后才执行。
4. 优先隔离到另一个卷（同卷不释放空间，脚本会警告）。
5. 数据指纹（数据库/文档/项目文件）目录永不自动清理。

完整工作流、评分规则与安全边界见 `skills/windows-disk-cleanup/SKILL.md`。
