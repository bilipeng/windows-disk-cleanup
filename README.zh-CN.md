# windows-disk-cleanup（中文说明）

面向 Claude Code 的 Windows 磁盘审计与安全清理技能。

**默认只读、逐项授权、隔离可恢复、覆盖率可量化**——"没发现问题"不会被当成"已经扫完"。

[English README](README.md)

---

## 它解决什么问题

Windows 的 C 盘常年被这些内容占据，但普通清理工具要么扫不到，要么删得危险：

- 卸载软件留下的孤儿目录、服务、计划任务、自启动项
- 已安装软件内部的缓存（浏览器、微信/企业微信、IDE、Notion、开发包管理器）
- 散落全盘的临时文件、崩溃转储、旧安装包、大文件
- 后端看不见的占用：WinSxS、Windows 更新缓存、阴影存储、休眠文件、WSL/Docker 虚拟磁盘

本技能把"审计"和"删除"彻底分开：先只读扫描并给出带证据的候选，用户逐项确认后才生成计划，DryRun 预览后再执行隔离。

---

## 两条扫描线

### 1. 孤儿审计（`Invoke-DiskAudit.ps1`）

读取注册表中的已安装程序作为"应存在"的基准，反推 `AppData`、`ProgramData`、`Program Files` 中的孤儿目录，并交叉核对：

- 第三方 / 失效服务
- 失效计划任务（正确处理引号、空格、环境变量；无法解析时只标记，不判失效）
- 失效自启动项
- 卸载注册表孤儿（安装目录已不存在）

输出中文报告 + `audit.json`（清理计划草稿，全部 `Pending`）。

### 2. 深度扫描（`Invoke-DeepScan.ps1`）

全卷普查 + 七条独立轨：

| 轨 | 扫描内容 | 判据 |
|---|---|---|
| T0 卷级普查 | 整卷遍历（跳过重解析点） | 覆盖率 = 已解释字节 / 卷已用字节；缺口过大时明确声明报告不完整 |
| T2 缓存 | `Cache`、`Code Cache`、`GPUCache`、`Service Worker`、`ShaderCache`、`Thumbnail` 等 | 缓存名签名 + **数据指纹排除**（含数据库/文档/项目文件则降级） |
| T3 垃圾文件 | `.tmp`、`.log`、`.dmp`、`.old`、`.bak`、`.crdownload` 等 | 扩展名 + 年龄门槛 + 非系统路径 |
| T4 大文件 | 超过阈值（默认 500 MB） | 只报告，不作为删除目标 |
| T5 系统空间 | Windows 更新缓存、WER、CBS、MEMORY.DMP、Windows.edb、Prefetch、回收站、休眠/pagefile、DISM、阴影存储 | 只报告，清理走独立确认流程 |
| T6 开发缓存 | `node_modules`、`.gradle/caches`、`.m2/repository`、`.nuget/packages`、pip/npm/pnpm/yarn/uv/cargo/go/conda 等 | 按"可再生包缓存"语义识别，不按品牌名 |
| T7 捆绑软件 | 服务、计划任务、自启动项 | 可疑路径、隐藏任务、更新器命名等信号累积评分 |
| T8 安装残留 | 卸载记录 ↔ 实际目录 / 服务 | 安装位置缺失、服务可执行文件缺失 |

输出中文报告 + `deepscan.json`（含 `Targets` 草稿，全部 `Pending`）。

---

## 证据评分

任何**单一信号都不能判定可删除**。评分规则：

```
基础分 30
缓存签名        +30
开发缓存        +25
数据指纹        -45   （.db/.sqlite/文档/项目文件）
年龄 ≥ 30 天    +10
体积 ≥ 500 MB   +10
与已安装程序相关 -10
未签名          -10
有进程占用      → 直接归入 C 桶（禁止修改）
```

- **≥ 80 → A 桶**：低风险候选（仍然需要本轮授权）
- **40–79 → B 桶**：需要人工确认
- **< 40 → C 桶**：只报告，不修改

每个候选都会输出：路径、逻辑大小、逐条证据、置信度、风险等级、数据分类、建议操作、是否可恢复。

---

## 安装

在 Claude Code 会话中：

```
/plugin install windows-disk-cleanup --marketplace bilipeng/windows-disk-cleanup
```

手动安装（Windows PowerShell）：

```powershell
git clone https://github.com/bilipeng/windows-disk-cleanup
Copy-Item -Recurse .\windows-disk-cleanup\skills\windows-disk-cleanup $env:USERPROFILE\.claude\skills\
```

---

## 不用 Claude、或换用其他 AI 工具

脚本是纯 PowerShell，**不依赖任何 AI**：

- **双击 `Start-Cleanup.cmd`**：交互式向导，自动扫描、编号列出候选、让你选择、预览后再隔离。报告写入 `%USERPROFILE%\disk-cleanup-reports`。
- **Codex 等编码 agent**：让它先读 [`AGENTS.md`](AGENTS.md)，里面规定了“扫描 → 报告 → 用户确认 → DryRun → 执行”的强制顺序。
- **通用 skills 安装器**：仓库根目录有 `SKILL.md`，支持读取根级技能的安装器（例如 `npx skills add bilipeng/windows-disk-cleanup`）可以直接识别。
- **豆包、ChatGPT 等纯对话助手**：它们不能执行本地 PowerShell。但向导会生成 `report-*.md`，你可以把它上传给豆包，让豆包解释报告内容；真正的扫描和清理必须在你的电脑上通过向导或脚本完成。

### 给非 AI 用户的最短路径

```powershell
git clone https://github.com/bilipeng/windows-disk-cleanup
cd windows-disk-cleanup
.\Start-Cleanup.cmd
```

向导会提示是否以管理员身份重启（推荐），随后自动完成扫描、选择、预览和执行。

## 使用

直接用自然语言触发：

- “审计我的 C 盘”
- “深度扫描磁盘，看看什么在占空间”
- “找出卸载软件留下的残留”
- “C 盘清理 / 磁盘清理 / 清理残留”

也可以直接运行脚本（建议管理员 PowerShell）：

```powershell
# 1) 只读孤儿审计
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DiskAudit.ps1 -OutFile audit.json

# 2) 只读深度扫描
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DeepScan.ps1 -OutFile deepscan.json

# 3) 预览已批准的计划（零变更）
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DiskCleanup.ps1 -PlanFile plan.json -DryRun

# 4) 执行隔离（建议指定另一个卷，才能真实释放空间）
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\scripts\Invoke-DiskCleanup.ps1 -PlanFile plan.json -Execute -QuarantineRoot D:\_cleanup_quarantine
```

### 权限不足时

审计脚本支持手动提权：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Invoke-DiskAudit.ps1 -RequestElevation
```

会弹出 UAC 让你确认，批准后以管理员身份重新运行完整审计；拒绝则继续做不完整审计并明确声明。脚本不会静默提权。

### 主要参数

| 脚本 | 参数 | 说明 |
|---|---|---|
| Audit | `-Scope CurrentUser \| AllUsers` | 当前用户 / 尝试枚举所有可访问用户配置 |
| Audit | `-OutFile` | 输出 JSON 计划草稿（UTF-8 BOM） |
| Audit | `-ExtraScanRoots` | 额外授权的扫描目录 |
| Audit | `-RequestElevation` | 通过 UAC 手动提权后重跑 |
| DeepScan | `-Root` | 扫描根（默认系统盘） |
| DeepScan | `-MinCacheMB` / `-MinJunkAgeDays` / `-MinJunkDirMB` / `-LargeFileMB` | 各轨阈值 |
| DeepScan | `-SkipDism` | 跳过 DISM 组件存储分析 |
| DeepScan | `-RequestElevation` | 同上 |
| Cleanup | `-PlanFile` | 必填，计划 JSON |
| Cleanup | `-DryRun` | 只预览，零变更 |
| Cleanup | `-Execute` | 实际执行；不传则默认 DryRun |
| Cleanup | `-QuarantineRoot` | 隔离目录；同卷会明确警告“未释放空间” |
| Cleanup | `-QuarantineRetentionDays` | 保留天数（默认 7），过期只提醒 |
| Cleanup | `-AuditLogPath` | 审计日志路径 |

---

## 安全模型

- **审计与深度扫描完全只读**：不删除、不移动、不修改文件、注册表、服务或系统配置。
- **删除只发生在执行器**，且仅针对 `ApprovalStatus=Approved` 的目标；执行器会独立复核保护路径、路径穿越、重解析点和授权范围，不信任计划里填写的安全标签。
- **事务式隔离**：
  - 移动前做**预检锁**（独占打开每个文件），任一被占用则整项失败、零移动；
  - 按顶层项逐个移动，任一步失败则把已移动项全部移回；
  - 生成 `restore-manifest.json`，记录原路径、隔离路径、项数、恢复命令。
- **同卷隔离不释放空间**，脚本会明确告诉你；跨卷隔离才真正释放。
- **默认永不自动清理**：微信/企业微信聊天数据库、浏览器配置、IDE 项目状态、任何含数据指纹的目录。
- **系统项独立处理**：Windows.old、WinSxS、阴影存储、WSL/Docker VHDX、休眠文件都需要单独确认，不并入普通删除。

### 恢复隔离内容

```powershell
Move-Item -LiteralPath "D:\_cleanup_quarantine\<PlanId>\<时间戳>__<名称>" -Destination "<原路径>"
```

恢复前请确认原路径不存在，避免覆盖新文件。

---

## 测试

```powershell
powershell -ExecutionPolicy Bypass -File .\skills\windows-disk-cleanup\tests\DiskCleanup.Tests.ps1
```

覆盖：路径解析（中文/空格/引号）、Junction 跳过、保护路径拒绝、预检锁、隔离回滚、证据评分、缓存签名、数据指纹、覆盖率核算。所有测试只作用于临时目录。

---

## 系统要求

- Windows 10 / 11
- Windows PowerShell 5.1 或更高
- 完整审计需要管理员权限；非管理员会明确声明报告不完整

---

## 已知限制

- 大小为**逻辑估算**：硬链接会重复计数、云端占位文件已排除、重解析点不跟随；实际释放量以执行后实测为准。
- 覆盖率可能因硬链接超过 100%，脚本会说明并做上限处理。
- 文本启发式可能误判特殊目录布局；每个候选都会附证据，由人做最终决定。
- 捆绑软件信号是“指标”而非“结论”。
- `build/target/dist` 只有在同级存在工程清单时才视为可再生，且仍需确认。
- 服务 / 计划任务 / 自启动在 v1.0 中**只报告**，执行器会拒绝修改它们。

---

## 许可

MIT
