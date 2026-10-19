---
name: windows-disk-cleanup
description: "Windows 系统盘（默认 C 盘，可自动识别系统盘）空间审计与安全清理。只读审计生成清理计划，用户逐项授权后才执行。适用于：C 盘爆满、卸载软件残留清理、缓存清理、休眠文件、WSL/Docker 虚拟磁盘、阴影存储、Windows Installer 孤儿文件、服务/计划任务/自启动项残留排查。触发词：C 盘清理、磁盘清理、清理垃圾、系统瘦身、释放空间、临时文件清理、卸载残留。"
---

# Windows 磁盘清理与孤儿审计（v1.0）

## 总则

1. **默认只读**。审计阶段（`Invoke-DiskAudit.ps1`）不删除、不移动、不修改任何文件、注册表、服务或系统配置。
2. **用户授权必须限定到具体路径和具体操作**。对一个目录的授权不自动扩展到子目录、兄弟目录或其他操作。
3. **单一证据不证明可删除**。目录名、软件品牌、文件年龄、注册表缺失中任何一项都不能单独作为"已卸载、可删除"的证明。
4. **用途不明 → Unknown → 禁止自动清理**。
5. **执行前必须复核**：目标自扫描后发生变化（大小、占用、属性）必须跳过并报告。
6. **禁止静默吞错**：所有读取/计算/操作失败必须记录路径、原因、阶段。
7. 最终报告**使用中文**。

## 工作流程（五阶段）

### 阶段 1 — 审计（只读）

运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Invoke-DiskAudit.ps1 [-Scope CurrentUser|AllUsers] [-OutFile audit.json] [-RequestElevation]
```

**权限不足时的手动授权**：脚本检测到非管理员时不自行提权、也不假装完整。可加 `-RequestElevation`，脚本会通过 UAC 弹窗请求用户手动授权后以管理员身份重新运行；用户拒绝则继续做不完整审计并明确声明。用户只批准审计时，不得据此执行清理。

脚本职责：
- 动态获取系统盘（不假设是 C）、Windows 目录、Program Files、ProgramData、各用户配置目录。
- 收集：系统版本、盘容量/剩余、`hiberfil.sys`/`pagefile.sys`/`swapfile.sys` 状态与大小、当前权限、重解析点跳过数、云端占位文件排除数、无法读取路径数。
- 扫描根**去重**（互相包含的根只递归外层；候选按规范化路径去重）。
- 安装基线：读取机器级 + 当前用户级 Uninstall 键（`AllUsers` 模式尝试枚举其他用户配置）；**保留原始记录**，`WindowsInstaller=1`/`SystemComponent=1`/补丁/隐藏项只**标记**，不删除。
- 候选发现：用户 AppData、ProgramData、Program Files（x86 与 64）、临时目录；安装目录的父/子关系参与判定（任一有效 `InstallLocation` 指向候选目录或其内部 → 不得判整个父目录为残留）。
- 证据收集（每项独立记录）：关键词命中、目录名、最后修改时间、近 6 个月内修改的 >1MB EXE（**便携软件信号 → 取消自动清理资格**）、相关进程/服务/计划任务/自启动/安装记录。
- 缓存与数据识别：缓存目录名只是线索；`IndexedDB`/`Local Storage`/聊天记录/数据库/媒体/下载/IDE 项目状态/应用配置/模型文件默认按**数据**处理；无法区分时**禁止删整个应用目录**。
- 分类：A（低风险，仍需进入本轮计划并获授权）/ B（待确认，附证据、风险、建议操作、可恢复性）/ C（禁止修改，只报原因）。
- 特殊资源**只报告**，不交给普通目录清理器：
  - `Windows.old`：报大小 + 回退风险，引导用 Windows 设置里的存储清理；
  - `C:\Windows\Installer` 未引用 MSP：只报"疑似"，不删；
  - 阴影存储/系统还原点：只报用量，用户确认后走独立系统维护流程；
  - WSL/Docker VHDX：只报位置与大小；不关 WSL、不压缩、不清 Docker；
  - 休眠文件：报大小 + 休眠/快速启动影响，用户确认后才提供关闭操作；
  - DISM：先 `/AnalyzeComponentStore` 分析，用户确认后跑普通组件清理；`/ResetBase` 永不默认；
  - 服务/计划任务/自启动/注册表残留：**第一阶段只报告**。无法可靠解析的命令标记"无法解析"，不认定失效；计划任务 WorkingDirectory 为空 ≠ 失效；解析 exe 时正确处理引号、参数、环境变量、`cmd /c` 等解释器。
- 输出：`audit.json`（含报告数据 + 清理计划草稿，所有条目 `ApprovalStatus=Pending`）+ 中文报告（9 栏目，见下）。

### 阶段 1b — 深度扫描（只读，补齐覆盖率）

孤儿审计只能发现"卸载残留"。已安装软件内部的缓存、散落全盘的大文件/垃圾文件，需要独立的深度扫描：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Invoke-DeepScan.ps1 [-OutFile deepscan.json] [-SkipDism] [-MinCacheMB 50] [-MinJunkAgeDays 14] [-LargeFileMB 500] [-RequestElevation]
```

八条独立轨：

| 轨 | 内容 | 判据 |
|---|---|---|
| T0 卷级普查 | 遍历整卷（跳过重解析点），按顶层目录记账 | 覆盖率 = 已解释字节 / 卷已用字节；**缺口 >5% 必须声明报告不完整** |
| T2 缓存轨 | 任意深度的 `Cache/Code Cache/GPUCache/Service Worker/CacheStorage/ShaderCache/Thumbnail/...` | 缓存名签名 + **数据指纹排除**（含 .db/.sqlite/文档/项目文件则降级为 C）+ 年龄 + 体积 |
| T3 垃圾轨 | `.tmp/.temp/.log/.dmp/.old/.bak/.crdownload/...` | 扩展名 + 年龄门槛 + 非系统路径 |
| T4 大文件轨 | >阈值（默认 500MB） | 只报告，不作为删除目标 |
| T5 系统轨 | WU 缓存、DeliveryOptimization、WER、CBS、MEMORY.DMP、Windows.edb、Prefetch、回收站、休眠/pagefile、DISM Analyze、阴影存储 | 只报告；清理走独立确认流程 |
| T6 开发缓存轨 | node_modules、.gradle/caches、.m2/repository、.nuget/packages、pip/npm/pnpm/yarn/uv/cargo/go/conda、target/build | 按"可再生包缓存"语义识别，不按品牌 |
| T7 捆绑轨 | 服务/计划任务/Run 项 | 路径在 Temp/AppData/随机名 ProgramData、隐藏任务、名称含 cleaner/update/helper/加速/清理 → 证据评分 |
| T8 残留轨 | 卸载记录 ↔ 目录/服务 | InstallLocation 缺失、服务 exe 缺失 |

**证据评分**（任何单一信号不得判删）：

```
基础分 30；缓存签名 +30；开发缓存 +25；数据指纹 -45；年龄≥30天 +10；
体积≥500MB +10；安装在用 -10；未签名 -10；有进程占用 → 直接 C
≥80 → A，40–79 → B，<40 → C
```

深度扫描输出 `deepscan.json`，并生成与审计相同的 `Targets` 草稿（全部 Pending），可直接交给 `Invoke-DiskCleanup.ps1` 做 DryRun/隔离。

### 阶段 1c — 合并报告

最终报告同时包含：基线与覆盖、A/B/C 候选、缓存轨、垃圾轨、大文件、系统可回收、捆绑信号、安装残留、错误与跳过。覆盖率缺口必须如实展示，不得用"没发现问题"代替"没扫到"。

### 阶段 2 — 展示与用户确认

向用户展示完整报告。用户逐项/分组确认 B 桶（使用 `AskUserQuestion` 多选；混合缓存/数据的应用必须问"只清缓存还是连数据"，默认只清缓存）。用户只批准审计时，**不得执行清理**。

### 阶段 3 — 生成获批计划

把用户批准的路径 + 操作写入计划 JSON（结构见 `schemas/cleanup-plan.schema.json`），全部目标标记 `ApprovalStatus=Approved` 并记录批准的操作。未批准目标不得出现在计划中。

### 阶段 4 — DryRun

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Invoke-DiskCleanup.ps1 -Plan plan.json -DryRun
```

DryRun 列出每个具体目标与预计操作，**不产生任何文件系统或系统配置变更**。DryRun 成功 ≠ 获得执行授权。

### 阶段 5 — 执行 + 复测

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\Invoke-DiskCleanup.ps1 -Plan plan.json
```

执行器职责：
- 独立校验计划 JSON（结构 + 保护路径 + 授权范围），**不信任计划里 AI 填写的安全标签**。
- 每个目标执行前复核：路径仍满足安全条件、大小/状态未变、无占用。任一失败 → 跳过该目标并记录。
- 隔离与永久清除是**独立操作**：
  - 隔离前先做**预检锁**：尝试以独占方式打开目标内每个文件；任一失败则整单失败、零移动（避免部分移动）。
  - 目录隔离按顶层项逐个移动，任一步失败则**回滚已移动项**，保持原目录不变。
  - 禁止隔离整个已安装软件目录、整个用户配置目录、未知数据目录；
  - 隔离记录原路径、目标路径、时间、顶层项清单、恢复命令（restore-manifest.json）；
  - 同卷隔离**不释放当前卷空间**（必须如实说明）；跨卷隔离完成后才删除原件；
  - 默认不自动永久清除隔离内容；过期只提醒，用户再次确认才清除。
- 执行后复测：读前后剩余空间，展示 9 栏目最终报告。

## 保护路径（C 桶，永不修改）

- `pagefile.sys` / `swapfile.sys` / `hiberfil.sys`（只报大小）
- `USOShared`、`Windows Master Store`、`System Volume Information`
- `C:\Windows`（及其 Installer/WinSxS 等受保护子树，WinSxS 仅允许 DISM 官方清理）
- 当前有进程运行其中的目录（活动 IDE / 活动 AI 工具）
- 整个 `Program Files` / 用户配置目录 / `AppData` 本身不得作为普通清理目标
- 无法确认用途的数据、未识别的云端占位数据

## 计划校验规则（执行器独立执行）

- 路径必须是绝对路径，不得包含 `..` 穿越；
- 目标不得是：系统盘根、`C:\`、`C:\Windows`、整个 `Program Files`、整个 `AppData`、整个用户配置目录；
- 目标不得是重解析点；
- 操作类型必须与目标 Bucket 兼容（C 桶任何操作拒绝）；
- 未授权路径、越权子目录操作 → 拒绝并记录。

## 最终报告栏目（中文）

1. 基线与扫描范围
2. A 类低风险候选
3. B 类待确认候选
4. C 类保护项
5. 残留交叉核对（服务/计划任务/自启动/Uninstall 孤儿）
6. 特殊空间占用（hiberfil、VHDX、阴影、Windows.old、Installer MSP）
7. 错误与跳过路径
8. DryRun 计划
9. 实际执行与复测结果（前后剩余空间、实测增量、逻辑删除量、仍占卷的隔离量、失败/跳过/占用/权限/校验失败明细、需后续处理的特殊资源）

**不得承诺逻辑文件大小之和等于实际释放空间。**

## 已知限制（须在报告中声明）

- 大小为**逻辑估算**：硬链接重复计数、OneDrive 占位文件已排除（不触发下载）、重解析点未跟随；覆盖率可能因硬链接超过 100%，已做上限处理；
- 非管理员模式下其他用户目录不完整，报告必须声明"扫描不完整"，不得假装已提权；
- 深度扫描的 `build/target/dist` 目录按"可再生构建产物"处理，但可能包含用户交付物，故只进入 B 桶并要求逐项确认；
- 无法解析的服务/任务/自启动命令 ≠ 失效，只标记；
- WSL/Docker、DISM、阴影、休眠的清理走独立确认流程，不并入普通删除。
