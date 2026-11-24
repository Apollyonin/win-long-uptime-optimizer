# Windows 长运行自动性能优化与闭环自迭代系统 (`winopt`)

> **声明**：本项目使用 AI 辅助开发。

面向 **长时间不关机** 的 Windows 10/11 工作站与游戏电脑，每 **12 小时** 自动执行安全、可验证的系统优化，保证在长时间运行后随时开启 **工程模拟软件（ANSYS / SolidWorks / MATLAB / Blender / AutoCAD 等）** 或 **大型 3A 游戏** 时尽量不卡顿，并持续追踪内存泄漏与自我迭代优化。

---

## 核心设计思想

1. **为什么长期不关机后开启大软件会卡顿？**
   - **Standby List 挤压与硬/软页错误**：长时间缓存的旧文件页挤占 Standby 列表，新启动大软件申请数百 MB–数 GB 物理内存时，内存管理器需要频繁驱逐并重构页面列表。
   - **后台闲置进程工作集膨胀**：长时间打开的聊天软件、浏览器后台渲染进程、更新器等占用大量物理工作集。
   - **私有提交内存 / 句柄 / GDI / 显存 (VRAM) 慢速泄漏**：`Commit Charge` 逼近上限、内核非分页池 (`Nonpaged Pool`) 膨胀或 `dwm.exe`/后台程序占用大量显存，导致大软件启动即掉帧或爆内存。
   - **禁止破坏性“一刀切”清理**：直接全局清空所有进程工作集 (`MemoryEmptyWorkingSets`) 反而会导致桌面与前台软件瞬间卡顿。本系统仅针对**闲置、低 CPU、非保护、非前台、非重负载**的后台进程进行选择性修剪。

2. **闭环验证与“查漏补缺”机制**
   - 每次优化严格采集三阶段状态：`T0 (优化前基准)` → `T1 (刚优化后)` → `T2 (静置观察期后)`。
   - 运行非破坏性微基准（`128 MB` 页分配接触耗时、5ms 定时器调度 P95 抖动、磁盘 I/O 探针）。
   - 计算 **重负载就绪度评分 (0-100)**，逐进程检查工作集修剪后在 `T2` 是否快速回弹。
   - **查漏补缺 (Gap Analysis)**：明确指出哪些问题通过自动清理已解决，哪些问题受限于系统原理无法通过内存修剪消除（例如高 `Commit` 进程、高独立显存占用、`dwm.exe` 显存累积、内核非分页池膨胀等），给出精准到进程名和 MB 数的可操作建议。

3. **有边界的自迭代与自动回滚保护**
   - 连续高比例回弹的后台进程，在达到连续触发次数 (`rebound_exclude_strikes=2`) 后自动写入 `dynamic_trim_exclude`，避免反复修剪引发软页错误抖动。
   - 所有自适应阈值均被严格钳位在安全上下界 (`bounds`) 内，**绝不自动修改保护白名单，也绝不自动查杀用户应用**。
   - 若某次策略迭代导致下一次相同负载配置下的就绪度评分显著下降或页分配耗时飙升，系统自动**回滚**至上一已知良好策略版本 (`last_known_good_version`)。

---

## 快速开始

### 1. 只读深度诊断（不修改系统状态）
```powershell
python -m winopt.cli diagnose
```

### 2. 预演模式 (Dry-Run)
```powershell
python -m winopt.cli run --dry-run
```

### 3. 手动执行一次完整闭环优化
```powershell
python -m winopt.cli run
```
或使用 PowerShell 包装脚本：
```powershell
.\run_optimizer.ps1 run
```

### 4. 开启大型工程软件 / 游戏前的“战前加速”
```powershell
python -m winopt.cli boost
```

### 5. 安装每 12 小时自动执行的 Windows 计划任务（需管理员权限）
```powershell
python -m winopt.cli schedule install
python -m winopt.cli schedule status
```
如需卸载：
```powershell
python -m winopt.cli schedule uninstall
```

### 6. 启动本地交互式 Web 控制台（推荐）
在正常 Windows 交互桌面双击 [start_web_console.bat](start_web_console.bat)，或在系统终端运行：
```powershell
python -m winopt.cli web --open
```
> **说明**：涉及重启桌面 GUI 应用（如 Chrome/Edge/软件窗口）时，控制台必须在正常桌面会话 (`WinSta0\Default`) 启动，新拉起的软件窗口才会正常显示在前台；若运行在隔离桌面/非交互沙箱，控制台会自动拦截 GUI 重启以防隐身窗口锁死。

浏览器打开 `http://127.0.0.1:18765/` 后可使用：
- **手动一键清理按键**：立即执行完整闭环优化 (`T0→T2`)、大软件/游戏战前加速 (`Boost`)、快速释放内存 (`Standby + 工作集`)。
- **高占用/泄漏进程与进程树安全治理**：
  - 实时识别私有提交内存、物理工作集、专用显存、句柄/GDI 异常的进程或进程树。
  - **三层安全分级**：
    - `forbidden`（禁用按钮）：禁止终止系统内核/桌面合成/安全服务（`svchost.exe`、`dwm.exe`、`csrss.exe` 等）以及控制台自身祖先进程树。
    - `shell_restart`：支持 `explorer.exe` 专用安全重启并自动/兜底拉起桌面壳。
    - `safe_restart`：先发送 `WM_CLOSE` 优雅退出信号，再终止同名进程树（拉起时自动剥离 Chromium/Electron 子进程 `--type=` 参数），对浏览器/Office/CAD/聊天软件弹出未保存提醒确认框。
  - **安全模型**：严格仅监听 `127.0.0.1` 回环地址，所有写操作校验随机生成的 `X-WinOpt-Token` CSRF 令牌与本机 `Origin`，并记录至 SQLite `manual_actions` 审计表。

### 7. 查看历史运行、策略演化与可视化面板
```powershell
python -m winopt.cli history
python -m winopt.cli policy show
python -m winopt.cli policy history
python -m winopt.cli report
```
生成的可视化报告位于：
- [latest_report.md](reports/latest_report.md)
- [latest_dashboard.html](reports/latest_dashboard.html)

---

## Git 自动同步（仅代码 / 配置 / 文档）

- **隐私隔离**：`.gitignore` 默认排除 `data/`（含 SQLite 数据库、`policy_state.json` 本机进程名、计划任务 XML 与日志）和 `reports/`（含本地系统诊断报告），仅同步代码、配置、测试与文档改动。
- **同步脚本**：[scripts/git_auto_sync.ps1](scripts/git_auto_sync.ps1) 会自动检测未忽略的源码/配置改动，提交并推送到 `origin/main`（支持 `-DryRun` 预演）。
- **脚本挂钩**：通过 `.\run_optimizer.ps1` 运行命令且退出码为 `0` 时会自动触发同步（可通过设置环境变量 `$env:WINOPT_DISABLE_GIT_SYNC = "1"` 临时禁用）。

---

## 运行测试

```powershell
python -m unittest discover -s tests -v
```

---

## 开源许可

本项目采用 **MIT License**（使用 AI 辅助开发），详见 [LICENSE](LICENSE)。
