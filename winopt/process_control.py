"""Safe process and process-tree inspection, working-set trim, and restart engine."""

from __future__ import annotations

import os
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import psutil

from winopt.config import OptimizerConfig
from winopt.models import LeakEvent, ProcessMetric, SystemSnapshot
from winopt.win32_native import (
    IS_WINDOWS,
    empty_process_working_set,
    enable_privileges,
    get_current_desktop_info,
    post_wm_close_to_pids,
)

FORBIDDEN_PROCESSES: frozenset[str] = frozenset(
    {
        "system",
        "registry",
        "idle",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "lsaext.exe",
        "svchost.exe",
        "dwm.exe",
        "winlogon.exe",
        "fontdrvhost.exe",
        "memory compression",
        "audiodg.exe",
        "hipsdaemon.exe",
        "todesk_service.exe",
        "nvdisplay.container.exe",
    }
)

SHELL_SPECIAL_PROCESSES: frozenset[str] = frozenset({"explorer.exe"})

AUTO_RESPAWN_PROCESSES: frozenset[str] = frozenset({"explorer.exe", "nvidia overlay.exe"})

UNSAVED_WORK_RISK_PROCESSES: frozenset[str] = frozenset(
    {
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "obsidian.exe",
        "code.exe",
        "antigravity.exe",
        "blender.exe",
        "solidworks.exe",
        "sldworks.exe",
        "ansys.exe",
        "fluent.exe",
        "matlab.exe",
        "acad.exe",
        "qq.exe",
        "wechat.exe",
        "weixin.exe",
        "dingtalk.exe",
    }
)

CHROMIUM_BROWSERS: frozenset[str] = frozenset({"chrome.exe", "msedge.exe", "brave.exe"})

CLI_TEST_SAFE_PROCESSES: frozenset[str] = frozenset(
    {"python.exe", "pythonw.exe", "cmd.exe", "powershell.exe", "pwsh.exe"}
)

_DETACHED_FLAGS = 0x00000008 | 0x00000200 if IS_WINDOWS else 0
_GUI_RELAUNCH_FLAGS = 0x00000200 if IS_WINDOWS else 0


def get_self_lineage_pids() -> set[int]:
    """Return current process PID and all ancestor PIDs so console never terminates itself/IDE."""
    lineage: set[int] = set()
    try:
        cur: psutil.Process | None = psutil.Process(os.getpid())
        while cur is not None and cur.pid not in lineage:
            lineage.add(cur.pid)
            try:
                cur = cur.parent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
    except Exception:
        lineage.add(os.getpid())
    return lineage


def classify_process(pid: int, name: str, self_lineage: set[int] | None = None) -> dict[str, Any]:
    """Classify a process into forbidden / shell_restart / safe_restart safety tiers."""
    lineage = self_lineage if self_lineage is not None else get_self_lineage_pids()
    lname = (name or "").strip().lower()

    if pid <= 4 or pid in lineage:
        return {
            "safety_tier": "forbidden",
            "safety_reason": "当前控制台自身或核心祖先进程，禁止终止或修剪",
            "unsaved_work_risk": False,
            "can_restart": False,
            "can_trim": False,
        }
    if lname in FORBIDDEN_PROCESSES:
        return {
            "safety_tier": "forbidden",
            "safety_reason": f"系统关键内核/桌面合成/安全服务 ({name})，禁止直接终止",
            "unsaved_work_risk": False,
            "can_restart": False,
            "can_trim": False,
        }
    if lname in SHELL_SPECIAL_PROCESSES:
        return {
            "safety_tier": "shell_restart",
            "safety_reason": "桌面资源管理器专用安全重启（重启后自动/兜底拉起桌面壳）",
            "unsaved_work_risk": False,
            "can_restart": True,
            "can_trim": False,
        }
    return {
        "safety_tier": "safe_restart",
        "safety_reason": "支持安全优雅退出并按原路径重新拉起",
        "unsaved_work_risk": lname in UNSAVED_WORK_RISK_PROCESSES,
        "can_restart": True,
        "can_trim": True,
    }


def resolve_same_app_tree(pid: int) -> tuple[psutil.Process, list[psutil.Process]]:
    """Climb parent chain across identical process names (never entering self lineage), then collect descendants."""
    lineage = get_self_lineage_pids()
    target = psutil.Process(pid)
    target_name = target.name().lower()
    root = target
    visited = {root.pid}

    while True:
        try:
            parent = root.parent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
        if parent is None or parent.pid <= 4 or parent.pid in visited or parent.pid in lineage:
            break
        try:
            if parent.name().lower() != target_name:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
        visited.add(parent.pid)
        root = parent

    members: list[psutil.Process] = [root]
    seen_pids = {root.pid}
    try:
        for child in root.children(recursive=True):
            if child.pid not in seen_pids:
                seen_pids.add(child.pid)
                members.append(child)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return (root, members)


def resolve_targets_by_scope(pid: int, scope: str = "tree") -> tuple[psutil.Process, list[psutil.Process]]:
    """Resolve process targets for `single`, `tree`, or `group` (all same-name instances)."""
    if scope == "single":
        p = psutil.Process(pid)
        return (p, [p])
    if scope == "group":
        lineage = get_self_lineage_pids()
        root, tree_members = resolve_same_app_tree(pid)
        lname = root.name().lower()
        by_pid: dict[int, psutil.Process] = {m.pid: m for m in tree_members if m.pid not in lineage}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if p.pid in lineage:
                    continue
                if (p.info.get("name") or "").lower() == lname:
                    by_pid.setdefault(p.pid, p)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        ordered = [root] + [p for k, p in by_pid.items() if k != root.pid]
        return (root, ordered)
    return resolve_same_app_tree(pid)


def build_relaunch_command(exe: str, cmdline: list[str], name: str) -> list[str]:
    """Build a safe relaunch command, stripping internal/transient Chromium flags."""
    lname = (name or "").strip().lower()
    if lname == "explorer.exe":
        return ["explorer.exe"]

    clean_exe = (exe or "").strip()
    if not clean_exe and cmdline:
        cand = str(cmdline[0]).strip()
        if cand and Path(cand).exists():
            clean_exe = cand

    if lname in CHROMIUM_BROWSERS:
        if not clean_exe or not Path(clean_exe).exists():
            return []
        safe_flags: list[str] = []
        i = 1
        args = cmdline or []
        while i < len(args):
            arg = str(args[i])
            if arg.startswith("--profile-directory=") or arg.startswith("--user-data-dir="):
                safe_flags.append(arg)
            elif arg in ("--profile-directory", "--user-data-dir") and (i + 1) < len(args):
                safe_flags.extend([arg, str(args[i + 1])])
                i += 1
            i += 1
        return [clean_exe, *safe_flags]

    is_internal_child = any(str(arg).startswith("--type=") for arg in (cmdline or []))

    if not is_internal_child and cmdline:
        first = str(cmdline[0]).strip()
        if first and Path(first).exists():
            return [str(a) for a in cmdline]

    if clean_exe and Path(clean_exe).exists():
        return [clean_exe]
    return []


def _choose_representative_root(group: list[ProcessMetric]) -> ProcessMetric:
    """Pick the most likely root PID among processes sharing the same name."""
    pid_set = {p.pid for p in group}
    # Check live parent links when possible so Chromium browser root is preferred over renderer
    candidates: list[tuple[int, float, ProcessMetric]] = []
    for pm in group:
        has_same_parent = False
        try:
            parent = psutil.Process(pm.pid).parent()
            if parent is not None and parent.pid in pid_set:
                has_same_parent = True
        except Exception:
            pass
        # Sort priority: (0 if top-level root else 1, -private_mb)
        candidates.append((0 if not has_same_parent else 1, -pm.private_mb, pm))
    candidates.sort(key=lambda item: (item[0], item[1]))
    return candidates[0][2]


def build_heavy_process_entries(
    snapshot: SystemSnapshot,
    leaks: list[LeakEvent],
    cfg: OptimizerConfig,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Aggregate live processes + leak markers into actionable console governance rows."""
    lineage = get_self_lineage_pids()
    heavy_keywords = [kw.lower() for kw in cfg.guard.heavy_app_processes]
    leaks_by_pid: dict[int, list[LeakEvent]] = defaultdict(list)
    leaks_by_name: dict[str, list[LeakEvent]] = defaultdict(list)

    for lk in leaks:
        if lk.pid > 0:
            leaks_by_pid[lk.pid].append(lk)
        base_name = lk.process_name.split(" (")[0].strip().lower()
        leaks_by_name[base_name].append(lk)

    by_name: dict[str, list[ProcessMetric]] = defaultdict(list)
    for proc in snapshot.processes:
        if proc.pid <= 4:
            continue
        by_name[proc.name.lower()].append(proc)

    entries: list[dict[str, Any]] = []
    sev_weight = {"CRITICAL": 3, "WARN": 2, "INFO": 1}

    for lname, group in by_name.items():
        total_priv = round(sum(p.private_mb for p in group), 1)
        total_rss = round(sum(p.rss_mb for p in group), 1)
        total_vram = round(
            sum(p.vram_dedicated_mb for p in group if not p.vram_glitch), 1
        )
        total_handles = sum(p.handles for p in group)
        max_gdi = max((p.gdi_objects for p in group), default=0)
        max_user = max((p.user_objects for p in group), default=0)
        total_cpu = round(sum(p.cpu_pct for p in group), 1)

        matched_leaks: list[LeakEvent] = list(leaks_by_name.get(lname, []))
        for p in group:
            for lk in leaks_by_pid.get(p.pid, []):
                if lk not in matched_leaks:
                    matched_leaks.append(lk)

        is_notable = (
            total_priv >= 280.0
            or total_rss >= 280.0
            or total_vram >= 100.0
            or total_handles >= 2500
            or max_gdi >= 1000
            or max_user >= 1000
            or bool(matched_leaks)
        )
        if not is_notable:
            continue

        rep = _choose_representative_root(group)
        safety = classify_process(rep.pid, rep.name, lineage)
        if any(p.pid in lineage for p in group):
            safety = classify_process(rep.pid, rep.name, lineage | {rep.pid})

        relaunch_preview = ""
        if safety["can_restart"]:
            if lname == "explorer.exe":
                relaunch_preview = "explorer.exe"
            elif rep.exe:
                relaunch_preview = rep.exe

        is_heavy_workload = any(kw in lname for kw in heavy_keywords)
        top_sev_score = max(
            (sev_weight.get(lk.severity, 0) for lk in matched_leaks),
            default=0,
        )

        entries.append(
            {
                "name": rep.name,
                "root_pid": rep.pid,
                "pids": [p.pid for p in group],
                "process_count": len(group),
                "total_private_mb": total_priv,
                "total_rss_mb": total_rss,
                "total_vram_mb": total_vram,
                "total_handles": total_handles,
                "max_gdi": max_gdi,
                "max_user": max_user,
                "total_cpu_pct": total_cpu,
                "exe": rep.exe,
                "relaunch_preview": relaunch_preview,
                "is_heavy_workload": is_heavy_workload,
                "leak_tags": [
                    {
                        "severity": lk.severity,
                        "category": lk.category,
                        "current_value": lk.current_value,
                        "recommendation": lk.recommendation,
                    }
                    for lk in matched_leaks
                ],
                "top_severity_score": top_sev_score,
                **safety,
            }
        )

    entries.sort(
        key=lambda e: (
            -e["top_severity_score"],
            -(e["total_private_mb"] + e["total_vram_mb"] * 2.0 + e["total_rss_mb"] * 0.25),
        )
    )
    return entries[:limit]


def safe_trim_target(pid: int, scope: str = "tree") -> dict[str, Any]:
    """Safely trim working sets of target process or same-app group/tree."""
    lineage = get_self_lineage_pids()
    try:
        root, members = resolve_targets_by_scope(pid, scope=scope)
    except psutil.NoSuchProcess:
        return {
            "ok": False,
            "http_status": 404,
            "message": f"进程 PID {pid} 已不存在",
        }
    except psutil.AccessDenied:
        return {
            "ok": False,
            "http_status": 403,
            "message": f"无权限访问进程 PID {pid}",
        }

    root_name = root.name()
    safety = classify_process(root.pid, root_name, lineage)
    if not safety["can_trim"]:
        return {
            "ok": False,
            "http_status": 403,
            "message": f"拒绝修剪: {safety['safety_reason']}",
        }

    if IS_WINDOWS:
        enable_privileges(["SeDebugPrivilege", "SeIncreaseQuotaPrivilege"])

    trimmed_count = 0
    before_rss = 0.0
    after_rss = 0.0
    for proc in members:
        try:
            p_cls = classify_process(proc.pid, proc.name(), lineage)
            if not p_cls["can_trim"]:
                continue
            b_mb = proc.memory_info().rss / (1024.0 * 1024.0)
            before_rss += b_mb
            if empty_process_working_set(proc.pid):
                trimmed_count += 1
            a_mb = proc.memory_info().rss / (1024.0 * 1024.0)
            after_rss += a_mb
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    freed_rss = round(max(0.0, before_rss - after_rss), 2)
    return {
        "ok": True,
        "http_status": 200,
        "target_name": root_name,
        "target_pid": root.pid,
        "scope": scope,
        "trimmed_count": trimmed_count,
        "freed_rss_mb": freed_rss,
        "message": f"已修剪 {root_name} ({trimmed_count} 个进程) 工作集，释放物理驻留 {freed_rss:.1f} MB",
    }


def _collect_process_footprint(procs: list[psutil.Process]) -> dict[str, Any]:
    total_priv = 0.0
    total_rss = 0.0
    total_handles = 0
    for p in procs:
        try:
            mem = p.memory_info()
            total_rss += mem.rss / (1024.0 * 1024.0)
            total_priv += getattr(mem, "private", mem.rss) / (1024.0 * 1024.0)
            total_handles += int(p.num_handles())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return {
        "private_mb": round(total_priv, 2),
        "rss_mb": round(total_rss, 2),
        "handles": total_handles,
    }


def _find_respawned_pid(
    name_lower: str,
    old_pids: set[int],
    min_create_time: float,
) -> int | None:
    for p in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            if (p.info.get("name") or "").lower() != name_lower:
                continue
            if p.pid in old_pids:
                continue
            ct = float(p.info.get("create_time") or 0.0)
            if ct >= min_create_time - 2.0:
                return p.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None


def safe_restart_target(
    pid: int,
    scope: str = "tree",
    relaunch: bool = True,
    graceful_timeout_s: float = 4.0,
) -> dict[str, Any]:
    """Safely terminate a process or same-app process tree and optionally relaunch it."""
    lineage = get_self_lineage_pids()
    try:
        root, targets = resolve_targets_by_scope(pid, scope=scope)
    except psutil.NoSuchProcess:
        return {
            "ok": False,
            "http_status": 404,
            "message": f"目标进程 PID {pid} 已不存在",
        }
    except psutil.AccessDenied:
        return {
            "ok": False,
            "http_status": 403,
            "message": f"无权限检查进程 PID {pid}",
        }

    root_name = root.name()
    root_name_lower = root_name.lower()

    # Non-default desktop guard: never relaunch GUI apps onto an isolated/invisible desktop!
    if IS_WINDOWS and relaunch and root_name_lower not in CLI_TEST_SAFE_PROCESSES:
        desk = get_current_desktop_info()
        if not desk["is_default_desktop"]:
            return {
                "ok": False,
                "http_status": 409,
                "target_name": root_name,
                "target_pid": root.pid,
                "message": (
                    f"当前 Web 控制台运行在非交互/隔离桌面 ({desk['window_station']}\\{desk['desktop']})，"
                    f"在此环境中重启 GUI 应用 ({root_name}) 会导致窗口不可见并锁死应用配置！"
                    "请先关闭当前后台服务，改在正常 Windows 桌面双击 start_web_console.bat "
                    "或在系统终端运行 python -m winopt.cli web --open 后再操作。"
                ),
            }

    # Validate EVERY member against FORBIDDEN and self-lineage
    for proc in targets:
        try:
            p_name = proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        p_cls = classify_process(proc.pid, p_name, lineage)
        if not p_cls["can_restart"]:
            return {
                "ok": False,
                "http_status": 403,
                "message": f"安全拦截: {p_name} (PID {proc.pid}) — {p_cls['safety_reason']}",
            }

    # Capture executable, cmdline, cwd & footprint before stopping
    try:
        exe = root.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        exe = ""
    try:
        cmdline = root.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        cmdline = []
    try:
        cwd = root.cwd()
        if not cwd or not Path(cwd).exists():
            cwd = str(Path(exe).parent) if exe else None
    except Exception:
        cwd = str(Path(exe).parent) if exe else None

    relaunch_cmd = build_relaunch_command(exe, cmdline, root_name)
    if relaunch and not relaunch_cmd:
        return {
            "ok": False,
            "http_status": 400,
            "message": f"无法解析 {root_name} 的可执行文件路径，已取消重启以防结束后无法拉起",
        }

    before_stats = _collect_process_footprint(targets)
    old_pids = {p.pid for p in targets}
    start_wall = time.time()

    # Phase 1: Graceful WM_CLOSE wait -> terminate survivors -> force kill stubborn PIDs
    if IS_WINDOWS and root_name_lower != "explorer.exe":
        wm_sent = post_wm_close_to_pids(old_pids)
        if wm_sent > 0:
            psutil.wait_procs(targets, timeout=max(0.5, graceful_timeout_s))

    alive_procs: list[psutil.Process] = []
    for p in targets:
        try:
            if p.is_running():
                p.terminate()
                alive_procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    _, still_alive = psutil.wait_procs(alive_procs, timeout=min(2.0, max(0.5, graceful_timeout_s)))
    killed_force = 0
    for p in still_alive:
        try:
            if p.is_running():
                p.kill()
                killed_force += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if still_alive:
        psutil.wait_procs(still_alive, timeout=1.5)

    time.sleep(0.8)
    if root_name_lower in CHROMIUM_BROWSERS:
        # Ensure Chromium User Data lockfile holders from old_pids have fully exited
        lingering = [psutil.Process(op) for op in old_pids if psutil.pid_exists(op)]
        if lingering:
            psutil.wait_procs(lingering, timeout=1.5)

    # Phase 2: Relaunch if requested
    new_pid: int | None = None
    relaunch_status = "not_requested"
    if relaunch:
        # Check if Windows Shell or auto-respawner daemon already brought it back
        if root_name_lower in AUTO_RESPAWN_PROCESSES:
            time.sleep(0.6)
            new_pid = _find_respawned_pid(root_name_lower, old_pids, start_wall)
            if new_pid is not None:
                relaunch_status = "auto_respawned"

        if new_pid is None:
            try:
                popen_kwargs: dict[str, Any] = {
                    "cwd": cwd,
                    "close_fds": True,
                    "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.DEVNULL,
                    "stderr": subprocess.DEVNULL,
                }
                if IS_WINDOWS:
                    si = subprocess.STARTUPINFO()
                    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    si.wShowWindow = 1  # SW_SHOWNORMAL
                    popen_kwargs["startupinfo"] = si
                    popen_kwargs["creationflags"] = (
                        _DETACHED_FLAGS
                        if root_name_lower in CLI_TEST_SAFE_PROCESSES
                        else _GUI_RELAUNCH_FLAGS
                    )

                proc_new = subprocess.Popen(relaunch_cmd, **popen_kwargs)
                time.sleep(0.7)
                if proc_new.poll() is None:
                    new_pid = proc_new.pid
                    relaunch_status = "relaunched"
                else:
                    # Launcher wrapper may spawn real process and exit immediately (e.g. Chrome/Explorer)
                    respawned = _find_respawned_pid(root_name_lower, old_pids, start_wall)
                    if respawned is not None:
                        new_pid = respawned
                        relaunch_status = "relaunched_via_wrapper"
                    else:
                        relaunch_status = f"launcher_exited_{proc_new.returncode}"
            except Exception as exc:
                relaunch_status = f"relaunch_failed: {exc}"

    after_stats = {"private_mb": 0.0, "rss_mb": 0.0, "handles": 0}
    if new_pid is not None:
        try:
            _, new_tree = resolve_same_app_tree(new_pid)
            after_stats = _collect_process_footprint(new_tree)
        except Exception:
            pass

    freed_priv = round(max(0.0, before_stats["private_mb"] - after_stats["private_mb"]), 2)
    freed_rss = round(max(0.0, before_stats["rss_mb"] - after_stats["rss_mb"]), 2)
    freed_handles = max(0, int(before_stats["handles"] - after_stats["handles"]))

    action_label = "安全重启" if relaunch else "安全结束"
    new_pid_note = f"，新 PID={new_pid}" if new_pid else ""
    msg = (
        f"已{action_label} {root_name} (原 {len(old_pids)} 个进程，强制结束 {killed_force} 个){new_pid_note}；"
        f"释放私有提交内存 {freed_priv:.1f} MB，物理内存 {freed_rss:.1f} MB，句柄 {freed_handles}"
    )

    return {
        "ok": True,
        "http_status": 200,
        "target_name": root_name,
        "target_pid": root.pid,
        "terminated_pids": sorted(old_pids),
        "killed_force_count": killed_force,
        "scope": scope,
        "relaunch": relaunch,
        "relaunch_status": relaunch_status,
        "relaunch_cmd": relaunch_cmd,
        "new_pid": new_pid,
        "before": before_stats,
        "after": after_stats,
        "freed_private_mb": freed_priv,
        "freed_rss_mb": freed_rss,
        "freed_handles": freed_handles,
        "message": msg,
    }
