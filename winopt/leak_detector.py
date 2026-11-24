"""Multi-dimensional memory, handle, GDI/USER, VRAM, and kernel pool leak detector."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from winopt.config import OptimizerConfig
from winopt.models import GuardDecision, LeakEvent, ProcessMetric, SystemSnapshot
from winopt.storage import StorageManager


def compute_rate_per_hour(
    points: list[tuple[str, float]],
    min_samples: int = 2,
    min_span_hours: float = 1.0 / 60.0,
) -> float | None:
    """Compute OLS linear regression slope (units per hour) over timestamped points."""
    if len(points) < min_samples:
        return None

    parsed: list[tuple[float, float]] = []
    for ts_str, val in points:
        try:
            dt = datetime.fromisoformat(ts_str)
            parsed.append((dt.timestamp(), float(val)))
        except Exception:
            continue

    if len(parsed) < min_samples:
        return None

    parsed.sort(key=lambda x: x[0])
    t0 = parsed[0][0]
    span_hours = (parsed[-1][0] - t0) / 3600.0
    if span_hours < min_span_hours:
        return None

    xs = [(t - t0) / 3600.0 for t, _ in parsed]
    ys = [v for _, v in parsed]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    if denom <= 1e-9:
        return None
    numer = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    return round(numer / denom, 2)


def detect_leaks(
    snapshot: SystemSnapshot,
    cfg: OptimizerConfig,
    storage: StorageManager | None,
    guard: GuardDecision | None = None,
) -> list[LeakEvent]:
    """Analyze current snapshot + SQLite history to detect leaks and resource bloat."""
    events: list[LeakEvent] = []
    ld = cfg.leak_detection
    heavy_pids = set(guard.active_heavy_pids) if guard else set()
    now_iso = snapshot.captured_at

    # 1. Kernel Nonpaged Pool & System Commit Charge
    if snapshot.kernel_nonpaged_mb >= ld.nonpaged_pool_warn_mb:
        sev = "CRITICAL" if snapshot.kernel_nonpaged_mb >= ld.nonpaged_pool_warn_mb * 1.5 else "WARN"
        events.append(
            LeakEvent(
                detected_at=now_iso,
                severity=sev,
                category="nonpaged_pool",
                pid=0,
                process_name="Kernel Nonpaged Pool",
                current_value=snapshot.kernel_nonpaged_mb,
                growth_rate_per_hour=None,
                recommendation=(
                    "内核非分页池偏高（无法通过内存修剪释放），常见原因包括网卡/显卡/杀毒驱动或虚拟网卡长时间运行泄漏，"
                    "建议找空闲窗口重启电脑或排查近期更新的驱动。"
                ),
                details={"paged_pool_mb": snapshot.kernel_paged_mb},
            )
        )

    if snapshot.commit_pct >= ld.commit_pct_crit:
        events.append(
            LeakEvent(
                detected_at=now_iso,
                severity="CRITICAL",
                category="commit",
                pid=0,
                process_name="System Commit Charge",
                current_value=snapshot.commit_pct,
                growth_rate_per_hour=None,
                recommendation=(
                    "系统提交内存已接近上限，新启动大型工程软件或游戏极易闪退或剧烈卡顿！"
                    "建议立即关闭长期驻留的浏览器/Electron 后台进程或检查虚拟内存页面文件上限。"
                ),
                details={
                    "commit_total_mb": snapshot.commit_total_mb,
                    "commit_limit_mb": snapshot.commit_limit_mb,
                },
            )
        )
    elif snapshot.commit_pct >= ld.commit_pct_warn:
        events.append(
            LeakEvent(
                detected_at=now_iso,
                severity="WARN",
                category="commit",
                pid=0,
                process_name="System Commit Charge",
                current_value=snapshot.commit_pct,
                growth_rate_per_hour=None,
                recommendation=(
                    "系统提交内存占比偏高，开启大型软件前建议关闭部分常驻应用以留足虚拟地址空间。"
                ),
                details={
                    "commit_total_mb": snapshot.commit_total_mb,
                    "commit_limit_mb": snapshot.commit_limit_mb,
                },
            )
        )

    # 2. Per-process instance analysis
    by_name: dict[str, list[ProcessMetric]] = defaultdict(list)
    for proc in snapshot.processes:
        by_name[proc.name.lower()].append(proc)
        if proc.pid <= 4 or proc.pid in heavy_pids:
            continue

        # Only fetch history for processes with non-trivial footprint to keep queries minimal
        need_hist = (
            proc.private_mb >= 200.0
            or proc.handles >= 1000
            or proc.gdi_objects >= 500
            or proc.user_objects >= 500
            or (not proc.vram_glitch and proc.vram_dedicated_mb >= 150.0)
        )
        hist: list[dict[str, Any]] = []
        if storage is not None and need_hist:
            hist = storage.get_process_history(proc.pid, proc.create_time, phase="t2", limit=15)

        # Private memory trend & absolute threshold
        priv_pts = [(h["captured_at"], h["private_mb"]) for h in hist]
        priv_pts.append((now_iso, proc.private_mb))
        priv_slope = compute_rate_per_hour(priv_pts, min_samples=ld.min_samples_for_trend)

        if (priv_slope is not None and priv_slope >= ld.private_mb_per_hour_crit and proc.private_mb >= 400.0) or (
            proc.private_mb >= ld.private_abs_warn_mb * 1.8
        ):
            events.append(
                LeakEvent(
                    detected_at=now_iso,
                    severity="CRITICAL",
                    category="private_mem",
                    pid=proc.pid,
                    process_name=proc.name,
                    current_value=proc.private_mb,
                    growth_rate_per_hour=priv_slope,
                    recommendation=f"进程 {proc.name} (PID {proc.pid}) 私有内存占用过高或持续快速增长，建议保存工作后重启该进程。",
                    details={"rss_mb": proc.rss_mb, "samples": len(priv_pts)},
                )
            )
        elif (priv_slope is not None and priv_slope >= ld.private_mb_per_hour_warn and proc.private_mb >= 300.0) or (
            proc.private_mb >= ld.private_abs_warn_mb
        ):
            events.append(
                LeakEvent(
                    detected_at=now_iso,
                    severity="WARN",
                    category="private_mem",
                    pid=proc.pid,
                    process_name=proc.name,
                    current_value=proc.private_mb,
                    growth_rate_per_hour=priv_slope,
                    recommendation=f"进程 {proc.name} (PID {proc.pid}) 存在较大私有提交内存或持续增长趋势，建议按需重启释放提交内存。",
                    details={"rss_mb": proc.rss_mb, "samples": len(priv_pts)},
                )
            )

        # Handle leak check
        hdl_pts = [(h["captured_at"], h["handles"]) for h in hist]
        hdl_pts.append((now_iso, float(proc.handles)))
        hdl_slope = compute_rate_per_hour(hdl_pts, min_samples=ld.min_samples_for_trend)

        def _handle_rec(sev_desc: str) -> str:
            lname = proc.name.lower()
            if lname == "svchost.exe":
                return f"系统服务宿主 {proc.name} (PID {proc.pid}) {sev_desc}，可用 `tasklist /svc /fi \"pid eq {proc.pid}\"` 定位对应服务并在空闲时重启电脑。"
            if lname == "explorer.exe":
                return f"桌面资源管理器 {proc.name} (PID {proc.pid}) {sev_desc}，可在任务管理器中右键“重新启动”资源管理器以安全释放。"
            return f"进程 {proc.name} (PID {proc.pid}) {sev_desc}，建议保存工作后重启该进程。"

        if proc.handles >= ld.handle_warn_count * 2 or (
            hdl_slope is not None and hdl_slope >= ld.handle_per_hour_warn * 3 and proc.handles >= 2000
        ):
            events.append(
                LeakEvent(
                    detected_at=now_iso,
                    severity="CRITICAL",
                    category="handles",
                    pid=proc.pid,
                    process_name=proc.name,
                    current_value=float(proc.handles),
                    growth_rate_per_hour=hdl_slope,
                    recommendation=_handle_rec("内核句柄数严重异常，可能引发系统调度和池内存消耗"),
                    details={"samples": len(hdl_pts)},
                )
            )
        elif proc.handles >= ld.handle_warn_count or (
            hdl_slope is not None and hdl_slope >= ld.handle_per_hour_warn and proc.handles >= 1500
        ):
            events.append(
                LeakEvent(
                    detected_at=now_iso,
                    severity="WARN",
                    category="handles",
                    pid=proc.pid,
                    process_name=proc.name,
                    current_value=float(proc.handles),
                    growth_rate_per_hour=hdl_slope,
                    recommendation=_handle_rec("句柄数偏高或持续上升"),
                    details={"samples": len(hdl_pts)},
                )
            )

        # GDI & USER object checks (Windows per-process hard cap is 10,000)
        if proc.gdi_objects >= ld.gdi_warn_count:
            events.append(
                LeakEvent(
                    detected_at=now_iso,
                    severity="CRITICAL" if proc.gdi_objects >= 6000 else "WARN",
                    category="gdi",
                    pid=proc.pid,
                    process_name=proc.name,
                    current_value=float(proc.gdi_objects),
                    growth_rate_per_hour=None,
                    recommendation=f"进程 {proc.name} (PID {proc.pid}) GDI 对象数偏高 (上限 10,000)，持续增长会导致界面卡死或花屏。",
                )
            )

        if proc.user_objects >= ld.user_obj_warn_count:
            events.append(
                LeakEvent(
                    detected_at=now_iso,
                    severity="CRITICAL" if proc.user_objects >= 6000 else "WARN",
                    category="user_obj",
                    pid=proc.pid,
                    process_name=proc.name,
                    current_value=float(proc.user_objects),
                    growth_rate_per_hour=None,
                    recommendation=f"进程 {proc.name} (PID {proc.pid}) USER 窗口对象数偏高 (上限 10,000)，建议重启该应用。",
                )
            )

        # Dedicated GPU VRAM leak check (ignore WDDM glitch rows)
        if not proc.vram_glitch and proc.vram_dedicated_mb > 0:
            vram_pts = [
                (h["captured_at"], h["vram_dedicated_mb"])
                for h in hist
                if not h.get("vram_glitch", 0)
            ]
            vram_pts.append((now_iso, proc.vram_dedicated_mb))
            vram_slope = compute_rate_per_hour(vram_pts, min_samples=ld.min_samples_for_trend)
            is_dwm = proc.name.lower() == "dwm.exe"
            warn_threshold = cfg.gpu.dwm_vram_warn_mb if is_dwm else ld.vram_warn_mb

            if (is_dwm and proc.vram_dedicated_mb >= warn_threshold * 2) or (
                not is_dwm and proc.vram_dedicated_mb >= warn_threshold * 1.8
            ):
                events.append(
                    LeakEvent(
                        detected_at=now_iso,
                        severity="CRITICAL",
                        category="vram",
                        pid=proc.pid,
                        process_name=proc.name,
                        current_value=proc.vram_dedicated_mb,
                        growth_rate_per_hour=vram_slope,
                        recommendation=(
                            "dwm.exe 显存长期膨胀（常见于长时间不重启桌面合成器），启动大型游戏/渲染软件前建议注销重登或重启电脑。"
                            if is_dwm
                            else f"后台进程 {proc.name} (PID {proc.pid}) 占用大量专用显存 ({proc.vram_dedicated_mb:.0f} MB)，启动高显存软件前建议关闭。"
                        ),
                        details={"shared_mb": proc.vram_shared_mb},
                    )
                )
            elif proc.vram_dedicated_mb >= warn_threshold or (
                vram_slope is not None and vram_slope >= ld.vram_per_hour_warn and proc.vram_dedicated_mb >= 250.0
            ):
                events.append(
                    LeakEvent(
                        detected_at=now_iso,
                        severity="WARN",
                        category="vram",
                        pid=proc.pid,
                        process_name=proc.name,
                        current_value=proc.vram_dedicated_mb,
                        growth_rate_per_hour=vram_slope,
                        recommendation=(
                            f"dwm.exe 专用显存偏高 ({proc.vram_dedicated_mb:.0f} MB)，可考虑启用硬件加速清理或找空闲时间重启桌面会话。"
                            if is_dwm
                            else f"进程 {proc.name} (PID {proc.pid}) 占用较多专用显存 ({proc.vram_dedicated_mb:.0f} MB)，启动大型游戏/仿真软件前可酌情关闭。"
                        ),
                        details={"shared_mb": proc.vram_shared_mb},
                    )
                )

    # 3. Multi-process aggregate checks (browsers, WebView2, chat apps)
    flagged_names = {e.process_name.lower() for e in events if e.category == "private_mem"}
    for name_lower, group in by_name.items():
        if len(group) < 2 or name_lower in flagged_names:
            continue
        if any(p.pid in heavy_pids for p in group):
            continue
        total_priv = round(sum(p.private_mb for p in group), 2)
        if total_priv < 800.0:
            continue

        agg_slope: float | None = None
        if storage is not None:
            agg_hist = storage.get_process_name_aggregate_history(group[0].name, phase="t2", limit=15)
            agg_pts = [(h["captured_at"], h["private_mb"]) for h in agg_hist]
            agg_pts.append((now_iso, total_priv))
            agg_slope = compute_rate_per_hour(agg_pts, min_samples=ld.min_samples_for_trend)

        if total_priv >= ld.private_abs_warn_mb * 1.4 or (
            agg_slope is not None and agg_slope >= ld.private_mb_per_hour_warn * 1.5
        ):
            events.append(
                LeakEvent(
                    detected_at=now_iso,
                    severity="WARN",
                    category="private_mem",
                    pid=0,
                    process_name=f"{group[0].name} (多进程合计 {len(group)} 个)",
                    current_value=total_priv,
                    growth_rate_per_hour=agg_slope,
                    recommendation=(
                        f"{group[0].name} 的 {len(group)} 个子进程累计提交内存达 {total_priv:.0f} MB，"
                        "开启大型软件前建议关闭无用标签页或重启该应用释放提交内存。"
                    ),
                    details={"process_count": len(group)},
                )
            )

    sev_rank = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    events.sort(key=lambda e: (sev_rank.get(e.severity, 9), -e.current_value))
    return events
