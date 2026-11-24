"""Workload guard to protect active heavy engineering software and games."""

from __future__ import annotations

from pathlib import PurePath

from winopt.config import OptimizerConfig
from winopt.models import GuardDecision, SystemSnapshot


def _process_stem(name: str) -> str:
    return PurePath(name.strip().lower()).stem


def evaluate_workload_guard(
    snapshot: SystemSnapshot,
    cfg: OptimizerConfig,
    mode: str = "manual",
) -> GuardDecision:
    """Decide execution profile (`full` or `conservative`) based on live system load."""
    if not cfg.guard.enabled:
        return GuardDecision(
            profile="full",
            reasons=["负载保护已关闭，按完整模式执行"],
        )

    heavy_keywords = [kw.lower() for kw in cfg.guard.heavy_app_processes]
    active_apps: list[str] = []
    active_pids: list[int] = []
    reasons: list[str] = []

    for proc in snapshot.processes:
        stem = _process_stem(proc.name)
        name_lower = proc.name.lower()
        if any(kw in stem or kw in name_lower for kw in heavy_keywords):
            # Consider active if foreground OR non-trivial CPU/RAM/VRAM footprint
            is_fg = snapshot.foreground_pid == proc.pid
            is_loaded = proc.rss_mb >= 250.0 or proc.cpu_pct >= 2.0 or proc.vram_dedicated_mb >= 128.0
            if is_fg or is_loaded:
                active_apps.append(proc.name)
                active_pids.append(proc.pid)

    unique_apps = sorted(set(active_apps))
    if unique_apps:
        reasons.append(f"检测到活跃重负载软件: {', '.join(unique_apps[:5])}")

    if snapshot.cpu_pct >= cfg.guard.cpu_busy_threshold_pct:
        reasons.append(
            f"系统 CPU 占用较高 ({snapshot.cpu_pct:.1f}% >= {cfg.guard.cpu_busy_threshold_pct:.1f}%)"
        )

    if snapshot.gpu.present and snapshot.gpu.utilization_gpu_pct >= cfg.guard.gpu_busy_threshold_pct:
        reasons.append(
            f"GPU 利用率较高 ({snapshot.gpu.utilization_gpu_pct:.1f}% >= {cfg.guard.gpu_busy_threshold_pct:.1f}%)"
        )

    if mode == "boost":
        reasons.append("Boost 预启动加速模式：执行完整清理，同时保护活跃重负载与前台窗口")
        return GuardDecision(
            profile="full",
            reasons=reasons,
            active_heavy_apps=unique_apps,
            active_heavy_pids=active_pids,
        )

    if reasons and cfg.guard.downgrade_to_conservative_when_busy:
        return GuardDecision(
            profile="conservative",
            reasons=reasons,
            active_heavy_apps=unique_apps,
            active_heavy_pids=active_pids,
        )

    if not reasons:
        reasons.append("系统处于常规空闲/轻负载状态，可执行完整优化")

    return GuardDecision(
        profile="full",
        reasons=reasons,
        active_heavy_apps=unique_apps,
        active_heavy_pids=active_pids,
    )
