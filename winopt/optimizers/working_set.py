"""Selective, protection-aware background process working set trimmer."""

from __future__ import annotations

import os
import time
from typing import Any

import psutil

from winopt.models import ActionResult
from winopt.optimizers.base import BaseOptimizer, OptimizationContext
from winopt.win32_native import IS_WINDOWS, empty_process_working_set, enable_privileges


class WorkingSetOptimizer(BaseOptimizer):
    name = "working_set"

    def run(self, ctx: OptimizationContext) -> ActionResult:
        t_start = time.perf_counter()
        ws_cfg = ctx.config.working_set
        if not ws_cfg.enabled:
            return ActionResult(
                module_name=self.name,
                status="skipped",
                duration_ms=0.0,
                summary="配置已禁用工作集修剪模块",
            )

        profile = ctx.guard.profile
        min_ws_mb = float(ctx.policy.min_working_set_mb)
        min_uptime_s = float(ctx.policy.min_uptime_seconds)
        max_cpu = float(ws_cfg.max_cpu_pct_for_trim)
        if profile == "conservative":
            min_ws_mb *= 2.0
            max_cpu = min(max_cpu, 0.5)

        protected = {p.lower() for p in ws_cfg.protected_processes}
        dynamic_exclude = {p.lower() for p in ctx.policy.dynamic_trim_exclude}
        heavy_pids = set(ctx.guard.active_heavy_pids)
        fg_pid = ctx.t0.foreground_pid
        self_pid = os.getpid()
        now_ts = time.time()

        candidates = []
        for proc in ctx.t0.processes:
            name_lower = proc.name.lower()
            if proc.pid <= 4 or proc.pid == self_pid or proc.pid == fg_pid:
                continue
            if proc.pid in heavy_pids:
                continue
            if name_lower in protected or name_lower in dynamic_exclude:
                continue
            if proc.rss_mb < min_ws_mb:
                continue
            if proc.create_time > 0 and (now_ts - proc.create_time) < min_uptime_s:
                continue
            if proc.cpu_pct > max_cpu:
                continue
            candidates.append(proc)

        candidates.sort(key=lambda p: p.rss_mb, reverse=True)

        if ctx.dry_run:
            est = round(sum(p.rss_mb * 0.35 for p in candidates), 2)
            return ActionResult(
                module_name=self.name,
                status="dry_run",
                duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
                reclaimed_mb=est,
                items_processed=len(candidates),
                summary=f"[Dry-Run] 将修剪 {len(candidates)} 个闲置后台进程工作集 (保守预计释放 ~{est:.0f} MB)",
                details={
                    "candidate_count": len(candidates),
                    "candidates": [{"pid": p.pid, "name": p.name, "rss_mb": p.rss_mb} for p in candidates[:15]],
                    "trimmed_processes": [],
                },
            )

        if not IS_WINDOWS:
            return ActionResult(
                module_name=self.name,
                status="skipped",
                duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
                summary="非 Windows 系统，跳过工作集修剪",
            )

        enable_privileges(["SeDebugPrivilege", "SeIncreaseQuotaPrivilege"])

        trimmed_records: list[dict[str, Any]] = []
        total_trimmed = 0.0
        access_denied = 0

        for proc in candidates:
            try:
                p_obj = psutil.Process(proc.pid)
                before_mb = round(p_obj.memory_info().rss / (1024.0 * 1024.0), 2)
                ok = empty_process_working_set(proc.pid)
                if not ok:
                    access_denied += 1
                    continue
                after_mb = round(p_obj.memory_info().rss / (1024.0 * 1024.0), 2)
                delta = round(max(0.0, before_mb - after_mb), 2)
                total_trimmed += delta
                trimmed_records.append(
                    {
                        "pid": proc.pid,
                        "name": proc.name,
                        "before_mb": before_mb,
                        "after_mb": after_mb,
                        "trimmed_mb": delta,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                access_denied += 1
                continue

        total_trimmed = round(total_trimmed, 2)
        trimmed_records.sort(key=lambda r: r["trimmed_mb"], reverse=True)

        return ActionResult(
            module_name=self.name,
            status="ok",
            duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
            reclaimed_mb=total_trimmed,
            items_processed=len(trimmed_records),
            summary=(
                f"选择性修剪 {len(trimmed_records)} 个闲置后台进程工作集，共腾出 {total_trimmed:.1f} MB 物理工作集"
                + (f"（跳过受保护/无权限进程 {access_denied} 个）" if access_denied else "")
            ),
            details={
                "profile": profile,
                "min_ws_mb": min_ws_mb,
                "candidate_count": len(candidates),
                "trimmed_count": len(trimmed_records),
                "access_denied_count": access_denied,
                "trimmed_processes": trimmed_records,
            },
        )
