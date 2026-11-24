"""Native NT Memory List optimizer (Modified flush, Physical memory combine, Standby purge)."""

from __future__ import annotations

import time
from typing import Any

from winopt.models import ActionResult
from winopt.optimizers.base import BaseOptimizer, OptimizationContext
from winopt.telemetry import query_windows_perf_counters
from winopt.win32_native import (
    IS_WINDOWS,
    MEMORY_FLUSH_MODIFIED_LIST,
    MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST,
    MEMORY_PURGE_STANDBY_LIST,
    enable_privileges,
    format_ntstatus,
    get_performance_info,
    is_admin,
    nt_combine_physical_memory,
    nt_memory_list_command,
)


class MemoryListsOptimizer(BaseOptimizer):
    name = "memory_lists"

    def run(self, ctx: OptimizationContext) -> ActionResult:
        t_start = time.perf_counter()
        cfg_mem = ctx.config.memory
        standby_mb = ctx.t0.standby_total_mb
        modified_mb = ctx.t0.modified_list_mb
        profile = ctx.guard.profile
        standby_threshold = ctx.policy.standby_purge_min_mb

        details: dict[str, Any] = {
            "profile": profile,
            "standby_before_mb": standby_mb,
            "modified_before_mb": modified_mb,
            "standby_threshold_mb": standby_threshold,
            "steps": [],
        }
        warnings: list[str] = []

        if not IS_WINDOWS:
            return ActionResult(
                module_name=self.name,
                status="skipped",
                duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
                summary="非 Windows 系统，跳过 NT 内存列表优化",
                details=details,
            )

        if ctx.dry_run:
            est_reclaim = 0.0
            planned: list[str] = []
            if cfg_mem.flush_modified_list and profile == "full" and modified_mb >= cfg_mem.modified_flush_min_mb:
                planned.append("MemoryFlushModifiedList")
            if cfg_mem.combine_physical_memory:
                planned.append("MemoryCombinePhysicalMemory")
            if profile == "conservative" and cfg_mem.purge_low_priority_standby_only_in_conservative:
                planned.append("MemoryPurgeLowPriorityStandbyList")
                est_reclaim += round(ctx.t0.standby_reserve_mb + ctx.t0.standby_normal_mb * 0.25, 1)
            elif standby_mb >= standby_threshold:
                planned.append("MemoryPurgeStandbyList")
                est_reclaim += round(standby_mb * 0.85, 1)

            details["planned_commands"] = planned
            return ActionResult(
                module_name=self.name,
                status="dry_run",
                duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
                reclaimed_mb=est_reclaim,
                items_processed=len(planned),
                summary=f"[Dry-Run] 计划执行: {', '.join(planned) if planned else '无需清理'}",
                details=details,
            )

        if not is_admin():
            return ActionResult(
                module_name=self.name,
                status="skipped",
                duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
                summary="未以管理员身份运行，无法执行 NT 内核内存列表清理",
                details=details,
                warnings=["请使用管理员权限运行或通过 HighestAvailable 计划任务执行"],
            )

        privs = enable_privileges(["SeProfileSingleProcessPrivilege"])
        if not privs.get("SeProfileSingleProcessPrivilege"):
            return ActionResult(
                module_name=self.name,
                status="error",
                duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
                summary="无法启用 SeProfileSingleProcessPrivilege 特权",
                details=details,
                warnings=["未能开启 SeProfileSingleProcessPrivilege"],
            )

        perf_before = get_performance_info()
        avail_before_mb = perf_before.get("physical_available_bytes", 0) / (1024.0 * 1024.0)
        steps_executed = 0

        # 1. Flush Modified Page List cleanly before Standby Purge (full mode only)
        if cfg_mem.flush_modified_list and profile == "full" and modified_mb >= cfg_mem.modified_flush_min_mb:
            ok, status = nt_memory_list_command(MEMORY_FLUSH_MODIFIED_LIST)
            details["steps"].append(
                {
                    "command": "MemoryFlushModifiedList",
                    "ok": ok,
                    "ntstatus": format_ntstatus(status),
                }
            )
            if ok:
                steps_executed += 1
            else:
                warnings.append(f"MemoryFlushModifiedList 返回 {format_ntstatus(status)}")

        # 2. Combine identical physical memory pages across processes
        if cfg_mem.combine_physical_memory:
            ok, status, pages_combined = nt_combine_physical_memory()
            combined_mb = round((pages_combined * 4096) / (1024.0 * 1024.0), 2)
            details["steps"].append(
                {
                    "command": "MemoryCombinePhysicalMemory",
                    "ok": ok,
                    "ntstatus": format_ntstatus(status),
                    "pages_combined": pages_combined,
                    "combined_mb": combined_mb,
                }
            )
            if ok:
                steps_executed += 1
            else:
                warnings.append(f"MemoryCombinePhysicalMemory 返回 {format_ntstatus(status)}")

        # 3. Purge Standby List (low-priority only in conservative mode)
        if profile == "conservative" and cfg_mem.purge_low_priority_standby_only_in_conservative:
            if standby_mb >= max(512, standby_threshold // 2):
                ok, status = nt_memory_list_command(MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST)
                details["steps"].append(
                    {
                        "command": "MemoryPurgeLowPriorityStandbyList",
                        "ok": ok,
                        "ntstatus": format_ntstatus(status),
                    }
                )
                if ok:
                    steps_executed += 1
                else:
                    warnings.append(f"MemoryPurgeLowPriorityStandbyList 返回 {format_ntstatus(status)}")
        elif standby_mb >= standby_threshold:
            ok, status = nt_memory_list_command(MEMORY_PURGE_STANDBY_LIST)
            details["steps"].append(
                {
                    "command": "MemoryPurgeStandbyList",
                    "ok": ok,
                    "ntstatus": format_ntstatus(status),
                }
            )
            if ok:
                steps_executed += 1
            else:
                warnings.append(f"MemoryPurgeStandbyList 返回 {format_ntstatus(status)}")
        else:
            details["steps"].append(
                {
                    "command": "MemoryPurgeStandbyList",
                    "ok": True,
                    "skipped_reason": f"Standby ({standby_mb:.0f} MB) < 阈值 ({standby_threshold} MB)",
                }
            )

        perf_after = get_performance_info()
        avail_after_mb = perf_after.get("physical_available_bytes", 0) / (1024.0 * 1024.0)
        counters_after, _ = query_windows_perf_counters(0)
        standby_after_mb = round(
            counters_after["standby_normal_mb"]
            + counters_after["standby_reserve_mb"]
            + counters_after["standby_core_mb"],
            2,
        )
        standby_freed = max(0.0, round(standby_mb - standby_after_mb, 2))
        details["standby_after_mb"] = standby_after_mb
        details["standby_freed_mb"] = standby_freed
        details["available_delta_mb"] = round(avail_after_mb - avail_before_mb, 2)

        return ActionResult(
            module_name=self.name,
            status="ok" if not warnings or steps_executed > 0 else "error",
            duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
            reclaimed_mb=standby_freed,
            items_processed=steps_executed,
            summary=(
                f"执行 {steps_executed} 项内核内存列表操作，Standby 列表释放 {standby_freed:.1f} MB "
                f"({standby_mb:.0f} -> {standby_after_mb:.0f} MB)"
            ),
            details=details,
            warnings=warnings,
        )
