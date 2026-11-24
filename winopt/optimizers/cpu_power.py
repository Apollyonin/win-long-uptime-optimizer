"""CPU power scheme auditor, boost-mode switcher, and safe background updater demoter."""

from __future__ import annotations

import subprocess
import time
from typing import Any

from winopt.models import ActionResult
from winopt.optimizers.base import BaseOptimizer, OptimizationContext
from winopt.win32_native import IS_WINDOWS, set_process_below_normal_priority

HIGH_PERFORMANCE_GUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
BALANCED_GUID = "381b4222-f694-41f0-9685-ff5bb260df2e"


class CpuPowerOptimizer(BaseOptimizer):
    name = "cpu_power"

    def run(self, ctx: OptimizationContext) -> ActionResult:
        t_start = time.perf_counter()
        cfg_cpu = ctx.config.cpu_power
        demote_targets = {p.lower() for p in cfg_cpu.background_demote_processes}
        heavy_pids = set(ctx.guard.active_heavy_pids)

        demoted: list[dict[str, Any]] = []
        warnings: list[str] = []
        plan_switched_to = ""

        # Demote runaway background updaters (only if CPU > 10% and not conservative)
        if ctx.guard.profile == "full":
            for proc in ctx.t0.processes:
                if proc.pid in heavy_pids or proc.pid == ctx.t0.foreground_pid:
                    continue
                if proc.name.lower() in demote_targets and proc.cpu_pct >= 10.0:
                    ok = True if ctx.dry_run else set_process_below_normal_priority(proc.pid)
                    if ok:
                        demoted.append(
                            {
                                "pid": proc.pid,
                                "name": proc.name,
                                "cpu_pct": proc.cpu_pct,
                                "new_priority": "BELOW_NORMAL",
                            }
                        )

        # In explicit boost mode, switch Balanced -> High Performance if requested
        if (
            IS_WINDOWS
            and ctx.mode == "boost"
            and cfg_cpu.switch_high_perf_in_boost_mode
            and ctx.t0.power_plan_guid == BALANCED_GUID
        ):
            if ctx.dry_run:
                plan_switched_to = HIGH_PERFORMANCE_GUID
            else:
                try:
                    res = subprocess.run(
                        ["powercfg", "/setactive", HIGH_PERFORMANCE_GUID],
                        capture_output=True,
                        timeout=5.0,
                        check=False,
                    )
                    if res.returncode == 0:
                        plan_switched_to = HIGH_PERFORMANCE_GUID
                    else:
                        warnings.append("未能切换到高性能电源计划（系统可能隐藏了该电源方案）")
                except Exception as exc:
                    warnings.append(f"电源计划切换失败: {exc}")

        if ctx.t0.dpc_time_pct >= 5.0 or ctx.t0.interrupt_time_pct >= 5.0:
            warnings.append(
                f"系统 DPC/中断占用偏高 (DPC {ctx.t0.dpc_time_pct:.1f}%, 中断 {ctx.t0.interrupt_time_pct:.1f}%)，"
                "可能造成音视频爆音或游戏微卡顿"
            )

        prefix = "[Dry-Run] " if ctx.dry_run else ""
        plan_desc = f"当前电源计划: {ctx.t0.power_plan_name}"
        if plan_switched_to:
            plan_desc += " -> 已切换至高性能方案 (Boost)"

        return ActionResult(
            module_name=self.name,
            status="dry_run" if ctx.dry_run else "ok",
            duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
            reclaimed_mb=0.0,
            items_processed=len(demoted) + (1 if plan_switched_to else 0),
            summary=(
                f"{prefix}{plan_desc}；高占用更新器降优先级 {len(demoted)} 个；"
                f"Timer 分辨率 {ctx.t0.timer_res_current_ms} ms"
            ),
            details={
                "power_plan_guid": ctx.t0.power_plan_guid,
                "power_plan_name": ctx.t0.power_plan_name,
                "plan_switched_to": plan_switched_to,
                "timer_res_current_ms": ctx.t0.timer_res_current_ms,
                "dpc_time_pct": ctx.t0.dpc_time_pct,
                "interrupt_time_pct": ctx.t0.interrupt_time_pct,
                "processor_queue_len": ctx.t0.processor_queue_len,
                "demoted_processes": demoted,
            },
            warnings=warnings,
        )
