"""Effectiveness evaluator (T0/T1/T2 deltas, rebound check) and Gap Analyzer (查漏补缺)."""

from __future__ import annotations

import os
from typing import Any

from winopt.config import OptimizerConfig
from winopt.models import (
    ActionResult,
    BenchmarkResult,
    EvaluationReport,
    GapFinding,
    LeakEvent,
    ReboundItem,
    ScoreBreakdown,
    SystemSnapshot,
)


def compute_readiness_score(
    snap: SystemSnapshot,
    bench: BenchmarkResult | None,
    cfg: OptimizerConfig,
    leaks: list[LeakEvent] | None = None,
) -> ScoreBreakdown:
    """Compute Heavy-App Readiness Score (0-100) from memory, alloc speed, GPU, hygiene, and storage."""
    # 1. Memory Headroom (30 pts)
    avail_pct = (snap.available_ram_mb / snap.total_ram_mb * 100.0) if snap.total_ram_mb > 0 else 0.0
    avail_pts = max(0.0, min(15.0, (avail_pct / 45.0) * 15.0))
    commit_pts = max(0.0, min(15.0, ((95.0 - snap.commit_pct) / 40.0) * 15.0))
    memory_headroom = round(avail_pts + commit_pts, 2)

    # 2. Standby Hygiene & Page Allocation Speed (25 pts)
    standby_pct = (snap.standby_total_mb / snap.total_ram_mb * 100.0) if snap.total_ram_mb > 0 else 0.0
    standby_pts = max(2.0, min(12.0, 12.0 - max(0.0, standby_pct - 8.0) / 27.0 * 10.0))
    if bench is not None and bench.alloc_touch_ms > 0:
        alloc_pts = max(2.0, min(13.0, 13.0 - max(0.0, bench.alloc_touch_ms - 60.0) / 240.0 * 11.0))
    else:
        alloc_pts = 10.0
    standby_and_alloc = round(standby_pts + alloc_pts, 2)

    # 3. GPU Readiness (20 pts)
    dwm_vram = sum(
        p.vram_dedicated_mb
        for p in snap.processes
        if not p.vram_glitch and p.name.lower() == "dwm.exe"
    )
    if snap.gpu.present and snap.gpu.vram_total_mb > 0:
        free_vram_pct = snap.gpu.vram_free_mb / snap.gpu.vram_total_mb * 100.0
        vram_pts = max(2.0, min(16.0, ((free_vram_pct - 10.0) / 65.0) * 14.0 + 2.0))
        dwm_warn = cfg.gpu.dwm_vram_warn_mb
        if dwm_vram <= dwm_warn:
            dwm_pts = 4.0
        elif dwm_vram <= dwm_warn * 2:
            dwm_pts = 2.0
        else:
            dwm_pts = 0.0
        gpu_readiness = round(vram_pts + dwm_pts, 2)
    else:
        gpu_readiness = 16.0

    # 4. System Hygiene & Latency (15 pts)
    hygiene = 15.0
    if snap.kernel_nonpaged_mb > 1000.0:
        hygiene -= min(5.0, (snap.kernel_nonpaged_mb - 1000.0) / 800.0 * 5.0)
    if bench is not None and bench.jitter_p95_ms > 2.5:
        hygiene -= min(4.0, (bench.jitter_p95_ms - 2.5) / 10.0 * 4.0)
    if (snap.dpc_time_pct + snap.interrupt_time_pct) > 2.0:
        hygiene -= min(3.0, (snap.dpc_time_pct + snap.interrupt_time_pct - 2.0) * 0.5)
    if leaks:
        leak_penalty = sum(2.5 if lk.severity == "CRITICAL" else (1.0 if lk.severity == "WARN" else 0.0) for lk in leaks)
        hygiene -= min(5.0, leak_penalty)
    system_hygiene = round(max(0.0, min(15.0, hygiene)), 2)

    # 5. Storage & Power (10 pts)
    sys_drive = (os.environ.get("SystemDrive", "C:") or "C:").rstrip("\\").lower()
    sys_free_pct = 25.0
    for d in snap.disks:
        if d.drive.rstrip("\\").lower() == sys_drive:
            sys_free_pct = d.free_pct
            break
    disk_pts = max(0.0, min(6.0, ((sys_free_pct - 5.0) / 20.0) * 6.0))
    plan_l = snap.power_plan_name.lower()
    if "saver" in plan_l or "节能" in plan_l:
        power_pts = 1.0
    elif bench is not None and bench.disk_total_ms > 150.0:
        power_pts = 2.5
    else:
        power_pts = 4.0
    storage_and_power = round(disk_pts + power_pts, 2)

    total = round(
        memory_headroom + standby_and_alloc + gpu_readiness + system_hygiene + storage_and_power,
        2,
    )
    return ScoreBreakdown(
        total=total,
        memory_headroom=memory_headroom,
        standby_and_alloc=standby_and_alloc,
        gpu_readiness=gpu_readiness,
        system_hygiene=system_hygiene,
        storage_and_power=storage_and_power,
    )


def analyze_rebound(
    module_results: list[ActionResult],
    t2: SystemSnapshot,
    rebound_threshold_ratio: float,
) -> tuple[float, float, float, list[ReboundItem], list[ReboundItem]]:
    """Measure how much trimmed working set rebounded by T2."""
    ws_mod = next((m for m in module_results if m.module_name == "working_set"), None)
    if ws_mod is None:
        return (0.0, 0.0, 0.0, [], [])

    trimmed_list: list[dict[str, Any]] = ws_mod.details.get("trimmed_processes", [])
    if not trimmed_list:
        return (0.0, 0.0, 0.0, [], [])

    t2_by_pid = {p.pid: p for p in t2.processes}
    trimmed_total = 0.0
    rebound_total = 0.0
    rebounders: list[ReboundItem] = []
    non_rebounders: list[ReboundItem] = []

    for rec in trimmed_list:
        trimmed_mb = float(rec.get("trimmed_mb", 0.0))
        if trimmed_mb < 10.0:
            continue
        pid = int(rec["pid"])
        after_mb = float(rec.get("after_trim_mb", rec.get("after_mb", 0.0)))
        before_mb = float(rec.get("before_mb", after_mb + trimmed_mb))
        t2_proc = t2_by_pid.get(pid)
        if t2_proc is None:
            continue
        settled_mb = t2_proc.rss_mb
        rebound_mb = round(max(0.0, settled_mb - after_mb), 2)
        # Cap rebound ratio at 1.5 to avoid noise on tiny trims
        ratio = round(min(1.5, rebound_mb / trimmed_mb), 3) if trimmed_mb > 0 else 0.0

        trimmed_total += trimmed_mb
        rebound_total += min(trimmed_mb, rebound_mb)
        item = ReboundItem(
            pid=pid,
            name=str(rec["name"]),
            before_mb=before_mb,
            after_trim_mb=after_mb,
            settled_mb=settled_mb,
            trimmed_mb=trimmed_mb,
            rebound_mb=rebound_mb,
            rebound_ratio=ratio,
        )
        if ratio >= rebound_threshold_ratio:
            rebounders.append(item)
        else:
            non_rebounders.append(item)

    overall_ratio = round((rebound_total / trimmed_total), 3) if trimmed_total > 0 else 0.0
    rebounders.sort(key=lambda x: x.rebound_mb, reverse=True)
    non_rebounders.sort(key=lambda x: x.trimmed_mb - x.rebound_mb, reverse=True)
    return (
        round(trimmed_total, 2),
        round(rebound_total, 2),
        overall_ratio,
        rebounders,
        non_rebounders,
    )


def analyze_gaps(
    t2: SystemSnapshot,
    bench_t1: BenchmarkResult | None,
    module_results: list[ActionResult],
    leaks: list[LeakEvent],
    rebounders: list[ReboundItem],
    cfg: OptimizerConfig,
) -> list[GapFinding]:
    """Identify remaining post-optimization bottlenecks (查漏补缺) that automation alone cannot erase."""
    gaps: list[GapFinding] = []

    # 1. Residual Commit Charge pressure (working-set trimming CANNOT reduce Private Commit!)
    if t2.commit_pct >= cfg.leak_detection.commit_pct_warn:
        top_commit = sorted(t2.processes, key=lambda p: p.private_mb, reverse=True)[:5]
        top_desc = ", ".join(f"{p.name} ({p.private_mb:.0f} MB)" for p in top_commit)
        gaps.append(
            GapFinding(
                severity="CRITICAL" if t2.commit_pct >= cfg.leak_detection.commit_pct_crit else "WARN",
                code="HIGH_COMMIT_RESIDUAL",
                title="优化后系统提交内存 (Commit Charge) 依然偏高",
                description=(
                    f"清理后 Commit 占比仍达 {t2.commit_pct:.1f}% ({t2.commit_total_mb:.0f}/{t2.commit_limit_mb:.0f} MB)。"
                    f"工作集修剪仅调整物理驻留集，无法释放进程私有提交内存。当前私有内存最高进程: {top_desc}"
                ),
                metric_value=f"{t2.commit_pct:.1f}%",
                recommendation="开启工程模拟软件或大型游戏前，建议关闭/重启上述高私有内存驻留应用，或适当增大虚拟内存页面文件上限。",
                auto_action_taken="已记录高频私有提交进程快照用于跨周期泄漏追踪",
            )
        )

    # 2. GPU VRAM occupancy & DWM bloat
    if t2.gpu.present and t2.gpu.vram_total_mb > 0:
        used_pct = (t2.gpu.vram_used_mb / t2.gpu.vram_total_mb) * 100.0
        dwm_vram = sum(
            p.vram_dedicated_mb
            for p in t2.processes
            if not p.vram_glitch and p.name.lower() == "dwm.exe"
        )
        non_sys_hogs = sorted(
            [
                p
                for p in t2.processes
                if not p.vram_glitch
                and p.vram_dedicated_mb >= 120.0
                and p.name.lower() not in {"dwm.exe", "csrss.exe", "system"}
            ],
            key=lambda p: p.vram_dedicated_mb,
            reverse=True,
        )[:5]

        if dwm_vram >= cfg.gpu.dwm_vram_warn_mb:
            gaps.append(
                GapFinding(
                    severity="WARN",
                    code="DWM_VRAM_LEAK",
                    title="桌面窗口管理器 (dwm.exe) 长期运行显存偏高",
                    description=(
                        f"dwm.exe 当前占用专用显存 {dwm_vram:.0f} MB (阈值 {cfg.gpu.dwm_vram_warn_mb:.0f} MB)，"
                        "系 Windows 长时间不重启常见合成器显存累积现象。"
                    ),
                    metric_value=f"{dwm_vram:.0f} MB",
                    recommendation="若准备游玩高画质游戏或运行 GPU 仿真/渲染，建议找空闲窗口重启电脑或注销重新登录以彻底重置 dwm 显存。",
                    auto_action_taken="已将其列入显存监控告警，避免误杀导致桌面崩溃",
                )
            )

        if used_pct >= 38.0 and non_sys_hogs:
            hog_desc = ", ".join(f"{p.name} ({p.vram_dedicated_mb:.0f} MB)" for p in non_sys_hogs)
            reclaimable = sum(p.vram_dedicated_mb for p in non_sys_hogs)
            gaps.append(
                GapFinding(
                    severity="WARN" if used_pct >= 50.0 else "INFO",
                    code="HIGH_VRAM_OCCUPANCY",
                    title="后台桌面软件占用较多独立显存",
                    description=(
                        f"优化后 {t2.gpu.name} 显存仍占用 {t2.gpu.vram_used_mb:.0f}/{t2.gpu.vram_total_mb:.0f} MB ({used_pct:.1f}%)。"
                        f"主要非核心后台显存大户: {hog_desc}"
                    ),
                    metric_value=f"{t2.gpu.vram_used_mb:.0f} MB ({used_pct:.1f}%)",
                    recommendation=f"启动大型游戏或仿真软件前关闭上述后台软件（如动态壁纸/多余浏览器窗口）可立刻释放约 {reclaimable:.0f} MB 显存。",
                )
            )

    # 3. Working set rebounders
    if rebounders:
        rb_desc = ", ".join(f"{r.name} (回弹 {r.rebound_ratio*100:.0f}%)" for r in rebounders[:5])
        gaps.append(
            GapFinding(
                severity="INFO",
                code="TRIM_REBOUNDERS",
                title="部分后台进程修剪工作集后快速回弹",
                description=f"以下进程在稳定观察期内快速把被修剪的内存重新换回物理内存: {rb_desc}",
                metric_value=f"{len(rebounders)} 个进程",
                recommendation="此类进程正在后台活跃使用内存，重复修剪只会增加软页错误开销。",
                auto_action_taken="自迭代引擎将累加其回弹计数，连续达标后自动移出修剪名单",
            )
        )

    # 4. Kernel Nonpaged Pool bloat & long uptime advisory
    if t2.kernel_nonpaged_mb >= cfg.leak_detection.nonpaged_pool_warn_mb:
        gaps.append(
            GapFinding(
                severity="WARN",
                code="KERNEL_POOL_BLOAT",
                title="内核非分页池 (Nonpaged Pool) 占用偏高",
                description=(
                    f"当前非分页池达 {t2.kernel_nonpaged_mb:.0f} MB (通常健康机器为 300-800 MB)，"
                    "内核池无法被用户态或 Standby 清理工具释放。"
                ),
                metric_value=f"{t2.kernel_nonpaged_mb:.0f} MB",
                recommendation="若持续高于 1500 MB 且已连续运行多天，建议安排一次系统重启并检查远程桌面虚拟显示/杀毒/网卡驱动。",
            )
        )

    if t2.uptime_hours >= 240.0 and (
        t2.commit_pct >= cfg.leak_detection.commit_pct_warn
        or t2.kernel_nonpaged_mb >= cfg.leak_detection.nonpaged_pool_warn_mb
    ):
        gaps.append(
            GapFinding(
                severity="INFO",
                code="LONG_UPTIME_ADVISORY",
                title="系统已连续运行超过 10 天且存在不可自动回收的内核/提交累积",
                description=f"当前连续开机 {t2.uptime_hours / 24.0:.1f} 天 ({t2.uptime_hours:.1f} 小时)。",
                metric_value=f"{t2.uptime_hours / 24.0:.1f} 天",
                recommendation="尽管本工具可清理 Standby 与后台工作集，仍建议每 2-3 周在业务空闲期重启一次以重置内核池和 WDDM 显存。",
            )
        )

    # 5. Micro-benchmark anomalies
    if bench_t1 is not None:
        if bench_t1.alloc_touch_ms >= 180.0:
            gaps.append(
                GapFinding(
                    severity="WARN",
                    code="ALLOC_LATENCY_HIGH",
                    title="优化后大页分配接触耗时依然偏高",
                    description=f"分配并写入 {bench_t1.alloc_touch_mb} MB 耗时 {bench_t1.alloc_touch_ms:.1f} ms ({bench_t1.alloc_throughput_gbps:.2f} GB/s)。",
                    metric_value=f"{bench_t1.alloc_touch_ms:.1f} ms",
                    recommendation="可能由于可用物理内存仍然紧张或后台存在高内存压力任务，启动重负载软件前建议关闭高占用进程。",
                )
            )
        if bench_t1.jitter_p95_ms >= 10.0:
            gaps.append(
                GapFinding(
                    severity="WARN",
                    code="SCHEDULER_JITTER_HIGH",
                    title="系统调度定时器抖动 (P95) 偏高",
                    description=f"5ms 定时唤醒 P95 超调抖动达 {bench_t1.jitter_p95_ms:.2f} ms (最大值 {bench_t1.jitter_max_ms:.2f} ms)。",
                    metric_value=f"{bench_t1.jitter_p95_ms:.2f} ms",
                    recommendation="检查系统是否处于节能电源计划，或排查高 DPC 延迟驱动与重负载后台下载/杀毒扫描。",
                )
            )

    # 6. Disk free space low
    sys_drive = (os.environ.get("SystemDrive", "C:") or "C:").rstrip("\\").lower()
    for d in t2.disks:
        if d.drive.rstrip("\\").lower() == sys_drive and d.free_pct < cfg.storage.min_free_disk_pct:
            gaps.append(
                GapFinding(
                    severity="WARN",
                    code="LOW_DISK_HEADROOM",
                    title=f"系统盘 ({d.drive}) 剩余空间不足",
                    description=f"系统盘仅剩 {d.free_gb:.1f} GB ({d.free_pct:.1f}%)，可能影响页面文件扩容、着色器缓存及 SSD 写入性能。",
                    metric_value=f"{d.free_gb:.1f} GB ({d.free_pct:.1f}%)",
                    recommendation="建议清理大型安装包、休眠文件或将工程缓存目录迁移至非系统盘，保持至少 15%-20% 剩余空间。",
                )
            )

    # 7. Module errors / missing privileges
    for mod in module_results:
        if mod.status == "error" or (mod.status == "skipped" and mod.warnings):
            gaps.append(
                GapFinding(
                    severity="WARN",
                    code="MODULE_ERROR_OR_PRIVILEGE",
                    title=f"优化模块 {mod.module_name} 未能完整执行",
                    description=mod.summary,
                    metric_value=mod.status,
                    recommendation="; ".join(mod.warnings) if mod.warnings else "请确认以管理员权限运行本工具。",
                )
            )

    # 8. Summarize active critical/warn process leaks if not already covered
    proc_leaks = [lk for lk in leaks if lk.pid > 0 and lk.severity in ("WARN", "CRITICAL")]
    if proc_leaks:
        top_lk = ", ".join(f"{lk.process_name}({lk.category})" for lk in proc_leaks[:4])
        gaps.append(
            GapFinding(
                severity="WARN",
                code="CHRONIC_LEAKERS",
                title="发现潜在进程级资源泄漏或异常驻留",
                description=f"共检出 {len(proc_leaks)} 项进程异常: {top_lk}",
                metric_value=f"{len(proc_leaks)} 项",
                recommendation="详见下方“内存与资源泄漏追踪表”，建议针对告警进程按需重启释放资源。",
            )
        )

    sev_order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    gaps.sort(key=lambda g: sev_order.get(g.severity, 9))
    return gaps


def evaluate_run(
    t0: SystemSnapshot,
    t1: SystemSnapshot | None,
    t2: SystemSnapshot,
    bench_t0: BenchmarkResult | None,
    bench_t1: BenchmarkResult | None,
    module_results: list[ActionResult],
    leaks: list[LeakEvent],
    cfg: OptimizerConfig,
    leaks_t0: list[LeakEvent] | None = None,
) -> EvaluationReport:
    """Evaluate optimization effectiveness across T0 -> T1 -> T2 and produce Gap Analysis."""
    t0_leaks = leaks if leaks_t0 is None else leaks_t0
    score_t0 = compute_readiness_score(t0, bench_t0, cfg, leaks=t0_leaks)
    score_t1 = compute_readiness_score(t1, bench_t1, cfg, leaks=leaks) if t1 is not None else None
    score_t2 = compute_readiness_score(t2, bench_t1, cfg, leaks=leaks)

    trimmed_total, rebound_total, rebound_ratio, rebounders, non_rebounders = analyze_rebound(
        module_results, t2, cfg.verification.rebound_threshold_ratio
    )
    gaps = analyze_gaps(t2, bench_t1, module_results, leaks, rebounders, cfg)

    net_avail_delta = round(t2.available_ram_mb - t0.available_ram_mb, 2)
    net_standby_delta = round(t2.standby_total_mb - t0.standby_total_mb, 2)
    net_commit_delta = round(t2.commit_pct - t0.commit_pct, 2)
    alloc_delta = (
        round(bench_t1.alloc_touch_ms - bench_t0.alloc_touch_ms, 2)
        if (bench_t0 is not None and bench_t1 is not None)
        else None
    )
    jitter_delta = (
        round(bench_t1.jitter_p95_ms - bench_t0.jitter_p95_ms, 3)
        if (bench_t0 is not None and bench_t1 is not None)
        else None
    )

    score_gain = round(score_t2.total - score_t0.total, 2)
    if score_gain >= 3.0 or net_avail_delta >= 500.0:
        verdict = f"效果显著：就绪度评分提升 {score_gain:+.1f} 分，净释放可用物理内存 {net_avail_delta:+.0f} MB"
    elif score_gain >= 0.0 and net_avail_delta >= 0.0:
        verdict = f"平稳有效：就绪度评分变化 {score_gain:+.1f} 分，系统保持高就绪状态"
    else:
        verdict = f"受限/回弹：就绪度评分变化 {score_gain:+.1f} 分，建议查看查漏补缺项"

    return EvaluationReport(
        score_t0=score_t0,
        score_t1=score_t1,
        score_t2=score_t2,
        net_available_ram_delta_mb=net_avail_delta,
        net_standby_delta_mb=net_standby_delta,
        net_commit_delta_pct=net_commit_delta,
        alloc_latency_delta_ms=alloc_delta,
        jitter_p95_delta_ms=jitter_delta,
        trimmed_total_mb=trimmed_total,
        rebound_total_mb=rebound_total,
        overall_rebound_ratio=rebound_ratio,
        rebounders=rebounders,
        non_rebounders=non_rebounders,
        gaps=gaps,
        verdict=verdict,
    )
