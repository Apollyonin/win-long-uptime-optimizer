"""Test factory helpers for synthetic snapshots and configurations."""

from __future__ import annotations

from pathlib import Path

from winopt.config import OptimizerConfig, load_config
from winopt.models import (
    BenchmarkResult,
    DiskTelemetry,
    GpuTelemetry,
    ProcessMetric,
    SystemSnapshot,
)


def make_test_config(tmp_dir: Path) -> OptimizerConfig:
    return load_config(
        workspace_dir=Path(__file__).resolve().parent.parent,
        data_dir=tmp_dir / "data",
        reports_dir=tmp_dir / "reports",
    )


def make_snapshot(
    captured_at: str = "2026-11-24T08:00:00-05:00",
    uptime_hours: float = 120.0,
    cpu_pct: float = 8.0,
    available_ram_mb: float = 12000.0,
    total_ram_mb: float = 32768.0,
    standby_total_mb: float = 4000.0,
    modified_list_mb: float = 120.0,
    commit_total_mb: float = 28000.0,
    commit_limit_mb: float = 65536.0,
    kernel_nonpaged_mb: float = 600.0,
    gpu_used_mb: float = 1500.0,
    gpu_total_mb: float = 8188.0,
    gpu_util_pct: float = 5.0,
    processes: list[ProcessMetric] | None = None,
    foreground_pid: int | None = None,
    free_disk_pct: float = 40.0,
) -> SystemSnapshot:
    commit_pct = round(commit_total_mb / commit_limit_mb * 100.0, 2) if commit_limit_mb else 0.0
    ram_used_pct = round((total_ram_mb - available_ram_mb) / total_ram_mb * 100.0, 2)
    return SystemSnapshot(
        captured_at=captured_at,
        uptime_hours=uptime_hours,
        is_admin=True,
        cpu_pct=cpu_pct,
        dpc_time_pct=0.2,
        interrupt_time_pct=0.1,
        processor_queue_len=0.0,
        timer_res_current_ms=1.0,
        timer_res_min_ms=15.625,
        timer_res_max_ms=0.5,
        power_plan_guid="381b4222-f694-41f0-9685-ff5bb260df2e",
        power_plan_name="平衡",
        total_ram_mb=total_ram_mb,
        available_ram_mb=available_ram_mb,
        ram_used_pct=ram_used_pct,
        standby_normal_mb=standby_total_mb * 0.8,
        standby_reserve_mb=standby_total_mb * 0.15,
        standby_core_mb=standby_total_mb * 0.05,
        standby_total_mb=standby_total_mb,
        modified_list_mb=modified_list_mb,
        commit_total_mb=commit_total_mb,
        commit_limit_mb=commit_limit_mb,
        commit_pct=commit_pct,
        kernel_nonpaged_mb=kernel_nonpaged_mb,
        kernel_paged_mb=900.0,
        system_cache_mb=2000.0,
        total_handles=120000,
        total_processes=220,
        total_threads=3400,
        foreground_pid=foreground_pid,
        foreground_name="",
        gpu=GpuTelemetry(
            present=True,
            name="NVIDIA GeForce RTX 4060 Ti",
            vram_total_mb=gpu_total_mb,
            vram_used_mb=gpu_used_mb,
            vram_free_mb=max(0.0, gpu_total_mb - gpu_used_mb),
            utilization_gpu_pct=gpu_util_pct,
            temperature_c=45.0,
            pstate="P8",
        ),
        disks=[DiskTelemetry(drive="C:", total_gb=500.0, free_gb=500.0 * free_disk_pct / 100.0, free_pct=free_disk_pct)],
        tcp_counts={"TOTAL": 120, "ESTABLISHED": 45, "TIME_WAIT": 10, "CLOSE_WAIT": 2},
        vram_glitch_count=0,
        processes=processes or [],
    )


def make_benchmark(
    alloc_ms: float = 55.0,
    jitter_p95_ms: float = 1.8,
    disk_total_ms: float = 18.0,
) -> BenchmarkResult:
    return BenchmarkResult(
        captured_at="2026-11-24T08:00:05-05:00",
        alloc_touch_mb=128,
        alloc_touch_ms=alloc_ms,
        alloc_throughput_gbps=round(0.125 / max(0.001, alloc_ms / 1000.0), 3),
        jitter_iterations=40,
        jitter_p50_ms=0.8,
        jitter_p95_ms=jitter_p95_ms,
        jitter_p99_ms=jitter_p95_ms * 1.2,
        jitter_max_ms=jitter_p95_ms * 1.5,
        disk_write_ms=disk_total_ms * 0.7,
        disk_read_ms=disk_total_ms * 0.3,
        disk_total_ms=disk_total_ms,
    )
