"""System, GPU, disk, network, and per-process telemetry collector."""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Any

import psutil

from winopt.config import OptimizerConfig
from winopt.models import DiskTelemetry, GpuTelemetry, ProcessMetric, SystemSnapshot
from winopt.win32_native import (
    IS_WINDOWS,
    get_foreground_pid,
    get_performance_info,
    get_process_gui_resources,
    is_admin,
    query_timer_resolution,
)

_PID_RE = re.compile(r"pid_(\d+)_", re.IGNORECASE)
_GUID_NAME_RE = re.compile(
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*\(([^)]+)\)"
)
_MB = 1024.0 * 1024.0
_GB = 1024.0 * 1024.0 * 1024.0


def _decode_bytes(data: bytes) -> str:
    if not data:
        return ""
    for enc in ("utf-8", "cp936", "mbcs", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _run_cmd(args: list[str], timeout: float = 12.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return (
            proc.returncode,
            _decode_bytes(proc.stdout),
            _decode_bytes(proc.stderr),
        )
    except Exception as exc:
        return (-1, "", str(exc))


def sanitize_vram_bytes(raw_bytes: float, total_gpu_vram_bytes: int) -> tuple[float, bool]:
    """Filter WDDM counter wrap/overflow anomalies.

    Windows GPU Process Memory counters occasionally underflow to multi-terabyte values.
    Returns (sanitized_bytes, is_glitch).
    """
    try:
        val = float(raw_bytes)
    except (TypeError, ValueError):
        return (0.0, True)

    if math.isnan(val) or math.isinf(val) or val < 0.0:
        return (0.0, True)
    if total_gpu_vram_bytes > 0 and val > float(total_gpu_vram_bytes) * 1.15:
        return (0.0, True)
    if val > 128.0 * _GB:
        return (0.0, True)
    return (val, False)


def parse_nvidia_smi_output(text: str) -> GpuTelemetry:
    """Parse CSV output from nvidia-smi --query-gpu=..."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 7:
            continue

        def _num(val: str) -> float:
            try:
                return float(val)
            except ValueError:
                return 0.0

        return GpuTelemetry(
            present=True,
            name=parts[0],
            vram_total_mb=_num(parts[1]),
            vram_used_mb=_num(parts[2]),
            vram_free_mb=_num(parts[3]),
            utilization_gpu_pct=_num(parts[4]),
            temperature_c=_num(parts[5]),
            pstate=parts[6],
        )
    return GpuTelemetry(present=False)


def parse_powercfg_output(text: str) -> tuple[str, str]:
    """Parse GUID and plan name from `powercfg /getactivescheme` across locales."""
    m = _GUID_NAME_RE.search(text or "")
    if not m:
        return ("", "Unknown")
    return (m.group(1).lower(), m.group(2).strip())


def query_gpu_nvidia_smi() -> GpuTelemetry:
    exe = shutil.which("nvidia-smi")
    if not exe and IS_WINDOWS:
        sys_exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "nvidia-smi.exe")
        if os.path.exists(sys_exe):
            exe = sys_exe
    if not exe:
        return GpuTelemetry(present=False)

    rc, out, _ = _run_cmd(
        [
            exe,
            "--query-gpu=name,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu,pstate",
            "--format=csv,noheader,nounits",
        ],
        timeout=6.0,
    )
    if rc != 0:
        return GpuTelemetry(present=False)
    return parse_nvidia_smi_output(out)


def query_active_power_plan() -> tuple[str, str]:
    if not IS_WINDOWS:
        return ("", "Non-Windows")
    rc, out, _ = _run_cmd(["powercfg", "/getactivescheme"], timeout=5.0)
    if rc != 0:
        return ("", "Unknown")
    return parse_powercfg_output(out)


def parse_counter_samples(
    samples: list[dict[str, Any]],
    total_gpu_vram_bytes: int = 0,
) -> dict[str, Any]:
    """Parse Windows Get-Counter sample dicts into structured memory/CPU/GPU counters."""
    parsed: dict[str, Any] = {
        "standby_normal_mb": 0.0,
        "standby_reserve_mb": 0.0,
        "standby_core_mb": 0.0,
        "modified_list_mb": 0.0,
        "dpc_time_pct": 0.0,
        "interrupt_time_pct": 0.0,
        "processor_queue_len": 0.0,
        "gpu_process_vram": {},  # pid -> {"dedicated_mb": float, "shared_mb": float, "glitch": bool}
        "vram_glitch_count": 0,
    }

    gpu_vram: dict[int, dict[str, Any]] = {}
    for item in samples:
        path = str(item.get("Path", "")).lower()
        val = float(item.get("CookedValue", 0.0) or 0.0)

        if "standby cache normal priority bytes" in path:
            parsed["standby_normal_mb"] = round(val / _MB, 2)
        elif "standby cache reserve bytes" in path:
            parsed["standby_reserve_mb"] = round(val / _MB, 2)
        elif "standby cache core bytes" in path:
            parsed["standby_core_mb"] = round(val / _MB, 2)
        elif "modified page list bytes" in path:
            parsed["modified_list_mb"] = round(val / _MB, 2)
        elif "% dpc time" in path:
            parsed["dpc_time_pct"] = round(val, 2)
        elif "% interrupt time" in path:
            parsed["interrupt_time_pct"] = round(val, 2)
        elif "processor queue length" in path:
            parsed["processor_queue_len"] = round(val, 2)
        elif "gpu process memory(" in path:
            m = _PID_RE.search(path)
            if not m:
                continue
            pid = int(m.group(1))
            clean_bytes, is_glitch = sanitize_vram_bytes(val, total_gpu_vram_bytes)
            entry = gpu_vram.setdefault(
                pid, {"dedicated_mb": 0.0, "shared_mb": 0.0, "glitch": False}
            )
            if is_glitch:
                entry["glitch"] = True
                parsed["vram_glitch_count"] += 1
            elif path.endswith("\\dedicated usage"):
                entry["dedicated_mb"] += round(clean_bytes / _MB, 2)
            elif path.endswith("\\shared usage"):
                entry["shared_mb"] += round(clean_bytes / _MB, 2)

    parsed["gpu_process_vram"] = gpu_vram
    return parsed


def query_windows_perf_counters(total_gpu_vram_bytes: int = 0) -> tuple[dict[str, Any], list[str]]:
    """Query Windows memory lists, DPC/interrupt, and GPU process memory via one PowerShell call."""
    if not IS_WINDOWS:
        return (parse_counter_samples([], total_gpu_vram_bytes), [])

    ps_script = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$paths = @("
        "'\\Memory\\Standby Cache Normal Priority Bytes',"
        "'\\Memory\\Standby Cache Reserve Bytes',"
        "'\\Memory\\Standby Cache Core Bytes',"
        "'\\Memory\\Modified Page List Bytes',"
        "'\\Processor(_Total)\\% DPC Time',"
        "'\\Processor(_Total)\\% Interrupt Time',"
        "'\\System\\Processor Queue Length',"
        "'\\GPU Process Memory(*)\\Dedicated Usage',"
        "'\\GPU Process Memory(*)\\Shared Usage'"
        "); "
        "$res = Get-Counter -Counter $paths -ErrorAction SilentlyContinue; "
        "if ($res -and $res.CounterSamples) { "
        "  $res.CounterSamples | Select-Object Path, CookedValue | ConvertTo-Json -Compress "
        "} else { '[]' }"
    )
    rc, out, err = _run_cmd(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
        timeout=15.0,
    )
    notes: list[str] = []
    if rc != 0 and not out.strip():
        notes.append(f"Get-Counter 查询异常 (rc={rc}): {err.strip()[:160]}")
        return (parse_counter_samples([], total_gpu_vram_bytes), notes)

    raw_text = out.strip()
    if not raw_text:
        return (parse_counter_samples([], total_gpu_vram_bytes), notes)

    try:
        data = json.loads(raw_text)
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            data = []
        return (parse_counter_samples(data, total_gpu_vram_bytes), notes)
    except Exception as exc:
        notes.append(f"Get-Counter JSON 解析失败: {exc}")
        return (parse_counter_samples([], total_gpu_vram_bytes), notes)


def collect_disk_telemetry() -> list[DiskTelemetry]:
    disks: list[DiskTelemetry] = []
    seen_mounts: set[str] = set()
    for part in psutil.disk_partitions(all=False):
        if "cdrom" in part.opts.lower() or not part.fstype:
            continue
        mount = part.mountpoint
        if mount in seen_mounts:
            continue
        seen_mounts.add(mount)
        try:
            usage = psutil.disk_usage(mount)
            disks.append(
                DiskTelemetry(
                    drive=mount.rstrip("\\"),
                    total_gb=round(usage.total / _GB, 2),
                    free_gb=round(usage.free / _GB, 2),
                    free_pct=round(100.0 - usage.percent, 2),
                )
            )
        except Exception:
            continue
    return disks


def collect_tcp_counts() -> dict[str, int]:
    counts: dict[str, int] = {"TOTAL": 0, "ESTABLISHED": 0, "TIME_WAIT": 0, "CLOSE_WAIT": 0}
    try:
        conns = psutil.net_connections(kind="tcp")
        counts["TOTAL"] = len(conns)
        for c in conns:
            st = str(c.status)
            if st in counts:
                counts[st] += 1
    except Exception:
        pass
    return counts


def _sample_process_cpu_baseline() -> tuple[float, dict[int, float]]:
    t0 = time.perf_counter()
    cpu_map: dict[int, float] = {}
    for p in psutil.process_iter(["pid"]):
        try:
            ct = p.cpu_times()
            cpu_map[p.pid] = float(ct.user + ct.system)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return (t0, cpu_map)


def collect_snapshot(
    cfg: OptimizerConfig | None = None,
    include_processes: bool = True,
) -> SystemSnapshot:
    """Capture a complete point-in-time system and process telemetry snapshot."""
    del cfg  # reserved for future drive/filter configuration
    notes: list[str] = []

    # Step 1: Prime per-process CPU baseline & system CPU % before PowerShell wait
    t_cpu_0, cpu_times_0 = (0.0, {})
    if include_processes:
        t_cpu_0, cpu_times_0 = _sample_process_cpu_baseline()

    psutil.cpu_percent(interval=None)
    gpu = query_gpu_nvidia_smi()
    total_vram_bytes = int(gpu.vram_total_mb * _MB) if gpu.present else 0
    counters, counter_notes = query_windows_perf_counters(total_vram_bytes)
    notes.extend(counter_notes)

    cpu_pct = float(psutil.cpu_percent(interval=0.2 if not include_processes else None))
    if include_processes and cpu_pct == 0.0:
        cpu_pct = float(psutil.cpu_percent(interval=0.1))

    perf = get_performance_info()
    vm = psutil.virtual_memory()
    uptime_hours = round(max(0.0, (time.time() - psutil.boot_time()) / 3600.0), 2)
    timer_info = query_timer_resolution()
    plan_guid, plan_name = query_active_power_plan()
    fg_pid = get_foreground_pid()

    total_ram_mb = round((perf.get("physical_total_bytes") or vm.total) / _MB, 2)
    available_ram_mb = round((perf.get("physical_available_bytes") or vm.available) / _MB, 2)
    ram_used_pct = round(
        ((total_ram_mb - available_ram_mb) / total_ram_mb * 100.0) if total_ram_mb > 0 else vm.percent,
        2,
    )

    commit_total_mb = round(perf.get("commit_total_bytes", 0) / _MB, 2)
    commit_limit_mb = round(perf.get("commit_limit_bytes", 0) / _MB, 2)
    commit_pct = round(
        (commit_total_mb / commit_limit_mb * 100.0) if commit_limit_mb > 0 else 0.0, 2
    )

    standby_normal = float(counters["standby_normal_mb"])
    standby_reserve = float(counters["standby_reserve_mb"])
    standby_core = float(counters["standby_core_mb"])
    standby_total = round(standby_normal + standby_reserve + standby_core, 2)

    processes: list[ProcessMetric] = []
    fg_name = ""
    if include_processes:
        t_cpu_1 = time.perf_counter()
        dt = max(0.05, t_cpu_1 - t_cpu_0)
        logical_cpus = psutil.cpu_count(logical=True) or 1
        gpu_proc_vram: dict[int, dict[str, Any]] = counters["gpu_process_vram"]

        for p in psutil.process_iter(["pid", "name", "exe", "create_time", "num_threads"]):
            try:
                info = p.info
                pid = int(info["pid"])
                name = str(info.get("name") or "")
                if pid == fg_pid:
                    fg_name = name

                mem = p.memory_info()
                rss_mb = round(mem.rss / _MB, 2)
                private_mb = round(getattr(mem, "private", mem.rss) / _MB, 2)
                try:
                    handles = int(p.num_handles())
                except Exception:
                    handles = 0

                gdi_obj, user_obj = get_process_gui_resources(pid)

                ct = p.cpu_times()
                c_total = float(ct.user + ct.system)
                prev_c = cpu_times_0.get(pid)
                proc_cpu_pct = 0.0
                if prev_c is not None and c_total >= prev_c:
                    proc_cpu_pct = round(
                        min(100.0, ((c_total - prev_c) / (dt * logical_cpus)) * 100.0), 2
                    )

                v_info = gpu_proc_vram.get(pid, {})
                processes.append(
                    ProcessMetric(
                        pid=pid,
                        name=name,
                        exe=str(info.get("exe") or ""),
                        create_time=float(info.get("create_time") or 0.0),
                        rss_mb=rss_mb,
                        private_mb=private_mb,
                        handles=handles,
                        gdi_objects=gdi_obj,
                        user_objects=user_obj,
                        vram_dedicated_mb=round(float(v_info.get("dedicated_mb", 0.0)), 2),
                        vram_shared_mb=round(float(v_info.get("shared_mb", 0.0)), 2),
                        vram_glitch=bool(v_info.get("glitch", False)),
                        cpu_pct=proc_cpu_pct,
                        threads=int(info.get("num_threads") or 0),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue

    return SystemSnapshot(
        captured_at=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        uptime_hours=uptime_hours,
        is_admin=is_admin(),
        cpu_pct=round(cpu_pct, 2),
        dpc_time_pct=float(counters["dpc_time_pct"]),
        interrupt_time_pct=float(counters["interrupt_time_pct"]),
        processor_queue_len=float(counters["processor_queue_len"]),
        timer_res_current_ms=float(timer_info.get("current_ms", 0.0)),
        timer_res_min_ms=float(timer_info.get("min_ms", 0.0)),
        timer_res_max_ms=float(timer_info.get("max_ms", 0.0)),
        power_plan_guid=plan_guid,
        power_plan_name=plan_name,
        total_ram_mb=total_ram_mb,
        available_ram_mb=available_ram_mb,
        ram_used_pct=ram_used_pct,
        standby_normal_mb=standby_normal,
        standby_reserve_mb=standby_reserve,
        standby_core_mb=standby_core,
        standby_total_mb=standby_total,
        modified_list_mb=float(counters["modified_list_mb"]),
        commit_total_mb=commit_total_mb,
        commit_limit_mb=commit_limit_mb,
        commit_pct=commit_pct,
        kernel_nonpaged_mb=round(perf.get("kernel_nonpaged_bytes", 0) / _MB, 2),
        kernel_paged_mb=round(perf.get("kernel_paged_bytes", 0) / _MB, 2),
        system_cache_mb=round(perf.get("system_cache_bytes", 0) / _MB, 2),
        total_handles=int(perf.get("handle_count", 0)),
        total_processes=int(perf.get("process_count", len(processes))),
        total_threads=int(perf.get("thread_count", 0)),
        foreground_pid=fg_pid,
        foreground_name=fg_name,
        gpu=gpu,
        disks=collect_disk_telemetry(),
        tcp_counts=collect_tcp_counts(),
        vram_glitch_count=int(counters["vram_glitch_count"]),
        processes=processes,
        notes=notes,
    )
