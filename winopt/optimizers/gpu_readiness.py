"""GPU VRAM readiness auditor and stale shader temp cleaner."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from winopt.models import ActionResult
from winopt.optimizers.base import BaseOptimizer, OptimizationContext

_CRITICAL_SYSTEM_GPU = {
    "system",
    "dwm.exe",
    "csrss.exe",
    "explorer.exe",
    "startmenuexperiencehost.exe",
    "searchhost.exe",
    "textinputhost.exe",
    "shellexperiencehost.exe",
}


class GpuReadinessOptimizer(BaseOptimizer):
    name = "gpu_readiness"

    def run(self, ctx: OptimizationContext) -> ActionResult:
        t_start = time.perf_counter()
        gpu_cfg = ctx.config.gpu
        heavy_pids = set(ctx.guard.active_heavy_pids)

        # Audit VRAM hogs (excluding glitch counters)
        vram_hogs: list[dict[str, Any]] = []
        reclaimable_user_vram_mb = 0.0
        dwm_vram_mb = 0.0

        for proc in ctx.t0.processes:
            if proc.vram_glitch or proc.vram_dedicated_mb <= 0:
                continue
            lname = proc.name.lower()
            if lname == "dwm.exe":
                dwm_vram_mb = round(dwm_vram_mb + proc.vram_dedicated_mb, 2)
            if proc.pid not in heavy_pids and lname not in _CRITICAL_SYSTEM_GPU:
                if proc.vram_dedicated_mb >= 64.0:
                    reclaimable_user_vram_mb += proc.vram_dedicated_mb
            if proc.vram_dedicated_mb >= gpu_cfg.vram_hog_warn_mb or (
                lname == "dwm.exe" and proc.vram_dedicated_mb >= gpu_cfg.dwm_vram_warn_mb
            ):
                vram_hogs.append(
                    {
                        "pid": proc.pid,
                        "name": proc.name,
                        "vram_dedicated_mb": proc.vram_dedicated_mb,
                        "vram_shared_mb": proc.vram_shared_mb,
                        "is_system": lname in _CRITICAL_SYSTEM_GPU,
                    }
                )

        vram_hogs.sort(key=lambda x: x["vram_dedicated_mb"], reverse=True)
        reclaimable_user_vram_mb = round(reclaimable_user_vram_mb, 2)

        # Clean only safe aged Windows D3DSCache temp files (> max_age_days);
        # audit vendor DXCache/GLCache without deleting to avoid game shader compilation stutter!
        cleaned_mb = 0.0
        cleaned_files = 0
        vendor_cache_mb = 0.0
        local_app = os.environ.get("LOCALAPPDATA", "")

        if local_app:
            for vd in (
                Path(local_app) / "NVIDIA" / "DXCache",
                Path(local_app) / "NVIDIA" / "GLCache",
                Path(local_app) / "AMD" / "DxCache",
            ):
                if vd.exists() and vd.is_dir():
                    for root, _, files in os.walk(vd):
                        for fn in files:
                            try:
                                vendor_cache_mb += (Path(root) / fn).stat().st_size / (1024.0 * 1024.0)
                            except OSError:
                                continue

        if gpu_cfg.clean_stale_shader_temp and ctx.guard.profile == "full" and local_app:
            d3d_dir = Path(local_app) / "D3DSCache"
            cutoff = time.time() - (max(30, gpu_cfg.shader_temp_max_age_days) * 86400.0)
            if d3d_dir.exists() and d3d_dir.is_dir():
                for root, _, files in os.walk(d3d_dir):
                    for fn in files:
                        fpath = Path(root) / fn
                        try:
                            st = fpath.stat()
                            if st.st_mtime < cutoff:
                                size_mb = st.st_size / (1024.0 * 1024.0)
                                if not ctx.dry_run:
                                    fpath.unlink()
                                cleaned_mb += size_mb
                                cleaned_files += 1
                        except OSError:
                            continue

        cleaned_mb = round(cleaned_mb, 2)
        vendor_cache_mb = round(vendor_cache_mb, 1)
        gpu_info = ctx.t0.gpu
        vram_summary = (
            f"GPU {gpu_info.name}: 已用 {gpu_info.vram_used_mb:.0f}/{gpu_info.vram_total_mb:.0f} MB "
            f"(空闲 {gpu_info.vram_free_mb:.0f} MB)"
            if gpu_info.present
            else "未检测到 NVIDIA GPU，仅审计 WDDM 进程显存"
        )
        prefix = "[Dry-Run] " if ctx.dry_run else ""

        return ActionResult(
            module_name=self.name,
            status="dry_run" if ctx.dry_run else "ok",
            duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
            reclaimed_mb=cleaned_mb,
            items_processed=cleaned_files,
            summary=(
                f"{prefix}{vram_summary}；可释放非核心后台显存约 {reclaimable_user_vram_mb:.0f} MB；"
                f"D3D 过期缓存清理 {cleaned_files} 个 ({cleaned_mb:.1f} MB)；"
                f"显卡驱动着色器缓存占用 {vendor_cache_mb:.0f} MB (保留防游戏卡顿)"
            ),
            details={
                "dwm_vram_mb": dwm_vram_mb,
                "reclaimable_user_vram_mb": reclaimable_user_vram_mb,
                "vram_hogs": vram_hogs[:10],
                "stale_shader_files_cleaned": cleaned_files,
                "stale_shader_mb_cleaned": cleaned_mb,
                "vendor_shader_cache_mb": vendor_cache_mb,
                "vram_glitch_samples_filtered": ctx.t0.vram_glitch_count,
            },
        )
