"""Safe aged temp/crash-dump cleaner and periodic SSD ReTrim optimizer."""

from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from winopt.models import ActionResult
from winopt.optimizers.base import BaseOptimizer, OptimizationContext
from winopt.win32_native import IS_WINDOWS, is_admin


def _clean_aged_files_in_dir(
    root_dir: Path,
    cutoff_ts: float,
    dry_run: bool,
    max_files: int = 4000,
) -> tuple[int, float, int]:
    """Delete files older than cutoff_ts inside root_dir, safely skipping locked files."""
    if not root_dir.exists() or not root_dir.is_dir():
        return (0, 0.0, 0)

    removed = 0
    freed_bytes = 0
    skipped_locked = 0
    scanned = 0

    for current_root, _, files in os.walk(root_dir):
        for name in files:
            scanned += 1
            if scanned > max_files:
                return (removed, round(freed_bytes / (1024.0 * 1024.0), 2), skipped_locked)
            fpath = Path(current_root) / name
            try:
                st = fpath.stat()
                if st.st_mtime >= cutoff_ts:
                    continue
                size = st.st_size
                if not dry_run:
                    fpath.unlink()
                removed += 1
                freed_bytes += size
            except OSError:
                skipped_locked += 1
                continue

    return (removed, round(freed_bytes / (1024.0 * 1024.0), 2), skipped_locked)


class StorageTempOptimizer(BaseOptimizer):
    name = "storage_temp"

    def run(self, ctx: OptimizationContext) -> ActionResult:
        t_start = time.perf_counter()
        st_cfg = ctx.config.storage
        cutoff = time.time() - (max(1, st_cfg.temp_min_age_hours) * 3600.0)

        target_dirs: list[Path] = []
        if st_cfg.clean_temp_files:
            user_temp = os.environ.get("TEMP") or os.environ.get("TMP")
            if user_temp:
                target_dirs.append(Path(user_temp))
            win_root = os.environ.get("SystemRoot", r"C:\Windows")
            target_dirs.append(Path(win_root) / "Temp")

        if st_cfg.clean_wer_dumps:
            local_app = os.environ.get("LOCALAPPDATA", "")
            if local_app:
                target_dirs.append(Path(local_app) / "CrashDumps")
            prog_data = os.environ.get("ProgramData", r"C:\ProgramData")
            target_dirs.append(Path(prog_data) / "Microsoft" / "Windows" / "WER" / "ReportArchive")

        # Deduplicate while preserving order
        seen_dirs: set[str] = set()
        total_removed = 0
        total_freed_mb = 0.0
        total_locked = 0
        dir_stats: list[dict[str, Any]] = []

        for d in target_dirs:
            norm = str(d).lower()
            if norm in seen_dirs:
                continue
            seen_dirs.add(norm)
            rem, freed, locked = _clean_aged_files_in_dir(d, cutoff, ctx.dry_run)
            total_removed += rem
            total_freed_mb += freed
            total_locked += locked
            if rem > 0 or freed > 0:
                dir_stats.append(
                    {"dir": str(d), "removed_files": rem, "freed_mb": freed, "locked_skipped": locked}
                )

        total_freed_mb = round(total_freed_mb, 2)

        # Conditional SSD ReTrim (at most once per ssd_retrim_min_interval_hours, full profile + admin)
        retrim_status = "skipped"
        if (
            IS_WINDOWS
            and st_cfg.ssd_retrim_enabled
            and ctx.guard.profile == "full"
            and is_admin()
        ):
            due = True
            if ctx.policy.last_ssd_retrim_iso:
                try:
                    last_dt = datetime.fromisoformat(ctx.policy.last_ssd_retrim_iso)
                    hours_since = (datetime.now(timezone.utc).astimezone() - last_dt).total_seconds() / 3600.0
                    if hours_since < st_cfg.ssd_retrim_min_interval_hours:
                        due = False
                        retrim_status = f"cooldown ({hours_since:.1f}h < {st_cfg.ssd_retrim_min_interval_hours}h)"
                except Exception:
                    due = True

            if due:
                if ctx.dry_run:
                    retrim_status = "dry_run_would_retrim_C"
                else:
                    sys_drive = (os.environ.get("SystemDrive", "C:") or "C:")[0]
                    ps_cmd = (
                        f"$p = Get-PhysicalDisk | Where-Object {{ $_.MediaType -eq 'SSD' }}; "
                        f"if ($p) {{ Optimize-Volume -DriveLetter {sys_drive} -ReTrim -ErrorAction SilentlyContinue; 'OK' }} "
                        f"else {{ 'NO_SSD' }}"
                    )
                    try:
                        res = subprocess.run(
                            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                            capture_output=True,
                            timeout=25.0,
                            check=False,
                        )
                        out_text = res.stdout.decode("utf-8", errors="replace").strip()
                        if res.returncode == 0 and "OK" in out_text:
                            retrim_status = f"retrimmed_{sys_drive}"
                            ctx.policy.last_ssd_retrim_iso = (
                                datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
                            )
                        else:
                            retrim_status = out_text or "no_action"
                    except Exception as exc:
                        retrim_status = f"error: {exc}"

        prefix = "[Dry-Run] " if ctx.dry_run else ""
        return ActionResult(
            module_name=self.name,
            status="dry_run" if ctx.dry_run else "ok",
            duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
            reclaimed_mb=total_freed_mb,
            items_processed=total_removed,
            summary=(
                f"{prefix}清理陈旧临时/崩溃转储文件 {total_removed} 个，释放磁盘 {total_freed_mb:.1f} MB；"
                f"SSD ReTrim: {retrim_status}"
            ),
            details={
                "removed_files": total_removed,
                "freed_mb": total_freed_mb,
                "locked_skipped": total_locked,
                "retrim_status": retrim_status,
                "directories": dir_stats,
            },
        )
