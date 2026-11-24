"""DNS cache flush and TCP socket health check."""

from __future__ import annotations

import subprocess
import time

from winopt.models import ActionResult
from winopt.optimizers.base import BaseOptimizer, OptimizationContext
from winopt.win32_native import IS_WINDOWS


class NetworkDnsOptimizer(BaseOptimizer):
    name = "network_dns"

    def run(self, ctx: OptimizationContext) -> ActionResult:
        t_start = time.perf_counter()
        net_cfg = ctx.config.network
        tcp = ctx.t0.tcp_counts
        total_sock = tcp.get("TOTAL", 0)
        close_wait = tcp.get("CLOSE_WAIT", 0)
        time_wait = tcp.get("TIME_WAIT", 0)
        warnings: list[str] = []

        if total_sock >= net_cfg.socket_warn_threshold or close_wait >= 300:
            warnings.append(
                f"TCP 连接数偏高 (总数 {total_sock}, TIME_WAIT {time_wait}, CLOSE_WAIT {close_wait})，"
                "若长期不关机可能是某后台服务未正确释放句柄"
            )

        flushed = False
        if net_cfg.flush_dns and IS_WINDOWS and not ctx.dry_run:
            try:
                res = subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True,
                    timeout=6.0,
                    check=False,
                )
                flushed = res.returncode == 0
            except Exception as exc:
                warnings.append(f"DNS 缓存刷新失败: {exc}")

        prefix = "[Dry-Run] " if ctx.dry_run else ""
        dns_msg = "计划刷新 DNS 解析缓存" if ctx.dry_run else ("已刷新 DNS 解析缓存" if flushed else "跳过/未刷新 DNS")
        return ActionResult(
            module_name=self.name,
            status="dry_run" if ctx.dry_run else "ok",
            duration_ms=round((time.perf_counter() - t_start) * 1000.0, 2),
            reclaimed_mb=0.0,
            items_processed=1 if flushed else 0,
            summary=f"{prefix}{dns_msg}；TCP 状态: 总 {total_sock} (ESTABLISHED {tcp.get('ESTABLISHED', 0)}, CLOSE_WAIT {close_wait})",
            details={"dns_flushed": flushed, "tcp_counts": tcp},
            warnings=warnings,
        )
