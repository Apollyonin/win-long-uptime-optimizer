import tempfile
import unittest
from pathlib import Path

from tests.helpers import make_benchmark, make_snapshot, make_test_config
from winopt.engine import run_optimization_cycle
from winopt.models import ActionResult, ProcessMetric
from winopt.optimizers.base import BaseOptimizer, OptimizationContext


class _FakeMemoryOptimizer(BaseOptimizer):
    name = "memory_lists"

    def run(self, ctx: OptimizationContext) -> ActionResult:
        return ActionResult(
            module_name=self.name,
            status="dry_run" if ctx.dry_run else "ok",
            duration_ms=12.0,
            reclaimed_mb=2400.0,
            items_processed=2,
            summary="Fake Standby purge 2400 MB",
        )


class _FakeWorkingSetOptimizer(BaseOptimizer):
    name = "working_set"

    def run(self, ctx: OptimizationContext) -> ActionResult:
        return ActionResult(
            module_name=self.name,
            status="dry_run" if ctx.dry_run else "ok",
            duration_ms=8.0,
            reclaimed_mb=400.0,
            items_processed=1,
            summary="Fake trim 400 MB",
            details={
                "trimmed_processes": [
                    {
                        "pid": 3001,
                        "name": "rebounder.exe",
                        "before_mb": 500.0,
                        "after_mb": 100.0,
                        "trimmed_mb": 400.0,
                    }
                ]
            },
        )


class TestEngineE2E(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cfg = make_test_config(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_full_closed_loop_two_cycles_and_reports(self) -> None:
        call_counter = {"n": 0}

        def fake_snapshot(cfg, include_processes: bool = True):
            del cfg, include_processes
            idx = call_counter["n"]
            call_counter["n"] += 1
            # Phase sequence per run: 0=T0, 1=T1, 2=T2
            phase = idx % 3
            if phase == 0:
                return make_snapshot(
                    available_ram_mb=8000.0,
                    standby_total_mb=5200.0,
                    processes=[ProcessMetric(pid=3001, name="rebounder.exe", rss_mb=500.0, private_mb=450.0)],
                )
            if phase == 1:
                return make_snapshot(available_ram_mb=12800.0, standby_total_mb=800.0)
            return make_snapshot(
                available_ram_mb=12200.0,
                standby_total_mb=1100.0,
                processes=[ProcessMetric(pid=3001, name="rebounder.exe", rss_mb=460.0, private_mb=450.0)],
            )

        def fake_bench(alloc_mb: int, probe_dir: Path | None = None):
            del alloc_mb, probe_dir
            return make_benchmark(alloc_ms=55.0, jitter_p95_ms=1.6)

        opts = [_FakeMemoryOptimizer(), _FakeWorkingSetOptimizer()]

        # Dry run should not persist runs
        dry_out = run_optimization_cycle(
            self.cfg,
            mode="dry_run",
            dry_run=True,
            settle_seconds=0,
            snapshot_fn=fake_snapshot,
            bench_fn=fake_bench,
            optimizers=opts,
        )
        self.assertTrue(dry_out.dry_run)
        self.assertIsNone(dry_out.md_report_path)

        # Cycle 1
        call_counter["n"] = 0
        out1 = run_optimization_cycle(
            self.cfg,
            mode="scheduled",
            dry_run=False,
            settle_seconds=0,
            snapshot_fn=fake_snapshot,
            bench_fn=fake_bench,
            optimizers=opts,
        )
        self.assertIsNotNone(out1.md_report_path)
        self.assertIsNotNone(out1.html_dashboard_path)
        self.assertTrue(out1.md_report_path.exists())
        self.assertTrue(out1.html_dashboard_path.exists())
        self.assertEqual(out1.policy.rebound_strikes.get("rebounder.exe"), 1)

        # Cycle 2 -> rebounder.exe reaches 2 strikes -> auto-excluded & SVG trends have 2 points!
        out2 = run_optimization_cycle(
            self.cfg,
            mode="scheduled",
            dry_run=False,
            settle_seconds=0,
            snapshot_fn=fake_snapshot,
            bench_fn=fake_bench,
            optimizers=opts,
        )
        self.assertIn("rebounder.exe", out2.policy.dynamic_trim_exclude)
        html_content = out2.html_dashboard_path.read_text(encoding="utf-8")
        self.assertIn("<polyline", html_content)
        self.assertIn("查漏补缺", html_content)


if __name__ == "__main__":
    unittest.main()
