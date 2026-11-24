import tempfile
import unittest
from pathlib import Path

from tests.helpers import make_snapshot, make_test_config
from winopt.models import ProcessMetric
from winopt.workload_guard import evaluate_workload_guard


class TestWorkloadGuard(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cfg = make_test_config(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_idle_system_uses_full_profile(self) -> None:
        snap = make_snapshot(cpu_pct=5.0, gpu_util_pct=4.0)
        decision = evaluate_workload_guard(snap, self.cfg, mode="scheduled")
        self.assertEqual(decision.profile, "full")
        self.assertEqual(decision.active_heavy_apps, [])

    def test_active_engineering_app_triggers_conservative(self) -> None:
        ansys = ProcessMetric(
            pid=5555,
            name="fluent.exe",
            rss_mb=4200.0,
            private_mb=4100.0,
            cpu_pct=35.0,
        )
        snap = make_snapshot(cpu_pct=42.0, processes=[ansys])
        decision = evaluate_workload_guard(snap, self.cfg, mode="scheduled")
        self.assertEqual(decision.profile, "conservative")
        self.assertIn("fluent.exe", decision.active_heavy_apps)
        self.assertIn(5555, decision.active_heavy_pids)

    def test_high_gpu_or_cpu_triggers_conservative(self) -> None:
        snap = make_snapshot(cpu_pct=72.0, gpu_util_pct=65.0)
        decision = evaluate_workload_guard(snap, self.cfg, mode="manual")
        self.assertEqual(decision.profile, "conservative")
        self.assertGreaterEqual(len(decision.reasons), 2)

    def test_boost_mode_keeps_full_profile_while_protecting_apps(self) -> None:
        blender = ProcessMetric(pid=7777, name="blender.exe", rss_mb=1800.0, cpu_pct=1.0)
        snap = make_snapshot(cpu_pct=12.0, processes=[blender], foreground_pid=7777)
        decision = evaluate_workload_guard(snap, self.cfg, mode="boost")
        self.assertEqual(decision.profile, "full")
        self.assertIn(7777, decision.active_heavy_pids)


if __name__ == "__main__":
    unittest.main()
