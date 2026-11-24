import tempfile
import unittest
from pathlib import Path

from tests.helpers import make_benchmark, make_snapshot, make_test_config
from winopt.leak_detector import compute_rate_per_hour, detect_leaks
from winopt.models import ProcessMetric
from winopt.storage import StorageManager


class TestLeakDetector(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cfg = make_test_config(Path(self._tmp.name))
        self.storage = StorageManager(self.cfg.db_path, self.cfg.policy_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_ols_rate_per_hour(self) -> None:
        pts = [
            ("2026-11-23T08:00:00-05:00", 500.0),
            ("2026-11-23T20:00:00-05:00", 860.0),  # +360 over 12h = +30/h
            ("2026-11-24T08:00:00-05:00", 1220.0),
        ]
        slope = compute_rate_per_hour(pts)
        self.assertIsNotNone(slope)
        self.assertAlmostEqual(slope, 30.0, places=1)

    def test_detects_private_handle_gdi_vram_and_ignores_glitch(self) -> None:
        # Persist historical T2 snapshot 12 hours ago for PID 4242
        hist_proc = ProcessMetric(
            pid=4242,
            name="leaky_service.exe",
            create_time=1700000000.0,
            rss_mb=520.0,
            private_mb=480.0,
            handles=1800,
            gdi_objects=300,
            user_objects=150,
            vram_dedicated_mb=260.0,
        )
        old_snap = make_snapshot(
            captured_at="2026-11-23T20:00:00-05:00",
            processes=[hist_proc],
        )
        self.storage.save_run(
            run_id="hist_run_1",
            started_at="2026-11-23T20:00:00-05:00",
            finished_at="2026-11-23T20:01:00-05:00",
            mode="scheduled",
            execution_profile="full",
            policy_version=1,
            t0=old_snap,
            t1=None,
            t2=old_snap,
            bench_t0=make_benchmark(),
            bench_t1=make_benchmark(),
            score_t0=70.0,
            score_t1=None,
            score_t2=75.0,
            summary={},
            module_results=[],
            leak_events=[],
            gap_findings=[],
            save_process_phases=(("t2", old_snap),),
        )

        # Now 12 hours later: +420 MB private (+35 MB/h), +2400 handles (+200/h), high GDI, plus a glitch VRAM process
        cur_leaky = ProcessMetric(
            pid=4242,
            name="leaky_service.exe",
            create_time=1700000000.0,
            rss_mb=950.0,
            private_mb=900.0,
            handles=4200,
            gdi_objects=2500,
            user_objects=2200,
            vram_dedicated_mb=680.0,  # +420 MB / 12h = +35 MB/h -> warn!
        )
        glitch_proc = ProcessMetric(
            pid=9999,
            name="NVIDIA Overlay.exe",
            create_time=1700000100.0,
            rss_mb=120.0,
            private_mb=100.0,
            vram_dedicated_mb=0.0,
            vram_glitch=True,
        )
        cur_snap = make_snapshot(
            captured_at="2026-11-24T08:00:00-05:00",
            commit_total_mb=52000.0,  # 79.3% -> WARN
            kernel_nonpaged_mb=1450.0,  # >= 1200 -> WARN
            processes=[cur_leaky, glitch_proc],
        )

        leaks = detect_leaks(cur_snap, self.cfg, self.storage)
        cats = {(lk.process_name, lk.category): lk for lk in leaks}

        self.assertIn(("Kernel Nonpaged Pool", "nonpaged_pool"), cats)
        self.assertIn(("System Commit Charge", "commit"), cats)
        self.assertIn(("leaky_service.exe", "private_mem"), cats)
        self.assertIn(("leaky_service.exe", "handles"), cats)
        self.assertIn(("leaky_service.exe", "gdi"), cats)
        self.assertIn(("leaky_service.exe", "user_obj"), cats)
        self.assertIn(("leaky_service.exe", "vram"), cats)
        # Ensure glitch process was NOT falsely flagged for VRAM leak
        self.assertNotIn(("NVIDIA Overlay.exe", "vram"), cats)


if __name__ == "__main__":
    unittest.main()
