import tempfile
import unittest
from pathlib import Path

from tests.helpers import make_benchmark, make_snapshot, make_test_config
from winopt.evaluator import evaluate_run
from winopt.iterator import iterate_policy
from winopt.models import ActionResult, ProcessMetric
from winopt.storage import StorageManager


class TestEvaluatorAndIterator(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cfg = make_test_config(Path(self._tmp.name))
        self.storage = StorageManager(self.cfg.db_path, self.cfg.policy_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_rebound_detection_and_gap_analysis(self) -> None:
        p_rebound_t0 = ProcessMetric(pid=101, name="chat_rebound.exe", rss_mb=600.0, private_mb=550.0)
        p_stay_t0 = ProcessMetric(pid=102, name="idle_tray.exe", rss_mb=400.0, private_mb=350.0)
        p_dwm = ProcessMetric(pid=103, name="dwm.exe", rss_mb=500.0, private_mb=300.0, vram_dedicated_mb=950.0)
        p_hog = ProcessMetric(pid=104, name="chrome.exe", rss_mb=2400.0, private_mb=2200.0, vram_dedicated_mb=1200.0)

        t0 = make_snapshot(
            uptime_hours=300.0,
            available_ram_mb=7000.0,
            standby_total_mb=8500.0,
            commit_total_mb=54000.0,  # 82.4% commit -> WARN
            kernel_nonpaged_mb=1500.0,
            gpu_used_mb=4500.0,
            processes=[p_rebound_t0, p_stay_t0, p_dwm, p_hog],
        )
        # After trim: chat_rebound 600->120, idle_tray 400->80
        ws_result = ActionResult(
            module_name="working_set",
            status="ok",
            reclaimed_mb=800.0,
            items_processed=2,
            details={
                "trimmed_processes": [
                    {"pid": 101, "name": "chat_rebound.exe", "before_mb": 600.0, "after_mb": 120.0, "trimmed_mb": 480.0},
                    {"pid": 102, "name": "idle_tray.exe", "before_mb": 400.0, "after_mb": 80.0, "trimmed_mb": 320.0},
                ]
            },
        )
        # At T2: chat_rebound bounced back to 540 MB (420/480 = 87.5% rebound!), idle_tray stayed at 110 MB
        p_rebound_t2 = ProcessMetric(pid=101, name="chat_rebound.exe", rss_mb=540.0, private_mb=550.0)
        p_stay_t2 = ProcessMetric(pid=102, name="idle_tray.exe", rss_mb=110.0, private_mb=350.0)
        t2 = make_snapshot(
            uptime_hours=300.0,
            available_ram_mb=14000.0,
            standby_total_mb=1500.0,
            commit_total_mb=54000.0,
            kernel_nonpaged_mb=1500.0,
            gpu_used_mb=4500.0,
            processes=[p_rebound_t2, p_stay_t2, p_dwm, p_hog],
        )

        ev = evaluate_run(
            t0=t0,
            t1=t2,
            t2=t2,
            bench_t0=make_benchmark(alloc_ms=140.0),
            bench_t1=make_benchmark(alloc_ms=52.0),
            module_results=[ws_result],
            leaks=[],
            cfg=self.cfg,
        )

        self.assertGreater(ev.score_t2.total, ev.score_t0.total)
        self.assertEqual([r.name for r in ev.rebounders], ["chat_rebound.exe"])
        self.assertEqual([r.name for r in ev.non_rebounders], ["idle_tray.exe"])

        gap_codes = {g.code for g in ev.gaps}
        self.assertIn("HIGH_COMMIT_RESIDUAL", gap_codes)
        self.assertIn("DWM_VRAM_LEAK", gap_codes)
        self.assertIn("HIGH_VRAM_OCCUPANCY", gap_codes)
        self.assertIn("TRIM_REBOUNDERS", gap_codes)
        self.assertIn("KERNEL_POOL_BLOAT", gap_codes)
        self.assertIn("LONG_UPTIME_ADVISORY", gap_codes)

    def test_auto_exclude_after_strikes_and_rollback_on_regression(self) -> None:
        policy = self.storage.ensure_policy(self.cfg)
        self.assertEqual(policy.version, 1)

        # Build a run where chat_rebound.exe rebounds AND high rebound rate triggers parameter tuning
        t0 = make_snapshot(available_ram_mb=15000.0, standby_total_mb=2000.0)
        t2 = make_snapshot(
            available_ram_mb=15100.0,
            standby_total_mb=1800.0,
            processes=[ProcessMetric(pid=101, name="chat_rebound.exe", rss_mb=580.0)],
        )
        ws_mod = ActionResult(
            module_name="working_set",
            status="ok",
            reclaimed_mb=480.0,
            items_processed=1,
            details={
                "trimmed_processes": [
                    {"pid": 101, "name": "chat_rebound.exe", "before_mb": 600.0, "after_mb": 120.0, "trimmed_mb": 480.0}
                ]
            },
        )
        ev1 = evaluate_run(t0, t2, t2, make_benchmark(60.0), make_benchmark(58.0), [ws_mod], [], self.cfg)
        # First strike -> tunes min_working_set_mb upward -> bumps to v2
        out1 = iterate_policy(
            "run_1", "full", policy, t0, t2, make_benchmark(58.0), [ws_mod], ev1, [], self.cfg, self.storage
        )
        self.assertEqual(out1.action, "iterate")
        self.assertEqual(out1.new_version, 2)
        self.assertEqual(policy.rebound_strikes["chat_rebound.exe"], 1)

        # Second run: suppose v2 produces healthy non-regressed score AND chat_rebound hits strike #2 -> auto-excluded -> v3
        ev2 = evaluate_run(t0, t2, t2, make_benchmark(60.0), make_benchmark(56.0), [ws_mod], [], self.cfg)
        out2 = iterate_policy(
            "run_2", "full", policy, t0, t2, make_benchmark(56.0), [ws_mod], ev2, [], self.cfg, self.storage
        )
        self.assertEqual(out2.action, "iterate")
        self.assertEqual(out2.new_version, 3)
        self.assertIn("chat_rebound.exe", policy.dynamic_trim_exclude)

        # Third run: simulate severe regression (score drops > 5 pts & alloc latency jumps > 35%) -> auto rollback to v2!
        bad_t2 = make_snapshot(
            available_ram_mb=3500.0,
            standby_total_mb=9000.0,
            commit_total_mb=59000.0,
            gpu_used_mb=7200.0,
            kernel_nonpaged_mb=1800.0,
        )
        bad_bench = make_benchmark(alloc_ms=240.0, jitter_p95_ms=11.0)
        ev3 = evaluate_run(bad_t2, bad_t2, bad_t2, bad_bench, bad_bench, [], [], self.cfg)
        out3 = iterate_policy(
            "run_3", "full", policy, bad_t2, bad_t2, bad_bench, [], ev3, [], self.cfg, self.storage
        )
        self.assertEqual(out3.action, "rollback")
        self.assertEqual(out3.new_version, 4)
        reloaded = self.storage.ensure_policy(self.cfg)
        self.assertNotIn("chat_rebound.exe", reloaded.dynamic_trim_exclude)


if __name__ == "__main__":
    unittest.main()
