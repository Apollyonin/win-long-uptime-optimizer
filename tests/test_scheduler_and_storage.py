import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from tests.helpers import make_benchmark, make_snapshot, make_test_config
from winopt.models import ActionResult, GapFinding, LeakEvent, ProcessMetric
from winopt.scheduler import export_task_xml
from winopt.storage import StorageManager


class TestSchedulerAndStorage(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.cfg = make_test_config(self.tmp_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_task_scheduler_xml_12h_utf16(self) -> None:
        xml_file = self.tmp_path / "task.xml"
        out = export_task_xml(self.cfg, xml_file)
        self.assertTrue(out.exists())
        raw_bytes = out.read_bytes()
        # UTF-16 BOM
        self.assertTrue(raw_bytes.startswith(b"\xff\xfe") or raw_bytes.startswith(b"\xfe\xff"))

        text = out.read_text(encoding="utf-16")
        root = ET.fromstring(text)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        interval = root.find(".//t:Repetition/t:Interval", ns)
        run_level = root.find(".//t:Principal/t:RunLevel", ns)
        workdir = root.find(".//t:Exec/t:WorkingDirectory", ns)
        args = root.find(".//t:Exec/t:Arguments", ns)

        self.assertIsNotNone(interval)
        self.assertEqual(interval.text, "PT12H")
        self.assertEqual(run_level.text, "HighestAvailable")
        self.assertEqual(workdir.text, str(self.cfg.workspace_dir))
        self.assertIn("--mode scheduled", args.text)

    def test_storage_roundtrip_and_pruning(self) -> None:
        store = StorageManager(self.cfg.db_path, self.cfg.policy_path)
        policy = store.ensure_policy(self.cfg)
        self.assertEqual(policy.version, 1)

        snap = make_snapshot(
            captured_at="2020-01-01T00:00:00+00:00",
            processes=[ProcessMetric(pid=88, name="old_proc.exe", rss_mb=150.0, private_mb=120.0)],
        )
        store.save_run(
            run_id="run_old",
            started_at="2020-01-01T00:00:00+00:00",
            finished_at="2020-01-01T00:01:00+00:00",
            mode="scheduled",
            execution_profile="full",
            policy_version=1,
            t0=snap,
            t1=snap,
            t2=snap,
            bench_t0=make_benchmark(),
            bench_t1=make_benchmark(),
            score_t0=65.0,
            score_t1=72.0,
            score_t2=71.0,
            summary={"evaluation": {"net_available_ram_delta_mb": 1200.0}},
            module_results=[ActionResult(module_name="memory_lists", status="ok", reclaimed_mb=1200.0)],
            leak_events=[
                LeakEvent(
                    detected_at="2020-01-01T00:01:00+00:00",
                    severity="WARN",
                    category="private_mem",
                    pid=88,
                    process_name="old_proc.exe",
                    current_value=120.0,
                    growth_rate_per_hour=25.0,
                    recommendation="restart",
                )
            ],
            gap_findings=[
                GapFinding(
                    severity="INFO",
                    code="TEST",
                    title="Test Gap",
                    description="desc",
                    metric_value="1",
                    recommendation="rec",
                )
            ],
            save_process_phases=(("t2", snap),),
        )

        details = store.get_latest_run_details()
        self.assertIsNotNone(details)
        self.assertEqual(details["run_id"], "run_old")
        self.assertEqual(len(details["modules"]), 1)
        self.assertEqual(len(details["leaks"]), 1)
        self.assertEqual(len(details["gaps"]), 1)

        pruned = store.prune_old_process_snapshots(retain_days=30)
        self.assertEqual(pruned, 1)


if __name__ == "__main__":
    unittest.main()
