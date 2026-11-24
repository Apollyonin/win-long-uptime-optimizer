import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil

from tests.helpers import make_test_config
from winopt.process_control import (
    build_relaunch_command,
    classify_process,
    get_self_lineage_pids,
    resolve_same_app_tree,
    safe_restart_target,
    safe_trim_target,
)
from winopt.web_console import create_web_server
from winopt.win32_native import get_current_desktop_info


def _kill_pid_tree(pid: int | None) -> None:
    if not pid:
        return
    try:
        p = psutil.Process(pid)
        children = p.children(recursive=True)
        for ch in children:
            try:
                ch.kill()
            except Exception:
                pass
        try:
            p.kill()
        except Exception:
            pass
        psutil.wait_procs([p, *children], timeout=2.0)
    except Exception:
        pass


class TestProcessControlAndWeb(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.cfg = make_test_config(Path(self._tmp.name))
        self._cleanup_pids: list[int] = []
        self._popen_handles: list[subprocess.Popen] = []

    def tearDown(self) -> None:
        for pid in self._cleanup_pids:
            _kill_pid_tree(pid)
        for proc in self._popen_handles:
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass
        self._tmp.cleanup()

    def test_classify_process_and_self_lineage(self) -> None:
        lineage = get_self_lineage_pids()
        self.assertIn(os.getpid(), lineage)

        self_cls = classify_process(os.getpid(), "python.exe", lineage)
        self.assertEqual(self_cls["safety_tier"], "forbidden")
        self.assertFalse(self_cls["can_restart"])
        self.assertFalse(self_cls["can_trim"])

        svchost_cls = classify_process(999999, "svchost.exe", lineage)
        self.assertEqual(svchost_cls["safety_tier"], "forbidden")
        self.assertFalse(svchost_cls["can_restart"])

        dwm_cls = classify_process(999998, "dwm.exe", lineage)
        self.assertEqual(dwm_cls["safety_tier"], "forbidden")

        exp_cls = classify_process(999997, "explorer.exe", lineage)
        self.assertEqual(exp_cls["safety_tier"], "shell_restart")
        self.assertTrue(exp_cls["can_restart"])
        self.assertFalse(exp_cls["can_trim"])

        chrome_cls = classify_process(999996, "chrome.exe", lineage)
        self.assertEqual(chrome_cls["safety_tier"], "safe_restart")
        self.assertTrue(chrome_cls["unsaved_work_risk"])
        self.assertTrue(chrome_cls["can_restart"])
        self.assertTrue(chrome_cls["can_trim"])

    def test_build_relaunch_command_strips_renderer_flags(self) -> None:
        exe = sys.executable
        child_cmd = [exe, "--type=renderer", "--field-trial-handle=123"]
        self.assertEqual(build_relaunch_command(exe, child_cmd, "chrome.exe"), [exe])

        chrome_cmd = [
            exe,
            "--profile-directory=Profile 1",
            "--source-shortcut-location=taskbar",
            "--flag-switches-begin",
            "--flag-switches-end",
            "--origin-trial-disabled-features=CanvasTextNg",
        ]
        self.assertEqual(
            build_relaunch_command(exe, chrome_cmd, "chrome.exe"),
            [exe, "--profile-directory=Profile 1"],
        )

        normal_cmd = [exe, "-c", "import time; time.sleep(1)"]
        self.assertEqual(build_relaunch_command(exe, normal_cmd, "python.exe"), normal_cmd)

        self.assertEqual(build_relaunch_command(r"C:\Windows\explorer.exe", [], "explorer.exe"), ["explorer.exe"])

    def test_non_default_desktop_blocks_gui_relaunch(self) -> None:
        desk = get_current_desktop_info()
        self.assertIn("window_station", desk)
        self.assertIn("desktop", desk)
        self.assertIn("is_default_desktop", desk)

        fake_proc = MagicMock()
        fake_proc.pid = 999990
        fake_proc.name.return_value = "chrome.exe"
        fake_proc.exe.return_value = sys.executable

        with (
            patch("winopt.process_control.IS_WINDOWS", True),
            patch("winopt.process_control.resolve_targets_by_scope", return_value=(fake_proc, [fake_proc])),
            patch(
                "winopt.process_control.get_current_desktop_info",
                return_value={
                    "window_station": "WinSta0",
                    "desktop": "exebox-test",
                    "is_default_desktop": False,
                },
            ),
        ):
            res = safe_restart_target(999990, scope="group", relaunch=True)
        self.assertFalse(res["ok"])
        self.assertEqual(res["http_status"], 409)
        self.assertIn("start_web_console.bat", res["message"])

    def test_real_tree_trim_and_restart_on_dummy_subprocess_tree(self) -> None:
        # Spawn dummy python parent -> child tree
        script = (
            "import subprocess, sys, time; "
            "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
            "time.sleep(60)"
        )
        parent = subprocess.Popen([sys.executable, "-c", script])
        self._popen_handles.append(parent)
        self._cleanup_pids.append(parent.pid)

        # Wait up to 3s for child process to appear
        child_pid = None
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                children = psutil.Process(parent.pid).children(recursive=True)
                if children:
                    child_pid = children[0].pid
                    self._cleanup_pids.append(child_pid)
                    break
            except Exception:
                pass
            time.sleep(0.1)

        self.assertIsNotNone(child_pid, "Dummy child process did not spawn in time")
        root, members = resolve_same_app_tree(child_pid)
        self.assertEqual(root.pid, parent.pid)
        self.assertEqual({m.pid for m in members}, {parent.pid, child_pid})

        trim_res = safe_trim_target(parent.pid, scope="tree")
        self.assertTrue(trim_res["ok"])
        self.assertEqual(trim_res["trimmed_count"], 2)

        restart_res = safe_restart_target(
            child_pid,
            scope="tree",
            relaunch=True,
            graceful_timeout_s=1.5,
        )
        self.assertTrue(restart_res["ok"], msg=restart_res)
        self.assertFalse(psutil.pid_exists(parent.pid))
        self.assertFalse(psutil.pid_exists(child_pid))

        new_pid = restart_res["new_pid"]
        self.assertIsNotNone(new_pid)
        self.assertNotIn(new_pid, (parent.pid, child_pid))
        self._cleanup_pids.append(new_pid)
        self.assertTrue(psutil.pid_exists(new_pid))

    def test_web_console_http_security_and_endpoints(self) -> None:
        server, ctx = create_web_server(self.cfg, host="127.0.0.1", port=0)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        try:
            base = f"http://127.0.0.1:{port}"
            # 1. GET / serves console HTML with CSRF token
            with urllib.request.urlopen(f"{base}/", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                page = resp.read().decode("utf-8")
            self.assertIn(ctx.csrf_token, page)
            self.assertIn("立即执行完整优化", page)
            self.assertIn("安全重启", page)

            def _post(path: str, payload: dict, headers: dict | None = None):
                req = urllib.request.Request(
                    f"{base}{path}",
                    data=json.dumps(payload).encode("utf-8"),
                    method="POST",
                    headers={"Content-Type": "application/json", **(headers or {})},
                )
                try:
                    with urllib.request.urlopen(req, timeout=8) as r:
                        return (r.status, json.loads(r.read().decode("utf-8")))
                except urllib.error.HTTPError as e:
                    return (e.code, json.loads(e.read().decode("utf-8")))

            # 2. Missing CSRF token -> 403
            st_no_tok, _ = _post("/api/process/restart", {"pid": 12345})
            self.assertEqual(st_no_tok, 403)

            # 3. Bad Origin -> 403
            st_bad_org, _ = _post(
                "/api/process/restart",
                {"pid": 12345},
                headers={"X-WinOpt-Token": ctx.csrf_token, "Origin": "https://evil.example"},
            )
            self.assertEqual(st_bad_org, 403)

            # 4. Forbidden self PID -> 403
            st_self, body_self = _post(
                "/api/process/restart",
                {"pid": os.getpid(), "scope": "single"},
                headers={"X-WinOpt-Token": ctx.csrf_token, "Origin": base},
            )
            self.assertEqual(st_self, 403)
            self.assertFalse(body_self["ok"])

            # 5. Valid restart on dummy subprocess -> 200 & persisted in manual_actions
            dummy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
            self._popen_handles.append(dummy)
            self._cleanup_pids.append(dummy.pid)
            time.sleep(0.2)

            st_ok, body_ok = _post(
                "/api/process/restart",
                {"pid": dummy.pid, "scope": "single", "relaunch": True},
                headers={"X-WinOpt-Token": ctx.csrf_token, "Origin": base},
            )
            self.assertEqual(st_ok, 200)
            self.assertTrue(body_ok["ok"])
            if body_ok.get("new_pid"):
                self._cleanup_pids.append(body_ok["new_pid"])

            with urllib.request.urlopen(f"{base}/api/state", timeout=5) as resp:
                state_data = json.loads(resp.read().decode("utf-8"))
            self.assertGreaterEqual(len(state_data["manual_actions"]), 1)
            self.assertEqual(state_data["manual_actions"][0]["action_type"], "restart_process")
        finally:
            server.shutdown()
            server.server_close()

    def test_exclusive_port_fallback_avoids_shadowing(self) -> None:
        s1, _ = create_web_server(self.cfg, host="127.0.0.1", port=0)
        try:
            occupied_port = s1.server_address[1]
            s2, _ = create_web_server(self.cfg, host="127.0.0.1", port=occupied_port, fallback_range=10)
            try:
                self.assertNotEqual(s2.server_address[1], occupied_port)
            finally:
                s2.server_close()
        finally:
            s1.server_close()


if __name__ == "__main__":
    unittest.main()
