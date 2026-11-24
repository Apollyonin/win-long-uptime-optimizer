import unittest

from winopt.telemetry import (
    parse_counter_samples,
    parse_nvidia_smi_output,
    parse_powercfg_output,
    sanitize_vram_bytes,
)
from winopt.win32_native import (
    IS_WINDOWS,
    get_performance_info,
    query_timer_resolution,
)


class TestWin32AndTelemetry(unittest.TestCase):
    def test_sanitize_vram_overflow_glitch(self) -> None:
        total_vram_bytes = 8188 * 1024 * 1024
        # Reproduce the real 21,673,524.4 MB overflow seen on Windows 11 WDDM counters
        bogus_bytes = 21673524.4 * 1024 * 1024
        cleaned, glitch = sanitize_vram_bytes(bogus_bytes, total_vram_bytes)
        self.assertTrue(glitch)
        self.assertEqual(cleaned, 0.0)

        neg_cleaned, neg_glitch = sanitize_vram_bytes(-500.0, total_vram_bytes)
        self.assertTrue(neg_glitch)
        self.assertEqual(neg_cleaned, 0.0)

        valid_bytes = 512 * 1024 * 1024
        ok_val, ok_glitch = sanitize_vram_bytes(valid_bytes, total_vram_bytes)
        self.assertFalse(ok_glitch)
        self.assertAlmostEqual(ok_val, valid_bytes)

    def test_parse_counter_samples_filters_glitch(self) -> None:
        total_vram_bytes = 8188 * 1024 * 1024
        samples = [
            {
                "Path": r"\\PC\memory\standby cache normal priority bytes",
                "CookedValue": 2048 * 1024 * 1024,
            },
            {
                "Path": r"\\PC\gpu process memory(pid_13296_luid_0x0_phys_0)\dedicated usage",
                "CookedValue": 21673524.4 * 1024 * 1024,
            },
            {
                "Path": r"\\PC\gpu process memory(pid_1992_luid_0x0_phys_0)\dedicated usage",
                "CookedValue": 480 * 1024 * 1024,
            },
        ]
        parsed = parse_counter_samples(samples, total_vram_bytes)
        self.assertAlmostEqual(parsed["standby_normal_mb"], 2048.0, places=1)
        self.assertEqual(parsed["vram_glitch_count"], 1)
        self.assertTrue(parsed["gpu_process_vram"][13296]["glitch"])
        self.assertEqual(parsed["gpu_process_vram"][13296]["dedicated_mb"], 0.0)
        self.assertFalse(parsed["gpu_process_vram"][1992]["glitch"])
        self.assertAlmostEqual(parsed["gpu_process_vram"][1992]["dedicated_mb"], 480.0, places=1)

    def test_parse_nvidia_smi_and_powercfg(self) -> None:
        smi = "NVIDIA GeForce RTX 4060 Ti, 8188, 3200, 4988, 12, 48, P3\n"
        gpu = parse_nvidia_smi_output(smi)
        self.assertTrue(gpu.present)
        self.assertEqual(gpu.name, "NVIDIA GeForce RTX 4060 Ti")
        self.assertEqual(gpu.vram_free_mb, 4988.0)
        self.assertEqual(gpu.utilization_gpu_pct, 12.0)

        guid_cn, name_cn = parse_powercfg_output(
            "电源方案 GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (平衡)"
        )
        self.assertEqual(guid_cn, "381b4222-f694-41f0-9685-ff5bb260df2e")
        self.assertEqual(name_cn, "平衡")

        guid_en, name_en = parse_powercfg_output(
            "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)"
        )
        self.assertEqual(guid_en, "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c")
        self.assertEqual(name_en, "High performance")

    @unittest.skipUnless(IS_WINDOWS, "Windows-specific native API test")
    def test_live_win32_perf_and_timer(self) -> None:
        perf = get_performance_info()
        self.assertGreater(perf["physical_total_bytes"], 0)
        self.assertGreater(perf["commit_limit_bytes"], 0)
        timer = query_timer_resolution()
        self.assertGreater(timer["min_ms"], 0.0)
        self.assertGreater(timer["current_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
