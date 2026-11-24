"""Fast, non-destructive micro-benchmarks measuring memory allocation, jitter, and disk I/O."""

from __future__ import annotations

import os
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from winopt.models import BenchmarkResult


def bench_memory_alloc_touch(size_mb: int = 128) -> tuple[float, float]:
    """Allocate and touch one byte per 4KB OS page to measure physical page supply speed.

    Returns (elapsed_ms, throughput_gbps).
    """
    total_bytes = max(16, int(size_mb)) * 1024 * 1024
    start = time.perf_counter()
    buf = bytearray(total_bytes)
    # Touch every 4KB page so OS commits real physical frames
    buf[0::4096] = b"\x01" * (total_bytes // 4096)
    elapsed_s = max(1e-6, time.perf_counter() - start)
    del buf

    elapsed_ms = round(elapsed_s * 1000.0, 2)
    throughput_gbps = round((total_bytes / (1024.0**3)) / elapsed_s, 3)
    return (elapsed_ms, throughput_gbps)


def bench_scheduler_jitter(iterations: int = 40, sleep_ms: float = 5.0) -> dict[str, float]:
    """Measure OS sleep timer overshoot jitter (p50, p95, p99, max in ms)."""
    target_s = sleep_ms / 1000.0
    jitters: list[float] = []
    for _ in range(max(10, iterations)):
        t0 = time.perf_counter()
        time.sleep(target_s)
        actual_ms = (time.perf_counter() - t0) * 1000.0
        jitters.append(max(0.0, actual_ms - sleep_ms))

    jitters.sort()
    n = len(jitters)

    def _pct(p: float) -> float:
        idx = min(n - 1, max(0, int(round((p / 100.0) * (n - 1)))))
        return round(jitters[idx], 3)

    return {
        "p50_ms": round(statistics.median(jitters), 3),
        "p95_ms": _pct(95.0),
        "p99_ms": _pct(99.0),
        "max_ms": round(max(jitters), 3),
    }


def bench_disk_io_latency(probe_dir: Path | None = None, size_mb: int = 4) -> dict[str, float]:
    """Measure small-file write+fsync and read latency in ms."""
    target_dir = Path(probe_dir) if probe_dir else Path(tempfile.gettempdir())
    target_dir.mkdir(parents=True, exist_ok=True)
    payload = b"W" * (max(1, size_mb) * 1024 * 1024)
    fd, path = tempfile.mkstemp(prefix="winopt_probe_", suffix=".tmp", dir=str(target_dir))
    os.close(fd)

    try:
        t0 = time.perf_counter()
        with open(path, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        write_ms = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        with open(path, "rb") as f:
            _ = f.read()
        read_ms = (time.perf_counter() - t1) * 1000.0
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    return {
        "write_ms": round(write_ms, 2),
        "read_ms": round(read_ms, 2),
        "total_ms": round(write_ms + read_ms, 2),
    }


def run_micro_benchmarks(alloc_mb: int = 128, probe_dir: Path | None = None) -> BenchmarkResult:
    """Execute the full suite of non-destructive responsiveness micro-benchmarks."""
    alloc_ms, alloc_gbps = bench_memory_alloc_touch(alloc_mb)
    jitter = bench_scheduler_jitter(iterations=40, sleep_ms=5.0)
    disk = bench_disk_io_latency(probe_dir=probe_dir, size_mb=4)
    return BenchmarkResult(
        captured_at=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        alloc_touch_mb=alloc_mb,
        alloc_touch_ms=alloc_ms,
        alloc_throughput_gbps=alloc_gbps,
        jitter_iterations=40,
        jitter_p50_ms=jitter["p50_ms"],
        jitter_p95_ms=jitter["p95_ms"],
        jitter_p99_ms=jitter["p99_ms"],
        jitter_max_ms=jitter["max_ms"],
        disk_write_ms=disk["write_ms"],
        disk_read_ms=disk["read_ms"],
        disk_total_ms=disk["total_ms"],
    )
