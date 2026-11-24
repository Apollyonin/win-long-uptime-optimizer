"""Shared typed data models for winopt."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ProcessMetric:
    pid: int
    name: str
    exe: str = ""
    create_time: float = 0.0
    rss_mb: float = 0.0
    private_mb: float = 0.0
    handles: int = 0
    gdi_objects: int = 0
    user_objects: int = 0
    vram_dedicated_mb: float = 0.0
    vram_shared_mb: float = 0.0
    vram_glitch: bool = False
    cpu_pct: float = 0.0
    threads: int = 0


@dataclass
class GpuTelemetry:
    present: bool = False
    name: str = ""
    vram_total_mb: float = 0.0
    vram_used_mb: float = 0.0
    vram_free_mb: float = 0.0
    utilization_gpu_pct: float = 0.0
    temperature_c: float = 0.0
    pstate: str = ""


@dataclass
class DiskTelemetry:
    drive: str
    total_gb: float
    free_gb: float
    free_pct: float


@dataclass
class SystemSnapshot:
    captured_at: str
    uptime_hours: float
    is_admin: bool
    cpu_pct: float
    dpc_time_pct: float
    interrupt_time_pct: float
    processor_queue_len: float
    timer_res_current_ms: float
    timer_res_min_ms: float
    timer_res_max_ms: float
    power_plan_guid: str
    power_plan_name: str
    total_ram_mb: float
    available_ram_mb: float
    ram_used_pct: float
    standby_normal_mb: float
    standby_reserve_mb: float
    standby_core_mb: float
    standby_total_mb: float
    modified_list_mb: float
    commit_total_mb: float
    commit_limit_mb: float
    commit_pct: float
    kernel_nonpaged_mb: float
    kernel_paged_mb: float
    system_cache_mb: float
    total_handles: int
    total_processes: int
    total_threads: int
    foreground_pid: int | None
    foreground_name: str
    gpu: GpuTelemetry = field(default_factory=GpuTelemetry)
    disks: list[DiskTelemetry] = field(default_factory=list)
    tcp_counts: dict[str, int] = field(default_factory=dict)
    vram_glitch_count: int = 0
    processes: list[ProcessMetric] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self, include_processes: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_processes:
            data.pop("processes", None)
        return data


@dataclass
class BenchmarkResult:
    captured_at: str
    alloc_touch_mb: int = 0
    alloc_touch_ms: float = 0.0
    alloc_throughput_gbps: float = 0.0
    jitter_iterations: int = 0
    jitter_p50_ms: float = 0.0
    jitter_p95_ms: float = 0.0
    jitter_p99_ms: float = 0.0
    jitter_max_ms: float = 0.0
    disk_write_ms: float = 0.0
    disk_read_ms: float = 0.0
    disk_total_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GuardDecision:
    profile: str  # "full" | "conservative" | "deferred"
    reasons: list[str] = field(default_factory=list)
    active_heavy_apps: list[str] = field(default_factory=list)
    active_heavy_pids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActionResult:
    module_name: str
    status: str  # "ok" | "skipped" | "error" | "dry_run"
    duration_ms: float = 0.0
    reclaimed_mb: float = 0.0
    items_processed: int = 0
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LeakEvent:
    detected_at: str
    severity: str  # "INFO" | "WARN" | "CRITICAL"
    category: str  # "private_mem" | "handles" | "gdi" | "user_obj" | "vram" | "nonpaged_pool" | "commit"
    pid: int
    process_name: str
    current_value: float
    growth_rate_per_hour: float | None
    recommendation: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GapFinding:
    severity: str  # "INFO" | "WARN" | "CRITICAL"
    code: str
    title: str
    description: str
    metric_value: str
    recommendation: str
    auto_action_taken: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReboundItem:
    pid: int
    name: str
    before_mb: float
    after_trim_mb: float
    settled_mb: float
    trimmed_mb: float
    rebound_mb: float
    rebound_ratio: float


@dataclass
class ScoreBreakdown:
    total: float
    memory_headroom: float
    standby_and_alloc: float
    gpu_readiness: float
    system_hygiene: float
    storage_and_power: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationReport:
    score_t0: ScoreBreakdown
    score_t1: ScoreBreakdown | None
    score_t2: ScoreBreakdown
    net_available_ram_delta_mb: float
    net_standby_delta_mb: float
    net_commit_delta_pct: float
    alloc_latency_delta_ms: float | None
    jitter_p95_delta_ms: float | None
    trimmed_total_mb: float
    rebound_total_mb: float
    overall_rebound_ratio: float
    rebounders: list[ReboundItem] = field(default_factory=list)
    non_rebounders: list[ReboundItem] = field(default_factory=list)
    gaps: list[GapFinding] = field(default_factory=list)
    verdict: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyChange:
    field: str
    old_value: Any
    new_value: Any
    reason: str


@dataclass
class PolicyState:
    version: int = 1
    standby_purge_min_mb: int = 1536
    min_working_set_mb: int = 120
    min_uptime_seconds: int = 300
    dynamic_trim_exclude: list[str] = field(default_factory=list)
    rebound_strikes: dict[str, int] = field(default_factory=dict)
    leak_watchlist: list[str] = field(default_factory=list)
    module_enabled: dict[str, bool] = field(
        default_factory=lambda: {
            "memory_lists": True,
            "working_set": True,
            "gpu_readiness": True,
            "cpu_power": True,
            "storage_temp": True,
            "network_dns": True,
        }
    )
    module_roi_ema: dict[str, float] = field(default_factory=dict)
    module_zero_streak: dict[str, int] = field(default_factory=dict)
    last_ssd_retrim_iso: str | None = None
    last_known_good_version: int = 1
    pending_eval_from_version: int | None = None
    pending_eval_profile: str | None = None
    baseline_score_t2: float | None = None
    baseline_alloc_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PolicyState:
        defaults = cls()
        kwargs: dict[str, Any] = {}
        for f_name in cls.__dataclass_fields__:
            kwargs[f_name] = raw.get(f_name, getattr(defaults, f_name))
        return cls(**kwargs)
