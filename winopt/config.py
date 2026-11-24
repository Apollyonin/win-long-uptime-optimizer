"""Configuration loader and typed settings for winopt."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml


def _default_heavy_apps() -> list[str]:
    return [
        "ansys",
        "fluent",
        "abaqus",
        "comsol",
        "solidworks",
        "sldworks",
        "matlab",
        "autocad",
        "acad",
        "revit",
        "catia",
        "nx",
        "ugraf",
        "creo",
        "blender",
        "unreal",
        "ue4editor",
        "unrealeditor",
        "unity",
        "houdini",
        "maya",
        "3dsmax",
        "davinci",
        "resolve",
        "premiere",
        "afterfx",
        "cyberpunk2077",
        "eldenring",
        "blackmyth",
        "b1-win64-shipping",
        "valorant",
        "cs2",
        "genshinimpact",
        "starrail",
        "forza",
        "flightsimulator",
        "starcitizen",
        "dcs",
        "rdr2",
        "gta5",
        "hogwartslegacy",
        "monsterhunter",
        "wukong",
    ]


def _default_protected_processes() -> list[str]:
    return [
        "system",
        "registry",
        "idle",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "lsaext.exe",
        "svchost.exe",
        "dwm.exe",
        "explorer.exe",
        "audiodg.exe",
        "taskmgr.exe",
        "python.exe",
        "pythonw.exe",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "windowsterminal.exe",
        "antigravity.exe",
        "code.exe",
        "conhost.exe",
        "ctfmon.exe",
        "hipsdaemon.exe",
        "hipsmain.exe",
        "searchindexer.exe",
        "searchhost.exe",
        "startmenuexperiencehost.exe",
        "shellexperiencehost.exe",
        "textinputhost.exe",
        "fontdrvhost.exe",
        "memory compression",
        "nvcontainer.exe",
        "nvdisplay.container.exe",
        "nvidia overlay.exe",
        "todesk_service.exe",
        "todesk.exe",
    ]


def _default_background_demote() -> list[str]:
    return [
        "onedrivesetup.exe",
        "googleupdate.exe",
        "microsoftedgeupdate.exe",
        "tiworker.exe",
        "trustedinstaller.exe",
        "msiexec.exe",
    ]


@dataclass
class ScheduleConfig:
    interval_hours: int = 12
    task_name: str = "WinLongUptimeOptimizer"
    execution_time_limit_minutes: int = 30


@dataclass
class GuardConfig:
    enabled: bool = True
    cpu_busy_threshold_pct: float = 65.0
    gpu_busy_threshold_pct: float = 55.0
    downgrade_to_conservative_when_busy: bool = True
    heavy_app_processes: list[str] = field(default_factory=_default_heavy_apps)


@dataclass
class MemoryConfig:
    standby_purge_min_mb: int = 1536
    flush_modified_list: bool = True
    modified_flush_min_mb: int = 64
    combine_physical_memory: bool = True
    purge_low_priority_standby_only_in_conservative: bool = True


@dataclass
class WorkingSetConfig:
    enabled: bool = True
    min_working_set_mb: int = 120
    min_uptime_seconds: int = 300
    max_cpu_pct_for_trim: float = 2.0
    protected_processes: list[str] = field(default_factory=_default_protected_processes)


@dataclass
class GpuConfig:
    vram_hog_warn_mb: float = 500.0
    dwm_vram_warn_mb: float = 600.0
    clean_stale_shader_temp: bool = True
    shader_temp_max_age_days: int = 30


@dataclass
class StorageConfig:
    clean_temp_files: bool = True
    temp_min_age_hours: int = 24
    clean_wer_dumps: bool = True
    ssd_retrim_enabled: bool = True
    ssd_retrim_min_interval_hours: int = 24
    min_free_disk_pct: float = 15.0


@dataclass
class NetworkConfig:
    flush_dns: bool = True
    socket_warn_threshold: int = 2000


@dataclass
class CpuPowerConfig:
    audit_power_plan: bool = True
    switch_high_perf_in_boost_mode: bool = True
    background_demote_processes: list[str] = field(default_factory=_default_background_demote)


@dataclass
class VerificationConfig:
    settle_seconds: int = 20
    run_micro_benchmarks: bool = True
    alloc_bench_mb: int = 128
    rebound_threshold_ratio: float = 0.70


@dataclass
class LeakDetectionConfig:
    min_samples_for_trend: int = 2
    private_mb_per_hour_warn: float = 20.0
    private_mb_per_hour_crit: float = 80.0
    private_abs_warn_mb: float = 2500.0
    handle_warn_count: int = 5000
    handle_per_hour_warn: float = 100.0
    gdi_warn_count: int = 2000
    user_obj_warn_count: int = 2000
    vram_warn_mb: float = 800.0
    vram_per_hour_warn: float = 30.0
    nonpaged_pool_warn_mb: float = 1200.0
    commit_pct_warn: float = 75.0
    commit_pct_crit: float = 88.0


@dataclass
class IterationBounds:
    standby_purge_min_mb: tuple[int, int] = (512, 4096)
    min_working_set_mb: tuple[int, int] = (60, 512)
    min_uptime_seconds: tuple[int, int] = (120, 1800)


@dataclass
class IterationConfig:
    enabled: bool = True
    rebound_exclude_strikes: int = 2
    rollback_score_drop_threshold: float = 5.0
    rollback_alloc_latency_increase_pct: float = 35.0
    bounds: IterationBounds = field(default_factory=IterationBounds)


@dataclass
class OptimizerConfig:
    workspace_dir: Path
    data_dir: Path
    reports_dir: Path
    db_path: Path
    policy_path: Path
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    guard: GuardConfig = field(default_factory=GuardConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    working_set: WorkingSetConfig = field(default_factory=WorkingSetConfig)
    gpu: GpuConfig = field(default_factory=GpuConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    cpu_power: CpuPowerConfig = field(default_factory=CpuPowerConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    leak_detection: LeakDetectionConfig = field(default_factory=LeakDetectionConfig)
    iteration: IterationConfig = field(default_factory=IterationConfig)

    def to_dict(self) -> dict[str, Any]:
        raw = asdict(self)
        for key in ("workspace_dir", "data_dir", "reports_dir", "db_path", "policy_path"):
            raw[key] = str(raw[key])
        return raw


def _merge_dataclass(cls: type, base_obj: Any, override: dict[str, Any] | None) -> Any:
    if not override:
        return base_obj
    kwargs: dict[str, Any] = {}
    for field_name in cls.__dataclass_fields__:
        current = getattr(base_obj, field_name)
        if field_name not in override:
            kwargs[field_name] = current
            continue
        val = override[field_name]
        if field_name == "bounds" and isinstance(val, dict):
            b_kwargs = {}
            for bf in IterationBounds.__dataclass_fields__:
                bv = val.get(bf, getattr(current, bf))
                b_kwargs[bf] = (int(bv[0]), int(bv[1]))
            kwargs[field_name] = IterationBounds(**b_kwargs)
        elif isinstance(current, list) and isinstance(val, list):
            kwargs[field_name] = [str(x).lower() for x in val]
        else:
            kwargs[field_name] = val
    return cls(**kwargs)


def load_config(
    config_path: str | Path | None = None,
    workspace_dir: str | Path | None = None,
    data_dir: str | Path | None = None,
    reports_dir: str | Path | None = None,
) -> OptimizerConfig:
    """Load config.yaml merged over defaults and resolve project paths."""
    if workspace_dir is None:
        ws = Path(__file__).resolve().parent.parent
    else:
        ws = Path(workspace_dir).resolve()

    cfg_file = Path(config_path).resolve() if config_path else (ws / "config.yaml")
    raw: dict[str, Any] = {}
    if cfg_file.exists():
        loaded = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            raw = loaded

    resolved_data = Path(data_dir).resolve() if data_dir else (ws / "data")
    resolved_reports = Path(reports_dir).resolve() if reports_dir else (ws / "reports")
    resolved_data.mkdir(parents=True, exist_ok=True)
    resolved_reports.mkdir(parents=True, exist_ok=True)

    cfg = OptimizerConfig(
        workspace_dir=ws,
        data_dir=resolved_data,
        reports_dir=resolved_reports,
        db_path=resolved_data / "optimizer.db",
        policy_path=resolved_data / "policy_state.json",
        schedule=_merge_dataclass(ScheduleConfig, ScheduleConfig(), raw.get("schedule")),
        guard=_merge_dataclass(GuardConfig, GuardConfig(), raw.get("guard")),
        memory=_merge_dataclass(MemoryConfig, MemoryConfig(), raw.get("memory")),
        working_set=_merge_dataclass(WorkingSetConfig, WorkingSetConfig(), raw.get("working_set")),
        gpu=_merge_dataclass(GpuConfig, GpuConfig(), raw.get("gpu")),
        storage=_merge_dataclass(StorageConfig, StorageConfig(), raw.get("storage")),
        network=_merge_dataclass(NetworkConfig, NetworkConfig(), raw.get("network")),
        cpu_power=_merge_dataclass(CpuPowerConfig, CpuPowerConfig(), raw.get("cpu_power")),
        verification=_merge_dataclass(VerificationConfig, VerificationConfig(), raw.get("verification")),
        leak_detection=_merge_dataclass(LeakDetectionConfig, LeakDetectionConfig(), raw.get("leak_detection")),
        iteration=_merge_dataclass(IterationConfig, IterationConfig(), raw.get("iteration")),
    )
    return cfg
