"""Core orchestration engine closing the loop from telemetry -> optimization -> verification -> iteration."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from winopt.benchmark import run_micro_benchmarks
from winopt.config import OptimizerConfig
from winopt.evaluator import analyze_gaps, compute_readiness_score, evaluate_run
from winopt.iterator import IterationOutcome, iterate_policy
from winopt.leak_detector import detect_leaks
from winopt.models import (
    ActionResult,
    BenchmarkResult,
    EvaluationReport,
    GapFinding,
    GuardDecision,
    LeakEvent,
    PolicyState,
    ScoreBreakdown,
    SystemSnapshot,
)
from winopt.optimizers import (
    BaseOptimizer,
    CpuPowerOptimizer,
    GpuReadinessOptimizer,
    MemoryListsOptimizer,
    NetworkDnsOptimizer,
    StorageTempOptimizer,
    WorkingSetOptimizer,
)
from winopt.optimizers.base import OptimizationContext
from winopt.reporter import write_reports
from winopt.storage import StorageManager, utc_now_iso
from winopt.telemetry import collect_snapshot
from winopt.workload_guard import evaluate_workload_guard


@dataclass
class CycleOutput:
    run_id: str
    mode: str
    dry_run: bool
    guard: GuardDecision
    t0: SystemSnapshot
    t1: SystemSnapshot | None
    t2: SystemSnapshot
    bench_t0: BenchmarkResult | None
    bench_t1: BenchmarkResult | None
    module_results: list[ActionResult]
    leaks: list[LeakEvent]
    evaluation: EvaluationReport
    policy: PolicyState
    iteration: IterationOutcome | None
    md_report_path: Path | None
    html_dashboard_path: Path | None


@dataclass
class DiagnoseOutput:
    snapshot: SystemSnapshot
    bench: BenchmarkResult | None
    guard: GuardDecision
    score: ScoreBreakdown
    leaks: list[LeakEvent]
    gaps: list[GapFinding]


def _default_optimizers() -> list[BaseOptimizer]:
    return [
        MemoryListsOptimizer(),
        WorkingSetOptimizer(),
        GpuReadinessOptimizer(),
        CpuPowerOptimizer(),
        StorageTempOptimizer(),
        NetworkDnsOptimizer(),
    ]


def run_diagnose(
    cfg: OptimizerConfig,
    run_bench: bool = True,
    storage: StorageManager | None = None,
    snapshot_fn: Callable[..., SystemSnapshot] | None = None,
    bench_fn: Callable[..., BenchmarkResult] | None = None,
) -> DiagnoseOutput:
    """Perform a non-destructive read-only system health, leak, and gap diagnosis."""
    store = storage or StorageManager(cfg.db_path, cfg.policy_path)
    snap_call = snapshot_fn or collect_snapshot
    bench_call = bench_fn or run_micro_benchmarks

    snap = snap_call(cfg, include_processes=True)
    bench = (
        bench_call(cfg.verification.alloc_bench_mb, cfg.data_dir)
        if (run_bench and cfg.verification.run_micro_benchmarks)
        else None
    )
    guard = evaluate_workload_guard(snap, cfg, mode="manual")
    leaks = detect_leaks(snap, cfg, store, guard=guard)
    score = compute_readiness_score(snap, bench, cfg, leaks=leaks)
    gaps = analyze_gaps(snap, bench, [], leaks, [], cfg)
    return DiagnoseOutput(
        snapshot=snap,
        bench=bench,
        guard=guard,
        score=score,
        leaks=leaks,
        gaps=gaps,
    )


def run_optimization_cycle(
    cfg: OptimizerConfig,
    mode: str = "manual",
    dry_run: bool = False,
    settle_seconds: int | None = None,
    run_bench: bool | None = None,
    storage: StorageManager | None = None,
    snapshot_fn: Callable[..., SystemSnapshot] | None = None,
    bench_fn: Callable[..., BenchmarkResult] | None = None,
    optimizers: list[BaseOptimizer] | None = None,
) -> CycleOutput:
    """Execute one full closed-loop optimization, verification, gap-check, and iteration cycle."""
    store = storage or StorageManager(cfg.db_path, cfg.policy_path)
    snap_call = snapshot_fn or collect_snapshot
    bench_call = bench_fn or run_micro_benchmarks
    mods = optimizers or _default_optimizers()

    started_at = utc_now_iso()
    run_id = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    policy = store.ensure_policy(cfg)

    do_bench = cfg.verification.run_micro_benchmarks if run_bench is None else bool(run_bench)
    settle_s = cfg.verification.settle_seconds if settle_seconds is None else max(0, int(settle_seconds))
    if dry_run:
        settle_s = 0

    # Phase T0: Pre-optimization baseline
    t0 = snap_call(cfg, include_processes=True)
    bench_t0 = bench_call(cfg.verification.alloc_bench_mb, cfg.data_dir) if do_bench else None

    # Workload Guard
    guard = evaluate_workload_guard(t0, cfg, mode=mode)
    ctx = OptimizationContext(
        mode=mode,
        dry_run=dry_run,
        guard=guard,
        t0=t0,
        policy=policy,
        config=cfg,
    )

    # Execute modular optimizers safely
    module_results: list[ActionResult] = []
    for mod in mods:
        if not policy.module_enabled.get(mod.name, True):
            module_results.append(
                ActionResult(
                    module_name=mod.name,
                    status="skipped",
                    summary="策略配置已禁用此模块",
                )
            )
            continue
        try:
            res = mod.run(ctx)
        except Exception as exc:
            res = ActionResult(
                module_name=mod.name,
                status="error",
                summary=f"模块执行异常: {exc}",
                warnings=[str(exc)],
            )
        res.details.setdefault("summary", res.summary)
        module_results.append(res)

    # Phase T1: Immediate post-optimization snapshot
    t1 = snap_call(cfg, include_processes=False) if not dry_run else None

    # Settle wait to observe rebound / true sustained effect
    if settle_s > 0:
        time.sleep(settle_s)

    # Phase T2: Settled snapshot & post-optimization benchmark
    t2 = t0 if dry_run else snap_call(cfg, include_processes=True)
    bench_t1 = (
        bench_call(cfg.verification.alloc_bench_mb, cfg.data_dir)
        if (do_bench and not dry_run)
        else bench_t0
    )

    # Leak detection & Effectiveness + Gap evaluation
    leaks_t0 = detect_leaks(t0, cfg, store, guard=guard)
    leaks = leaks_t0 if dry_run else detect_leaks(t2, cfg, store, guard=guard)
    evaluation = evaluate_run(
        t0=t0,
        t1=t1,
        t2=t2,
        bench_t0=bench_t0,
        bench_t1=bench_t1,
        module_results=module_results,
        leaks=leaks,
        cfg=cfg,
        leaks_t0=leaks_t0,
    )

    iteration_outcome: IterationOutcome | None = None
    md_path: Path | None = None
    html_path: Path | None = None
    finished_at = utc_now_iso()

    if not dry_run:
        iteration_outcome = iterate_policy(
            run_id=run_id,
            execution_profile=guard.profile,
            policy=policy,
            t0=t0,
            t2=t2,
            bench_t1=bench_t1,
            module_results=module_results,
            evaluation=evaluation,
            leaks=leaks,
            cfg=cfg,
            storage=store,
        )

        # Reload updated policy state (in case rollback replaced policy object)
        policy = store.ensure_policy(cfg)

        summary_payload = {
            "guard": guard.to_dict(),
            "evaluation": evaluation.to_dict(),
            "module_summaries": {m.module_name: m.summary for m in module_results},
            "iteration": {
                "action": iteration_outcome.action,
                "new_version": iteration_outcome.new_version,
                "rationale": iteration_outcome.rationale,
                "changes": [c.__dict__ for c in iteration_outcome.changes],
            },
        }
        store.save_run(
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            mode=mode,
            execution_profile=guard.profile,
            policy_version=policy.version,
            t0=t0,
            t1=t1,
            t2=t2,
            bench_t0=bench_t0,
            bench_t1=bench_t1,
            score_t0=evaluation.score_t0.total,
            score_t1=evaluation.score_t1.total if evaluation.score_t1 else None,
            score_t2=evaluation.score_t2.total,
            summary=summary_payload,
            module_results=module_results,
            leak_events=leaks,
            gap_findings=evaluation.gaps,
            save_process_phases=(("t2", t2),),
        )
        store.prune_old_process_snapshots(retain_days=30)

        latest_rec = store.get_latest_run_details()
        recent = store.get_recent_runs(limit=16)
        pol_hist = store.list_policy_history(limit=15)
        if latest_rec is not None:
            md_path, html_path = write_reports(
                cfg=cfg,
                run_id=run_id,
                mode=mode,
                guard=guard,
                t0=t0,
                t1=t1,
                t2=t2,
                bench_t0=bench_t0,
                bench_t1=bench_t1,
                module_results=module_results,
                leaks=leaks,
                evaluation=evaluation,
                policy=policy,
                iteration=iteration_outcome,
                latest_run_record=latest_rec,
                recent_runs=recent,
                policy_history=pol_hist,
            )

    return CycleOutput(
        run_id=run_id,
        mode=mode,
        dry_run=dry_run,
        guard=guard,
        t0=t0,
        t1=t1,
        t2=t2,
        bench_t0=bench_t0,
        bench_t1=bench_t1,
        module_results=module_results,
        leaks=leaks,
        evaluation=evaluation,
        policy=policy,
        iteration=iteration_outcome,
        md_report_path=md_path,
        html_dashboard_path=html_path,
    )
