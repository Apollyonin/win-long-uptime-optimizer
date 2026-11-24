"""Bounded self-iteration engine with regression rollback protection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from winopt.config import OptimizerConfig
from winopt.models import (
    ActionResult,
    BenchmarkResult,
    EvaluationReport,
    LeakEvent,
    PolicyChange,
    PolicyState,
    SystemSnapshot,
)
from winopt.storage import StorageManager


@dataclass
class IterationOutcome:
    action: str  # "none" | "iterate" | "rollback"
    new_version: int
    changes: list[PolicyChange]
    rationale: str


def _clamp(val: int, bounds: tuple[int, int]) -> int:
    lo, hi = int(bounds[0]), int(bounds[1])
    return max(lo, min(hi, int(val)))


def iterate_policy(
    run_id: str,
    execution_profile: str,
    policy: PolicyState,
    t0: SystemSnapshot,
    t2: SystemSnapshot,
    bench_t1: BenchmarkResult | None,
    module_results: list[ActionResult],
    evaluation: EvaluationReport,
    leaks: list[LeakEvent],
    cfg: OptimizerConfig,
    storage: StorageManager,
) -> IterationOutcome:
    """Evaluate prior iteration outcome (rollback on regression) and tune bounded policy."""
    if not cfg.iteration.enabled:
        storage.update_current_policy_metadata(policy)
        return IterationOutcome(
            action="none",
            new_version=policy.version,
            changes=[],
            rationale="配置已禁用自迭代策略调整",
        )

    cur_alloc_ms = bench_t1.alloc_touch_ms if bench_t1 is not None else None
    cur_score_t2 = evaluation.score_t2.total

    # 1. Check whether previous policy mutation caused a measurable regression
    if (
        policy.pending_eval_from_version is not None
        and policy.pending_eval_profile == execution_profile
        and policy.baseline_score_t2 is not None
    ):
        score_drop = policy.baseline_score_t2 - cur_score_t2
        alloc_regressed = (
            policy.baseline_alloc_ms is not None
            and cur_alloc_ms is not None
            and policy.baseline_alloc_ms > 15.0
            and cur_alloc_ms
            > policy.baseline_alloc_ms
            * (1.0 + cfg.iteration.rollback_alloc_latency_increase_pct / 100.0)
        )
        score_regressed = score_drop >= cfg.iteration.rollback_score_drop_threshold

        if score_regressed or alloc_regressed:
            target_ver = policy.last_known_good_version
            good_state = storage.get_policy_version(target_ver)
            if good_state is not None:
                old_ver = policy.version
                next_ver = old_ver + 1
                reasons: list[str] = []
                if score_regressed:
                    reasons.append(
                        f"T2 就绪度评分从基准 {policy.baseline_score_t2:.1f} 降至 {cur_score_t2:.1f} (下降 {score_drop:.1f} 分)"
                    )
                if alloc_regressed:
                    reasons.append(
                        f"内存分配延迟从 {policy.baseline_alloc_ms:.1f} ms 升至 {cur_alloc_ms:.1f} ms"
                    )
                rationale = f"检测到策略 v{old_ver} 性能退化（{'; '.join(reasons)}），自动回滚到稳定版 v{target_ver}"

                restored = PolicyState.from_dict(good_state.to_dict())
                restored.version = next_ver
                restored.last_known_good_version = target_ver
                restored.pending_eval_from_version = None
                restored.pending_eval_profile = None
                restored.baseline_score_t2 = None
                restored.baseline_alloc_ms = None
                restored.last_ssd_retrim_iso = policy.last_ssd_retrim_iso

                changes = [
                    PolicyChange(
                        field="policy_version_rollback",
                        old_value=old_ver,
                        new_value=target_ver,
                        reason=rationale,
                    )
                ]
                storage.save_policy_revision(
                    state=restored,
                    trigger_run_id=run_id,
                    action="rollback",
                    parent_version=target_ver,
                    changes=[c.__dict__ for c in changes],
                    rationale=rationale,
                )
                return IterationOutcome(
                    action="rollback",
                    new_version=next_ver,
                    changes=changes,
                    rationale=rationale,
                )

        # No regression -> promote current policy version as known-good
        policy.last_known_good_version = policy.version
        policy.pending_eval_from_version = None
        policy.pending_eval_profile = None
        policy.baseline_score_t2 = None
        policy.baseline_alloc_ms = None

    # 2. Update module ROI exponential moving average
    for mod in module_results:
        if mod.status != "ok":
            continue
        roi = round(mod.reclaimed_mb + (10.0 if mod.items_processed > 0 else 0.0), 2)
        prev_ema = policy.module_roi_ema.get(mod.module_name, roi)
        policy.module_roi_ema[mod.module_name] = round(0.6 * prev_ema + 0.4 * roi, 2)
        if mod.reclaimed_mb < 1.0 and mod.items_processed == 0:
            policy.module_zero_streak[mod.module_name] = (
                policy.module_zero_streak.get(mod.module_name, 0) + 1
            )
        else:
            policy.module_zero_streak[mod.module_name] = 0

    # 3. Promote active WARN/CRITICAL leakers to leak_watchlist
    watchlist_set = {x.lower(): x for x in policy.leak_watchlist}
    for lk in leaks:
        if lk.pid > 0 and lk.severity in ("WARN", "CRITICAL"):
            key = lk.process_name.lower()
            if key not in watchlist_set:
                watchlist_set[key] = lk.process_name
    policy.leak_watchlist = sorted(watchlist_set.values())

    # 4. Track per-process working set rebound strikes & bounded parameter tuning
    changes: list[PolicyChange] = []
    rebound_names = {r.name.lower() for r in evaluation.rebounders}
    non_rebound_names = {r.name.lower() for r in evaluation.non_rebounders}
    exclude_set = {x.lower() for x in policy.dynamic_trim_exclude}
    newly_excluded: list[str] = []

    for rname in rebound_names:
        strikes = policy.rebound_strikes.get(rname, 0) + 1
        policy.rebound_strikes[rname] = strikes
        if strikes >= cfg.iteration.rebound_exclude_strikes and rname not in exclude_set:
            exclude_set.add(rname)
            newly_excluded.append(rname)

    for nrname in non_rebound_names - rebound_names:
        if nrname in policy.rebound_strikes and policy.rebound_strikes[nrname] > 0:
            policy.rebound_strikes[nrname] -= 1

    if newly_excluded:
        old_list = list(policy.dynamic_trim_exclude)
        policy.dynamic_trim_exclude = sorted(exclude_set)
        changes.append(
            PolicyChange(
                field="dynamic_trim_exclude",
                old_value=old_list,
                new_value=list(policy.dynamic_trim_exclude),
                reason=(
                    f"进程 {', '.join(newly_excluded)} 连续 {cfg.iteration.rebound_exclude_strikes} 次修剪后高比例回弹，"
                    "自动加入动态排除名单以避免无谓页错误"
                ),
            )
        )

    bounds = cfg.iteration.bounds

    # Tune min_working_set_mb & min_uptime_seconds based on rebound rate vs memory scarcity
    if (
        evaluation.trimmed_total_mb >= 50.0
        and evaluation.overall_rebound_ratio > 0.65
        and (evaluation.trimmed_total_mb - evaluation.rebound_total_mb) < 120.0
    ):
        new_ws = _clamp(policy.min_working_set_mb + 30, bounds.min_working_set_mb)
        if new_ws != policy.min_working_set_mb:
            changes.append(
                PolicyChange(
                    field="min_working_set_mb",
                    old_value=policy.min_working_set_mb,
                    new_value=new_ws,
                    reason=(
                        f"本轮工作集整体回弹率过高 ({evaluation.overall_rebound_ratio * 100:.0f}%)，"
                        "提高修剪门槛以减少无效抖动"
                    ),
                )
            )
            policy.min_working_set_mb = new_ws

        new_up = _clamp(policy.min_uptime_seconds + 120, bounds.min_uptime_seconds)
        if new_up != policy.min_uptime_seconds:
            changes.append(
                PolicyChange(
                    field="min_uptime_seconds",
                    old_value=policy.min_uptime_seconds,
                    new_value=new_up,
                    reason="适当延长最小存活门槛，避开刚启动不久的进程",
                )
            )
            policy.min_uptime_seconds = new_up
    else:
        t2_avail_pct = (t2.available_ram_mb / t2.total_ram_mb * 100.0) if t2.total_ram_mb > 0 else 100.0
        if (
            t2_avail_pct < 25.0
            and evaluation.overall_rebound_ratio < 0.30
            and evaluation.trimmed_total_mb < 150.0
        ):
            new_ws = _clamp(policy.min_working_set_mb - 20, bounds.min_working_set_mb)
            if new_ws != policy.min_working_set_mb:
                changes.append(
                    PolicyChange(
                        field="min_working_set_mb",
                        old_value=policy.min_working_set_mb,
                        new_value=new_ws,
                        reason=(
                            f"可用物理内存紧张 ({t2_avail_pct:.1f}%) 且工作集回弹率低 ({evaluation.overall_rebound_ratio * 100:.0f}%)，"
                            "适度下调修剪阈值以腾出更多物理内存"
                        ),
                    )
                )
                policy.min_working_set_mb = new_ws

    # Tune standby_purge_min_mb if T0 had moderate standby below threshold AND slow page allocation
    if (
        512 <= t0.standby_total_mb < policy.standby_purge_min_mb
        and cur_alloc_ms is not None
        and cur_alloc_ms > 120.0
    ):
        new_sb = _clamp(policy.standby_purge_min_mb - 256, bounds.standby_purge_min_mb)
        if new_sb != policy.standby_purge_min_mb:
            changes.append(
                PolicyChange(
                    field="standby_purge_min_mb",
                    old_value=policy.standby_purge_min_mb,
                    new_value=new_sb,
                    reason=(
                        f"T0 Standby ({t0.standby_total_mb:.0f} MB) 未触发清理但内存分配较慢 ({cur_alloc_ms:.1f} ms)，"
                        "适当降低 Standby 清理触发阈值"
                    ),
                )
            )
            policy.standby_purge_min_mb = new_sb

    if changes:
        parent_ver = policy.version
        policy.last_known_good_version = parent_ver
        policy.version = parent_ver + 1
        policy.pending_eval_from_version = parent_ver
        policy.pending_eval_profile = execution_profile
        policy.baseline_score_t2 = cur_score_t2
        policy.baseline_alloc_ms = cur_alloc_ms

        rationale = "；".join(c.reason for c in changes)
        storage.save_policy_revision(
            state=policy,
            trigger_run_id=run_id,
            action="iterate",
            parent_version=parent_ver,
            changes=[c.__dict__ for c in changes],
            rationale=rationale,
        )
        return IterationOutcome(
            action="iterate",
            new_version=policy.version,
            changes=changes,
            rationale=rationale,
        )

    storage.update_current_policy_metadata(policy)
    return IterationOutcome(
        action="none",
        new_version=policy.version,
        changes=[],
        rationale="当前策略表现稳定，无需调整参数",
    )
