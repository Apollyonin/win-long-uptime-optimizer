"""UTF-8 CLI entry point for Windows 12-hour Automated Long-Uptime Performance Optimizer."""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path

from winopt.config import load_config
from winopt.engine import run_diagnose, run_optimization_cycle
from winopt.models import PolicyChange, PolicyState
from winopt.reporter import generate_html_dashboard
from winopt.scheduler import (
    export_task_xml,
    get_scheduled_task_status,
    install_scheduled_task,
    run_scheduled_task_now,
    uninstall_scheduled_task,
)
from winopt.storage import StorageManager
from winopt.web_console import serve_web_console


def _force_utf8_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        elif stream is not None and hasattr(stream, "buffer"):
            try:
                setattr(
                    sys,
                    stream_name,
                    io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace"),
                )
            except Exception:
                pass


def _print_diagnose(out) -> None:
    s = out.snapshot
    print("=== Windows 长运行性能深度诊断 (只读) ===")
    print(f"时间: {s.captured_at} | 管理员权限: {s.is_admin} | 连续开机: {s.uptime_hours:.1f} 小时 ({s.uptime_hours/24:.1f} 天)")
    print(f"重负载就绪度评分: {out.score.total:.1f} / 100 "
          f"(内存裕度 {out.score.memory_headroom:.1f}/30, Standby/分配 {out.score.standby_and_alloc:.1f}/25, "
          f"GPU {out.score.gpu_readiness:.1f}/20, 系统卫生 {out.score.system_hygiene:.1f}/15, 存储/电源 {out.score.storage_and_power:.1f}/10)")
    print(f"负载判定: {out.guard.profile} — {'; '.join(out.guard.reasons)}")
    print(
        f"内存: 可用 {s.available_ram_mb:.0f} / {s.total_ram_mb:.0f} MB ({100-s.ram_used_pct:.1f}% 空闲) | "
        f"Standby {s.standby_total_mb:.0f} MB | Modified {s.modified_list_mb:.0f} MB"
    )
    print(
        f"提交/内核: Commit {s.commit_total_mb:.0f}/{s.commit_limit_mb:.0f} MB ({s.commit_pct:.1f}%) | "
        f"非分页池 {s.kernel_nonpaged_mb:.0f} MB | 分页池 {s.kernel_paged_mb:.0f} MB | 总句柄 {s.total_handles}"
    )
    if s.gpu.present:
        print(
            f"GPU ({s.gpu.name}): 显存已用 {s.gpu.vram_used_mb:.0f}/{s.gpu.vram_total_mb:.0f} MB "
            f"(空闲 {s.gpu.vram_free_mb:.0f} MB) | 利用率 {s.gpu.utilization_gpu_pct:.0f}% | {s.gpu.temperature_c:.0f}C"
        )
    print(f"电源方案: {s.power_plan_name} | Timer 分辨率: {s.timer_res_current_ms} ms | DPC {s.dpc_time_pct:.1f}%")
    if out.bench:
        b = out.bench
        print(
            f"微基准: {b.alloc_touch_mb}MB 页分配耗时 {b.alloc_touch_ms:.1f} ms ({b.alloc_throughput_gbps:.2f} GB/s) | "
            f"调度抖动 P95 {b.jitter_p95_ms:.2f} ms | 磁盘探针 {b.disk_total_ms:.1f} ms"
        )

    print("\n--- 私有内存 Top 5 进程 ---")
    for p in sorted(s.processes, key=lambda x: x.private_mb, reverse=True)[:5]:
        print(f"  PID {p.pid:<6} {p.name:<28} 私有 {p.private_mb:>7.1f} MB | RSS {p.rss_mb:>7.1f} MB | 句柄 {p.handles}")

    vram_top = sorted(
        [p for p in s.processes if not p.vram_glitch and p.vram_dedicated_mb >= 50],
        key=lambda x: x.vram_dedicated_mb,
        reverse=True,
    )[:5]
    if vram_top:
        print("\n--- 专用显存 Top 5 进程 (已过滤 WDDM 异常计数) ---")
        for p in vram_top:
            print(f"  PID {p.pid:<6} {p.name:<28} 专用显存 {p.vram_dedicated_mb:>7.1f} MB")

    print(f"\n--- 泄漏检测 ({len(out.leaks)} 项) ---")
    if not out.leaks:
        print("  未发现显著泄漏。")
    else:
        for lk in out.leaks[:8]:
            rate = f" ({lk.growth_rate_per_hour:+.1f}/h)" if lk.growth_rate_per_hour is not None else ""
            print(f"  [{lk.severity}] {lk.process_name} [{lk.category}]: {lk.current_value:.1f}{rate} -> {lk.recommendation}")

    print(f"\n--- 查漏补缺 ({len(out.gaps)} 项) ---")
    if not out.gaps:
        print("  无显著瓶颈。")
    else:
        for g in out.gaps:
            print(f"  [{g.severity}] {g.title} ({g.metric_value}): {g.recommendation}")


def _print_cycle(out) -> None:
    ev = out.evaluation
    print(f"=== 优化执行完成 (run_id={out.run_id}, mode={out.mode}, dry_run={out.dry_run}) ===")
    print(f"负载策略: {out.guard.profile} — {'; '.join(out.guard.reasons)}")
    print(f"就绪度评分: T0 {ev.score_t0.total:.1f} -> T2 {ev.score_t2.total:.1f} ({ev.score_t2.total - ev.score_t0.total:+.1f})")
    print(
        f"可用内存: {out.t0.available_ram_mb:.0f} -> {out.t2.available_ram_mb:.0f} MB ({ev.net_available_ram_delta_mb:+.0f} MB) | "
        f"Standby: {out.t0.standby_total_mb:.0f} -> {out.t2.standby_total_mb:.0f} MB ({ev.net_standby_delta_mb:+.0f} MB) | "
        f"Commit: {out.t2.commit_pct:.1f}%"
    )
    if out.bench_t0 and out.bench_t1:
        print(
            f"微基准: 页分配 {out.bench_t0.alloc_touch_ms:.1f} -> {out.bench_t1.alloc_touch_ms:.1f} ms | "
            f"调度抖动 P95 {out.bench_t0.jitter_p95_ms:.2f} -> {out.bench_t1.jitter_p95_ms:.2f} ms"
        )
    print("\n--- 模块结果 ---")
    for m in out.module_results:
        print(f"  [{m.status}] {m.module_name:<15} {m.summary}")

    if ev.trimmed_total_mb > 0:
        print(
            f"\n工作集修剪与回弹: 修剪 {ev.trimmed_total_mb:.1f} MB | 回弹 {ev.rebound_total_mb:.1f} MB "
            f"({ev.overall_rebound_ratio*100:.1f}%) | 高回弹进程 {len(ev.rebounders)} 个"
        )

    print(f"\n--- 查漏补缺 ({len(ev.gaps)} 项) ---")
    if not ev.gaps:
        print("  无明显残余瓶颈。")
    else:
        for g in ev.gaps:
            print(f"  [{g.severity}] {g.title} ({g.metric_value}) -> {g.recommendation}")

    if out.iteration:
        print(f"\n--- 自迭代策略: {out.iteration.action} -> v{out.iteration.new_version} ---")
        print(f"  {out.iteration.rationale}")

    if out.md_report_path and out.html_dashboard_path:
        print(f"\n报告已生成:")
        print(f"  Markdown: {out.md_report_path}")
        print(f"  HTML 面板: {out.html_dashboard_path}")


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdio()
    parser = argparse.ArgumentParser(
        prog="winopt",
        description="Windows 12 小时自动长运行性能优化与闭环迭代系统",
    )
    parser.add_argument("--config", type=str, default=None, help="自定义 config.yaml 路径")
    sub = parser.add_subparsers(dest="command", required=True)

    # run
    p_run = sub.add_parser("run", help="执行一次完整闭环优化与验证")
    p_run.add_argument("--mode", choices=["manual", "scheduled"], default="manual")
    p_run.add_argument("--dry-run", action="store_true", help="仅预演不实际改动系统")
    p_run.add_argument("--settle-seconds", type=int, default=None, help="覆盖静置回弹观察秒数")
    p_run.add_argument("--no-bench", action="store_true", help="跳过微基准测试")

    # boost
    p_boost = sub.add_parser("boost", help="开启大型工程软件/游戏前的战前加速准备")
    p_boost.add_argument("--dry-run", action="store_true")
    p_boost.add_argument("--settle-seconds", type=int, default=8)
    p_boost.add_argument("--no-bench", action="store_true")

    # diagnose
    p_diag = sub.add_parser("diagnose", help="只读深度系统诊断、泄漏检查与查漏补缺")
    p_diag.add_argument("--no-bench", action="store_true")
    p_diag.add_argument("--json", action="store_true")

    # history
    p_hist = sub.add_parser("history", help="查看最近优化运行历史")
    p_hist.add_argument("--limit", type=int, default=10)

    # policy
    p_pol = sub.add_parser("policy", help="查看或回滚自迭代策略版本")
    pol_sub = p_pol.add_subparsers(dest="policy_action", required=True)
    pol_sub.add_parser("show")
    pol_sub.add_parser("history")
    p_rb = pol_sub.add_parser("rollback")
    p_rb.add_argument("version", type=int)

    # report
    sub.add_parser("report", help="根据数据库重新生成最新 HTML 面板")

    # web
    p_web = sub.add_parser("web", help="启动本地交互式 Web 控制台 (127.0.0.1)")
    p_web.add_argument("--port", type=int, default=18765, help="监听端口 (默认 18765，被占用时自动顺延)")
    p_web.add_argument("--open", action="store_true", help="自动打开浏览器")

    # schedule
    p_sched = sub.add_parser("schedule", help="管理 12 小时 Windows 计划任务")
    sched_sub = p_sched.add_subparsers(dest="schedule_action", required=True)
    sched_sub.add_parser("install")
    sched_sub.add_parser("uninstall")
    sched_sub.add_parser("status")
    sched_sub.add_parser("run-now")
    p_exp = sched_sub.add_parser("export-xml")
    p_exp.add_argument("--output", type=str, default=None)

    args = parser.parse_args(argv)
    cfg = load_config(config_path=args.config)

    if args.command == "diagnose":
        out = run_diagnose(cfg, run_bench=not args.no_bench)
        if args.json:
            payload = {
                "snapshot": out.snapshot.to_dict(include_processes=False),
                "bench": out.bench.to_dict() if out.bench else None,
                "score": out.score.to_dict(),
                "leaks": [lk.to_dict() for lk in out.leaks],
                "gaps": [g.to_dict() for g in out.gaps],
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            _print_diagnose(out)
        return 0

    if args.command == "run":
        out = run_optimization_cycle(
            cfg,
            mode="dry_run" if args.dry_run else args.mode,
            dry_run=bool(args.dry_run),
            settle_seconds=args.settle_seconds,
            run_bench=not args.no_bench,
        )
        _print_cycle(out)
        return 0

    if args.command == "boost":
        out = run_optimization_cycle(
            cfg,
            mode="boost",
            dry_run=bool(args.dry_run),
            settle_seconds=args.settle_seconds,
            run_bench=not args.no_bench,
        )
        _print_cycle(out)
        return 0

    store = StorageManager(cfg.db_path, cfg.policy_path)

    if args.command == "history":
        runs = store.get_recent_runs(limit=args.limit)
        if not runs:
            print("尚无优化运行记录。")
            return 0
        print(f"最近 {len(runs)} 次运行记录:")
        for r in runs:
            ev = r["summary"].get("evaluation", {})
            print(
                f"  {r['run_id']} | {r['started_at']} | {r['mode']}/{r['execution_profile']} | "
                f"v{r['policy_version']} | Score {r['score_t0']:.1f}->{r['score_t2']:.1f} | "
                f"RAM {ev.get('net_available_ram_delta_mb', 0):+.0f} MB | Commit {r['t2']['commit_pct']:.1f}%"
            )
        return 0

    if args.command == "policy":
        policy = store.ensure_policy(cfg)
        if args.policy_action == "show":
            print(json.dumps(policy.to_dict(), ensure_ascii=False, indent=2))
            return 0
        if args.policy_action == "history":
            for item in store.list_policy_history(limit=20):
                print(
                    f"  v{item['version']} ({item['action']}) [{item['created_at']}] -> {item['rationale']}"
                )
            return 0
        if args.policy_action == "rollback":
            target = store.get_policy_version(args.version)
            if target is None:
                print(f"未找到策略版本 v{args.version}", file=sys.stderr)
                return 1
            new_ver = policy.version + 1
            restored = PolicyState.from_dict(target.to_dict())
            restored.version = new_ver
            restored.last_known_good_version = args.version
            restored.pending_eval_from_version = None
            restored.pending_eval_profile = None
            rationale = f"用户手动回滚至历史版本 v{args.version}"
            store.save_policy_revision(
                state=restored,
                trigger_run_id=None,
                action="rollback",
                parent_version=args.version,
                changes=[
                    PolicyChange("manual_rollback", policy.version, args.version, rationale).__dict__
                ],
                rationale=rationale,
            )
            print(f"已创建策略 v{new_ver}（恢复自 v{args.version}）。")
            return 0

    if args.command == "report":
        latest = store.get_latest_run_details()
        if latest is None:
            print("数据库尚无记录，请先运行 `python -m winopt.cli run`。")
            return 1
        recent = store.get_recent_runs(limit=16)
        policy = store.ensure_policy(cfg)
        pol_hist = store.list_policy_history(limit=15)
        html_text = generate_html_dashboard(latest, recent, policy, pol_hist)
        out_html = cfg.reports_dir / "latest_dashboard.html"
        out_html.write_text(html_text, encoding="utf-8")
        print(f"已刷新 HTML 仪表盘: {out_html}")
        return 0

    if args.command == "schedule":
        if args.schedule_action == "export-xml":
            out_path = args.output or (cfg.data_dir / f"{cfg.schedule.task_name}.xml")
            saved = export_task_xml(cfg, out_path)
            print(f"已导出 12 小时计划任务 XML: {saved}")
            return 0
        if args.schedule_action == "install":
            ok, msg = install_scheduled_task(cfg)
            print(msg)
            return 0 if ok else 1
        if args.schedule_action == "uninstall":
            ok, msg = uninstall_scheduled_task(cfg)
            print(msg)
            return 0 if ok else 1
        if args.schedule_action == "run-now":
            ok, msg = run_scheduled_task_now(cfg)
            print(msg)
            return 0 if ok else 1
        if args.schedule_action == "status":
            st = get_scheduled_task_status(cfg)
            print(f"任务名: {st['task_name']} | 已安装: {st['installed']}")
            if st["raw"]:
                print(st["raw"])
            return 0

    if args.command == "web":
        serve_web_console(cfg, port=args.port, open_browser=bool(args.open))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
