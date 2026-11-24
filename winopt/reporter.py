"""Markdown & self-contained offline HTML Dashboard reporter with SVG trend charts."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

from winopt.config import OptimizerConfig
from winopt.iterator import IterationOutcome
from winopt.models import (
    ActionResult,
    BenchmarkResult,
    EvaluationReport,
    GuardDecision,
    LeakEvent,
    PolicyState,
    SystemSnapshot,
)


def _fmt_delta(val: float | None, unit: str = "", invert_good: bool = False) -> str:
    if val is None:
        return "-"
    sign = "+" if val > 0 else ""
    return f"{sign}{val:.1f}{unit}"


def generate_markdown_report(
    run_id: str,
    mode: str,
    guard: GuardDecision,
    t0: SystemSnapshot,
    t1: SystemSnapshot | None,
    t2: SystemSnapshot,
    bench_t0: BenchmarkResult | None,
    bench_t1: BenchmarkResult | None,
    module_results: list[ActionResult],
    leaks: list[LeakEvent],
    evaluation: EvaluationReport,
    policy: PolicyState,
    iteration: IterationOutcome | None,
) -> str:
    lines: list[str] = []
    lines.append(f"# Windows 长运行性能优化报告 (`{run_id}`)")
    lines.append("")
    lines.append(f"- **执行时间**: {t2.captured_at}")
    lines.append(f"- **运行模式**: `{mode}` | **执行配置**: `{guard.profile}` | **管理员权限**: `{t2.is_admin}`")
    lines.append(f"- **系统已连续开机**: `{t2.uptime_hours:.1f} 小时 ({t2.uptime_hours / 24.0:.1f} 天)`")
    lines.append(f"- **策略版本**: `v{policy.version}` (最近迭代动作: `{iteration.action if iteration else 'diagnose'}`)")
    lines.append(f"- **核心结论**: {evaluation.verdict}")
    lines.append("")

    # Score summary
    s0 = evaluation.score_t0
    s2 = evaluation.score_t2
    lines.append("## 1. 重负载软件就绪度评分 (0-100)")
    lines.append("")
    lines.append(f"| 维度 | 满分 | 优化前 (T0) | 静置后 (T2) | 变化 |")
    lines.append("|---|---:|---:|---:|---:|")
    lines.append(f"| **总分 (Readiness Score)** | **100** | **{s0.total:.1f}** | **{s2.total:.1f}** | **{s2.total - s0.total:+.1f}** |")
    lines.append(f"| 可用内存与 Commit 裕度 | 30 | {s0.memory_headroom:.1f} | {s2.memory_headroom:.1f} | {s2.memory_headroom - s0.memory_headroom:+.1f} |")
    lines.append(f"| Standby 与页分配速度 | 25 | {s0.standby_and_alloc:.1f} | {s2.standby_and_alloc:.1f} | {s2.standby_and_alloc - s0.standby_and_alloc:+.1f} |")
    lines.append(f"| GPU 显存与合成器健康度 | 20 | {s0.gpu_readiness:.1f} | {s2.gpu_readiness:.1f} | {s2.gpu_readiness - s0.gpu_readiness:+.1f} |")
    lines.append(f"| 内核池/调度抖动/泄漏卫生 | 15 | {s0.system_hygiene:.1f} | {s2.system_hygiene:.1f} | {s2.system_hygiene - s0.system_hygiene:+.1f} |")
    lines.append(f"| 磁盘空间与电源策略 | 10 | {s0.storage_and_power:.1f} | {s2.storage_and_power:.1f} | {s2.storage_and_power - s0.storage_and_power:+.1f} |")
    lines.append("")

    # T0 / T1 / T2 Metrics
    lines.append("## 2. 优化前后系统指标对比 (T0 -> T1 -> T2)")
    lines.append("")
    lines.append("| 指标 | 优化前 (T0) | 刚优化 (T1) | 静置验证 (T2) | 净变化 (T2 - T0) |")
    lines.append("|---|---:|---:|---:|---:|")
    t1_avail = f"{t1.available_ram_mb:.0f} MB" if t1 else "-"
    t1_sb = f"{t1.standby_total_mb:.0f} MB" if t1 else "-"
    t1_mod = f"{t1.modified_list_mb:.0f} MB" if t1 else "-"
    t1_com = f"{t1.commit_pct:.1f}%" if t1 else "-"
    lines.append(f"| 可用物理内存 | {t0.available_ram_mb:.0f} MB | {t1_avail} | {t2.available_ram_mb:.0f} MB | {evaluation.net_available_ram_delta_mb:+.0f} MB |")
    lines.append(f"| Standby 缓存总计 | {t0.standby_total_mb:.0f} MB | {t1_sb} | {t2.standby_total_mb:.0f} MB | {evaluation.net_standby_delta_mb:+.0f} MB |")
    lines.append(f"| Modified 脏页列表 | {t0.modified_list_mb:.0f} MB | {t1_mod} | {t2.modified_list_mb:.0f} MB | {t2.modified_list_mb - t0.modified_list_mb:+.0f} MB |")
    lines.append(f"| 系统 Commit 占比 | {t0.commit_pct:.1f}% | {t1_com} | {t2.commit_pct:.1f}% | {evaluation.net_commit_delta_pct:+.1f}% |")
    lines.append(f"| 内核非分页池 (Nonpaged) | {t0.kernel_nonpaged_mb:.0f} MB | - | {t2.kernel_nonpaged_mb:.0f} MB | {t2.kernel_nonpaged_mb - t0.kernel_nonpaged_mb:+.0f} MB |")
    if t2.gpu.present:
        lines.append(
            f"| GPU 空闲显存 ({t2.gpu.name}) | {t0.gpu.vram_free_mb:.0f} MB | - | {t2.gpu.vram_free_mb:.0f} MB | {t2.gpu.vram_free_mb - t0.gpu.vram_free_mb:+.0f} MB |"
        )
    if bench_t0 and bench_t1:
        lines.append(
            f"| {bench_t0.alloc_touch_mb}MB 页分配接触耗时 | {bench_t0.alloc_touch_ms:.1f} ms | - | {bench_t1.alloc_touch_ms:.1f} ms | {evaluation.alloc_latency_delta_ms:+.1f} ms |"
        )
        lines.append(
            f"| 调度定时器 P95 抖动 | {bench_t0.jitter_p95_ms:.2f} ms | - | {bench_t1.jitter_p95_ms:.2f} ms | {evaluation.jitter_p95_delta_ms:+.2f} ms |"
        )
    lines.append("")

    # Guard & Modules
    lines.append("## 3. 负载保护与模块执行明细")
    lines.append("")
    lines.append(f"- **负载保护决策**: `{guard.profile}` — {'; '.join(guard.reasons)}")
    lines.append("")
    if module_results:
        lines.append("| 模块 | 状态 | 耗时 (ms) | 释放/腾出 (MB) | 说明 |")
        lines.append("|---|---|---:|---:|---|")
        for m in module_results:
            lines.append(f"| `{m.module_name}` | `{m.status}` | {m.duration_ms:.1f} | {m.reclaimed_mb:.1f} | {m.summary} |")
        lines.append("")

    # Working set rebound
    if evaluation.trimmed_total_mb > 0:
        lines.append("## 4. 工作集修剪回弹审计")
        lines.append("")
        lines.append(
            f"- 累计修剪: **{evaluation.trimmed_total_mb:.1f} MB** | 观察期回弹: **{evaluation.rebound_total_mb:.1f} MB** | 总体回弹率: **{evaluation.overall_rebound_ratio * 100:.1f}%**"
        )
        if evaluation.rebounders:
            lines.append("- **高频回弹进程 (下次迭代将逐步自动排除)**:")
            for r in evaluation.rebounders[:8]:
                lines.append(
                    f"  - `{r.name}` (PID {r.pid}): {r.before_mb:.0f} -> {r.after_trim_mb:.0f} -> {r.settled_mb:.0f} MB (回弹 {r.rebound_ratio * 100:.0f}%)"
                )
        lines.append("")

    # Leak detection
    lines.append("## 5. 内存与资源泄漏追踪")
    lines.append("")
    if not leaks:
        lines.append("- 本轮未检测到异常的内存、句柄、GDI/USER 或显存泄漏。")
    else:
        lines.append("| 级别 | 类别 | 进程 / 对象 | PID | 当前值 | 增长速率 (/h) | 建议 |")
        lines.append("|---|---|---|---:|---:|---:|---|")
        for lk in leaks:
            rate = f"{lk.growth_rate_per_hour:+.1f}" if lk.growth_rate_per_hour is not None else "-"
            lines.append(
                f"| **{lk.severity}** | `{lk.category}` | {lk.process_name} | {lk.pid} | {lk.current_value:.1f} | {rate} | {lk.recommendation} |"
            )
    lines.append("")

    # Gap analysis ("查漏补缺")
    lines.append("## 6. 本次优化“查漏补缺”诊断")
    lines.append("")
    if not evaluation.gaps:
        lines.append("- 未发现遗留性能短板，系统状态优良，适合随时启动大型工程软件或游戏。")
    else:
        for g in evaluation.gaps:
            lines.append(f"- **[{g.severity}] {g.title}** (`{g.code}`, 指标: `{g.metric_value}`)")
            lines.append(f"  - 现状: {g.description}")
            lines.append(f"  - 建议: {g.recommendation}")
            if g.auto_action_taken:
                lines.append(f"  - 自动化处理: {g.auto_action_taken}")
    lines.append("")

    # Iteration
    lines.append("## 7. 策略自迭代与参数状态")
    lines.append("")
    if iteration:
        lines.append(f"- **本轮迭代结果**: `{iteration.action}` -> 策略 `v{iteration.new_version}`")
        lines.append(f"- **依据**: {iteration.rationale}")
    lines.append(
        f"- **当前参数**: `standby_purge_min_mb={policy.standby_purge_min_mb}`, "
        f"`min_working_set_mb={policy.min_working_set_mb}`, "
        f"`min_uptime_seconds={policy.min_uptime_seconds}`"
    )
    if policy.dynamic_trim_exclude:
        lines.append(f"- **自动学习排除修剪名单**: `{', '.join(policy.dynamic_trim_exclude)}`")
    if policy.leak_watchlist:
        lines.append(f"- **泄漏重点观察名单**: `{', '.join(policy.leak_watchlist)}`")
    lines.append("")
    return "\n".join(lines)


def _build_svg_chart(
    title: str,
    series: list[tuple[str, str, list[float]]],
    labels: list[str],
    y_min: float = 0.0,
    y_max: float = 100.0,
    unit: str = "",
) -> str:
    """Build a crisp, zero-dependency inline SVG multi-line trend chart."""
    w, h = 560, 200
    pad_l, pad_r, pad_t, pad_b = 46, 20, 28, 30
    cw = w - pad_l - pad_r
    ch = h - pad_t - pad_b
    span_y = max(1.0, y_max - y_min)

    parts: list[str] = [
        f'<svg viewBox="0 0 {w} {h}" class="chart-svg" xmlns="http://www.w3.org/2000/svg">',
        f'<text x="{pad_l}" y="16" fill="#e2e8f0" font-size="12" font-weight="600">{html.escape(title)}</text>',
    ]

    # Grid lines
    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = pad_t + ch * (1.0 - frac)
        val = y_min + span_y * frac
        parts.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{w - pad_r}" y2="{y:.1f}" stroke="#334155" stroke-dasharray="3,3" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{pad_l - 6}" y="{y + 4:.1f}" text-anchor="end" fill="#94a3b8" font-size="10">{val:.0f}{html.escape(unit)}</text>'
        )

    n = len(labels)
    if n > 0:
        for i, lbl in enumerate(labels):
            if n > 8 and i % 2 != 0 and i != n - 1:
                continue
            x = pad_l + (cw * i / max(1, n - 1)) if n > 1 else pad_l + cw / 2
            parts.append(
                f'<text x="{x:.1f}" y="{h - 8}" text-anchor="middle" fill="#94a3b8" font-size="10">{html.escape(lbl)}</text>'
            )

        legend_x = w - pad_r
        for idx, (s_name, color, vals) in enumerate(series):
            if not vals:
                continue
            pts: list[str] = []
            for i, v in enumerate(vals):
                x = pad_l + (cw * i / max(1, n - 1)) if n > 1 else pad_l + cw / 2
                clamped = max(y_min, min(y_max, float(v)))
                y = pad_t + ch * (1.0 - (clamped - y_min) / span_y)
                pts.append(f"{x:.1f},{y:.1f}")
            if len(pts) >= 2:
                parts.append(
                    f'<polyline fill="none" stroke="{color}" stroke-width="2.2" points="{" ".join(pts)}"/>'
                )
            for p_str in pts:
                cx, cy = p_str.split(",")
                parts.append(f'<circle cx="{cx}" cy="{cy}" r="3.2" fill="{color}"/>')

            lx = legend_x - idx * 120
            parts.append(
                f'<text x="{lx}" y="16" text-anchor="end" fill="{color}" font-size="11" font-weight="600">● {html.escape(s_name)}</text>'
            )

    parts.append("</svg>")
    return "".join(parts)


def generate_html_dashboard(
    latest_run: dict[str, Any],
    recent_runs: list[dict[str, Any]],
    policy: PolicyState,
    policy_history: list[dict[str, Any]],
) -> str:
    """Generate a self-contained offline HTML dashboard for run results and trends."""
    t0 = latest_run["t0"]
    t2 = latest_run["t2"]
    summary = latest_run["summary"]
    eval_data = summary.get("evaluation", {})
    s0 = eval_data.get("score_t0", {})
    s2 = eval_data.get("score_t2", {})
    modules = latest_run.get("modules", [])
    leaks = latest_run.get("leaks", [])
    gaps = latest_run.get("gaps", [])
    bench_t0 = latest_run.get("bench_t0")
    bench_t1 = latest_run.get("bench_t1")

    # Chronological order for trend charts
    chrono = list(reversed(recent_runs))
    labels = [r["started_at"][5:16].replace("T", " ") for r in chrono]
    scores_t0 = [float(r["score_t0"]) for r in chrono]
    scores_t2 = [float(r["score_t2"]) for r in chrono]
    avail_ram_gbs = [round(float(r["t2"]["available_ram_mb"]) / 1024.0, 2) for r in chrono]
    total_ram_gb = max(16.0, round(float(t2["total_ram_mb"]) / 1024.0, 0))
    commit_pcts = [float(r["t2"]["commit_pct"]) for r in chrono]

    svg_score = _build_svg_chart(
        "重负载就绪度评分趋势 (T0 优化前 vs T2 静置后)",
        [("T2 静置后", "#34d399", scores_t2), ("T0 优化前", "#94a3b8", scores_t0)],
        labels,
        0.0,
        100.0,
        "",
    )
    svg_mem = _build_svg_chart(
        "可用内存 (GB) 与 Commit 占用 (%)",
        [("Commit %", "#fbbf24", commit_pcts), ("可用 RAM (GB)", "#38bdf8", avail_ram_gbs)],
        labels,
        0.0,
        max(100.0, total_ram_gb),
        "",
    )

    def _badge(sev: str) -> str:
        cls = {
            "CRITICAL": "badge-crit",
            "WARN": "badge-warn",
            "INFO": "badge-info",
            "ok": "badge-ok",
            "dry_run": "badge-info",
            "skipped": "badge-muted",
            "error": "badge-crit",
        }.get(sev, "badge-info")
        return f'<span class="badge {cls}">{html.escape(str(sev))}</span>'

    mod_rows = "".join(
        f"<tr><td><code>{html.escape(m['module_name'])}</code></td>"
        f"<td>{_badge(m['status'])}</td>"
        f"<td class='num'>{m['duration_ms']:.1f}</td>"
        f"<td class='num'>{m['reclaimed_mb']:.1f}</td>"
        f"<td>{html.escape(str(m.get('details', {}).get('summary') or summary.get('module_summaries', {}).get(m['module_name'], '')))}</td></tr>"
        for m in modules
    )

    def _fmt_growth(val: float | None) -> str:
        return f"{val:+.1f}" if val is not None else "-"

    leak_rows = (
        "".join(
            f"<tr><td>{_badge(lk['severity'])}</td>"
            f"<td><code>{html.escape(lk['category'])}</code></td>"
            f"<td>{html.escape(lk['process_name'])}</td>"
            f"<td class='num'>{lk['pid']}</td>"
            f"<td class='num'>{lk['current_value']:.1f}</td>"
            f"<td class='num'>{_fmt_growth(lk['growth_rate_per_hour'])}</td>"
            f"<td>{html.escape(lk['recommendation'])}</td></tr>"
            for lk in leaks
        )
        if leaks
        else '<tr><td colspan="7" class="muted">本轮未检出显著内存/句柄/显存泄漏</td></tr>'
    )

    gap_cards = (
        "".join(
            f'<div class="gap-card gap-{html.escape(g["severity"].lower())}">'
            f'<div class="gap-head">{_badge(g["severity"])} <strong>{html.escape(g["title"])}</strong>'
            f' <span class="metric-pill">{html.escape(g["metric_value"])}</span></div>'
            f'<p>{html.escape(g["description"])}</p>'
            f'<p class="rec"><strong>建议:</strong> {html.escape(g["recommendation"])}</p>'
            + (
                f'<p class="auto"><strong>自动处置:</strong> {html.escape(g["auto_action_taken"])}</p>'
                if g.get("auto_action_taken")
                else ""
            )
            + "</div>"
            for g in gaps
        )
        if gaps
        else '<div class="gap-card gap-info"><strong>系统就绪度良好</strong><p>未发现阻碍大型工程软件或游戏启动的明显短板。</p></div>'
    )

    policy_rows = "".join(
        f"<tr><td><code>v{ph['version']}</code></td>"
        f"<td>{html.escape(ph['created_at'])}</td>"
        f"<td>{_badge(ph['action'])}</td>"
        f"<td>{html.escape(ph['rationale'])}</td></tr>"
        for ph in policy_history[:8]
    )

    bench_html = ""
    if bench_t0 and bench_t1:
        bench_html = (
            f"<tr><td>{bench_t0['alloc_touch_mb']}MB 页分配接触耗时</td>"
            f"<td class='num'>{bench_t0['alloc_touch_ms']:.1f} ms</td>"
            f"<td class='num'>{bench_t1['alloc_touch_ms']:.1f} ms</td>"
            f"<td class='num'>{bench_t1['alloc_touch_ms'] - bench_t0['alloc_touch_ms']:+.1f} ms</td></tr>"
            f"<tr><td>调度定时器 P95 抖动</td>"
            f"<td class='num'>{bench_t0['jitter_p95_ms']:.2f} ms</td>"
            f"<td class='num'>{bench_t1['jitter_p95_ms']:.2f} ms</td>"
            f"<td class='num'>{bench_t1['jitter_p95_ms'] - bench_t0['jitter_p95_ms']:+.2f} ms</td></tr>"
        )

    gpu_row = ""
    if t2.get("gpu", {}).get("present"):
        g0 = t0["gpu"]
        g2 = t2["gpu"]
        gpu_row = (
            f"<tr><td>GPU 空闲显存 ({html.escape(g2['name'])})</td>"
            f"<td class='num'>{g0['vram_free_mb']:.0f} MB</td>"
            f"<td class='num'>{g2['vram_free_mb']:.0f} MB</td>"
            f"<td class='num'>{g2['vram_free_mb'] - g0['vram_free_mb']:+.0f} MB</td></tr>"
        )

    score_delta = float(s2.get("total", 0.0)) - float(s0.get("total", 0.0))
    avail_delta = float(eval_data.get("net_available_ram_delta_mb", 0.0))

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Windows 长运行性能优化仪表盘 - {html.escape(latest_run['run_id'])}</title>
<style>
  :root {{
    --bg: #0b1120; --card: #111827; --border: #1f2937;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
    --green: #34d399; --amber: #fbbf24; --red: #f87171;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 24px; background: var(--bg); color: var(--text);
    font-family: "Segoe UI", "Microsoft YaHei", system-ui, sans-serif; line-height: 1.5;
  }}
  .container {{ max-width: 1240px; margin: 0 auto; }}
  .header {{
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
    border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px;
  }}
  .header h1 {{ margin: 0; font-size: 22px; color: #f8fafc; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
  .kpi-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px; margin-bottom: 20px;
  }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px; margin-bottom: 18px;
  }}
  .kpi-title {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.4px; }}
  .kpi-val {{ font-size: 26px; font-weight: 700; margin: 6px 0 2px; color: #f8fafc; }}
  .kpi-sub {{ font-size: 12px; color: var(--muted); }}
  .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(460px, 1fr)); gap: 16px; margin-bottom: 18px; }}
  .chart-svg {{ width: 100%; height: auto; display: block; }}
  h2 {{ font-size: 16px; margin: 0 0 12px; color: #f1f5f9; border-left: 3px solid var(--accent); padding-left: 10px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ color: var(--muted); font-weight: 600; background: #0f172a; }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 11px; font-weight: 600;
  }}
  .badge-ok {{ background: rgba(52,211,153,0.16); color: var(--green); }}
  .badge-warn {{ background: rgba(251,191,36,0.18); color: var(--amber); }}
  .badge-crit {{ background: rgba(248,113,113,0.18); color: var(--red); }}
  .badge-info {{ background: rgba(56,189,248,0.16); color: var(--accent); }}
  .badge-muted {{ background: rgba(148,163,184,0.16); color: var(--muted); }}
  .gap-card {{
    border: 1px solid var(--border); border-left-width: 4px; border-radius: 8px;
    padding: 12px 14px; margin-bottom: 10px; background: #0f172a;
  }}
  .gap-critical {{ border-left-color: var(--red); }}
  .gap-warn {{ border-left-color: var(--amber); }}
  .gap-info {{ border-left-color: var(--accent); }}
  .gap-head {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }}
  .metric-pill {{
    margin-left: auto; font-size: 12px; color: var(--muted);
    background: #1e293b; padding: 2px 8px; border-radius: 6px;
  }}
  .gap-card p {{ margin: 4px 0; font-size: 13px; color: #cbd5e1; }}
  .gap-card .rec {{ color: #93c5fd; }}
  .gap-card .auto {{ color: var(--green); }}
  .muted {{ color: var(--muted); text-align: center; }}
  code {{ background: #1e293b; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>Windows 长运行自动优化与闭环诊断面板</h1>
      <div class="meta">
        运行 ID: <code>{html.escape(latest_run['run_id'])}</code> · 模式: <code>{html.escape(latest_run['mode'])}</code>
        · 负载策略: <code>{html.escape(latest_run['execution_profile'])}</code> · 连续开机: <strong>{latest_run['uptime_hours'] / 24.0:.1f} 天</strong>
        · 策略版本: <code>v{policy.version}</code>
      </div>
    </div>
    <div class="meta">{html.escape(latest_run['finished_at'])}</div>
  </div>

  <div class="card" style="background:#0f172a;border-color:#0369a1;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;">
    <div>
      <strong>需要交互式手动清理或安全重启泄漏进程/进程树？</strong>
      <div class="kpi-sub">本静态离线报告为只读快照。运行 <code>python -m winopt.cli web --open</code> 启动本地控制台，即可点击一键优化、快速释放内存与安全重启进程树。</div>
    </div>
    <a href="http://127.0.0.1:18765/" target="_blank" style="background:#0284c7;color:#f8fafc;padding:8px 14px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;">打开交互式控制台 (127.0.0.1:18765)</a>
  </div>

  <div class="kpi-grid">
    <div class="card">
      <div class="kpi-title">重负载就绪度评分 (T2)</div>
      <div class="kpi-val">{s2.get('total', 0.0):.1f} <span style="font-size:14px;color:var(--muted)">/ 100</span></div>
      <div class="kpi-sub">较优化前 T0 ({s0.get('total', 0.0):.1f}) 变化 {score_delta:+.1f} 分</div>
    </div>
    <div class="card">
      <div class="kpi-title">可用物理内存 (T2)</div>
      <div class="kpi-val">{t2['available_ram_mb'] / 1024.0:.2f} GB</div>
      <div class="kpi-sub">净释放 {avail_delta:+.0f} MB · Standby {t2['standby_total_mb']:.0f} MB</div>
    </div>
    <div class="card">
      <div class="kpi-title">系统 Commit 占比</div>
      <div class="kpi-val">{t2['commit_pct']:.1f}%</div>
      <div class="kpi-sub">{t2['commit_total_mb'] / 1024.0:.1f} / {t2['commit_limit_mb'] / 1024.0:.1f} GB</div>
    </div>
    <div class="card">
      <div class="kpi-title">GPU 空闲显存</div>
      <div class="kpi-val">{(t2['gpu']['vram_free_mb'] / 1024.0):.2f} GB</div>
      <div class="kpi-sub">{html.escape(t2['gpu'].get('name') or 'N/A')} · 内核非分页池 {t2['kernel_nonpaged_mb']:.0f} MB</div>
    </div>
  </div>

  <div class="charts-grid">
    <div class="card">{svg_score}</div>
    <div class="card">{svg_mem}</div>
  </div>

  <div class="card">
    <h2>优化前后对比 (T0 优化前 vs T2 观察稳定后)</h2>
    <table>
      <thead><tr><th>核心指标</th><th class="num">优化前 (T0)</th><th class="num">静置后 (T2)</th><th class="num">净变化</th></tr></thead>
      <tbody>
        <tr><td>可用物理内存</td><td class="num">{t0['available_ram_mb']:.0f} MB</td><td class="num">{t2['available_ram_mb']:.0f} MB</td><td class="num">{avail_delta:+.0f} MB</td></tr>
        <tr><td>Standby 缓存总计</td><td class="num">{t0['standby_total_mb']:.0f} MB</td><td class="num">{t2['standby_total_mb']:.0f} MB</td><td class="num">{t2['standby_total_mb'] - t0['standby_total_mb']:+.0f} MB</td></tr>
        <tr><td>系统 Commit 占比</td><td class="num">{t0['commit_pct']:.1f}%</td><td class="num">{t2['commit_pct']:.1f}%</td><td class="num">{t2['commit_pct'] - t0['commit_pct']:+.1f}%</td></tr>
        {gpu_row}
        {bench_html}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>查漏补缺 (Gap Analysis) — 尚未自动消除的瓶颈与对策</h2>
    {gap_cards}
  </div>

  <div class="card">
    <h2>内存与资源泄漏追踪</h2>
    <table>
      <thead><tr><th>级别</th><th>类别</th><th>进程 / 对象</th><th class="num">PID</th><th class="num">当前值</th><th class="num">增长 (/h)</th><th>建议</th></tr></thead>
      <tbody>{leak_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>各优化模块执行情况</h2>
    <table>
      <thead><tr><th>模块</th><th>状态</th><th class="num">耗时 (ms)</th><th class="num">释放 (MB)</th><th>摘要</th></tr></thead>
      <tbody>{mod_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>自迭代策略演化历史 (当前参数: standby≥{policy.standby_purge_min_mb}MB, trim≥{policy.min_working_set_mb}MB, uptime≥{policy.min_uptime_seconds}s)</h2>
    <table>
      <thead><tr><th>版本</th><th>时间</th><th>动作</th><th>迭代原因与调整明细</th></tr></thead>
      <tbody>{policy_rows}</tbody>
    </table>
  </div>
</div>
</body>
</html>
"""


def write_reports(
    cfg: OptimizerConfig,
    run_id: str,
    mode: str,
    guard: GuardDecision,
    t0: SystemSnapshot,
    t1: SystemSnapshot | None,
    t2: SystemSnapshot,
    bench_t0: BenchmarkResult | None,
    bench_t1: BenchmarkResult | None,
    module_results: list[ActionResult],
    leaks: list[LeakEvent],
    evaluation: EvaluationReport,
    policy: PolicyState,
    iteration: IterationOutcome | None,
    latest_run_record: dict[str, Any],
    recent_runs: list[dict[str, Any]],
    policy_history: list[dict[str, Any]],
) -> tuple[Path, Path]:
    """Write Markdown & HTML reports to reports/ and return (md_path, html_path)."""
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    ts_slug = run_id

    md_text = generate_markdown_report(
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
        iteration=iteration,
    )
    md_archive = cfg.reports_dir / f"report_{ts_slug}.md"
    md_latest = cfg.reports_dir / "latest_report.md"
    md_archive.write_text(md_text, encoding="utf-8")
    md_latest.write_text(md_text, encoding="utf-8")

    html_text = generate_html_dashboard(
        latest_run=latest_run_record,
        recent_runs=recent_runs,
        policy=policy,
        policy_history=policy_history,
    )
    html_archive = cfg.reports_dir / f"dashboard_{ts_slug}.html"
    html_latest = cfg.reports_dir / "latest_dashboard.html"
    html_archive.write_text(html_text, encoding="utf-8")
    html_latest.write_text(html_text, encoding="utf-8")

    return (md_latest, html_latest)
