"""Localhost interactive Web Console (127.0.0.1) for winopt manual cleanup & process governance."""

from __future__ import annotations

import html
import json
import secrets
import socket
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from winopt.config import OptimizerConfig
from winopt.engine import run_optimization_cycle
from winopt.evaluator import analyze_gaps, compute_readiness_score
from winopt.leak_detector import detect_leaks
from winopt.optimizers import MemoryListsOptimizer, NetworkDnsOptimizer, WorkingSetOptimizer
from winopt.optimizers.base import OptimizationContext
from winopt.process_control import (
    build_heavy_process_entries,
    safe_restart_target,
    safe_trim_target,
)
from winopt.reporter import _build_svg_chart
from winopt.storage import StorageManager, utc_now_iso
from winopt.telemetry import collect_snapshot
from winopt.win32_native import get_current_desktop_info
from winopt.workload_guard import evaluate_workload_guard


def _is_allowed_origin(origin: str | None) -> bool:
    if not origin:
        return True
    lower = origin.strip().lower()
    return lower.startswith("http://127.0.0.1:") or lower.startswith("http://localhost:") or lower in {
        "http://127.0.0.1",
        "http://localhost",
    }


class WebConsoleContext:
    """Shared state, locks, CSRF token, and single-flight optimization runner."""

    def __init__(self, cfg: OptimizerConfig) -> None:
        self.cfg = cfg
        self.storage = StorageManager(cfg.db_path, cfg.policy_path)
        self.csrf_token = secrets.token_urlsafe(24)
        self._job_lock = threading.Lock()
        self.current_job: dict[str, Any] = {
            "status": "idle",
            "job_id": None,
            "mode": None,
            "started_at": None,
            "finished_at": None,
            "message": "空闲就绪",
            "result": None,
        }

    def get_job_snapshot(self) -> dict[str, Any]:
        with self._job_lock:
            return dict(self.current_job)

    def start_optimize_job(self, mode: str = "manual", settle_seconds: int = 5) -> tuple[bool, dict[str, Any]]:
        with self._job_lock:
            if self.current_job["status"] == "running":
                return (
                    False,
                    {
                        "ok": False,
                        "message": "已有优化任务正在执行中，请等待本轮完成后再试",
                        "job": dict(self.current_job),
                    },
                )
            job_id = f"job_{int(time.time())}"
            self.current_job = {
                "status": "running",
                "job_id": job_id,
                "mode": mode,
                "started_at": utc_now_iso(),
                "finished_at": None,
                "message": f"正在执行 {mode} 闭环优化与验证...",
                "result": None,
            }

        def _worker() -> None:
            try:
                out = run_optimization_cycle(
                    self.cfg,
                    mode=mode,
                    dry_run=False,
                    settle_seconds=max(1, int(settle_seconds)),
                    run_bench=True,
                    storage=self.storage,
                )
                self.storage.save_manual_action(
                    action_type=f"optimize_{mode}",
                    target_name="System",
                    target_pid=0,
                    scope="system",
                    status="ok",
                    freed_rss_mb=out.evaluation.net_available_ram_delta_mb,
                    message=(
                        f"{mode} 优化完成: Score {out.evaluation.score_t0.total:.1f} -> "
                        f"{out.evaluation.score_t2.total:.1f}, 可用内存 {out.evaluation.net_available_ram_delta_mb:+.0f} MB"
                    ),
                    details={"run_id": out.run_id},
                )
                with self._job_lock:
                    self.current_job = {
                        "status": "done",
                        "job_id": job_id,
                        "mode": mode,
                        "started_at": self.current_job["started_at"],
                        "finished_at": utc_now_iso(),
                        "message": (
                            f"完成 ({out.run_id}): 就绪度 {out.evaluation.score_t0.total:.1f} -> "
                            f"{out.evaluation.score_t2.total:.1f}, 净释放可用内存 {out.evaluation.net_available_ram_delta_mb:+.0f} MB"
                        ),
                        "result": {
                            "run_id": out.run_id,
                            "score_t0": out.evaluation.score_t0.total,
                            "score_t2": out.evaluation.score_t2.total,
                            "net_available_ram_delta_mb": out.evaluation.net_available_ram_delta_mb,
                        },
                    }
            except Exception as exc:
                with self._job_lock:
                    self.current_job = {
                        "status": "error",
                        "job_id": job_id,
                        "mode": mode,
                        "started_at": self.current_job["started_at"],
                        "finished_at": utc_now_iso(),
                        "message": f"优化执行失败: {exc}",
                        "result": None,
                    }

        threading.Thread(target=_worker, daemon=True, name="winopt-job").start()
        return (True, {"ok": True, "message": "已启动后台闭环优化任务", "job": self.get_job_snapshot()})

    def run_quick_clean(self) -> dict[str, Any]:
        policy = self.storage.ensure_policy(self.cfg)
        t0 = collect_snapshot(self.cfg, include_processes=True)
        guard = evaluate_workload_guard(t0, self.cfg, mode="manual")
        ctx = OptimizationContext(
            mode="manual",
            dry_run=False,
            guard=guard,
            t0=t0,
            policy=policy,
            config=self.cfg,
        )
        mods = [MemoryListsOptimizer(), WorkingSetOptimizer(), NetworkDnsOptimizer()]
        results = []
        for m in mods:
            try:
                results.append(m.run(ctx))
            except Exception as exc:
                results.append({"module_name": m.name, "status": "error", "summary": str(exc)})

        t_after = collect_snapshot(self.cfg, include_processes=False)
        avail_delta = round(t_after.available_ram_mb - t0.available_ram_mb, 1)
        standby_delta = round(t_after.standby_total_mb - t0.standby_total_mb, 1)
        summaries = [getattr(r, "summary", str(r)) for r in results]
        msg = (
            f"快速内存清理完成 ({guard.profile} 模式): 可用物理内存 {avail_delta:+.0f} MB "
            f"({t0.available_ram_mb:.0f} -> {t_after.available_ram_mb:.0f} MB), "
            f"Standby {standby_delta:+.0f} MB"
        )
        self.storage.save_manual_action(
            action_type="quick_clean",
            target_name="Memory & Standby",
            target_pid=0,
            scope="system",
            status="ok",
            freed_rss_mb=max(0.0, avail_delta),
            message=msg,
            details={"summaries": summaries},
        )
        return {
            "ok": True,
            "message": msg,
            "available_before_mb": t0.available_ram_mb,
            "available_after_mb": t_after.available_ram_mb,
            "available_delta_mb": avail_delta,
            "standby_delta_mb": standby_delta,
            "summaries": summaries,
        }

    def collect_live_heavy_payload(self) -> dict[str, Any]:
        snap = collect_snapshot(self.cfg, include_processes=True)
        guard = evaluate_workload_guard(snap, self.cfg, mode="manual")
        leaks = detect_leaks(snap, self.cfg, self.storage, guard=guard)
        score = compute_readiness_score(snap, None, self.cfg, leaks=leaks)
        gaps = analyze_gaps(snap, None, [], leaks, [], self.cfg)
        heavy_entries = build_heavy_process_entries(snap, leaks, self.cfg, limit=30)
        return {
            "captured_at": snap.captured_at,
            "is_admin": snap.is_admin,
            "uptime_hours": snap.uptime_hours,
            "guard": guard.to_dict(),
            "score": score.to_dict(),
            "kpis": {
                "total_ram_mb": snap.total_ram_mb,
                "available_ram_mb": snap.available_ram_mb,
                "standby_total_mb": snap.standby_total_mb,
                "modified_list_mb": snap.modified_list_mb,
                "commit_pct": snap.commit_pct,
                "commit_total_mb": snap.commit_total_mb,
                "commit_limit_mb": snap.commit_limit_mb,
                "kernel_nonpaged_mb": snap.kernel_nonpaged_mb,
                "cpu_pct": snap.cpu_pct,
                "gpu_present": snap.gpu.present,
                "gpu_name": snap.gpu.name,
                "vram_used_mb": snap.gpu.vram_used_mb,
                "vram_free_mb": snap.gpu.vram_free_mb,
                "vram_total_mb": snap.gpu.vram_total_mb,
                "power_plan_name": snap.power_plan_name,
            },
            "heavy_processes": heavy_entries,
            "leaks": [lk.to_dict() for lk in leaks],
            "gaps": [g.to_dict() for g in gaps],
        }

    def collect_state_payload(self) -> dict[str, Any]:
        latest = self.storage.get_latest_run_details()
        recent = self.storage.get_recent_runs(limit=16)
        policy = self.storage.ensure_policy(self.cfg)
        pol_hist = self.storage.list_policy_history(limit=15)
        manual_actions = self.storage.list_manual_actions(limit=25)
        charts = self._build_charts_html(recent, latest)
        return {
            "latest_run": latest,
            "recent_runs": recent,
            "policy": policy.to_dict(),
            "policy_history": pol_hist,
            "manual_actions": manual_actions,
            "job": self.get_job_snapshot(),
            "charts": charts,
            "desktop_info": get_current_desktop_info(),
        }

    @staticmethod
    def _build_charts_html(recent_runs: list[dict[str, Any]], latest: dict[str, Any] | None) -> dict[str, str]:
        if not recent_runs:
            return {"score_svg": "", "memory_svg": ""}
        chrono = list(reversed(recent_runs))
        labels = [r["started_at"][5:16].replace("T", " ") for r in chrono]
        scores_t0 = [float(r["score_t0"]) for r in chrono]
        scores_t2 = [float(r["score_t2"]) for r in chrono]
        avail_ram_gbs = [round(float(r["t2"]["available_ram_mb"]) / 1024.0, 2) for r in chrono]
        total_ram_gb = (
            max(16.0, round(float(latest["t2"]["total_ram_mb"]) / 1024.0, 0))
            if latest
            else 32.0
        )
        commit_pcts = [float(r["t2"]["commit_pct"]) for r in chrono]

        score_svg = _build_svg_chart(
            "重负载就绪度评分趋势 (T0 优化前 vs T2 静置后)",
            [("T2 静置后", "#34d399", scores_t2), ("T0 优化前", "#94a3b8", scores_t0)],
            labels,
            0.0,
            100.0,
            "",
        )
        memory_svg = _build_svg_chart(
            "可用内存 (GB) 与 Commit 占用 (%)",
            [("Commit %", "#fbbf24", commit_pcts), ("可用 RAM (GB)", "#38bdf8", avail_ram_gbs)],
            labels,
            0.0,
            max(100.0, total_ram_gb),
            "",
        )
        return {"score_svg": score_svg, "memory_svg": memory_svg}


def render_web_console_html(ctx: WebConsoleContext) -> str:
    """Render the interactive localhost HTML governance console."""
    state_json = json.dumps(ctx.collect_state_payload(), ensure_ascii=False)
    token_escaped = html.escape(ctx.csrf_token)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>WinOpt 交互式控制台 · 长运行性能优化与进程治理</title>
<style>
  :root {{
    --bg: #0b1120; --card: #111827; --card2: #0f172a; --border: #1f2937;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
    --green: #34d399; --amber: #fbbf24; --red: #f87171; --purple: #a78bfa;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 22px; background: var(--bg); color: var(--text);
    font-family: "Segoe UI", "Microsoft YaHei", system-ui, sans-serif; line-height: 1.5;
  }}
  .container {{ max-width: 1320px; margin: 0 auto; }}
  .header {{
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
    gap: 14px; border-bottom: 1px solid var(--border); padding-bottom: 14px; margin-bottom: 18px;
  }}
  .header h1 {{ margin: 0; font-size: 21px; color: #f8fafc; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-top: 3px; }}
  .toolbar {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; }}
  button {{
    border: 1px solid var(--border); background: #1e293b; color: #f8fafc;
    padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600;
    transition: all 0.15s ease;
  }}
  button:hover:not(:disabled) {{ filter: brightness(1.15); transform: translateY(-1px); }}
  button:disabled {{ opacity: 0.42; cursor: not-allowed; }}
  .btn-primary {{ background: #0284c7; border-color: #0369a1; }}
  .btn-boost {{ background: #7c3aed; border-color: #6d28d9; }}
  .btn-quick {{ background: #059669; border-color: #047857; }}
  .btn-warn {{ background: rgba(251,191,36,0.16); color: var(--amber); border-color: rgba(251,191,36,0.38); }}
  .btn-danger {{ background: rgba(248,113,113,0.16); color: var(--red); border-color: rgba(248,113,113,0.38); }}
  .btn-sm {{ padding: 4px 9px; font-size: 12px; border-radius: 6px; }}
  .banner {{
    padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 13px;
    border: 1px solid var(--border); background: var(--card2); display: flex; justify-content: space-between; align-items: center; gap: 12px;
  }}
  .banner-running {{ border-color: var(--accent); background: rgba(56,189,248,0.12); }}
  .banner-ok {{ border-color: var(--green); background: rgba(52,211,153,0.12); }}
  .banner-err {{ border-color: var(--red); background: rgba(248,113,113,0.12); }}
  .kpi-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 14px; margin-bottom: 18px;
  }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px; margin-bottom: 18px;
  }}
  .kpi-title {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.4px; }}
  .kpi-val {{ font-size: 25px; font-weight: 700; margin: 6px 0 2px; color: #f8fafc; }}
  .kpi-sub {{ font-size: 12px; color: var(--muted); }}
  .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(460px, 1fr)); gap: 16px; margin-bottom: 18px; }}
  .chart-svg {{ width: 100%; height: auto; display: block; }}
  h2 {{ font-size: 16px; margin: 0 0 12px; color: #f1f5f9; border-left: 3px solid var(--accent); padding-left: 10px; display: flex; justify-content: space-between; align-items: center; }}
  .filter-bar {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 12px; }}
  .filter-bar input[type="text"] {{
    background: var(--card2); color: var(--text); border: 1px solid var(--border);
    padding: 7px 11px; border-radius: 7px; font-size: 13px; min-width: 240px;
  }}
  .filter-bar label {{ font-size: 13px; color: var(--muted); display: flex; align-items: center; gap: 6px; cursor: pointer; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: middle; }}
  th {{ color: var(--muted); font-weight: 600; background: var(--card2); }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 11px; font-weight: 600; margin-right: 4px;
  }}
  .badge-ok {{ background: rgba(52,211,153,0.16); color: var(--green); }}
  .badge-warn {{ background: rgba(251,191,36,0.18); color: var(--amber); }}
  .badge-crit {{ background: rgba(248,113,113,0.18); color: var(--red); }}
  .badge-info {{ background: rgba(56,189,248,0.16); color: var(--accent); }}
  .badge-purple {{ background: rgba(167,139,250,0.18); color: var(--purple); }}
  .badge-muted {{ background: rgba(148,163,184,0.16); color: var(--muted); }}
  .actions-cell {{ display: flex; flex-wrap: wrap; gap: 6px; }}
  .gap-card {{
    border: 1px solid var(--border); border-left-width: 4px; border-radius: 8px;
    padding: 12px 14px; margin-bottom: 10px; background: var(--card2);
  }}
  .gap-critical {{ border-left-color: var(--red); }}
  .gap-warn {{ border-left-color: var(--amber); }}
  .gap-info {{ border-left-color: var(--accent); }}
  .gap-head {{ display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }}
  .metric-pill {{ margin-left: auto; font-size: 12px; color: var(--muted); background: #1e293b; padding: 2px 8px; border-radius: 6px; }}
  code {{ background: #1e293b; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
  .modal-backdrop {{
    position: fixed; inset: 0; background: rgba(2,6,23,0.78); display: none;
    align-items: center; justify-content: center; z-index: 999; padding: 16px;
  }}
  .modal {{
    background: var(--card); border: 1px solid #334155; border-radius: 12px;
    max-width: 560px; width: 100%; padding: 20px; box-shadow: 0 20px 60px rgba(0,0,0,0.5);
  }}
  .modal h3 {{ margin: 0 0 10px; font-size: 17px; color: #f8fafc; }}
  .modal-info {{ background: var(--card2); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; font-size: 13px; margin: 10px 0; }}
  .modal-warn {{ background: rgba(251,191,36,0.14); border: 1px solid rgba(251,191,36,0.4); color: #fde68a; border-radius: 8px; padding: 10px 12px; font-size: 13px; margin: 10px 0; }}
  .modal-actions {{ display: flex; justify-content: flex-end; gap: 10px; margin-top: 16px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>WinOpt 本地实时控制台 · 性能优化与安全进程治理</h1>
      <div class="meta" id="headerMeta">加载实时系统状态中...</div>
    </div>
    <div class="meta">仅限本机回环访问 <code>127.0.0.1</code> · CSRF 校验已启用</div>
  </div>

  <div class="banner" id="desktopGuardBanner" style="display:none;border-color:rgba(251,191,36,0.55);background:rgba(251,191,36,0.12);color:#fde68a;">
    <span id="desktopGuardText"></span>
  </div>

  <div class="toolbar">
    <button class="btn-primary" id="btnOptimizeManual" onclick="triggerOptimize('manual')">立即执行完整优化 (T0→T2)</button>
    <button class="btn-boost" id="btnOptimizeBoost" onclick="triggerOptimize('boost')">大软件/游戏战前加速 (Boost)</button>
    <button class="btn-quick" id="btnQuickClean" onclick="triggerQuickClean()">快速释放内存 (Standby + 工作集)</button>
    <button id="btnRefreshLive" onclick="refreshAll()">刷新实时进程与诊断</button>
  </div>

  <div class="banner" id="statusBanner" style="display:none;">
    <span id="statusBannerText"></span>
    <button class="btn-sm" onclick="document.getElementById('statusBanner').style.display='none'">关闭</button>
  </div>

  <div class="kpi-grid" id="kpiGrid"></div>

  <div class="card">
    <h2>
      <span>高占用 / 泄漏进程与进程树治理</span>
      <span class="meta" id="heavyCountLabel"></span>
    </h2>
    <div class="filter-bar">
      <input type="text" id="procSearch" placeholder="筛选进程名 / PID / 泄漏类型..." oninput="renderHeavyTable()"/>
      <label><input type="checkbox" id="onlyLeaksToggle" onchange="renderHeavyTable()"/> 仅显示存在泄漏告警的进程</label>
      <label><input type="checkbox" id="hideForbiddenToggle" onchange="renderHeavyTable()"/> 隐藏系统禁止终止核心进程</label>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>进程 / 进程树</th>
            <th class="num">实例数 / 主PID</th>
            <th class="num">私有提交</th>
            <th class="num">物理工作集</th>
            <th class="num">专用显存</th>
            <th class="num">句柄 / GDI</th>
            <th>泄漏与安全级别</th>
            <th>安全治理操作</th>
          </tr>
        </thead>
        <tbody id="heavyTableBody">
          <tr><td colspan="8" style="text-align:center;color:var(--muted)">正在采集实时进程快照...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="charts-grid">
    <div class="card" id="scoreChartCard"></div>
    <div class="card" id="memoryChartCard"></div>
  </div>

  <div class="card">
    <h2>实时“查漏补缺”诊断与未自动消除瓶颈</h2>
    <div id="gapsContainer"></div>
  </div>

  <div class="card">
    <h2>手动清理与安全重启审计日志</h2>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr><th>时间</th><th>操作</th><th>目标</th><th class="num">释放私有/物理</th><th class="num">新 PID</th><th>执行结果</th></tr>
        </thead>
        <tbody id="manualActionsBody"></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>自迭代策略演化历史</h2>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>版本</th><th>时间</th><th>动作</th><th>迭代原因与调整明细</th></tr></thead>
        <tbody id="policyHistoryBody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="modal-backdrop" id="confirmModal">
  <div class="modal">
    <h3 id="modalTitle">确认操作</h3>
    <div class="modal-info" id="modalDetails"></div>
    <div class="modal-warn" id="modalWarn" style="display:none;"></div>
    <div class="modal-actions">
      <button onclick="closeModal()">取消</button>
      <button class="btn-danger" id="modalConfirmBtn" onclick="executeConfirmedAction()">确认执行</button>
    </div>
  </div>
</div>

<script>
const CSRF_TOKEN = "{token_escaped}";
let STATE = {state_json};
let LIVE = null;
let PENDING_ACTION = null;
let JOB_TIMER = null;

function esc(str) {{
  return String(str ?? "").replace(/[&<>"']/g, s => ({{
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }}[s]));
}}

function badge(text, cls) {{
  return `<span class="badge ${{cls}}">${{esc(text)}}</span>`;
}}

function showBanner(msg, kind="info") {{
  const el = document.getElementById("statusBanner");
  const txt = document.getElementById("statusBannerText");
  el.className = "banner " + (kind === "ok" ? "banner-ok" : kind === "err" ? "banner-err" : "banner-running");
  txt.textContent = msg;
  el.style.display = "flex";
}}

async function apiPost(path, body) {{
  const res = await fetch(path, {{
    method: "POST",
    headers: {{
      "Content-Type": "application/json",
      "X-WinOpt-Token": CSRF_TOKEN
    }},
    body: JSON.stringify(body || {{}})
  }});
  const data = await res.json();
  if (!res.ok && !data.message) {{
    throw new Error("HTTP " + res.status);
  }}
  return {{ status: res.status, data }};
}}

async function triggerOptimize(mode) {{
  try {{
    const {{ status, data }} = await apiPost("/api/actions/optimize", {{ mode, settle_seconds: 5 }});
    if (status === 409) {{
      showBanner(data.message || "任务已在运行中", "running");
      startJobPolling();
      return;
    }}
    showBanner(data.message, data.ok ? "running" : "err");
    if (data.ok) startJobPolling();
  }} catch (e) {{
    showBanner("请求失败: " + e.message, "err");
  }}
}}

async function triggerQuickClean() {{
  const btn = document.getElementById("btnQuickClean");
  btn.disabled = true;
  showBanner("正在执行快速内存与 Standby 清理...", "running");
  try {{
    const {{ data }} = await apiPost("/api/actions/quick-clean", {{}});
    showBanner(data.message, data.ok ? "ok" : "err");
    await refreshAll();
  }} catch (e) {{
    showBanner("快速清理失败: " + e.message, "err");
  }} finally {{
    btn.disabled = false;
  }}
}}

function startJobPolling() {{
  if (JOB_TIMER) clearInterval(JOB_TIMER);
  JOB_TIMER = setInterval(async () => {{
    try {{
      const res = await fetch("/api/jobs/current");
      const job = await res.json();
      if (job.status === "running") {{
        showBanner(job.message || "优化任务执行中...", "running");
      }} else {{
        clearInterval(JOB_TIMER);
        JOB_TIMER = null;
        showBanner(job.message || "任务已完成", job.status === "error" ? "err" : "ok");
        await refreshAll();
      }}
    }} catch (_) {{
      clearInterval(JOB_TIMER);
      JOB_TIMER = null;
    }}
  }}, 1500);
}}

async function refreshState() {{
  const res = await fetch("/api/state");
  STATE = await res.json();
  renderStateSections();
}}

async function refreshLive() {{
  const res = await fetch("/api/processes/heavy");
  LIVE = await res.json();
  renderLiveSections();
}}

async function refreshAll() {{
  await Promise.all([refreshState(), refreshLive()]);
}}

function renderLiveSections() {{
  if (!LIVE) return;
  const k = LIVE.kpis;
  const pol = STATE.policy || {{}};
  document.getElementById("headerMeta").innerHTML =
    `连续开机: <strong>${{(LIVE.uptime_hours / 24).toFixed(1)}} 天</strong> · 管理员权限: <code>${{LIVE.is_admin}}</code> · 负载模式: <code>${{esc(LIVE.guard.profile)}}</code> · 当前策略: <code>v${{pol.version || 1}}</code> · 刷新时间: ${{esc(LIVE.captured_at)}}`;

  const gpuCard = k.gpu_present
    ? `<div class="card"><div class="kpi-title">GPU 空闲显存 (${{esc(k.gpu_name)}})</div><div class="kpi-val">${{(k.vram_free_mb / 1024).toFixed(2)}} GB</div><div class="kpi-sub">已用 ${{k.vram_used_mb.toFixed(0)}} / ${{k.vram_total_mb.toFixed(0)}} MB · 非分页池 ${{k.kernel_nonpaged_mb.toFixed(0)}} MB</div></div>`
    : `<div class="card"><div class="kpi-title">内核非分页池</div><div class="kpi-val">${{k.kernel_nonpaged_mb.toFixed(0)}} MB</div><div class="kpi-sub">电源方案: ${{esc(k.power_plan_name)}}</div></div>`;

  document.getElementById("kpiGrid").innerHTML = `
    <div class="card">
      <div class="kpi-title">重负载实时就绪度</div>
      <div class="kpi-val">${{LIVE.score.total.toFixed(1)}} <span style="font-size:14px;color:var(--muted)">/ 100</span></div>
      <div class="kpi-sub">内存 ${{LIVE.score.memory_headroom.toFixed(1)}}/30 · Standby ${{LIVE.score.standby_and_alloc.toFixed(1)}}/25 · GPU ${{LIVE.score.gpu_readiness.toFixed(1)}}/20</div>
    </div>
    <div class="card">
      <div class="kpi-title">实时可用物理内存</div>
      <div class="kpi-val">${{(k.available_ram_mb / 1024).toFixed(2)}} GB</div>
      <div class="kpi-sub">总计 ${{(k.total_ram_mb / 1024).toFixed(1)}} GB · Standby ${{k.standby_total_mb.toFixed(0)}} MB · Modified ${{k.modified_list_mb.toFixed(0)}} MB</div>
    </div>
    <div class="card">
      <div class="kpi-title">系统 Commit 占比</div>
      <div class="kpi-val">${{k.commit_pct.toFixed(1)}}%</div>
      <div class="kpi-sub">${{(k.commit_total_mb / 1024).toFixed(1)}} / ${{(k.commit_limit_mb / 1024).toFixed(1)}} GB · CPU ${{k.cpu_pct.toFixed(1)}}%</div>
    </div>
    ${{gpuCard}}
  `;

  renderHeavyTable();
  renderGaps();
}}

function renderHeavyTable() {{
  if (!LIVE) return;
  const q = (document.getElementById("procSearch").value || "").trim().toLowerCase();
  const onlyLeaks = document.getElementById("onlyLeaksToggle").checked;
  const hideForbidden = document.getElementById("hideForbiddenToggle").checked;

  const rows = (LIVE.heavy_processes || []).filter(p => {{
    if (onlyLeaks && (!p.leak_tags || p.leak_tags.length === 0)) return false;
    if (hideForbidden && p.safety_tier === "forbidden") return false;
    if (!q) return true;
    const leakText = (p.leak_tags || []).map(l => l.category + " " + l.severity).join(" ").toLowerCase();
    return p.name.toLowerCase().includes(q) || String(p.root_pid).includes(q) || leakText.includes(q);
  }});

  document.getElementById("heavyCountLabel").textContent = `显示 ${{rows.length}} / ${{(LIVE.heavy_processes || []).length}} 项重点进程`;

  const tbody = document.getElementById("heavyTableBody");
  if (rows.length === 0) {{
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted)">没有符合筛选条件的进程</td></tr>';
    return;
  }}

  tbody.innerHTML = rows.map(p => {{
    const leakBadges = (p.leak_tags || []).map(lk => {{
      const cls = lk.severity === "CRITICAL" ? "badge-crit" : lk.severity === "WARN" ? "badge-warn" : "badge-info";
      return badge(`${{lk.severity}}:${{lk.category}}`, cls);
    }}).join("");

    const tierBadge = p.safety_tier === "forbidden"
      ? badge("禁止终止", "badge-muted")
      : p.safety_tier === "shell_restart"
        ? badge("外壳安全重启", "badge-purple")
        : badge("可安全重启", "badge-ok");

    const riskBadge = p.unsaved_work_risk ? badge("含未保存风险", "badge-warn") : "";
    const heavyBadge = p.is_heavy_workload ? badge("重负载", "badge-info") : "";

    let btns = "";
    if (p.safety_tier === "forbidden") {{
      btns = `<button class="btn-sm" disabled title="${{esc(p.safety_reason)}}">核心受保护</button>`;
    }} else {{
      const treeScope = p.process_count > 1 ? "group" : "tree";
      const restartLabel = p.process_count > 1 ? "安全重启进程树" : "安全重启";
      btns += `<button class="btn-sm btn-warn" onclick='openConfirm("restart", ${{JSON.stringify(p)}}, "${{treeScope}}", true)'>${{restartLabel}}</button>`;
      if (p.process_count > 1 && p.safety_tier !== "shell_restart") {{
        btns += `<button class="btn-sm" onclick='openConfirm("restart", ${{JSON.stringify(p)}}, "single", true)'>仅重启主进程</button>`;
      }}
      if (p.can_trim) {{
        btns += `<button class="btn-sm btn-quick" onclick='runTrim(${{p.root_pid}}, "${{treeScope}}")'>释放工作集</button>`;
      }}
      if (p.safety_tier !== "shell_restart") {{
        btns += `<button class="btn-sm btn-danger" onclick='openConfirm("restart", ${{JSON.stringify(p)}}, "${{treeScope}}", false)'>仅结束</button>`;
      }}
    }}

    return `
      <tr>
        <td><strong>${{esc(p.name)}}</strong> ${{heavyBadge}}<div class="meta">${{esc(p.exe || "")}}</div></td>
        <td class="num">${{p.process_count}} 个 / <code>${{p.root_pid}}</code></td>
        <td class="num"><strong>${{p.total_private_mb.toFixed(0)}} MB</strong></td>
        <td class="num">${{p.total_rss_mb.toFixed(0)}} MB</td>
        <td class="num">${{p.total_vram_mb.toFixed(0)}} MB</td>
        <td class="num">${{p.total_handles}} / ${{p.max_gdi}}</td>
        <td>${{tierBadge}}${{riskBadge}}${{leakBadges}}</td>
        <td><div class="actions-cell">${{btns}}</div></td>
      </tr>
    `;
  }}).join("");
}}

function openConfirm(actionType, procObj, scope, relaunch) {{
  PENDING_ACTION = {{ actionType, procObj, scope, relaunch }};
  const label = relaunch ? (scope === "single" ? "安全重启主进程" : "安全重启进程树") : "仅安全结束进程树";
  document.getElementById("modalTitle").textContent = `${{label}}: ${{procObj.name}}`;
  const pidList = scope === "single" ? [procObj.root_pid] : procObj.pids;
  document.getElementById("modalDetails").innerHTML = `
    <div><strong>目标进程:</strong> ${{esc(procObj.name)}} (${{pidList.length}} 个 PID: <code>${{pidList.slice(0, 12).join(", ")}}${{pidList.length > 12 ? "..." : ""}}</code>)</div>
    <div><strong>预计可释放资源:</strong> 私有提交 <strong>${{procObj.total_private_mb.toFixed(0)}} MB</strong> · 物理工作集 ${{procObj.total_rss_mb.toFixed(0)}} MB · 专用显存 ${{procObj.total_vram_mb.toFixed(0)}} MB</div>
    <div><strong>结束后重新拉起:</strong> ${{relaunch ? `<code>${{esc(procObj.relaunch_preview || procObj.exe || procObj.name)}}</code>` : "否（仅结束）"}}</div>
  `;
  const warnBox = document.getElementById("modalWarn");
  if (procObj.unsaved_work_risk) {{
    warnBox.style.display = "block";
    warnBox.textContent = "提醒：该应用可能包含未保存的网页标签、文档、聊天草稿或工程文件。建议先保存重要内容再确认重启。";
  }} else if (procObj.safety_tier === "shell_restart") {{
    warnBox.style.display = "block";
    warnBox.textContent = "提醒：重启 explorer.exe 期间桌面任务栏会短暂闪烁 1-2 秒，随后自动恢复并释放累积句柄与 GDI/显存。";
  }} else {{
    warnBox.style.display = "none";
  }}
  document.getElementById("confirmModal").style.display = "flex";
}}

function closeModal() {{
  document.getElementById("confirmModal").style.display = "none";
  PENDING_ACTION = null;
}}

async function executeConfirmedAction() {{
  if (!PENDING_ACTION) return;
  const act = PENDING_ACTION;
  closeModal();
  showBanner(`正在处理 ${{act.procObj.name}} (PID ${{act.procObj.root_pid}})...`, "running");
  try {{
    const {{ data }} = await apiPost("/api/process/restart", {{
      pid: act.procObj.root_pid,
      scope: act.scope,
      relaunch: act.relaunch
    }});
    showBanner(data.message, data.ok ? "ok" : "err");
    await refreshAll();
  }} catch (e) {{
    showBanner("操作失败: " + e.message, "err");
  }}
}}

async function runTrim(pid, scope) {{
  showBanner(`正在修剪 PID ${{pid}} 工作集...`, "running");
  try {{
    const {{ data }} = await apiPost("/api/process/trim", {{ pid, scope }});
    showBanner(data.message, data.ok ? "ok" : "err");
    await refreshAll();
  }} catch (e) {{
    showBanner("修剪失败: " + e.message, "err");
  }}
}}

function renderGaps() {{
  const gaps = (LIVE && LIVE.gaps) || [];
  const box = document.getElementById("gapsContainer");
  if (!gaps.length) {{
    box.innerHTML = '<div class="gap-card gap-info"><strong>状态良好</strong><div>暂未发现需要人工介入的瓶颈。</div></div>';
    return;
  }}
  box.innerHTML = gaps.map(g => {{
    const sevCls = g.severity === "CRITICAL" ? "badge-crit" : g.severity === "WARN" ? "badge-warn" : "badge-info";
    return `
      <div class="gap-card gap-${{esc(g.severity.toLowerCase())}}">
        <div class="gap-head">${{badge(g.severity, sevCls)}} <strong>${{esc(g.title)}}</strong> <span class="metric-pill">${{esc(g.metric_value)}}</span></div>
        <div style="font-size:13px;color:#cbd5e1;">${{esc(g.description)}}</div>
        <div style="font-size:13px;color:#93c5fd;margin-top:4px;"><strong>建议:</strong> ${{esc(g.recommendation)}}</div>
      </div>
    `;
  }}).join("");
}}

function renderStateSections() {{
  const charts = STATE.charts || {{}};
  document.getElementById("scoreChartCard").innerHTML = charts.score_svg || '<div class="meta">暂无多轮趋势数据</div>';
  document.getElementById("memoryChartCard").innerHTML = charts.memory_svg || '<div class="meta">暂无多轮趋势数据</div>';

  const acts = STATE.manual_actions || [];
  const abody = document.getElementById("manualActionsBody");
  abody.innerHTML = acts.length
    ? acts.map(a => `
        <tr>
          <td>${{esc(a.created_at)}}</td>
          <td><code>${{esc(a.action_type)}}</code></td>
          <td>${{esc(a.target_name)}} (PID ${{a.target_pid}})</td>
          <td class="num">${{a.freed_private_mb.toFixed(0)}} / ${{a.freed_rss_mb.toFixed(0)}} MB</td>
          <td class="num">${{a.new_pid ? a.new_pid : "-"}}</td>
          <td>${{esc(a.message)}}</td>
        </tr>
      `).join("")
    : '<tr><td colspan="6" style="text-align:center;color:var(--muted)">暂无手动操作记录</td></tr>';

  const phs = STATE.policy_history || [];
  document.getElementById("policyHistoryBody").innerHTML = phs.map(ph => `
    <tr>
      <td><code>v${{ph.version}}</code></td>
      <td>${{esc(ph.created_at)}}</td>
      <td>${{badge(ph.action, ph.action === "rollback" ? "badge-crit" : ph.action === "iterate" ? "badge-info" : "badge-ok")}}</td>
      <td>${{esc(ph.rationale)}}</td>
    </tr>
  `).join("");

  const desk = STATE.desktop_info;
  const dBanner = document.getElementById("desktopGuardBanner");
  const dText = document.getElementById("desktopGuardText");
  if (desk && desk.is_default_desktop === false) {{
    dText.textContent = `环境安全提示：当前控制台运行在隔离桌面 (${{desk.window_station}}\\\\${{desk.desktop}}) 而非正常交互桌面 (WinSta0\\\\Default)。为避免重启浏览器/GUI 软件后窗口隐身锁死，控制台已自动拦截 GUI 重启。请关闭本后台进程，在正常桌面双击 start_web_console.bat 启动！`;
    dBanner.style.display = "flex";
  }} else {{
    dBanner.style.display = "none";
  }}
}}

renderStateSections();
refreshLive();
if (STATE.job && STATE.job.status === "running") startJobPolling();
</script>
</body>
</html>
"""


class _ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    """Windows-safe ThreadingHTTPServer that refuses to shadow an already-bound port."""

    allow_reuse_address = False

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def create_web_server(
    cfg: OptimizerConfig,
    host: str = "127.0.0.1",
    port: int = 18765,
    fallback_range: int = 20,
) -> tuple[ThreadingHTTPServer, WebConsoleContext]:
    """Create a bound localhost ThreadingHTTPServer + WebConsoleContext."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("出于安全原因，Web 控制台仅允许绑定到 127.0.0.1 / localhost")

    ctx = WebConsoleContext(cfg)

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return  # Keep console stdout clean

        def _send_json(self, status_code: int, payload: Any) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, status_code: int, html_text: str) -> None:
            raw = html_text.encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(min(length, 1024 * 1024))
            if not raw:
                return {}
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}

        def _verify_post_security(self) -> bool:
            origin = self.headers.get("Origin")
            if not _is_allowed_origin(origin):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"ok": False, "message": "拒绝非本机 Origin 请求"},
                )
                return False
            token = self.headers.get("X-WinOpt-Token", "")
            if not token or not secrets.compare_digest(token, ctx.csrf_token):
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"ok": False, "message": "CSRF Token 无效或缺失"},
                )
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/" or path == "/index.html":
                self._send_html(HTTPStatus.OK, render_web_console_html(ctx))
                return
            if path == "/api/state":
                self._send_json(HTTPStatus.OK, ctx.collect_state_payload())
                return
            if path == "/api/processes/heavy":
                self._send_json(HTTPStatus.OK, ctx.collect_live_heavy_payload())
                return
            if path == "/api/jobs/current":
                self._send_json(HTTPStatus.OK, ctx.get_job_snapshot())
                return
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if not self._verify_post_security():
                return
            try:
                body = self._read_json_body()
            except Exception as exc:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "message": f"JSON 解析失败: {exc}"},
                )
                return

            if path == "/api/actions/optimize":
                mode = str(body.get("mode", "manual"))
                if mode not in ("manual", "boost"):
                    mode = "manual"
                settle = int(body.get("settle_seconds", 5))
                started, resp = ctx.start_optimize_job(mode=mode, settle_seconds=settle)
                self._send_json(HTTPStatus.OK if started else HTTPStatus.CONFLICT, resp)
                return

            if path == "/api/actions/quick-clean":
                resp = ctx.run_quick_clean()
                self._send_json(HTTPStatus.OK, resp)
                return

            if path == "/api/process/trim":
                pid = int(body.get("pid", 0))
                scope = str(body.get("scope", "tree"))
                if scope not in ("single", "tree", "group"):
                    scope = "tree"
                res = safe_trim_target(pid, scope=scope)
                ctx.storage.save_manual_action(
                    action_type="trim_working_set",
                    target_name=res.get("target_name", f"PID {pid}"),
                    target_pid=pid,
                    scope=scope,
                    status="ok" if res["ok"] else "blocked",
                    freed_rss_mb=float(res.get("freed_rss_mb", 0.0)),
                    message=res["message"],
                    details=res,
                )
                self._send_json(int(res.get("http_status", 200)), res)
                return

            if path == "/api/process/restart":
                pid = int(body.get("pid", 0))
                scope = str(body.get("scope", "tree"))
                if scope not in ("single", "tree", "group"):
                    scope = "tree"
                relaunch = bool(body.get("relaunch", True))
                res = safe_restart_target(pid, scope=scope, relaunch=relaunch)
                ctx.storage.save_manual_action(
                    action_type="restart_process" if relaunch else "terminate_process",
                    target_name=res.get("target_name", f"PID {pid}"),
                    target_pid=pid,
                    scope=scope,
                    status="ok" if res["ok"] else "blocked",
                    freed_private_mb=float(res.get("freed_private_mb", 0.0)),
                    freed_rss_mb=float(res.get("freed_rss_mb", 0.0)),
                    freed_handles=int(res.get("freed_handles", 0)),
                    new_pid=res.get("new_pid"),
                    message=res["message"],
                    details=res,
                )
                self._send_json(int(res.get("http_status", 200)), res)
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Not found"})

    if int(port) == 0:
        server = _ExclusiveThreadingHTTPServer((host, 0), _Handler)
        return (server, ctx)

    last_exc: OSError | None = None
    for candidate in range(int(port), int(port) + max(0, int(fallback_range)) + 1):
        try:
            server = _ExclusiveThreadingHTTPServer((host, candidate), _Handler)
            return (server, ctx)
        except OSError as exc:
            last_exc = exc
            continue
    raise OSError(f"无法在端口范围 {port}-{int(port) + fallback_range} 绑定服务: {last_exc}")


def serve_web_console(
    cfg: OptimizerConfig,
    port: int = 18765,
    open_browser: bool = False,
) -> None:
    """Start the blocking localhost Web Console server."""
    server, _ = create_web_server(cfg, host="127.0.0.1", port=port)
    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}/"
    try:
        (cfg.data_dir / "web_console_url.txt").write_text(url, encoding="utf-8")
    except OSError:
        pass
    print(f"WinOpt 交互式控制台已启动: {url}", flush=True)
    print("按 Ctrl+C 停止控制台服务。", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在关闭 Web 控制台...")
    finally:
        server.server_close()
