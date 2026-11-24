"""SQLite persistence layer and policy state storage for winopt."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from winopt.config import OptimizerConfig
from winopt.models import (
    ActionResult,
    BenchmarkResult,
    GapFinding,
    LeakEvent,
    PolicyState,
    ProcessMetric,
    SystemSnapshot,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class StorageManager:
    """Manages SQLite database (data/optimizer.db) and policy JSON state."""

    def __init__(self, db_path: Path, policy_path: Path) -> None:
        self.db_path = Path(db_path)
        self.policy_path = Path(policy_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    execution_profile TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,
                    uptime_hours REAL NOT NULL,
                    score_t0 REAL NOT NULL,
                    score_t1 REAL,
                    score_t2 REAL NOT NULL,
                    t0_json TEXT NOT NULL,
                    t1_json TEXT,
                    t2_json TEXT NOT NULL,
                    bench_t0_json TEXT,
                    bench_t1_json TEXT,
                    summary_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS process_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    captured_at TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    exe TEXT,
                    create_time REAL NOT NULL,
                    rss_mb REAL NOT NULL,
                    private_mb REAL NOT NULL,
                    handles INTEGER NOT NULL,
                    gdi_objects INTEGER NOT NULL,
                    user_objects INTEGER NOT NULL,
                    vram_dedicated_mb REAL NOT NULL,
                    vram_shared_mb REAL NOT NULL,
                    vram_glitch INTEGER NOT NULL DEFAULT 0,
                    cpu_pct REAL NOT NULL,
                    threads INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_proc_identity
                    ON process_snapshots(pid, create_time, captured_at);
                CREATE INDEX IF NOT EXISTS idx_proc_run_phase
                    ON process_snapshots(run_id, phase);
                CREATE INDEX IF NOT EXISTS idx_proc_name_time
                    ON process_snapshots(name, captured_at);

                CREATE TABLE IF NOT EXISTS module_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    reclaimed_mb REAL NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS leak_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    current_value REAL NOT NULL,
                    growth_rate_per_hour REAL,
                    recommendation TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS gap_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    code TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    metric_value TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    auto_action_taken TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS policy_history (
                    version INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    trigger_run_id TEXT,
                    action TEXT NOT NULL,
                    parent_version INTEGER,
                    policy_json TEXT NOT NULL,
                    changes_json TEXT NOT NULL,
                    rationale TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS manual_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target_name TEXT NOT NULL,
                    target_pid INTEGER NOT NULL,
                    scope TEXT NOT NULL,
                    status TEXT NOT NULL,
                    freed_private_mb REAL NOT NULL,
                    freed_rss_mb REAL NOT NULL,
                    freed_vram_mb REAL NOT NULL,
                    freed_handles INTEGER NOT NULL,
                    new_pid INTEGER,
                    message TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                """
            )

    def ensure_policy(self, cfg: OptimizerConfig) -> PolicyState:
        """Load latest PolicyState from SQLite/JSON, or initialize v1 from config."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT policy_json FROM policy_history ORDER BY version DESC LIMIT 1"
            ).fetchone()
            if row is not None:
                state = PolicyState.from_dict(json.loads(row["policy_json"]))
                self._write_policy_json(state)
                return state

        if self.policy_path.exists():
            try:
                raw = json.loads(self.policy_path.read_text(encoding="utf-8"))
                state = PolicyState.from_dict(raw)
            except Exception:
                state = self._default_policy_from_config(cfg)
        else:
            state = self._default_policy_from_config(cfg)

        self.save_policy_revision(
            state=state,
            trigger_run_id=None,
            action="init",
            parent_version=None,
            changes=[],
            rationale="从 config.yaml 初始化策略 v1",
        )
        return state

    @staticmethod
    def _default_policy_from_config(cfg: OptimizerConfig) -> PolicyState:
        return PolicyState(
            version=1,
            standby_purge_min_mb=cfg.memory.standby_purge_min_mb,
            min_working_set_mb=cfg.working_set.min_working_set_mb,
            min_uptime_seconds=cfg.working_set.min_uptime_seconds,
            last_known_good_version=1,
        )

    def _write_policy_json(self, state: PolicyState) -> None:
        self.policy_path.write_text(
            json.dumps(state.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def save_policy_revision(
        self,
        state: PolicyState,
        trigger_run_id: str | None,
        action: str,
        parent_version: int | None,
        changes: list[dict[str, Any]],
        rationale: str,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO policy_history
                (version, created_at, trigger_run_id, action, parent_version, policy_json, changes_json, rationale)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    state.version,
                    utc_now_iso(),
                    trigger_run_id,
                    action,
                    parent_version,
                    json.dumps(state.to_dict(), ensure_ascii=False),
                    json.dumps(changes, ensure_ascii=False),
                    rationale,
                ),
            )
        self._write_policy_json(state)

    def update_current_policy_metadata(self, state: PolicyState) -> None:
        """Persist non-versioned runtime counters (strikes, watchlist, last_retrim) onto current version."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE policy_history SET policy_json = ? WHERE version = ?",
                (json.dumps(state.to_dict(), ensure_ascii=False), state.version),
            )
        self._write_policy_json(state)

    def get_policy_version(self, version: int) -> PolicyState | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT policy_json FROM policy_history WHERE version = ?", (version,)
            ).fetchone()
            if row is None:
                return None
            return PolicyState.from_dict(json.loads(row["policy_json"]))

    def list_policy_history(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT version, created_at, trigger_run_id, action, parent_version, changes_json, rationale
                FROM policy_history
                ORDER BY version DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            result.append(
                {
                    "version": r["version"],
                    "created_at": r["created_at"],
                    "trigger_run_id": r["trigger_run_id"],
                    "action": r["action"],
                    "parent_version": r["parent_version"],
                    "changes": json.loads(r["changes_json"]),
                    "rationale": r["rationale"],
                }
            )
        return result

    def save_run(
        self,
        run_id: str,
        started_at: str,
        finished_at: str,
        mode: str,
        execution_profile: str,
        policy_version: int,
        t0: SystemSnapshot,
        t1: SystemSnapshot | None,
        t2: SystemSnapshot,
        bench_t0: BenchmarkResult | None,
        bench_t1: BenchmarkResult | None,
        score_t0: float,
        score_t1: float | None,
        score_t2: float,
        summary: dict[str, Any],
        module_results: list[ActionResult],
        leak_events: list[LeakEvent],
        gap_findings: list[GapFinding],
        save_process_phases: tuple[tuple[str, SystemSnapshot | None], ...] = (),
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, started_at, finished_at, mode, execution_profile,
                    policy_version, uptime_hours, score_t0, score_t1, score_t2,
                    t0_json, t1_json, t2_json, bench_t0_json, bench_t1_json, summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    started_at,
                    finished_at,
                    mode,
                    execution_profile,
                    policy_version,
                    t2.uptime_hours,
                    score_t0,
                    score_t1,
                    score_t2,
                    json.dumps(t0.to_dict(include_processes=False), ensure_ascii=False),
                    json.dumps(t1.to_dict(include_processes=False), ensure_ascii=False) if t1 else None,
                    json.dumps(t2.to_dict(include_processes=False), ensure_ascii=False),
                    json.dumps(bench_t0.to_dict(), ensure_ascii=False) if bench_t0 else None,
                    json.dumps(bench_t1.to_dict(), ensure_ascii=False) if bench_t1 else None,
                    json.dumps(summary, ensure_ascii=False),
                ),
            )

            for phase_name, snap in save_process_phases:
                if snap is None or not snap.processes:
                    continue
                self._insert_process_batch(conn, run_id, phase_name, snap.captured_at, snap.processes)

            for mod in module_results:
                conn.execute(
                    """
                    INSERT INTO module_results
                    (run_id, module_name, status, duration_ms, reclaimed_mb, details_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        mod.module_name,
                        mod.status,
                        mod.duration_ms,
                        mod.reclaimed_mb,
                        json.dumps(mod.details, ensure_ascii=False),
                    ),
                )

            for lk in leak_events:
                conn.execute(
                    """
                    INSERT INTO leak_events
                    (run_id, detected_at, severity, category, pid, process_name,
                     current_value, growth_rate_per_hour, recommendation, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        lk.detected_at,
                        lk.severity,
                        lk.category,
                        lk.pid,
                        lk.process_name,
                        lk.current_value,
                        lk.growth_rate_per_hour,
                        lk.recommendation,
                        json.dumps(lk.details, ensure_ascii=False),
                    ),
                )

            for gap in gap_findings:
                conn.execute(
                    """
                    INSERT INTO gap_findings
                    (run_id, severity, code, title, description, metric_value, recommendation, auto_action_taken)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        gap.severity,
                        gap.code,
                        gap.title,
                        gap.description,
                        gap.metric_value,
                        gap.recommendation,
                        gap.auto_action_taken,
                    ),
                )

    @staticmethod
    def _insert_process_batch(
        conn: sqlite3.Connection,
        run_id: str,
        phase: str,
        captured_at: str,
        processes: list[ProcessMetric],
    ) -> None:
        # Keep meaningful processes (or top processes) to keep DB lean while tracking leaks accurately
        rows = [
            (
                run_id,
                phase,
                captured_at,
                p.pid,
                p.name,
                p.exe,
                p.create_time,
                round(p.rss_mb, 2),
                round(p.private_mb, 2),
                p.handles,
                p.gdi_objects,
                p.user_objects,
                round(p.vram_dedicated_mb, 2),
                round(p.vram_shared_mb, 2),
                1 if p.vram_glitch else 0,
                round(p.cpu_pct, 2),
                p.threads,
            )
            for p in processes
            if (
                p.rss_mb >= 20.0
                or p.private_mb >= 20.0
                or p.handles >= 400
                or p.gdi_objects >= 100
                or p.user_objects >= 100
                or p.vram_dedicated_mb >= 10.0
            )
        ]
        conn.executemany(
            """
            INSERT INTO process_snapshots (
                run_id, phase, captured_at, pid, name, exe, create_time,
                rss_mb, private_mb, handles, gdi_objects, user_objects,
                vram_dedicated_mb, vram_shared_mb, vram_glitch, cpu_pct, threads
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    def get_process_history(
        self,
        pid: int,
        create_time: float,
        phase: str = "t2",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieve historical snapshots for a specific process instance (pid + create_time)."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT captured_at, rss_mb, private_mb, handles, gdi_objects, user_objects,
                       vram_dedicated_mb, vram_glitch
                FROM process_snapshots
                WHERE pid = ? AND ABS(create_time - ?) < 2.0 AND phase = ?
                ORDER BY captured_at ASC
                LIMIT ?
                """,
                (pid, create_time, phase, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_process_name_aggregate_history(
        self,
        name: str,
        phase: str = "t2",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Retrieve historical aggregate metrics grouped by run for multi-process apps."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT run_id, MAX(captured_at) AS captured_at,
                       SUM(private_mb) AS private_mb,
                       SUM(handles) AS handles,
                       SUM(CASE WHEN vram_glitch = 0 THEN vram_dedicated_mb ELSE 0 END) AS vram_dedicated_mb
                FROM process_snapshots
                WHERE LOWER(name) = LOWER(?) AND phase = ?
                GROUP BY run_id
                ORDER BY captured_at ASC
                LIMIT ?
                """,
                (name, phase, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT run_id, started_at, finished_at, mode, execution_profile, policy_version,
                       uptime_hours, score_t0, score_t1, score_t2, t0_json, t2_json,
                       bench_t0_json, bench_t1_json, summary_json
                FROM runs
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "run_id": r["run_id"],
                    "started_at": r["started_at"],
                    "finished_at": r["finished_at"],
                    "mode": r["mode"],
                    "execution_profile": r["execution_profile"],
                    "policy_version": r["policy_version"],
                    "uptime_hours": r["uptime_hours"],
                    "score_t0": r["score_t0"],
                    "score_t1": r["score_t1"],
                    "score_t2": r["score_t2"],
                    "t0": json.loads(r["t0_json"]),
                    "t2": json.loads(r["t2_json"]),
                    "bench_t0": json.loads(r["bench_t0_json"]) if r["bench_t0_json"] else None,
                    "bench_t1": json.loads(r["bench_t1_json"]) if r["bench_t1_json"] else None,
                    "summary": json.loads(r["summary_json"]),
                }
            )
        return out

    def get_latest_run_details(self) -> dict[str, Any] | None:
        runs = self.get_recent_runs(limit=1)
        if not runs:
            return None
        latest = runs[0]
        run_id = latest["run_id"]
        with self._connect() as conn:
            mods = conn.execute(
                "SELECT module_name, status, duration_ms, reclaimed_mb, details_json FROM module_results WHERE run_id = ?",
                (run_id,),
            ).fetchall()
            leaks = conn.execute(
                """
                SELECT detected_at, severity, category, pid, process_name,
                       current_value, growth_rate_per_hour, recommendation, details_json
                FROM leak_events WHERE run_id = ?
                """,
                (run_id,),
            ).fetchall()
            gaps = conn.execute(
                """
                SELECT severity, code, title, description, metric_value, recommendation, auto_action_taken
                FROM gap_findings WHERE run_id = ?
                """,
                (run_id,),
            ).fetchall()
        latest["modules"] = [
            {
                "module_name": m["module_name"],
                "status": m["status"],
                "duration_ms": m["duration_ms"],
                "reclaimed_mb": m["reclaimed_mb"],
                "details": json.loads(m["details_json"]),
            }
            for m in mods
        ]
        latest["leaks"] = [
            {
                "detected_at": lk["detected_at"],
                "severity": lk["severity"],
                "category": lk["category"],
                "pid": lk["pid"],
                "process_name": lk["process_name"],
                "current_value": lk["current_value"],
                "growth_rate_per_hour": lk["growth_rate_per_hour"],
                "recommendation": lk["recommendation"],
                "details": json.loads(lk["details_json"]),
            }
            for lk in leaks
        ]
        latest["gaps"] = [dict(g) for g in gaps]
        return latest

    def prune_old_process_snapshots(self, retain_days: int = 30) -> int:
        cutoff = (datetime.now(timezone.utc).astimezone() - timedelta(days=retain_days)).isoformat(
            timespec="seconds"
        )
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM process_snapshots WHERE captured_at < ?", (cutoff,)
            )
            return cur.rowcount or 0

    def save_manual_action(
        self,
        action_type: str,
        target_name: str,
        target_pid: int,
        scope: str,
        status: str,
        freed_private_mb: float = 0.0,
        freed_rss_mb: float = 0.0,
        freed_vram_mb: float = 0.0,
        freed_handles: int = 0,
        new_pid: int | None = None,
        message: str = "",
        details: dict[str, Any] | None = None,
    ) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO manual_actions (
                    created_at, action_type, target_name, target_pid, scope, status,
                    freed_private_mb, freed_rss_mb, freed_vram_mb, freed_handles,
                    new_pid, message, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now_iso(),
                    action_type,
                    target_name,
                    int(target_pid),
                    scope,
                    status,
                    round(float(freed_private_mb), 2),
                    round(float(freed_rss_mb), 2),
                    round(float(freed_vram_mb), 2),
                    int(freed_handles),
                    int(new_pid) if new_pid is not None else None,
                    message,
                    json.dumps(details or {}, ensure_ascii=False),
                ),
            )
            return int(cur.lastrowid or 0)

    def list_manual_actions(self, limit: int = 25) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, action_type, target_name, target_pid, scope, status,
                       freed_private_mb, freed_rss_mb, freed_vram_mb, freed_handles,
                       new_pid, message, details_json
                FROM manual_actions
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "id": r["id"],
                    "created_at": r["created_at"],
                    "action_type": r["action_type"],
                    "target_name": r["target_name"],
                    "target_pid": r["target_pid"],
                    "scope": r["scope"],
                    "status": r["status"],
                    "freed_private_mb": r["freed_private_mb"],
                    "freed_rss_mb": r["freed_rss_mb"],
                    "freed_vram_mb": r["freed_vram_mb"],
                    "freed_handles": r["freed_handles"],
                    "new_pid": r["new_pid"],
                    "message": r["message"],
                    "details": json.loads(r["details_json"]),
                }
            )
        return out
