"""Windows Task Scheduler XML builder and schtasks.exe manager for 12-hour automation."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from winopt.config import OptimizerConfig
from winopt.win32_native import IS_WINDOWS


def _decode_out(data: bytes) -> str:
    for enc in ("utf-8", "cp936", "mbcs", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def generate_task_xml(
    cfg: OptimizerConfig,
    python_exe: str | None = None,
    start_boundary: str | None = None,
    user_id: str | None = None,
) -> str:
    """Build Windows Task Scheduler v1.2 XML for recurring 12-hour HighestAvailable execution."""
    py = python_exe or sys.executable
    workdir = str(cfg.workspace_dir)
    interval_h = max(1, int(cfg.schedule.interval_hours))
    limit_m = max(5, int(cfg.schedule.execution_time_limit_minutes))

    if start_boundary is None:
        dt = datetime.now() + timedelta(minutes=2)
        start_boundary = dt.strftime("%Y-%m-%dT%H:%M:%S")

    if user_id is None:
        domain = os.environ.get("USERDOMAIN", "").strip()
        user = os.environ.get("USERNAME", "").strip()
        user_id = f"{domain}\\{user}" if (domain and user) else user

    user_xml = f"\n      <UserId>{escape(user_id)}</UserId>" if user_id else ""
    arguments = "-m winopt.cli run --mode scheduled"

    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <RegistrationInfo>\n"
        "    <Description>Windows 12-hour Automated Long-Uptime Performance Optimizer &amp; Self-Iteration (winopt)</Description>\n"
        f"    <URI>\\{escape(cfg.schedule.task_name)}</URI>\n"
        "  </RegistrationInfo>\n"
        "  <Triggers>\n"
        "    <TimeTrigger>\n"
        "      <Repetition>\n"
        f"        <Interval>PT{interval_h}H</Interval>\n"
        "        <StopAtDurationEnd>false</StopAtDurationEnd>\n"
        "      </Repetition>\n"
        f"      <StartBoundary>{escape(start_boundary)}</StartBoundary>\n"
        "      <Enabled>true</Enabled>\n"
        "    </TimeTrigger>\n"
        "  </Triggers>\n"
        "  <Principals>\n"
        '    <Principal id="Author">'
        f"{user_xml}\n"
        "      <LogonType>InteractiveToken</LogonType>\n"
        "      <RunLevel>HighestAvailable</RunLevel>\n"
        "    </Principal>\n"
        "  </Principals>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <AllowHardTerminate>true</AllowHardTerminate>\n"
        "    <StartWhenAvailable>true</StartWhenAvailable>\n"
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
        "    <IdleSettings>\n"
        "      <StopOnIdleEnd>false</StopOnIdleEnd>\n"
        "      <RestartOnIdle>false</RestartOnIdle>\n"
        "    </IdleSettings>\n"
        "    <AllowStartOnDemand>true</AllowStartOnDemand>\n"
        "    <Enabled>true</Enabled>\n"
        "    <Hidden>false</Hidden>\n"
        "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n"
        "    <WakeToRun>false</WakeToRun>\n"
        f"    <ExecutionTimeLimit>PT{limit_m}M</ExecutionTimeLimit>\n"
        "    <Priority>6</Priority>\n"
        "  </Settings>\n"
        "  <Actions Context=\"Author\">\n"
        "    <Exec>\n"
        f"      <Command>{escape(py)}</Command>\n"
        f"      <Arguments>{escape(arguments)}</Arguments>\n"
        f"      <WorkingDirectory>{escape(workdir)}</WorkingDirectory>\n"
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>\n"
    )


def export_task_xml(cfg: OptimizerConfig, output_path: str | Path) -> Path:
    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    xml_text = generate_task_xml(cfg)
    out.write_text(xml_text, encoding="utf-16")
    return out


def _run_schtasks(args: list[str]) -> tuple[int, str, str]:
    if not IS_WINDOWS:
        return (-1, "", "Non-Windows environment")
    proc = subprocess.run(
        ["schtasks", *args],
        capture_output=True,
        timeout=15.0,
        check=False,
    )
    return (proc.returncode, _decode_out(proc.stdout), _decode_out(proc.stderr))


def install_scheduled_task(cfg: OptimizerConfig) -> tuple[bool, str]:
    xml_path = cfg.data_dir / f"{cfg.schedule.task_name}.xml"
    export_task_xml(cfg, xml_path)
    rc, out, err = _run_schtasks(
        ["/Create", "/TN", cfg.schedule.task_name, "/XML", str(xml_path), "/F"]
    )
    if rc == 0:
        return (
            True,
            f"已成功安装 12 小时自动优化计划任务 '{cfg.schedule.task_name}' (XML: {xml_path})",
        )
    return (False, f"安装计划任务失败 (rc={rc}): {(err or out).strip()}")


def uninstall_scheduled_task(cfg: OptimizerConfig) -> tuple[bool, str]:
    rc, out, err = _run_schtasks(["/Delete", "/TN", cfg.schedule.task_name, "/F"])
    if rc == 0:
        return (True, f"已卸载计划任务 '{cfg.schedule.task_name}'")
    return (False, f"卸载计划任务失败 (rc={rc}): {(err or out).strip()}")


def get_scheduled_task_status(cfg: OptimizerConfig) -> dict[str, Any]:
    rc, out, err = _run_schtasks(
        ["/Query", "/TN", cfg.schedule.task_name, "/V", "/FO", "LIST"]
    )
    if rc != 0:
        return {
            "installed": False,
            "task_name": cfg.schedule.task_name,
            "raw": (err or out).strip(),
        }
    return {
        "installed": True,
        "task_name": cfg.schedule.task_name,
        "raw": out.strip(),
    }


def run_scheduled_task_now(cfg: OptimizerConfig) -> tuple[bool, str]:
    rc, out, err = _run_schtasks(["/Run", "/TN", cfg.schedule.task_name])
    if rc == 0:
        return (True, f"已立即触发计划任务 '{cfg.schedule.task_name}'")
    return (False, f"触发计划任务失败 (rc={rc}): {(err or out).strip()}")
