"""Native Windows API bindings via ctypes for memory management, telemetry, and process control."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from typing import Any

IS_WINDOWS = sys.platform == "win32"

# Process access rights
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SET_QUOTA = 0x0100
PROCESS_SET_INFORMATION = 0x0200

# Token access rights & privilege attributes
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_NOT_ALL_ASSIGNED = 1300

# Process priority classes
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS = 0x00000020

# NtSetSystemInformation information classes
SYSTEM_MEMORY_LIST_INFORMATION = 80
SYSTEM_COMBINE_PHYSICAL_MEMORY_INFORMATION = 130

# SYSTEM_MEMORY_LIST_COMMAND enum (ntexapi.h)
MEMORY_CAPTURE_ACCESSED_BITS = 0
MEMORY_CAPTURE_AND_RESET_ACCESSED_BITS = 1
MEMORY_EMPTY_WORKING_SETS = 2
MEMORY_FLUSH_MODIFIED_LIST = 3
MEMORY_PURGE_STANDBY_LIST = 4
MEMORY_PURGE_LOW_PRIORITY_STANDBY_LIST = 5

GR_GDIOBJECTS = 0
GR_USEROBJECTS = 1


if IS_WINDOWS:
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _shell32 = ctypes.WinDLL("shell32")
else:  # pragma: no cover - non-Windows fallback
    _kernel32 = _advapi32 = _psapi = _user32 = _ntdll = _shell32 = None


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", wintypes.DWORD),
        ("ProcessCount", wintypes.DWORD),
        ("ThreadCount", wintypes.DWORD),
    ]


class MEMORY_COMBINE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("Handle", wintypes.HANDLE),
        ("PagesCombined", ctypes.c_size_t),
        ("Flags", wintypes.ULONG),
    ]


if IS_WINDOWS:
    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE

    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _kernel32.GetPriorityClass.argtypes = [wintypes.HANDLE]
    _kernel32.GetPriorityClass.restype = wintypes.DWORD

    _kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.SetPriorityClass.restype = wintypes.BOOL

    _advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _advapi32.OpenProcessToken.restype = wintypes.BOOL

    _advapi32.LookupPrivilegeValueW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.POINTER(LUID),
    ]
    _advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL

    _advapi32.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(TOKEN_PRIVILEGES),
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

    _psapi.GetPerformanceInfo.argtypes = [
        ctypes.POINTER(PERFORMANCE_INFORMATION),
        wintypes.DWORD,
    ]
    _psapi.GetPerformanceInfo.restype = wintypes.BOOL

    _psapi.EmptyWorkingSet.argtypes = [wintypes.HANDLE]
    _psapi.EmptyWorkingSet.restype = wintypes.BOOL

    _user32.GetForegroundWindow.argtypes = []
    _user32.GetForegroundWindow.restype = wintypes.HWND

    _user32.GetWindowThreadProcessId.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD

    _user32.GetGuiResources.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _user32.GetGuiResources.restype = wintypes.DWORD

    _WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    _user32.EnumWindows.argtypes = [_WNDENUMPROC, wintypes.LPARAM]
    _user32.EnumWindows.restype = wintypes.BOOL
    _user32.PostMessageW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    _user32.PostMessageW.restype = wintypes.BOOL

    _ntdll.NtQueryTimerResolution.argtypes = [
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(wintypes.ULONG),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _ntdll.NtQueryTimerResolution.restype = ctypes.c_int32

    _ntdll.NtSetSystemInformation.argtypes = [
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    _ntdll.NtSetSystemInformation.restype = ctypes.c_int32

    _shell32.IsUserAnAdmin.argtypes = []
    _shell32.IsUserAnAdmin.restype = wintypes.BOOL


def is_admin() -> bool:
    """Return True if current process runs with Administrator privileges."""
    if not IS_WINDOWS or _shell32 is None:
        return False
    try:
        return bool(_shell32.IsUserAnAdmin())
    except Exception:
        return False


def enable_privileges(names: list[str]) -> dict[str, bool]:
    """Attempt to enable requested Windows privileges on the current process token."""
    results = {name: False for name in names}
    if not IS_WINDOWS:
        return results

    h_token = wintypes.HANDLE()
    h_proc = _kernel32.GetCurrentProcess()
    if not _advapi32.OpenProcessToken(
        h_proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)
    ):
        return results

    try:
        for name in names:
            luid = LUID()
            if not _advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                continue
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

            ctypes.set_last_error(0)
            ok = _advapi32.AdjustTokenPrivileges(
                h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None
            )
            err = ctypes.get_last_error()
            results[name] = bool(ok) and err == 0
    finally:
        _kernel32.CloseHandle(h_token)

    return results


def get_performance_info() -> dict[str, int]:
    """Query system commit, physical memory, kernel pools, handles, and counts."""
    if not IS_WINDOWS:
        return {}

    pi = PERFORMANCE_INFORMATION()
    pi.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)
    ok = _psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb)
    if not ok:
        return {}

    page_size = int(pi.PageSize) or 4096
    return {
        "page_size": page_size,
        "commit_total_bytes": int(pi.CommitTotal) * page_size,
        "commit_limit_bytes": int(pi.CommitLimit) * page_size,
        "commit_peak_bytes": int(pi.CommitPeak) * page_size,
        "physical_total_bytes": int(pi.PhysicalTotal) * page_size,
        "physical_available_bytes": int(pi.PhysicalAvailable) * page_size,
        "system_cache_bytes": int(pi.SystemCache) * page_size,
        "kernel_total_bytes": int(pi.KernelTotal) * page_size,
        "kernel_paged_bytes": int(pi.KernelPaged) * page_size,
        "kernel_nonpaged_bytes": int(pi.KernelNonpaged) * page_size,
        "handle_count": int(pi.HandleCount),
        "process_count": int(pi.ProcessCount),
        "thread_count": int(pi.ThreadCount),
    }


def query_timer_resolution() -> dict[str, float]:
    """Return Windows system timer resolution (min/max/current) in milliseconds."""
    if not IS_WINDOWS:
        return {"min_ms": 0.0, "max_ms": 0.0, "current_ms": 0.0}

    mn = wintypes.ULONG()
    mx = wintypes.ULONG()
    cur = wintypes.ULONG()
    status = _ntdll.NtQueryTimerResolution(
        ctypes.byref(mn), ctypes.byref(mx), ctypes.byref(cur)
    )
    if status != 0:
        return {"min_ms": 0.0, "max_ms": 0.0, "current_ms": 0.0}
    return {
        "min_ms": round(mn.value / 10000.0, 3),
        "max_ms": round(mx.value / 10000.0, 3),
        "current_ms": round(cur.value / 10000.0, 3),
    }


def get_foreground_pid() -> int | None:
    """Return PID owning the current foreground window, or None."""
    if not IS_WINDOWS:
        return None
    hwnd = _user32.GetForegroundWindow()
    if not hwnd:
        return None
    pid = wintypes.DWORD(0)
    _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return int(pid.value) if pid.value else None


def get_process_gui_resources(pid: int) -> tuple[int, int]:
    """Return (gdi_objects, user_objects) for a PID; (0, 0) on access failure."""
    if not IS_WINDOWS or pid <= 4:
        return (0, 0)

    handle = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return (0, 0)
    try:
        gdi = int(_user32.GetGuiResources(handle, GR_GDIOBJECTS))
        user = int(_user32.GetGuiResources(handle, GR_USEROBJECTS))
        return (gdi, user)
    finally:
        _kernel32.CloseHandle(handle)


def nt_memory_list_command(command: int) -> tuple[bool, int]:
    """Invoke NtSetSystemInformation(SystemMemoryListInformation, command).

    Returns (success, ntstatus_uint32).
    """
    if not IS_WINDOWS:
        return (False, 0xFFFFFFFF)

    cmd = ctypes.c_int32(int(command))
    _ntdll.NtSetSystemInformation.argtypes = [
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    _ntdll.NtSetSystemInformation.restype = ctypes.c_int32
    status = _ntdll.NtSetSystemInformation(
        SYSTEM_MEMORY_LIST_INFORMATION,
        ctypes.byref(cmd),
        ctypes.sizeof(cmd),
    )
    return (status == 0, int(status) & 0xFFFFFFFF)


def nt_combine_physical_memory() -> tuple[bool, int, int]:
    """Invoke NtSetSystemInformation(SystemCombinePhysicalMemoryInformation).

    Returns (success, ntstatus_uint32, pages_combined).
    """
    if not IS_WINDOWS:
        return (False, 0xFFFFFFFF, 0)

    info = MEMORY_COMBINE_INFORMATION_EX()
    info.Handle = None
    info.PagesCombined = 0
    info.Flags = 0

    _ntdll.NtSetSystemInformation.argtypes = [
        ctypes.c_int32,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    _ntdll.NtSetSystemInformation.restype = ctypes.c_int32
    status = _ntdll.NtSetSystemInformation(
        SYSTEM_COMBINE_PHYSICAL_MEMORY_INFORMATION,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    return (status == 0, int(status) & 0xFFFFFFFF, int(info.PagesCombined))


def empty_process_working_set(pid: int) -> bool:
    """Safely trim working set of a single non-protected background process."""
    if not IS_WINDOWS or pid <= 4:
        return False

    access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA
    handle = _kernel32.OpenProcess(access, False, int(pid))
    if not handle:
        return False
    try:
        ok = _psapi.EmptyWorkingSet(handle)
        return bool(ok)
    finally:
        _kernel32.CloseHandle(handle)


def set_process_below_normal_priority(pid: int) -> bool:
    """Lower process priority class to BELOW_NORMAL_PRIORITY_CLASS without terminating."""
    if not IS_WINDOWS or pid <= 4:
        return False

    access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION
    handle = _kernel32.OpenProcess(access, False, int(pid))
    if not handle:
        return False
    try:
        cur = _kernel32.GetPriorityClass(handle)
        if cur == BELOW_NORMAL_PRIORITY_CLASS:
            return True
        return bool(_kernel32.SetPriorityClass(handle, BELOW_NORMAL_PRIORITY_CLASS))
    finally:
        _kernel32.CloseHandle(handle)


def format_ntstatus(status: int) -> str:
    return f"0x{status & 0xFFFFFFFF:08X}"


def post_wm_close_to_pids(pids: set[int]) -> int:
    """Send WM_CLOSE (0x0010) to all top-level windows owned by `pids` for graceful exit."""
    if not IS_WINDOWS or not pids or _user32 is None:
        return 0

    WM_CLOSE = 0x0010
    target_set = {int(p) for p in pids if p > 4}
    if not target_set:
        return 0

    sent = 0

    def _cb(hwnd: wintypes.HWND, _lparam: wintypes.LPARAM) -> bool:
        nonlocal sent
        win_pid = wintypes.DWORD(0)
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(win_pid))
        if int(win_pid.value) in target_set:
            if _user32.PostMessageW(hwnd, WM_CLOSE, 0, 0):
                sent += 1
        return True

    cb_ref = _WNDENUMPROC(_cb)
    try:
        _user32.EnumWindows(cb_ref, 0)
    except Exception:
        pass
    return sent


def sanitize_win32_check() -> dict[str, Any]:
    """Quick self-diagnostic returning admin status and native API probe."""
    privs = enable_privileges(
        ["SeProfileSingleProcessPrivilege", "SeIncreaseQuotaPrivilege", "SeDebugPrivilege"]
    )
    perf = get_performance_info()
    timer = query_timer_resolution()
    return {
        "is_admin": is_admin(),
        "privileges": privs,
        "perf_keys": sorted(perf.keys()),
        "timer": timer,
    }
