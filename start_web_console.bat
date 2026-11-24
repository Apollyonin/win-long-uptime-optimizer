@echo off
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
where python >nul 2>&1
if %errorlevel%==0 (
    python -m winopt.cli web --open
) else (
    C:\Python313\python.exe -m winopt.cli web --open
)
pause
