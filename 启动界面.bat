@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================
echo   puzzle-toolkit 本地界面
echo ============================================
echo.

rem 优先用 Windows 的 py 启动器，没有就退回 python
where py >nul 2>nul
if %errorlevel%==0 (
    py ui.py %*
) else (
    python ui.py %*
)

if %errorlevel% neq 0 (
    echo.
    echo 启动失败。常见原因：
    echo   1. 没装 Python，或没加进 PATH
    echo   2. 这个 .bat 不在 puzzle-toolkit 目录里
    echo.
    pause
)
