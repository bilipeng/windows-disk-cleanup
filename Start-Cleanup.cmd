@echo off
chcp 65001 >nul
setlocal
echo Starting Windows Disk Cleanup wizard...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0skills\windows-disk-cleanup\scripts\Start-Cleanup.ps1" %*
set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" echo Exit code: %RC%
pause
endlocal
