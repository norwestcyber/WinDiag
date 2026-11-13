@echo off
rem Double-click launcher: runs the full WinDiag triage elevated, bypassing execution policy for this run only.
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%~dp0' -Filter *.ps1 | Unblock-File; & '%~dp0Invoke-WinDiag.ps1' -Elevate %*"
pause
