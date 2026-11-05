@echo off
setlocal
cd /d "%~dp0"
py -3 -m security_log_analyzer
if errorlevel 1 pause
