@echo off
setlocal
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0nettest.py" %*
) else (
    py -3 "%~dp0nettest.py" %*
)
exit /b %errorlevel%
