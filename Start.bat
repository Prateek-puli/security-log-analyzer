@echo off
cd /d "%~dp0"
rem Use the project's virtual environment if it exists, otherwise the Python launcher or python on PATH.
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" app.py
) else (
    where py >nul 2>nul && (py -3 app.py) || (python app.py)
)
pause
