@echo off
REM ARTS runner script — one command to validate and launch the web prototype.
REM Usage: run.bat

echo === ARTS Agentic Red Team Simulator ===
echo.

echo [1/4] Installing dependencies...
pip install -q -r requirements.txt
if ERRORLEVEL 1 (echo FAIL: pip install && exit /b 1)

echo [2/4] Running smoke test...
python tests/smoke.py
if ERRORLEVEL 1 (echo FAIL: smoke test && exit /b 1)

echo [3/4] Running headline experiment...
python experiments/headline.py
if ERRORLEVEL 1 (echo FAIL: headline experiment && exit /b 1)

echo [4/4] Launching web prototype on http://localhost:8000
echo        Press Ctrl+C to stop.
python -m uvicorn web.app:app --reload --port 8000
