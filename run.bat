@echo off
echo Starting WebSentry...
echo.

REM Start Python API backend in background
echo [1/2] Starting scanner.py API on port 8081...
start "WebSentry API" cmd /k python scanner.py

REM Small delay to let the backend start
timeout /t 2 /nobreak >nul

REM Start React frontend dev server
echo [2/2] Starting React frontend on port 5173...
cd frontend
start "WebSentry Frontend" cmd /k npm run dev

echo.
echo WebSentry is running!
echo   API:      http://localhost:8081/scan
echo   Frontend: http://localhost:5173
echo.
timeout /t 3 /nobreak >nul
start http://localhost:5173
