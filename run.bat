@echo off
setlocal enabledelayedexpansion

echo Starting WebSentry...
echo.

REM Check for Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH.
    echo Please install Python 3.x and try again.
    pause
    exit /b 1
)

REM Check for Node/npm
where npm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] npm is not installed or not in your PATH.
    echo Please install Node.js and try again.
    pause
    exit /b 1
)

REM Start Python API backend in background
echo [1/2] Starting scanner.py API on port 8081...
start "WebSentry API" cmd /k "python scanner.py"

REM Small delay to let the backend start
timeout /t 2 /nobreak >nul

REM Start React frontend dev server
echo [2/2] Starting React frontend on port 5173...
if not exist "frontend\node_modules" (
    echo node_modules not found. Installing dependencies...
    cd frontend
    call npm install
    cd ..
)

cd frontend
start "WebSentry Frontend" cmd /k "npm run dev"

echo.
echo WebSentry is running!
echo   API:      http://localhost:8081/scan
echo   Frontend: http://localhost:5173
echo.
echo The dashboard will open in your browser shortly...
timeout /t 5 /nobreak >nul
start http://localhost:5173
