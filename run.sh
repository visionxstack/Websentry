#!/usr/bin/env bash
set -e

echo "Starting WebSentry..."
echo

# Start Python API backend in background
echo "[1/2] Starting scanner.py API on port 8081..."
python3 scanner.py &
BACKEND_PID=$!

# Small delay to let the backend start
sleep 2

# Start React frontend dev server
echo "[2/2] Starting React frontend dev server..."
cd frontend
npm run dev &
FRONTEND_PID=$!

echo
echo "WebSentry is running!"
echo "  API:      http://localhost:8081/scan"
echo "  Frontend: http://localhost:5173"
echo
echo "Press Ctrl+C to stop both servers."

# Wait for either process to exit
wait $BACKEND_PID $FRONTEND_PID

# Cleanup on exit
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
