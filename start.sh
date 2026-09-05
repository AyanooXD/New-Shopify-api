#!/bin/sh
PORT="${PORT:-8080}"
echo "Starting uvicorn on port $PORT"
exec uvicorn api:app --host 0.0.0.0 --port "$PORT" --workers 1
