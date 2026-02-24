#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ThreatTriage — Single-command startup script
# Runs both the FastAPI backend and Vite frontend in one terminal.
# Usage:  ./start.sh          (start both servers)
#         ./start.sh --stop   (kill both servers)
#         ./start.sh --setup  (first-time setup: venv + deps + frontend)
# ─────────────────────────────────────────────────────────────────────────────

set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PID_DIR="$ROOT_DIR/.pids"
mkdir -p "$PID_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ── Stop function ─────────────────────────────────────────────────────────────
stop_servers() {
    echo -e "${YELLOW}⏹  Stopping ThreatTriage servers...${NC}"
    if [ -f "$PID_DIR/backend.pid" ]; then
        kill "$(cat "$PID_DIR/backend.pid")" 2>/dev/null && echo -e "  ${RED}✗${NC} Backend stopped" || true
        rm -f "$PID_DIR/backend.pid"
    fi
    if [ -f "$PID_DIR/frontend.pid" ]; then
        kill "$(cat "$PID_DIR/frontend.pid")" 2>/dev/null && echo -e "  ${RED}✗${NC} Frontend stopped" || true
        rm -f "$PID_DIR/frontend.pid"
    fi
    # Clean up any orphaned processes
    pkill -f "uvicorn threattriage" 2>/dev/null || true
    pkill -f "vite.*--host" 2>/dev/null || true
    echo -e "${GREEN}✓ All servers stopped.${NC}"
    exit 0
}

# ── Setup function ────────────────────────────────────────────────────────────
setup_project() {
    echo -e "${CYAN}${BOLD}🔧 Setting up ThreatTriage...${NC}"
    echo ""

    # Python venv
    if [ ! -d "$ROOT_DIR/.venv" ]; then
        echo -e "  ${CYAN}▶${NC} Creating Python virtual environment..."
        python3 -m venv "$ROOT_DIR/.venv"
        echo -e "  ${GREEN}✓${NC} venv created"
    else
        echo -e "  ${GREEN}✓${NC} venv already exists"
    fi

    source "$ROOT_DIR/.venv/bin/activate"

    # Backend deps
    echo -e "  ${CYAN}▶${NC} Installing backend dependencies..."
    pip install -e "$ROOT_DIR" --quiet
    echo -e "  ${GREEN}✓${NC} Backend dependencies installed"

    # Frontend deps
    if [ ! -d "$ROOT_DIR/frontend/node_modules" ]; then
        echo -e "  ${CYAN}▶${NC} Installing frontend dependencies..."
        cd "$ROOT_DIR/frontend" && npm install --silent
        echo -e "  ${GREEN}✓${NC} Frontend dependencies installed"
    else
        echo -e "  ${GREEN}✓${NC} Frontend node_modules already exists"
    fi

    echo ""
    echo -e "${GREEN}${BOLD}  ✅ Setup complete! Run ${NC}${BOLD}./start.sh${NC}${GREEN}${BOLD} to start the app.${NC}"
    exit 0
}

# Handle flags
if [ "$1" = "--stop" ] || [ "$1" = "stop" ]; then
    stop_servers
fi

if [ "$1" = "--setup" ] || [ "$1" = "setup" ]; then
    setup_project
fi

# ── Trap Ctrl+C to clean shutdown ─────────────────────────────────────────────
cleanup() {
    echo ""
    stop_servers
}
trap cleanup SIGINT SIGTERM

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║         🛡️  ThreatTriage SOC Engine              ║${NC}"
echo -e "${CYAN}${BOLD}║         Automated Alert & Log Analysis           ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo -e ""

# ── Kill any existing instances ───────────────────────────────────────────────
pkill -f "uvicorn threattriage" 2>/dev/null || true
pkill -f "vite.*--host" 2>/dev/null || true
sleep 1

# ── Activate virtual environment ──────────────────────────────────────────────
if [ -f "$ROOT_DIR/.venv/bin/activate" ]; then
    source "$ROOT_DIR/.venv/bin/activate"
    echo -e "  ${GREEN}✓${NC} Python venv activated"
else
    echo -e "  ${RED}✗${NC} No .venv found — run: ${BOLD}./start.sh --setup${NC}"
    exit 1
fi

# ── Check frontend dependencies ──────────────────────────────────────────────
if [ ! -d "$ROOT_DIR/frontend/node_modules" ]; then
    echo -e "  ${RED}✗${NC} Frontend dependencies missing — run: ${BOLD}./start.sh --setup${NC}"
    exit 1
fi

# ── Start Backend (FastAPI + Uvicorn) ─────────────────────────────────────────
echo -e "  ${CYAN}▶${NC} Starting backend API server..."
cd "$ROOT_DIR"
PYTHONPATH=src nohup uvicorn threattriage.main:app \
    --host 0.0.0.0 --port 8000 --log-level info \
    > "$ROOT_DIR/.pids/backend.log" 2>&1 &
BACKEND_PID=$!
echo "$BACKEND_PID" > "$PID_DIR/backend.pid"

# Wait for backend to be ready
for i in {1..10}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Backend running on ${BOLD}http://localhost:8000${NC}  (PID: $BACKEND_PID)"
        break
    fi
    sleep 1
done

if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "  ${RED}✗${NC} Backend failed to start — check .pids/backend.log"
    exit 1
fi

# ── Start Frontend (Vite dev server) ─────────────────────────────────────────
echo -e "  ${CYAN}▶${NC} Starting frontend dev server..."
cd "$ROOT_DIR/frontend"
nohup npm run dev -- --host \
    > "$ROOT_DIR/.pids/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo "$FRONTEND_PID" > "$PID_DIR/frontend.pid"

# Wait for frontend to be ready
for i in {1..8}; do
    FRONTEND_PORT=$(grep -oP 'localhost:\K[0-9]+' "$ROOT_DIR/.pids/frontend.log" 2>/dev/null | head -1)
    if [ -n "$FRONTEND_PORT" ]; then
        break
    fi
    sleep 1
done
FRONTEND_PORT=${FRONTEND_PORT:-5173}

echo -e "  ${GREEN}✓${NC} Frontend running on ${BOLD}http://localhost:${FRONTEND_PORT}${NC}  (PID: $FRONTEND_PID)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e ""
echo -e "${GREEN}${BOLD}  ✅ ThreatTriage is ready!${NC}"
echo -e ""
echo -e "  ${BOLD}Dashboard:${NC}  http://localhost:${FRONTEND_PORT}"
echo -e "  ${BOLD}API Docs:${NC}   http://localhost:8000/docs"
echo -e "  ${BOLD}WebSocket:${NC}  ws://localhost:8000/ws/alerts"
echo -e "  ${BOLD}Health:${NC}     http://localhost:8000/health"
echo -e ""
echo -e "  ${YELLOW}Logs:${NC}  tail -f .pids/backend.log"
echo -e "         tail -f .pids/frontend.log"
echo -e ""
echo -e "  ${RED}Stop:${NC}  ./start.sh --stop  ${CYAN}(or Ctrl+C)${NC}"
echo -e ""

# ── Keep script alive to catch Ctrl+C ────────────────────────────────────────
echo -e "${CYAN}  Streaming backend logs... (Ctrl+C to stop all)${NC}"
echo -e "  ─────────────────────────────────────────────────"
tail -f "$ROOT_DIR/.pids/backend.log"
