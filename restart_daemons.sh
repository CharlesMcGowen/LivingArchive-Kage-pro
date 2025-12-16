#!/bin/bash
# Restart daemons script for Kage-pro agents
# This script stops and starts the ryu, kumo, and kaze daemons

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔄 Restarting daemons..."

# Function to stop a daemon
stop_daemon() {
    local daemon_name=$1
    local pid_file="/tmp/${daemon_name}_daemon.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo "🛑 Stopping ${daemon_name} daemon (PID: $pid)..."
            kill -TERM "$pid" 2>/dev/null || true
            sleep 2
            # Force kill if still running
            if ps -p "$pid" > /dev/null 2>&1; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$pid_file"
    else
        # Try to find and kill by process name
        pkill -f "${daemon_name}_daemon.py" 2>/dev/null || true
    fi
}

# Function to start a daemon
start_daemon() {
    local daemon_name=$1
    local daemon_script="daemons/${daemon_name}_daemon.py"
    
    if [ ! -f "$daemon_script" ]; then
        echo "⚠️  Daemon script not found: $daemon_script"
        return 1
    fi
    
    echo "🚀 Starting ${daemon_name} daemon..."
    nohup python3 "$daemon_script" > /dev/null 2>&1 &
    sleep 1
    
    local pid_file="/tmp/${daemon_name}_daemon.pid"
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            echo "✅ ${daemon_name} daemon started (PID: $pid)"
        else
            echo "❌ ${daemon_name} daemon failed to start"
            return 1
        fi
    else
        echo "⚠️  ${daemon_name} daemon PID file not found, but process may be running"
    fi
}

# Stop all daemons
echo "📋 Stopping existing daemons..."
stop_daemon "ryu"
stop_daemon "kumo"
stop_daemon "kaze"

# Wait a moment for processes to fully stop
sleep 2

# Start all daemons
echo ""
echo "📋 Starting daemons..."
start_daemon "ryu"
start_daemon "kumo"
start_daemon "kaze"

echo ""
echo "✅ Daemon restart complete!"
echo ""
echo "📊 Check daemon status:"
echo "   ps aux | grep -E '(ryu|kumo|kaze)_daemon' | grep -v grep"
echo ""
echo "📝 View logs:"
echo "   tail -f logs/ryu/ryu_daemon_\$(date +%Y%m%d).log"
echo "   tail -f logs/kumo/kumo_daemon_\$(date +%Y%m%d).log"
echo "   tail -f logs/kaze/kaze_daemon_\$(date +%Y%m%d).log"
