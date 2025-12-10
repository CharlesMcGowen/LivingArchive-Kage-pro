#!/usr/bin/env python3
"""
Daemon Management Script
=======================
Start, stop, and check status of Kage, Kumo, and Ryu daemons.
"""

import os
import sys
import subprocess
import signal
from pathlib import Path

DAEMON_DIR = Path(__file__).parent
PID_DIR = Path('/tmp')

DAEMONS = {
    'kage': {
        'script': DAEMON_DIR / 'kage_daemon.py',
        'pid_file': PID_DIR / 'kage_daemon.pid',
        'name': 'Kage'
    },
    'kumo': {
        'script': DAEMON_DIR / 'kumo_daemon.py',
        'pid_file': PID_DIR / 'kumo_daemon.pid',
        'name': 'Kumo'
    },
    'ryu': {
        'script': DAEMON_DIR / 'ryu_daemon.py',
        'pid_file': PID_DIR / 'ryu_daemon.pid',
        'name': 'Ryu'
    }
}


def get_pid(daemon_name):
    """Get PID from PID file"""
    if daemon_name not in DAEMONS:
        return None
    
    pid_file = DAEMONS[daemon_name]['pid_file']
    if not pid_file.exists():
        return None
    
    try:
        return int(pid_file.read_text().strip())
    except Exception:
        return None


def is_running(daemon_name):
    """Check if daemon is running"""
    pid = get_pid(daemon_name)
    if not pid:
        return False
    
    try:
        os.kill(pid, 0)  # Signal 0 just checks if process exists
        return True
    except ProcessLookupError:
        # Process doesn't exist, remove stale PID file
        DAEMONS[daemon_name]['pid_file'].unlink()
        return False
    except PermissionError:
        # Process exists but we don't have permission (running as different user)
        return True


def start_daemon(daemon_name):
    """Start a daemon"""
    if daemon_name not in DAEMONS:
        print(f"❌ Unknown daemon: {daemon_name}")
        return False
    
    if is_running(daemon_name):
        pid = get_pid(daemon_name)
        print(f"⚠️  {DAEMONS[daemon_name]['name']} is already running (PID: {pid})")
        return False
    
    script = DAEMONS[daemon_name]['script']
    if not script.exists():
        print(f"❌ Daemon script not found: {script}")
        return False
    
    try:
        # Start daemon in background
        process = subprocess.Popen(
            [sys.executable, str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(DAEMON_DIR.parent.parent.parent)
        )
        
        # Give it a moment to start
        import time
        time.sleep(1)
        
        if is_running(daemon_name):
            pid = get_pid(daemon_name)
            print(f"✅ {DAEMONS[daemon_name]['name']} started (PID: {pid})")
            return True
        else:
            print(f"❌ {DAEMONS[daemon_name]['name']} failed to start")
            return False
    except Exception as e:
        print(f"❌ Error starting {daemon_name}: {e}")
        return False


def pause_daemon(daemon_name):
    """Pause a daemon (SIGUSR1)"""
    if daemon_name not in DAEMONS:
        print(f"❌ Unknown daemon: {daemon_name}")
        return False
    
    if not is_running(daemon_name):
        print(f"⚠️  {DAEMONS[daemon_name]['name']} is not running")
        return False
    
    pid = get_pid(daemon_name)
    try:
        os.kill(pid, signal.SIGUSR1)
        print(f"✅ {DAEMONS[daemon_name]['name']} paused (SIGUSR1 sent)")
        return True
    except ProcessLookupError:
        print(f"⚠️  {DAEMONS[daemon_name]['name']} process not found")
        return False
    except Exception as e:
        print(f"❌ Error pausing {daemon_name}: {e}")
        return False


def resume_daemon(daemon_name):
    """Resume a daemon (SIGUSR2)"""
    if daemon_name not in DAEMONS:
        print(f"❌ Unknown daemon: {daemon_name}")
        return False
    
    if not is_running(daemon_name):
        print(f"⚠️  {DAEMONS[daemon_name]['name']} is not running")
        return False
    
    pid = get_pid(daemon_name)
    try:
        os.kill(pid, signal.SIGUSR2)
        print(f"✅ {DAEMONS[daemon_name]['name']} resumed (SIGUSR2 sent)")
        return True
    except ProcessLookupError:
        print(f"⚠️  {DAEMONS[daemon_name]['name']} process not found")
        return False
    except Exception as e:
        print(f"❌ Error resuming {daemon_name}: {e}")
        return False


def stop_daemon(daemon_name):
    """Stop a daemon"""
    if daemon_name not in DAEMONS:
        print(f"❌ Unknown daemon: {daemon_name}")
        return False
    
    if not is_running(daemon_name):
        print(f"⚠️  {DAEMONS[daemon_name]['name']} is not running")
        return False
    
    pid = get_pid(daemon_name)
    try:
        os.kill(pid, signal.SIGTERM)
        
        # Wait for process to stop
        import time
        for _ in range(10):
            if not is_running(daemon_name):
                print(f"✅ {DAEMONS[daemon_name]['name']} stopped")
                return True
            time.sleep(0.5)
        
        # Force kill if still running
        if is_running(daemon_name):
            os.kill(pid, signal.SIGKILL)
            print(f"✅ {DAEMONS[daemon_name]['name']} force-killed")
            return True
        
    except ProcessLookupError:
        print(f"⚠️  {DAEMONS[daemon_name]['name']} process not found")
        return True
    except Exception as e:
        print(f"❌ Error stopping {daemon_name}: {e}")
        return False


def status_daemon(daemon_name):
    """Get daemon status"""
    if daemon_name not in DAEMONS:
        print(f"❌ Unknown daemon: {daemon_name}")
        return
    
    if is_running(daemon_name):
        pid = get_pid(daemon_name)
        print(f"✅ {DAEMONS[daemon_name]['name']} is running (PID: {pid})")
    else:
        print(f"❌ {DAEMONS[daemon_name]['name']} is not running")


def status_all():
    """Get status of all daemons"""
    print("Daemon Status:")
    print("-" * 40)
    for daemon_name in DAEMONS.keys():
        status_daemon(daemon_name)


def main():
    """Main CLI"""
    if len(sys.argv) < 2:
        print("Usage: manage_daemons.py <action> [daemon_name]")
        print("Actions: start, stop, pause, resume, status, restart")
        print("Daemons: kage, kumo, ryu, all")
        sys.exit(1)
    
    action = sys.argv[1].lower()
    daemon_name = sys.argv[2].lower() if len(sys.argv) > 2 else None
    
    if action == 'status':
        if daemon_name and daemon_name != 'all':
            status_daemon(daemon_name)
        else:
            status_all()
    
    elif action == 'start':
        if daemon_name == 'all':
            for name in DAEMONS.keys():
                start_daemon(name)
        elif daemon_name:
            start_daemon(daemon_name)
        else:
            print("❌ Please specify daemon name or 'all'")
    
    elif action == 'stop':
        if daemon_name == 'all':
            for name in DAEMONS.keys():
                stop_daemon(name)
        elif daemon_name:
            stop_daemon(daemon_name)
        else:
            print("❌ Please specify daemon name or 'all'")
    
    elif action == 'pause':
        if daemon_name == 'all':
            for name in DAEMONS.keys():
                pause_daemon(name)
        elif daemon_name:
            pause_daemon(daemon_name)
        else:
            print("❌ Please specify daemon name or 'all'")
    
    elif action == 'resume':
        if daemon_name == 'all':
            for name in DAEMONS.keys():
                resume_daemon(name)
        elif daemon_name:
            resume_daemon(daemon_name)
        else:
            print("❌ Please specify daemon name or 'all'")
    
    elif action == 'restart':
        if daemon_name == 'all':
            for name in DAEMONS.keys():
                stop_daemon(name)
                import time
                time.sleep(1)
                start_daemon(name)
        elif daemon_name:
            stop_daemon(daemon_name)
            import time
            time.sleep(1)
            start_daemon(daemon_name)
        else:
            print("❌ Please specify daemon name or 'all'")
    
    else:
        print(f"❌ Unknown action: {action}")
        sys.exit(1)


if __name__ == '__main__':
    main()

