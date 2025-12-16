#!/usr/bin/env python3
"""
Kaze Daemon - Standalone Port Scanner Service
=============================================
Runs as an independent process, communicates with Django via API.
"""

import os
import sys
import time
import signal
import logging
import requests
import json
from pathlib import Path
from enum import Enum
from dataclasses import asdict, is_dataclass
from datetime import datetime

# Add project root to path (for isolated repo)
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging to both file and console
project_root = Path(__file__).parent.parent
logs_dir = project_root / 'logs' / 'kaze'
logs_dir.mkdir(parents=True, exist_ok=True)
log_file = logs_dir / f'kaze_daemon_{datetime.now().strftime("%Y%m%d")}.log'

# Create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Remove existing handlers to avoid duplicates
logger.handlers.clear()

# File handler with rotation (keep last 7 days)
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter(
    '%(asctime)s [KAZE] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter(
    '%(asctime)s [KAZE] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Prevent propagation to root logger
logger.propagate = False

# Load agent configuration
from daemons.config_loader import AgentConfig
config = AgentConfig('kaze')

# Configuration from config file or environment variables
DJANGO_API_BASE = config.get_server_url()
PID_FILE = config.get_pid_file()
SCAN_INTERVAL = config.get_scan_interval(30)
MAX_SCANS_PER_CYCLE = config.get_max_scans_per_cycle(5)


class KazeDaemon:
    """Standalone Kaze daemon process"""
    
    def __init__(self):
        self.running = False
        self.paused = False  # Pause state
        self.pid = os.getpid()
        self.scanner = None
        self.config = config  # Store config reference
        self._current_task = None  # Track current work for graceful pause
        self._retry_count = 0  # Retry counter for exponential backoff
        self._init_scanner()
        
    def _init_scanner(self):
        """Initialize Nmap scanner"""
        try:
            from kaze.nmap_scanner import get_kaze_scanner
            self.scanner = get_kaze_scanner(parallel_enabled=True)
            if self.scanner:
                logger.info("✅ Kaze Nmap scanner initialized")
            else:
                logger.error("❌ Failed to initialize scanner: get_kaze_scanner returned None")
                self.scanner = None
        except ImportError as e:
            logger.error(f"❌ Failed to import kaze scanner module: {e}", exc_info=True)
            self.scanner = None
        except Exception as e:
            logger.error(f"❌ Failed to initialize scanner: {e}", exc_info=True)
            self.scanner = None
    
    def _get_eggrecords(self):
        """Get eggrecords to scan from Django API with exponential backoff retry"""
        retry_config = self.config.get_retry_config()
        timeout_config = self.config.get_timeout_config()
        max_retries = retry_config['max_retries']
        base_wait = retry_config['base_wait']
        max_wait = retry_config['max_wait']
        
        for attempt in range(max_retries):
            try:
                url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/kaze/eggrecords/"
                params = {'limit': self.config.get_max_scans_per_cycle(5)}
                response = requests.get(url, params=params, timeout=timeout_config['api_timeout'])
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        self._retry_count = 0  # Reset on success
                        return data.get('eggrecords', [])
                    else:
                        logger.warning(f"API returned error: {data.get('error')}")
                else:
                    logger.warning(f"API request failed: {response.status_code}")
            except requests.exceptions.RequestException as e:
                self._retry_count = attempt + 1
                if attempt < max_retries - 1:
                    wait_time = min(base_wait ** (attempt + 1), max_wait)  # Exponential backoff
                    logger.warning(f"API error (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Max retries reached, API unavailable: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                break
        
        return []
    
    def _sanitize_for_json(self, obj):
        """Recursively sanitize objects for JSON serialization"""
        if obj is None:
            return None
        elif isinstance(obj, Enum):
            # Convert Enum to its value
            return obj.value if hasattr(obj, 'value') else str(obj)
        elif is_dataclass(obj):
            # Convert dataclass to dict
            return self._sanitize_for_json(asdict(obj))
        elif isinstance(obj, dict):
            # Recursively sanitize dictionary values
            return {k: self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            # Recursively sanitize list items
            return [self._sanitize_for_json(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool)):
            # Already JSON-serializable
            return obj
        else:
            # Try to convert to string for unknown types
            try:
                # Check if it has a __dict__ attribute (object with attributes)
                if hasattr(obj, '__dict__'):
                    return self._sanitize_for_json(obj.__dict__)
                else:
                    return str(obj)
            except Exception:
                return str(obj)
    
    def _submit_scan_result(self, eggrecord_id, target, scan_type, result):
        """Submit scan result to Django API"""
        try:
            # Sanitize result to ensure JSON serialization works
            sanitized_result = self._sanitize_for_json(result)
            
            timeout_config = self.config.get_timeout_config()
            url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/kaze/scan/"
            data = {
                'eggrecord_id': eggrecord_id,
                'target': target,
                'scan_type': scan_type,
                'result': sanitized_result
            }
            response = requests.post(url, json=data, timeout=timeout_config['submit_timeout'])
            
            if response.status_code == 200:
                result_data = response.json()
                if result_data.get('success'):
                    logger.info(f"✅ Scan result submitted for {target}")
                    return True
                else:
                    logger.warning(f"API returned error: {result_data.get('error')}")
            else:
                logger.warning(f"API request failed: {response.status_code}: {response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error submitting scan result: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
        
        return False
    
    def pause(self):
        """Pause processing (finish current task first)"""
        logger.info("⏸️  Pausing Kaze daemon...")
        self.paused = True
        # Wait for current task to finish (with timeout)
        timeout = 60  # Max 60 seconds to finish current task
        start_time = time.time()
        while self._current_task is not None and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        if self._current_task is not None:
            logger.warning("⚠️  Current task did not finish before pause timeout")
        logger.info("✅ Kaze daemon paused")
    
    def resume(self):
        """Resume processing"""
        logger.info("▶️  Resuming Kaze daemon...")
        self.paused = False
        logger.info("✅ Kaze daemon resumed")
    
    def graceful_shutdown(self):
        """Graceful shutdown - finish current work then stop"""
        logger.info("🛑 Initiating graceful shutdown...")
        self.running = False
        # Wait for current task to finish
        timeout = 30
        start_time = time.time()
        while self._current_task is not None and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        logger.info("✅ Graceful shutdown complete")
    
    def _scan_loop(self):
        """Main scanning loop"""
        logger.info(f"🔄 Kaze daemon scan loop started (PID: {self.pid})")
        cycle_count = 0
        
        while self.running:
            try:
                # Check pause state
                while self.paused and self.running:
                    time.sleep(1)
                
                if not self.running:
                    break
                
                cycle_count += 1
                logger.info(f"🔄 Kaze scan cycle #{cycle_count}")
                
                if not self.scanner:
                    logger.warning("⚠️  Scanner not available, waiting...")
                    time.sleep(self.config.get_scan_interval(30))
                    continue
                
                # Get eggrecords to scan
                eggrecords = self._get_eggrecords()
                
                if not eggrecords:
                    logger.debug("No eggrecords to scan, waiting...")
                    time.sleep(self.config.get_scan_interval(30))
                    continue
                
                logger.info(f"📋 Found {len(eggrecords)} eggrecords to scan")
                
                # Scan each eggrecord
                scanned = 0
                for eggrecord in eggrecords:
                    if not self.running or self.paused:
                        break
                    
                    try:
                        eggrecord_id = str(eggrecord['id'])
                        target = eggrecord.get('subDomain') or eggrecord.get('domainname', 'unknown')
                        
                        # Mark current task
                        self._current_task = eggrecord_id
                        
                        logger.info(f"🔍 Scanning {target} ({eggrecord_id})")
                        
                        # Perform scan (pass eggrecord data to avoid Django model lookup)
                        # Set write_to_db=False so we submit via API for consistent timestamping
                        result = self.scanner.scan_egg_record(eggrecord_id, scan_type='kaze_port_scan', write_to_db=False, egg_record_data=eggrecord)
                        
                        if result.get('success'):
                            # Submit result to API (this will write to database with consistent timestamping)
                            self._submit_scan_result(
                                eggrecord_id,
                                target,
                                'kaze_port_scan',
                                result
                            )
                            scanned += 1
                        else:
                            logger.warning(f"❌ Scan failed for {target}: {result.get('error', 'Unknown error')}")
                        
                        # Clear current task
                        self._current_task = None
                        
                        time.sleep(0.1)  # Small delay between scans
                        
                    except Exception as e:
                        self._current_task = None
                        logger.error(f"❌ Error scanning eggrecord: {e}", exc_info=True)
                        continue
                
                if scanned > 0:
                    logger.info(f"✅ Completed {scanned} scans this cycle")
                
                # Wait before next cycle
                time.sleep(self.config.get_scan_interval(30))
                
            except KeyboardInterrupt:
                logger.info("⚠️  Scan loop interrupted")
                self.running = False
                break
            except Exception as e:
                logger.error(f"❌ Fatal error in scan loop: {e}", exc_info=True)
                time.sleep(10)  # Wait before retrying
        
        logger.info("🛑 Kaze daemon scan loop ended")
    
    def start(self):
        """Start the daemon"""
        if self.running:
            logger.warning("Daemon already running")
            return False
        
        # Write PID file
        try:
            pid_file = self.config.get_pid_file()
            pid_file.write_text(str(self.pid))
            logger.info(f"📝 PID file written: {pid_file} (PID: {self.pid})")
        except Exception as e:
            logger.warning(f"Could not write PID file: {e}")
        
        # Set process name
        try:
            import setproctitle
            setproctitle.setproctitle(f"kaze-recon-daemon [PID:{self.pid}]")
        except ImportError:
            pass
        
        self.running = True
        logger.info(f"🚀 Kaze daemon started (PID: {self.pid})")
        self._scan_loop()
        return True
    
    def stop(self):
        """Stop the daemon"""
        logger.info("🛑 Stopping Kaze daemon...")
        self.running = False
        
        # Remove PID file
        try:
            pid_file = self.config.get_pid_file()
            if pid_file.exists():
                pid_file.unlink()
        except Exception as e:
            logger.warning(f"Could not remove PID file: {e}")


def signal_handler(signum, frame):
    """Handle shutdown and control signals"""
    if signum == signal.SIGTERM or signum == signal.SIGINT:
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        if daemon:
            daemon.graceful_shutdown()
            daemon.stop()
        sys.exit(0)
    elif signum == signal.SIGUSR1:
        logger.info("Received SIGUSR1, pausing...")
        if daemon:
            daemon.pause()
    elif signum == signal.SIGUSR2:
        logger.info("Received SIGUSR2, resuming...")
        if daemon:
            daemon.resume()


# Global daemon instance
daemon = None

if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGUSR1, signal_handler)  # Pause
    signal.signal(signal.SIGUSR2, signal_handler)  # Resume
    
    # Check if already running
    pid_file = config.get_pid_file()
    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text().strip())
            # Check if process is actually running
            try:
                os.kill(old_pid, 0)  # Signal 0 just checks if process exists
                logger.error(f"❌ Daemon already running (PID: {old_pid})")
                sys.exit(1)
            except ProcessLookupError:
                # Process doesn't exist, remove stale PID file
                pid_file.unlink()
                logger.info("Removed stale PID file")
        except Exception as e:
            logger.warning(f"Error checking PID file: {e}")
    
    # Create and start daemon
    daemon = KazeDaemon()
    try:
        daemon.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        daemon.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        daemon.stop()
        sys.exit(1)

