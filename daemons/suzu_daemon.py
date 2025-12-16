#!/usr/bin/env python3
"""
Suzu Daemon - Standalone Directory Enumeration Service with Full Heuristics
===========================================================================
Runs as an independent process, communicates with Django via API.
Uses SuzuDirectoryEnumerator with:
- Priority scoring
- CMS detection
- Vector DB weighted paths
- Learned patterns from Kumo
- Technology fingerprint correlation
"""

import os
import sys
import time
import signal
import logging
import requests
import json
from pathlib import Path
from datetime import datetime

# Add project root to path (for isolated repo)
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Also add /app to path (for Docker container)
if '/app' not in sys.path:
    sys.path.insert(0, '/app')

# Configure logging to both file and console FIRST (before Django setup that might use logger)
project_root = Path(__file__).parent.parent
logs_dir = project_root / 'logs' / 'suzu'
logs_dir.mkdir(parents=True, exist_ok=True)
log_file = logs_dir / f'suzu_daemon_{datetime.now().strftime("%Y%m%d")}.log'

# Create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Remove existing handlers to avoid duplicates
logger.handlers.clear()

# File handler with rotation (keep last 7 days)
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setLevel(logging.INFO)
file_formatter = logging.Formatter(
    '%(asctime)s [SUZU] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter(
    '%(asctime)s [SUZU] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# Prevent propagation to root logger
logger.propagate = False

# Setup Django for SuzuDirectoryEnumerator (optional - enumerator will handle it if needed)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
try:
    import django
    django.setup()
    logger.debug("✅ Django setup complete")
except Exception as e:
    # Django setup is optional - SuzuDirectoryEnumerator will handle it
    logger.debug(f"Django setup skipped (will be handled by enumerator): {e}")

# Load agent configuration
from daemons.config_loader import AgentConfig
config = AgentConfig('suzu')

# Configuration from config file or environment variables
DJANGO_API_BASE = config.get_server_url()
PID_FILE = config.get_pid_file()
ENUM_INTERVAL = config.get_enum_interval(60)
MAX_ENUMS_PER_CYCLE = config.get_max_enums_per_cycle(2)


class SuzuDaemon:
    """Standalone Suzu daemon process for directory enumeration with full heuristics"""
    
    def __init__(self):
        self.running = False
        self.paused = False  # Pause state
        self.pid = os.getpid()
        self.config = config  # Store config reference
        self._current_task = None  # Track current work for graceful pause
        self._retry_count = 0  # Retry counter for exponential backoff
        
        # Progress tracking for dashboard
        self.progress = {
            'status': 'idle',  # 'idle', 'enumerating', 'processing', 'completed'
            'current_target': None,
            'current_eggrecord_id': None,
            'current_step': None,  # 'cms_detection', 'vector_query', 'enumeration', 'scoring'
            'progress_percent': 0,
            'cycle_number': 0,
            'enumerated_this_cycle': 0,
            'total_in_queue': 0,
            'paths_found': 0,
            'cms_detected': None,
            'started_at': None,
            'estimated_completion': None
        }
        
        # Initialize SuzuDirectoryEnumerator with full heuristics
        try:
            # Ensure suzu module is importable
            suzu_path = project_root / 'suzu'
            if str(suzu_path.parent) not in sys.path:
                sys.path.insert(0, str(suzu_path.parent))
            
            from suzu.directory_enumerator import SuzuDirectoryEnumerator
            self.enumerator = SuzuDirectoryEnumerator(parallel_enabled=True)
            logger.info("✅ SuzuDirectoryEnumerator initialized with full heuristics")
        except ImportError as e:
            logger.error(f"❌ Failed to import SuzuDirectoryEnumerator: {e}")
            logger.debug(f"Python path: {sys.path[:5]}")
            logger.debug(f"Project root: {project_root}")
            logger.debug(f"Suzu path exists: {(project_root / 'suzu').exists()}")
            self.enumerator = None
        except Exception as e:
            logger.error(f"❌ Failed to initialize SuzuDirectoryEnumerator: {e}", exc_info=True)
            self.enumerator = None
        
    def _get_eggrecords(self):
        """Get eggrecords to enumerate from Django API with exponential backoff retry"""
        retry_config = self.config.get_retry_config()
        timeout_config = self.config.get_timeout_config()
        max_retries = retry_config['max_retries']
        base_wait = retry_config['base_wait']
        max_wait = retry_config['max_wait']
        
        for attempt in range(max_retries):
            try:
                url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/suzu/eggrecords/"
                params = {'limit': self.config.get_max_enums_per_cycle(2)}
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
    
    def _enumerate_target(self, eggrecord_id: str, target: str):
        """
        Perform directory enumeration on target using full heuristics system.
        
        Args:
            eggrecord_id: UUID of the eggrecord
            target: Target domain/subdomain
        
        Returns:
            Dictionary with enumeration results including priority scores
        """
        if not self.enumerator:
            return {
                'success': False,
                'error': 'SuzuDirectoryEnumerator not initialized'
            }
        
        try:
            # Use SuzuDirectoryEnumerator with full heuristics
            # This includes: CMS detection, priority scoring, vector DB, learned patterns
            result = self.enumerator.enumerate_egg_record(
                egg_record_id=eggrecord_id,
                write_to_db=False,  # We'll submit via API instead
                egg_record_data={'subDomain': target, 'domainname': target}
            )
            
            if result.get('success'):
                logger.info(f"✅ Enumeration completed: {result.get('paths_discovered', 0)} paths found")
                return result
            else:
                logger.warning(f"❌ Enumeration failed: {result.get('error', 'Unknown error')}")
                return result
                
        except Exception as e:
            logger.error(f"❌ Error during enumeration: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }
    
    def _update_progress_api(self):
        """Update progress via API for dashboard"""
        try:
            url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/suzu/progress/"
            # Add timestamp
            progress_data = self.progress.copy()
            progress_data['started_at'] = progress_data.get('started_at')
            if progress_data.get('started_at'):
                progress_data['started_at'] = progress_data['started_at']
            
            response = requests.post(url, json=progress_data, timeout=5)
            if response.status_code == 200:
                logger.debug("Progress updated via API")
        except Exception as e:
            logger.debug(f"Could not update progress API: {e}")
    
    def _submit_enum_result(self, eggrecord_id, target, result):
        """
        Submit enumeration result to Django API with full heuristics data.
        
        The result from SuzuDirectoryEnumerator includes:
        - paths_discovered: List of discovered paths with metadata
        - cms_detection: CMS detection results
        - priority_scores: Priority scores for each path
        - enumeration_metadata: Tool used, wordlist, etc.
        """
        try:
            timeout_config = self.config.get_timeout_config()
            url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/enumeration/"
            
            # Extract enumeration results from SuzuDirectoryEnumerator output
            enumeration_results = result.get('enumeration_results', [])
            paths_discovered = result.get('paths_discovered', [])
            cms_detection = result.get('cms_detection')
            enumeration_metadata = result.get('enumeration_metadata', {})
            
            # Prepare data for API
            data = {
                'eggrecord_id': eggrecord_id,
                'target': target,
                'result': {
                    'success': result.get('success', False),
                    'paths_discovered': len(paths_discovered),
                    'enumeration_results': enumeration_results,  # Full results with priority scores
                    'cms_detection': cms_detection,
                    'enumeration_metadata': enumeration_metadata,
                    'duration': result.get('duration', 0),
                    'results_stored': result.get('results_stored', 0)
                }
            }
            
            response = requests.post(url, json=data, timeout=timeout_config['submit_timeout'])
            
            if response.status_code == 200:
                result_data = response.json()
                if result_data.get('success'):
                    paths_inserted = result_data.get('paths_inserted', 0)
                    logger.info(f"✅ Enumeration result submitted for {target}: {paths_inserted} paths with heuristics")
                    return True
                else:
                    logger.warning(f"API returned error: {result_data.get('error')}")
            else:
                logger.warning(f"API request failed: {response.status_code}: {response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error submitting enumeration result: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
        
        return False
    
    def pause(self):
        """Pause processing (finish current task first)"""
        logger.info("⏸️  Pausing Suzu daemon...")
        self.paused = True
        # Wait for current task to finish (with timeout)
        timeout = 300  # Max 5 minutes to finish current enumeration
        start_time = time.time()
        while self._current_task is not None and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        if self._current_task is not None:
            logger.warning("⚠️  Current task did not finish before pause timeout")
        logger.info("✅ Suzu daemon paused")
    
    def resume(self):
        """Resume processing"""
        logger.info("▶️  Resuming Suzu daemon...")
        self.paused = False
        logger.info("✅ Suzu daemon resumed")
    
    def graceful_shutdown(self):
        """Graceful shutdown - finish current work then stop"""
        logger.info("🛑 Initiating graceful shutdown...")
        self.running = False
        # Wait for current task to finish
        timeout = 300  # 5 minutes for enumeration
        start_time = time.time()
        while self._current_task is not None and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        logger.info("✅ Graceful shutdown complete")
    
    def _enum_loop(self):
        """Main enumeration loop"""
        logger.info(f"🔄 Suzu daemon enumeration loop started (PID: {self.pid})")
        cycle_count = 0
        
        while self.running:
            try:
                # Check pause state
                while self.paused and self.running:
                    time.sleep(1)
                
                if not self.running:
                    break
                
                cycle_count += 1
                logger.info(f"🔄 Suzu enumeration cycle #{cycle_count}")
                
                # Update progress
                self.progress['cycle_number'] = cycle_count
                self.progress['status'] = 'enumerating'
                self.progress['started_at'] = time.time()
                self._update_progress_api()
                
                # Get eggrecords to enumerate
                eggrecords = self._get_eggrecords()
                
                if not eggrecords:
                    logger.debug("No eggrecords to enumerate, waiting...")
                    self.progress['status'] = 'idle'
                    self.progress['current_target'] = None
                    self.progress['current_step'] = None
                    self.progress['progress_percent'] = 0
                    self._update_progress_api()
                    time.sleep(self.config.get_enum_interval(60))
                    continue
                
                logger.info(f"📋 Found {len(eggrecords)} eggrecords to enumerate")
                self.progress['total_in_queue'] = len(eggrecords)
                self.progress['enumerated_this_cycle'] = 0
                self._update_progress_api()
                
                # Enumerate each eggrecord
                enumerated = 0
                total_targets = len(eggrecords)
                
                for idx, eggrecord in enumerate(eggrecords):
                    if not self.running or self.paused:
                        break
                    
                    try:
                        eggrecord_id = str(eggrecord['id'])
                        target = eggrecord.get('subDomain') or eggrecord.get('domainname', 'unknown')
                        
                        if not target or target == 'unknown':
                            logger.warning(f"⚠️  Skipping eggrecord {eggrecord_id}: no valid target")
                            continue
                        
                        # Mark current task
                        self._current_task = eggrecord_id
                        
                        # Update progress
                        self.progress['current_target'] = target
                        self.progress['current_eggrecord_id'] = eggrecord_id
                        self.progress['current_step'] = 'starting'
                        self.progress['progress_percent'] = int((idx / total_targets) * 100)
                        
                        logger.info(f"🔔 Enumerating directories for {target} ({eggrecord_id}) with full heuristics")
                        
                        # Update progress - CMS detection phase
                        self.progress['current_step'] = 'cms_detection'
                        self.progress['progress_percent'] = int(((idx + 0.2) / total_targets) * 100)
                        self._update_progress_api()
                        
                        # Perform enumeration using full heuristics system
                        self.progress['current_step'] = 'enumeration'
                        self.progress['progress_percent'] = int(((idx + 0.5) / total_targets) * 100)
                        self._update_progress_api()
                        
                        result = self._enumerate_target(eggrecord_id, target)
                        
                        if result.get('success'):
                            # Update progress - scoring phase
                            self.progress['current_step'] = 'scoring'
                            self.progress['progress_percent'] = int(((idx + 0.8) / total_targets) * 100)
                            self._update_progress_api()
                            
                            # Submit result to API (includes priority scores, CMS detection, etc.)
                            self._submit_enum_result(
                                eggrecord_id,
                                target,
                                result
                            )
                            enumerated += 1
                            self.progress['enumerated_this_cycle'] = enumerated
                            
                            # Log heuristics summary
                            cms_detection = result.get('cms_detection')
                            if cms_detection:
                                self.progress['cms_detected'] = cms_detection.get('cms')
                                logger.info(f"🔍 CMS detected: {cms_detection.get('cms')} (confidence: {cms_detection.get('confidence', 0):.2f})")
                            
                            paths_count = result.get('paths_discovered', [])
                            if isinstance(paths_count, list):
                                self.progress['paths_found'] += len(paths_count)
                                logger.info(f"📊 Discovered {len(paths_count)} paths with priority scores")
                        else:
                            logger.warning(f"❌ Enumeration failed for {target}: {result.get('error', 'Unknown error')}")
                        
                        # Clear current task and progress
                        self._current_task = None
                        self.progress['current_step'] = 'completed'
                        self.progress['progress_percent'] = int(((idx + 1) / total_targets) * 100)
                        self._update_progress_api()
                        
                        time.sleep(2)  # Delay between enumerations (slightly longer for heuristics processing)
                        
                    except Exception as e:
                        self._current_task = None
                        logger.error(f"❌ Error enumerating eggrecord: {e}", exc_info=True)
                        continue
                
                if enumerated > 0:
                    logger.info(f"✅ Completed {enumerated} enumerations this cycle")
                
                # Update progress - cycle complete
                self.progress['status'] = 'completed'
                self.progress['current_target'] = None
                self.progress['current_eggrecord_id'] = None
                self.progress['current_step'] = None
                self.progress['progress_percent'] = 100
                self._update_progress_api()
                
                # Wait before next cycle
                time.sleep(self.config.get_enum_interval(60))
                
                # Reset progress for next cycle
                self.progress['paths_found'] = 0
                self.progress['cms_detected'] = None
                self.progress['status'] = 'idle'
                self._update_progress_api()
                
            except KeyboardInterrupt:
                logger.info("⚠️  Enumeration loop interrupted")
                self.running = False
                break
            except Exception as e:
                logger.error(f"❌ Fatal error in enumeration loop: {e}", exc_info=True)
                time.sleep(10)  # Wait before retrying
        
        logger.info("🛑 Suzu daemon enumeration loop ended")
    
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
            setproctitle.setproctitle(f"suzu-recon-daemon [PID:{self.pid}]")
        except ImportError:
            pass
        
        self.running = True
        logger.info(f"🚀 Suzu daemon started (PID: {self.pid})")
        self._enum_loop()
        return True
    
    def stop(self):
        """Stop the daemon"""
        logger.info("🛑 Stopping Suzu daemon...")
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
    daemon = SuzuDaemon()
    try:
        daemon.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        daemon.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        daemon.stop()

