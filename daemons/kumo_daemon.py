#!/usr/bin/env python3
"""
Kumo Daemon - Standalone HTTP Spider Service
============================================
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

# Add project root to path (for isolated repo)
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [KUMO] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration
DJANGO_API_BASE = os.getenv('DJANGO_API_BASE', 'http://127.0.0.1:9000')
PID_FILE = Path('/tmp/kumo_daemon.pid')
SPIDER_INTERVAL = int(os.getenv('KUMO_SPIDER_INTERVAL', '45'))
MAX_SPIDERS_PER_CYCLE = int(os.getenv('KUMO_MAX_SPIDERS', '3'))


class KumoDaemon:
    """Standalone Kumo daemon process"""
    
    def __init__(self):
        self.running = False
        self.paused = False  # Pause state
        self.pid = os.getpid()
        self.spider = None
        self._current_task = None  # Track current work for graceful pause
        self._retry_count = 0  # Retry counter for exponential backoff
        self._init_spider()
        
    def _init_spider(self):
        """Initialize HTTP spider"""
        try:
            from kumo.http_spider import KumoHttpSpider
            self.spider = KumoHttpSpider()
            logger.info("✅ Kumo HTTP spider initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize spider: {e}")
            self.spider = None
    
    def _get_eggrecords(self):
        """Get eggrecords to spider from Django API with exponential backoff retry"""
        max_retries = 5
        base_wait = 2  # Base wait time in seconds
        
        for attempt in range(max_retries):
            try:
                url = f"{DJANGO_API_BASE}/reconnaissance/api/daemon/kumo/eggrecords/"
                params = {'limit': MAX_SPIDERS_PER_CYCLE}
                response = requests.get(url, params=params, timeout=10)
                
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
                    wait_time = min(base_wait ** (attempt + 1), 60)  # Exponential backoff, max 60s
                    logger.warning(f"API error (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Max retries reached, API unavailable: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                break
        
        return []
    
    def _submit_spider_result(self, eggrecord_id, target, result):
        """Submit spider result to Django API"""
        try:
            url = f"{DJANGO_API_BASE}/reconnaissance/api/daemon/kumo/spider/"
            data = {
                'eggrecord_id': eggrecord_id,
                'target': target,
                'result': result
            }
            response = requests.post(url, json=data, timeout=30)
            
            if response.status_code == 200:
                result_data = response.json()
                if result_data.get('success'):
                    logger.info(f"✅ Spider result submitted for {target}")
                    return True
                else:
                    logger.warning(f"API returned error: {result_data.get('error')}")
            else:
                logger.warning(f"API request failed: {response.status_code}: {response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error submitting spider result: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
        
        return False
    
    def pause(self):
        """Pause processing (finish current task first)"""
        logger.info("⏸️  Pausing Kumo daemon...")
        self.paused = True
        # Wait for current task to finish (with timeout)
        timeout = 60  # Max 60 seconds to finish current task
        start_time = time.time()
        while self._current_task is not None and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        if self._current_task is not None:
            logger.warning("⚠️  Current task did not finish before pause timeout")
        logger.info("✅ Kumo daemon paused")
    
    def resume(self):
        """Resume processing"""
        logger.info("▶️  Resuming Kumo daemon...")
        self.paused = False
        logger.info("✅ Kumo daemon resumed")
    
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
    
    def _spider_loop(self):
        """Main spidering loop"""
        logger.info(f"🔄 Kumo daemon spider loop started (PID: {self.pid})")
        cycle_count = 0
        
        while self.running:
            try:
                # Check pause state
                while self.paused and self.running:
                    time.sleep(1)
                
                if not self.running:
                    break
                
                cycle_count += 1
                logger.info(f"🔄 Kumo spider cycle #{cycle_count}")
                
                if not self.spider:
                    logger.warning("⚠️  Spider not available, waiting...")
                    time.sleep(SPIDER_INTERVAL)
                    continue
                
                # Get eggrecords to spider
                eggrecords = self._get_eggrecords()
                
                if not eggrecords:
                    logger.debug("No eggrecords to spider, waiting...")
                    time.sleep(SPIDER_INTERVAL)
                    continue
                
                logger.info(f"📋 Found {len(eggrecords)} eggrecords to spider")
                
                # Spider each eggrecord
                spidered = 0
                for eggrecord in eggrecords:
                    if not self.running or self.paused:
                        break
                    
                    try:
                        eggrecord_id = str(eggrecord['id'])
                        target = eggrecord.get('subDomain') or eggrecord.get('domainname', 'unknown')
                        target_url = f"http://{target}" if not target.startswith('http') else target
                        
                        # Mark current task
                        self._current_task = eggrecord_id
                        
                        logger.info(f"🕷️  Spidering {target_url} ({eggrecord_id})")
                        
                        # Perform spidering (pass eggrecord data to avoid Django model lookup)
                        result = self.spider.spider_egg_record(eggrecord_id, eggrecord_data=eggrecord)
                        
                        if result.get('success'):
                            # Submit result to API
                            self._submit_spider_result(
                                eggrecord_id,
                                target_url,
                                result
                            )
                            spidered += 1
                        else:
                            logger.warning(f"❌ Spider failed for {target_url}: {result.get('error', 'Unknown error')}")
                        
                        # Clear current task
                        self._current_task = None
                        
                        time.sleep(0.1)  # Small delay between spiders
                        
                    except Exception as e:
                        self._current_task = None
                        logger.error(f"❌ Error spidering eggrecord: {e}", exc_info=True)
                        continue
                
                if spidered > 0:
                    logger.info(f"✅ Completed {spidered} spiders this cycle")
                
                # Wait before next cycle
                time.sleep(SPIDER_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("⚠️  Spider loop interrupted")
                self.running = False
                break
            except Exception as e:
                logger.error(f"❌ Fatal error in spider loop: {e}", exc_info=True)
                time.sleep(10)  # Wait before retrying
        
        logger.info("🛑 Kumo daemon spider loop ended")
    
    def start(self):
        """Start the daemon"""
        if self.running:
            logger.warning("Daemon already running")
            return False
        
        # Write PID file
        try:
            PID_FILE.write_text(str(self.pid))
            logger.info(f"📝 PID file written: {PID_FILE} (PID: {self.pid})")
        except Exception as e:
            logger.warning(f"Could not write PID file: {e}")
        
        # Set process name
        try:
            import setproctitle
            setproctitle.setproctitle(f"kumo-recon-daemon [PID:{self.pid}]")
        except ImportError:
            pass
        
        self.running = True
        logger.info(f"🚀 Kumo daemon started (PID: {self.pid})")
        self._spider_loop()
        return True
    
    def stop(self):
        """Stop the daemon"""
        logger.info("🛑 Stopping Kumo daemon...")
        self.running = False
        
        # Remove PID file
        try:
            if PID_FILE.exists():
                PID_FILE.unlink()
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
    if PID_FILE.exists():
        try:
            old_pid = int(PID_FILE.read_text().strip())
            # Check if process is actually running
            try:
                os.kill(old_pid, 0)  # Signal 0 just checks if process exists
                logger.error(f"❌ Daemon already running (PID: {old_pid})")
                sys.exit(1)
            except ProcessLookupError:
                # Process doesn't exist, remove stale PID file
                PID_FILE.unlink()
                logger.info("Removed stale PID file")
        except Exception as e:
            logger.warning(f"Error checking PID file: {e}")
    
    # Create and start daemon
    daemon = KumoDaemon()
    try:
        daemon.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        daemon.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        daemon.stop()
        sys.exit(1)

