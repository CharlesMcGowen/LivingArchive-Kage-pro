#!/usr/bin/env python3
"""
Ryu Daemon - Standalone Threat Assessment Service
================================================
Runs as an independent process, communicates with Django via API.
Performs both Nmap scanning and threat assessments.
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
    format='%(asctime)s [RYU] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Load agent configuration
from daemons.config_loader import AgentConfig
config = AgentConfig('ryu')

# Configuration from config file or environment variables
DJANGO_API_BASE = config.get_server_url()
PID_FILE = config.get_pid_file()
SCAN_INTERVAL = config.get_scan_interval(30)
ASSESSMENT_INTERVAL = config.get_assessment_interval(60)
MAX_SCANS_PER_CYCLE = config.get_max_scans_per_cycle(5)
MAX_ASSESSMENTS_PER_CYCLE = config.get_max_assessments_per_cycle(2)


class RyuDaemon:
    """Standalone Ryu daemon process"""
    
    def __init__(self):
        self.running = False
        self.paused = False  # Pause state
        self.pid = os.getpid()
        self.scanner = None
        self.llm_enhancer = None
        self.config = config  # Store config reference
        self._current_task = None  # Track current work for graceful pause
        self._retry_count = 0  # Retry counter for exponential backoff
        self._init_scanner()
        self._init_llm()
        
    def _init_scanner(self):
        """Initialize Nmap scanner"""
        try:
            from kage.nmap_scanner import get_kage_scanner
            self.scanner = get_kage_scanner(parallel_enabled=True)
            logger.info("✅ Ryu Nmap scanner initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize scanner: {e}")
            self.scanner = None
    
    def _init_llm(self):
        """Initialize LLM enhancer"""
        try:
            from llm_enhancer import get_llm_enhancer
            self.llm_enhancer = get_llm_enhancer(enabled=True)
            if self.llm_enhancer and self.llm_enhancer.is_available():
                logger.info("🧠 LLM enhancer enabled for Ryu")
            else:
                logger.debug("LLM enhancer not available")
        except Exception as e:
            logger.debug(f"LLM enhancer not available: {e}")
            self.llm_enhancer = None
    
    def _get_eggrecords_to_scan(self):
        """Get eggrecords to scan from Django API with exponential backoff retry"""
        retry_config = self.config.get_retry_config()
        timeout_config = self.config.get_timeout_config()
        max_retries = retry_config['max_retries']
        base_wait = retry_config['base_wait']
        max_wait = retry_config['max_wait']
        
        for attempt in range(max_retries):
            try:
                url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/ryu/eggrecords/"
                params = {'limit': self.config.get_max_scans_per_cycle(5), 'scan_type': 'ryu_port_scan'}
                response = requests.get(url, params=params, timeout=timeout_config['api_timeout'])
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        self._retry_count = 0
                        return data.get('eggrecords', [])
            except requests.exceptions.RequestException as e:
                self._retry_count = attempt + 1
                if attempt < max_retries - 1:
                    wait_time = min(base_wait ** (attempt + 1), max_wait)
                    logger.warning(f"API error (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Max retries reached, API unavailable: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                break
        return []
    
    def _get_eggrecords_to_assess(self):
        """Get eggrecords to assess from Django API with exponential backoff retry"""
        retry_config = self.config.get_retry_config()
        timeout_config = self.config.get_timeout_config()
        max_retries = retry_config['max_retries']
        base_wait = retry_config['base_wait']
        max_wait = retry_config['max_wait']
        
        for attempt in range(max_retries):
            try:
                url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/ryu/eggrecords/"
                params = {'limit': self.config.get_max_assessments_per_cycle(2)}
                response = requests.get(url, params=params, timeout=timeout_config['api_timeout'])
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        self._retry_count = 0
                        return data.get('eggrecords', [])
            except requests.exceptions.RequestException as e:
                self._retry_count = attempt + 1
                if attempt < max_retries - 1:
                    wait_time = min(base_wait ** (attempt + 1), max_wait)
                    logger.warning(f"API error (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Max retries reached, API unavailable: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                break
        return []
    
    def _submit_scan_result(self, eggrecord_id, target, result):
        """Submit scan result to Django API"""
        try:
            timeout_config = self.config.get_timeout_config()
            url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/ryu/scan/"
            data = {
                'eggrecord_id': eggrecord_id,
                'target': target,
                'scan_type': 'ryu_port_scan',
                'result': result
            }
            response = requests.post(url, json=data, timeout=timeout_config['submit_timeout'])
            
            if response.status_code == 200:
                result_data = response.json()
                if result_data.get('success'):
                    logger.info(f"✅ Scan result submitted for {target}")
                    return True
        except Exception as e:
            logger.error(f"Error submitting scan result: {e}")
        return False
    
    def _submit_assessment(self, eggrecord_id, assessment_data):
        """Submit threat assessment to Django API"""
        try:
            timeout_config = self.config.get_timeout_config()
            url = f"{self.config.get_server_url()}/reconnaissance/api/daemon/assessment/"
            data = {
                'eggrecord_id': eggrecord_id,
                **assessment_data
            }
            response = requests.post(url, json=data, timeout=timeout_config['submit_timeout'])
            
            if response.status_code == 200:
                result_data = response.json()
                if result_data.get('success'):
                    logger.info(f"✅ Assessment submitted for {eggrecord_id}")
                    return True
        except Exception as e:
            logger.error(f"Error submitting assessment: {e}")
        return False
    
    def _perform_assessment(self, eggrecord_id, target):
        """Perform threat assessment (simplified version)"""
        try:
            # Get scan and spider data from API
            # For now, create a basic assessment
            # In full implementation, this would fetch data and use LLM
            
            assessment = {
                'risk_level': 'medium',  # Would be calculated
                'threat_summary': f'Threat assessment for {target}',
                'vulnerabilities': {},
                'attack_vectors': {},
                'remediation_priorities': {},
                'narrative': f'Assessment performed for {target}'
            }
            
            # Use LLM if available
            if self.llm_enhancer and self.llm_enhancer.is_available():
                try:
                    # Enhanced assessment with LLM
                    enhanced = self.llm_enhancer.analyze_threat_assessment({
                        'target': target,
                        'eggrecord_id': eggrecord_id
                    })
                    if enhanced:
                        assessment.update(enhanced)
                except Exception as e:
                    logger.debug(f"LLM enhancement failed: {e}")
            
            return assessment
        except Exception as e:
            logger.error(f"Error performing assessment: {e}", exc_info=True)
            return None
    
    def pause(self):
        """Pause processing (finish current task first)"""
        logger.info("⏸️  Pausing Ryu daemon...")
        self.paused = True
        timeout = 60
        start_time = time.time()
        while self._current_task is not None and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        if self._current_task is not None:
            logger.warning("⚠️  Current task did not finish before pause timeout")
        logger.info("✅ Ryu daemon paused")
    
    def resume(self):
        """Resume processing"""
        logger.info("▶️  Resuming Ryu daemon...")
        self.paused = False
        logger.info("✅ Ryu daemon resumed")
    
    def graceful_shutdown(self):
        """Graceful shutdown - finish current work then stop"""
        logger.info("🛑 Initiating graceful shutdown...")
        self.running = False
        timeout = 30
        start_time = time.time()
        while self._current_task is not None and (time.time() - start_time) < timeout:
            time.sleep(0.5)
        logger.info("✅ Graceful shutdown complete")
    
    def _coordination_loop(self):
        """Main coordination loop (scanning + assessments)"""
        logger.info(f"🔄 Ryu daemon coordination loop started (PID: {self.pid})")
        cycle_count = 0
        last_scan_time = 0
        last_assessment_time = 0
        
        while self.running:
            try:
                # Check pause state
                while self.paused and self.running:
                    time.sleep(1)
                
                if not self.running:
                    break
                
                cycle_count += 1
                current_time = time.time()
                
                # Perform Nmap scans
                scan_interval = self.config.get_scan_interval(30)
                if current_time - last_scan_time >= scan_interval and self.scanner:
                    logger.info(f"🔄 Ryu scan cycle #{cycle_count}")
                    eggrecords = self._get_eggrecords_to_scan()
                    
                    if eggrecords:
                        logger.info(f"📋 Found {len(eggrecords)} eggrecords to scan")
                        scanned = 0
                        max_scans = self.config.get_max_scans_per_cycle(5)
                        for eggrecord in eggrecords[:max_scans]:
                            if not self.running or self.paused:
                                break
                            
                            try:
                                eggrecord_id = str(eggrecord['id'])
                                target = eggrecord.get('subDomain') or eggrecord.get('domainname', 'unknown')
                                
                                # Mark current task
                                self._current_task = f"scan:{eggrecord_id}"
                                
                                logger.info(f"🔍 Scanning {target} ({eggrecord_id})")
                                # Set write_to_db=False so we submit via API for consistent timestamping
                                result = self.scanner.scan_egg_record(eggrecord_id, scan_type='ryu_port_scan', write_to_db=False)
                                
                                if result.get('success'):
                                    self._submit_scan_result(eggrecord_id, target, result)
                                    scanned += 1
                                
                                # Clear current task
                                self._current_task = None
                                
                                time.sleep(0.1)
                            except Exception as e:
                                self._current_task = None
                                logger.error(f"Error scanning: {e}")
                                continue
                        
                        if scanned > 0:
                            logger.info(f"✅ Completed {scanned} scans")
                    
                    last_scan_time = current_time
                
                # Perform threat assessments
                assessment_interval = self.config.get_assessment_interval(60)
                if current_time - last_assessment_time >= assessment_interval:
                    logger.info(f"🔄 Ryu assessment cycle #{cycle_count}")
                    eggrecords = self._get_eggrecords_to_assess()
                    
                    if eggrecords:
                        logger.info(f"📋 Found {len(eggrecords)} eggrecords to assess")
                        assessed = 0
                        max_assessments = self.config.get_max_assessments_per_cycle(2)
                        for eggrecord in eggrecords[:max_assessments]:
                            if not self.running or self.paused:
                                break
                            
                            try:
                                eggrecord_id = str(eggrecord['id'])
                                target = eggrecord.get('subDomain') or eggrecord.get('domainname', 'unknown')
                                
                                # Mark current task
                                self._current_task = f"assess:{eggrecord_id}"
                                
                                logger.info(f"🛡️  Assessing {target} ({eggrecord_id})")
                                assessment = self._perform_assessment(eggrecord_id, target)
                                
                                if assessment:
                                    self._submit_assessment(eggrecord_id, assessment)
                                    assessed += 1
                                
                                # Clear current task
                                self._current_task = None
                                
                                time.sleep(0.5)
                            except Exception as e:
                                self._current_task = None
                                logger.error(f"Error assessing: {e}")
                                continue
                        
                        if assessed > 0:
                            logger.info(f"✅ Completed {assessed} assessments")
                    
                    last_assessment_time = current_time
                
                # Sleep if no work done
                scan_interval = self.config.get_scan_interval(30)
                assessment_interval = self.config.get_assessment_interval(60)
                if current_time - last_scan_time < scan_interval and current_time - last_assessment_time < assessment_interval:
                    time.sleep(5)  # Short sleep when waiting
                
            except KeyboardInterrupt:
                logger.info("⚠️  Coordination loop interrupted")
                self.running = False
                break
            except Exception as e:
                logger.error(f"❌ Fatal error in coordination loop: {e}", exc_info=True)
                time.sleep(10)
        
        logger.info("🛑 Ryu daemon coordination loop ended")
    
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
            setproctitle.setproctitle(f"ryu-recon-daemon [PID:{self.pid}]")
        except ImportError:
            pass
        
        self.running = True
        logger.info(f"🚀 Ryu daemon started (PID: {self.pid})")
        self._coordination_loop()
        return True
    
    def stop(self):
        """Stop the daemon"""
        logger.info("🛑 Stopping Ryu daemon...")
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
            try:
                os.kill(old_pid, 0)
                logger.error(f"❌ Daemon already running (PID: {old_pid})")
                sys.exit(1)
            except ProcessLookupError:
                pid_file.unlink()
                logger.info("Removed stale PID file")
        except Exception as e:
            logger.warning(f"Error checking PID file: {e}")
    
    # Create and start daemon
    daemon = RyuDaemon()
    try:
        daemon.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        daemon.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        daemon.stop()
        sys.exit(1)

