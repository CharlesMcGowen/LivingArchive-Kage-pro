#!/usr/bin/env python3
"""
Oak Autonomous Curation Service
=================================

Self-starting curation worker that runs when Oak is idle.
Detects idle state and automatically processes uncured EggRecords.

Author: EGO Revolution Team
Version: 1.0.0
Migrated to Kage-pro: 2024
"""

import logging
import threading
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.cache import cache

logger = logging.getLogger(__name__)

# Try to import psutil, but make it optional
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available - system resource monitoring will be disabled for Oak autonomous curation")

# Note: BaseBugsyService is still in main codebase (Bugsy services not migrated)
try:
    from artificial_intelligence.personalities.security.bugsy.base_services import BaseBugsyService
except ImportError:
    # Fallback if BaseBugsyService is not available
    logger.warning("BaseBugsyService not available - using minimal implementation")
    class BaseBugsyService:
        def __init__(self, name, version):
            self.name = name
            self.version = version
            self.is_running = False
            self.start_time = None
            self.end_time = None
            self.logger = logging.getLogger(__name__)
        
        def log_service_event(self, event_type, data):
            self.logger.info(f"Service event: {event_type} - {data}")
        
        def get_service_status(self):
            return {
                'name': self.name,
                'version': self.version,
                'is_running': self.is_running,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None
            }


class OakAutonomousCurationService(BaseBugsyService):
    """
    Autonomous curation service that self-starts when Oak is idle.
    
    Monitors:
    - Oak workload (validation requests, signals)
    - System resources (CPU, memory)
    - Time since last curation
    
    When idle, automatically curates uncured EggRecords.
    """
    
    def __init__(self):
        super().__init__("OakAutonomousCuration", "1.0.0")
        
        # Monitoring configuration
        self.monitor_interval = 300  # 5 minutes
        self.idle_threshold = 600  # 10 minutes of inactivity
        self.batch_size = 10  # Reduced from 50 to prevent connection exhaustion
        
        # State tracking
        self.last_activity_time = None
        self.curation_thread = None
        self.is_curating = False
        # Thread-safety for curation batches
        # Initialize a real lock up-front so we never end up with a None
        # being used as a context manager.
        self._curation_lock = threading.Lock()
        
        # Connection exhaustion tracking
        self.connection_errors = 0
        self.last_connection_error_time = None
        self.backoff_multiplier = 1  # Multiplier for monitor_interval when connections fail
        
        # Statistics
        self.stats = {
            'cycles_completed': 0,
            'idle_detections': 0,
            'curation_batches': 0,
            'targets_processed': 0,
            'errors': 0,
            'connection_errors': 0
        }
        
        self.logger.info("🌳 Oak Autonomous Curation Service initialized")
    
    def start_service(self):
        """Start the autonomous monitoring loop."""
        if self.is_running:
            self.logger.warning("Service already running")
            return False
        
        try:
            self.is_running = True
            # Use datetime.now() instead of timezone.now() during initialization to avoid database access
            from datetime import datetime
            self.start_time = datetime.now()
            # Initialize to allow immediate idle detection
            self.last_activity_time = datetime.now() - timedelta(seconds=self.idle_threshold + 1)
            
            # Start monitoring thread
            self.curation_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True,
                name="OakAutonomousCuration"
            )
            self.curation_thread.start()
            
            self.logger.info("🌳 Autonomous curation service started")
            self.log_service_event("service_started", self.stats)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting service: {e}")
            self.is_running = False
            return False
    
    def stop_service(self):
        """Stop the autonomous monitoring loop."""
        try:
            self.is_running = False
            self.end_time = timezone.now()
            
            # Wait for thread to finish
            if self.curation_thread and self.curation_thread.is_alive():
                self.curation_thread.join(timeout=5)
            
            self.logger.info("🌳 Autonomous curation service stopped")
            self.log_service_event("service_stopped", self.stats)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping service: {e}")
            return False
    
    def _monitoring_loop(self):
        """Main monitoring loop - runs in background thread."""
        try:
            while self.is_running:
                # Use datetime to avoid database access during monitoring loop
                from datetime import datetime
                try:
                    cycle_start = timezone.now()
                except Exception:
                    cycle_start = datetime.now()
                
                # Check if Oak is idle
                if self._is_idle():
                    self.stats['idle_detections'] += 1
                    self.logger.info("🌳 Oak is idle - starting curation batch")
                    
                    # Process one batch
                    if not self.is_curating:
                        self._process_idle_curation_batch()
                # Don't update activity time here - only when actual Bugsy activity occurs
                
                # Update statistics
                self.stats['cycles_completed'] += 1
                try:
                    cycle_end = timezone.now()
                except Exception:
                    cycle_end = datetime.now()
                cycle_duration = (cycle_end - cycle_start).total_seconds()
                
                # Adjust wait time based on connection errors (exponential backoff)
                wait_time = self.monitor_interval * self.backoff_multiplier
                
                # Reset backoff if no recent connection errors (after 30 minutes)
                if self.last_connection_error_time:
                    time_since_error = time.time() - self.last_connection_error_time
                    if time_since_error > 1800:  # 30 minutes
                        self.connection_errors = 0
                        self.backoff_multiplier = 1
                        self.last_connection_error_time = None
                    elif self.connection_errors > 5:
                        # Increase backoff if still having issues
                        self.backoff_multiplier = min(self.backoff_multiplier * 1.5, 4)  # Max 4x delay
                
                # Wait for next cycle
                time.sleep(wait_time)
                
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}")
            self.is_running = False
    
    def _is_idle(self) -> bool:
        """
        Determine if Oak is idle.
        
        Conditions:
        - No validation requests in last 10 minutes
        - System resources available (CPU < 50%, memory < 70%)
        - Not currently processing curation
        """
        try:
            # Check time since last activity
            if self.last_activity_time is None:
                # First run, not idle yet
                return False
            
            # Handle both datetime and timezone-aware datetime
            from datetime import datetime
            try:
                now = timezone.now()
            except Exception:
                now = datetime.now()
            
            # Ensure both are timezone-aware or both are naive
            last_activity = self.last_activity_time
            if isinstance(now, datetime) and isinstance(last_activity, datetime):
                if now.tzinfo is None and last_activity.tzinfo is not None:
                    # Make now timezone-aware
                    try:
                        from django.utils import timezone as tz
                        now = tz.now()
                    except Exception:
                        # If timezone not ready, convert last_activity to naive
                        last_activity = last_activity.replace(tzinfo=None)
                elif now.tzinfo is not None and last_activity.tzinfo is None:
                    # Make last_activity timezone-aware
                    try:
                        from django.utils import timezone as tz
                        last_activity = tz.now() - timedelta(seconds=self.idle_threshold + 1)
                    except Exception:
                        # If timezone not ready, convert now to naive
                        now = now.replace(tzinfo=None)
            
            time_since_activity = (now - last_activity).total_seconds()
            if time_since_activity < self.idle_threshold:
                return False
            
            # Check if currently curating
            if self.is_curating:
                return False
            
            # Check system resources (if psutil is available)
            if PSUTIL_AVAILABLE:
                try:
                    cpu_percent = psutil.cpu_percent(interval=None)
                    memory_percent = psutil.virtual_memory().percent
                    
                    if cpu_percent > 50 or memory_percent > 70:
                        self.logger.debug(f"System resources busy: CPU {cpu_percent:.1f}%, Memory {memory_percent:.1f}%")
                        return False
                except Exception as e:
                    self.logger.debug(f"Error checking system resources: {e}")
                    # Continue without resource check if psutil fails
            
            # Check cache for recent activity (wrap in try/except to avoid database access during init)
            try:
                recent_activity = cache.get('oak_recent_activity', False)
                if recent_activity:
                    return False
            except Exception:
                # Cache may not be available during initialization
                pass
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking idle state: {e}")
            return False
    
    def _process_idle_curation_batch(self):
        """Legacy method - redirects to new _process_curation_batch"""
        return self._process_curation_batch(batch_size=self.batch_size, egg_id=None)
    
    def _process_curation_batch(self, batch_size: int = None, egg_id: Optional[str] = None):
        """
        Process one batch of uncured targets.
        Runs in background without blocking.
        
        Args:
            batch_size: Number of records to process (defaults to self.batch_size)
            egg_id: Optional egg_id to filter records by (for grouping)
        """
        # Use thread-safe check to prevent duplicate processing
        # Lock is created in __init__, but keep a defensive fallback.
        if self._curation_lock is None:
            self._curation_lock = threading.Lock()
        with self._curation_lock:
            if self.is_curating:
                self.logger.warning("Curation already in progress, skipping batch")
                return
        
        try:
            with self._curation_lock:
                self.is_curating = True
            
            self.stats['curation_batches'] += 1
            effective_batch_size = batch_size or self.batch_size
            
            self.logger.info(f"🌳 Processing curation batch (size={effective_batch_size}" + (f", egg_id={egg_id}" if egg_id else "") + ")")
            
            # Get uncured target IDs (using Django connection)
            target_ids = self._get_uncured_targets(batch_size=effective_batch_size, egg_id=egg_id)
            
            if not target_ids:
                self.logger.info("No uncured targets found")
                return
            
            self.logger.info(f"Found {len(target_ids)} uncured target IDs")
            
            # Import curation service (relative import - same directory)
            try:
                from .target_curation_service import OakTargetCurationService
                curation_service = OakTargetCurationService()
            except Exception as e:
                self.logger.error(f"Failed to import curation service: {e}")
                raise
            
            # Batch fetch all EggRecords in a single query
            targets = self._batch_fetch_egg_records(target_ids)
            
            if not targets:
                self.logger.warning("No valid targets found after batch fetch")
                return
            
            self.logger.info(f"Fetched {len(targets)} EggRecords in batch")
            
            # Use batch queue method to reduce connection overhead
            try:
                batch_result = curation_service.queue_subdomains_batch(
                    egg_records=targets,
                    discovery_source='autonomous_curation',
                    priority='normal'
                )
                
                processed = batch_result.get('queued', 0)
                failed = batch_result.get('failed', 0)
                
                if batch_result.get('success'):
                    self.stats['targets_processed'] += processed
                    self.logger.info(f"✅ Batch queued {processed}/{len(targets)} targets successfully")
                    
                    if failed > 0:
                        self.stats['errors'] += failed
                        self.logger.warning(f"Failed to queue {failed} targets in batch")
                        if batch_result.get('errors'):
                            for error in batch_result['errors'][:5]:  # Log first 5 errors
                                self.logger.debug(f"Batch queue error: {error}")
                else:
                    self.stats['errors'] += failed
                    self.logger.error(f"Batch queue failed: {batch_result.get('errors', [])[:3]}")
                    
            except Exception as batch_error:
                error_str = str(batch_error)
                # Check for connection-related errors
                if 'too many clients' in error_str.lower() or 'connection' in error_str.lower():
                    self.connection_errors += 1
                    self.stats['connection_errors'] += 1
                    self.last_connection_error_time = time.time()
                    self.logger.warning(f"Connection error during batch queue, stopping batch early")
                    return
                
                # Fallback to individual processing if batch fails
                self.logger.warning(f"Batch queue failed ({error_str[:100]}), falling back to individual processing")
                processed = self._process_targets_individually(targets, curation_service)
            
            self.logger.info(f"✅ Batch complete: {processed}/{len(targets)} targets processed")
            
            # Also curate nmap scans from Kaze, Kage, and Ryu (if enabled)
            try:
                nmap_result = curation_service.curate_nmap_scans_for_reconnaissance(
                    scan_types=['kaze_port_scan', 'kage_port_scan', 'ryu_port_scan']
                )
                if nmap_result.get('success'):
                    self.logger.info(f"🌳 Curated {nmap_result.get('scans_curated', 0)} nmap scans from Kaze/Kage/Ryu "
                                   f"({nmap_result.get('scans_enriched', 0)} enriched with fingerprints)")
            except Exception as e:
                self.logger.debug(f"Nmap scan curation not available: {e}")
            
            # Mark last curation time
            from datetime import datetime
            try:
                self.last_activity_time = timezone.now()
                cache_time = timezone.now()
            except Exception:
                self.last_activity_time = datetime.now()
                cache_time = datetime.now()
            try:
                cache.set('oak_last_autonomous_curation', cache_time, timeout=86400)
            except Exception:
                pass
            
        except Exception as e:
            self.logger.error(f"Error in curation batch: {e}", exc_info=True)
            self.stats['errors'] += 1
        
        finally:
            with self._curation_lock:
                self.is_curating = False
    
    def _batch_fetch_egg_records(self, target_ids: List[str]) -> List:
        """
        Batch fetch EggRecords in a single database query.
        
        Args:
            target_ids: List of UUID strings for EggRecords
            
        Returns:
            List of SimpleEggRecord objects
        """
        if not target_ids:
            return []
        
        targets = []
        try:
            from django.db import connections
            
            try:
                db = connections['eggrecords']
            except KeyError:
                db = connections['default']
            
            with db.cursor() as cursor:
                # Build batch query
                placeholders = ','.join(['%s'] * len(target_ids))
                cursor.execute(f"""
                    SELECT id, "subDomain", domainname, alive, "skipScan"
                    FROM customer_eggs_eggrecords_general_models_eggrecord
                    WHERE id IN ({placeholders})
                """, target_ids)
                
                # Create SimpleEggRecord objects
                class SimpleEggRecord:
                    def __init__(self, id, subDomain, domainname, alive, skipScan):
                        self.id = id
                        self.subDomain = subDomain
                        self.domainname = domainname
                        self.alive = alive
                        self.skipScan = skipScan
                        self.discovery_metadata = {}
                
                for row in cursor.fetchall():
                    targets.append(SimpleEggRecord(row[0], row[1], row[2], row[3], row[4]))
                
        except Exception as e:
            self.logger.error(f"Error in batch fetch: {e}", exc_info=True)
        
        return targets
    
    def _process_targets_individually(self, targets: List, curation_service) -> int:
        """
        Fallback method to process targets individually if batch processing fails.
        
        Args:
            targets: List of EggRecord objects
            curation_service: OakTargetCurationService instance
            
        Returns:
            Number of successfully processed targets
        """
        processed = 0
        max_consecutive_errors = 3
        consecutive_errors = 0
        
        for target in targets:
            try:
                result = curation_service.queue_subdomain_for_curation(
                    egg_record=target,
                    discovery_source='autonomous_curation',
                    priority='normal'
                )
                
                if result['success']:
                    processed += 1
                    consecutive_errors = 0  # Reset on success
                else:
                    error_msg = result.get('error', 'Unknown error')
                    if 'too many clients' in str(error_msg).lower() or 'connection' in str(error_msg).lower():
                        self.connection_errors += 1
                        self.stats['connection_errors'] += 1
                        self.last_connection_error_time = time.time()
                        consecutive_errors += 1
                        if consecutive_errors >= max_consecutive_errors:
                            self.logger.warning(f"Too many consecutive connection errors, stopping early")
                            break
                    self.stats['errors'] += 1
                    
            except Exception as e:
                error_str = str(e)
                if 'too many clients' in error_str.lower() or 'connection' in error_str.lower():
                    self.connection_errors += 1
                    self.stats['connection_errors'] += 1
                    self.last_connection_error_time = time.time()
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        self.logger.warning(f"Too many consecutive connection errors, stopping early")
                        break
                self.stats['errors'] += 1
        
        return processed
    
    def _get_uncured_targets(self, batch_size: int = 50, egg_id: Optional[str] = None):
        """
        Get EggRecords that need curation using Django database connection.
        
        Args:
            batch_size: Number of records to fetch
            egg_id: Optional egg_id to filter by (for grouping by egg)
        
        Returns list of EggRecord IDs (UUIDs as strings).
        """
        try:
            # Use Django database connection (same as views.py)
            from django.db import connections
            
            try:
                db_connection = connections['eggrecords']
            except KeyError:
                db_connection = connections['default']
            
            # Use datetime to avoid database access during initialization
            from datetime import datetime
            try:
                stale_date = timezone.now() - timedelta(days=30)
            except Exception:
                stale_date = datetime.now() - timedelta(days=30)
            
            with db_connection.cursor() as cursor:
                # Build WHERE conditions
                where_parts = [
                    '"subDomain" IS NOT NULL',
                    'alive = true',
                    '"skipScan" = false',
                    '(bugsy_last_curated_at IS NULL OR bugsy_last_curated_at < %s)'
                ]
                
                params = [stale_date]
                
                # Add egg_id filter if provided
                if egg_id:
                    where_parts.append('egg_id_id = %s')
                    params.append(egg_id)
                    
                # Build SQL query
                sql = f"""
                    SELECT id FROM customer_eggs_eggrecords_general_models_eggrecord
                    WHERE {' AND '.join(where_parts)}
                    LIMIT %s
                """
                params.append(batch_size)
                
                # Execute query
                cursor.execute(sql, params)
                target_ids = [str(row[0]) for row in cursor.fetchall()]
                
                self.logger.info(f"Found {len(target_ids)} uncured target IDs via Django query")
                return target_ids
                    
        except Exception as e:
            self.logger.error(f"Error getting uncured targets: {e}", exc_info=True)
            # Fallback: Simple query without curation date check
            try:
                from django.db import connections
                try:
                    db_connection = connections['eggrecords']
                except KeyError:
                    db_connection = connections['default']
                
                with db_connection.cursor() as cursor:
                    where_parts = [
                        '"subDomain" IS NOT NULL',
                        'alive = true',
                        '"skipScan" = false'
                    ]
                    
                    params = []
                    if egg_id:
                        where_parts.append('egg_id_id = %s')
                        params.append(egg_id)
                    
                    sql = f"""
                        SELECT id FROM customer_eggs_eggrecords_general_models_eggrecord
                        WHERE {' AND '.join(where_parts)}
                        LIMIT %s
                    """
                    params.append(batch_size)
                    
                    cursor.execute(sql, params)
                    target_ids = [str(row[0]) for row in cursor.fetchall()]
                    
                    self.logger.info(f"Found {len(target_ids)} uncured target IDs via fallback query")
                    return target_ids
            except Exception as e2:
                self.logger.error(f"Fallback query also failed: {e2}", exc_info=True)
            return []
    
    def mark_activity(self):
        """Mark that Oak had activity (for idle detection)."""
        # Use datetime to avoid database access during initialization
        from datetime import datetime
        try:
            self.last_activity_time = timezone.now()
        except Exception:
            self.last_activity_time = datetime.now()
        try:
            cache.set('oak_recent_activity', True, timeout=600)
        except Exception:
            # Cache may not be available during initialization
            pass
    
    def _get_time_since_activity_seconds(self) -> Optional[float]:
        """Get time since last activity in seconds, handling timezone-aware/naive datetime."""
        if not self.last_activity_time:
            return None
        try:
            now = timezone.now()
            last = self.last_activity_time
            # Handle timezone mismatch
            if now.tzinfo and not last.tzinfo:
                from datetime import datetime
                last = datetime.now() - timedelta(seconds=self.idle_threshold + 1)
            elif not now.tzinfo and last.tzinfo:
                from datetime import datetime
                now = datetime.now()
            return (now - last).total_seconds()
        except Exception:
            return None
    
    def get_autonomous_stats(self) -> Dict[str, Any]:
        """Get autonomous curation statistics."""
        return {
            'service_status': self.get_service_status(),
            'monitoring': {
                'cycles_completed': self.stats['cycles_completed'],
                'idle_detections': self.stats['idle_detections'],
                'curation_batches': self.stats['curation_batches'],
                'targets_processed': self.stats['targets_processed'],
                'errors': self.stats['errors']
            },
            'current_state': {
                'is_idle': self._is_idle(),
                'is_curating': self.is_curating,
                'last_activity': self.last_activity_time.isoformat() if self.last_activity_time else None,
                'time_since_activity_seconds': self._get_time_since_activity_seconds()
            }
        }

# Singleton instance for easy access
_instance = None

def get_instance():
    """Get or create singleton instance."""
    global _instance
    if _instance is None:
        _instance = OakAutonomousCurationService()
    return _instance

