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
import psutil
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.cache import cache

# Note: BaseBugsyService is still in main codebase (Bugsy services not migrated)
from artificial_intelligence.personalities.security.bugsy.base_services import BaseBugsyService

logger = logging.getLogger(__name__)


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
        self.batch_size = 50
        
        # State tracking
        self.last_activity_time = None
        self.curation_thread = None
        self.is_curating = False
        # Thread-safety for curation batches
        # Initialize a real lock up-front so we never end up with a None
        # being used as a context manager.
        self._curation_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'cycles_completed': 0,
            'idle_detections': 0,
            'curation_batches': 0,
            'targets_processed': 0,
            'errors': 0
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
                
                # Wait for next cycle
                time.sleep(self.monitor_interval)
                
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
            
            # Check system resources
            cpu_percent = psutil.cpu_percent(interval=None)
            memory_percent = psutil.virtual_memory().percent
            
            if cpu_percent > 50 or memory_percent > 70:
                self.logger.debug(f"System resources busy: CPU {cpu_percent:.1f}%, Memory {memory_percent:.1f}%")
                return False
            
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
            
            # Import Django ORM models
            try:
                from artificial_intelligence.customer_eggs_eggrecords_general_models.models import EggRecord
                use_django_orm = True
            except ImportError:
                try:
                    from customer_eggs_eggrecords_general_models.models import EggRecord
                    use_django_orm = True
                except ImportError:
                    use_django_orm = False
                    self.logger.warning("Django ORM EggRecord not available, using raw SQL fallback")
            
            # Process targets
            processed = 0
            for target_id in target_ids:
                try:
                    # Check if we should stop
                    if not self.is_curating and not self.is_running:
                        self.logger.info("Curation stopped by user")
                        break
                    
                    # Get EggRecord object using Django ORM (wrap in thread to avoid async context issues)
                    target = None
                    if use_django_orm:
                        try:
                            # Use raw SQL to avoid Django ORM async context issues
                            from django.db import connections
                            db = connections['eggrecords']
                            with db.cursor() as cursor:
                                cursor.execute("""
                                    SELECT id, "subDomain", domainname, alive, "skipScan"
                                    FROM customer_eggs_eggrecords_general_models_eggrecord
                                    WHERE id = %s
                                """, [target_id])
                                row = cursor.fetchone()
                                if row:
                                    class SimpleEggRecord:
                                        def __init__(self, id, subDomain, domainname, alive, skipScan):
                                            self.id = id
                                            self.subDomain = subDomain
                                            self.domainname = domainname
                                            self.alive = alive
                                            self.skipScan = skipScan
                                            # discovery_metadata column doesn't exist, skip
                                            pass
                                    
                                    target = SimpleEggRecord(row[0], row[1], row[2], row[3], row[4])
                        except Exception as e:
                            self.logger.debug(f"Could not load EggRecord {target_id}: {e}")
                            self.logger.warning(f"EggRecord {target_id} not found in database")
                            continue
                        except Exception as e:
                            self.logger.warning(f"Django ORM query failed for {target_id}: {e}, trying raw SQL")
                            target = None
                    
                    # Fallback: Use raw SQL to get record data and create a minimal object
                    if target is None:
                        try:
                            from django.db import connections
                            db_connection = connections['eggrecords']
                            with db_connection.cursor() as cursor:
                                cursor.execute("""
                                    SELECT id, "subDomain", domainname, alive, "skipScan"
                                    FROM customer_eggs_eggrecords_general_models_eggrecord
                                    WHERE id = %s
                                """, [target_id])
                                row = cursor.fetchone()
                                if row:
                                    # Create a simple object with the needed attributes
                                    class SimpleEggRecord:
                                        def __init__(self, id, subDomain, domainname, alive, skipScan):
                                            self.id = id
                                            self.subDomain = subDomain
                                            self.domainname = domainname
                                            self.alive = alive
                                            self.skipScan = skipScan
                                            self.discovery_metadata = {}
                                    
                                    target = SimpleEggRecord(row[0], row[1], row[2], row[3], row[4])
                                else:
                                    self.logger.warning(f"EggRecord {target_id} not found in database")
                                    continue
                        except Exception as e:
                            self.logger.warning(f"Failed to load EggRecord {target_id}: {e}, skipping")
                            continue
                    
                    if target is None:
                        continue
                    
                    # Queue for curation
                    result = curation_service.queue_subdomain_for_curation(
                        egg_record=target,
                        discovery_source='manual_trigger',
                        priority='normal'
                    )
                    
                    if result['success']:
                        processed += 1
                        self.stats['targets_processed'] += 1
                        self.logger.debug(f"Queued {target.subDomain or target.domainname} for curation")
                    else:
                        self.stats['errors'] += 1
                        self.logger.warning(f"Failed to queue {target.subDomain or target.domainname}: {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    self.stats['errors'] += 1
                    self.logger.error(f"Error processing target {target_id}: {e}", exc_info=True)
            
            self.logger.info(f"✅ Batch complete: {processed}/{len(target_ids)} processed")
            
            # Also curate nmap scans from Kaze, Kage, and Ryu
            try:
                nmap_result = curation_service.curate_nmap_scans_for_reconnaissance(
                    scan_types=['kaze_port_scan', 'kage_port_scan', 'ryu_port_scan']
                )
                if nmap_result.get('success'):
                    self.logger.info(f"🌳 Curated {nmap_result.get('scans_curated', 0)} nmap scans from Kaze/Kage/Ryu "
                                   f"({nmap_result.get('scans_enriched', 0)} enriched with fingerprints)")
            except Exception as e:
                self.logger.debug(f"Nmap scan curation not available: {e}")
            
            # Mark last curation time (use datetime to avoid database access)
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
                # Cache may not be available during initialization
                pass
            
        except Exception as e:
            self.logger.error(f"Error in curation batch: {e}", exc_info=True)
            self.stats['errors'] += 1
            
        finally:
            with self._curation_lock:
                self.is_curating = False
    
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
                'time_since_activity_seconds': (timezone.now() - self.last_activity_time).total_seconds() if self.last_activity_time else None
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

