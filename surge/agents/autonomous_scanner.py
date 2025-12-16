#!/usr/bin/env python3
"""
Surge Autonomous Scanner
========================

Autonomous vulnerability scanning service for Kontrol AI eggs.
Runs continuously in Docker, fetching eggs and scanning them.

Author: EGO Revolution Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import os
import sys
import signal
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# Add project root to path for imports
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Try to add EgoLlama to path (optional dependency)
egollama_root = Path('/mnt/webapps-nvme/EgoLlama')
if egollama_root.exists():
    sys.path.insert(0, str(egollama_root))
else:
    # Try Docker path
    egollama_docker = Path('/app/egollama')
    if egollama_docker.exists():
        sys.path.insert(0, str(egollama_docker))

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
# Use project logs directory
log_file = os.environ.get('LOG_FILE', str(BASE_DIR / 'logs' / 'surge_autonomous.log'))

# Create logs directory if it doesn't exist
try:
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
except PermissionError:
    # Fallback to user's home directory if we can't write to surge directory
    log_file = os.path.expanduser('~/surge_logs/surge_autonomous.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

logging.basicConfig(
    level=getattr(logging, log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Import Surge Django ORM integration
try:
    from ..database.django_integration import surge_db
    _database_available = True
except ImportError as e:
    logger.warning(f"Surge database integration not available (this is OK for standalone mode): {e}")
    _database_available = False
    surge_db = None


class SurgeAutonomousScanner:
    """
    Autonomous scanning service for Surge.
    
    Continuously fetches eggs from Kontrol AI database and scans them.
    """
    
    def __init__(self):
        """Initialize autonomous scanner."""
        self.running = False
        self.scan_interval = int(os.environ.get('SURGE_SCAN_INTERVAL', '300'))
        self.batch_size = int(os.environ.get('SURGE_BATCH_SIZE', '5'))
        self.scan_type = os.environ.get('SURGE_SCAN_TYPE', 'quick')
        self.continuous = os.environ.get('SURGE_CONTINUOUS', 'true').lower() == 'true'
        # No cooldown - scan everything that's alive
        self.min_scan_age = int(os.environ.get('SURGE_MIN_SCAN_AGE', '0'))
        
        # Statistics
        self.stats = {
            'total_scans': 0,
            'successful_scans': 0,
            'failed_scans': 0,
            'total_vulnerabilities': 0,
            'uptime_start': datetime.now()
        }
        self._global_template_cache: List[str] = []
        self._global_template_cache_refreshed: datetime = datetime.min
        
        logger.info("⚡ Surge Autonomous Scanner initialized")
        logger.info(f"   Scan interval: {self.scan_interval}s")
        logger.info(f"   Batch size: {self.batch_size}")
        logger.info(f"   Scan type: {self.scan_type}")
        logger.info(f"   Continuous mode: {self.continuous}")
    
    def _fetch_global_template_pool(self, limit: int = 50) -> List[str]:
        """
        Fetch a global pool of high-performing templates to use as a fallback when Bugsy
        has no per-target recommendations ready yet.
        Uses Django ORM with raw SQL for custom queries.
        """
        limit = max(limit, 1)
        templates: List[str] = []
        try:
            from django.db import connections
            connection = connections['eggrecords']
            with connection.cursor() as cursor:
                # Try template effectiveness table first
                cursor.execute("""
                    SELECT template_id
                    FROM enrichment_system_templateeffectiveness
                    WHERE template_id IS NOT NULL
                    ORDER BY success_rate DESC NULLS LAST,
                             total_scans DESC NULLS LAST,
                             last_used DESC NULLS LAST
                    LIMIT %s
                """, [limit])
                templates = [row[0] for row in cursor.fetchall() if row and row[0]]
        except Exception as exc:
            logger.debug(f"Template effectiveness fallback query failed: {exc}")
            templates = []
        
        if not templates:
            try:
                from django.db import connections
                connection = connections['eggrecords']
                with connection.cursor() as cursor:
                    # Fallback to nuclei_templates table
                    cursor.execute("""
                        SELECT template_id
                        FROM nuclei_templates
                        WHERE is_active = true
                        ORDER BY success_rate DESC NULLS LAST,
                                 usage_count DESC NULLS LAST,
                                 updated_at DESC NULLS LAST
                        LIMIT %s
                    """, [limit])
                    templates = [row[0] for row in cursor.fetchall() if row and row[0]]
            except Exception as exc:
                logger.debug(f"Global template fallback query failed: {exc}")
                templates = []
        
        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for template in templates:
            if template not in seen:
                seen.add(template)
                deduped.append(template)
        return deduped
    
    @staticmethod
    def _parse_template_list(raw_value: Any) -> List[str]:
        """Normalise Bugsy's recommended template structures into a flat list of IDs."""
        if raw_value is None:
            return []
        data = raw_value
        if isinstance(raw_value, (str, bytes)):
            try:
                data = json.loads(raw_value)
            except Exception:
                return [raw_value] if isinstance(raw_value, str) else []
        templates: List[str] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    templates.append(item)
                elif isinstance(item, dict):
                    template_id = (
                        item.get('template_id')
                        or item.get('id')
                        or item.get('template')
                    )
                    if template_id:
                        templates.append(template_id)
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (list, tuple)):
                    for item in value:
                        if isinstance(item, str):
                            templates.append(item)
                        elif isinstance(item, dict):
                            template_id = (
                                item.get('template_id')
                                or item.get('id')
                                or item.get('template')
                            )
                            if template_id:
                                templates.append(template_id)
                elif isinstance(value, str):
                    templates.append(value)
            if not templates and isinstance(data.get('template_id'), str):
                templates.append(data['template_id'])
        return templates
    
    async def get_eggs_for_scanning(self) -> List[Dict[str, Any]]:
        """
        Fetch egg records (subdomains) that need scanning from Kontrol AI database.
        
        Surge scans the actual subdomains from eggrecord table, not the egg domainScope.
        
        Returns:
            List of subdomain records to scan
        """
        # Check if interpreter is shutting down
        import sys
        if sys.is_finalizing():
            logger.warning("⚠️  Interpreter shutting down, returning empty list")
            return []
        
        # Check if event loop is closing
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                logger.warning("⚠️  Event loop is closed, returning empty list")
                return []
        except RuntimeError:
            logger.warning("⚠️  No event loop available, returning empty list")
            return []
        
        # Use Django ORM exclusively
        if not _database_available:
            logger.warning("⚠️  Database not available, returning empty list")
            return []
        
        # Use asyncio.to_thread instead of sync_to_async to avoid deadlock
        # when running in a background thread with its own event loop
        try:
            return await asyncio.to_thread(self._get_eggs_via_django)
        except RuntimeError as e:
            if "cannot schedule new futures" in str(e) or "interpreter shutdown" in str(e) or "deadlock" in str(e).lower():
                logger.warning("⚠️  Interpreter shutting down or deadlock detected, returning empty list")
                return []
            raise
    
    def _get_eggs_via_django(self) -> List[Dict[str, Any]]:
        """Get eggs using Django ORM (primary method)."""
        try:
            from django.db import connections
            from django.utils import timezone
            
            min_scan_time = timezone.now() - timedelta(seconds=self.min_scan_age)
            
            # Use eggrecords database connection
            connection = connections['eggrecords']
            with connection.cursor() as cursor:
                additional_filters = ""
                params = [self.batch_size]
                if self.min_scan_age != 0:
                    additional_filters = """
                        AND (
                            er."lastScan" IS NULL 
                            OR er."lastScan" < %s
                        )
                    """
                    params.insert(0, min_scan_time)
                
                query = f"""
                    SELECT 
                        er.id,
                        er."subDomain",
                        er.domainname,
                        e."eisystem_in_thorm",
                        er."lastScan",
                        e."kontrol_tier",
                        er."total_scan_count",
                        COALESCE(er.bugsy_priority_score, 0),
                        er.bugsy_last_curated_at,
                        er.bugsy_curation_metadata
                    FROM customer_eggs_eggrecords_general_models_eggrecord er
                    JOIN customer_eggs_eggrecords_general_models_eggs e ON e.id = er."egg_id_id"
                    WHERE 
                        er.alive = true
                        AND er."skipScan" = false
                        {additional_filters}
                    ORDER BY 
                        COALESCE(er.bugsy_priority_score, 0) DESC,
                        er.bugsy_last_curated_at DESC NULLS LAST,
                        e."kontrol_tier" DESC,
                        er."lastScan" ASC NULLS FIRST,
                        er.created_at ASC
                    LIMIT %s
                """
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                eggs = []
                for row in rows:
                    eggs.append({
                        'id': str(row[0]),
                        'domain': row[1],
                        'domainname': row[2],
                        'customer_name': row[3],
                        'last_egg_scan': row[4],
                        'priority': row[5],
                        'scan_count': row[6] or 0,
                        'bugsy_priority_score': float(row[7]) if row[7] else 0.0,
                        'bugsy_curated_at': row[8],
                        'bugsy_recommendation': {
                            'type': None,
                            'expected_success_rate': None,
                            'metadata': json.loads(row[9]) if row[9] else None,
                        },
                        'templates': [],
                    })
                
                # Refresh template cache if needed
                now = datetime.now()
                if not self._global_template_cache or (now - self._global_template_cache_refreshed).total_seconds() > 900:
                    self._global_template_cache = self._fetch_global_template_pool(limit=80)
                    self._global_template_cache_refreshed = now
                
                # Add templates to each egg (use global cache as fallback)
                for egg in eggs:
                    if not egg.get('templates'):
                        egg['templates'] = self._global_template_cache[:40] if self._global_template_cache else []
                
                logger.info(f"📊 Found {len(eggs)} subdomains ready for scanning (via Django)")
                return eggs
        except Exception as e:
            logger.error(f"❌ Error fetching egg records via Django: {e}")
            return []
    
    def update_egg_scan_timestamp(self, egg_id: str) -> bool:
        """Update egg record scan timestamp and increment scan count using Django ORM."""
        try:
            from django.db import connections
            
            # Use eggrecords database connection
            connection = connections['eggrecords']
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE customer_eggs_eggrecords_general_models_eggrecord
                    SET 
                        "lastScan" = CURRENT_DATE,
                        "total_scan_count" = "total_scan_count" + 1,
                        updated_at = NOW()
                    WHERE id = %s
                """, [egg_id])
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"❌ Error updating egg record timestamp via Django: {e}")
            return False
    
    async def _run_nuclei_scan(self, domain: str, scan_config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Run Nuclei scan using new class-based API (NO subprocess).
        
        Uses the internal Go bridge for direct code-level control and real-time callbacks.
        
        Args:
            domain: Domain to scan
            scan_config: Optional scan configuration dictionary
            
        Returns:
            List of vulnerability dictionaries
        """
        try:
            # Import from the new API structure
            from ..nuclei.class_based_api import NucleiEngine, ScanConfig, Severity
            
            # 1. Prepare Configuration
            config_payload = dict(scan_config or {})
            config_payload.setdefault('scan_type', self.scan_type)
            
            # Convert scan_config to ScanConfig, enforcing thread-safe mode for concurrency
            config = ScanConfig(
                template_tags=config_payload.get('tags', ['cve', 'rce']),
                severity_levels=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
                rate_limit=config_payload.get('rate_limit', 10),
                use_thread_safe=True
            )
            
            # 2. Initialize Engine
            engine = NucleiEngine(config=config)
            
            # 3. Setup Callback
            vulnerabilities = []
            
            def on_vulnerability(finding):
                # Data structure mapping from finding dataclass back to agent's expected dict format
                vulnerabilities.append({
                    'template-id': finding.template_id,
                    'template': finding.template_name,
                    'info': {
                        'severity': finding.severity.value,
                        'name': finding.template_name,
                    },
                    'matched-at': finding.matched_at,
                    'target': finding.target,
                })
                logger.info(f"🎯 Found vulnerability: {finding.template_id} ({finding.severity.value}) on {domain}")
            
            # Attach the callback function
            engine.on_vulnerability.append(on_vulnerability)
            
            # 4. Execute Scan
            logger.info(f"🚀 Starting Nuclei scan for {domain} using class-based API")
            scan_id = engine.scan([domain])
            
            # 5. Wait for Completion (using asyncio)
            while engine.status.value not in ['completed', 'failed']:
                # Yield control to the event loop
                await asyncio.sleep(0.1)
            
            # 6. Cleanup and Return
            engine.close()
            logger.info(f"✅ Nuclei scan completed: {len(vulnerabilities)} vulnerabilities found")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"❌ Nuclei scan error for {domain}: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return []
    
    async def scan_egg(self, egg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan a single egg with Surge.
        
        Args:
            egg: Egg data dictionary
            
        Returns:
            Scan results
        """
            
        bugsy_priority = egg.get('bugsy_priority_score', 0) or 0
        bugsy_snapshot = egg.get('bugsy_recommendation') or {}
        bugsy_expected = bugsy_snapshot.get('expected_success_rate')
        info_parts = []
        if bugsy_priority > 0:
            info_parts.append(f"Bugsy Priority: {bugsy_priority:.1f}")
        if isinstance(bugsy_expected, (int, float)):
            info_parts.append(f"Expected Success: {bugsy_expected:.0%}")
        info_suffix = f" [{' | '.join(info_parts)}]" if info_parts else ""
        logger.info(f"⚡ Scanning subdomain: {egg['domain']} (Tier: {egg['priority']}{info_suffix})")
        
        try:
            template_list = [tpl for tpl in egg.get('templates', []) if tpl]
            if template_list:
                logger.info(f"   🧠 Bugsy provided {len(template_list)} curated templates")
            # Create scan
            scan_parameters = {
                'customer_name': egg['customer_name'],
                'autonomous': True,
                'priority': egg['priority'],
            }
            if bugsy_snapshot:
                scan_parameters['bugsy'] = {
                    'priority_score': bugsy_priority,
                    'recommendation': bugsy_snapshot,
                    'template_count': len(template_list),
                }
            
            # Create scan (only if surge_db is available)
            scan = None
            scan_id = None
            if surge_db is not None:
                scan = surge_db.create_scan(
                    target=egg['domain'],
                    scan_type=self.scan_type,
                    templates=template_list,  # Pass templates at creation
                    egg_id=egg['id'],
                    scan_parameters=scan_parameters
                )
                scan_id = scan.id if scan else None
                
                # Start scan with Kontrol team
                if scan_id:
                    kontrol_team = os.environ.get('SURGE_KONTROL_TEAM', 'Sparky,Thunder').split(',')
                    surge_db.start_scan(scan_id, kontrol_team)
            else:
                logger.warning("⚠️  surge_db not available, skipping database scan creation")
            
            # Run real Nuclei scan using unified API
            logger.info(f"🔍 Running real Nuclei scan on {egg['domain']}")
            scan_config = {'scan_type': self.scan_type}
            if template_list:
                scan_config['templates'] = template_list
                scan_config['max_templates'] = min(max(len(template_list) * 4, 40), 240)
            
            # Use the new unified API - directly call _run_nuclei_scan which uses the class-based API
            real_vulnerabilities = await self._run_nuclei_scan(egg['domain'], scan_config)
            
            # Extract template IDs from vulnerabilities
            templates_used = template_list.copy()  # Default to requested templates
            if isinstance(real_vulnerabilities, list) and real_vulnerabilities:
                # Extract unique template IDs from vulnerabilities
                templates_used = list(set([
                    v.get('template-id') for v in real_vulnerabilities 
                    if isinstance(v, dict) and v.get('template-id')
                ]))
            
            vuln_count = len(real_vulnerabilities) if real_vulnerabilities else 0
            if surge_db is not None and scan_id:
                vuln_count = surge_db.store_vulnerabilities(scan_id, real_vulnerabilities)
                
                # Update scan with actual templates used (before completing)
                if templates_used and _database_available:
                    try:
                        from ..models import NucleiScan
                        scan_record = NucleiScan.objects.filter(id=scan_id).first()
                        if scan_record:
                            scan_record.templates_used = templates_used
                            scan_record.save(update_fields=['templates_used'])
                            logger.info(f"✅ Updated scan {scan_id} with {len(templates_used)} templates: {templates_used[:5]}...")
                    except Exception as e:
                        logger.warning(f"Could not update templates_used: {e}")
                        import traceback
                        logger.debug(traceback.format_exc())
                
                # Complete scan
                surge_db.complete_scan(scan_id, success=True)
            
            # Update egg timestamp
            # Use asyncio.to_thread instead of sync_to_async to avoid deadlock
            await asyncio.to_thread(self.update_egg_scan_timestamp, egg['id'])
            
            # Update statistics
            self.stats['total_scans'] += 1
            self.stats['successful_scans'] += 1
            self.stats['total_vulnerabilities'] += vuln_count
            
            logger.info(f"✅ Completed scan {'#' + str(scan_id) if scan_id else ''} for {egg['domain']}: {vuln_count} vulnerabilities")
            
            return {
                'success': True,
                'scan_id': scan_id,
                'domain': egg['domain'],
                'vulnerabilities': vuln_count
            }
            
        except Exception as e:
            logger.error(f"❌ Error scanning egg {egg['domain']}: {e}")
            self.stats['total_scans'] += 1
            self.stats['failed_scans'] += 1
            
            return {
                'success': False,
                'domain': egg['domain'],
                'error': str(e)
            }
    
    async def scan_batch(self) -> Dict[str, Any]:
        """
        Scan a batch of eggs.
        
        Returns:
            Batch results
        """
        logger.info("=" * 70)
        logger.info("⚡ SURGE AUTONOMOUS SCAN BATCH")
        logger.info("=" * 70)
        
        # Fetch eggs
        eggs = await self.get_eggs_for_scanning()
        
        if not eggs:
            logger.info("📋 No eggs ready for scanning")
            return {
                'eggs_scanned': 0,
                'successful': 0,
                'failed': 0
            }
        
        # Scan each subdomain
        results = []
        for i, egg in enumerate(eggs, 1):
            logger.info(f"\n🎯 Scanning subdomain {i}/{len(eggs)}: {egg['domain']}")
            result = await self.scan_egg(egg)
            results.append(result)
            
            # Small delay between scans
            if i < len(eggs):
                await asyncio.sleep(2)
        
        # Calculate statistics
        successful = sum(1 for r in results if r['success'])
        failed = len(results) - successful
        
        logger.info("\n" + "=" * 70)
        logger.info("📊 BATCH SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Subdomains scanned: {len(eggs)}")
        logger.info(f"Successful: {successful}")
        logger.info(f"Failed: {failed}")
        logger.info(f"Success rate: {(successful/len(eggs)*100):.1f}%")
        logger.info("=" * 70 + "\n")
        
        return {
            'eggs_scanned': len(eggs),
            'successful': successful,
            'failed': failed,
            'results': results
        }
    
    def display_statistics(self):
        """Display running statistics."""
        uptime = datetime.now() - self.stats['uptime_start']
        uptime_hours = uptime.total_seconds() / 3600
        
        logger.info("\n" + "=" * 70)
        logger.info("📊 SURGE AUTONOMOUS SCANNER STATISTICS")
        logger.info("=" * 70)
        logger.info(f"Uptime: {uptime}")
        logger.info(f"Total scans: {self.stats['total_scans']}")
        logger.info(f"Successful: {self.stats['successful_scans']}")
        logger.info(f"Failed: {self.stats['failed_scans']}")
        logger.info(f"Total vulnerabilities: {self.stats['total_vulnerabilities']}")
        
        if uptime_hours > 0:
            scans_per_hour = self.stats['total_scans'] / uptime_hours
            logger.info(f"Scan rate: {scans_per_hour:.2f} scans/hour")
        
        success_rate = 0
        if self.stats['total_scans'] > 0:
            success_rate = (self.stats['successful_scans'] / self.stats['total_scans'] * 100)
        logger.info(f"Success rate: {success_rate:.1f}%")
        logger.info("=" * 70 + "\n")
    
    async def run(self):
        """Run autonomous scanner."""
        self.running = True
        logger.info("🚀 Starting Surge Autonomous Scanner")
        logger.info(f"   Batch size: {self.batch_size}, Scan type: {self.scan_type}")
        logger.info(f"   Next scan in {self.scan_interval}s")
        
        try:
            while self.running:
                # Check if interpreter is shutting down
                import sys
                if sys.is_finalizing():
                    logger.info("⚠️  Interpreter shutting down, stopping scanner")
                    break
                
                # Check if event loop is closing
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_closed():
                        logger.info("⚠️  Event loop closed, stopping scanner")
                        break
                except RuntimeError:
                    logger.info("⚠️  No event loop available, stopping scanner")
                    break
                
                try:
                    # Run scan batch
                    logger.info("📋 Starting scan batch...")
                    await self.scan_batch()
                    
                    # Display statistics
                    self.display_statistics()
                    
                    # Check if continuous mode
                    if not self.continuous:
                        logger.info("📋 Single run mode - exiting")
                        break
                    
                    # Wait for next scan interval
                    logger.info(f"⏰ Next scan in {self.scan_interval} seconds...")
                    await asyncio.sleep(self.scan_interval)
                except RuntimeError as e:
                    if "cannot schedule new futures" in str(e) or "interpreter shutdown" in str(e):
                        logger.info("⚠️  Interpreter shutting down, stopping scanner gracefully")
                        break
                    logger.error(f"❌ RuntimeError in scan batch: {e}", exc_info=True)
                    # Continue to next iteration instead of stopping
                    logger.info("⏰ Waiting before retry...")
                    try:
                        await asyncio.sleep(60)  # Wait 1 minute before retry
                    except RuntimeError:
                        # Interpreter shutting down during sleep
                        break
                    # Continue to next iteration instead of stopping
                    logger.info("⏰ Waiting before retry...")
                    try:
                        await asyncio.sleep(60)  # Wait 1 minute before retry
                    except RuntimeError:
                        # Interpreter shutting down during sleep
                        break
                except Exception as batch_error:
                    logger.error(f"❌ Error in scan batch: {batch_error}", exc_info=True)
                    # Continue to next iteration instead of stopping
                    logger.info("⏰ Waiting before retry...")
                    try:
                        await asyncio.sleep(60)  # Wait 1 minute before retry
                    except RuntimeError:
                        # Interpreter shutting down during sleep
                        break
                
        except KeyboardInterrupt:
            logger.info("\n⚠️  Received interrupt signal")
        except Exception as e:
            logger.error(f"❌ Fatal error in scanner run loop: {e}", exc_info=True)
            raise
        finally:
            self.running = False
            logger.info("🛑 Surge Autonomous Scanner stopped")
            self.display_statistics()
    
    def stop(self):
        """Stop the scanner gracefully."""
        logger.info("🛑 Stopping Surge Autonomous Scanner...")
        self.running = False


# Global scanner instance
scanner = None
_scanner_instance = None


def get_instance():
    """Get or create singleton scanner instance."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = SurgeAutonomousScanner()
    return _scanner_instance


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"\n⚠️  Received signal {signum}")
    if scanner:
        scanner.stop()
    sys.exit(0)


async def main():
    """Main entry point."""
    global scanner
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("=" * 70)
    logger.info("⚡ SURGE AUTONOMOUS SCANNER")
    logger.info("=" * 70)
    logger.info("Electric Scanning for Kontrol AI Eggs")
    logger.info("Author: EGO Revolution Team")
    logger.info("=" * 70 + "\n")
    
    # Test database connection
    logger.info("🔌 Testing database connection...")
    try:
        from django.db import connections
        connection = connections['eggrecords']
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        logger.info("✅ Database connection successful\n")
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        logger.error("   Please check Django database configuration")
        return 1
    
    # Create and run scanner
    scanner = SurgeAutonomousScanner()
    await scanner.run()
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

