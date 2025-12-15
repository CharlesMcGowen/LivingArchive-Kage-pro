#!/usr/bin/env python3
"""
Oak Target Curation Service
================================

Comprehensive subdomain curation service that enriches every discovered subdomain with:
- Technology fingerprinting
- CVE correlation
- Confidence scoring
- Risk assessment
- Scan recommendations

Oak's meticulous approach ensures every subdomain has complete vulnerability intelligence.

Author: EGO Revolution Team - Oak
Version: 1.0.0
Migrated to Kage-pro: 2024
"""

import logging
import uuid
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction, models
from django.db.models import Avg, Count, Q, Max
# Fully synchronous implementation - no async needed

logger = logging.getLogger(__name__)


class OakTargetCurationService:
    """
    Oak's target curation and intelligence coordination service.
    
    Automatically enriches subdomains discovered by Ash/Jade with comprehensive
    vulnerability intelligence for Surge scanning.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.curation_queue = []
        self.processing_count = 0
        self.completed_count = 0
        
        # Import services (lazy to avoid TemplateEffectiveness import issues)
        self.cve_service = None
        self.fingerprint_service = None
        self._services_imported = False
    
    def _ensure_services_imported(self):
        """Lazy import of services to avoid TemplateEffectiveness import errors"""
        if self._services_imported:
            return
        
        try:
            # Only import CVE intelligence service - Bugsy fingerprinting moved to Oak
            # Note: Bugsy services are still in main codebase, import from there
            from artificial_intelligence.personalities.security.bugsy.cve_intelligence_service import BugsyCVEIntelligenceService
            self.cve_service = BugsyCVEIntelligenceService()
            # Note: Fingerprinting is now handled by Oak's data_curator, not Bugsy
            self.fingerprint_service = None
            self._services_imported = True
        except Exception as e:
            self.logger.warning(f"⚠️ CVE service not available: {e}")
            # Continue without services - curation can still queue records
    
    
    def queue_subdomain_for_curation(self, egg_record, discovery_source: str = 'unknown', 
                                    priority: str = 'normal') -> Dict[str, Any]:
        """
        Queue a subdomain for Oak's curation workflow.
        
        Args:
            egg_record: The EggRecord (subdomain) to curate
            discovery_source: 'ash', 'jade', or 'ash_jade_discovery'
            priority: 'high', 'normal', or 'low'
            
        Returns:
            Dict with queue status and details
        """
        try:
            # Use raw SQL to avoid Django ORM async context issues
            from django.db import connections, transaction
            import json
            import uuid as uuid_lib
            
            egg_record_id = str(egg_record.id) if hasattr(egg_record, 'id') else str(egg_record)
            
            # Use transaction.atomic() to properly manage database connections
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    # Check if queue entry exists
                    cursor.execute("""
                        SELECT id, status, retry_count
                        FROM enrichment_system_subdomaincurationqueue
                        WHERE egg_record_id = %s
                        LIMIT 1
                    """, [egg_record_id])
                    existing = cursor.fetchone()
                    
                    if existing:
                        queue_entry_id, status, retry_count = existing
                        created = False
                        
                        # Update if failed
                        if status == 'failed':
                            cursor.execute("""
                                UPDATE enrichment_system_subdomaincurationqueue
                                SET status = 'queued',
                                    retry_count = %s,
                                    queued_at = NOW()
                                WHERE id = %s
                            """, [retry_count + 1, queue_entry_id])
                    else:
                        # Create new queue entry
                        queue_entry_id = str(uuid_lib.uuid4())
                        created = True
                        
                        # Metadata - discovery_metadata column doesn't exist, use empty dict
                        metadata = {}
                        
                        cursor.execute("""
                            INSERT INTO enrichment_system_subdomaincurationqueue (
                                id, egg_record_id, status, priority, discovery_source,
                                queued_at, metadata, retry_count, created_at, updated_at
                            ) VALUES (%s, %s, 'queued', %s, %s, NOW(), %s, 0, NOW(), NOW())
                        """, [queue_entry_id, egg_record_id, priority, discovery_source, json.dumps(metadata)])
                    
                    # Get queue position
                    cursor.execute("""
                        SELECT COUNT(*) 
                        FROM enrichment_system_subdomaincurationqueue
                        WHERE status = 'queued'
                        AND queued_at <= (SELECT queued_at FROM enrichment_system_subdomaincurationqueue WHERE id = %s)
                    """, [queue_entry_id])
                    queue_position = cursor.fetchone()[0] or 0
                    
                    # Django commits automatically when transaction.atomic() block exits successfully
                
            return {
                'success': True,
                'queue_entry_id': queue_entry_id,
                'queue_position': queue_position,
                'status': 'queued',
                'created': created
            }
            
        except Exception as e:
            error_msg = str(e)
            # Check if table doesn't exist - fallback to direct processing
            if 'does not exist' in error_msg or 'relation' in error_msg.lower():
                self.logger.debug("SubdomainCurationQueue table not available, processing directly")
                return self._process_curation_directly(egg_record, discovery_source, priority)
            
            # Check for TemplateEffectiveness conflict
            if 'Conflicting' in error_msg and 'templateeffectiveness' in error_msg.lower():
                self.logger.debug(f"TemplateEffectiveness model conflict detected, using direct processing: {error_msg[:100]}")
            # Check for table redefinition error
            elif 'already defined for this MetaData instance' in error_msg or 'extend_existing' in error_msg.lower():
                self.logger.debug(f"Table redefinition detected (this should be fixed by extend_existing=True): {error_msg[:100]}")
            # ImportError is expected if SubdomainCurationQueue doesn't exist
            elif isinstance(e, ImportError) and 'SubdomainCurationQueue' in error_msg:
                self.logger.debug(f"SubdomainCurationQueue not available, processing directly: {e}")
            else:
                self.logger.warning(f"Failed to queue subdomain: {error_msg[:200]}, trying direct processing")
            # Fallback: try direct processing
            try:
                return self._process_curation_directly(egg_record, discovery_source, priority)
            except Exception as e2:
                error_msg2 = str(e2)
                # Check if it's also a TemplateEffectiveness conflict
                if 'Conflicting' in error_msg2 and 'templateeffectiveness' in error_msg2.lower():
                    self.logger.debug(f"TemplateEffectiveness model conflict in direct processing, skipping: {error_msg2[:100]}")
                    # Don't log as error - this is expected and handled gracefully
                # Check for table redefinition error
                elif 'already defined for this MetaData instance' in error_msg2 or 'extend_existing' in error_msg2.lower():
                    self.logger.debug(f"Table redefinition in direct processing (should be fixed): {error_msg2[:100]}")
                else:
                    self.logger.error(f"❌ Oak: Curation failed for {egg_record.subDomain or egg_record.domainname}: {error_msg2[:200]}")
                return {
                    'success': False,
                    'error': error_msg2[:200]  # Truncate long error messages
                }
    
    def _process_curation_directly(self, egg_record, discovery_source: str, priority: str) -> Dict[str, Any]:
        """
        Process curation directly without queue (fallback method).
        """
        try:
            # Process curation in background thread (sync function)
            import threading
            
            def run_curation():
                try:
                    # Check if interpreter is shutting down
                    import sys
                    if sys.is_finalizing():
                        self.logger.warning("Interpreter shutting down - skipping curation")
                        return {'success': False, 'error': 'Interpreter shutting down'}
                    
                    # Call sync function directly - no async needed
                    result = self.curate_subdomain(egg_record)
                    return result
                except Exception as e:
                    error_msg = str(e)
                    # Check if it's a TemplateEffectiveness conflict - log as debug
                    if 'Conflicting' in error_msg and 'templateeffectiveness' in error_msg.lower():
                        self.logger.debug(f"TemplateEffectiveness conflict in background curation (expected): {error_msg[:100]}")
                        return {'success': True, 'warning': 'TemplateEffectiveness conflict detected'}
                    # Check for table redefinition
                    elif 'already defined for this MetaData instance' in error_msg:
                        self.logger.debug(f"Table redefinition in background curation: {error_msg[:100]}")
                        return {'success': True, 'warning': 'Table redefinition detected'}
                    else:
                        self.logger.error(f"Error in direct curation: {e}", exc_info=True)
                        return {'success': False, 'error': error_msg[:200]}
            
            # Run in background thread
            thread = threading.Thread(target=run_curation, daemon=True)
            thread.start()
            
            return {
                'success': True,
                'status': 'processing',
                'message': 'Curation started in background'
            }
        except Exception as e:
            self.logger.error(f"Failed to process curation directly: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    
    def curate_subdomain(self, egg_record) -> Dict[str, Any]:
        """
        Oak's comprehensive subdomain curation workflow.
        
        Steps:
            1. Check if HTTP request metadata exists (from Kaze/Ryu scans)
            2. Perform technology fingerprinting
            3. Correlate with CVE database
            4. Calculate confidence score
            5. Generate scan recommendations
            6. Create vulnerability profile
        
        Returns:
            Dict with curation results and metadata
        """
        subdomain = egg_record.subDomain or egg_record.domainname
        self.logger.info(f"🌳 Oak: Starting curation for {subdomain}")
        
        results = {
            'subdomain': subdomain,
            'egg_record_id': str(egg_record.id),
            'fingerprints_created': 0,
            'cve_matches': 0,
            'recommendations': 0,
            'confidence_score': 0.0,
            'steps_completed': []
        }
        
        try:
            # Step 1: Check for HTTP request metadata (from Kaze/Ryu scans)
            # Note: Kaze and Ryu handle HTTP spidering, no need to trigger separate collection
            http_data = self._check_http_metadata(egg_record)
            if http_data['success']:
                results['steps_completed'].append('http_metadata_collected')
                results['http_metadata_id'] = http_data.get('metadata_id')
            
            # Step 2: Technology fingerprinting (Oak handles all fingerprinting)
            self._ensure_services_imported()
            # Oak's _perform_fingerprinting uses Nmap data from data_curator, not Bugsy
            fingerprint_result = self._perform_fingerprinting(egg_record)
            results['fingerprints_created'] = fingerprint_result['fingerprints_count']
            if fingerprint_result['fingerprints_count'] > 0:
                results['steps_completed'].append('fingerprinting')
            
            # Step 3: CVE correlation (happens automatically via signals)
            # Give signals time to process
            import time
            time.sleep(1)
            
            # Step 4: Calculate confidence score (direct sync call - we're in background thread)
            try:
                confidence_result = self.calculate_subdomain_confidence(egg_record)
            except Exception as e:
                self.logger.warning(f"Error calculating confidence: {e}")
                confidence_result = {'overall_score': 0.0, 'breakdown': {}}
            
            results['confidence_score'] = confidence_result['overall_score']
            results['confidence_breakdown'] = confidence_result['breakdown']
            results['steps_completed'].append('confidence_calculation')
            
            # Step 5: Count results (use raw SQL to avoid relationship issues)
            # Direct sync call - no async needed
            def _count_cve_results_sync(egg_id: str) -> Dict[str, int]:
                from django.db import connections, transaction
                # Use transaction.atomic() to properly manage connections
                with transaction.atomic(using='eggrecords'):
                    try:
                        db = connections['eggrecords']
                    except KeyError:
                        db = connections['default']
                    
                    with db.cursor() as cursor:
                        cursor.execute("""
                            SELECT COUNT(*) FROM enrichment_system_cvefingerprintmatch
                            WHERE egg_record_id = %s
                        """, [egg_id])
                        cve_matches = cursor.fetchone()[0] or 0
                        
                        cursor.execute("""
                            SELECT COUNT(*) FROM enrichment_system_cvefingerprintmatch
                            WHERE egg_record_id = %s AND recommended_for_scanning = true
                        """, [egg_id])
                        recommendations = cursor.fetchone()[0] or 0
                        
                        return {'cve_matches': cve_matches, 'recommendations': recommendations}
            
            try:
                count_results = _count_cve_results_sync(str(egg_record.id))
            except Exception as e:
                self.logger.warning(f"Error counting CVE results: {e}")
                count_results = {'cve_matches': 0, 'recommendations': 0}
            results['cve_matches'] = count_results['cve_matches']
            results['recommendations'] = count_results['recommendations']
            
            # Step 5.5: Ensure Nmap scan exists and select Nuclei templates
            try:
                from ..nmap_coordination_service import OakNmapCoordinationService
                nmap_coord = OakNmapCoordinationService()
                
                # Ensure Nmap scan exists (will trigger if needed)
                nmap_result = nmap_coord.ensure_nmap_scan_for_egg_record(
                    egg_record=egg_record,
                    scan_agent='kage',
                    priority='normal'
                )
                results['nmap_scan_status'] = nmap_result
                
                # Select Nuclei templates based on fingerprints, CVEs, and ports
                template_result = nmap_coord.select_nuclei_templates_for_egg_record(
                    egg_record=egg_record,
                    max_templates=20
                )
                results['nuclei_templates'] = template_result
                results['templates_selected'] = template_result.get('template_count', 0)
                results['steps_completed'].append('nuclei_template_selection')
                
                if template_result.get('success'):
                    self.logger.info(f"✅ Oak: Selected {template_result.get('template_count', 0)} Nuclei templates for {subdomain}")
            except Exception as e:
                self.logger.warning(f"Error in Nmap coordination/template selection: {e}")
                results['nmap_scan_status'] = {'success': False, 'error': str(e)}
                results['nuclei_templates'] = {'success': False, 'error': str(e)}
            
            # Step 6: Create vulnerability profile (direct sync call - we're in background thread)
            try:
                profile_result = self._create_vulnerability_profile(egg_record, results)
            except Exception as e:
                self.logger.warning(f"Error creating vulnerability profile: {e}")
                profile_result = {}
            results['profile_id'] = profile_result.get('profile_id')
            results['steps_completed'].append('vulnerability_profile')
            
            results['success'] = True
            results['curation_completed_at'] = timezone.now().isoformat()
            
            # Always update bugsy_last_curated_at to mark record as curated
            # This ensures autonomous curation doesn't re-process it immediately
            try:
                from django.db import connections, transaction
                with transaction.atomic(using='eggrecords'):
                    try:
                        db = connections['eggrecords']
                    except KeyError:
                        db = connections['default']
                    
                    with db.cursor() as cursor:
                        # Update curation timestamp (even if some steps failed)
                        cursor.execute("""
                            UPDATE customer_eggs_eggrecords_general_models_eggrecord
                            SET bugsy_last_curated_at = NOW()
                            WHERE id = %s
                        """, [str(egg_record.id)])
            except Exception as e:
                self.logger.debug(f"Could not update bugsy_last_curated_at: {e}")
            
            self.logger.info(f"✅ Oak: Curation complete for {subdomain}")
            self.logger.info(f"   Fingerprints: {results['fingerprints_created']} | CVEs: {results['cve_matches']}")
            self.logger.info(f"   Confidence: {results['confidence_score']:.1f}% | Recommendations: {results['recommendations']}")
            
        except Exception as e:
            error_msg = str(e)
            # Check if it's a TemplateEffectiveness conflict - log as debug, not error
            if 'Conflicting' in error_msg and 'templateeffectiveness' in error_msg.lower():
                self.logger.debug(f"TemplateEffectiveness conflict in curation for {subdomain} (expected, handled gracefully): {error_msg[:100]}")
                # Mark as success with note that some steps may have been skipped
                results['success'] = True
                results['warning'] = 'TemplateEffectiveness conflict detected, some steps may have been skipped'
            # Check for table redefinition errors
            elif 'already defined for this MetaData instance' in error_msg or 'extend_existing' in error_msg.lower():
                self.logger.debug(f"Table redefinition in curation for {subdomain} (should be fixed): {error_msg[:100]}")
                results['success'] = True
                results['warning'] = 'Table redefinition detected, some steps may have been skipped'
            else:
                self.logger.error(f"❌ Oak: Curation failed for {subdomain}: {error_msg[:200]}")
                results['success'] = False
                results['error'] = error_msg[:200]
                
                # Still update curation timestamp on failure (to prevent immediate retry)
                # Only if we got past initial steps
                if results.get('steps_completed'):
                    try:
                        from django.db import connections, transaction
                        with transaction.atomic(using='eggrecords'):
                            try:
                                db = connections['eggrecords']
                            except KeyError:
                                db = connections['default']
                            
                            with db.cursor() as cursor:
                                cursor.execute("""
                                    UPDATE customer_eggs_eggrecords_general_models_eggrecord
                                    SET bugsy_last_curated_at = NOW()
                                    WHERE id = %s
                                """, [str(egg_record.id)])
                    except Exception as e:
                        self.logger.debug(f"Could not update bugsy_last_curated_at on failure: {e}")
        
        return results
    
    
    def _check_http_metadata(self, egg_record) -> Dict[str, Any]:
        """
        Check for HTTP request metadata from Kaze/Ryu scans.
        
        Note: Misty no longer exists - HTTP spidering is handled by Kaze and Ryu.
        This just checks for existing data, doesn't trigger scans.
        
        Uses raw SQL to avoid SQLAlchemy/Django ORM conflicts.
        Called directly (no sync_to_async) since we're in a background thread.
        """
        # Helper function to check for existing HTTP metadata (sync)
        def _check_http_metadata_sync(egg_id: str) -> Optional[Dict[str, Any]]:
            from django.db import connections, transaction
            try:
                db_connection = connections['eggrecords']
            except KeyError:
                db_connection = connections['default']
            
            try:
                # Use transaction.atomic() to properly manage connections
                with transaction.atomic(using='eggrecords'):
                    with db_connection.cursor() as cursor:
                        cursor.execute("""
                            SELECT id, record_id_id, target_url, response_status, response_headers, 
                                   response_body, timestamp, created_at
                            FROM customer_eggs_eggrecords_general_models_requestmetadata
                            WHERE record_id_id = %s
                            ORDER BY timestamp DESC NULLS LAST, created_at DESC NULLS LAST
                            LIMIT 1
                        """, [egg_id])
                        
                        row = cursor.fetchone()
                        if row:
                            return {
                                'success': True,
                                'metadata_id': str(row[0]),
                                'source': 'existing'
                            }
            except Exception as e:
                # Table might not exist or other error - log and continue
                self.logger.debug(f"Could not check for existing HTTP metadata: {e}")
            return None
        
        # Check for existing data (direct sync call - we're in background thread)
        egg_id = str(egg_record.id)
        try:
            existing_data = _check_http_metadata_sync(egg_id)
        except Exception as e:
            self.logger.warning(f"Error checking HTTP metadata: {e}")
            existing_data = None
        
        if existing_data:
            return existing_data
        
        # No HTTP metadata found - that's OK, Kaze/Ryu will collect it when they scan
        return {
            'success': False,
            'source': 'none',
            'note': 'No HTTP metadata found - will be collected by Kaze/Ryu scans'
        }
    
    
    def _perform_fingerprinting(self, egg_record) -> Dict[str, Any]:
        """
        Perform Oak's comprehensive technology fingerprinting.
        Uses multiple detection methods for maximum accuracy.
        """
        subdomain = egg_record.subDomain or egg_record.domainname
        fingerprints_created = 0
        
        try:
            # Use Django ORM for TechnologyFingerprint
            try:
                from artificial_intelligence.customer_eggs_eggrecords_general_models.models import TechnologyFingerprint
                use_orm = True
            except ImportError:
                try:
                    from customer_eggs_eggrecords_general_models.models import TechnologyFingerprint
                    use_orm = True
                except (ImportError, Exception) as import_err:
                    error_str = str(import_err)
                    self.logger.debug(f"TechnologyFingerprint Django ORM not available: {error_str[:100]}")
                    use_orm = False
            # Method 1: Nmap-based fingerprinting (if Ash scan exists)
            # Use raw SQL to avoid async context issues
            def _fetch_nmap_scans_sync(egg_id: str):
                """Sync helper to fetch Nmap scans."""
                from django.db import connections, transaction
                try:
                    with transaction.atomic(using='eggrecords'):
                        try:
                            db = connections['eggrecords']
                        except KeyError:
                            db = connections['default']
                        
                        with db.cursor() as cursor:
                            cursor.execute("""
                                SELECT id, service_name, service_version, port, protocol, scan_type, open_ports
                                FROM customer_eggs_eggrecords_general_models_nmap
                                WHERE record_id_id = %s AND scan_status = 'completed'
                                ORDER BY created_at DESC
                            """, [egg_id])
                            return cursor.fetchall()
                except Exception as e:
                    self.logger.debug(f"Could not fetch Nmap scans: {e}")
                    return []
            
            try:
                nmap_scans_data = _fetch_nmap_scans_sync(str(egg_record.id))
            except Exception as e:
                self.logger.warning(f"Error fetching Nmap scans: {e}")
                nmap_scans_data = []
            # Convert to simple objects for processing
            class SimpleNmapScan:
                def __init__(self, scan_id, service_name, service_version, port, protocol, scan_type, open_ports=None):
                    self.id = scan_id
                    self.service_name = service_name
                    self.service_version = service_version
                    self.port = port
                    self.protocol = protocol or 'tcp'
                    self.scan_type = scan_type or 'unknown'
                    # Parse open_ports if it's a JSON string
                    if open_ports:
                        if isinstance(open_ports, str):
                            try:
                                import json
                                self.open_ports = json.loads(open_ports)
                            except:
                                self.open_ports = []
                        else:
                            self.open_ports = open_ports
                    else:
                        self.open_ports = []
            
            nmap_scans = [SimpleNmapScan(*row) for row in nmap_scans_data]
            
            # Helper function to create fingerprint from Nmap scan (sync)
            def _create_nmap_fingerprint_sync(egg_id: str, scan_id: Optional[str], service_name: str, 
                                             service_version: str, port: str, protocol: str, scan_type: str) -> bool:
                """Sync helper to create fingerprint from Nmap scan."""
                from django.db import connections, transaction
                import uuid as uuid_lib
                import json
                try:
                    with transaction.atomic(using='eggrecords'):
                        try:
                            db = connections['eggrecords']
                        except KeyError:
                            db = connections['default']
                        
                        with db.cursor() as cursor:
                            # Check if fingerprint already exists
                            cursor.execute("""
                                SELECT id FROM enrichment_system_technologyfingerprint
                                WHERE egg_record_id = %s 
                                AND technology_name = %s 
                                AND technology_version = %s
                                AND detection_method = 'nmap'
                                LIMIT 1
                            """, [egg_id, service_name, service_version or ''])
                            existing = cursor.fetchone()
                            
                            if not existing:
                                # Create new fingerprint
                                fingerprint_id = str(uuid_lib.uuid4())
                                cursor.execute("""
                                    INSERT INTO enrichment_system_technologyfingerprint (
                                        id, egg_record_id, nmap_scan_id, technology_name, 
                                        technology_version, detection_method, confidence_score,
                                        technology_category, raw_detection_data, created_at, updated_at
                                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                                """, [
                                    fingerprint_id,
                                    egg_id,
                                    scan_id,
                                    service_name,
                                    service_version or '',
                                    'nmap',
                                    0.85,
                                    'service',
                                    json.dumps({
                                        'port': port,
                                        'protocol': protocol,
                                        'scan_type': scan_type
                                    })
                                ])
                                return True
                except Exception as e:
                    self.logger.debug(f"Failed to create fingerprint from Nmap: {e}")
                return False
            
            # Create fingerprints for all Nmap scans (async)
            for nmap_scan in nmap_scans:
                if nmap_scan.service_name:
                    try:
                        created = _create_nmap_fingerprint_sync(
                            str(egg_record.id),
                            str(nmap_scan.id) if hasattr(nmap_scan, 'id') else None,
                            nmap_scan.service_name,
                            nmap_scan.service_version or '',
                            str(nmap_scan.port) if hasattr(nmap_scan, 'port') else '',
                            getattr(nmap_scan, 'protocol', 'tcp'),
                            getattr(nmap_scan, 'scan_type', 'unknown')
                        )
                    except Exception as e:
                        self.logger.warning(f"Error creating Nmap fingerprint: {e}")
                        created = False
                    if created:
                        fingerprints_created += 1
            
            # Method 2: HTTP-based fingerprinting (if HTTP metadata exists from Kaze/Ryu)
            # Use raw SQL to query RequestMetaData (Django ORM model available but using raw SQL for safety)
            # Called directly (no sync_to_async) since we're in a background thread
            def _fetch_request_metadata_sync(egg_id: str):
                """Sync helper to fetch request metadata."""
                from django.db import connections, transaction
                try:
                    with transaction.atomic(using='eggrecords'):
                        try:
                            db_connection = connections['eggrecords']
                        except KeyError:
                            db_connection = connections['default']
                        
                        with db_connection.cursor() as cursor:
                            cursor.execute("""
                                SELECT id, record_id_id, target_url, response_status, response_headers, 
                                       response_body, timestamp, created_at
                                FROM customer_eggs_eggrecords_general_models_requestmetadata
                                WHERE record_id_id = %s
                                ORDER BY timestamp DESC NULLS LAST, created_at DESC NULLS LAST
                                LIMIT 1
                            """, [egg_id])
                            
                            row = cursor.fetchone()
                            if row:
                                # Create simple object with needed attributes
                                class SimpleRequestMetaData:
                                    def __init__(self, id, record_id_id, target_url, response_status, 
                                                response_headers, response_body, timestamp, created_at):
                                        self.id = id
                                        self.record_id_id = record_id_id
                                        self.target_url = target_url
                                        self.response_status = response_status
                                        # Parse JSON if string
                                        import json
                                        if isinstance(response_headers, str):
                                            try:
                                                self.response_headers = json.loads(response_headers)
                                            except:
                                                self.response_headers = {}
                                        else:
                                            self.response_headers = response_headers or {}
                                        self.response_body = response_body
                                        self.timestamp = timestamp
                                        self.created_at = created_at
                                
                                return SimpleRequestMetaData(*row)
                except Exception as e:
                    self.logger.debug(f"Could not fetch request metadata: {e}")
                return None
            
            try:
                request_metadata = _fetch_request_metadata_sync(str(egg_record.id))
            except Exception as e:
                self.logger.warning(f"Error fetching request metadata: {e}")
                request_metadata = None
            
            if request_metadata and hasattr(request_metadata, 'response_headers') and request_metadata.response_headers:
                # Oak's comprehensive HTTP analysis
                try:
                    from ai_system.personalities.security.bugsy.technology_detection_database import (
                        BugsyTechnologyDetector
                    )
                except ImportError:
                    from artificial_intelligence.personalities.security.bugsy.technology_detection_database import (
                        BugsyTechnologyDetector
                    )
                
                detection_result = BugsyTechnologyDetector.detect_comprehensive(
                    headers=request_metadata.response_headers,
                    cookies={},
                    html_content=request_metadata.response_body or ''
                )
                
                # Helper function to create fingerprint from HTTP detection (sync)
                def _create_http_fingerprint_sync(egg_id: str, detection: Dict, metadata_id: Optional[str]) -> bool:
                    """Sync helper to create fingerprint from HTTP detection."""
                    from django.db import connections, transaction
                    import uuid as uuid_lib
                    import json
                    try:
                        with transaction.atomic(using='eggrecords'):
                            try:
                                db = connections['eggrecords']
                            except KeyError:
                                db = connections['default']
                            
                            with db.cursor() as cursor:
                                # Check if fingerprint already exists
                                cursor.execute("""
                                    SELECT id FROM enrichment_system_technologyfingerprint
                                    WHERE egg_record_id = %s 
                                    AND technology_name = %s 
                                    AND technology_version = %s
                                    AND detection_method = 'oak_fingerprint'
                                    LIMIT 1
                                """, [egg_id, detection['name'], detection.get('version', '')])
                                existing = cursor.fetchone()
                                
                                if not existing:
                                    # Create new fingerprint
                                    fingerprint_id = str(uuid_lib.uuid4())
                                    cursor.execute("""
                                        INSERT INTO enrichment_system_technologyfingerprint (
                                            id, egg_record_id, request_metadata_id, technology_name, 
                                            technology_version, detection_method, confidence_score,
                                            technology_category, raw_detection_data, created_at, updated_at
                                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                                    """, [
                                        fingerprint_id,
                                        egg_id,
                                        metadata_id,
                                        detection['name'],
                                        detection.get('version', ''),
                                        'oak_fingerprint',
                                        detection.get('confidence', 0.5),
                                        detection.get('category', 'unknown'),
                                        json.dumps({
                                            'detection_methods': detection.get('detection_methods', []) if isinstance(detection, dict) else [],
                                            'evidence': detection.get('evidence', {}) if isinstance(detection, dict) else {}
                                        })
                                    ])
                                    return True
                    except Exception as e:
                        self.logger.debug(f"Failed to create fingerprint from HTTP: {e}")
                    return False
                
                # Create fingerprints for all detections (async)
                for detection in detection_result.get('detections', []):
                    try:
                        created = _create_http_fingerprint_sync(
                            str(egg_record.id),
                            detection,
                            str(request_metadata.id) if request_metadata and hasattr(request_metadata, 'id') else None
                        )
                    except Exception as e:
                        self.logger.warning(f"Error creating HTTP fingerprint: {e}")
                        created = False
                    if created:
                        fingerprints_created += 1
            
            # Method 3: Note - Removed Bugsy active fingerprinting fallback
            # Oak now handles all fingerprinting through Nmap data analysis
            # If no fingerprints were created, that's OK - will be enriched when scans complete
            if fingerprints_created == 0:
                self.logger.debug(f"No fingerprints created for {subdomain} - will enrich when scan data available")
            
            return {
                'success': True,
                'fingerprints_count': fingerprints_created
            }
            
        except Exception as e:
            self.logger.error(f"Fingerprinting failed for {subdomain}: {e}", exc_info=True)
            return {
                'success': False,
                'fingerprints_count': fingerprints_created,
                'error': str(e)
            }
    
    
    def calculate_subdomain_confidence(self, egg_record) -> Dict[str, Any]:
        """
        Oak's comprehensive confidence score calculation.
        
        Combines multiple signals:
        - Technology fingerprint confidence
        - CVE match quality
        - Detection method diversity
        - Version specificity
        - Data freshness
        
        Returns:
            Dict with overall score (0-100) and breakdown
        """
        breakdown = {}
        
        # Use a single transaction block to reduce connection overhead
        from django.db import connections, transaction
        with transaction.atomic(using='eggrecords'):
            try:
                db = connections['eggrecords']
            except KeyError:
                db = connections['default']
            
            with db.cursor() as cursor:
                # 1. Technology Fingerprint Confidence (35% weight)
                cursor.execute("""
                    SELECT AVG(confidence_score), COUNT(*)
                    FROM enrichment_system_technologyfingerprint
                    WHERE egg_record_id = %s
                """, [str(egg_record.id)])
                row = cursor.fetchone()
                avg_fingerprint_confidence = float(row[0]) if row and row[0] else 0.0
                fingerprint_count = row[1] or 0
                breakdown['fingerprint_confidence'] = avg_fingerprint_confidence * 100
                
                # 2. CVE Match Confidence (30% weight)
                cursor.execute("""
                    SELECT cve_severity, match_confidence
                    FROM enrichment_system_cvefingerprintmatch
                    WHERE egg_record_id = %s
                """, [str(egg_record.id)])
                cve_matches = cursor.fetchall()
                
                # 3. Detection Method Diversity (20% weight)
                cursor.execute("""
                    SELECT COUNT(DISTINCT detection_method)
                    FROM enrichment_system_technologyfingerprint
                    WHERE egg_record_id = %s
                """, [str(egg_record.id)])
                unique_methods = cursor.fetchone()[0] or 0
                
                # 4. Version Specificity (15% weight)
                if fingerprint_count > 0:
                    cursor.execute("""
                        SELECT COUNT(*) FROM enrichment_system_technologyfingerprint
                        WHERE egg_record_id = %s 
                        AND technology_version IS NOT NULL 
                        AND technology_version != ''
                    """, [str(egg_record.id)])
                    versioned_count = cursor.fetchone()[0] or 0
                else:
                    versioned_count = 0
        
        # Process CVE matches (outside transaction to avoid holding connection)
        if cve_matches:
            weighted_cve_confidence = 0.0
            total_weight = 0.0
            for severity, match_confidence in cve_matches:
                severity_weight = {
                    'CRITICAL': 1.0,
                    'HIGH': 0.8,
                    'MEDIUM': 0.6,
                    'LOW': 0.4
                }.get(severity or 'UNKNOWN', 0.5)
                match_conf = float(match_confidence) if match_confidence else 0.5
                weighted_cve_confidence += match_conf * severity_weight
                total_weight += severity_weight
            
            breakdown['cve_match_confidence'] = (weighted_cve_confidence / max(total_weight, 1)) * 100
        else:
            breakdown['cve_match_confidence'] = 50.0  # Neutral score if no CVEs
        
        method_diversity_score = min(unique_methods / 3.0, 1.0)  # Max at 3 methods
        breakdown['method_diversity'] = method_diversity_score * 100
        
        version_specificity = versioned_count / fingerprint_count if fingerprint_count > 0 else 0.0
        breakdown['version_specificity'] = version_specificity * 100
        
        # Calculate overall score
        overall_score = (
            (breakdown['fingerprint_confidence'] * 0.35) +
            (breakdown['cve_match_confidence'] * 0.30) +
            (breakdown['method_diversity'] * 0.20) +
            (breakdown['version_specificity'] * 0.15)
        )
        
        # Store confidence score in egg record metadata (use raw SQL to avoid async issues)
        # Note: discovery_metadata column may not exist, so we use bugsy_curation_metadata instead
        import json
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    # Check if bugsy_curation_metadata column exists
                    cursor.execute("""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = 'customer_eggs_eggrecords_general_models_eggrecord'
                        AND column_name = 'bugsy_curation_metadata'
                    """)
                    has_metadata_column = cursor.fetchone() is not None
                    
                    if has_metadata_column:
                        cursor.execute("""
                            SELECT bugsy_curation_metadata FROM customer_eggs_eggrecords_general_models_eggrecord
                            WHERE id = %s
                        """, [str(egg_record.id)])
                        row = cursor.fetchone()
                        metadata = json.loads(row[0]) if row and row[0] else {}
                        
                        metadata['oak_confidence_score'] = round(overall_score, 2)
                        metadata['oak_confidence_updated'] = timezone.now().isoformat()
                        
                        cursor.execute("""
                            UPDATE customer_eggs_eggrecords_general_models_eggrecord
                            SET bugsy_curation_metadata = %s
                            WHERE id = %s
                        """, [json.dumps(metadata), str(egg_record.id)])
        except Exception as e:
            self.logger.debug(f"Could not update metadata: {e}")
        
        return {
            'overall_score': round(overall_score, 2),
            'breakdown': breakdown,
            'grade': self._get_confidence_grade(overall_score)
        }
    
    
    def _get_confidence_grade(self, score: float) -> str:
        """Convert confidence score to letter grade."""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    
    def _create_vulnerability_profile(self, egg_record, curation_results: Dict) -> Dict[str, Any]:
        """
        Create a comprehensive vulnerability profile for the subdomain.
        Stores aggregated intelligence for quick access.
        """
        try:
            # Aggregate CVE data using raw SQL (no TargetVulnerabilityProfile model needed)
            from django.db import connections, transaction
            import json
            
            # Use transaction.atomic() to properly manage connections
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    # Get CVE counts
                    cursor.execute("""
                        SELECT COUNT(*) 
                        FROM enrichment_system_cvefingerprintmatch
                        WHERE egg_record_id = %s
                    """, [str(egg_record.id)])
                    total_cves = cursor.fetchone()[0] or 0
                    
                    # Calculate risk score (simplified - no severity breakdown in current schema)
                    risk_score = min(total_cves * 10, 100)  # Cap at 100
                    
                    # Get technology stack
                    cursor.execute("""
                        SELECT technology_name, technology_version
                        FROM enrichment_system_technologyfingerprint
                        WHERE egg_record_id = %s
                    """, [str(egg_record.id)])
                    tech_stack = [{'name': row[0], 'version': row[1]} for row in cursor.fetchall()]
                    
                    # Store profile data in egg_record's bugsy_curation_metadata field
                    profile_data = {
                        'total_cves': total_cves,
                        'risk_score': risk_score,
                        'confidence_score': curation_results.get('confidence_score', 0.0),
                        'technology_stack': tech_stack,
                        'fingerprints_count': len(tech_stack),
                        'scan_recommendations_count': curation_results.get('recommendations', 0),
                        'last_curated_at': timezone.now().isoformat(),
                        'curated_by': 'oak_target_curation_service'
                    }
                    
                    # Update egg_record with profile data
                    cursor.execute("""
                        UPDATE customer_eggs_eggrecords_general_models_eggrecord
                        SET bugsy_curation_metadata = %s,
                            bugsy_last_curated_at = NOW()
                        WHERE id = %s
                    """, [json.dumps(profile_data), str(egg_record.id)])
            
            return {
                'success': True,
                'profile_id': str(egg_record.id),  # Use egg_record ID as profile ID
                'created': True,
                'risk_score': risk_score
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create vulnerability profile: {e}")
            return {
                'success': False,
                'error': str(e)
            }


    def curate_nmap_scans_for_reconnaissance(self, scan_types: List[str] = None) -> Dict[str, Any]:
        """
        Curate nmap scans from Kaze, Kage, and Ryu reconnaissance agents.
        
        Processes nmap scans and enriches them with:
        - Technology fingerprinting
        - CVE correlation
        - Priority scoring
        - Scan quality assessment
        
        Args:
            scan_types: List of scan types to curate. Defaults to ['kaze_port_scan', 'kage_port_scan', 'ryu_port_scan']
        
        Returns:
            Dict with curation results
        """
        if scan_types is None:
            scan_types = ['kaze_port_scan', 'kage_port_scan', 'ryu_port_scan']
        
        try:
            from django.db import connections, transaction
            import json
            
            curated_count = 0
            enriched_count = 0
            
            # Use transaction.atomic() to properly manage database connections
            with transaction.atomic(using='eggrecords'):
                try:
                    conn = connections['eggrecords']
                except KeyError:
                    conn = connections['default']
                
                with conn.cursor() as cursor:
                    # Check if bugsy_curated_at column exists, add if not
                    try:
                        cursor.execute("""
                            SELECT column_name 
                            FROM information_schema.columns 
                            WHERE table_name = 'customer_eggs_eggrecords_general_models_nmap'
                            AND column_name = 'bugsy_curated_at'
                        """)
                        has_curation_column = cursor.fetchone() is not None
                        
                        if not has_curation_column:
                            cursor.execute("""
                                ALTER TABLE customer_eggs_eggrecords_general_models_nmap
                                ADD COLUMN IF NOT EXISTS bugsy_curated_at TIMESTAMP
                            """)
                            self.logger.info("Added bugsy_curated_at column to nmap table")
                    except Exception as e:
                        self.logger.debug(f"Could not check/add curation column: {e}")
                    
                    # Get uncured nmap scans from Kaze, Kage, and Ryu
                    # Prioritize by scan_priority_score if available
                    scan_types_placeholders = ','.join(['%s'] * len(scan_types))
                    
                    # Check if scan_priority_score column exists
                    cursor.execute("""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = 'customer_eggs_eggrecords_general_models_nmap'
                        AND column_name = 'scan_priority_score'
                    """)
                    has_priority_column = cursor.fetchone() is not None
                    
                    if has_priority_column:
                        # Order by scan priority score (highest first), then by creation date
                        cursor.execute(f"""
                            SELECT 
                                n.id,
                                n.record_id_id,
                                n.target,
                                n.scan_type,
                                n.open_ports,
                                n.service_name,
                                n.service_version,
                                n.scan_status,
                                n.scan_priority_score,
                                n.created_at,
                                e."subDomain",
                                e.domainname,
                                e.alive
                            FROM customer_eggs_eggrecords_general_models_nmap n
                            INNER JOIN customer_eggs_eggrecords_general_models_eggrecord e
                                ON e.id = n.record_id_id
                            WHERE n.scan_type IN ({scan_types_placeholders})
                            AND n.scan_status = 'completed'
                            AND e.alive = true
                            AND (n.bugsy_curated_at IS NULL OR n.bugsy_curated_at < NOW() - INTERVAL '30 days')
                            ORDER BY COALESCE(n.scan_priority_score, 0) DESC, n.created_at DESC
                            LIMIT 100
                        """, scan_types)
                    else:
                        # Fallback: order by creation date only
                        cursor.execute(f"""
                            SELECT 
                                n.id,
                                n.record_id_id,
                                n.target,
                                n.scan_type,
                                n.open_ports,
                                n.service_name,
                                n.service_version,
                                n.scan_status,
                                NULL as scan_priority_score,
                                n.created_at,
                                e."subDomain",
                                e.domainname,
                                e.alive
                            FROM customer_eggs_eggrecords_general_models_nmap n
                            INNER JOIN customer_eggs_eggrecords_general_models_eggrecord e
                                ON e.id = n.record_id_id
                            WHERE n.scan_type IN ({scan_types_placeholders})
                            AND n.scan_status = 'completed'
                            AND e.alive = true
                            AND (n.bugsy_curated_at IS NULL OR n.bugsy_curated_at < NOW() - INTERVAL '30 days')
                            ORDER BY n.created_at DESC
                            LIMIT 100
                        """, scan_types)
                    
                    scans = []
                    columns = [col[0] for col in cursor.description]
                    for row in cursor.fetchall():
                        scan_dict = dict(zip(columns, row))
                        # Parse open_ports JSON if it's a string
                        if isinstance(scan_dict.get('open_ports'), str):
                            try:
                                scan_dict['open_ports'] = json.loads(scan_dict['open_ports'])
                            except:
                                scan_dict['open_ports'] = []
                        scans.append(scan_dict)
                    
                    # Process each scan
                    for scan in scans:
                        try:
                                # Get the egg_record for curation
                                egg_record_id = scan['record_id_id']
                                
                                # Use existing curation workflow to enrich the target
                                # This will trigger fingerprinting, CVE matching, etc.
                                # Always use raw SQL to avoid async context issues
                                cursor.execute("""
                                    SELECT id, "subDomain", domainname, alive
                                    FROM customer_eggs_eggrecords_general_models_eggrecord
                                    WHERE id = %s
                                """, [egg_record_id])
                                row = cursor.fetchone()
                                if not row:
                                    continue
                                # Create minimal object
                                class SimpleEggRecord:
                                    def __init__(self, id, subDomain, domainname, alive):
                                        self.id = id
                                        self.subDomain = subDomain
                                        self.domainname = domainname
                                        self.alive = alive
                                        self.discovery_metadata = {}
                                
                                egg_record = SimpleEggRecord(row[0], row[1], row[2], row[3])
                                
                                # Queue for full curation (this will process nmap data via existing signals)
                                result = self.queue_subdomain_for_curation(
                                    egg_record=egg_record,
                                    discovery_source=f"{scan['scan_type']}_curation",
                                    priority='normal'
                                )
                                
                                if result.get('success'):
                                    curated_count += 1
                                    
                                    # Mark scan as curated
                                    try:
                                        cursor.execute("""
                                            UPDATE customer_eggs_eggrecords_general_models_nmap
                                            SET bugsy_curated_at = NOW()
                                            WHERE id = %s
                                        """, [scan['id']])
                                    except Exception as e:
                                        self.logger.debug(f"Could not update bugsy_curated_at: {e}")
                                    
                                    # Extract technology fingerprints from nmap data
                                    if scan.get('service_name'):
                                        enriched_count += self._enrich_scan_with_fingerprints(
                                            cursor, scan, egg_record_id
                                        )
                        
                        except Exception as e:
                            self.logger.error(f"Error curating scan {scan.get('id')}: {e}", exc_info=True)
                        
                        # Django commits automatically when transaction.atomic() block exits successfully
                        
            return {
                'success': True,
                'scans_processed': len(scans),
                'scans_curated': curated_count,
                'scans_enriched': enriched_count,
                'scan_types': scan_types
            }
                
        except Exception as e:
            self.logger.error(f"Error in nmap scan curation: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }
    
    def _enrich_scan_with_fingerprints(self, cursor, scan: Dict, egg_record_id: str) -> int:
        """
        Enrich nmap scan with technology fingerprints.
        Uses all fields from port_info dicts: port, protocol, service, version, state, banner
        
        Returns number of fingerprints created.
        Uses raw SQL to avoid ORM conflicts.
        """
        try:
            import uuid as uuid_lib
            import json
            from django.db import connections
            
            fingerprints_created = 0
            service_name = scan.get('service_name', '')
            service_version = scan.get('service_version', '')
            open_ports = scan.get('open_ports', [])
            
            # Use eggrecords database connection
            try:
                db = connections['eggrecords']
            except KeyError:
                db = connections['default']
            
            # Create fingerprint from service_name (scan-level metadata)
            if service_name:
                try:
                    with db.cursor() as fp_cursor:
                        # Check if fingerprint already exists
                        fp_cursor.execute("""
                            SELECT id FROM enrichment_system_technologyfingerprint
                            WHERE egg_record_id = %s 
                            AND technology_name = %s 
                            AND technology_version = %s
                            AND detection_method = 'nmap'
                            LIMIT 1
                        """, [egg_record_id, service_name, service_version or ''])
                        existing = fp_cursor.fetchone()
                        
                        if not existing:
                            # Create new fingerprint
                            fingerprint_id = str(uuid_lib.uuid4())
                            fp_cursor.execute("""
                                INSERT INTO enrichment_system_technologyfingerprint (
                                    id, egg_record_id, technology_name, technology_version,
                                    detection_method, confidence_score, technology_category,
                                    raw_detection_data, created_at, updated_at
                                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                            """, [
                                fingerprint_id,
                                egg_record_id,
                                service_name,
                                service_version or '',
                                'nmap',
                                0.85,
                                self._categorize_service(service_name),
                                json.dumps({
                                    'scan_type': scan.get('scan_type'),
                                    'target': scan.get('target'),
                                    'port': scan.get('port', ''),
                                    'protocol': scan.get('protocol', 'tcp'),
                                })
                            ])
                            fingerprints_created += 1
                except Exception as e:
                    self.logger.debug(f"Could not create fingerprint: {e}")
            
            # Create fingerprints from open_ports - using ALL key-value pairs
            if isinstance(open_ports, list):
                for port_info in open_ports:
                    if not isinstance(port_info, dict):
                        continue
                    
                    # Extract all fields from port_info dict
                    port = port_info.get('port', 0)
                    protocol = port_info.get('protocol', 'tcp')
                    port_service = port_info.get('service', '').lower()
                    port_version = port_info.get('version', '')
                    state = port_info.get('state', 'open')
                    banner = port_info.get('banner', '')
                    
                    # CRITICAL: Only process open ports
                    if state != 'open':
                        self.logger.debug(f"Skipping port {port} (state: {state})")
                        continue
                    
                    # Extract service/version from banner if fields are empty
                    if not port_service and banner:
                        port_service = self._extract_service_from_banner(banner) or port_service
                    if not port_version and banner:
                        port_version = self._extract_version_from_banner(banner) or port_version
                    
                    # Skip if no service identified
                    if not port_service:
                        continue
                    
                    # Skip if this service already processed from scan metadata
                    if port_service == service_name.lower() and port_version == service_version:
                        continue
                    
                    try:
                        with db.cursor() as fp_cursor:
                            # Check if fingerprint already exists
                            fp_cursor.execute("""
                                SELECT id FROM enrichment_system_technologyfingerprint
                                WHERE egg_record_id = %s 
                                AND technology_name = %s 
                                AND technology_version = %s
                                AND detection_method = 'nmap'
                                LIMIT 1
                            """, [egg_record_id, port_service, port_version or ''])
                            existing = fp_cursor.fetchone()
                            
                            if not existing:
                                # Create new fingerprint with all port data
                                fingerprint_id = str(uuid_lib.uuid4())
                                fp_cursor.execute("""
                                    INSERT INTO enrichment_system_technologyfingerprint (
                                        id, egg_record_id, technology_name, technology_version,
                                        detection_method, confidence_score, technology_category,
                                        raw_detection_data, created_at, updated_at
                                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                                """, [
                                    fingerprint_id,
                                    egg_record_id,
                                    port_service,
                                    port_version or '',
                                    'nmap',
                                    0.80,
                                    self._categorize_service(port_service),
                                    json.dumps({
                                        'scan_type': scan.get('scan_type'),
                                        'port': port,
                                        'protocol': protocol,
                                        'state': state,
                                        'banner': banner,
                                        'extracted_from': 'port_info'
                                    })
                                ])
                                fingerprints_created += 1
                                self.logger.debug(
                                    f"Created fingerprint from port_info: {port_service} "
                                    f"v{port_version} on {protocol} port {port}"
                                )
                    except Exception as e:
                        self.logger.debug(f"Could not create fingerprint from port: {e}")
            
            return fingerprints_created
            
        except Exception as e:
            self.logger.error(f"Error enriching scan with fingerprints: {e}")
            return 0
    
    def _extract_service_from_banner(self, banner: str) -> str:
        """Extract service name from banner string."""
        if not banner:
            return ''
        
        banner_lower = banner.lower()
        service_patterns = {
            'apache': ['apache', 'httpd', 'apache/'],
            'nginx': ['nginx', 'nginx/'],
            'iis': ['iis', 'microsoft-iis', 'microsoft httpapi'],
            'ssh': ['ssh', 'openssh', 'ssh-2.0', 'ssh-1.99'],
            'ftp': ['ftp', 'vsftpd', 'proftpd', 'filezilla'],
            'mysql': ['mysql', 'mariadb'],
            'postgresql': ['postgresql', 'postgres', 'pg'],
            'mongodb': ['mongodb'],
            'redis': ['redis'],
            'tomcat': ['tomcat', 'apache-coyote'],
            'jetty': ['jetty'],
            'node': ['node.js', 'express'],
            'python': ['python', 'django', 'flask', 'tornado'],
            'php': ['php', 'php/'],
            'ruby': ['ruby', 'rails', 'unicorn'],
            'java': ['java', 'jboss', 'weblogic', 'websphere'],
            'iis': ['iis', 'microsoft-iis'],
            'lighttpd': ['lighttpd'],
            'caddy': ['caddy'],
        }
        
        for service, patterns in service_patterns.items():
            if any(pattern in banner_lower for pattern in patterns):
                return service
        
        return ''
    
    def _extract_version_from_banner(self, banner: str) -> str:
        """Extract version number from banner string."""
        if not banner:
            return ''
        
        import re
        version_patterns = [
            r'/(\d+\.\d+(?:\.\d+)?)',  # Apache/2.4.41
            r'(\d+\.\d+(?:\.\d+)?)',    # Generic version
            r'_(\d+\.\d+)',              # OpenSSH_8.2
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        
        return ''
    
    def _categorize_service(self, service_name: str) -> str:
        """Categorize service for technology fingerprint."""
        if not service_name:
            return 'service'
        
        service_lower = service_name.lower()
        
        if any(x in service_lower for x in ['apache', 'nginx', 'iis', 'httpd', 'lighttpd']):
            return 'web_server'
        elif any(x in service_lower for x in ['mysql', 'postgres', 'mongodb', 'redis', 'mariadb', 'mssql', 'oracle']):
            return 'database'
        elif any(x in service_lower for x in ['ssh', 'ftp', 'telnet', 'rdp', 'vnc']):
            return 'remote_access'
        elif any(x in service_lower for x in ['tomcat', 'jetty', 'jboss', 'weblogic', 'glassfish']):
            return 'application_server'
        elif any(x in service_lower for x in ['wordpress', 'drupal', 'joomla', 'magento']):
            return 'cms'
        else:
            return 'service'

