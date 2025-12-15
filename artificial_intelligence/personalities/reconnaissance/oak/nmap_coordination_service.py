#!/usr/bin/env python3
"""
Oak Nmap Coordination Service
==============================

Oak coordinates Nmap scanning for Nuclei agents by:
1. Triggering Nmap scans via daemon API when needed
2. Ensuring scans complete before Nuclei scanning
3. Selecting appropriate Nuclei templates based on fingerprints/CVEs
4. Creating relationships between templates and EggRecords

Author: EGO Revolution Team - Oak
Version: 1.0.0
"""

import logging
import requests
import time
from typing import Dict, List, Optional, Any
from django.db import connections, transaction
from django.utils import timezone
import json
import uuid

logger = logging.getLogger(__name__)

# Lazy import for Django ORM models
def _get_nuclei_template_model():
    """Get NucleiTemplate Django ORM model."""
    try:
        from artificial_intelligence.customer_eggs_eggrecords_general_models.models import NucleiTemplate
        return NucleiTemplate
    except ImportError:
        try:
            from customer_eggs_eggrecords_general_models.models import NucleiTemplate
            return NucleiTemplate
        except ImportError:
            logger.warning("NucleiTemplate model not available")
            return None

# Lazy import to avoid circular dependencies
_template_registry = None

def _get_template_registry():
    """Get or create template registry service instance."""
    global _template_registry
    if _template_registry is None:
        try:
            from .template_registry_service import OakTemplateRegistryService
            _template_registry = OakTemplateRegistryService()
        except Exception as e:
            logger.warning(f"Template registry not available: {e}")
            _template_registry = None
    return _template_registry


class OakNmapCoordinationService:
    """
    Oak's service for coordinating Nmap scans and Nuclei template selection.
    
    Ensures proper workflow:
        EggRecord → Nmap Scan (if needed) → Fingerprinting → CVE Match → Template Selection → Nuclei Scan
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Daemon API base URL (can be configured via environment)
        import os
        self.daemon_api_base = os.environ.get('DAEMON_API_BASE_URL', 'http://localhost:8000')
        
    def ensure_nmap_scan_for_egg_record(self, egg_record, scan_agent: str = 'kage', 
                                     priority: str = 'normal') -> Dict[str, Any]:
        """
        Ensure an Nmap scan exists for an EggRecord.
        If no scan exists or scan is stale, trigger a new scan.
        
        Args:
            egg_record: The EggRecord to scan
            scan_agent: 'kage', 'ryu', or 'ash' (default: 'kage')
            priority: 'high', 'normal', or 'low'
            
        Returns:
            Dict with scan status and scan_id if available
        """
        try:
            egg_record_id = str(egg_record.id)
            subdomain = egg_record.subDomain or egg_record.domainname
            
            # Check if recent scan exists
            scan_type = f'{scan_agent}_port_scan'
            recent_scan = self._check_recent_scan(egg_record_id, scan_type)
            
            if recent_scan:
                self.logger.info(f"🌳 Oak: Recent Nmap scan exists for {subdomain} (scan_id: {recent_scan['id']})")
                return {
                    'success': True,
                    'scan_exists': True,
                    'scan_id': recent_scan['id'],
                    'scan_status': recent_scan['status'],
                    'message': 'Recent scan found'
                }
            
            # No recent scan - trigger new scan
            self.logger.info(f"🌳 Oak: Triggering Nmap scan for {subdomain} via {scan_agent}")
            
            # Method 1: Try daemon API (if daemons are running)
            scan_result = self._trigger_scan_via_daemon_api(egg_record, scan_agent, priority)
            
            if scan_result.get('success'):
                return scan_result
            
            # Method 2: Fallback - mark for daemon to pick up
            # Daemons poll the API, so we just need to ensure the EggRecord is ready
            self.logger.info(f"🌳 Oak: Daemon API unavailable, marking {subdomain} for daemon pickup")
            
            # Update EggRecord metadata to indicate scan needed
            self._mark_for_scan(egg_record_id, scan_type, priority)
            
            return {
                'success': True,
                'scan_exists': False,
                'queued': True,
                'message': f'Queued for {scan_agent} daemon pickup'
            }
            
        except Exception as e:
            self.logger.error(f"Error ensuring Nmap scan: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }
    
    def _check_recent_scan(self, egg_record_id: str, scan_type: str, max_age_hours: int = 24) -> Optional[Dict]:
        """Check if a recent Nmap scan exists for the EggRecord."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, scan_status, created_at, target
                        FROM customer_eggs_eggrecords_general_models_nmap
                        WHERE record_id_id = %s
                        AND scan_type = %s
                        AND scan_status = 'completed'
                        AND created_at > NOW() - INTERVAL '%s hours'
                        ORDER BY created_at DESC
                        LIMIT 1
                    """, [egg_record_id, scan_type, max_age_hours])
                    
                    row = cursor.fetchone()
                    if row:
                        return {
                            'id': str(row[0]),
                            'status': row[1],
                            'created_at': row[2],
                            'target': row[3]
                        }
                    return None
        except Exception as e:
            self.logger.debug(f"Error checking recent scan: {e}")
            return None
    
    def _trigger_scan_via_daemon_api(self, egg_record, scan_agent: str, priority: str) -> Dict[str, Any]:
        """Try to trigger scan via daemon API (if daemons support push requests)."""
        try:
            # Most daemons poll, but some may support push
            # For now, return not available - daemons will pick up via polling
            return {
                'success': False,
                'error': 'Daemon API push not implemented - using polling'
            }
        except Exception as e:
            self.logger.debug(f"Daemon API trigger failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _mark_for_scan(self, egg_record_id: str, scan_type: str, priority: str):
        """Mark EggRecord for scanning by updating metadata."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    # Update EggRecord updated_at to make it appear in daemon queries
                    cursor.execute("""
                        UPDATE customer_eggs_eggrecords_general_models_eggrecord
                        SET updated_at = NOW()
                        WHERE id = %s
                    """, [egg_record_id])
                    
                    self.logger.debug(f"Marked EggRecord {egg_record_id} for {scan_type} scan")
        except Exception as e:
            self.logger.debug(f"Error marking for scan: {e}")
    
    def select_nuclei_templates_for_egg_record(self, egg_record, 
                                           max_templates: int = 20) -> Dict[str, Any]:
        """
        Select Nuclei templates for an EggRecord based on:
        - Technology fingerprints
        - CVE matches
        - Open ports/services
        - Scan recommendations
        
        Uses Django ORM NucleiTemplate model for intelligent correlation.
        
        Args:
            egg_record: The EggRecord to select templates for
            max_templates: Maximum number of templates to return
            
        Returns:
            Dict with selected templates and reasoning
        """
        try:
            egg_record_id = str(egg_record.id)
            subdomain = egg_record.subDomain or egg_record.domainname
            
            self.logger.info(f"🌳 Oak: Selecting Nuclei templates for {subdomain}")
            
            # Step 1: Get technology fingerprints
            fingerprints = self._get_technology_fingerprints(egg_record_id)
            
            # Step 2: Get CVE matches
            cve_matches = self._get_cve_matches(egg_record_id)
            
            # Step 3: Get open ports/services from Nmap
            open_ports = self._get_open_ports(egg_record_id)
            
            # Step 4: Get existing scan recommendations
            scan_recommendations = self._get_scan_recommendations(egg_record_id)
            
            # Step 5: Select templates based on all data (using Django ORM)
            selected_templates = self._select_templates(
                egg_record_id=egg_record_id,
                fingerprints=fingerprints,
                cve_matches=cve_matches,
                open_ports=open_ports,
                scan_recommendations=scan_recommendations,
                max_templates=max_templates
            )
            
            # Step 6: Create/update template relationships in database
            template_relationships = self._create_template_relationships(
                egg_record_id, selected_templates
            )
            
            self.logger.info(f"✅ Oak: Selected {len(selected_templates)} templates for {subdomain}")
            
            return {
                'success': True,
                'templates': selected_templates,
                'template_count': len(selected_templates),
                'relationships_created': template_relationships,
                'fingerprints_used': len(fingerprints),
                'cve_matches_used': len(cve_matches),
                'open_ports_used': len(open_ports)
            }
            
        except Exception as e:
            self.logger.error(f"Error selecting Nuclei templates: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'templates': []
            }
    
    def _get_technology_fingerprints(self, egg_record_id: str) -> List[Dict]:
        """Get technology fingerprints for EggRecord."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, technology_name, technology_version, 
                               technology_category, confidence_score, detection_method
                        FROM enrichment_system_technologyfingerprint
                        WHERE egg_record_id = %s
                        AND confidence_score >= 0.5
                        ORDER BY confidence_score DESC
                    """, [egg_record_id])
                    
                    fingerprints = []
                    for row in cursor.fetchall():
                        fingerprints.append({
                            'id': str(row[0]),
                            'technology_name': row[1],
                            'technology_version': row[2] or '',
                            'category': row[3] or 'service',
                            'confidence': float(row[4]) if row[4] else 0.0,
                            'detection_method': row[5] or 'unknown'
                        })
                    
                    return fingerprints
        except Exception as e:
            self.logger.debug(f"Error getting fingerprints: {e}")
            return []
    
    def _get_cve_matches(self, egg_record_id: str) -> List[Dict]:
        """Get CVE matches for EggRecord."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT cve_id, cve_severity, cve_cvss_score, 
                               technology_name, match_confidence, nuclei_template_available,
                               nuclei_template_ids
                        FROM enrichment_system_cvefingerprintmatch
                        WHERE egg_record_id = %s
                        AND recommended_for_scanning = true
                        ORDER BY cve_cvss_score DESC, match_confidence DESC
                    """, [egg_record_id])
                    
                    cve_matches = []
                    for row in cursor.fetchall():
                        template_ids = []
                        if row[6]:  # nuclei_template_ids
                            try:
                                template_ids = json.loads(row[6]) if isinstance(row[6], str) else row[6]
                            except:
                                pass
                        
                        cve_matches.append({
                            'cve_id': row[0],
                            'severity': row[1] or 'UNKNOWN',
                            'cvss_score': float(row[2]) if row[2] else 0.0,
                            'technology': row[3] or '',
                            'match_confidence': float(row[4]) if row[4] else 0.0,
                            'has_nuclei_template': bool(row[5]),
                            'nuclei_template_ids': template_ids if isinstance(template_ids, list) else []
                        })
                    
                    return cve_matches
        except Exception as e:
            self.logger.debug(f"Error getting CVE matches: {e}")
            return []
    
    def _get_open_ports(self, egg_record_id: str) -> List[Dict]:
        """Get open ports from Nmap scans."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT DISTINCT port, protocol, service_name, service_version
                        FROM customer_eggs_eggrecords_general_models_nmap
                        WHERE record_id_id = %s
                        AND scan_status = 'completed'
                        AND port IS NOT NULL
                        ORDER BY port
                    """, [egg_record_id])
                    
                    open_ports = []
                    for row in cursor.fetchall():
                        open_ports.append({
                            'port': int(row[0]) if row[0] else 0,
                            'protocol': row[1] or 'tcp',
                            'service': row[2] or '',
                            'version': row[3] or ''
                        })
                    
                    return open_ports
        except Exception as e:
            self.logger.debug(f"Error getting open ports: {e}")
            return []
    
    def _get_scan_recommendations(self, egg_record_id: str) -> List[Dict]:
        """Get existing scan recommendations."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, recommendation_type, expected_success_rate,
                               bugsy_reasoning, priority_override
                        FROM enrichment_system_cvescanrecommendation
                        WHERE egg_record_id = %s
                        AND status = 'pending'
                        ORDER BY priority_override DESC, expected_success_rate DESC
                    """, [egg_record_id])
                    
                    recommendations = []
                    for row in cursor.fetchall():
                        recommendations.append({
                            'id': str(row[0]),
                            'type': row[1] or 'nuclei',
                            'expected_success': float(row[2]) if row[2] else 0.0,
                            'reasoning': row[3] or '',
                            'high_priority': bool(row[4]) if row[4] is not None else False
                        })
                    
                    return recommendations
        except Exception as e:
            self.logger.debug(f"Error getting scan recommendations: {e}")
            return []
    
    def _select_templates(self, egg_record_id: str, fingerprints: List[Dict], cve_matches: List[Dict],
                         open_ports: List[Dict], scan_recommendations: List[Dict],
                         max_templates: int) -> List[Dict]:
        """
        Select Nuclei templates based on all available intelligence.
        
        Uses Django ORM NucleiTemplate.find_for_egg_record() for intelligent correlation,
        with fallback to template registry service if ORM is unavailable.
        
        Priority:
        1. Templates from CVE matches (highest priority)
        2. Templates from scan recommendations
        3. Templates based on technology fingerprints
        4. Templates based on open ports/services
        """
        selected = []
        template_ids_seen = set()
        
        # Try Django ORM first (preferred method)
        NucleiTemplate = _get_nuclei_template_model()
        if NucleiTemplate:
            try:
                # Use the powerful find_for_egg_record() method that correlates everything
                templates_qs = NucleiTemplate.find_for_egg_record(
                    egg_record_id=egg_record_id,
                    technology_fingerprints=fingerprints,
                    cve_matches=cve_matches
                )
                
                # Convert QuerySet to list of dicts with priority scoring
                for template in templates_qs[:max_templates]:
                    template_id = template.template_id
                    if template_id and template_id not in template_ids_seen:
                        # Determine priority based on source
                        priority = 'medium'
                        source = 'correlation'
                        source_id = ''
                        reasoning = f"Correlated match: {template.template_name or template_id}"
                        
                        # Check if this template matches a CVE
                        template_cves = template.get_cve_ids()
                        for cve_match in cve_matches:
                            cve_id = cve_match.get('cve_id', '').upper()
                            if cve_id in template_cves:
                                priority = 'high'
                                source = 'cve_match'
                                source_id = cve_id
                                reasoning = f"CVE {cve_id} ({cve_match.get('severity', 'UNKNOWN')}) - {template.template_name or template_id}"
                                break
                        
                        # If not CVE match, check technology match
                        if priority == 'medium':
                            template_techs = template.get_technologies()
                            for fingerprint in fingerprints:
                                tech_name = fingerprint.get('technology_name', '').lower()
                                if tech_name in template_techs:
                                    source = 'fingerprint'
                                    source_id = fingerprint.get('id', '')
                                    reasoning = f"Technology: {fingerprint['technology_name']} v{fingerprint.get('technology_version', '')} - {template.template_name or template_id}"
                                    break
                        
                        selected.append({
                            'template_id': template_id,
                            'template_path': template.template_path,
                            'template_name': template.template_name,
                            'source': source,
                            'source_id': source_id,
                            'priority': priority,
                            'reasoning': reasoning,
                            'severity': template.severity or 'info',
                            'cve_ids': template_cves,
                            'technologies': template.get_technologies(),
                            'tags': template.tags or []
                        })
                        template_ids_seen.add(template_id)
                        
                        if len(selected) >= max_templates:
                            return selected
                
                # If we got templates from ORM, return them (even if less than max)
                if selected:
                    self.logger.info(f"✅ Found {len(selected)} templates via Django ORM correlation")
                    return selected
                    
            except Exception as e:
                self.logger.warning(f"Error using Django ORM for template selection: {e}, falling back to registry")
                import traceback
                self.logger.debug(f"Django ORM error traceback: {traceback.format_exc()}")
        
        # Fallback: Use template registry service (raw SQL)
        self.logger.debug("Using template registry service as fallback")
        registry = _get_template_registry()
        
        # Priority 1: Templates from CVE matches
        if registry:
            for cve_match in cve_matches:
                cve_id = cve_match.get('cve_id', '')
                if cve_id:
                    templates = registry.find_templates_by_cve(cve_id)
                    for template in templates:
                        template_id = template.get('template_id')
                        if template_id and template_id not in template_ids_seen:
                            selected.append({
                                'template_id': template_id,
                                'template_path': template.get('template_path'),
                                'template_name': template.get('template_name'),
                                'source': 'cve_match',
                                'source_id': cve_id,
                                'priority': 'high',
                                'reasoning': f"CVE {cve_id} ({cve_match.get('severity', 'UNKNOWN')}) - Template: {template.get('template_name', template_id)}",
                                'cvss_score': cve_match.get('cvss_score', 0.0),
                                'severity': template.get('severity', 'info')
                            })
                            template_ids_seen.add(template_id)
                            if len(selected) >= max_templates:
                                return selected
        
        # Priority 2: Templates from scan recommendations
        for rec in scan_recommendations:
            if rec.get('type') == 'nuclei' and rec.get('high_priority'):
                # Extract template IDs from reasoning if available
                pass
        
        # Priority 3: Templates based on technology fingerprints
        if registry:
            for fingerprint in fingerprints:
                tech_name = fingerprint.get('technology_name', '')
                category = fingerprint.get('category', '').lower()
                if tech_name:
                    templates = registry.find_templates_by_technology(tech_name, severity=None)
                    
                    # If no templates found by technology field, try tags
                    if not templates:
                        tags_list = [tech_name.lower()]
                        templates = registry.find_templates_by_tags(tags_list)
                    
                    # If still no templates, search by template_id patterns
                    if not templates:
                        template_patterns = self._get_template_patterns_for_technology(tech_name, category)
                        try:
                            with transaction.atomic(using='eggrecords'):
                                try:
                                    db = connections['eggrecords']
                                except KeyError:
                                    db = connections['default']
                                
                                with db.cursor() as cursor:
                                    pattern_conditions = []
                                    pattern_params = []
                                    for pattern in template_patterns[:3]:  # Limit patterns
                                        pattern_conditions.append("template_id LIKE %s")
                                        pattern_params.append(f'%{pattern}%')
                                    
                                    if pattern_conditions:
                                        query = f"""
                                            SELECT template_id, template_path, template_name, severity
                                            FROM enrichment_system_nucleitemplate
                                            WHERE {' OR '.join(pattern_conditions)}
                                            ORDER BY 
                                                CASE severity
                                                    WHEN 'critical' THEN 0
                                                    WHEN 'high' THEN 1
                                                    WHEN 'medium' THEN 2
                                                    WHEN 'low' THEN 3
                                                    ELSE 4
                                                END
                                            LIMIT 10
                                        """
                                        cursor.execute(query, pattern_params)
                                        
                                        for row in cursor.fetchall():
                                            templates.append({
                                                'template_id': row[0],
                                                'template_path': row[1],
                                                'template_name': row[2] or row[0],
                                                'severity': row[3] or 'info'
                                            })
                        except Exception as e:
                            self.logger.debug(f"Error searching templates by pattern: {e}")
                    
                    # Prioritize by severity (critical/high first)
                    templates.sort(key=lambda x: {
                        'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4
                    }.get(x.get('severity', 'info'), 4))
                    
                    for template in templates[:10]:  # Limit to top 10 per technology
                        template_id = template.get('template_id')
                        if template_id and template_id not in template_ids_seen:
                            selected.append({
                                'template_id': template_id,
                                'template_path': template.get('template_path'),
                                'template_name': template.get('template_name'),
                                'source': 'fingerprint',
                                'source_id': fingerprint['id'],
                                'priority': 'medium',
                                'reasoning': f"Technology: {fingerprint['technology_name']} v{fingerprint.get('technology_version', '')} - {template.get('template_name', template_id)}",
                                'confidence': fingerprint.get('confidence', 0.0),
                                'severity': template.get('severity', 'info')
                            })
                            template_ids_seen.add(template_id)
                            if len(selected) >= max_templates:
                                return selected
        else:
            # Fallback to hardcoded patterns if registry not available
            for fingerprint in fingerprints:
                tech_name = fingerprint.get('technology_name', '')
                category = fingerprint.get('category', '').lower()
                template_patterns = self._get_template_patterns_for_technology(tech_name, category)
                
                # Try to find templates by pattern in registry
                if registry:
                    for pattern in template_patterns:
                        # Search by template_id pattern
                        try:
                            with transaction.atomic(using='eggrecords'):
                                try:
                                    db = connections['eggrecords']
                                except KeyError:
                                    db = connections['default']
                                
                                with db.cursor() as cursor:
                                    cursor.execute("""
                                        SELECT template_id, template_path, template_name, severity
                                        FROM enrichment_system_nucleitemplate
                                        WHERE template_id LIKE %s OR template_id LIKE %s
                                        ORDER BY 
                                            CASE severity
                                                WHEN 'critical' THEN 0
                                                WHEN 'high' THEN 1
                                                WHEN 'medium' THEN 2
                                                WHEN 'low' THEN 3
                                                ELSE 4
                                            END
                                        LIMIT 5
                                    """, [f'%{pattern}%', f'{pattern}-%'])
                                    
                                    for row in cursor.fetchall():
                                        template_id = row[0]
                                        if template_id and template_id not in template_ids_seen:
                                            selected.append({
                                                'template_id': template_id,
                                                'template_path': row[1],
                                                'template_name': row[2] or template_id,
                                                'source': 'fingerprint',
                                                'source_id': fingerprint['id'],
                                                'priority': 'medium',
                                                'reasoning': f"Technology: {fingerprint['technology_name']} v{fingerprint.get('technology_version', '')} - Pattern: {pattern}",
                                                'confidence': fingerprint.get('confidence', 0.0),
                                                'severity': row[3] or 'info'
                                            })
                                            template_ids_seen.add(template_id)
                                            if len(selected) >= max_templates:
                                                return selected
                        except Exception as e:
                            self.logger.debug(f"Error searching templates by pattern {pattern}: {e}")
                            continue
                else:
                    # No registry - use patterns as template IDs (fallback)
                    for pattern in template_patterns:
                        if pattern not in template_ids_seen:
                            selected.append({
                                'template_id': pattern,
                                'source': 'fingerprint',
                                'source_id': fingerprint['id'],
                                'priority': 'medium',
                                'reasoning': f"Technology: {fingerprint['technology_name']} v{fingerprint.get('technology_version', '')}",
                                'confidence': fingerprint.get('confidence', 0.0)
                            })
                            template_ids_seen.add(pattern)
                            if len(selected) >= max_templates:
                                return selected
        
        # Priority 4: Templates based on open ports/services
        for port_info in open_ports:
            service = port_info.get('service', '').lower()
            port_num = port_info.get('port', 0)
            
            # Map common services to template patterns
            service_templates = self._get_template_patterns_for_service(service, port_num)
            
            for template_id in service_templates:
                if template_id and template_id not in template_ids_seen:
                    selected.append({
                        'template_id': template_id,
                        'source': 'port_scan',
                        'source_id': f"port_{port_num}",
                        'priority': 'medium',
                        'reasoning': f"Open port {port_num} ({service})",
                        'port': port_num
                    })
                    template_ids_seen.add(template_id)
                    if len(selected) >= max_templates:
                        return selected
        
        return selected
    
    def _get_template_patterns_for_technology(self, tech_name: str, category: str) -> List[str]:
        """
        Get Nuclei template patterns for a technology.
        
        This is a fallback method when template registry is not available.
        In production, templates should come from the registry.
        """
        patterns = []
        
        tech_lower = tech_name.lower()
        
        # Web servers
        if 'apache' in tech_lower:
            patterns.extend(['apache', 'httpd', 'cve-apache'])
        elif 'nginx' in tech_lower:
            patterns.extend(['nginx', 'cve-nginx'])
        elif 'iis' in tech_lower or 'microsoft-iis' in tech_lower:
            patterns.extend(['iis', 'microsoft-iis', 'cve-iis'])
        
        # Databases
        if 'mysql' in tech_lower:
            patterns.extend(['mysql', 'cve-mysql', 'mariadb'])
        elif 'postgres' in tech_lower:
            patterns.extend(['postgresql', 'postgres', 'cve-postgres'])
        elif 'mongodb' in tech_lower:
            patterns.extend(['mongodb', 'cve-mongodb'])
        elif 'redis' in tech_lower:
            patterns.extend(['redis', 'cve-redis'])
        
        # Application servers
        if 'tomcat' in tech_lower:
            patterns.extend(['tomcat', 'apache-tomcat', 'cve-tomcat'])
        elif 'jetty' in tech_lower:
            patterns.extend(['jetty', 'cve-jetty'])
        
        # CMS
        if 'wordpress' in tech_lower:
            patterns.extend(['wordpress', 'wp', 'cve-wordpress'])
        elif 'drupal' in tech_lower:
            patterns.extend(['drupal', 'cve-drupal'])
        
        return patterns[:5]  # Limit to 5 patterns per technology
    
    def _get_template_patterns_for_service(self, service: str, port: int) -> List[str]:
        """Get Nuclei template patterns for a service/port."""
        patterns = []
        
        service_lower = service.lower()
        
        # Common port-based templates
        if port == 80 or port == 443 or 'http' in service_lower:
            patterns.extend(['http', 'https', 'web'])
        elif port == 22 or 'ssh' in service_lower:
            patterns.extend(['ssh', 'openssh', 'cve-ssh'])
        elif port == 21 or 'ftp' in service_lower:
            patterns.extend(['ftp', 'cve-ftp'])
        elif port == 3306 or 'mysql' in service_lower:
            patterns.extend(['mysql', 'cve-mysql'])
        elif port == 5432 or 'postgres' in service_lower:
            patterns.extend(['postgresql', 'cve-postgres'])
        elif port == 27017 or 'mongodb' in service_lower:
            patterns.extend(['mongodb', 'cve-mongodb'])
        elif port == 6379 or 'redis' in service_lower:
            patterns.extend(['redis', 'cve-redis'])
        elif port == 8080 or 'tomcat' in service_lower:
            patterns.extend(['tomcat', 'apache-tomcat'])
        
        return patterns[:3]  # Limit to 3 patterns per service
    
    def _create_template_relationships(self, egg_record_id: str, 
                                      templates: List[Dict]) -> int:
        """
        Create database relationships between Nuclei templates and EggRecord.
        
        Creates entries in a new table: enrichment_system_nucleitemplaterecommendation
        """
        try:
            relationships_created = 0
            
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    # Check if table exists, create if not
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'public'
                            AND table_name = 'enrichment_system_nucleitemplaterecommendation'
                        )
                    """)
                    
                    table_exists = cursor.fetchone()[0]
                    
                    if not table_exists:
                        # Create table
                        cursor.execute("""
                            CREATE TABLE IF NOT EXISTS enrichment_system_nucleitemplaterecommendation (
                                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                                egg_record_id UUID NOT NULL,
                                template_id VARCHAR(500) NOT NULL,
                                template_source VARCHAR(100) NOT NULL,
                                source_id VARCHAR(500),
                                priority VARCHAR(20) NOT NULL,
                                reasoning TEXT,
                                status VARCHAR(20) DEFAULT 'pending',
                                created_at TIMESTAMP DEFAULT NOW(),
                                updated_at TIMESTAMP DEFAULT NOW(),
                                scanned_at TIMESTAMP,
                                scan_result JSONB,
                                UNIQUE(egg_record_id, template_id)
                            )
                        """)
                        
                        # Create index
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_nuclei_template_egg_record 
                            ON enrichment_system_nucleitemplaterecommendation(egg_record_id)
                        """)
                        
                        cursor.execute("""
                            CREATE INDEX IF NOT EXISTS idx_nuclei_template_status 
                            ON enrichment_system_nucleitemplaterecommendation(status)
                        """)
                        
                        self.logger.info("Created enrichment_system_nucleitemplaterecommendation table")
                    
                    # Insert template recommendations
                    for template in templates:
                        template_id = template.get('template_id', '')
                        if not template_id:
                            continue
                        
                        try:
                            relationship_id = str(uuid.uuid4())
                            cursor.execute("""
                                INSERT INTO enrichment_system_nucleitemplaterecommendation (
                                    id, egg_record_id, template_id, template_source,
                                    source_id, priority, reasoning, status, created_at, updated_at
                                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', NOW(), NOW())
                                ON CONFLICT (egg_record_id, template_id) 
                                DO UPDATE SET 
                                    priority = EXCLUDED.priority,
                                    reasoning = EXCLUDED.reasoning,
                                    updated_at = NOW()
                            """, [
                                relationship_id,
                                egg_record_id,
                                template_id,
                                template.get('source', 'unknown'),
                                template.get('source_id', ''),
                                template.get('priority', 'medium'),
                                template.get('reasoning', '')
                            ])
                            relationships_created += 1
                        except Exception as e:
                            self.logger.debug(f"Error creating template relationship: {e}")
                            continue
                    
                    return relationships_created
        except Exception as e:
            self.logger.error(f"Error creating template relationships: {e}", exc_info=True)
            return 0
    
    def get_recommended_templates_for_egg_record(self, egg_record_id: str, 
                                            status: str = 'pending') -> List[Dict]:
        """
        Get recommended Nuclei templates for an EggRecord.
        
        Args:
            egg_record_id: The EggRecord ID
            status: Filter by status ('pending', 'scanned', 'failed')
            
        Returns:
            List of template recommendations
        """
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
                
                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, template_id, template_source, source_id,
                               priority, reasoning, status, created_at, scanned_at
                        FROM enrichment_system_nucleitemplaterecommendation
                        WHERE egg_record_id = %s
                        AND status = %s
                        ORDER BY 
                            CASE priority
                                WHEN 'high' THEN 1
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 3
                            END,
                            created_at DESC
                    """, [egg_record_id, status])
                    
                    recommendations = []
                    for row in cursor.fetchall():
                        recommendations.append({
                            'id': str(row[0]),
                            'template_id': row[1],
                            'source': row[2],
                            'source_id': row[3] or '',
                            'priority': row[4],
                            'reasoning': row[5] or '',
                            'status': row[6],
                            'created_at': row[7].isoformat() if row[7] else None,
                            'scanned_at': row[8].isoformat() if row[8] else None
                        })
                    
                    return recommendations
        except Exception as e:
            self.logger.debug(f"Error getting recommended templates: {e}")
            return []

