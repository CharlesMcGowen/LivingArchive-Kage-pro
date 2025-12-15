"""
Daemon API Endpoints for Kage, Kaze, Kumo, Ryu, and Suzu
========================================================
API endpoints for standalone daemon processes to interact with Django.
"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import connections
from django.utils import timezone
from urllib.parse import urljoin
import json
import logging
import uuid
import os
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@csrf_exempt
def daemon_get_eggrecords(request, personality):
    """
    API: Get eggrecords for a daemon to process
    
    Args:
        personality: 'kage', 'kaze', 'kumo', 'ryu', or 'suzu'
        limit: Optional query param for max records (default: 10)
        scan_type: For kage/kaze/ryu - 'kage_port_scan', 'kaze_port_scan', or 'ryu_port_scan'
    """
    try:
        if personality not in ['kage', 'kaze', 'kumo', 'ryu', 'suzu']:
            return JsonResponse({'success': False, 'error': 'Invalid personality'}, status=400)
        
        limit = int(request.GET.get('limit', 10))
        scan_type = request.GET.get('scan_type', f'{personality}_port_scan' if personality in ['kage', 'kaze', 'ryu'] else None)
        
        conn = connections['customer_eggs']
        with conn.cursor() as cursor:
            # Handle Ryu scan requests (distinguish between scans and assessments)
            if personality == 'ryu' and scan_type == 'ryu_port_scan':
                # Get eggrecords that need Ryu Nmap scanning
                # Rule: Only scan once per year (max 1 scan from any scanner: Kage, Kaze, or Ryu)
                # Note: egg_id_id is included but nullable, so it won't affect query results
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at, e.egg_id_id
                    FROM customer_eggs_eggrecords_general_models_eggrecord e
                    WHERE e.alive = true
                    AND (
                        SELECT COUNT(*) FROM customer_eggs_eggrecords_general_models_nmap n
                        WHERE n.record_id_id = e.id
                        AND n.scan_type IN ('kage_port_scan', 'kaze_port_scan', 'ryu_port_scan')
                        AND n.created_at > NOW() - INTERVAL '1 year'
                    ) = 0
                    ORDER BY e.updated_at ASC
                    LIMIT %s
                """, [limit])
                
            elif personality == 'kage':
                # Get eggrecords that need Nmap scanning
                # Rule: Only scan once per year (max 1 scan from any scanner: Kage or Kaze)
                # Note: egg_id_id is included but nullable, so it won't affect query results
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at, e.egg_id_id
                    FROM customer_eggs_eggrecords_general_models_eggrecord e
                    WHERE e.alive = true
                    AND (
                        SELECT COUNT(*) FROM customer_eggs_eggrecords_general_models_nmap n
                        WHERE n.record_id_id = e.id
                        AND n.scan_type IN ('kage_port_scan', 'kaze_port_scan')
                        AND n.created_at > NOW() - INTERVAL '1 year'
                    ) = 0
                    ORDER BY e.updated_at ASC
                    LIMIT %s
                """, [limit])
                
            elif personality == 'kaze':
                # Get eggrecords that need high-speed Nmap scanning
                # Rule: Only scan once per year (max 1 scan from any scanner: Kage or Kaze)
                # Note: egg_id_id is included but nullable, so it won't affect query results
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at, e.egg_id_id
                    FROM customer_eggs_eggrecords_general_models_eggrecord e
                    WHERE e.alive = true
                    AND (
                        SELECT COUNT(*) FROM customer_eggs_eggrecords_general_models_nmap n
                        WHERE n.record_id_id = e.id
                        AND n.scan_type IN ('kage_port_scan', 'kaze_port_scan')
                        AND n.created_at > NOW() - INTERVAL '1 year'
                    ) = 0
                    ORDER BY e.updated_at ASC
                    LIMIT %s
                """, [limit])
                
            elif personality == 'kumo':
                # Get eggrecords that need HTTP spidering
                # Note: egg_id_id is included but nullable, so it won't affect query results
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at, e.egg_id_id
                    FROM customer_eggs_eggrecords_general_models_eggrecord e
                    LEFT JOIN customer_eggs_eggrecords_general_models_requestmetadata r ON r.record_id_id = e.id
                    WHERE e.alive = true
                    AND (
                        r.id IS NULL 
                        OR r.timestamp < NOW() - INTERVAL '6 months'
                    )
                    ORDER BY e.updated_at ASC
                    LIMIT %s
                """, [limit])
                
            elif personality == 'ryu':
                # Get eggrecords that need assessment (have scan or HTTP data)
                # Note: This is used when scan_type is NOT 'ryu_port_scan' (defaults to assessment query)
                # Note: egg_id_id is included but nullable, so it won't affect query results
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at, e.egg_id_id,
                        CASE 
                            WHEN EXISTS (
                                SELECT 1 FROM customer_eggs_eggrecords_general_models_nmap n 
                                WHERE n.record_id_id = e.id
                            ) AND EXISTS (
                                SELECT 1 FROM customer_eggs_eggrecords_general_models_requestmetadata r 
                                WHERE r.record_id_id = e.id
                            ) THEN 1
                            ELSE 0
                        END as priority
                    FROM customer_eggs_eggrecords_general_models_eggrecord e
                    WHERE e.alive = true
                    AND (
                        EXISTS (
                            SELECT 1 FROM customer_eggs_eggrecords_general_models_nmap n 
                            WHERE n.record_id_id = e.id
                        )
                        OR
                        EXISTS (
                            SELECT 1 FROM customer_eggs_eggrecords_general_models_requestmetadata r 
                            WHERE r.record_id_id = e.id
                        )
                    )
                    AND NOT EXISTS (
                        -- LEGACY TABLE NAME: Requires database migration from jadeassessment to ryuassessment for legal compliance
                        SELECT 1 FROM customer_eggs_eggrecords_general_models_jadeassessment j
                        WHERE j.record_id_id = e.id
                        AND j.created_at > NOW() - INTERVAL '7 days'
                    )
                    ORDER BY priority DESC, e.updated_at DESC
                    LIMIT %s
                """, [limit])
                
            elif personality == 'suzu':
                # Get eggrecords that need directory enumeration (have HTTP ports but no enumeration yet)
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at
                    FROM customer_eggs_eggrecords_general_models_eggrecord e
                    INNER JOIN customer_eggs_eggrecords_general_models_nmap n ON n.record_id_id = e.id
                    WHERE e.alive = true
                    AND n.port IS NOT NULL
                    AND n.port != ''
                    AND CAST(n.port AS INTEGER) IN (80, 443, 8080, 8443)
                    AND NOT EXISTS (
                        SELECT 1 FROM customer_eggs_eggrecords_general_models_requestmetadata r
                        WHERE r.record_id_id = e.id
                        AND (r.user_agent LIKE '%%Suzu%%' OR r.session_id LIKE 'suzu-%%')
                        AND r.timestamp > NOW() - INTERVAL '30 days'
                    )
                    ORDER BY e.updated_at ASC
                    LIMIT %s
                """, [limit])
            
            # Check if cursor.description exists (query might return no columns if error)
            if cursor.description is None:
                return JsonResponse({
                    'success': False,
                    'error': 'Query execution failed - no description available'
                }, status=500)
            
            columns = [col[0] for col in cursor.description]
            results = []
            for row in cursor.fetchall():
                row_dict = dict(zip(columns, row))
                # Convert UUID to string
                if 'id' in row_dict and row_dict['id']:
                    row_dict['id'] = str(row_dict['id'])
                # Convert egg_id_id UUID to string if present
                if 'egg_id_id' in row_dict and row_dict['egg_id_id']:
                    row_dict['egg_id_id'] = str(row_dict['egg_id_id'])
                # Convert datetime to ISO format
                if 'updated_at' in row_dict and row_dict['updated_at']:
                    row_dict['updated_at'] = row_dict['updated_at'].isoformat()
                results.append(row_dict)
            
            # Log query results for debugging
            logger.debug(f"Query for {personality} returned {len(results)} eggrecords (limit was {limit})")
            if len(results) == 0:
                logger.info(f"No eggrecords found for {personality} - all may have been scanned recently or none are alive")
            
            return JsonResponse({
                'success': True,
                'count': len(results),
                'eggrecords': results
            })
            
    except Exception as e:
        logger.error(f"Error getting eggrecords for {personality}: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def daemon_submit_scan(request, personality):
    """
    API: Submit Nmap scan results from daemon
    
    Expected JSON:
    {
        "eggrecord_id": "uuid",
        "target": "hostname",
        "scan_type": "kage_port_scan", "kaze_port_scan", or "ryu_port_scan",
        "result": {
            "open_ports": [...],
            "scan_command": "...",
            ...
        }
    }
    """
    try:
        if personality not in ['kage', 'kaze', 'ryu']:
            return JsonResponse({'success': False, 'error': 'Invalid personality for scan submission'}, status=400)
        
        data = json.loads(request.body)
        eggrecord_id = data.get('eggrecord_id')
        target = data.get('target', 'unknown')
        scan_type = data.get('scan_type', f'{personality}_port_scan')
        result = data.get('result', {})
        
        if not eggrecord_id:
            return JsonResponse({'success': False, 'error': 'eggrecord_id required'}, status=400)
        
        open_ports = result.get('open_ports', [])
        if not open_ports:
            return JsonResponse({'success': False, 'error': 'No open ports in result'}, status=400)
        
        conn = connections['customer_eggs']
        with conn.cursor() as cursor:
            # Check for very recent duplicate scans (within last 5 minutes) to prevent race conditions
            # This is a minimal safety check to prevent simultaneous submissions from multiple daemons
            # Determine which scan types to check based on the submitting scanner
            scan_types_to_check = []
            if scan_type in ['kage_port_scan', 'kaze_port_scan']:
                scan_types_to_check = ['kage_port_scan', 'kaze_port_scan']
            elif scan_type == 'ryu_port_scan':
                scan_types_to_check = ['kage_port_scan', 'kaze_port_scan', 'ryu_port_scan']
            else:
                scan_types_to_check = [scan_type]
            
            cursor.execute("""
                SELECT COUNT(*) as recent_scan_count
                FROM customer_eggs_eggrecords_general_models_nmap n
                WHERE n.record_id_id = %s
                AND n.scan_type = ANY(%s)
                AND n.created_at > NOW() - INTERVAL '5 minutes'
            """, [eggrecord_id, scan_types_to_check])
            recent_count = cursor.fetchone()[0]
            
            if recent_count > 0:
                return JsonResponse({
                    'success': False,
                    'error': f'Domain has been scanned very recently (within last 5 minutes). Found {recent_count} recent scan(s). Skipping duplicate.',
                    'skip_reason': 'very_recent_scan_exists'
                }, status=409)  # 409 Conflict
            
            # Check total scan count within last year - only allow 1 scan per year
            cursor.execute("""
                SELECT COUNT(*) as yearly_scan_count
                FROM customer_eggs_eggrecords_general_models_nmap n
                WHERE n.record_id_id = %s
                AND n.scan_type IN ('kage_port_scan', 'kaze_port_scan', 'ryu_port_scan')
                AND n.created_at > NOW() - INTERVAL '1 year'
            """, [eggrecord_id])
            yearly_count = cursor.fetchone()[0]
            
            if yearly_count >= 1:
                return JsonResponse({
                    'success': False,
                    'error': f'Domain has already been scanned {yearly_count} time(s) within the last year (max 1 allowed per year). Skipping duplicate.',
                    'skip_reason': 'yearly_scan_limit_exceeded',
                    'current_scan_count': yearly_count
                }, status=409)  # 409 Conflict
            
            # Generate MD5 hash
            import hashlib
            scan_data_str = f"{target}:{eggrecord_id}:{timezone.now().isoformat()}"
            md5_hash = hashlib.md5(scan_data_str.encode()).hexdigest()
            
            # Prepare open_ports JSONB data
            ports_json = []
            for port_info in open_ports:
                if isinstance(port_info, dict):
                    ports_json.append({
                        'port': port_info.get('port'),
                        'protocol': port_info.get('protocol', 'tcp'),
                        'service': port_info.get('service_name', ''),
                        'version': port_info.get('service_version', ''),
                        'state': 'open',
                        'banner': port_info.get('service_info', '')
                    })
            
            # Insert into database
            cursor.execute("""
                INSERT INTO customer_eggs_eggrecords_general_models_nmap (
                    id, md5, target, scan_type, scan_stage, scan_status, 
                    port, service_name, service_version, open_ports, 
                    scan_command, name, hostname, date, record_id_id, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, [
                str(uuid.uuid4()),
                md5_hash,
                target,
                scan_type,
                'completed',
                'completed',
                str(open_ports[0]['port']) if open_ports else '',
                open_ports[0].get('service_name', '') if open_ports else '',
                open_ports[0].get('service_version', '') if open_ports else '',
                json.dumps(ports_json),
                result.get('scan_command', f'nmap scan for {target}'),
                target,
                target,
                timezone.now(),
                eggrecord_id,
                timezone.now(),
                timezone.now()
            ])
            conn.commit()
            
            return JsonResponse({
                'success': True,
                'message': f'Scan result submitted for {target}'
            })
            
    except Exception as e:
        logger.error(f"Error submitting scan for {personality}: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def daemon_submit_spider(request):
    """
    API: Submit HTTP spider results from Kumo daemon
    
    Expected JSON:
    {
        "eggrecord_id": "uuid",
        "target": "url",
        "result": {
            "request_metadata": [...],
            ...
        }
    }
    """
    try:
        data = json.loads(request.body)
        eggrecord_id = data.get('eggrecord_id')
        target_url = data.get('target', 'unknown')
        result = data.get('result', {})
        
        if not eggrecord_id:
            return JsonResponse({'success': False, 'error': 'eggrecord_id required'}, status=400)
        
        request_metadata = result.get('request_metadata', [])
        if not request_metadata:
            return JsonResponse({'success': False, 'error': 'No request_metadata in result'}, status=400)
        
        conn = connections['customer_eggs']
        with conn.cursor() as cursor:
            # Insert request metadata
            for metadata in request_metadata:
                cursor.execute("""
                    INSERT INTO customer_eggs_eggrecords_general_models_requestmetadata (
                        id, record_id_id, target_url, request_method, response_status,
                        response_time_ms, user_agent, timestamp, created_at, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                """, [
                    str(uuid.uuid4()),
                    eggrecord_id,
                    metadata.get('target_url', target_url),
                    metadata.get('request_method', 'GET'),
                    metadata.get('response_status', 200),
                    metadata.get('response_time_ms', 0),
                    metadata.get('user_agent', 'Kumo/1.0'),
                    timezone.now(),
                    timezone.now(),
                    timezone.now()
                ])
            conn.commit()
            
            return JsonResponse({
                'success': True,
                'message': f'Spider result submitted for {target_url}',
                'requests_inserted': len(request_metadata)
            })
            
    except Exception as e:
        logger.error(f"Error submitting spider result: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def daemon_submit_enumeration(request):
    """
    API: Submit directory enumeration results from Suzu daemon with full heuristics.
    
    Expected JSON (new format with heuristics):
    {
        "eggrecord_id": "uuid",
        "target": "domain.com",
        "result": {
            "success": true,
            "paths_discovered": 10,
            "enumeration_results": [
                {
                    "success": true,
                    "paths": [
                        {
                            "path": "/admin",
                            "status": 200,
                            "size": 1234,
                            "content_type": "text/html",
                            "priority_score": 0.75,
                            "priority_factors": {...}
                        }
                    ],
                    "tool": "dirsearch",
                    ...
                }
            ],
            "cms_detection": {
                "cms": "wordpress",
                "confidence": 0.85,
                ...
            },
            "enumeration_metadata": {...}
        }
    }
    
    Legacy format (backward compatible):
    {
        "eggrecord_id": "uuid",
        "target": "url",
        "result": {
            "tool": "dirsearch",
            "paths": ["/admin", "/api", ...]
        }
    }
    """
    try:
        data = json.loads(request.body)
        eggrecord_id = data.get('eggrecord_id')
        target = data.get('target', 'unknown')
        result = data.get('result', {})
        
        if not eggrecord_id:
            return JsonResponse({'success': False, 'error': 'eggrecord_id required'}, status=400)
        
        conn = connections['customer_eggs']
        paths_inserted = 0
        
        # Check if this is the new format with heuristics
        paths_discovered = result.get('paths_discovered', [])  # This is the list of paths with priority scores
        enumeration_results = result.get('enumeration_results', [])  # Raw tool output (for reference)
        cms_detection = result.get('cms_detection')
        enumeration_metadata = result.get('enumeration_metadata', {})
        
        if paths_discovered:
            # New format: Store in DirectoryEnumerationResult with priority scores
            with conn.cursor() as cursor:
                tool = enumeration_metadata.get('tool_used') or (enumeration_results[0].get('tool') if enumeration_results else 'unknown')
                wordlist_used = enumeration_metadata.get('wordlist_used') or 'default'
                
                for path_data in paths_discovered[:200]:  # Limit to 200 paths per enumeration
                    try:
                        # Extract path data (paths_discovered already has priority scores)
                        if isinstance(path_data, dict):
                            discovered_path = path_data.get('path', '')
                            status_code = path_data.get('status', 0)
                            content_length = path_data.get('size', 0)
                            content_type = path_data.get('content_type', '')
                            priority_score = path_data.get('priority_score', 0.0)
                            priority_factors = path_data.get('priority_factors', {})
                            response_time = path_data.get('response_time', 0.0)
                        else:
                            # Fallback: path_data is a string
                            discovered_path = str(path_data)
                            status_code = 200
                            content_length = 0
                            content_type = ''
                            priority_score = 0.0
                            priority_factors = {}
                            response_time = 0.0
                        
                        if not discovered_path:
                            continue
                        
                        # Extract CMS info from detection
                        detected_cms = None
                        detected_cms_version = None
                        cms_detection_confidence = 0.0
                        if cms_detection:
                            detected_cms = cms_detection.get('cms') or cms_detection.get('cms_name')
                            detected_cms_version = cms_detection.get('version') or cms_detection.get('cms_version')
                            cms_detection_confidence = cms_detection.get('confidence', 0.0)
                        
                        # Insert into DirectoryEnumerationResult
                        cursor.execute("""
                            INSERT INTO customer_eggs_eggrecords_general_models_directoryenumerationresult (
                                id, egg_record_id, discovered_path, path_status_code,
                                path_content_length, path_content_type, path_response_time_ms,
                                detected_cms, detected_cms_version, cms_detection_confidence,
                                priority_score, priority_factors,
                                enumeration_tool, wordlist_used, enumeration_depth,
                                created_at, updated_at
                            ) VALUES (
                                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                            )
                            ON CONFLICT DO NOTHING
                        """, [
                            str(uuid.uuid4()),
                            eggrecord_id,
                            discovered_path,
                            status_code if status_code else None,
                            content_length if content_length else None,
                            content_type if content_type else None,
                            response_time if response_time else None,
                            detected_cms,
                            detected_cms_version,
                            cms_detection_confidence,
                            priority_score,
                            json.dumps(priority_factors) if priority_factors else None,
                            tool,
                            wordlist_used,
                            1,  # enumeration_depth
                            timezone.now(),
                            timezone.now()
                        ])
                        paths_inserted += 1
                    except Exception as e:
                        logger.warning(f"Error inserting path {path_data}: {e}")
                        continue
                
                conn.commit()
        else:
            # Legacy format: backward compatibility
            paths = result.get('paths', [])
            if not paths:
                return JsonResponse({'success': False, 'error': 'No paths in result'}, status=400)
            
            with conn.cursor() as cursor:
                # Store as RequestMetadata for backward compatibility
                for path in paths[:100]:
                    full_url = urljoin(target, path) if isinstance(path, str) else target
                    cursor.execute("""
                        INSERT INTO customer_eggs_eggrecords_general_models_requestmetadata (
                            id, record_id_id, target_url, request_method, response_status,
                            response_time_ms, user_agent, session_id, timestamp, created_at, updated_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        ON CONFLICT DO NOTHING
                    """, [
                        str(uuid.uuid4()),
                        eggrecord_id,
                        full_url,
                        'GET',
                        200,
                        0,
                        'Suzu/1.0',
                        f'suzu-{eggrecord_id}',
                        timezone.now(),
                        timezone.now(),
                        timezone.now()
                    ])
                conn.commit()
                paths_inserted = len(paths)
        
        return JsonResponse({
            'success': True,
            'message': f'Enumeration result submitted for {target}',
            'paths_inserted': paths_inserted,
            'format': 'heuristics' if enumeration_results else 'legacy'
        })
            
    except Exception as e:
        logger.error(f"Error submitting enumeration result: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# Global progress storage (in-memory, shared across requests)
# In production, consider using Redis or database
_suzu_progress = {
    'status': 'idle',
    'current_target': None,
    'current_eggrecord_id': None,
    'current_step': None,
    'progress_percent': 0,
    'cycle_number': 0,
    'enumerated_this_cycle': 0,
    'total_in_queue': 0,
    'paths_found': 0,
    'cms_detected': None,
    'started_at': None,
    'estimated_completion': None
}


@csrf_exempt
def suzu_update_progress(request):
    """
    API: Update Suzu daemon progress (called by daemon)
    
    POST /reconnaissance/api/daemon/suzu/progress/
    {
        "status": "enumerating",
        "current_target": "example.com",
        "current_step": "cms_detection",
        "progress_percent": 50,
        ...
    }
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        global _suzu_progress
        
        # Update progress (merge with existing)
        _suzu_progress.update({
            'status': data.get('status', _suzu_progress.get('status', 'idle')),
            'current_target': data.get('current_target'),
            'current_eggrecord_id': data.get('current_eggrecord_id'),
            'current_step': data.get('current_step'),
            'progress_percent': data.get('progress_percent', 0),
            'cycle_number': data.get('cycle_number', _suzu_progress.get('cycle_number', 0)),
            'enumerated_this_cycle': data.get('enumerated_this_cycle', 0),
            'total_in_queue': data.get('total_in_queue', 0),
            'paths_found': data.get('paths_found', _suzu_progress.get('paths_found', 0)),
            'cms_detected': data.get('cms_detected'),
            'started_at': data.get('started_at'),
            'estimated_completion': data.get('estimated_completion'),
            'last_updated': timezone.now().isoformat()
        })
        
        return JsonResponse({'success': True, 'message': 'Progress updated'})
    except Exception as e:
        logger.error(f"Error updating progress: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


def suzu_get_progress(request):
    """
    API: Get Suzu daemon progress (for dashboard)
    
    GET /reconnaissance/api/suzu/progress/
    """
    global _suzu_progress
    return JsonResponse({
        'success': True,
        'progress': _suzu_progress
    })


@csrf_exempt
def daemon_submit_assessment(request):
    """
    API: Submit threat assessment results from Ryu daemon
    
    Expected JSON:
    {
        "eggrecord_id": "uuid",
        "risk_level": "high|medium|low",
        "threat_summary": "...",
        "vulnerabilities": {...},
        "attack_vectors": {...},
        "remediation_priorities": {...},
        "narrative": "..."
    }
    """
    try:
        data = json.loads(request.body)
        eggrecord_id = data.get('eggrecord_id')
        
        if not eggrecord_id:
            return JsonResponse({'success': False, 'error': 'eggrecord_id required'}, status=400)
        
        conn = connections['customer_eggs']
        with conn.cursor() as cursor:
            # Insert assessment
            # LEGACY TABLE NAME: Requires database migration from jadeassessment to ryuassessment for legal compliance
            cursor.execute("""
                INSERT INTO customer_eggs_eggrecords_general_models_jadeassessment (
                    id, record_id_id, risk_level, threat_summary,
                    vulnerabilities, attack_vectors, remediation_priorities,
                    narrative, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, [
                str(uuid.uuid4()),
                eggrecord_id,
                data.get('risk_level', 'medium'),
                data.get('threat_summary'),
                json.dumps(data.get('vulnerabilities', {})),
                json.dumps(data.get('attack_vectors', {})),
                json.dumps(data.get('remediation_priorities', {})),
                data.get('narrative'),
                timezone.now(),
                timezone.now()
            ])
            conn.commit()
            
            return JsonResponse({
                'success': True,
                'message': f'Assessment submitted for eggrecord {eggrecord_id}'
            })
            
    except Exception as e:
        logger.error(f"Error submitting assessment: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def daemon_health_check(request, personality):
    """
    API: Health check endpoint for Docker containers
    
    Returns health status for monitoring and container health checks.
    """
    try:
        if personality not in ['kage', 'kaze', 'kumo', 'ryu', 'suzu']:
            return JsonResponse({
                'success': False,
                'error': 'Invalid personality'
            }, status=400)
        
        # Check database connectivity
        db_healthy = False
        try:
            conn = connections['customer_eggs']
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                db_healthy = True
        except Exception as e:
            logger.warning(f"Database health check failed: {e}")
        
        # Check if we can query eggrecords (basic functionality test)
        functional = False
        try:
            conn = connections['customer_eggs']
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM customer_eggs_eggrecords_general_models_eggrecord LIMIT 1")
                functional = True
        except Exception as e:
            logger.warning(f"Functional check failed: {e}")
        
        health_status = 'healthy' if (db_healthy and functional) else 'degraded'
        
        return JsonResponse({
            'success': True,
            'status': health_status,
            'personality': personality,
            'database': 'connected' if db_healthy else 'disconnected',
            'functional': functional,
            'timestamp': timezone.now().isoformat(),
            'pid': os.getpid() if hasattr(os, 'getpid') else None
        })
        
    except Exception as e:
        logger.error(f"Error in health check: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'status': 'unhealthy',
            'error': str(e)
        }, status=500)

