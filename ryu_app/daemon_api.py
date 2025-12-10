"""
Daemon API Endpoints for Kage, Kumo, and Ryu
===========================================
API endpoints for standalone daemon processes to interact with Django.
"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db import connections
from django.utils import timezone
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
        personality: 'kage', 'kumo', or 'ryu'
        limit: Optional query param for max records (default: 10)
        scan_type: For kage/ryu - 'kage_port_scan' or 'ryu_port_scan'
    """
    try:
        if personality not in ['kage', 'kumo', 'ryu']:
            return JsonResponse({'success': False, 'error': 'Invalid personality'}, status=400)
        
        limit = int(request.GET.get('limit', 10))
        scan_type = request.GET.get('scan_type', f'{personality}_port_scan' if personality in ['kage', 'ryu'] else None)
        
        conn = connections['customer_eggs']
        with conn.cursor() as cursor:
            if personality == 'kage':
                # Get eggrecords that need Nmap scanning
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at
                    FROM customer_eggs_eggrecords_general_models_eggrecord e
                    LEFT JOIN customer_eggs_eggrecords_general_models_nmap n ON n.record_id_id = e.id 
                        AND n.scan_type = 'kage_port_scan'
                    WHERE e.alive = true
                    AND (n.id IS NULL OR n.created_at < NOW() - INTERVAL '24 hours')
                    ORDER BY e.updated_at ASC
                    LIMIT %s
                """, [limit])
                
            elif personality == 'kumo':
                # Get eggrecords that need HTTP spidering
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at
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
                cursor.execute("""
                    SELECT DISTINCT e.id, e."subDomain", e.domainname, e.alive, e.updated_at,
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
                        SELECT 1 FROM customer_eggs_eggrecords_general_models_jadeassessment j
                        WHERE j.record_id_id = e.id
                        AND j.created_at > NOW() - INTERVAL '7 days'
                    )
                    ORDER BY priority DESC, e.updated_at DESC
                    LIMIT %s
                """, [limit])
            
            columns = [col[0] for col in cursor.description]
            results = []
            for row in cursor.fetchall():
                row_dict = dict(zip(columns, row))
                # Convert UUID to string
                if 'id' in row_dict:
                    row_dict['id'] = str(row_dict['id'])
                # Convert datetime to ISO format
                if 'updated_at' in row_dict and row_dict['updated_at']:
                    row_dict['updated_at'] = row_dict['updated_at'].isoformat()
                results.append(row_dict)
            
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
        "scan_type": "kage_port_scan" or "ryu_port_scan",
        "result": {
            "open_ports": [...],
            "scan_command": "...",
            ...
        }
    }
    """
    try:
        if personality not in ['kage', 'ryu']:
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
        if personality not in ['kage', 'kumo', 'ryu']:
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

