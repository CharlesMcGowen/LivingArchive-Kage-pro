#!/usr/bin/env python3
"""
Surge Service Management API Views
=================================

API endpoints for managing the Lt. Surge 24/7 scanning service.
Provides status monitoring, health checks, and service control.

Author: EGO Revolution Team
Version: 1.0.0
"""

import os
import sys
import logging
from datetime import datetime, timedelta
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from django.utils import timezone
from django.db.models import Count, Q
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

# Import models
from customer_eggs_eggrecords_general_models.core_models.vulnerability_scanner import (
    ScanTarget, VulnerabilityScanSession, VulnerabilityScanResult
)

logger = logging.getLogger(__name__)

@api_view(['GET'])
except Exception as e:
    logger.error(f"Unexpected error in __main__: {e}", exc_info=True)
    raise
def surge_service_status(request):
    """
    Get current status of the Surge scanning service.
    """
    try:
        # Check if Surge service is running via continuous services manager
        from ai_system.ai_services.continuous_services_manager import continuous_services_manager
        
        # Get continuous services status
        continuous_status = continuous_services_manager.get_continuous_status()
        
        # Check for Surge-specific metrics
        surge_targets = ScanTarget.objects.filter(created_by='surge_nuclei').count()
        surge_sessions = VulnerabilityScanSession.objects.filter(
            created_by='surge_nuclei'
        ).count()
        
        # Get recent activity (last 24 hours)
        recent_time = timezone.now() - timedelta(hours=24)
        recent_targets = ScanTarget.objects.filter(
            created_by='surge_nuclei',
            created_at__gte=recent_time
        ).count()
        
        recent_vulnerabilities = VulnerabilityScanResult.objects.filter(
            scanner_name='nuclei',
            detected_at__gte=recent_time
        ).count()
        
        # Check if Surge is in the running services
        surge_running = 'surge_nuclei_scanner' in continuous_services_manager.running_services
        
        return Response({
            'status': 'success',
            'data': {
                'service_running': surge_running,
                'continuous_operation': continuous_status.get('continuous_operation', False),
                'operation_window': continuous_status.get('operation_window', False),
                'current_time': timezone.now().isoformat(),
                'surge_metrics': {
                    'total_targets': surge_targets,
                    'total_sessions': surge_sessions,
                    'recent_targets_24h': recent_targets,
                    'recent_vulnerabilities_24h': recent_vulnerabilities
                },
                'continuous_services': {
                    'services_running': continuous_status.get('services_running', 0),
                    'gpu_available': continuous_status.get('gpu_available', False),
                    'resource_usage': continuous_status.get('resource_usage', {})
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting Surge service status: {e}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def surge_health_check(request):
    """
    Perform health check on the Surge service.
    """
    try:
        # Check database connectivity
        db_healthy = True
        try:
            ScanTarget.objects.count()
        except Exception:
            db_healthy = False
        
        # Check if Surge service is responding
        surge_healthy = False
        try:
            from ai_system.ai_services.continuous_services_manager import continuous_services_manager
            surge_healthy = 'surge_nuclei_scanner' in continuous_services_manager.running_services
        except Exception:
            surge_healthy = False
        
        # Check recent activity
        recent_activity = False
        try:
            recent_time = timezone.now() - timedelta(hours=1)
            recent_activity = VulnerabilityScanResult.objects.filter(
                scanner_name='nuclei',
                detected_at__gte=recent_time
            ).exists()
        except Exception:
            recent_activity = False
        
        health_status = {
            'overall_health': 'healthy' if (db_healthy and surge_healthy) else 'unhealthy',
            'database': 'healthy' if db_healthy else 'unhealthy',
            'surge_service': 'healthy' if surge_healthy else 'unhealthy',
            'recent_activity': recent_activity,
            'timestamp': timezone.now().isoformat()
        }
        
        return Response({
            'status': 'success',
            'data': health_status
        })
        
    except Exception as e:
        logger.error(f"Error performing Surge health check: {e}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def surge_activity_summary(request):
    """
    Get summary of Surge scanning activity.
    """
    try:
        # Get time range from query params
        hours = int(request.GET.get('hours', 24))
        start_time = timezone.now() - timedelta(hours=hours)
        
        # Get activity metrics
        targets_created = ScanTarget.objects.filter(
            created_by='surge_nuclei',
            created_at__gte=start_time
        ).count()
        
        targets_scanned = ScanTarget.objects.filter(
            created_by='surge_nuclei',
            is_scanned=True,
            scanned_at__gte=start_time
        ).count()
        
        vulnerabilities_found = VulnerabilityScanResult.objects.filter(
            scanner_name='nuclei',
            detected_at__gte=start_time
        ).count()
        
        # Get scan sessions
        scan_sessions = VulnerabilityScanSession.objects.filter(
            created_by='surge_nuclei',
            created_at__gte=start_time
        ).count()
        
        # Get top vulnerability types
        top_vulnerabilities = VulnerabilityScanResult.objects.filter(
            scanner_name='nuclei',
            detected_at__gte=start_time
        ).values('vulnerability_definition__name').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        return Response({
            'status': 'success',
            'data': {
                'time_range_hours': hours,
                'start_time': start_time.isoformat(),
                'end_time': timezone.now().isoformat(),
                'activity_summary': {
                    'targets_created': targets_created,
                    'targets_scanned': targets_scanned,
                    'vulnerabilities_found': vulnerabilities_found,
                    'scan_sessions': scan_sessions,
                    'scan_success_rate': (targets_scanned / targets_created * 100) if targets_created > 0 else 0
                },
                'top_vulnerabilities': list(top_vulnerabilities)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting Surge activity summary: {e}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def surge_restart_service(request):
    """
    Restart the Surge scanning service.
    """
    try:
        from ai_system.ai_services.continuous_services_manager import continuous_services_manager
        
        # Stop existing Surge service if running
        if 'surge_nuclei_scanner' in continuous_services_manager.running_services:
            continuous_services_manager._stop_service('surge_nuclei_scanner')
        
        # Start Surge service again
        surge_config = continuous_services_manager.service_configs.get('surge_nuclei_scanner', {})
        if surge_config.get('enabled', True):
            # Get targets from database
            targets = continuous_services_manager._get_targets_from_database()
            
            # Start Surge service
            surge_service = continuous_services_manager._create_surge_nuclei_service(surge_config)
            if surge_service:
                results = continuous_services_manager._start_service_with_gpu(
                    'surge_nuclei_scanner',
                    surge_config,
                    targets
                )
                
                return Response({
                    'status': 'success',
                    'message': 'Surge service restarted successfully',
                    'data': results
                })
            else:
                return Response({
                    'status': 'error',
                    'message': 'Failed to create Surge service instance'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                'status': 'error',
                'message': 'Surge service is disabled in configuration'
            }, status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.error(f"Error restarting Surge service: {e}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def surge_service_logs(request):
    """
    Get recent logs from the Surge service.
    """
    try:
        # This would typically read from log files
        # For now, return a placeholder
        return Response({
            'status': 'success',
            'data': {
                'logs': [
                    {
                        'timestamp': timezone.now().isoformat(),
                        'level': 'INFO',
                        'message': 'Surge service is running in continuous mode'
                    }
                ],
                'note': 'Log retrieval not fully implemented yet'
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting Surge service logs: {e}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def get_all_services_status(request):
    """
    Get status of all main services running in the system.
    """
    try:
        from ai_system.ai_services.continuous_services_manager import continuous_services_manager
        
        services = []
        
        # Get continuous services
        continuous_status = continuous_services_manager.get_continuous_status()
        
        # Surge Service
        surge_running = 'surge_nuclei_scanner' in continuous_services_manager.running_services
        services.append({
            'name': 'Surge 24/7 Scanner',
            'slug': 'surge_nuclei_scanner',
            'status': 'running' if surge_running else 'stopped',
            'type': 'vulnerability_scanner',
            'description': '24/7 Nuclei vulnerability scanner',
            'detail_url': '/enrichment/surge-dashboard/',
            'has_controls': True
        })
        
        # Check for other gym leader services
        gym_leader_services = [
            {
                'name': 'Misty Analytics',
                'slug': 'misty_analyzer',
                'type': 'analytics',
                'description': 'Water-type analytics and data processing',
                'detail_url': '/gymleaders/misty/',
                'has_controls': False
            },
            {
                'name': 'Brock Network Scanner',
                'slug': 'brock_scanner',
                'type': 'network_scanner',
                'description': 'Rock-solid network scanning',
                'detail_url': '/gymleaders/brock/',
                'has_controls': False
            },
            {
                'name': 'Sabrina Pentester',
                'slug': 'sabrina_pentester',
                'type': 'pentesting',
                'description': 'Psychic penetration testing',
                'detail_url': '/sabrina/dashboard/',
                'has_controls': False
            }
        ]
        
        for service in gym_leader_services:
            service.get('status', None) = 'unknown'
            services.append(service)
        
        # Get database session counts
        from customer_eggs_eggrecords_general_models.core_models.vulnerability_scanner import VulnerabilityScanSession
        
        running_sessions = VulnerabilityScanSession.objects.filter(status='running').count()
        
        return Response({
            'status': 'success',
            'data': {
                'services': services,
                'total_services': len(services),
                'running_services': sum(1 for s in services if s['status'] == 'running'),
                'running_sessions': running_sessions,
                'timestamp': timezone.now().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting all services status: {e}")
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def stop_individual_session(request, session_id):
    """
    Stop an individual scan session by ID.
    """
    try:
        from customer_eggs_eggrecords_general_models.core_models.vulnerability_scanner import VulnerabilityScanSession
        
        logger.info(f"[STOP_SESSION] Stopping session {session_id}...")
        
        # Get the session
        try:
            session = VulnerabilityScanSession.objects.get(pk=session_id)
        except VulnerabilityScanSession.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'Session not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Mark as cancelled
        session.status = 'cancelled'
        session.completed_at = timezone.now()
        session.save()
        
        logger.info(f"[STOP_SESSION] Session {session_id} marked as cancelled")
        
        return Response({
            'status': 'success',
            'message': 'Session stopped successfully',
            'session_id': str(session_id),
            'timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"[STOP_SESSION_ERROR] Error stopping session {session_id}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def surge_force_start(request):
    """
    Force start the Surge service regardless of operation window.
    """
    try:
        from ai_system.ai_services.continuous_services_manager import continuous_services_manager
        
        # Force start by bypassing the operation window check
        result = continuous_services_manager.start_continuous_services(force=True)
        
        return Response({
            'status': 'success',
            'message': 'Surge service force started',
            'result': result,
            'timestamp': timezone.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error force starting Surge service: {e}")
        return Response({'status': 'error', 'message': str(e)}, status=500)

@api_view(['POST'])
def surge_start_service(request):
    """
    Start the Surge scanning service.
    """
    try:
        from ai_system.ai_services.continuous_services_manager import continuous_services_manager
        
        logger.info("[SURGE_START] Starting Surge service...")
        
        # Check if already running
        if 'surge_nuclei_scanner' in continuous_services_manager.running_services:
            return Response({
                'status': 'warning',
                'message': 'Surge service is already running',
                'already_running': True
            })
        
        # Get surge config
        surge_config = continuous_services_manager.service_configs.get('surge_nuclei_scanner', {})
        if not surge_config.get('enabled', True):
            surge_config['enabled'] = True  # Force enable
        
        # Get targets from database
        targets = continuous_services_manager._get_targets_from_database()
        
        # Create and start Surge service
        surge_service = continuous_services_manager._create_surge_nuclei_service(surge_config)
        if surge_service:
            results = continuous_services_manager._start_service_with_gpu(
                'surge_nuclei_scanner',
                surge_config,
                targets
            )
            
            logger.info(f"[SURGE_START] Service started successfully")
            
            return Response({
                'status': 'success',
                'message': 'Surge service started successfully',
                'data': results,
                'timestamp': timezone.now().isoformat()
            })
        else:
            return Response({
                'status': 'error',
                'message': 'Failed to create Surge service instance'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    except Exception as e:
        logger.error(f"[SURGE_START_ERROR] Error starting Surge service: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def surge_stop_service(request):
    """
    Stop the Surge scanning service and kill all processes AND database sessions.
    """
    try:
        import subprocess
        import signal
        
        logger.info("[SURGE_STOP] Stopping Surge service...")
        
        from ai_system.ai_services.continuous_services_manager import continuous_services_manager
        from customer_eggs_eggrecords_general_models.core_models.vulnerability_scanner import VulnerabilityScanSession
        
        processes_killed = 0
        sessions_killed = 0
        
        # Step 1: Stop via continuous services manager if running
        if 'surge_nuclei_scanner' in continuous_services_manager.running_services:
            continuous_services_manager._stop_service('surge_nuclei_scanner')
            logger.info("[SURGE_STOP] Stopped via continuous services manager")
        
        # Step 2: Kill ALL running database sessions (not just surge_nuclei)
        try:
            running_sessions = VulnerabilityScanSession.objects.filter(
                status='running'
            )
            sessions_killed = running_sessions.count()
            running_sessions.update(
                status='cancelled',
                completed_at=timezone.now()
            )
            logger.info(f"[SURGE_STOP] Killed {sessions_killed} database sessions (ALL running)")
        except Exception as e:
            logger.warning(f"[SURGE_STOP] Session kill warning: {e}")
        
        # Step 3: Kill any remaining Surge processes
        if os.name == 'nt':  # Windows
            result = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq python.exe', '/FO', 'CSV'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                surge_pids = []
                
                for line in lines[1:]:  # Skip header
                    if 'lt_surge_24_7_standalone.py' in line or 'surge' in line.lower():
                        # Extract PID from CSV
                        parts = line.split(',')
                        if len(parts) > 1:
                            pid = parts[1].strip('"')
                            surge_pids.append(pid)
                
                if surge_pids:
                    for pid in surge_pids:
                        try:
                            os.kill(int(pid), signal.SIGTERM)
                            processes_killed += 1
                            logger.info(f"[SURGE_STOP] Killed process {pid}")
                        except (OSError, ValueError) as e:
                            logger.warning(f"[SURGE_STOP] Could not kill process {pid}: {e}")
        else:  # Unix/Linux
            # Use pkill to find and kill surge processes
            result = subprocess.run(
                ['pkill', '-f', 'lt_surge_24_7_standalone.py'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                processes_killed += 1
                logger.info("[SURGE_STOP] Killed Surge processes via pkill")
        
        logger.info(f"[SURGE_STOP] Service stopped. {processes_killed} processes + {sessions_killed} sessions killed.")
        
        return Response({
            'status': 'success',
            'message': 'Surge service stopped successfully',
            'processes_killed': processes_killed,
            'sessions_killed': sessions_killed,
            'timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"[SURGE_STOP_ERROR] Error stopping Surge service: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def surge_reset_service(request):
    """
    Reset the Surge scanning service completely.
    This performs a hard reset:
    - Kills all processes
    - Clears cached data
    - Resets stuck states
    - Force restarts with fresh configuration
    """
    try:
        import subprocess
        import signal
        import shutil
        
        logger.info("[SURGE_RESET] Resetting Surge service...")
        
        from ai_system.ai_services.continuous_services_manager import continuous_services_manager
        
        actions_performed = []
        processes_killed = 0
        
        # Step 1: Stop via continuous services manager
        if 'surge_nuclei_scanner' in continuous_services_manager.running_services:
            continuous_services_manager._stop_service('surge_nuclei_scanner')
            actions_performed.append("Stopped service manager")
            logger.info("[SURGE_RESET] Stopped via continuous services manager")
        
        # Step 2: Kill all Surge processes (aggressive)
        if os.name == 'nt':  # Windows
            result = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq python.exe', '/FO', 'CSV'],
                capture_output=True, text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                surge_pids = []
                
                for line in lines[1:]:  # Skip header
                    if 'lt_surge' in line.lower() or 'nuclei' in line.lower():
                        parts = line.split(',')
                        if len(parts) > 1:
                            pid = parts[1].strip('"')
                            surge_pids.append(pid)
                
                if surge_pids:
                    for pid in surge_pids:
                        try:
                            os.kill(int(pid), signal.SIGTERM)
                            processes_killed += 1
                            logger.info(f"[SURGE_RESET] Killed process {pid}")
                        except (OSError, ValueError) as e:
                            logger.warning(f"[SURGE_RESET] Could not kill process {pid}: {e}")
        else:  # Unix/Linux
            result = subprocess.run(
                ['pkill', '-9', '-f', 'surge'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                processes_killed += 1
        
        if processes_killed > 0:
            actions_performed.append(f"Killed {processes_killed} processes")
        
        # Step 3: Clear any cached scan data (if exists)
        try:
            cache_paths = [
                'enrichment_system/services/.surge_cache',
                'apps/gymleaders/services/surge/.cache',
            ]
            for cache_path in cache_paths:
                if os.path.exists(cache_path):
                    shutil.rmtree(cache_path, ignore_errors=True)
                    actions_performed.append("Cleared cache")
                    logger.info(f"[SURGE_RESET] Cleared cache: {cache_path}")
        except Exception as e:
            logger.warning(f"[SURGE_RESET] Cache clear warning: {e}")
        
        # Step 4: Reset scan session states in database
        try:
            from customer_eggs_eggrecords_general_models.core_models.vulnerability_scanner import VulnerabilityScanSession
            
            # Mark any running sessions as cancelled
            running_sessions = VulnerabilityScanSession.objects.filter(
                status='running',
                created_by='surge_nuclei'
            )
            count = running_sessions.update(
                status='cancelled',
                completed_at=timezone.now()
            )
            if count > 0:
                actions_performed.append(f"Reset {count} stuck sessions")
                logger.info(f"[SURGE_RESET] Reset {count} stuck scan sessions")
        except Exception as e:
            logger.warning(f"[SURGE_RESET] Session reset warning: {e}")
        
        # Step 5: Wait a moment for cleanup
        import time
        time.sleep(2)
        
        # Step 6: Restart service fresh
        try:
            surge_config = continuous_services_manager.service_configs.get('surge_nuclei_scanner', {})
            surge_config['enabled'] = True  # Force enable
            
            targets = continuous_services_manager._get_targets_from_database()
            surge_service = continuous_services_manager._create_surge_nuclei_service(surge_config)
            
            if surge_service:
                continuous_services_manager._start_service_with_gpu(
                    'surge_nuclei_scanner',
                    surge_config,
                    targets
                )
                actions_performed.append("Restarted fresh")
                logger.info("[SURGE_RESET] Service restarted fresh")
        except Exception as e:
            logger.warning(f"[SURGE_RESET] Restart warning: {e}")
            actions_performed.append("Clean state ready for manual start")
        
        logger.info(f"[SURGE_RESET] Reset complete. Actions: {', '.join(actions_performed)}")
        
        return Response({
            'status': 'success',
            'message': 'Surge service reset successfully',
            'actions_performed': actions_performed,
            'processes_killed': processes_killed,
            'timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"[SURGE_RESET_ERROR] Error resetting Surge service: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
