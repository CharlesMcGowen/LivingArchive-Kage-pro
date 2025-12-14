"""
Surge Scan Tracking API Views
============================

API endpoints for monitoring surge scan tracking and statistics.
"""

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta

from customer_eggs_eggrecords_general_models.core_models.vulnerability_scanner import ScanTarget, VulnerabilityScanSession
from services.surge import surge_scan_tracking

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def surge_scan_stats(request):
    """
    Get surge scan tracking statistics.
    
    Returns:
        - Total scan sessions
        - Active scan sessions
        - Total targets registered
        - Scanned targets
        - Unscanned targets
        - Recent scan activity
    """
    try:
        # Get overall statistics
        total_sessions = VulnerabilityScanSession.objects.count()
        active_sessions = VulnerabilityScanSession.objects.filter(
            status='running'
        ).count()
        
        total_targets = ScanTarget.objects.count()
        scanned_targets = ScanTarget.objects.filter(is_scanned=True).count()
        unscanned_targets = ScanTarget.objects.filter(is_scanned=False).count()
        
        # Get recent activity (last 24 hours)
        last_24h = timezone.now() - timedelta(hours=24)
        recent_scans = ScanTarget.objects.filter(
            updated_at__gte=last_24h,
            is_scanned=True
        ).count()
        
        # Get scan sessions by status
        sessions_by_status = VulnerabilityScanSession.objects.values('status').annotate(
            count=Count('id')
        ).order_by('status')
        
        # Get targets by type
        targets_by_type = ScanTarget.objects.values('target_type').annotate(
            count=Count('id')
        ).order_by('target_type')
        
        # Get recent scan sessions
        recent_sessions = VulnerabilityScanSession.objects.order_by('-started_at')[:10]
        recent_sessions_data = []
        for session in recent_sessions:
            session_stats = surge_scan_tracking.get_scan_session_stats(session)
            recent_sessions_data.append(session_stats)
        
        return Response({
            'status': 'success',
            'data': {
                'overview': {
                    'total_sessions': total_sessions,
                    'active_sessions': active_sessions,
                    'total_targets': total_targets,
                    'scanned_targets': scanned_targets,
                    'unscanned_targets': unscanned_targets,
                    'recent_scans_24h': recent_scans
                },
                'sessions_by_status': list(sessions_by_status),
                'targets_by_type': list(targets_by_type),
                'recent_sessions': recent_sessions_data
            }
        }, status=status.HTTP_200_OK)
        
        return Response({
            'status': 'error',
            'message': f'Error retrieving surge scan stats: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def surge_scan_session_detail(request, session_id):
    """
    Get detailed information about a specific scan session.
    
    Args:
        session_id: UUID of the scan session
        
    Returns:
        Detailed scan session information including targets and progress
    """
    try:
        session = VulnerabilityScanSession.objects.get(id=session_id)
        session_stats = surge_scan_tracking.get_scan_session_stats(session)
        
        # Get targets for this session
        targets = ScanTarget.objects.filter(scan_session=session).order_by('-created_at')
        targets_data = []
        for target in targets:
            targets_data.append({
                'id': str(target.id),
                'target_type': target.target_type,
                'target_value': target.target_value,
                'is_scanned': target.is_scanned,
                'scan_result': target.scan_result,
                'scanned_by': target.scanned_by,
                'scanned_at': target.scanned_at,
                'created_at': target.created_at,
                'updated_at': target.updated_at,
                'created_by': target.created_by
            })
        
        return Response({
            'status': 'success',
            'data': {
                'session': session_stats,
                'targets': targets_data
            }
        }, status=status.HTTP_200_OK)
        
    except VulnerabilityScanSession.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Scan session not found'
        }, status=status.HTTP_404_NOT_FOUND)
        return Response({
            'status': 'error',
            'message': f'Error retrieving scan session: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def surge_unscanned_targets(request):
    """
    Get list of unscanned targets.
    
    Query Parameters:
        - limit: Maximum number of targets to return (default: 100)
        - target_type: Filter by target type (subdomain, ip, url, port)
        
    Returns:
        List of unscanned targets
    """
    try:
        limit = int(request.GET.get('limit', 100))
        target_type = request.GET.get('target_type')
        
        # Build query
        query = Q(is_scanned=False)
        if target_type:
            query &= Q(target_type=target_type)
        
        # Get unscanned targets
        targets = ScanTarget.objects.filter(query).order_by('created_at')[:limit]
        
        targets_data = []
        for target in targets:
            targets_data.append({
                'id': str(target.id),
                'target_type': target.target_type,
                'target_value': target.target_value,
                'is_scanned': target.is_scanned,
                'scanned_by': target.scanned_by,
                'scanned_at': target.scanned_at,
                'created_at': target.created_at,
                'created_by': target.created_by,
                'scan_session_id': str(target.scan_session.id) if target.scan_session else None
            })
        
        return Response({
            'status': 'success',
            'data': {
                'targets': targets_data,
                'count': len(targets_data),
                'limit': limit,
                'target_type_filter': target_type
            }
        }, status=status.HTTP_200_OK)
        
        return Response({
            'status': 'error',
            'message': f'Error retrieving unscanned targets: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def surge_cleanup_sessions(request):
    """
    Clean up old scan sessions.
    
    Body:
        - days_old: Number of days old sessions to clean up (default: 7)
        
    Returns:
        Cleanup results
    """
    try:
        days_old = int(request.data.get('days_old', 7))
        
        # Get sessions to be cleaned up
        cutoff_date = timezone.now() - timedelta(days=days_old)
        old_sessions = VulnerabilityScanSession.objects.filter(
            started_at__lt=cutoff_date,
            status='completed'
        )
        
        # Count targets that will be deleted
        total_targets = 0
        for session in old_sessions:
            total_targets += ScanTarget.objects.filter(scan_session=session).count()
        
        # Perform cleanup
        surge_scan_tracking.cleanup_old_sessions(days_old)
        
        return Response({
            'status': 'success',
            'message': f'Cleaned up {old_sessions.count()} sessions and {total_targets} targets older than {days_old} days'
        }, status=status.HTTP_200_OK)
        
        return Response({
            'status': 'error',
            'message': f'Error during cleanup: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def surge_scan_bugsy_targets(request):
    """
    Fetch targets from Bugsy's curated lists and start scanning them.
    
    This endpoint integrates Surge with Bugsy by:
    1. Fetching high-priority curated targets from Bugsy
    2. Creating a new scan session
    3. Registering the targets for scanning
    4. Returning session info for monitoring
    
    Body:
        - limit: Maximum number of targets to fetch (default: 50)
        - priority: Priority level ('high', 'medium', 'low', default: 'high')
        - session_name: Optional custom session name
        
    Returns:
        Scan session information and target count
    """
    try:
        # Get parameters
        limit = int(request.data.get('limit', 50))
        priority = request.data.get('priority', 'high')
        session_name = request.data.get('session_name')
        
        # Validate priority
        if priority not in ['high', 'medium', 'low']:
            return Response({
                'status': 'error',
                'message': 'Invalid priority. Must be high, medium, or low'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Fetch targets from Bugsy
        targets = surge_scan_tracking.get_targets_from_bugsy(
            limit=limit,
            priority=priority
        )
        
        if not targets:
            return Response({
                'status': 'warning',
                'message': f'No targets found in Bugsy curated lists with priority {priority}',
                'data': {
                    'targets_fetched': 0,
                    'session_created': False
                }
            }, status=status.HTTP_200_OK)
        
        # Create scan session
        if not session_name:
            session_name = f"bugsy_{priority}_{timezone.now().strftime('%Y%m%d_%H%M%S')}"
        
        scan_session = surge_scan_tracking.create_scan_session(session_name)
        
        # Register targets for scanning
        registered_targets = surge_scan_tracking.register_targets_for_scanning(
            targets=targets,
            scan_session=scan_session,
            scanner_name='surge_nuclei_bugsy'
        )
        
        # Get session stats
        session_stats = surge_scan_tracking.get_scan_session_stats(scan_session)
        
        return Response({
            'status': 'success',
            'message': f'Successfully created scan session with {len(registered_targets)} targets from Bugsy',
            'data': {
                'session': session_stats,
                'targets_fetched': len(targets),
                'targets_registered': len(registered_targets),
                'priority': priority,
                'bugsy_integration': True
            }
        }, status=status.HTTP_201_CREATED)
        
        return Response({
            'status': 'error',
            'message': f'Invalid parameter value: {str(e)}'
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error fetching Bugsy targets: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
