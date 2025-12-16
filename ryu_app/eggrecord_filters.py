"""
Reusable Django ORM filter utilities for EggRecords.
This module provides a clean interface for filtering EggRecords similar to 
the implementation in kage_dashboard and eggrecord_list views.
"""
import logging
from django.db import connections
from django.db.models import Count, Q
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


def get_eggrecord_queryset(
    database_name: str = 'customer_eggs',
    filter_egg_id: Optional[str] = None,
    filter_alive: Optional[bool] = None,
    filter_domain: Optional[str] = None,
    filter_subdomain: Optional[str] = None,
    order_by: str = '-updated_at',
    limit: Optional[int] = None,
    include_annotations: bool = True
) -> Any:
    """
    Get a filtered queryset of EggRecords using Django ORM.
    
    Args:
        database_name: Database name to use ('customer_eggs' or default)
        filter_egg_id: Filter by egg_id UUID
        filter_alive: Filter by alive status (True/False)
        filter_domain: Filter by domain name (case-insensitive contains)
        filter_subdomain: Filter by subdomain (case-insensitive contains)
        order_by: Field to order by (default: '-updated_at')
        limit: Limit number of results (None = no limit)
        include_annotations: Include count annotations (nmap_count, request_count, dns_count)
    
    Returns:
        Django QuerySet of PostgresEggRecord objects
    """
    from .postgres_models import PostgresEggRecord
    
    if database_name not in connections.databases:
        logger.warning(f"Database '{database_name}' not found in connections")
        return PostgresEggRecord.objects.none()
    
    try:
        # Build base queryset using Django ORM
        queryset = PostgresEggRecord.objects.using(database_name).select_related('egg_id')
        
        # Apply filters
        if filter_egg_id:
            try:
                queryset = queryset.filter(egg_id_id=filter_egg_id)
            except Exception as filter_error:
                logger.warning(f"Error applying egg_id filter: {filter_error}")
        
        if filter_alive is not None:
            queryset = queryset.filter(alive=filter_alive)
        
        if filter_domain:
            queryset = queryset.filter(domainname__icontains=filter_domain)
        
        if filter_subdomain:
            queryset = queryset.filter(subDomain__icontains=filter_subdomain)
        
        # Add annotations if requested
        if include_annotations:
            try:
                queryset = queryset.annotate(
                    nmap_count=Count('nmap_scans', distinct=True),
                    request_count=Count('http_requests', distinct=True),
                    dns_count=Count('dns_queries', distinct=True)
                )
            except Exception as annot_error:
                logger.warning(f"Annotations failed: {annot_error}")
                include_annotations = False
        
        # Apply ordering
        queryset = queryset.order_by(order_by)
        
        # Apply limit if specified
        if limit:
            queryset = queryset[:limit]
        
        return queryset, include_annotations
        
    except Exception as e:
        logger.error(f"Error building EggRecord queryset: {e}", exc_info=True)
        return PostgresEggRecord.objects.none(), False


def get_eggrecords_as_dicts(
    database_name: str = 'customer_eggs',
    filter_egg_id: Optional[str] = None,
    filter_alive: Optional[bool] = None,
    filter_domain: Optional[str] = None,
    filter_subdomain: Optional[str] = None,
    order_by: str = '-updated_at',
    limit: Optional[int] = None,
    include_annotations: bool = True
) -> List[Dict[str, Any]]:
    """
    Get filtered EggRecords as a list of dictionaries.
    
    Returns a list suitable for passing to Django templates.
    Each dict contains:
        - id, subDomain, domainname, alive, created_at, updated_at
        - eggname, projectegg (if available)
        - egg_id, egg_name, eisystem_name (from related egg)
        - nmap_count, request_count, dns_count (if annotations included)
    """
    queryset, use_annotations = get_eggrecord_queryset(
        database_name=database_name,
        filter_egg_id=filter_egg_id,
        filter_alive=filter_alive,
        filter_domain=filter_domain,
        filter_subdomain=filter_subdomain,
        order_by=order_by,
        limit=limit,
        include_annotations=include_annotations
    )
    
    if not queryset:
        return []
    
    eggrecords = []
    for e in queryset:
        eggrecord_dict = {
            'id': str(e.id),
            'subDomain': e.subDomain,
            'domainname': e.domainname,
            'alive': e.alive,
            'created_at': e.created_at,
            'updated_at': e.updated_at,
            'eggname': getattr(e, 'eggname', None),
            'projectegg': getattr(e, 'projectegg', None),
            'egg_id': str(e.egg_id.id) if e.egg_id else None,
            'egg_name': e.egg_id.eggName if e.egg_id else None,
            'eisystem_name': e.egg_id.eisystem_in_thorm if e.egg_id else None,
        }
        
        if use_annotations:
            eggrecord_dict['nmap_count'] = getattr(e, 'nmap_count', 0)
            eggrecord_dict['request_count'] = getattr(e, 'request_count', 0)
            eggrecord_dict['dns_count'] = getattr(e, 'dns_count', 0)
        else:
            eggrecord_dict['nmap_count'] = 0
            eggrecord_dict['request_count'] = 0
            eggrecord_dict['dns_count'] = 0
        
        eggrecords.append(eggrecord_dict)
    
    return eggrecords


def get_eggrecord_counts(
    database_name: str = 'customer_eggs',
    filter_egg_id: Optional[str] = None,
    filter_alive: Optional[bool] = None,
    filter_domain: Optional[str] = None,
    filter_subdomain: Optional[str] = None
) -> Dict[str, int]:
    """
    Get count statistics for filtered EggRecords.
    
    Returns a dict with:
        - total: Total count matching filters
        - alive: Count of alive records matching filters
        - dead: Count of dead records matching filters
    """
    from .postgres_models import PostgresEggRecord
    
    if database_name not in connections.databases:
        return {'total': 0, 'alive': 0, 'dead': 0}
    
    try:
        queryset = PostgresEggRecord.objects.using(database_name)
        
        # Apply same filters as get_eggrecord_queryset
        if filter_egg_id:
            queryset = queryset.filter(egg_id_id=filter_egg_id)
        if filter_alive is not None:
            queryset = queryset.filter(alive=filter_alive)
        if filter_domain:
            queryset = queryset.filter(domainname__icontains=filter_domain)
        if filter_subdomain:
            queryset = queryset.filter(subDomain__icontains=filter_subdomain)
        
        total = queryset.count()
        alive = queryset.filter(alive=True).count()
        dead = queryset.filter(alive=False).count()
        
        return {
            'total': total,
            'alive': alive,
            'dead': dead
        }
    except Exception as e:
        logger.error(f"Error getting EggRecord counts: {e}", exc_info=True)
        return {'total': 0, 'alive': 0, 'dead': 0}


def get_unique_eggs_for_filter(
    database_name: str = 'customer_eggs'
) -> List[Dict[str, Any]]:
    """
    Get unique eggs that have associated EggRecords for filter dropdowns.
    
    Returns a list of dicts with: id, eggName, eisystem_in_thorm
    """
    from .postgres_models import PostgresEggs
    
    if database_name not in connections.databases:
        return []
    
    try:
        eggs_with_records = PostgresEggs.objects.using(database_name).filter(
            egg_records__isnull=False
        ).distinct().values('id', 'eggName', 'eisystem_in_thorm').order_by('eggName')
        
        return list(eggs_with_records)
    except Exception as e:
        logger.warning(f"Error fetching unique eggs: {e}")
        return []


def extract_eggrecord_filters_from_request(request) -> Dict[str, Any]:
    """
    Extract filter parameters from Django request.GET.
    
    Returns a dict with normalized filter values:
        - filter_egg_id: UUID string or None
        - filter_alive: bool or None
        - filter_domain: string or None
        - filter_subdomain: string or None
    """
    filter_egg_id = request.GET.get('egg', '').strip() or None
    filter_domain = request.GET.get('domain', '').strip() or None
    filter_subdomain = request.GET.get('subdomain', '').strip() or None
    
    # Handle alive filter (can be 'true', 'false', '1', '0', or empty)
    alive_param = request.GET.get('alive', '').strip().lower()
    if alive_param in ('true', '1', 'yes'):
        filter_alive = True
    elif alive_param in ('false', '0', 'no'):
        filter_alive = False
    else:
        filter_alive = None
    
    return {
        'filter_egg_id': filter_egg_id,
        'filter_alive': filter_alive,
        'filter_domain': filter_domain,
        'filter_subdomain': filter_subdomain,
    }


def build_eggrecord_filter_context(request, database_name: str = 'customer_eggs') -> Dict[str, Any]:
    """
    Build a complete context dict for Django templates with filtered EggRecords.
    
    This is a convenience function that combines all the above utilities
    to provide a ready-to-use context dict similar to what kage_dashboard uses.
    
    Returns context dict with:
        - eggrecords: List of eggrecord dicts
        - total_eggrecords: Total count
        - alive_eggrecords: Alive count
        - filtered_count: Count of current results
        - unique_eggs: List of eggs for filter dropdown
        - filters: Dict of current filter values
        - filter_egg_id: Current egg filter (for template compatibility)
    """
    filters = extract_eggrecord_filters_from_request(request)
    
    # Get filtered eggrecords
    eggrecords = get_eggrecords_as_dicts(
        database_name=database_name,
        filter_egg_id=filters['filter_egg_id'],
        filter_alive=filters['filter_alive'],
        filter_domain=filters['filter_domain'],
        filter_subdomain=filters['filter_subdomain'],
        limit=200 if not filters['filter_egg_id'] else None,  # Limit only if not filtered
        include_annotations=True
    )
    
    # Get counts
    counts = get_eggrecord_counts(
        database_name=database_name,
        filter_egg_id=filters['filter_egg_id'],
        filter_alive=filters['filter_alive'],
        filter_domain=filters['filter_domain'],
        filter_subdomain=filters['filter_subdomain'],
    )
    
    # Get unique eggs for dropdown
    unique_eggs = get_unique_eggs_for_filter(database_name=database_name)
    
    context = {
        'eggrecords': eggrecords,
        'total_eggrecords': counts['total'],
        'alive_eggrecords': counts['alive'],
        'filtered_count': len(eggrecords),
        'total_count': len(eggrecords),
        'unique_eggs': unique_eggs,
        'filters': filters,
        'filter_egg_id': filters['filter_egg_id'],
    }
    
    return context

