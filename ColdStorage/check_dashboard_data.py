#!/usr/bin/env python3
"""
Diagnostic script to check why dashboards aren't populating
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
django.setup()

from ryu_app.postgres_models import PostgresNmap, PostgresRequestMetadata
from django.db import connections
from django.utils import timezone
from datetime import timedelta

print("=" * 60)
print("DASHBOARD DATA DIAGNOSTIC")
print("=" * 60)

# Check database connection
if 'customer_eggs' not in connections.databases:
    print("❌ ERROR: customer_eggs database not configured")
    sys.exit(1)
else:
    print("✅ customer_eggs database configured")

# Check Kaze scans
print("\n--- KAZE DASHBOARD ---")
try:
    kaze_total = PostgresNmap.objects.using('customer_eggs').filter(scan_type='kaze_port_scan').count()
    recent_time = timezone.now() - timedelta(hours=24)
    kaze_recent = PostgresNmap.objects.using('customer_eggs').filter(
        scan_type='kaze_port_scan',
        created_at__gte=recent_time
    ).count()
    print(f"Total kaze_port_scan records: {kaze_total}")
    print(f"Recent (24h) kaze_port_scan records: {kaze_recent}")
    
    if kaze_total > 0:
        latest = PostgresNmap.objects.using('customer_eggs').filter(
            scan_type='kaze_port_scan'
        ).order_by('-created_at').first()
        if latest:
            print(f"Latest scan: {latest.target} at {latest.created_at}")
except Exception as e:
    print(f"❌ ERROR querying Kaze: {e}")

# Check Ryu scans
print("\n--- RYU DASHBOARD ---")
try:
    ryu_total = PostgresNmap.objects.using('customer_eggs').filter(scan_type='ryu_port_scan').count()
    ryu_recent = PostgresNmap.objects.using('customer_eggs').filter(
        scan_type='ryu_port_scan',
        created_at__gte=recent_time
    ).count()
    print(f"Total ryu_port_scan records: {ryu_total}")
    print(f"Recent (24h) ryu_port_scan records: {ryu_recent}")
    
    if ryu_total > 0:
        latest = PostgresNmap.objects.using('customer_eggs').filter(
            scan_type='ryu_port_scan'
        ).order_by('-created_at').first()
        if latest:
            print(f"Latest scan: {latest.target} at {latest.created_at}")
except Exception as e:
    print(f"❌ ERROR querying Ryu: {e}")

# Check Kumo requests
print("\n--- KUMO DASHBOARD ---")
try:
    from django.db.models import Q
    kumo_total = PostgresRequestMetadata.objects.using('customer_eggs').filter(
        Q(user_agent__icontains='Kumo') | Q(session_id__icontains='kumo')
    ).count()
    kumo_recent = PostgresRequestMetadata.objects.using('customer_eggs').filter(
        Q(user_agent__icontains='Kumo') | Q(session_id__icontains='kumo'),
        created_at__gte=recent_time
    ).count()
    print(f"Total Kumo requests: {kumo_total}")
    print(f"Recent (24h) Kumo requests: {kumo_recent}")
    
    if kumo_total > 0:
        latest = PostgresRequestMetadata.objects.using('customer_eggs').filter(
            Q(user_agent__icontains='Kumo') | Q(session_id__icontains='kumo')
        ).order_by('-created_at').first()
        if latest:
            print(f"Latest request: {latest.url} at {latest.created_at}")
except Exception as e:
    print(f"❌ ERROR querying Kumo: {e}")

# Check Suzu requests
print("\n--- SUZU DASHBOARD ---")
try:
    suzu_total = PostgresRequestMetadata.objects.using('customer_eggs').filter(
        Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-')
    ).count()
    suzu_recent = PostgresRequestMetadata.objects.using('customer_eggs').filter(
        Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-'),
        created_at__gte=recent_time
    ).count()
    print(f"Total Suzu requests: {suzu_total}")
    print(f"Recent (24h) Suzu requests: {suzu_recent}")
    
    if suzu_total > 0:
        latest = PostgresRequestMetadata.objects.using('customer_eggs').filter(
            Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-')
        ).order_by('-created_at').first()
        if latest:
            print(f"Latest request: {latest.url} at {latest.created_at}")
except Exception as e:
    print(f"❌ ERROR querying Suzu: {e}")

# Check all scan types
print("\n--- ALL SCAN TYPES ---")
try:
    from django.db.models import Count
    scan_types = PostgresNmap.objects.using('customer_eggs').values('scan_type').annotate(
        count=Count('id')
    ).order_by('-count')
    print("Scan type distribution:")
    for st in scan_types:
        print(f"  {st['scan_type']}: {st['count']}")
except Exception as e:
    print(f"❌ ERROR: {e}")

print("\n" + "=" * 60)

