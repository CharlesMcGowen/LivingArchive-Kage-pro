#!/bin/bash
# Verification script for dashboard fixes

echo "=========================================="
echo "Dashboard Fixes Verification"
echo "=========================================="

echo ""
echo "1. Checking container status..."
cd /media/ego/328010BE80108A8D2/github_public/LivingArchive-Kage-pro/docker
docker compose ps --format "table {{.Name}}\t{{.Status}}" | grep recon-

echo ""
echo "2. Testing Kaze scanner initialization..."
docker exec recon-kaze python3 -c "
import sys
sys.path.insert(0, '/app')
try:
    from kage.nmap_scanner import get_kage_scanner
    scanner = get_kage_scanner()
    if scanner:
        print('✅ Kaze scanner initialized successfully')
    else:
        print('❌ Kaze scanner is None')
except Exception as e:
    print(f'❌ Kaze scanner error: {e}')
" 2>&1

echo ""
echo "3. Testing Django model fields..."
docker exec recon-django python3 -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
django.setup()
from ryu_app.postgres_models import PostgresRequestMetadata
fields = [f.name for f in PostgresRequestMetadata._meta.get_fields() if hasattr(f, 'name')]
if 'user_agent' in fields and 'session_id' in fields:
    print('✅ PostgresRequestMetadata has user_agent and session_id fields')
else:
    print('❌ Missing fields:', 'user_agent' if 'user_agent' not in fields else '', 'session_id' if 'session_id' not in fields else '')
" 2>&1

echo ""
echo "4. Checking recent daemon logs..."
echo "--- Kaze (last 5 lines) ---"
docker logs recon-kaze --tail 5 2>&1 | tail -5

echo ""
echo "--- Kumo (last 5 lines) ---"
docker logs recon-kumo --tail 5 2>&1 | tail -5

echo ""
echo "--- Ryu (last 5 lines) ---"
docker logs recon-ryu --tail 5 2>&1 | tail -5

echo ""
echo "=========================================="
echo "Verification complete"
echo "=========================================="

