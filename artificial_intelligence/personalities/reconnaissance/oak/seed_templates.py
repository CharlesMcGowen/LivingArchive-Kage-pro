#!/usr/bin/env python3
"""
Oak Template Registry Seed Script
==================================

Script to scan and index existing Nuclei templates into the database.
Run this after uploading templates or when setting up Oak for the first time.

Usage:
    python manage.py shell
    >>> from artificial_intelligence.personalities.reconnaissance.oak.seed_templates import seed_templates
    >>> seed_templates()

Or run directly:
    python artificial_intelligence/personalities/reconnaissance/oak/seed_templates.py
"""

import os
import sys
from pathlib import Path
import django

# Setup Django environment
if __name__ == '__main__':
    # Add project root to path
    project_root = Path(__file__).resolve().parent.parent.parent.parent.parent
    sys.path.insert(0, str(project_root))
    
    # Setup Django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
    django.setup()


def seed_templates(force_rescan: bool = False):
    """
    Scan and index all Nuclei templates.
    
    Args:
        force_rescan: If True, re-index existing templates
        
    Returns:
        Dict with scan statistics
    """
    from artificial_intelligence.personalities.reconnaissance.oak.template_registry_service import (
        OakTemplateRegistryService
    )
    
    print("🌳 Oak Template Registry - Scanning templates...")
    print(f"   Templates directory: {os.environ.get('NUCLEI_TEMPLATES_DIR', '/home/ego/nuclei-templates')}")
    
    registry = OakTemplateRegistryService()
    result = registry.scan_and_index_templates(force_rescan=force_rescan)
    
    if result.get('success'):
        print(f"✅ Template scan complete!")
        print(f"   Scanned: {result.get('scanned', 0)} templates")
        print(f"   Indexed: {result.get('indexed', 0)} new templates")
        print(f"   Updated: {result.get('updated', 0)} existing templates")
        print(f"   Errors: {result.get('errors', 0)}")
        print(f"   Total templates in registry: {result.get('total_templates', 0)}")
    else:
        print(f"❌ Template scan failed: {result.get('error', 'Unknown error')}")
    
    return result


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    
    parser = argparse.ArgumentParser(description='Seed Oak template registry')
    parser.add_argument('--force', action='store_true', help='Force rescan of existing templates')
    args = parser.parse_args()
    
    seed_templates(force_rescan=args.force)

