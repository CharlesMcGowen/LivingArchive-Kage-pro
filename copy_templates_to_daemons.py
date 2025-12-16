#!/usr/bin/env python3
"""
Copy Nuclei Templates to Daemon Directories
===========================================

Copies all indexed Nuclei templates from various source directories
to the directories used by Surge, Koga, and Bugsy daemons.

Usage:
    python copy_templates_to_daemons.py
"""

import os
import sys
import shutil
from pathlib import Path

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')

import django
django.setup()

# Import after Django setup
from artificial_intelligence.customer_eggs_eggrecords_general_models.models import NucleiTemplate


def copy_templates_to_daemon_dirs():
    """Copy all templates to daemon directories."""
    
    # Target directories for daemons
    target_dirs = {
        'surge': Path('/home/ego/nuclei-templates'),
        'koga': Path('/home/ego/nuclei-templates'),  # Same as Surge
        'bugsy': Path('/home/ego/nuclei-templates'),  # Same as Surge
    }
    
    # Source directories (where templates currently are)
    source_dirs = [
        Path('/home/ego/nuclei-templates'),
        Path('/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/40k-nuclei-templates'),
        Path('/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/nuclei-templates'),
        Path('/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/nuclei-templates-ai'),
    ]
    
    print('🔄 Copying Nuclei Templates to Daemon Directories')
    print('=' * 60)
    
    # Ensure target directory exists
    target_dir = target_dirs['surge']
    target_dir.mkdir(parents=True, exist_ok=True)
    print(f'📁 Target directory: {target_dir}')
    print()
    
    # Collect all template files
    template_files = []
    for source_dir in source_dirs:
        if source_dir.exists():
            yaml_files = list(source_dir.rglob('*.yaml')) + list(source_dir.rglob('*.yml'))
            template_files.extend(yaml_files)
            print(f'   Found {len(yaml_files)} templates in {source_dir.name}')
    
    print(f'\n📊 Total templates to copy: {len(template_files):,}')
    print()
    
    # Copy templates, preserving directory structure
    copied = 0
    skipped = 0
    errors = 0
    
    for template_file in template_files:
        try:
            # Calculate relative path from source
            relative_path = None
            for source_dir in source_dirs:
                try:
                    relative_path = template_file.relative_to(source_dir)
                    break
                except ValueError:
                    continue
            
            if not relative_path:
                # Use filename if can't determine relative path
                relative_path = Path(template_file.name)
            
            # Destination path
            dest_path = target_dir / relative_path
            
            # Skip if already exists and is same size
            if dest_path.exists():
                if dest_path.stat().st_size == template_file.stat().st_size:
                    skipped += 1
                    continue
            
            # Create parent directories
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy file
            shutil.copy2(template_file, dest_path)
            copied += 1
            
            if copied % 1000 == 0:
                print(f'   Progress: {copied:,} copied, {skipped:,} skipped, {errors:,} errors')
                
        except Exception as e:
            errors += 1
            if errors <= 10:  # Only show first 10 errors
                print(f'   ⚠️  Error copying {template_file.name}: {e}')
    
    print()
    print('=' * 60)
    print('📊 Copy Summary:')
    print(f'   Copied: {copied:,}')
    print(f'   Skipped (already exist): {skipped:,}')
    print(f'   Errors: {errors:,}')
    print(f'   Total processed: {len(template_files):,}')
    print()
    
    # Verify final count
    final_count = len(list(target_dir.rglob('*.yaml'))) + len(list(target_dir.rglob('*.yml')))
    print(f'✅ Final template count in {target_dir}: {final_count:,}')
    
    return {
        'copied': copied,
        'skipped': skipped,
        'errors': errors,
        'total': len(template_files),
        'final_count': final_count
    }


if __name__ == '__main__':
    result = copy_templates_to_daemon_dirs()
    sys.exit(0 if result['errors'] == 0 else 1)


