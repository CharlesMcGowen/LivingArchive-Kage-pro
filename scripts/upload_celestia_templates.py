#!/usr/bin/env python3
"""
Script to upload Celestia's Nuclei templates to Oak's template registry.

This script scans Celestia's cloned repos directories and uploads all Nuclei templates
to Oak's template registry via the upload API or direct indexing.

Usage:
    python upload_celestia_templates.py [--force-rescan] [--api-upload]
"""

import os
import sys
import argparse
from pathlib import Path
import requests
import json

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Celestia directories to scan
CELESTIA_DIRS = [
    '/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/40k-nuclei-templates',
    '/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/nuclei-templates',
    '/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos/nuclei-templates-ai',
]

API_BASE_URL = 'http://127.0.0.1:9000/reconnaissance/api/oak'


def find_template_files(directories):
    """Find all YAML template files in the given directories."""
    template_files = []
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.exists():
            print(f"⚠️  Directory not found: {directory}")
            continue
        
        print(f"🔍 Scanning {directory}...")
        yaml_files = list(dir_path.rglob('*.yaml')) + list(dir_path.rglob('*.yml'))
        template_files.extend(yaml_files)
        print(f"   Found {len(yaml_files)} template files")
    
    return template_files


def upload_via_api(template_files, force_rescan=False, batch_size=100):
    """Upload templates via the REST API."""
    print(f"\n📤 Uploading {len(template_files)} templates via API (batch size: {batch_size})...")
    
    uploaded = 0
    errors = 0
    
    # Process in batches
    for i in range(0, len(template_files), batch_size):
        batch = template_files[i:i + batch_size]
        print(f"\n📦 Processing batch {i // batch_size + 1} ({len(batch)} files)...")
        
        # Create a ZIP archive for this batch
        import tempfile
        import zipfile
        import shutil
        
        temp_dir = tempfile.mkdtemp(prefix='oak_upload_')
        zip_path = os.path.join(temp_dir, f'templates_batch_{i // batch_size + 1}.zip')
        
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for template_file in batch:
                    # Add file to ZIP with relative path
                    zipf.write(template_file, template_file.name)
            
            # Upload ZIP via API
            url = f"{API_BASE_URL}/upload-templates/?auto_index=true&force_rescan={'true' if force_rescan else 'false'}"
            
            with open(zip_path, 'rb') as f:
                files = {'archive': (os.path.basename(zip_path), f, 'application/zip')}
                response = requests.post(url, files=files, timeout=300)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    uploaded += data.get('uploaded', 0)
                    errors += data.get('error_count', 0)
                    print(f"   ✅ Batch uploaded: {data.get('uploaded', 0)} files, {data.get('indexed', 0)} indexed")
                else:
                    errors += len(batch)
                    print(f"   ❌ Batch failed: {data.get('error', 'Unknown error')}")
            else:
                errors += len(batch)
                print(f"   ❌ HTTP {response.status_code}: {response.text[:200]}")
        
        except Exception as e:
            errors += len(batch)
            print(f"   ❌ Error processing batch: {e}")
        
        finally:
            # Cleanup
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass
    
    return uploaded, errors


def upload_via_direct_indexing(template_files, force_rescan=False):
    """Upload templates via direct Django ORM indexing (requires Django environment)."""
    print(f"\n📤 Indexing {len(template_files)} templates directly...")
    
    try:
        # Set up Django
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
        import django
        django.setup()
        
        from artificial_intelligence.personalities.reconnaissance.oak.template_registry_service import (
            OakTemplateRegistryService
        )
        
        # Group templates by directory to initialize registry properly
        template_dirs = set()
        for template_file in template_files:
            template_dirs.add(str(template_file.parent))
        
        # Use first directory as primary, rest as additional
        dirs_list = sorted(list(template_dirs))
        primary_dir = dirs_list[0] if dirs_list else None
        additional_dirs = dirs_list[1:] if len(dirs_list) > 1 else []
        
        # Initialize registry with all directories
        registry = OakTemplateRegistryService(
            templates_dir=primary_dir,
            additional_dirs=additional_dirs
        )
        
        indexed = 0
        updated = 0
        errors = 0
        
        for template_file in template_files:
            try:
                template_data = registry._parse_template_file(template_file)
                if template_data:
                    result = registry._index_template(template_file, template_data, force_rescan)
                    if result == 'indexed':
                        indexed += 1
                    elif result == 'updated':
                        updated += 1
                    elif result == 'error':
                        errors += 1
                    
                    if (indexed + updated + errors) % 100 == 0:
                        print(f"   Progress: {indexed + updated + errors}/{len(template_files)} processed...")
                else:
                    errors += 1
            except Exception as e:
                errors += 1
                if errors <= 10:  # Only show first 10 errors
                    print(f"   ⚠️  Error processing {template_file.name}: {e}")
        
        print(f"\n✅ Direct indexing complete:")
        print(f"   Indexed: {indexed}")
        print(f"   Updated: {updated}")
        print(f"   Errors: {errors}")
        
        return indexed + updated, errors
    
    except ImportError as e:
        print(f"❌ Django not available: {e}")
        print("   Falling back to API upload method...")
        return upload_via_api(template_files, force_rescan)
    except Exception as e:
        print(f"❌ Error in direct indexing: {e}")
        import traceback
        traceback.print_exc()
        print("   Falling back to API upload method...")
        return upload_via_api(template_files, force_rescan)


def main():
    parser = argparse.ArgumentParser(description='Upload Celestia Nuclei templates to Oak')
    parser.add_argument('--force-rescan', action='store_true', 
                       help='Force rescan of existing templates')
    parser.add_argument('--api-upload', action='store_true',
                       help='Use API upload method instead of direct indexing')
    parser.add_argument('--batch-size', type=int, default=100,
                       help='Batch size for API uploads (default: 100)')
    
    args = parser.parse_args()
    
    print("🌳 Oak Template Uploader - Celestia Templates")
    print("=" * 60)
    
    # Find all template files
    template_files = find_template_files(CELESTIA_DIRS)
    
    if not template_files:
        print("❌ No template files found!")
        return 1
    
    print(f"\n📊 Found {len(template_files)} template files total")
    
    # Upload templates
    if args.api_upload:
        uploaded, errors = upload_via_api(template_files, args.force_rescan, args.batch_size)
    else:
        uploaded, errors = upload_via_direct_indexing(template_files, args.force_rescan)
    
    print("\n" + "=" * 60)
    print(f"✅ Upload complete!")
    print(f"   Total files: {len(template_files)}")
    print(f"   Processed: {uploaded}")
    print(f"   Errors: {errors}")
    
    return 0 if errors == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
