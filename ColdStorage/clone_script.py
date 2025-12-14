#!/usr/bin/env python3
import shutil
import os
import sys

src = '/media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage'
dst = '/media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro'

print(f"Source: {src}")
print(f"Destination: {dst}")
print(f"Source exists: {os.path.exists(src)}")

# Get list of items to copy
items = os.listdir(src)
print(f"Items to copy: {len(items)}")

# Remove existing files except what we want to keep
existing = os.listdir(dst)
for item in existing:
    if item not in ['README.md', 'requirements.txt', 'manage.py']:
        item_path = os.path.join(dst, item)
        try:
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)
        except Exception as e:
            print(f"Warning: Could not remove {item}: {e}")

# Copy all files and directories
copied_files = 0
copied_dirs = 0

for item in items:
    if item in ['.git', '__pycache__', 'test_file.txt', 'clone_script.py']:
        continue
        
    src_path = os.path.join(src, item)
    dst_path = os.path.join(dst, item)
    
    try:
        if os.path.isdir(src_path):
            if os.path.exists(dst_path):
                shutil.rmtree(dst_path)
            shutil.copytree(src_path, dst_path, ignore=shutil.ignore_patterns('*.pyc', 'db.sqlite3', '*.log', '__pycache__'))
            copied_dirs += 1
            print(f"✅ Copied directory: {item}")
        else:
            if not item.endswith(('.pyc', '.log')) and item != 'db.sqlite3':
                shutil.copy2(src_path, dst_path)
                copied_files += 1
                if copied_files % 10 == 0:
                    print(f"✅ Copied {copied_files} files...")
    except Exception as e:
        print(f"❌ Error copying {item}: {e}")

print(f"\n✅ Clone complete! Copied {copied_files} files and {copied_dirs} directories")

