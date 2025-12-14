#!/usr/bin/env python3
"""Clone LivingArchive-Kage to LivingArchive-Kage-pro"""
import shutil
import os

src = '/media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage'
dst = '/media/ego/328010BE80108A8D1/github_public/LivingArchive-Kage-pro'

# Use shutil.copytree with dirs_exist_ok
if os.path.exists(dst):
    # Remove everything except key files we want to keep
    keep = {'README.md', 'requirements.txt', 'manage.py', 'do_clone.py', 'clone_script.py'}
    for item in os.listdir(dst):
        if item not in keep:
            path = os.path.join(dst, item)
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)

# Copy everything
for root, dirs, files in os.walk(src):
    # Skip certain directories
    dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', '.pytest_cache']]
    
    # Calculate relative path
    rel_path = os.path.relpath(root, src)
    if rel_path == '.':
        dst_dir = dst
    else:
        dst_dir = os.path.join(dst, rel_path)
    
    # Create destination directory
    os.makedirs(dst_dir, exist_ok=True)
    
    # Copy files
    for file in files:
        if file.endswith(('.pyc', '.log')) or file == 'db.sqlite3':
            continue
        src_file = os.path.join(root, file)
        dst_file = os.path.join(dst_dir, file)
        shutil.copy2(src_file, dst_file)

print("Clone complete!")

