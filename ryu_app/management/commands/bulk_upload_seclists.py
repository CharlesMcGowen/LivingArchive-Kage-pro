"""
Django management command to bulk upload CMS wordlists from SecLists directory.

Usage:
    python manage.py bulk_upload_seclists
    python manage.py bulk_upload_seclists --dry-run
    python manage.py bulk_upload_seclists --cms-dir /path/to/CMS/
"""
from django.core.management.base import BaseCommand
from pathlib import Path
import logging
import sys
import os

# Add suzu to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), 'suzu'))

from suzu.upload_wordlist import upload_wordlist_file, infer_cms_from_filename, load_paths_from_file
from suzu.vector_path_store import VectorPathStore

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Bulk upload CMS wordlists from SecLists directory to Suzu vector database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be uploaded without actually uploading'
        )
        parser.add_argument(
            '--cms-dir',
            type=str,
            default='/home/ego/webapps-nvme/tools/SecLists/Discovery/Web-Content/CMS/',
            help='Path to CMS wordlists directory (default: /home/ego/webapps-nvme/tools/SecLists/Discovery/Web-Content/CMS/)'
        )
        parser.add_argument(
            '--recursive',
            action='store_true',
            help='Recursively process subdirectories'
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        cms_dir = Path(options['cms_dir'])
        recursive = options['recursive']

        if not cms_dir.exists():
            self.stdout.write(self.style.ERROR(f'❌ Directory does not exist: {cms_dir}'))
            return

        if not cms_dir.is_dir():
            self.stdout.write(self.style.ERROR(f'❌ Path is not a directory: {cms_dir}'))
            return

        # Find all wordlist files
        wordlist_extensions = ['.txt', '.fuzz', '.lst', '.wordlist']
        files_to_upload = []

        if recursive:
            for ext in wordlist_extensions:
                files_to_upload.extend(cms_dir.rglob(f'*{ext}'))
        else:
            for ext in wordlist_extensions:
                files_to_upload.extend(cms_dir.glob(f'*{ext}'))

        if not files_to_upload:
            self.stdout.write(self.style.WARNING(f'⚠️  No wordlist files found in {cms_dir}'))
            return

        self.stdout.write(self.style.SUCCESS(f'📁 Found {len(files_to_upload)} wordlist files'))

        if dry_run:
            self.stdout.write(self.style.WARNING('\n🔍 DRY RUN MODE - No files will be uploaded\n'))
            for file_path in files_to_upload:
                cms_name = infer_cms_from_filename(file_path.name)
                paths = load_paths_from_file(file_path)
                self.stdout.write(f'  📄 {file_path.name}')
                self.stdout.write(f'     CMS: {cms_name or "unknown"}')
                self.stdout.write(f'     Paths: {len(paths)}')
                self.stdout.write(f'     Full path: {file_path}')
            return

        # Initialize vector store
        try:
            vector_store = VectorPathStore()
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Failed to initialize vector store: {e}'))
            return

        total_uploaded = 0
        total_failed = 0
        processed = 0

        for file_path in files_to_upload:
            processed += 1
            self.stdout.write(f'\n{"="*60}')
            self.stdout.write(f'[{processed}/{len(files_to_upload)}] Processing: {file_path.name}')

            # Infer CMS from filename
            cms_name = infer_cms_from_filename(file_path.name)
            if cms_name:
                self.stdout.write(f'  🔍 Inferred CMS: {cms_name}')

            # Upload file
            result = upload_wordlist_file(
                file_path=file_path,
                cms_name=cms_name,
                wordlist_name=file_path.name,
                default_weight=0.4,
                source="seclist"
            )

            if result:
                total_uploaded += result['uploaded']
                total_failed += result['failed']
                self.stdout.write(self.style.SUCCESS(
                    f'  ✅ Uploaded: {result["uploaded"]}, Failed: {result["failed"]}'
                ))
            else:
                self.stdout.write(self.style.WARNING(f'  ⚠️  No result from upload'))

        self.stdout.write(f'\n{"="*60}')
        self.stdout.write(self.style.SUCCESS(
            f'📊 Total: {total_uploaded} paths uploaded, {total_failed} failed'
        ))

