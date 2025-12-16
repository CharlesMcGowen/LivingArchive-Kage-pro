#!/usr/bin/env python3
"""
Django management command to index Celestia's Nuclei templates.

This command can be run from the host system to index templates from Celestia's
cloned repos directories, even if they're not accessible from inside the container.

Usage:
    python manage.py index_celestia_templates [--force-rescan] [--dir DIR] [--dir DIR ...]
"""

from django.core.management.base import BaseCommand
from django.conf import settings
from pathlib import Path
import os
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Index Nuclei templates from Celestia directories'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force-rescan',
            action='store_true',
            help='Force rescan of existing templates',
        )
        parser.add_argument(
            '--dir',
            action='append',
            dest='directories',
            help='Additional template directory to scan (can be used multiple times)',
        )
        parser.add_argument(
            '--celestia-base',
            type=str,
            default='/home/ego/webapps-nvme/artificial_intelligence/personalities/research/celestia/cloned_repos',
            help='Base directory for Celestia cloned repos',
        )

    def handle(self, *args, **options):
        force_rescan = options['force_rescan']
        custom_dirs = options.get('directories') or []
        celestia_base = options['celestia_base']
        
        self.stdout.write(self.style.SUCCESS('🌳 Oak Template Indexer - Celestia Templates'))
        self.stdout.write('=' * 60)
        
        try:
            from artificial_intelligence.personalities.reconnaissance.oak.template_registry_service import (
                OakTemplateRegistryService
            )
        except ImportError as e:
            self.stdout.write(self.style.ERROR(f'❌ Could not import OakTemplateRegistryService: {e}'))
            return
        
        # Build list of directories to scan
        directories_to_scan = []
        
        # Add custom directories
        for dir_path in custom_dirs:
            path = Path(dir_path)
            if path.exists():
                directories_to_scan.append(str(path))
                self.stdout.write(f'✅ Added custom directory: {dir_path}')
            else:
                self.stdout.write(self.style.WARNING(f'⚠️  Directory not found: {dir_path}'))
        
        # Add Celestia directories if base exists
        if Path(celestia_base).exists():
            celestia_dirs = [
                f'{celestia_base}/40k-nuclei-templates',
                f'{celestia_base}/nuclei-templates',
                f'{celestia_base}/nuclei-templates-ai',
            ]
            
            for dir_path in celestia_dirs:
                path = Path(dir_path)
                if path.exists():
                    directories_to_scan.append(str(path))
                    self.stdout.write(f'✅ Found Celestia directory: {dir_path}')
                else:
                    self.stdout.write(self.style.WARNING(f'⚠️  Celestia directory not found: {dir_path}'))
        else:
            self.stdout.write(self.style.WARNING(f'⚠️  Celestia base directory not found: {celestia_base}'))
        
        if not directories_to_scan:
            self.stdout.write(self.style.ERROR('❌ No directories found to scan!'))
            return
        
        # Initialize registry with custom directories
        # Use the first directory as primary, or None to use default
        primary_dir = directories_to_scan[0] if directories_to_scan else None
        additional_dirs = directories_to_scan[1:] if len(directories_to_scan) > 1 else []
        
        try:
            registry = OakTemplateRegistryService(
                templates_dir=primary_dir,
                additional_dirs=additional_dirs
            )
            
            self.stdout.write(f'\n📤 Starting template scan...')
            self.stdout.write(f'   Primary directory: {registry.templates_dir}')
            self.stdout.write(f'   Additional directories: {len(registry.additional_dirs)}')
            
            result = registry.scan_and_index_templates(force_rescan=force_rescan)
            
            self.stdout.write('\n' + '=' * 60)
            self.stdout.write(self.style.SUCCESS('✅ Scan complete!'))
            self.stdout.write(f'   Scanned: {result.get("scanned", 0)}')
            self.stdout.write(f'   Indexed: {result.get("indexed", 0)}')
            self.stdout.write(f'   Updated: {result.get("updated", 0)}')
            self.stdout.write(f'   Errors: {result.get("errors", 0)}')
            
            if result.get('total_templates'):
                self.stdout.write(f'   Total templates in DB: {result.get("total_templates")}')
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Error during scan: {e}'))
            logger.exception('Error indexing Celestia templates')
            raise
