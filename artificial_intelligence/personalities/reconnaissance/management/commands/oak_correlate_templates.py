#!/usr/bin/env python3
"""
Oak Template Correlation Management Command
===========================================

Manually trigger Oak to perform correlation operations against EggRecords
using Nmap scan data to assign Nuclei templates.

Usage:
    python manage.py oak_correlate_templates --limit 50
    python manage.py oak_correlate_templates --limit 100 --min-confidence 0.7
    python manage.py oak_correlate_templates --egg-record-id <uuid>
    python manage.py oak_correlate_templates --subdomain example.com
"""

from django.core.management.base import BaseCommand
from django.db import connections, transaction
from django.db.models import Q
from django.utils import timezone
import logging
from typing import List, Dict, Optional, TYPE_CHECKING
import uuid

if TYPE_CHECKING:
    from artificial_intelligence.customer_eggs_eggrecords_general_models.models import EggRecord

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Manually trigger Oak to correlate Nuclei templates with EggRecords using Nmap data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=50,
            help='Maximum number of EggRecords to process (default: 50)'
        )
        parser.add_argument(
            '--min-confidence',
            type=float,
            default=0.5,
            help='Minimum confidence score for technology fingerprints (default: 0.5)'
        )
        parser.add_argument(
            '--egg-record-id',
            type=str,
            help='Process a specific EggRecord by UUID'
        )
        parser.add_argument(
            '--subdomain',
            type=str,
            help='Process a specific EggRecord by subdomain'
        )
        parser.add_argument(
            '--max-templates',
            type=int,
            default=20,
            help='Maximum number of templates to assign per EggRecord (default: 20)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force re-correlation even if templates already exist'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )

    def handle(self, *args, **options):
        limit = options['limit']
        min_confidence = options['min_confidence']
        egg_record_id = options.get('egg_record_id')
        subdomain = options.get('subdomain')
        max_templates = options['max_templates']
        force = options['force']
        dry_run = options['dry_run']

        self.stdout.write(self.style.SUCCESS('🌳 Oak Template Correlation Command'))
        self.stdout.write('=' * 60)

        # Import Oak services
        try:
            from artificial_intelligence.personalities.reconnaissance.oak.nmap_coordination_service import (
                OakNmapCoordinationService
            )
            from artificial_intelligence.customer_eggs_eggrecords_general_models.models import (
                EggRecord, Nmap
            )
        except ImportError:
            try:
                from customer_eggs_eggrecords_general_models.models import (
                    EggRecord, Nmap
                )
                from artificial_intelligence.personalities.reconnaissance.oak.nmap_coordination_service import (
                    OakNmapCoordinationService
                )
            except ImportError as e:
                self.stdout.write(self.style.ERROR(f'❌ Import error: {e}'))
                return

        nmap_coord = OakNmapCoordinationService()

        # Get EggRecords to process
        egg_records = self._get_egg_records(
            egg_record_id=egg_record_id,
            subdomain=subdomain,
            limit=limit,
            force=force
        )

        if not egg_records:
            self.stdout.write(self.style.WARNING('⚠️  No EggRecords found to process'))
            return

        self.stdout.write(f'📋 Found {len(egg_records)} EggRecord(s) to process')
        self.stdout.write('')

        # Process each EggRecord
        stats = {
            'processed': 0,
            'success': 0,
            'failed': 0,
            'templates_assigned': 0,
            'relationships_created': 0
        }

        for i, egg_record in enumerate(egg_records, 1):
            subdomain_name = egg_record.subDomain or egg_record.domainname or str(egg_record.id)
            self.stdout.write(f'[{i}/{len(egg_records)}] Processing: {subdomain_name}')

            try:
                # Check if Nmap scan exists
                nmap_scans = Nmap.objects.filter(
                    record_id_id=egg_record.id,
                    scan_status='completed'
                ).order_by('-created_at')[:1]

                if not nmap_scans.exists():
                    self.stdout.write(
                        self.style.WARNING(f'  ⚠️  No completed Nmap scan found, skipping...')
                    )
                    stats['failed'] += 1
                    continue

                # Check for existing templates if not forcing
                if not force:
                    existing_templates = self._get_existing_templates(str(egg_record.id))
                    if existing_templates:
                        self.stdout.write(
                            self.style.WARNING(
                                f'  ⚠️  Already has {len(existing_templates)} template(s), skipping (use --force to override)'
                            )
                        )
                        stats['processed'] += 1
                        continue

                if dry_run:
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✅ Would correlate templates (dry-run)')
                    )
                    stats['processed'] += 1
                    continue

                # Perform correlation
                result = nmap_coord.select_nuclei_templates_for_egg_record(
                    egg_record=egg_record,
                    max_templates=max_templates
                )

                if result.get('success'):
                    template_count = result.get('template_count', 0)
                    relationships = result.get('relationships_created', 0)
                    
                    stats['success'] += 1
                    stats['templates_assigned'] += template_count
                    stats['relationships_created'] += relationships

                    self.stdout.write(
                        self.style.SUCCESS(
                            f'  ✅ Assigned {template_count} template(s), created {relationships} relationship(s)'
                        )
                    )

                    # Show sample templates
                    templates = result.get('templates', [])[:5]
                    if templates:
                        self.stdout.write('  📝 Sample templates:')
                        for template in templates:
                            self.stdout.write(
                                f'     - {template.get("template_id")} '
                                f'({template.get("priority", "medium")} priority)'
                            )
                else:
                    error = result.get('error', 'Unknown error')
                    self.stdout.write(
                        self.style.ERROR(f'  ❌ Failed: {error}')
                    )
                    stats['failed'] += 1

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Error: {str(e)}')
                )
                logger.exception(f"Error processing EggRecord {egg_record.id}")
                stats['failed'] += 1

            stats['processed'] += 1
            self.stdout.write('')

        # Print summary
        self.stdout.write('=' * 60)
        self.stdout.write(self.style.SUCCESS('📊 Summary:'))
        self.stdout.write(f'  Processed: {stats["processed"]}')
        self.stdout.write(f'  Successful: {stats["success"]}')
        self.stdout.write(f'  Failed: {stats["failed"]}')
        self.stdout.write(f'  Templates assigned: {stats["templates_assigned"]}')
        self.stdout.write(f'  Relationships created: {stats["relationships_created"]}')

    def _get_egg_records(self, egg_record_id: Optional[str] = None,
                        subdomain: Optional[str] = None,
                        limit: int = 50,
                        force: bool = False) -> List:
        """Get EggRecords to process."""
        try:
            from artificial_intelligence.customer_eggs_eggrecords_general_models.models import (
                EggRecord, Nmap
            )
        except ImportError:
            from customer_eggs_eggrecords_general_models.models import (
                EggRecord, Nmap
            )
        
        queryset = EggRecord.objects.filter(alive=True, skipScan=False)

        # Filter by specific criteria
        if egg_record_id:
            try:
                uuid_obj = uuid.UUID(egg_record_id)
                queryset = queryset.filter(id=uuid_obj)
            except ValueError:
                self.stdout.write(self.style.ERROR(f'Invalid UUID: {egg_record_id}'))
                return []

        if subdomain:
            queryset = queryset.filter(
                Q(subDomain__icontains=subdomain) |
                Q(domainname__icontains=subdomain)
            )

        # Only get records with completed Nmap scans
        queryset = queryset.filter(
            id__in=Nmap.objects.filter(
                scan_status='completed'
            ).values_list('record_id_id', flat=True).distinct()
        )

        # Order by priority or recency
        queryset = queryset.order_by(
            '-bugsy_priority_score',
            '-bugsy_last_curated_at',
            '-created_at'
        )

        return list(queryset[:limit])

    def _get_existing_templates(self, egg_record_id: str) -> List[Dict]:
        """Check for existing template recommendations."""
        try:
            with transaction.atomic(using='eggrecords'):
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']

                with db.cursor() as cursor:
                    cursor.execute("""
                        SELECT template_id, status, priority
                        FROM enrichment_system_nucleitemplaterecommendation
                        WHERE egg_record_id = %s
                        LIMIT 10
                    """, [egg_record_id])

                    templates = []
                    for row in cursor.fetchall():
                        templates.append({
                            'template_id': row[0],
                            'status': row[1],
                            'priority': row[2]
                        })

                    return templates
        except Exception as e:
            logger.debug(f"Error checking existing templates: {e}")
            return []
