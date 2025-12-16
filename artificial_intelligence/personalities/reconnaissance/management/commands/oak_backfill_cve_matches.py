#!/usr/bin/env python3
"""
Oak CVE Match Backfill Command
================================

Backfill CVE matches for existing technology fingerprints.
This ensures all fingerprints get CVE intelligence for template correlation.

Usage:
    python manage.py oak_backfill_cve_matches --limit 100
    python manage.py oak_backfill_cve_matches --force
"""

from django.core.management.base import BaseCommand
from django.db.models import Q
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Backfill CVE matches for existing technology fingerprints'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Maximum number of fingerprints to process (default: 100)'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Re-create CVE matches even if they already exist'
        )

    def handle(self, *args, **options):
        limit = options['limit']
        force = options['force']

        self.stdout.write(self.style.SUCCESS('🌳 Oak CVE Match Backfill Command'))
        self.stdout.write('=' * 60)

        try:
            from artificial_intelligence.customer_eggs_eggrecords_general_models.models import (
                TechnologyFingerprint, CVEFingerprintMatch
            )
            from artificial_intelligence.personalities.reconnaissance.signals import (
                fingerprint_to_cve_correlation
            )
        except ImportError as e:
            self.stdout.write(self.style.ERROR(f'❌ Import error: {e}'))
            return

        # Get fingerprints without CVE matches (or all if force)
        if force:
            fingerprints = TechnologyFingerprint.objects.filter(
                confidence_score__gte=0.5
            ).order_by('-confidence_score', '-created_at')[:limit]
        else:
            # Get fingerprints that don't have CVE matches yet
            fingerprints_with_cves = CVEFingerprintMatch.objects.values_list(
                'technology_fingerprint_id', flat=True
            ).distinct()
            
            fingerprints = TechnologyFingerprint.objects.filter(
                confidence_score__gte=0.5
            ).exclude(
                id__in=fingerprints_with_cves
            ).order_by('-confidence_score', '-created_at')[:limit]

        total = fingerprints.count()
        self.stdout.write(f'📋 Found {total} fingerprint(s) to process')
        self.stdout.write('')

        stats = {
            'processed': 0,
            'cve_matches_created': 0,
            'failed': 0
        }

        for i, fingerprint in enumerate(fingerprints, 1):
            tech_name = fingerprint.technology_name or 'Unknown'
            self.stdout.write(f'[{i}/{total}] Processing: {tech_name} (confidence: {fingerprint.confidence_score:.2f})')

            try:
                before_count = CVEFingerprintMatch.objects.filter(
                    technology_fingerprint_id=fingerprint.id
                ).count()

                # Trigger CVE correlation signal
                fingerprint_to_cve_correlation(
                    sender=TechnologyFingerprint,
                    instance=fingerprint,
                    created=True
                )

                after_count = CVEFingerprintMatch.objects.filter(
                    technology_fingerprint_id=fingerprint.id
                ).count()

                created = after_count - before_count
                if created > 0:
                    stats['cve_matches_created'] += created
                    self.stdout.write(
                        self.style.SUCCESS(f'  ✅ Created {created} CVE match(es)')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'  ⚠️  No CVE matches found')
                    )

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ❌ Error: {str(e)[:100]}')
                )
                logger.exception(f"Error processing fingerprint {fingerprint.id}")
                stats['failed'] += 1

            stats['processed'] += 1

        # Print summary
        self.stdout.write('')
        self.stdout.write('=' * 60)
        self.stdout.write(self.style.SUCCESS('📊 Summary:'))
        self.stdout.write(f'  Processed: {stats["processed"]}')
        self.stdout.write(f'  CVE matches created: {stats["cve_matches_created"]}')
        self.stdout.write(f'  Failed: {stats["failed"]}')


