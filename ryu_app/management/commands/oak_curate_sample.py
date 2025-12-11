#!/usr/bin/env python3
"""
Django management command to force-curate a sample of EggRecords with Oak.

Usage:
    python manage.py oak_curate_sample --count 10
    python manage.py oak_curate_sample --count 10 --alive-only
"""

from django.core.management.base import BaseCommand
from django.db import connections
import random
import json
from datetime import datetime


class Command(BaseCommand):
    help = 'Force-curate a sample of random EggRecords with Oak'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=10,
            help='Number of EggRecords to curate (default: 10)'
        )
        parser.add_argument(
            '--alive-only',
            action='store_true',
            help='Only curate alive EggRecords'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output for each curation'
        )

    def handle(self, *args, **options):
        count = options['count']
        alive_only = options.get('alive_only', False)
        verbose = options.get('verbose', False)
        
        self.stdout.write(f"🌳 Oak Sample Curation - Selecting {count} random EggRecords...")
        
        # Get random EggRecords
        try:
            db = connections['customer_eggs']
        except KeyError:
            db = connections['default']
        
        with db.cursor() as cursor:
            # Build query
            where_clause = "WHERE 1=1"
            if alive_only:
                where_clause += " AND alive = true"
            
            # Get random sample
            cursor.execute(f"""
                SELECT id, "subDomain", domainname, alive
                FROM customer_eggs_eggrecords_general_models_eggrecord
                {where_clause}
                ORDER BY RANDOM()
                LIMIT %s
            """, [count])
            
            egg_records = cursor.fetchall()
            
            if not egg_records:
                self.stdout.write(self.style.WARNING("No EggRecords found matching criteria"))
                return
            
            self.stdout.write(f"✅ Found {len(egg_records)} EggRecords to curate\n")
            
            # Import curation service
            try:
                from artificial_intelligence.personalities.reconnaissance.oak.target_curation.target_curation_service import (
                    OakTargetCurationService
                )
            except (ImportError, ModuleNotFoundError) as e:
                self.stdout.write(self.style.ERROR(f"Failed to import Oak curation service: {e}"))
                self.stdout.write(self.style.WARNING("Note: This may be due to missing Bugsy security services."))
                self.stdout.write(self.style.WARNING("Oak can work without Bugsy, but CVE correlation may be limited."))
                return
            
            curation_service = OakTargetCurationService()
            results = []
            
            # Curate each EggRecord
            for idx, (egg_id, subdomain, domainname, alive) in enumerate(egg_records, 1):
                subdomain_name = subdomain or domainname or str(egg_id)
                self.stdout.write(f"\n[{idx}/{len(egg_records)}] Curating: {subdomain_name} (ID: {egg_id})")
                
                # Create simple object for EggRecord
                class SimpleEggRecord:
                    def __init__(self, egg_id, subdomain, domainname, alive):
                        self.id = egg_id
                        self.subDomain = subdomain
                        self.domainname = domainname
                        self.alive = alive
                
                egg_record = SimpleEggRecord(egg_id, subdomain, domainname, alive)
                
                try:
                    # Perform curation
                    result = curation_service.curate_subdomain(egg_record)
                    
                    # Store result
                    curation_result = {
                        'egg_record_id': str(egg_id),
                        'subdomain': subdomain_name,
                        'alive': alive,
                        'success': result.get('success', False),
                        'fingerprints_created': result.get('fingerprints_created', 0),
                        'cve_matches': result.get('cve_matches', 0),
                        'recommendations': result.get('recommendations', 0),
                        'confidence_score': result.get('confidence_score', 0.0),
                        'templates_selected': result.get('templates_selected', 0),
                        'steps_completed': result.get('steps_completed', []),
                        'error': result.get('error') if not result.get('success') else None
                    }
                    
                    # Add template details if available
                    if result.get('nuclei_templates'):
                        nuclei_templates = result.get('nuclei_templates', {})
                        curation_result['nuclei_template_count'] = nuclei_templates.get('template_count', 0)
                        curation_result['nuclei_template_sources'] = {
                            'fingerprints_used': nuclei_templates.get('fingerprints_used', 0),
                            'cve_matches_used': nuclei_templates.get('cve_matches_used', 0),
                            'open_ports_used': nuclei_templates.get('open_ports_used', 0)
                        }
                    
                    results.append(curation_result)
                    
                    # Display result
                    if result.get('success'):
                        self.stdout.write(self.style.SUCCESS(f"  ✅ Success"))
                        self.stdout.write(f"     Fingerprints: {curation_result['fingerprints_created']}")
                        self.stdout.write(f"     CVE Matches: {curation_result['cve_matches']}")
                        self.stdout.write(f"     Recommendations: {curation_result['recommendations']}")
                        self.stdout.write(f"     Confidence: {curation_result['confidence_score']:.1f}%")
                        self.stdout.write(f"     Templates Selected: {curation_result['templates_selected']}")
                        
                        if verbose:
                            self.stdout.write(f"     Steps: {', '.join(curation_result['steps_completed'])}")
                    else:
                        self.stdout.write(self.style.ERROR(f"  ❌ Failed: {result.get('error', 'Unknown error')}"))
                        
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"  ❌ Exception: {str(e)}"))
                    results.append({
                        'egg_record_id': str(egg_id),
                        'subdomain': subdomain_name,
                        'success': False,
                        'error': str(e)
                    })
            
            # Summary
            self.stdout.write("\n" + "="*60)
            self.stdout.write(self.style.SUCCESS("📊 Curation Summary"))
            self.stdout.write("="*60)
            
            successful = sum(1 for r in results if r.get('success'))
            total_fingerprints = sum(r.get('fingerprints_created', 0) for r in results)
            total_cves = sum(r.get('cve_matches', 0) for r in results)
            total_templates = sum(r.get('templates_selected', 0) for r in results)
            avg_confidence = sum(r.get('confidence_score', 0.0) for r in results) / len(results) if results else 0.0
            
            self.stdout.write(f"Total Curated: {len(results)}")
            self.stdout.write(f"Successful: {successful} ({successful/len(results)*100:.1f}%)")
            self.stdout.write(f"Total Fingerprints Created: {total_fingerprints}")
            self.stdout.write(f"Total CVE Matches: {total_cves}")
            self.stdout.write(f"Total Templates Selected: {total_templates}")
            self.stdout.write(f"Average Confidence Score: {avg_confidence:.1f}%")
            
            # Save results to file
            output_file = f"oak_curation_sample_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'count': count,
                    'alive_only': alive_only,
                    'summary': {
                        'total': len(results),
                        'successful': successful,
                        'total_fingerprints': total_fingerprints,
                        'total_cves': total_cves,
                        'total_templates': total_templates,
                        'avg_confidence': avg_confidence
                    },
                    'results': results
                }, f, indent=2)
            
            self.stdout.write(f"\n💾 Detailed results saved to: {output_file}")
            self.stdout.write(self.style.SUCCESS("\n✅ Sample curation complete!"))

