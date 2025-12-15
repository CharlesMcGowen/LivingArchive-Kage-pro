"""
Django management command to backfill IP addresses for eggrecords
from existing nmap scans and DNS resolution.
"""
from django.core.management.base import BaseCommand
from django.db import connections
from django.utils import timezone
import socket
import ipaddress
import json
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Backfill IP addresses for eggrecords from existing nmap scans'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be updated without making changes',
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=None,
            help='Limit number of records to process',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Update records even if they already have IP addresses',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        limit = options.get('limit')
        force = options.get('force')

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))

        if 'customer_eggs' not in connections.databases:
            self.stdout.write(self.style.ERROR('customer_eggs database not configured'))
            return

        db = connections['customer_eggs']
        
        # Find eggrecords that need IP addresses
        with db.cursor() as cursor:
            if force:
                # Get all eggrecords with nmap scans
                query = """
                    SELECT DISTINCT ON (er.id) er.id, er."subDomain", er.domainname, er.ip_address, er.ip, er.updated_at
                    FROM customer_eggs_eggrecords_general_models_eggrecord er
                    INNER JOIN customer_eggs_eggrecords_general_models_nmap n ON n.record_id_id = er.id
                    WHERE er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL
                    ORDER BY er.id, er.updated_at DESC
                """
            else:
                # Get eggrecords without IP addresses that have nmap scans
                query = """
                    SELECT DISTINCT ON (er.id) er.id, er."subDomain", er.domainname, er.ip_address, er.ip, er.updated_at
                    FROM customer_eggs_eggrecords_general_models_eggrecord er
                    INNER JOIN customer_eggs_eggrecords_general_models_nmap n ON n.record_id_id = er.id
                    WHERE (er.ip_address IS NULL OR er.ip = '[]'::jsonb OR er.ip IS NULL)
                      AND (er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL)
                    ORDER BY er.id, er.updated_at DESC
                """
            
            if limit:
                query += f" LIMIT {limit}"
            
            cursor.execute(query)
            records = cursor.fetchall()
        
        self.stdout.write(f"Found {len(records)} eggrecords to process")
        
        updated_count = 0
        error_count = 0
        skipped_count = 0

        for record in records:
            record_id, subdomain, domainname, current_ip, current_ip_json = record[:5]
            target = subdomain or domainname
            
            if not target:
                skipped_count += 1
                continue
            
            try:
                # Try to resolve IP address
                ip_address = None
                ipv6_addresses = []
                all_ips = []

                # Try IPv4 resolution
                try:
                    ip_address = socket.gethostbyname(target)
                    all_ips.append(ip_address)
                    self.stdout.write(f"  Resolved {target} -> {ip_address}")
                except socket.gaierror as e:
                    self.stdout.write(self.style.WARNING(f"  Could not resolve {target}: {e}"))
                    # Try to check if target is already an IP address
                    try:
                        ipaddress.IPv4Address(target)
                        ip_address = target
                        all_ips.append(target)
                        self.stdout.write(f"  Target is IPv4 address: {target}")
                    except ValueError:
                        try:
                            ipaddress.IPv6Address(target)
                            ip_address = target
                            all_ips.append(target)
                            self.stdout.write(f"  Target is IPv6 address: {target}")
                        except ValueError:
                            pass
                
                # Try to get IPv6 addresses
                try:
                    addr_info = socket.getaddrinfo(target, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    for info in addr_info:
                        addr = info[4][0]
                        try:
                            ipaddress.IPv6Address(addr)
                            if addr not in all_ips:
                                ipv6_addresses.append(addr)
                                all_ips.append(addr)
                        except ValueError:
                            pass
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f"  Could not get IPv6 addresses for {target}: {e}"))
                
                # If we found IP addresses, update the record
                if all_ips:
                    # Get primary IPv4 address for ip_address field
                    primary_ip = None
                    for ip in all_ips:
                        try:
                            ipaddress.IPv4Address(ip)
                            primary_ip = ip
                            break
                        except ValueError:
                            pass
                    
                    # If no IPv4, use first IP
                    if not primary_ip and all_ips:
                        primary_ip = all_ips[0]
                    
                    if primary_ip:
                        if dry_run:
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f"  [DRY RUN] Would update {target} (ID: {record_id}) "
                                    f"with IP: {primary_ip} (total: {len(all_ips)} IPs)"
                                )
                            )
                        else:
                            with db.cursor() as update_cursor:
                                update_cursor.execute("""
                                    UPDATE customer_eggs_eggrecords_general_models_eggrecord
                                    SET ip_address = %s::inet,
                                        ip = %s::jsonb,
                                        updated_at = %s
                                    WHERE id = %s
                                """, [
                                    primary_ip,
                                    json.dumps(all_ips),
                                    timezone.now(),
                                    str(record_id)
                                ])
                                db.commit()
                            
                            self.stdout.write(
                                self.style.SUCCESS(
                                    f"  ✅ Updated {target} (ID: {record_id}) "
                                    f"with IP: {primary_ip} (total: {len(all_ips)} IPs)"
                                )
                            )
                        updated_count += 1
                    else:
                        skipped_count += 1
                        self.stdout.write(
                            self.style.WARNING(
                                f"  ⚠️  No valid IP address found for {target} (ID: {record_id})"
                            )
                        )
                else:
                    skipped_count += 1
                    self.stdout.write(
                        self.style.WARNING(
                            f"  ⚠️  Could not resolve IP address for {target} (ID: {record_id})"
                        )
                    )
                    
            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(f"  ❌ Error processing {target} (ID: {record_id}): {e}")
                )
        
        # Summary
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write(self.style.SUCCESS("Backfill Summary:"))
        self.stdout.write(f"  Total records processed: {len(records)}")
        self.stdout.write(f"  Updated: {updated_count}")
        self.stdout.write(f"  Skipped: {skipped_count}")
        self.stdout.write(f"  Errors: {error_count}")
        if dry_run:
            self.stdout.write(self.style.WARNING("  (DRY RUN - No actual changes made)"))
