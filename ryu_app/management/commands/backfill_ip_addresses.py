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
            '--batch-size',
            type=int,
            default=500,
            help='Process records in batches of this size (default: 500)',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Update records even if they already have IP addresses',
        )
        parser.add_argument(
            '--all-records',
            action='store_true',
            help='Process ALL eggrecords, not just those with nmap scans',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        limit = options.get('limit')
        batch_size = options.get('batch_size', 500)
        force = options.get('force')
        all_records = options.get('all_records', False)

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))

        if 'customer_eggs' not in connections.databases:
            self.stdout.write(self.style.ERROR('customer_eggs database not configured'))
            return

        db = connections['customer_eggs']
        
        # First, get total count
        with db.cursor() as count_cursor:
            if all_records:
                # Count ALL eggrecords
                if force:
                    count_query = """
                        SELECT COUNT(*)
                        FROM customer_eggs_eggrecords_general_models_eggrecord er
                        WHERE er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL
                    """
                else:
                    count_query = """
                        SELECT COUNT(*)
                        FROM customer_eggs_eggrecords_general_models_eggrecord er
                        WHERE (er.ip_address IS NULL OR er.ip = '[]'::jsonb OR er.ip IS NULL)
                          AND (er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL)
                    """
            else:
                # Count only records with nmap scans
                if force:
                    count_query = """
                        SELECT COUNT(DISTINCT er.id)
                        FROM customer_eggs_eggrecords_general_models_eggrecord er
                        INNER JOIN customer_eggs_eggrecords_general_models_nmap n ON n.record_id_id = er.id
                        WHERE er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL
                    """
                else:
                    count_query = """
                        SELECT COUNT(DISTINCT er.id)
                        FROM customer_eggs_eggrecords_general_models_eggrecord er
                        INNER JOIN customer_eggs_eggrecords_general_models_nmap n ON n.record_id_id = er.id
                        WHERE (er.ip_address IS NULL OR er.ip = '[]'::jsonb OR er.ip IS NULL)
                          AND (er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL)
                    """
            count_cursor.execute(count_query)
            total_count = count_cursor.fetchone()[0] or 0
        
        self.stdout.write(f"Found {total_count} total eggrecords to process")
        if all_records:
            self.stdout.write(self.style.WARNING("Processing ALL eggrecords (not just those with nmap scans)"))
        if limit:
            self.stdout.write(f"Processing with limit: {limit}")
        else:
            self.stdout.write(f"Processing in batches of {batch_size}")
        
        # Process in batches to avoid memory issues
        offset = 0
        all_updated_count = 0
        all_error_count = 0
        all_skipped_count = 0
        processed_total = 0
        
        while True:
            # Find eggrecords that need IP addresses (batch query)
            with db.cursor() as cursor:
                if all_records:
                    # Process ALL eggrecords
                    if force:
                        query = """
                            SELECT er.id, er."subDomain", er.domainname, er.ip_address, er.ip, er.updated_at
                            FROM customer_eggs_eggrecords_general_models_eggrecord er
                            WHERE er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL
                            ORDER BY er.id
                            OFFSET %s
                            LIMIT %s
                        """
                    else:
                        query = """
                            SELECT er.id, er."subDomain", er.domainname, er.ip_address, er.ip, er.updated_at
                            FROM customer_eggs_eggrecords_general_models_eggrecord er
                            WHERE (er.ip_address IS NULL OR er.ip = '[]'::jsonb OR er.ip IS NULL)
                              AND (er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL)
                            ORDER BY er.id
                            OFFSET %s
                            LIMIT %s
                        """
                else:
                    # Process only records with nmap scans
                    if force:
                        query = """
                            SELECT er.id, er."subDomain", er.domainname, er.ip_address, er.ip, er.updated_at
                            FROM customer_eggs_eggrecords_general_models_eggrecord er
                            WHERE er.id IN (
                                SELECT DISTINCT n.record_id_id
                                FROM customer_eggs_eggrecords_general_models_nmap n
                                WHERE n.record_id_id IS NOT NULL
                            )
                            AND (er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL)
                            ORDER BY er.id
                            OFFSET %s
                            LIMIT %s
                        """
                    else:
                        query = """
                            SELECT er.id, er."subDomain", er.domainname, er.ip_address, er.ip, er.updated_at
                            FROM customer_eggs_eggrecords_general_models_eggrecord er
                            WHERE er.id IN (
                                SELECT DISTINCT n.record_id_id
                                FROM customer_eggs_eggrecords_general_models_nmap n
                                WHERE n.record_id_id IS NOT NULL
                            )
                            AND (er.ip_address IS NULL OR er.ip = '[]'::jsonb OR er.ip IS NULL)
                            AND (er."subDomain" IS NOT NULL OR er.domainname IS NOT NULL)
                            ORDER BY er.id
                            OFFSET %s
                            LIMIT %s
                        """
                
                batch_limit = limit - processed_total if limit and (limit - processed_total) < batch_size else batch_size
                if limit and processed_total >= limit:
                    break
                
                cursor.execute(query, [offset, batch_limit])
                records = cursor.fetchall()
            
            if not records:
                # No more records to process
                self.stdout.write(f"\nNo more records found. Processed {processed_total} total records.")
                break
            
            self.stdout.write(f"\nProcessing batch: {offset + 1} to {offset + len(records)} of {total_count}...")
            
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
            
            # Accumulate counts
            all_updated_count += updated_count
            all_error_count += error_count
            all_skipped_count += skipped_count
            processed_total += len(records)
            
            # Update offset for next batch
            offset += len(records)
            
            # Show batch summary
            self.stdout.write(f"  Batch complete: Updated {updated_count}, Skipped {skipped_count}, Errors {error_count}")
            
            # Break if we've processed all records or hit the limit
            if len(records) < batch_limit:
                # Last batch was smaller than requested, we're done
                break
        
        # Final Summary
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=" * 60))
        self.stdout.write(self.style.SUCCESS("Backfill Summary:"))
        self.stdout.write(f"  Total records processed: {processed_total}")
        self.stdout.write(f"  Updated: {all_updated_count}")
        self.stdout.write(f"  Skipped: {all_skipped_count}")
        self.stdout.write(f"  Errors: {all_error_count}")
        if dry_run:
            self.stdout.write(self.style.WARNING("  (DRY RUN - No actual changes made)"))
