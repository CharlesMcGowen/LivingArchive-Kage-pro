#!/usr/bin/env python3
"""
Management command to seed a default network map for 192.168.1.0/24
Creates sample hosts with IPs, technologies, and services
"""
from django.core.management.base import BaseCommand
from django.db import connections
from django.utils import timezone
import uuid
import json
import ipaddress


class Command(BaseCommand):
    help = 'Seed default network map for 192.168.1.0/24 with sample hosts and technologies'

    def add_arguments(self, parser):
        parser.add_argument(
            '--cidr',
            type=str,
            default='192.168.1.0/24',
            help='CIDR range to seed (default: 192.168.1.0/24)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing sample data before seeding'
        )

    def handle(self, *args, **options):
        cidr_str = options['cidr']
        clear_existing = options['clear']
        
        self.stdout.write(f"🌐 Seeding network map for {cidr_str}...")
        
        # Parse CIDR
        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError as e:
            self.stdout.write(self.style.ERROR(f"Invalid CIDR: {e}"))
            return
        
        conn = connections['customer_eggs']
        
        # Sample hosts with technologies
        sample_hosts = [
            {
                'ip': '192.168.1.1',
                'hostname': 'gateway',
                'domain': 'gateway.local',
                'technologies': ['RouterOS', 'MikroTik'],
                'ports': [80, 443, 22, 8080],
                'services': ['http', 'https', 'ssh', 'http-proxy']
            },
            {
                'ip': '192.168.1.10',
                'hostname': 'webserver',
                'domain': 'web.local',
                'technologies': ['Apache', 'PHP', 'MySQL', 'WordPress'],
                'ports': [80, 443, 3306, 22],
                'services': ['http', 'https', 'mysql', 'ssh']
            },
            {
                'ip': '192.168.1.20',
                'hostname': 'fileserver',
                'domain': 'files.local',
                'technologies': ['Samba', 'NFS', 'FTP'],
                'ports': [21, 22, 139, 445, 2049],
                'services': ['ftp', 'ssh', 'netbios-ssn', 'microsoft-ds', 'nfs']
            },
            {
                'ip': '192.168.1.30',
                'hostname': 'database',
                'domain': 'db.local',
                'technologies': ['PostgreSQL', 'Redis', 'MongoDB'],
                'ports': [5432, 6379, 27017, 22],
                'services': ['postgresql', 'redis', 'mongodb', 'ssh']
            },
            {
                'ip': '192.168.1.40',
                'hostname': 'appserver',
                'domain': 'app.local',
                'technologies': ['Node.js', 'Docker', 'Nginx'],
                'ports': [80, 443, 3000, 8080, 22],
                'services': ['http', 'https', 'http-alt', 'http-proxy', 'ssh']
            },
            {
                'ip': '192.168.1.50',
                'hostname': 'monitoring',
                'domain': 'monitor.local',
                'technologies': ['Grafana', 'Prometheus', 'InfluxDB'],
                'ports': [3000, 9090, 8086, 22],
                'services': ['http-alt', 'prometheus', 'influxdb', 'ssh']
            },
            {
                'ip': '192.168.1.100',
                'hostname': 'printer',
                'domain': 'printer.local',
                'technologies': ['HP Printer', 'CUPS'],
                'ports': [80, 443, 631, 9100],
                'services': ['http', 'https', 'ipp', 'jetdirect']
            },
            {
                'ip': '192.168.1.150',
                'hostname': 'nas',
                'domain': 'nas.local',
                'technologies': ['Synology', 'SMB', 'AFP'],
                'ports': [80, 443, 5000, 5001, 139, 445],
                'services': ['http', 'https', 'http-alt', 'https-alt', 'netbios-ssn', 'microsoft-ds']
            },
            {
                'ip': '192.168.1.200',
                'hostname': 'camera',
                'domain': 'camera.local',
                'technologies': ['IP Camera', 'RTSP', 'ONVIF'],
                'ports': [80, 554, 8554],
                'services': ['http', 'rtsp', 'rtsp-alt']
            },
            {
                'ip': '192.168.1.254',
                'hostname': 'switch',
                'domain': 'switch.local',
                'technologies': ['Cisco Switch', 'SNMP'],
                'ports': [23, 80, 161],
                'services': ['telnet', 'http', 'snmp']
            }
        ]
        
        # Filter hosts that are in the CIDR range
        valid_hosts = []
        for host in sample_hosts:
            try:
                ip = ipaddress.ip_address(host['ip'])
                if ip in network:
                    valid_hosts.append(host)
            except ValueError:
                continue
        
        if not valid_hosts:
            self.stdout.write(self.style.WARNING(f"No valid hosts found in {cidr_str}"))
            return
        
        self.stdout.write(f"📋 Creating {len(valid_hosts)} sample hosts...")
        
        with conn.cursor() as cursor:
            # Clear existing sample data if requested
            if clear_existing:
                self.stdout.write("🗑️  Clearing existing sample data...")
                # Delete sample eggrecords (those with IPs in the CIDR range)
                cursor.execute("""
                    DELETE FROM customer_eggs_eggrecords_general_models_nmap
                    WHERE record_id_id IN (
                        SELECT id FROM customer_eggs_eggrecords_general_models_eggrecord
                        WHERE ip_address::text LIKE %s
                    )
                """, [f"{network.network_address}/%"])
                
                cursor.execute("""
                    DELETE FROM customer_eggs_eggrecords_general_models_eggrecord
                    WHERE ip_address::text LIKE %s
                """, [f"{network.network_address}/%"])
                
                conn.commit()
                self.stdout.write(self.style.SUCCESS("✅ Cleared existing sample data"))
            
            # Create eggrecords and nmap scans
            created_count = 0
            for host in valid_hosts:
                try:
                    # Create eggrecord
                    eggrecord_id = str(uuid.uuid4())
                    eggname = f"sample-{host['hostname']}"
                    projectegg = "sample-network"
                    
                    # Generate MD5 hash
                    import hashlib
                    md5_hash = hashlib.md5(f"{host['ip']}:{host['domain']}".encode()).hexdigest()
                    
                    # Prepare JSON fields
                    ip_json = json.dumps([host['ip']])
                    open_ports_json = json.dumps(host['ports'])
                    technologies_json = json.dumps(host['technologies'])
                    
                    cursor.execute("""
                        INSERT INTO customer_eggs_eggrecords_general_models_eggrecord
                        (id, record_type, title, description, data, status, priority, created_at, updated_at,
                         md5, domainname, "subDomain", "dateCreated", "lastScan", "skipScan", alive, "nucleiBool",
                         ip, "Ipv6Scope", "OpenPorts", "CertBool", "CMS", "ASN", "Images", aws_scan, url, "agents_worked",
                         "agent_scan_history", "wordlists_used", current_project, last_agent_activity, total_agent_scans,
                         "vulnerabilities_found_by_agents", rescan_interval_days, next_scan_date, scan_priority,
                         scan_lock, scan_lock_agent, scan_lock_expires, total_scan_count, last_scan_duration_seconds,
                         last_scan_success, last_scan_findings_count, "scan_schedule_metadata", assigned_scan_agent,
                         scan_coordination_notes, ip_address, eggname, projectegg)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            "subDomain" = EXCLUDED."subDomain",
                            domainname = EXCLUDED.domainname,
                            ip_address = EXCLUDED.ip_address,
                            updated_at = EXCLUDED.updated_at
                    """, [
                        eggrecord_id,  # id
                        'network_host',  # record_type
                        f"{host['hostname']} - {host['ip']}",  # title
                        f"Sample network host with technologies: {', '.join(host['technologies'])}",  # description
                        json.dumps({'technologies': host['technologies']}),  # data
                        'active',  # status
                        'medium',  # priority
                        timezone.now(),  # created_at
                        timezone.now(),  # updated_at
                        md5_hash,  # md5
                        host['domain'],  # domainname
                        host['hostname'],  # subDomain
                        timezone.now(),  # dateCreated
                        timezone.now().date(),  # lastScan
                        False,  # skipScan
                        True,  # alive
                        False,  # nucleiBool
                        ip_json,  # ip
                        json.dumps([]),  # Ipv6Scope
                        open_ports_json,  # OpenPorts
                        False,  # CertBool
                        '',  # CMS
                        json.dumps({}),  # ASN
                        '',  # Images
                        False,  # aws_scan
                        f"http://{host['ip']}",  # url
                        json.dumps([]),  # agents_worked
                        json.dumps([]),  # agent_scan_history
                        json.dumps([]),  # wordlists_used
                        projectegg,  # current_project
                        None,  # last_agent_activity
                        0,  # total_agent_scans
                        json.dumps([]),  # vulnerabilities_found_by_agents
                        30,  # rescan_interval_days
                        None,  # next_scan_date
                        'normal',  # scan_priority
                        False,  # scan_lock
                        '',  # scan_lock_agent
                        None,  # scan_lock_expires
                        0,  # total_scan_count
                        None,  # last_scan_duration_seconds
                        None,  # last_scan_success
                        0,  # last_scan_findings_count
                        json.dumps({}),  # scan_schedule_metadata
                        '',  # assigned_scan_agent
                        '',  # scan_coordination_notes
                        host['ip'],  # ip_address
                        eggname,  # eggname
                        projectegg  # projectegg
                    ])
                    
                    # Create nmap scan for each open port
                    for port, service in zip(host['ports'], host['services']):
                        nmap_id = str(uuid.uuid4())
                        open_ports_json = json.dumps([{
                            'port': port,
                            'protocol': 'tcp',
                            'service': service,
                            'state': 'open'
                        }])
                        
                        cursor.execute("""
                            INSERT INTO customer_eggs_eggrecords_general_models_nmap
                            (id, record_id_id, target, scan_type, scan_stage, scan_status,
                             port, service_name, open_ports, scan_command, name, hostname,
                             date, created_at, updated_at, md5)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, [
                            nmap_id,
                            eggrecord_id,
                            host['ip'],
                            'kage_port_scan',
                            'completed',
                            'completed',
                            port,
                            service,
                            open_ports_json,
                            f"nmap -p {port} {host['ip']}",
                            host['hostname'],
                            host['ip'],
                            timezone.now(),
                            timezone.now(),
                            timezone.now(),
                            str(uuid.uuid4())[:32]  # MD5 hash
                        ])
                    
                    created_count += 1
                    self.stdout.write(f"  ✅ Created {host['hostname']} ({host['ip']}) with {len(host['ports'])} services")
                    
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"  ❌ Error creating {host['hostname']}: {e}"))
                    continue
            
            conn.commit()
            
            self.stdout.write(self.style.SUCCESS(
                f"\n✅ Successfully created {created_count} hosts in {cidr_str}\n"
                f"🌐 View the network map at: http://127.0.0.1:9000/reconnaissance/network/?filter_cidr={cidr_str.replace('/', '%2F')}"
            ))

