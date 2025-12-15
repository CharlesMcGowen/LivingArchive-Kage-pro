"""
Views for ryu_app.
"""
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.utils import timezone
from datetime import datetime, timedelta
import json
import ipaddress
import logging
import random
import os
from pathlib import Path
from .models import Project, Customer, EggRecord
from .postgres_models import PostgresEggRecord, PostgresNmap, PostgresRequestMetadata, PostgresDNSQuery
from .eggrecords_models import (
    KageWAFDetection, KageTechniqueEffectiveness, CalculatedHeuristicsRule,
    WAFDetectionDetail, IPTechniqueEffectiveness, TechnologyFingerprint, KageScanResult
)
from django.db import connections
from django.db.models import Count, Q, F, Avg, Max, Case, When, IntegerField
from django.db.utils import ProgrammingError, OperationalError, DatabaseError
from .mitre_mapping import get_mitre_mapper, map_finding_to_mitre_techniques

logger = logging.getLogger(__name__)


@csrf_exempt
def oak_nuclei_templates_api(request, egg_record_id):
    """
    API endpoint for Surge to query recommended Nuclei templates for an EggRecord.
    
    GET /api/oak/nuclei-templates/<egg_record_id>/
    
    Query params:
        - status: Filter by status ('pending', 'scanned', 'failed') - default: 'pending'
        - limit: Maximum number of templates to return - default: 20
    
    Returns:
        JSON with recommended templates and metadata including template_path for Surge
    """
    try:
        from artificial_intelligence.personalities.reconnaissance.oak.nmap_coordination_service import (
            OakNmapCoordinationService
        )
        from artificial_intelligence.personalities.reconnaissance.oak.template_registry_service import (
            OakTemplateRegistryService
        )
        
        status = request.GET.get('status', 'pending')
        limit = int(request.GET.get('limit', 20))
        
        nmap_coord = OakNmapCoordinationService()
        
        # Get recommended templates
        templates = nmap_coord.get_recommended_templates_for_egg_record(
            egg_record_id=str(egg_record_id),
            status=status
        )
        
        # Enrich templates with template_path from registry
        registry = OakTemplateRegistryService()
        enriched_templates = []
        
        for template in templates:
            template_id = template.get('template_id')
            if template_id and registry:
                # Get full template info from registry
                template_info = registry.get_template_by_id(template_id)
                if template_info:
                    template['template_path'] = template_info.get('template_path')
                    template['template_name'] = template_info.get('template_name')
                    template['severity'] = template_info.get('severity', template.get('severity', 'info'))
                    template['cve_id'] = template_info.get('cve_id')
                    template['technology'] = template_info.get('technology')
                else:
                    # Template not in registry, use template_id as path pattern
                    template['template_path'] = None
            else:
                template['template_path'] = None
            
            enriched_templates.append(template)
        
        # Limit results
        enriched_templates = enriched_templates[:limit]
        
        return JsonResponse({
            'success': True,
            'egg_record_id': str(egg_record_id),
            'status_filter': status,
            'templates': enriched_templates,
            'template_count': len(enriched_templates),
            'message': f'Found {len(enriched_templates)} recommended templates'
        })
        
    except Exception as e:
        logger.error(f"Error in oak_nuclei_templates_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e),
            'templates': []
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def oak_curate_sample_api(request):
    """
    API endpoint to force-curate a sample of random EggRecords with Oak.
    
    POST /api/oak/curate-sample/
    
    Body params (optional):
        - count: Number of EggRecords to curate (default: 10)
        - alive_only: Only curate alive EggRecords (default: false)
    
    Returns:
        JSON with curation results for each EggRecord
    """
    try:
        import json
        from django.db import connections
        import random
        from artificial_intelligence.personalities.reconnaissance.oak.target_curation.target_curation_service import (
            OakTargetCurationService
        )
        
        body = json.loads(request.body) if request.body else {}
        count = int(body.get('count', 10))
        alive_only = body.get('alive_only', False)
        
        # Get random EggRecords
        try:
            db = connections['customer_eggs']
        except KeyError:
            db = connections['default']
        
        with db.cursor() as cursor:
            where_clause = "WHERE 1=1"
            if alive_only:
                where_clause += " AND alive = true"
            
            cursor.execute(f"""
                SELECT id, "subDomain", domainname, alive
                FROM customer_eggs_eggrecords_general_models_eggrecord
                {where_clause}
                ORDER BY RANDOM()
                LIMIT %s
            """, [count])
            
            egg_records = cursor.fetchall()
            
            if not egg_records:
                return JsonResponse({
                    'success': False,
                    'error': 'No EggRecords found matching criteria',
                    'count': 0
                })
            
            # Perform curation
            curation_service = OakTargetCurationService()
            results = []
            
            for egg_id, subdomain, domainname, alive in egg_records:
                subdomain_name = subdomain or domainname or str(egg_id)
                
                # Create simple object for EggRecord
                class SimpleEggRecord:
                    def __init__(self, egg_id, subdomain, domainname, alive):
                        self.id = egg_id
                        self.subDomain = subdomain
                        self.domainname = domainname
                        self.alive = alive
                
                egg_record = SimpleEggRecord(egg_id, subdomain, domainname, alive)
                
                try:
                    result = curation_service.curate_subdomain(egg_record)
                    
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
                        'nuclei_templates': result.get('nuclei_templates', {}),
                        'nmap_scan_status': result.get('nmap_scan_status', {}),
                        'error': result.get('error') if not result.get('success') else None
                    }
                    
                    results.append(curation_result)
                    
                except Exception as e:
                    results.append({
                        'egg_record_id': str(egg_id),
                        'subdomain': subdomain_name,
                        'success': False,
                        'error': str(e)
                    })
            
            # Calculate summary
            successful = sum(1 for r in results if r.get('success'))
            total_fingerprints = sum(r.get('fingerprints_created', 0) for r in results)
            total_cves = sum(r.get('cve_matches', 0) for r in results)
            total_templates = sum(r.get('templates_selected', 0) for r in results)
            avg_confidence = sum(r.get('confidence_score', 0.0) for r in results) / len(results) if results else 0.0
            
            return JsonResponse({
                'success': True,
                'count': len(results),
                'summary': {
                    'successful': successful,
                    'failed': len(results) - successful,
                    'total_fingerprints': total_fingerprints,
                    'total_cve_matches': total_cves,
                    'total_templates_selected': total_templates,
                    'average_confidence_score': round(avg_confidence, 2)
                },
                'results': results
            })
        
    except Exception as e:
        logger.error(f"Error in oak_curate_sample_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def oak_refresh_templates_api(request):
    """
    API endpoint to refresh/scan Nuclei template registry.
    
    POST /api/oak/refresh-templates/
    
    Body params (optional):
        - force_rescan: If true, re-index existing templates (default: false)
    
    Returns:
        JSON with scan statistics
    """
    try:
        from artificial_intelligence.personalities.reconnaissance.oak.template_registry_service import (
            OakTemplateRegistryService
        )
        import json
        
        body = json.loads(request.body) if request.body else {}
        force_rescan = body.get('force_rescan', False)
        
        registry = OakTemplateRegistryService()
        result = registry.scan_and_index_templates(force_rescan=force_rescan)
        
        return JsonResponse({
            'success': result.get('success', False),
            'scanned': result.get('scanned', 0),
            'indexed': result.get('indexed', 0),
            'updated': result.get('updated', 0),
            'errors': result.get('errors', 0),
            'total_templates': result.get('total_templates', 0),
            'message': f"Scanned {result.get('scanned', 0)} templates, indexed {result.get('indexed', 0)} new, updated {result.get('updated', 0)} existing"
        })
        
    except Exception as e:
        logger.error(f"Error in oak_refresh_templates_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def get_projectegg_phases():
    """Load phase names from config file"""
    # Get the project root directory (parent of ryu_app)
    project_root = Path(__file__).parent.parent
    config_path = project_root / 'config' / 'projectegg_phases.txt'
    
    # Fallback to default phases if file doesn't exist
    default_phases = [
        'ALPHA', 'BETA', 'GAMMA', 'DELTA', 'ECHO', 'FOXTROT', 'GOLF', 'HOTEL',
        'INDIA', 'JULIET', 'KILO', 'LIMA', 'MIKE', 'NOVEMBER', 'OSCAR', 'PAPA',
        'QUEBEC', 'ROMEO', 'SIERRA', 'TANGO', 'UNIFORM', 'VICTOR', 'WHISKEY',
        'XRAY', 'YANKEE', 'ZULU', 'PHOENIX', 'THUNDER', 'STORM', 'SHADOW',
        'NIGHT', 'DAWN', 'TWILIGHT', 'AURORA', 'NEXUS', 'PRIME', 'CORE', 'EDGE',
        'BLADE', 'SHIELD'
    ]
    
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                phases = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            return phases if phases else default_phases
        except Exception as e:
            logger.warning(f"Error reading projectegg phases config: {e}")
            return default_phases
    else:
        # Create default config file if it doesn't exist
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write('# Project Egg Phase Names (Code Names for Obfuscation)\n')
                f.write('# One phase name per line\n\n')
                f.write('\n'.join(default_phases))
            return default_phases
        except Exception as e:
            logger.warning(f"Error creating projectegg phases config: {e}")
            return default_phases


def generate_projectegg():
    """Generate a random project egg from phase names"""
    phases = get_projectegg_phases()
    return random.choice(phases)


def _serialize_row(row):
    """Serialize a row, handling datetime and other non-JSON types."""
    from datetime import timezone as dt_timezone
    result = {}
    for key, value in row.items():
        if isinstance(value, datetime):
            # Ensure value is timezone-aware (assume UTC if naive)
            if timezone.is_naive(value):
                value = timezone.make_aware(value, dt_timezone.utc)
            # Always display in UTC to avoid date inconsistencies across timezones
            # Extract UTC time directly to ensure consistent date display
            if value.tzinfo:
                utc_time = value.astimezone(dt_timezone.utc)
            else:
                utc_time = value
            result[key] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
        elif hasattr(value, '__str__'):
            result[key] = str(value)
        else:
            result[key] = value
    return result


def index(request):
    """Ryu Cybersecurity Dashboard"""
    # Check if eggrecords are empty
    eggrecord_count = EggRecord.objects.count()
    is_empty = eggrecord_count == 0
    
    context = {
        'title': 'Ryu Cybersecurity',
        'icon': '🛡️',
        'eggrecord_count': eggrecord_count,
        'is_empty': is_empty,
    }
    return render(request, 'ryu_app/index.html', context)


@csrf_exempt
def check_empty(request):
    """API endpoint to check if eggrecords are empty"""
    count = EggRecord.objects.count()
    return JsonResponse({
        'is_empty': count == 0,
        'count': count
    })


@csrf_exempt
def seed_initial_entries(request):
    """API endpoint to create initial eggrecords from form data"""
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        
        project_name = data.get('project_name', '').strip()
        customer_name = data.get('customer_name', '').strip()
        domain = data.get('domain', '').strip()
        ip_or_cidr = data.get('ip_or_cidr', '').strip()
        
        # Validation
        if not project_name:
            return JsonResponse({'success': False, 'error': 'Project name is required'}, status=400)
        
        if not customer_name:
            return JsonResponse({'success': False, 'error': 'Customer name is required'}, status=400)
        
        if not domain and not ip_or_cidr:
            return JsonResponse({'success': False, 'error': 'Either domain or IP/CIDR is required'}, status=400)
        
        # Create or get project
        project, _ = Project.objects.get_or_create(name=project_name)
        
        # Create or get customer
        customer, _ = Customer.objects.get_or_create(
            name=customer_name,
            project=project
        )
        
        # Create eggrecords
        created_records = []
        
        if domain:
            # Create record for domain
            eggrecord = EggRecord.objects.create(
                project=project,
                customer=customer,
                domainname=domain,
                subDomain=domain,  # Use domain as subdomain initially
                alive=True
            )
            created_records.append(str(eggrecord.id))
        
        if ip_or_cidr:
            try:
                # Check if it's a CIDR range
                if '/' in ip_or_cidr:
                    # Parse CIDR and create records for each IP
                    network = ipaddress.ip_network(ip_or_cidr, strict=False)
                    # Limit to first 100 IPs to avoid creating too many records
                    for ip in list(network.hosts())[:100]:
                        eggrecord = EggRecord.objects.create(
                            project=project,
                            customer=customer,
                            ip_address=str(ip),
                            alive=True
                        )
                        created_records.append(str(eggrecord.id))
                else:
                    # Single IP address
                    ip = ipaddress.ip_address(ip_or_cidr)
                    eggrecord = EggRecord.objects.create(
                        project=project,
                        customer=customer,
                        ip_address=str(ip),
                        alive=True
                    )
                    created_records.append(str(eggrecord.id))
            except ValueError as e:
                return JsonResponse({'success': False, 'error': f'Invalid IP/CIDR: {str(e)}'}, status=400)
        
        return JsonResponse({
            'success': True,
            'message': f'Created {len(created_records)} eggrecord(s)',
            'created_count': len(created_records),
            'project_id': str(project.id),
            'customer_id': str(customer.id)
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def generate_projectegg_api(request):
    """API endpoint to generate a project egg code name"""
    try:
        projectegg = generate_projectegg()
        return JsonResponse({
            'success': True,
            'projectegg': projectegg
        })
    except Exception as e:
        logger.error(f"Error generating project egg: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


@csrf_exempt
def create_eggrecord_api(request):
    """API endpoint to create new eggrecords using Django ORM"""
    from django.db import connections
    from .postgres_models import PostgresEggRecord
    from django.utils import timezone
    import uuid
    
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        
        domain = data.get('domain', '').strip()
        subdomain = data.get('subdomain', '').strip() or domain
        ip_address = data.get('ip_address', '').strip()
        cidr = data.get('cidr', '').strip()
        alive = data.get('alive', True)
        eggname = data.get('eggname', '').strip()  # Optional customer name
        projectegg = data.get('projectegg', '').strip()  # Auto-generated or provided
        
        # Generate projectegg if not provided but eggname is provided
        if eggname and not projectegg:
            projectegg = generate_projectegg()
        
        if not domain and not ip_address and not cidr:
            return JsonResponse({'success': False, 'error': 'Either domain, IP address, or CIDR is required'}, status=400)
        
        if 'customer_eggs' not in connections.databases:
            return JsonResponse({
                'success': False,
                'error': 'PostgreSQL database not configured. Set DB_HOST environment variable.'
            })
        
        created_records = []
        now = timezone.now()
        
        if domain:
            # Create record for domain using Django ORM
            eggrecord = PostgresEggRecord.objects.using('customer_eggs').create(
                id=uuid.uuid4(),
                subDomain=subdomain if subdomain else None,
                domainname=domain,
                alive=alive,
                eggname=eggname if eggname else None,
                projectegg=projectegg if projectegg else None,
                created_at=now,
                updated_at=now
            )
            created_records.append(str(eggrecord.id))
        
        if ip_address:
            # Single IP address using Django ORM
            eggrecord = PostgresEggRecord.objects.using('customer_eggs').create(
                id=uuid.uuid4(),
                ip_address=ip_address,
                alive=alive,
                eggname=eggname if eggname else None,
                projectegg=projectegg if projectegg else None,
                created_at=now,
                updated_at=now
            )
            created_records.append(str(eggrecord.id))
        
        if cidr:
            # CIDR range - create records for each IP (limited to 100)
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                for ip in list(network.hosts())[:100]:
                    eggrecord = PostgresEggRecord.objects.using('customer_eggs').create(
                        id=uuid.uuid4(),
                        ip_address=str(ip),
                        alive=alive,
                        eggname=eggname if eggname else None,
                        projectegg=projectegg if projectegg else None,
                        created_at=now,
                        updated_at=now
                    )
                    created_records.append(str(eggrecord.id))
            except ValueError as e:
                return JsonResponse({'success': False, 'error': f'Invalid CIDR: {str(e)}'}, status=400)
        
        return JsonResponse({
            'success': True,
            'message': f'Created {len(created_records)} eggrecord(s)',
            'created_count': len(created_records),
            'created_ids': created_records,
            'projectegg': projectegg if projectegg else None
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error creating eggrecord: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


def kaze_dashboard(request):
    """Kaze (Wind) dashboard - High-speed port scanner"""
    context = {
        'personality': 'kaze',
        'title': 'Kaze Dashboard',
        'icon': '💨',
        'color': '#10b981'
    }
    
    # Get filter parameters from query string
    filter_target = request.GET.get('target', '').strip()
    filter_port = request.GET.get('port', '').strip()
    filter_service = request.GET.get('service', '').strip()
    filter_status = request.GET.get('status', '').strip()
    filter_date_from = request.GET.get('date_from', '').strip()
    filter_date_to = request.GET.get('date_to', '').strip()
    
    # Store filters in context for form persistence
    context['filters'] = {
        'target': filter_target,
        'port': filter_port,
        'service': filter_service,
        'status': filter_status,
        'date_from': filter_date_from,
        'date_to': filter_date_to
    }
    
    scan_records = []
    
    # Try to use PostgreSQL database if available
    total_eggrecord_scans = 0
    if 'customer_eggs' in connections.databases:
        try:
            # Get scans using Django ORM with filtering
            nmap_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='kaze_port_scan'
            ).select_related('record_id')
            
            # Apply filters
            if filter_target:
                nmap_scans = nmap_scans.filter(target__icontains=filter_target)
            if filter_port:
                try:
                    port_int = int(filter_port)
                    nmap_scans = nmap_scans.filter(port=port_int)
                except ValueError:
                    # If port is not a number, try string match
                    nmap_scans = nmap_scans.filter(port__icontains=filter_port)
            if filter_service:
                nmap_scans = nmap_scans.filter(service_name__icontains=filter_service)
            if filter_status:
                nmap_scans = nmap_scans.filter(scan_status=filter_status)
            if filter_date_from:
                try:
                    from_date = datetime.strptime(filter_date_from, '%Y-%m-%d')
                    if timezone.is_naive(from_date):
                        from_date = timezone.make_aware(from_date)
                    nmap_scans = nmap_scans.filter(created_at__gte=from_date)
                except ValueError:
                    pass
            if filter_date_to:
                try:
                    to_date = datetime.strptime(filter_date_to, '%Y-%m-%d')
                    if timezone.is_naive(to_date):
                        to_date = timezone.make_aware(to_date)
                    # Add 1 day to include the entire end date
                    to_date = to_date + timedelta(days=1)
                    nmap_scans = nmap_scans.filter(created_at__lt=to_date)
                except ValueError:
                    pass
            
            nmap_scans = nmap_scans.order_by('-created_at')
            total_eggrecord_scans = nmap_scans.count()
            
            # Limit to 1000 records for performance (pagination will handle displaying 25 at a time)
            for scan in nmap_scans[:1000]:
                row_dict = {
                    'id': str(scan.id),
                    'target': scan.target or '',
                    'scan_type': scan.scan_type or 'kaze_port_scan',
                    'scan_status': scan.scan_status or 'completed',
                    'port': scan.port,
                    'service_name': scan.service_name or '',
                    'open_ports': scan.open_ports or '',
                    'created_at': scan.created_at
                }
                serialized = _serialize_row(row_dict)
                serialized['full_data_json'] = json.dumps(serialized)
                scan_records.append(serialized)
        except Exception as e:
            logger.warning(f"Could not query Kaze scan records from PostgreSQL: {e}", exc_info=True)
    
    # Fallback to local SQLite database if PostgreSQL not available
    if not scan_records:
        try:
            eggrecords = EggRecord.objects.all().order_by('-updated_at')
            for egg in eggrecords:
                target = egg.domainname or egg.subDomain or str(egg.ip_address) or 'unknown'
                scan_records.append({
                    'id': str(egg.id),
                    'target': target,
                    'scan_type': 'kaze_port_scan',
                    'scan_status': 'completed' if egg.alive else 'failed',
                    'port': '',
                    'service_name': 'N/A',
                    'open_ports': '',
                    'created_at': egg.created_at,
                    'updated_at': egg.updated_at,
                    'full_data_json': json.dumps({
                        'id': str(egg.id),
                        'target': target,
                        'domainname': egg.domainname,
                        'subDomain': egg.subDomain,
                        'ip_address': str(egg.ip_address) if egg.ip_address else None,
                        'alive': egg.alive,
                        'created_at': egg.created_at.isoformat() if egg.created_at else None,
                        'updated_at': egg.updated_at.isoformat() if egg.updated_at else None,
                    })
                })
        except Exception as e:
            logger.warning(f"Could not query Kaze scans from SQLite: {e}")
    
    # Pagination
    paginator = Paginator(scan_records, 25)  # 25 items per page
    page = request.GET.get('page', 1)
    try:
        scans_page = paginator.page(page)
    except PageNotAnInteger:
        scans_page = paginator.page(1)
    except EmptyPage:
        scans_page = paginator.page(paginator.num_pages)
    
    context['scans'] = scans_page
    context['total_scans'] = total_eggrecord_scans if total_eggrecord_scans > 0 else len(scan_records)
    context['eggrecord_scans'] = len(scan_records)
    
    # Get recent scans (last 24 hours) using Django ORM and last scan timestamp
    recent_scans_24h = 0
    last_scan_time = None
    if 'customer_eggs' in connections.databases:
        try:
            recent_time = timezone.now() - timedelta(hours=24)
            recent_scans_24h = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='kaze_port_scan',
                created_at__gte=recent_time
            ).count()
            # Get the timestamp of the most recent scan
            last_scan = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='kaze_port_scan'
            ).order_by('-created_at').first()
            if last_scan:
                last_scan_time = last_scan.created_at
        except Exception as e:
            logger.debug(f"Could not query recent Kaze scans: {e}")
    else:
        try:
            recent_time = timezone.now() - timedelta(hours=24)
            recent_scans_24h = EggRecord.objects.filter(updated_at__gte=recent_time).count()
        except Exception as e:
            logger.debug(f"Could not query recent Kaze scans from SQLite: {e}")
    
    context['recent_scans_24h'] = recent_scans_24h
    context['last_scan_time'] = last_scan_time
    
    # Get WAF detection stats using Django ORM
    context['waf_count'] = 0
    context['technique_count'] = 0
    if 'eggrecords' in connections.databases:
        try:
            context['waf_count'] = KageWAFDetection.objects.using('eggrecords').count()
            context['technique_count'] = KageTechniqueEffectiveness.objects.using('eggrecords').count()
        except Exception as e:
            logger.debug(f"Could not query eggrecords stats: {e}")
    
    return render(request, 'reconnaissance/kaze_dashboard.html', context)


def learning_dashboard(request):
    """Collective Nmap Learning & Heuristics Dashboard"""
    from django.db import connections
    
    context = {
        'personality': 'learning',
        'title': 'Nmap Learning & Heuristics',
        'icon': '🧠',
        'color': '#8b5cf6'
    }
    
    # Get heuristics rules from calculated rules (backend calculation)
    if 'eggrecords' in connections.databases:
        try:
            # Try to import heuristics calculator from main system
            import sys
            main_system_path = '/mnt/webapps-nvme'
            if main_system_path not in sys.path:
                sys.path.insert(0, main_system_path)
            
            try:
                from artificial_intelligence.personalities.reconnaissance.heuristics_calculator import (
                    calculate_heuristics_rules_from_scans, store_heuristics_rules
                )
                
                # Calculate heuristics from recent scans
                calculated_rules = calculate_heuristics_rules_from_scans(limit=1000)
                
                # Store calculated rules
                if calculated_rules:
                    store_heuristics_rules(calculated_rules)
            except ImportError:
                calculated_rules = []
                logger.debug("Heuristics calculator not available, using database only")
            
            # Get stored rules from database - try calculated_heuristics_rules first, fallback to port_heuristics
            stored_rules = []
            try:
                # Try CalculatedHeuristicsRule model (calculated_heuristics_rules table)
                rules = CalculatedHeuristicsRule.objects.using(learning_db).order_by(
                    '-confidence_score', '-sample_count'
                )[:50]
                
                for rule in rules:
                    rule_dict = {
                        'rule_pattern': rule.rule_pattern,
                        'nmap_arguments': rule.nmap_arguments_list,
                        'recommended_technique': rule.recommended_technique,
                        'confidence_score': float(rule.confidence_score) if rule.confidence_score else None,
                        'success_rate': float(rule.success_rate) if rule.success_rate else None,
                        'sample_count': rule.sample_count,
                        'last_updated': rule.last_updated
                    }
                    stored_rules.append(rule_dict)
                logger.debug(f"Loaded {len(stored_rules)} rules from calculated_heuristics_rules")
            except Exception as e:
                logger.debug(f"Could not query calculated_heuristics_rules, trying port_heuristics: {e}")
                # Fallback to port_heuristics table using raw SQL
                try:
                    db = connections[learning_db]
                    with db.cursor() as cursor:
                        cursor.execute("""
                            SELECT rule_pattern, nmap_arguments, recommended_technique, 
                                   confidence_score, success_rate, sample_count, last_updated
                            FROM port_heuristics
                            ORDER BY confidence_score DESC, sample_count DESC
                            LIMIT 50
                        """)
                        for row in cursor.fetchall():
                            rule_dict = {
                                'rule_pattern': row[0] or '',
                                'nmap_arguments': row[1] if isinstance(row[1], list) else (json.loads(row[1]) if row[1] and isinstance(row[1], str) else []) if row[1] else [],
                                'recommended_technique': row[2] or '',
                                'confidence_score': float(row[3]) if row[3] else None,
                                'success_rate': float(row[4]) if row[4] else None,
                                'sample_count': row[5] or 0,
                                'last_updated': row[6]
                            }
                            stored_rules.append(rule_dict)
                        logger.debug(f"Loaded {len(stored_rules)} rules from port_heuristics")
                except Exception as e2:
                    logger.debug(f"Could not query port_heuristics either: {e2}")
            
            # If we still have no rules, use calculated rules if available
            if not stored_rules and 'calculated_rules' in locals() and calculated_rules:
                stored_rules = calculated_rules
            
            context['heuristics_rules'] = stored_rules
            # Extract unique arguments
            all_args = []
            for rule in stored_rules:
                nmap_args = rule.get('nmap_arguments') or []
                if isinstance(nmap_args, list):
                    all_args.extend(nmap_args)
                elif isinstance(nmap_args, str):
                    try:
                        import json
                        all_args.extend(json.loads(nmap_args))
                    except:
                        pass
            context['arguments_count'] = len(set(all_args))
            context['arguments'] = list(set(all_args))[:20]  # Top 20 unique arguments
        except Exception as e:
            logger.warning(f"Could not calculate heuristics rules: {e}", exc_info=True)
            context['heuristics_rules'] = []
            context['arguments_count'] = 0
            context['arguments'] = []
    else:
        context['heuristics_rules'] = []
        context['arguments_count'] = 0
        context['arguments'] = []
    
    # Get technique effectiveness (learning data) using Django ORM
    if 'eggrecords' in connections.databases:
        try:
            techniques_qs = KageTechniqueEffectiveness.objects.using('eggrecords').annotate(
                total_attempts=F('success_count') + F('failure_count')
            ).order_by('-total_attempts', '-success_count')[:50]
            
            techniques = []
            for tech in techniques_qs:
                tech_dict = {
                    'target_pattern': tech.target_pattern,
                    'waf_type': tech.waf_type,
                    'technique_name': tech.technique_name,
                    'success_count': tech.success_count,
                    'failure_count': tech.failure_count,
                    'success_rate': tech.success_rate,
                    'last_success': tech.last_success,
                    'last_failure': tech.last_failure,
                    'last_updated': tech.last_updated,
                    'technique_metadata': tech.technique_metadata
                }
                techniques.append(_serialize_row(tech_dict))
            context['techniques'] = techniques
            
            # Get WAF detection patterns using Django ORM
            try:
                # Check if waf_detection_details table exists by trying to query it
                waf_details_count = WAFDetectionDetail.objects.using(learning_db).count()
                has_enhanced_waf = waf_details_count > 0
            except Exception:
                has_enhanced_waf = False
            
            if has_enhanced_waf:
                # Use WAFDetectionDetail with aggregations
                waf_patterns_qs = WAFDetectionDetail.objects.using(learning_db).filter(
                    waf_type__isnull=False
                ).values('waf_type', 'waf_version', 'waf_product').annotate(
                    detection_count=Count('id'),
                    avg_confidence=Avg('confidence'),
                    last_detected=Max('detected_at'),
                    unique_targets=Count('target', distinct=True)
                ).order_by('-detection_count')[:50]
                
                waf_patterns = []
                for pattern in waf_patterns_qs:
                    pattern_dict = {
                        'waf_type': pattern['waf_type'],
                        'waf_version': pattern['waf_version'],
                        'waf_product': pattern['waf_product'],
                        'detection_count': pattern['detection_count'],
                        'avg_confidence': float(pattern['avg_confidence']) if pattern['avg_confidence'] else None,
                        'last_detected': pattern['last_detected'],
                        'unique_targets': pattern['unique_targets']
                    }
                    waf_patterns.append(_serialize_row(pattern_dict))
            else:
                # Use KageWAFDetection with aggregations
                waf_patterns_qs = KageWAFDetection.objects.using('eggrecords').filter(
                    waf_type__isnull=False
                ).values('waf_type').annotate(
                    detection_count=Count('id'),
                    bypass_count=Count(Case(When(bypass_successful=True, then=1), output_field=IntegerField())),
                    avg_confidence=Avg('confidence'),
                    last_detected=Max('detected_at')
                ).order_by('-detection_count')
                
                waf_patterns = []
                for pattern in waf_patterns_qs:
                    pattern_dict = {
                        'waf_type': pattern['waf_type'],
                        'detection_count': pattern['detection_count'],
                        'bypass_count': pattern['bypass_count'],
                        'avg_confidence': float(pattern['avg_confidence']) if pattern['avg_confidence'] else None,
                        'last_detected': pattern['last_detected']
                    }
                    waf_patterns.append(_serialize_row(pattern_dict))
            
            context['waf_patterns'] = waf_patterns
            
            # Get IP-based technique effectiveness using Django ORM
            try:
                ip_techniques_qs = IPTechniqueEffectiveness.objects.using(learning_db).annotate(
                    total_attempts=F('success_count') + F('failure_count')
                ).order_by('-total_attempts', '-success_count')[:50]
                
                ip_techniques = []
                for tech in ip_techniques_qs:
                    tech_dict = {
                        'asn': tech.asn,
                        'cidr_block': tech.cidr_block,
                        'ipv6_prefix': tech.ipv6_prefix,
                        'waf_type': tech.waf_type,
                        'technique_name': tech.technique_name,
                        'success_count': tech.success_count,
                        'failure_count': tech.failure_count,
                        'success_rate': tech.success_rate,
                        'avg_scan_duration': float(tech.avg_scan_duration) if tech.avg_scan_duration else None,
                        'last_updated': tech.last_updated
                    }
                    ip_techniques.append(_serialize_row(tech_dict))
                context['ip_techniques'] = ip_techniques
            except Exception as e:
                logger.debug(f"Could not query ip_technique_effectiveness: {e}")
                context['ip_techniques'] = []
            
            # Get technology fingerprints (Oak's curated data) using Django ORM
            try:
                tech_fingerprints_qs = TechnologyFingerprint.objects.using('eggrecords').values(
                    'technology_type', 'product', 'version'
                ).annotate(
                    count=Count('id'),
                    unique_targets=Count('target', distinct=True),
                    last_detected=Max('detected_at')
                ).order_by('-count')[:50]
                
                tech_fingerprints = []
                for fp in tech_fingerprints_qs:
                    fp_dict = {
                        'technology_type': fp['technology_type'],
                        'product': fp['product'],
                        'version': fp['version'],
                        'count': fp['count'],
                        'unique_targets': fp['unique_targets'],
                        'last_detected': fp['last_detected']
                    }
                    tech_fingerprints.append(_serialize_row(fp_dict))
                context['tech_fingerprints'] = tech_fingerprints
            except Exception as e:
                logger.debug(f"Could not query technology_fingerprints: {e}")
                context['tech_fingerprints'] = []
            
            # Get recent decision examples using Django ORM
            try:
                decisions_qs = KageScanResult.objects.using(learning_db).filter(
                    technique_used__isnull=False
                ).order_by('-scanned_at')[:20]
                
                decisions = []
                for decision in decisions_qs:
                    decision_dict = {
                        'target': decision.target,
                        'technique_used': decision.technique_used,
                        'waf_detected': decision.waf_detected,
                        'waf_type': decision.waf_type,
                        'open_ports_found': decision.open_ports_found,
                        'bypass_successful': decision.bypass_successful,
                        'scan_duration': float(decision.scan_duration) if decision.scan_duration else None,
                        'scanned_at': decision.scanned_at
                    }
                    decisions.append(_serialize_row(decision_dict))
                context['recent_decisions'] = decisions
            except Exception as e:
                logger.debug(f"Could not query kage scan results (legacy table: ash_scan_results): {e}")
                context['recent_decisions'] = []
                
        except Exception as e:
            logger.warning(f"Could not query learning data: {e}", exc_info=True)
            context['techniques'] = []
            context['waf_patterns'] = []
            context['recent_decisions'] = []
            context['ip_techniques'] = []
            context['tech_fingerprints'] = []
    else:
        # No PostgreSQL connection, use empty data
        context['techniques'] = []
        context['waf_patterns'] = []
        context['recent_decisions'] = []
        context['ip_techniques'] = []
        context['tech_fingerprints'] = []
    
    return render(request, 'reconnaissance/learning_dashboard.html', context)


def learning_heuristics_api(request):
    """API: Get heuristics rules"""
    from django.db import connections
    
    try:
        if 'eggrecords' not in connections.databases:
            return JsonResponse({
                'success': False,
                'error': 'PostgreSQL database not configured. Set DB_HOST environment variable.'
            })
        
        # Try to import heuristics calculator from main system
        import sys
        main_system_path = '/mnt/webapps-nvme'
        if main_system_path not in sys.path:
            sys.path.insert(0, main_system_path)
        
        try:
            from artificial_intelligence.personalities.reconnaissance.ash.nmap_argument_inference import NmapArgumentInference
            from pathlib import Path
            
            knowledge_paths = [
                Path('/mnt/webapps-nvme/nmap_knowledge/ash_nmap_knowledge.json'),
                Path('/mnt/webapps-nvme/artificial_intelligence/personalities/reconnaissance/kage/nmap_knowledge.json'),
            ]
            knowledge_base = None
            for path in knowledge_paths:
                if path.exists():
                    with open(path, 'r') as f:
                        knowledge_base = json.load(f)
                    break
            
            inference_engine = NmapArgumentInference(knowledge_base=knowledge_base or {})
            
            return JsonResponse({
                'success': True,
                'heuristics_rules': inference_engine.heuristics_rules,
                'arguments_count': len(inference_engine.arguments)
            })
        except ImportError:
            # Fallback to database-only approach using Django ORM
            try:
                rules_qs = CalculatedHeuristicsRule.objects.using('eggrecords').order_by(
                    '-confidence_score', '-sample_count'
                )[:50]
                
                rules = []
                for rule in rules_qs:
                    rule_dict = {
                        'rule_pattern': rule.rule_pattern,
                        'nmap_arguments': rule.nmap_arguments_list,
                        'recommended_technique': rule.recommended_technique,
                        'confidence_score': float(rule.confidence_score) if rule.confidence_score else None,
                        'success_rate': float(rule.success_rate) if rule.success_rate else None,
                        'sample_count': rule.sample_count,
                        'last_updated': rule.last_updated
                    }
                    rules.append(rule_dict)
                
                return JsonResponse({
                    'success': True,
                    'heuristics_rules': rules,
                    'arguments_count': len(set(
                        arg for rule in rules
                        for arg in (rule.get('nmap_arguments') or [])
                    ))
                })
            except Exception as e:
                logger.error(f"Error querying heuristics rules: {e}", exc_info=True)
                return JsonResponse({
                    'success': True,
                    'heuristics_rules': [],
                    'arguments_count': 0
                })
    except Exception as e:
        logger.error(f"Error getting heuristics: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)})


def learning_techniques_api(request):
    """API: Get technique effectiveness data (domain-based) using Django ORM"""
    try:
        if 'eggrecords' not in connections.databases:
            return JsonResponse({
                'success': False,
                'error': 'PostgreSQL database not configured. Set DB_HOST environment variable.'
            })
        
        limit = int(request.GET.get('limit', 100))
        techniques_qs = KageTechniqueEffectiveness.objects.using('eggrecords').annotate(
            total_attempts=F('success_count') + F('failure_count')
        ).order_by('-total_attempts')[:limit]
        
        data = []
        for tech in techniques_qs:
            tech_dict = {
                'target_pattern': tech.target_pattern,
                'waf_type': tech.waf_type,
                'technique_name': tech.technique_name,
                'success_count': tech.success_count,
                'failure_count': tech.failure_count,
                'success_rate': tech.success_rate,
                'last_success': tech.last_success,
                'last_failure': tech.last_failure,
                'last_updated': tech.last_updated
            }
            data.append(_serialize_row(tech_dict))
        
        return JsonResponse({'success': True, 'count': len(data), 'data': data})
    except Exception as e:
        logger.error(f"Error getting techniques: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)})


@csrf_exempt
def suzu_upload_paths_api(request):
    """
    API: Upload wordlist paths to vector database.
    Weight is automatically calculated based on CMS detection and path patterns.
    
    POST /reconnaissance/api/suzu/paths/upload/
    {
        "wordlist_name": "wordpress.fuzz.txt",
        "cms_name": "wordpress",  # Optional, auto-detected from paths
        "paths": ["/wp-admin/", "/wp-content/", ...],
        "source": "seclist",
        "category": "admin"  # Optional
    }
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        wordlist_name = data.get('wordlist_name')
        paths = data.get('paths', [])
        cms_name = data.get('cms_name')
        # Weight is now automatically calculated - ignore user input
        source = data.get('source', 'uploaded')
        category = data.get('category')
        
        if not wordlist_name or not paths:
            return JsonResponse({
                'success': False,
                'error': 'wordlist_name and paths required'
            }, status=400)
        
        # Add project root to path so we can import suzu
        import sys
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        # Initialize vector store
        try:
            from suzu.vector_path_store import VectorPathStore
            vector_store = VectorPathStore()
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Vector database not available: {str(e)}'
            }, status=503)
        
        # Upload paths with per-path CMS detection and weight calculation
        # cms_name is used as hint for per-path detection if provided
        result = vector_store.upload_paths(
            paths=paths,
            wordlist_name=wordlist_name,
            cms_name=cms_name,  # Used as fallback/hint only
            default_weight=0.4,  # Used as fallback only
            source=source,
            category=category,
            per_path_detection=True,  # Enable per-path detection
            filename_cms_hint=cms_name  # Use provided CMS as hint
        )
        
        return JsonResponse({
            'success': True,
            'uploaded': result['uploaded'],
            'failed': result['failed'],
            'collection': result['collection'],
            'total_dim': result['total_dim']
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        logger.error(f"Error uploading paths: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def suzu_similar_paths_api(request):
    """
    API: Find similar paths using vector matching.
    
    POST /reconnaissance/api/suzu/paths/similar/
    {
        "query_path": "/admin",
        "cms_name": "wordpress",  # Optional
        "limit": 10,
        "threshold": 0.7,
        "category": "admin"  # Optional
    }
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        query_path = data.get('query_path')
        
        if not query_path:
            return JsonResponse({
                'success': False,
                'error': 'query_path required'
            }, status=400)
        
        try:
            from suzu.vector_path_store import VectorPathStore
            vector_store = VectorPathStore()
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Vector database not available: {str(e)}'
            }, status=503)
        
        similar = vector_store.find_similar_paths(
            query_path=query_path,
            cms_name=data.get('cms_name'),
            limit=int(data.get('limit', 10)),
            threshold=float(data.get('threshold', 0.7)),
            category=data.get('category')
        )
        
        return JsonResponse({
            'success': True,
            'query_path': query_path,
            'similar_paths': similar,
            'count': len(similar)
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        logger.error(f"Error finding similar paths: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def suzu_weighted_paths_api(request):
    """
    API: Get weighted paths for Suzu enumeration.
    
    GET /reconnaissance/api/suzu/paths/weighted/?cms_name=wordpress&limit=100&min_weight=0.2
    """
    try:
        cms_name = request.GET.get('cms_name')
        limit = int(request.GET.get('limit', 100))
        min_weight = float(request.GET.get('min_weight', 0.2))
        
        try:
            from suzu.vector_path_store import VectorPathStore
            vector_store = VectorPathStore()
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Vector database not available: {str(e)}'
            }, status=503)
        
        weighted_paths = vector_store.get_weighted_paths(
            cms_name=cms_name,
            limit=limit,
            min_weight=min_weight
        )
        
        return JsonResponse({
            'success': True,
            'paths': weighted_paths,
            'count': len(weighted_paths),
            'cms_name': cms_name,
            'min_weight': min_weight
        })
        
    except Exception as e:
        logger.error(f"Error getting weighted paths: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def suzu_get_progress(request):
    """
    API: Get Suzu daemon progress (for dashboard)
    
    GET /reconnaissance/api/suzu/progress/
    """
    # Import from daemon_api module
    import ryu_app.daemon_api as daemon_api_module
    return JsonResponse({
        'success': True,
        'progress': daemon_api_module._suzu_progress
    })


@csrf_exempt
def suzu_upload_file_api(request):
    """
    API: Upload wordlist file via multipart/form-data.
    Weight is automatically calculated based on CMS detection and path patterns.
    
    POST /reconnaissance/api/suzu/paths/upload-file/
    
    Form data:
        - file: The wordlist file (.txt, .fuzz, etc.)
        - cms_name: Optional CMS name (auto-inferred from filename and path content)
        - wordlist_name: Optional wordlist name (default: filename)
        - source: Optional source (default: 'uploaded')
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        if 'file' not in request.FILES:
            return JsonResponse({
                'success': False,
                'error': 'No file provided'
            }, status=400)
        
        uploaded_file = request.FILES['file']
        cms_name = request.POST.get('cms_name', '').strip() or None
        wordlist_name = request.POST.get('wordlist_name', '').strip() or uploaded_file.name
        # Weight is now automatically calculated - ignore user input
        source = request.POST.get('source', 'uploaded')
        
        # Read file content efficiently using Go parser (if available) or Python fallback
        # Go parser is much faster for large files
        paths = []
        file_content_bytes = None  # Store original file content for hash calculation
        try:
            # Read file content first (Django UploadedFile can only be read once)
            # This ensures we have the content available for both Go and Python parsers
            try:
                uploaded_file.seek(0)  # Ensure we're at the start
            except (AttributeError, OSError):
                pass  # Some file objects don't support seek
            
            # Read file content - handle both bytes and text
            file_content = uploaded_file.read()
            file_content_bytes = file_content  # Keep original for hash
            if isinstance(file_content, str):
                file_content = file_content.encode('utf-8')
            elif not isinstance(file_content, bytes):
                file_content = bytes(file_content)
            
            # Try Go-based parser first for better performance
            go_parser_used = False
            try:
                from suzu.wordlist_parser_bridge import parse_wordlist_stream
                from io import BytesIO
                
                # Create BytesIO stream from file content
                file_stream = BytesIO(file_content)
                
                # Parse using Go parser
                parse_result = parse_wordlist_stream(
                    file_stream=file_stream,
                    batch_size=1000,
                    max_paths=0,  # Unlimited
                    skip_comments=True,
                    normalize_paths=True,
                    filename=getattr(uploaded_file, 'name', 'uploaded_file')
                )
                
                if parse_result.get('error'):
                    logger.warning(f"Go parser error: {parse_result['error']}, falling back to Python")
                    raise Exception(parse_result['error'])
                
                paths = parse_result.get('paths', [])
                if paths:
                    go_parser_used = True
                    logger.info(f"✅ Parsed {len(paths)} paths using Go parser (stats: {parse_result.get('stats', {})})")
                else:
                    raise Exception("Go parser returned no paths")
                
            except ImportError as import_error:
                # Import error - Go parser not available, use Python
                logger.debug(f"Go parser not available (ImportError: {import_error}), using Python parser")
                go_parser_used = False
            except Exception as go_error:
                # Other Go parser errors - fall back to Python
                logger.warning(f"Go parser failed ({type(go_error).__name__}: {go_error}), falling back to Python parser")
                go_parser_used = False
            
            # Fallback to Python parser if Go parser wasn't used or failed
            if not go_parser_used:
                # Use file_content we read earlier (always available)
                from io import BytesIO
                python_file_stream = BytesIO(file_content)
                
                # Iterate line by line
                for line in python_file_stream:
                    # Handle both bytes and text
                    if isinstance(line, bytes):
                        line = line.decode('utf-8', errors='ignore').strip()
                    else:
                        line = str(line).strip()
                    
                    if not line or line.startswith('#'):
                        continue
                    if not line.startswith('/'):
                        line = '/' + line
                    paths.append(line)
                
                logger.info(f"✅ Parsed {len(paths)} paths using Python parser")
                
        except Exception as e:
            logger.error(f"Error reading file: {e}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': f'Error reading file: {str(e)}'
            }, status=500)
        
        if not paths:
            # #region agent log
            import json; log_path = '/tmp/suzu_debug.log'; log_file = open(log_path, 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"API","location":"views.py:1325","message":"No paths found in file","data":{},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
            # #endregion
            return JsonResponse({
                'success': False,
                'error': 'No valid paths found in file'
            }, status=400)
        
        # #region agent log
        import json; log_path = '/tmp/suzu_debug.log'; log_file = open(log_path, 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"API","location":"views.py:1330","message":"Paths loaded, starting upload","data":{"path_count":len(paths)},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
        # #endregion
        
        # Add project root to path so we can import suzu
        import sys
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        # Get filename CMS hint for per-path detection
        filename_cms_hint = None
        try:
            from suzu.upload_wordlist import infer_cms_from_filename
            if not cms_name:
                filename_cms_hint = infer_cms_from_filename(uploaded_file.name)
            else:
                filename_cms_hint = cms_name
        except ImportError as e:
            # #region agent log
            import json; log_path = '/tmp/suzu_debug.log'; log_file = open(log_path, 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"API","location":"views.py:1345","message":"Import error for infer_cms_from_filename","data":{"error":str(e)},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
            # #endregion
            # Fallback if import fails
            pass
        
        # Upload to vector store with per-path detection
        # Use a try-finally to ensure cleanup
        vector_store = None
        try:
            from suzu.vector_path_store import VectorPathStore
            vector_store = VectorPathStore()
            # #region agent log
            import json; log_path = '/tmp/suzu_debug.log'; log_file = open(log_path, 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"API","location":"views.py:1355","message":"VectorPathStore initialized, calling upload_paths","data":{"filename_cms_hint":filename_cms_hint},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
            # #endregion
        except Exception as e:
            # #region agent log
            import json; log_path = '/tmp/suzu_debug.log'; log_file = open(log_path, 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"API","location":"views.py:1360","message":"VectorPathStore initialization failed","data":{"error":str(e)},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
            # #endregion
            logger.error(f"Failed to initialize vector store: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Vector database not available: {str(e)}'
            }, status=503)
        
        # Check for duplicate paths before uploading
        path_check = vector_store.check_existing_paths(paths, cms_name, wordlist_name)
        
        # Safety check: ensure path_check is valid and has required keys
        if not path_check or not isinstance(path_check, dict):
            path_check = {'existing': [], 'new': paths, 'existing_count': 0, 'new_count': len(paths)}
        
        # Ensure counts are integers, not None
        duplicate_count = path_check.get('existing_count', 0)
        if duplicate_count is None:
            duplicate_count = 0
        duplicate_count = int(duplicate_count)
        
        new_paths = path_check.get('new', paths)
        
        # Upload only new paths with per-path CMS detection and weight calculation
        result = None
        try:
            if new_paths:
                result = vector_store.upload_paths(
                    paths=new_paths,
                    wordlist_name=wordlist_name,
                    cms_name=cms_name,  # Used as fallback only
                    default_weight=0.4,  # Used as fallback only
                    source=source,
                    category=None,
                    per_path_detection=True,  # Enable per-path detection
                    filename_cms_hint=filename_cms_hint  # Pass filename hint
                )
            else:
                # All paths are duplicates
                result = {'uploaded': 0, 'failed': 0, 'collection': vector_store.collection_name if vector_store else 'unknown'}
            
            # Ensure result is valid
            if not result or not isinstance(result, dict):
                logger.warning(f"upload_paths returned invalid result: {result}, using defaults")
                result = {'uploaded': 0, 'failed': len(new_paths) if new_paths else 0}
        except Exception as upload_error:
            logger.error(f"Error uploading paths to vector store: {upload_error}", exc_info=True)
            result = {'uploaded': 0, 'failed': len(new_paths) if new_paths else 0}
            # Don't fail the entire request - still save upload history
        
        # #region agent log
        import json; log_path = '/tmp/suzu_debug.log'; log_file = open(log_path, 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"API","location":"views.py:1382","message":"Upload completed","data":{"uploaded":result.get('uploaded',0),"failed":result.get('failed',0),"duplicate_count":duplicate_count,"result":result},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
        # #endregion
        
        # Save upload history
        upload_record = None
        try:
            from ryu_app.models import WordlistUpload
            import hashlib
            
            # Calculate file hash for deduplication (use original file content if available, otherwise use paths)
            # Use the file_content_bytes we read earlier, or fallback to paths
            if file_content_bytes and isinstance(file_content_bytes, bytes):
                file_hash = hashlib.sha256(file_content_bytes).hexdigest()
            else:
                # Fallback: hash the paths
                paths_content = '\n'.join(paths).encode('utf-8')
                file_hash = hashlib.sha256(paths_content).hexdigest()
            
            upload_record = WordlistUpload.objects.create(
                wordlist_name=wordlist_name,
                filename=uploaded_file.name,
                cms_name=cms_name,
                source=source,
                paths_count=len(paths),
                uploaded_count=result.get('uploaded', 0),
                failed_count=result.get('failed', 0),
                file_hash=file_hash
            )
        except Exception as e:
            logger.error(f"Failed to save upload history: {e}", exc_info=True)
        
        # Ensure result has required keys
        uploaded_count = result.get('uploaded', 0) if result else 0
        failed_count = result.get('failed', 0) if result else len(new_paths) if new_paths else 0
        
        response = JsonResponse({
            'success': True,
            'uploaded': uploaded_count,
            'failed': failed_count,
            'duplicate_count': duplicate_count,
            'wordlist_name': wordlist_name,
            'cms_name': cms_name,
            'paths_count': len(paths),
            'new_paths_count': len(new_paths) if new_paths else 0,
            'upload_id': str(upload_record.id) if upload_record else None
        })
        
        # Cleanup: Close Qdrant connection if possible
        if vector_store and hasattr(vector_store, 'client') and vector_store.client:
            try:
                # Qdrant client doesn't have explicit close, but we can clear reference
                # The connection will be closed when the object is garbage collected
                pass
            except Exception:
                pass
        
        return response
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        # #region agent log
        import json; log_path = '/tmp/suzu_debug.log'; log_file = open(log_path, 'a'); log_file.write(json.dumps({"sessionId":"debug-session","runId":"run1","hypothesisId":"API","location":"views.py:1396","message":"Exception in suzu_upload_file_api","data":{"error":str(e),"error_type":type(e).__name__,"traceback":error_trace},"timestamp":int(__import__('time').time()*1000)}) + '\n'); log_file.close()
        # #endregion
        logger.error(f"Error uploading file: {e}\n{error_trace}", exc_info=True)
        
        # Cleanup on error
        if 'vector_store' in locals() and vector_store and hasattr(vector_store, 'client') and vector_store.client:
            try:
                pass  # Connection cleanup handled by garbage collection
            except Exception:
                pass
        
        return JsonResponse({
            'success': False,
            'error': f'Upload failed: {str(e)}. Check server logs for details.'
        }, status=500)


@csrf_exempt
def suzu_upload_directory_api(request):
    """
    API: Upload wordlist files from a directory path.
    Weight is automatically calculated for each file based on CMS detection and path patterns.
    
    POST /reconnaissance/api/suzu/paths/upload-directory/
    
    JSON body:
        {
            "directory_path": "/path/to/directory",
            "recursive": true,
            "source": "seclist"
        }
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        directory_path = data.get('directory_path')
        recursive = data.get('recursive', False)
        # Weight is now automatically calculated - ignore user input
        source = data.get('source', 'seclist')
        
        if not directory_path:
            return JsonResponse({
                'success': False,
                'error': 'directory_path required'
            }, status=400)
        
        dir_path = Path(directory_path)
        if not dir_path.exists():
            return JsonResponse({
                'success': False,
                'error': f'Directory does not exist: {directory_path}'
            }, status=400)
        
        if not dir_path.is_dir():
            return JsonResponse({
                'success': False,
                'error': f'Path is not a directory: {directory_path}'
            }, status=400)
        
        # Find wordlist files
        wordlist_extensions = ['.txt', '.fuzz', '.lst', '.wordlist']
        files_to_upload = []
        
        if recursive:
            for ext in wordlist_extensions:
                files_to_upload.extend(dir_path.rglob(f'*{ext}'))
        else:
            for ext in wordlist_extensions:
                files_to_upload.extend(dir_path.glob(f'*{ext}'))
        
        if not files_to_upload:
            return JsonResponse({
                'success': False,
                'error': f'No wordlist files found in {directory_path}'
            }, status=400)
        
        # Add project root to path so we can import suzu
        import sys
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        # Import upload functions
        from suzu.upload_wordlist import upload_wordlist_file, infer_cms_from_filename
        
        # Initialize vector store
        try:
            from suzu.vector_path_store import VectorPathStore
            vector_store = VectorPathStore()
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Vector database not available: {str(e)}'
            }, status=503)
        
        # Process each file
        results = []
        total_uploaded = 0
        total_failed = 0
        
        for file_path in files_to_upload:
            # CMS and weight are now automatically detected from filename and path content
            result = upload_wordlist_file(
                file_path=file_path,
                cms_name=None,  # Auto-infer from filename and paths
                wordlist_name=file_path.name,
                default_weight=0.4,  # Will be overridden by automatic calculation
                source=source
            )
            
            if result:
                results.append({
                    'file': file_path.name,
                    'cms_name': cms_name,
                    'uploaded': result['uploaded'],
                    'failed': result['failed']
                })
                total_uploaded += result['uploaded']
                total_failed += result['failed']
        
        return JsonResponse({
            'success': True,
            'files_processed': len(files_to_upload),
            'total_uploaded': total_uploaded,
            'total_failed': total_failed,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error uploading directory: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@csrf_exempt
def suzu_delete_wordlist_api(request, wordlist_id):
    """
    API: Delete a wordlist upload record.
    
    DELETE /reconnaissance/api/suzu/wordlist/<wordlist_id>/
    """
    if request.method != 'DELETE':
        return JsonResponse({'success': False, 'error': 'DELETE method required'}, status=405)
    
    try:
        from ryu_app.models import WordlistUpload
        
        try:
            wordlist = WordlistUpload.objects.get(id=wordlist_id)
            wordlist_name = wordlist.wordlist_name
            wordlist.delete()
            
            logger.info(f"Deleted wordlist upload: {wordlist_name} (ID: {wordlist_id})")
            
            return JsonResponse({
                'success': True,
                'message': f'Wordlist "{wordlist_name}" deleted successfully'
            })
        except WordlistUpload.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Wordlist not found'
            }, status=404)
            
    except Exception as e:
        logger.error(f"Error deleting wordlist: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
def suzu_delete_enumeration_api(request, enumeration_id):
    """
    API: Delete a directory enumeration result.
    
    DELETE /reconnaissance/api/suzu/enumeration/<enumeration_id>/
    """
    if request.method != 'DELETE':
        return JsonResponse({'success': False, 'error': 'DELETE method required'}, status=405)
    
    try:
        from artificial_intelligence.customer_eggs_eggrecords_general_models.models import DirectoryEnumerationResult
        from django.db import connections
        
        if 'customer_eggs' not in connections.databases:
            return JsonResponse({
                'success': False,
                'error': 'Database not configured'
            }, status=500)
        
        try:
            enumeration = DirectoryEnumerationResult.objects.using('customer_eggs').get(id=enumeration_id)
            target = enumeration.discovered_path or 'unknown'
            enumeration.delete()
            
            logger.info(f"Deleted enumeration result: {target} (ID: {enumeration_id})")
            
            return JsonResponse({
                'success': True,
                'message': f'Enumeration result deleted successfully'
            })
        except DirectoryEnumerationResult.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Enumeration result not found'
            }, status=404)
            
    except ImportError:
        return JsonResponse({
            'success': False,
            'error': 'DirectoryEnumerationResult model not available'
        }, status=500)
    except Exception as e:
        logger.error(f"Error deleting enumeration result: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def suzu_upload_history_api(request):
    """
    API: Get upload history for Suzu wordlist uploads.
    
    GET /reconnaissance/api/suzu/upload-history/
    Query params:
        - limit: Maximum number of records to return (default: 50)
        - wordlist_name: Filter by wordlist name (optional)
        - cms_name: Filter by CMS name (optional)
    """
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        from ryu_app.models import WordlistUpload
        
        limit = int(request.GET.get('limit', 50))
        wordlist_name_filter = request.GET.get('wordlist_name', '').strip()
        cms_name_filter = request.GET.get('cms_name', '').strip()
        
        uploads = WordlistUpload.objects.all().order_by('-created_at')
        
        if wordlist_name_filter:
            uploads = uploads.filter(wordlist_name__icontains=wordlist_name_filter)
        if cms_name_filter:
            uploads = uploads.filter(cms_name__icontains=cms_name_filter)
        
        uploads = uploads[:limit]
        
        data = [{
            'id': str(upload.id),
            'wordlist_name': upload.wordlist_name,
            'filename': upload.filename,
            'cms_name': upload.cms_name,
            'source': upload.source,
            'paths_count': upload.paths_count,
            'uploaded_count': upload.uploaded_count,
            'failed_count': upload.failed_count,
            'created_at': upload.created_at.isoformat(),
            'created_at_display': upload.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for upload in uploads]
        
        return JsonResponse({'success': True, 'uploads': data, 'count': len(data)})
    except Exception as e:
        logger.error(f"Error getting upload history: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@csrf_exempt
def suzu_check_duplicates_api(request):
    """
    API: Check for duplicate wordlist or paths before upload.
    
    POST /reconnaissance/api/suzu/check-duplicates/
    JSON body:
        {
            "wordlist_name": "wordpress.txt",
            "paths": ["/wp-admin/", "/wp-content/"],
            "cms_name": "wordpress"  // optional
        }
    
    Returns:
        {
            "success": true,
            "results": {
                "wordlist_exists": false,
                "existing_upload": null,
                "duplicate_paths": [],
                "new_paths": [...],
                "duplicate_count": 0,
                "new_count": 2
            }
        }
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        from ryu_app.models import WordlistUpload
        
        data = json.loads(request.body)
        wordlist_name = data.get('wordlist_name')
        paths = data.get('paths', [])
        cms_name = data.get('cms_name')
        
        results = {
            'wordlist_exists': False,
            'existing_upload': None,
            'duplicate_paths': [],
            'new_paths': paths,
            'duplicate_count': 0,
            'new_count': len(paths)
        }
        
        # Check if wordlist_name already exists
        if wordlist_name:
            existing_upload = WordlistUpload.objects.filter(wordlist_name=wordlist_name).order_by('-created_at').first()
            if existing_upload:
                results['wordlist_exists'] = True
                results['existing_upload'] = {
                    'id': str(existing_upload.id),
                    'created_at': existing_upload.created_at.isoformat(),
                    'uploaded_count': existing_upload.uploaded_count,
                    'paths_count': existing_upload.paths_count
                }
        
        # Check for duplicate paths in Vector DB
        # For very large files, we'll check a sample and estimate (to avoid timeout)
        # But we don't prevent upload - deduplication happens during upload anyway
        if paths:
            try:
                from suzu.vector_path_store import VectorPathStore
                vector_store = VectorPathStore()
                
                # For large files, check a sample for user info, but don't block upload
                # Sample size: up to 5000 paths (reasonable for quick check)
                sample_size = min(5000, len(paths))
                paths_to_check = paths[:sample_size] if len(paths) > sample_size else paths
                
                path_check = vector_store.check_existing_paths(paths_to_check, cms_name, wordlist_name)
                
                # Safety check: ensure path_check is valid and has required keys
                if not path_check or not isinstance(path_check, dict):
                    path_check = {'existing': [], 'new': paths_to_check, 'existing_count': 0, 'new_count': len(paths_to_check)}
                
                # Ensure counts are integers, not None
                existing_count = path_check.get('existing_count', 0)
                new_count = path_check.get('new_count', 0)
                if existing_count is None:
                    existing_count = 0
                if new_count is None:
                    new_count = 0
                existing_count = int(existing_count)
                new_count = int(new_count)
                
                results['duplicate_paths'] = path_check.get('existing', [])
                results['new_paths'] = path_check.get('new', paths_to_check)
                
                # Ensure sample_size is valid
                if sample_size is None:
                    sample_size = min(5000, len(paths))
                
                # If we only checked a sample, estimate the counts
                if len(paths) > sample_size:
                    sample_ratio = len(paths_to_check) / len(paths) if len(paths) > 0 else 1.0
                    results['duplicate_count'] = int(existing_count / sample_ratio) if sample_ratio > 0 else 0
                    results['new_count'] = len(paths) - results['duplicate_count']
                    results['sample_checked'] = True
                    results['sample_size'] = len(paths_to_check)
                    results['total_paths'] = len(paths)
                else:
                    results['duplicate_count'] = existing_count
                    results['new_count'] = new_count
                    results['sample_checked'] = False
            except Exception as e:
                logger.warning(f"Error checking duplicate paths in Vector DB: {e}")
                # Continue without path checking if Vector DB is unavailable
                # Don't block upload - deduplication happens during upload
                results['duplicate_count'] = 0
                results['new_count'] = len(paths)
        
        return JsonResponse({'success': True, 'results': results})
    except Exception as e:
        logger.error(f"Error checking duplicates: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


def learning_ip_effectiveness_api(request):
    """API: Get technique effectiveness by IP/ASN/CIDR using Django ORM"""
    try:
        if 'eggrecords' not in connections.databases:
            return JsonResponse({
                'success': False,
                'error': 'PostgreSQL database not configured. Set DB_HOST environment variable.'
            })
        
        limit = int(request.GET.get('limit', 100))
        
        try:
            ip_techniques_qs = IPTechniqueEffectiveness.objects.using('eggrecords').annotate(
                total_attempts=F('success_count') + F('failure_count')
            ).order_by('-total_attempts', '-success_count')[:limit]
            
            data = []
            for tech in ip_techniques_qs:
                tech_dict = {
                    'asn': tech.asn,
                    'cidr_block': tech.cidr_block,
                    'ipv6_prefix': tech.ipv6_prefix,
                    'waf_type': tech.waf_type,
                    'technique_name': tech.technique_name,
                    'success_count': tech.success_count,
                    'failure_count': tech.failure_count,
                    'success_rate': tech.success_rate,
                    'avg_scan_duration': float(tech.avg_scan_duration) if tech.avg_scan_duration else None,
                    'last_updated': tech.last_updated
                }
                data.append(_serialize_row(tech_dict))
            
            return JsonResponse({'success': True, 'count': len(data), 'data': data})
        except Exception as e:
            # Table might not exist
            logger.debug(f"IP technique effectiveness table may not exist: {e}")
            return JsonResponse({
                'success': True,
                'count': 0,
                'data': [],
                'note': 'IP-based effectiveness table not yet created'
            })
    except Exception as e:
        logger.error(f"Error getting IP effectiveness: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)})


def dashboard(request):
    """Main reconnaissance dashboard - redirects to overview"""
    context = {
        'title': 'Reconnaissance Team',
        'personalities': [
            {'name': 'Kage', 'icon': '⚡', 'url': '/reconnaissance/kage/', 'description': 'Port Scanner'},
            {'name': 'Kaze', 'icon': '💨', 'url': '/reconnaissance/kaze/', 'description': 'High-Speed Scanner'},
            {'name': 'Kumo', 'icon': '🌊', 'url': '/reconnaissance/kumo/', 'description': 'HTTP Spider'},
            {'name': 'Suzu', 'icon': '🔔', 'url': '/reconnaissance/suzu/', 'description': 'Directory Enumerator'},
            {'name': 'Ryu', 'icon': '🛡️', 'url': '/reconnaissance/ryu/', 'description': 'Cybersecurity'},
        ]
    }
    return render(request, 'reconnaissance/dashboard.html', context)


def general_dashboard(request):
    """General dashboard showing both Kage and Ryu's scans together"""
    context = {
        'personality': 'general',
        'title': 'Reconnaissance Overview',
        'icon': '🔍',
        'color': '#8b5cf6'
    }
    
    all_activities = []
    
    # Get Kage's scans using Django ORM
    if 'customer_eggs' in connections.databases:
        try:
            kage_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type__in=['kage_port_scan']
            ).select_related('record_id').order_by('-created_at')[:50]
            
            for scan in kage_scans:
                eggrecord = scan.record_id
                target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                all_activities.append({
                    'id': str(scan.id),
                    'target': target,
                    'scan_type': scan.scan_type or 'kage_port_scan',
                    'scan_status': scan.scan_status or 'completed',
                    'port': str(scan.port) if scan.port else '',
                    'service_name': scan.service_name or 'N/A',
                    'open_ports': scan.open_ports or '',
                    'created_at': scan.created_at,
                    'activity_type': 'scan',
                    'personality': 'kage'
                })
        except Exception as e:
            logger.warning(f"Could not query Kage scans: {e}", exc_info=True)
    
    # Get Ryu's scans using Django ORM
    if 'customer_eggs' in connections.databases:
        try:
            ryu_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='ryu_port_scan'
            ).select_related('record_id').order_by('-created_at')[:50]
            
            for scan in ryu_scans:
                eggrecord = scan.record_id
                target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                all_activities.append({
                    'id': str(scan.id),
                    'target': target,
                    'scan_type': scan.scan_type or 'ryu_port_scan',
                    'scan_status': scan.scan_status or 'completed',
                    'port': str(scan.port) if scan.port else '',
                    'service_name': scan.service_name or 'N/A',
                    'open_ports': scan.open_ports or '',
                    'created_at': scan.created_at,
                    'activity_type': 'scan',
                    'personality': 'ryu'
                })
        except Exception as e:
            logger.warning(f"Could not query Ryu scans: {e}", exc_info=True)
    
    # Sort all activities by created_at (most recent first)
    def get_sort_key(activity):
        created_at = activity.get('created_at')
        if created_at is None:
            return timezone.make_aware(datetime.min) if timezone.is_naive(datetime.min) else datetime.min
        if timezone.is_naive(created_at):
            return timezone.make_aware(created_at)
        return created_at
    all_activities.sort(key=get_sort_key, reverse=True)
    
    context['activities'] = all_activities[:100]
    context['total_count'] = len(all_activities)
    context['kage_scan_count'] = len([a for a in all_activities if a.get('personality') == 'kage'])
    context['ryu_scan_count'] = len([a for a in all_activities if a.get('personality') == 'ryu' and a.get('activity_type') == 'scan'])
    context['ryu_assessment_count'] = 0
    
    return render(request, 'reconnaissance/general_dashboard.html', context)


def oak_dashboard(request):
    """Oak Coordinator Dashboard - Task coordination and curation overview"""
    from django.db import connections
    from django.utils import timezone
    from datetime import datetime, timedelta
    
    context = {
        'personality': 'oak',
        'title': 'Oak Coordinator',
        'icon': '🌳',
        'color': '#10b981'
    }
    
    # Initialize stats
    stats = {
        'total_fingerprints': 0,
        'total_cve_matches': 0,
        'total_curated': 0,
        'pending_curation': 0,
        'recent_curations': 0,
        'autonomous_service_running': False,
        'curation_batches': 0,
        'targets_processed': 0
    }
    
    recent_curations = []
    
    # Try using Django ORM first (handles database routing automatically)
    try:
        from artificial_intelligence.customer_eggs_eggrecords_general_models.models import (
            TechnologyFingerprint, CVEFingerprintMatch, EggRecord
        )
        
        # Determine which database to use
        db_name = 'customer_eggs'
        if db_name not in connections.databases:
            db_name = 'eggrecords'
        if db_name not in connections.databases:
            db_name = 'default'
        
        # Count technology fingerprints using ORM
        try:
            stats['total_fingerprints'] = TechnologyFingerprint.objects.using(db_name).count()
        except Exception as e:
            logger.debug(f"Could not count fingerprints: {e}")
        
        # Count CVE matches using ORM
        try:
            stats['total_cve_matches'] = CVEFingerprintMatch.objects.using(db_name).count()
        except Exception as e:
            logger.debug(f"Could not count CVE matches: {e}")
        
        # Count curated records using ORM
        try:
            stats['total_curated'] = EggRecord.objects.using(db_name).filter(
                bugsy_last_curated_at__isnull=False
            ).count()
        except Exception as e:
            logger.debug(f"Could not count curated records: {e}")
        
        # Count pending curation
        try:
            thirty_days_ago = timezone.now() - timedelta(days=30)
            stats['pending_curation'] = EggRecord.objects.using(db_name).filter(
                subDomain__isnull=False,
                alive=True,
                skipScan=False
            ).filter(
                Q(bugsy_last_curated_at__isnull=True) | 
                Q(bugsy_last_curated_at__lt=thirty_days_ago)
            ).count()
        except Exception as e:
            logger.debug(f"Could not count pending curation: {e}")
        
        # Count recent curations (last 24 hours)
        try:
            one_day_ago = timezone.now() - timedelta(days=1)
            stats['recent_curations'] = EggRecord.objects.using(db_name).filter(
                bugsy_last_curated_at__gte=one_day_ago
            ).count()
        except Exception as e:
            logger.debug(f"Could not count recent curations: {e}")
        
        # Get recent curation activity
        try:
            recent_records = EggRecord.objects.using(db_name).filter(
                bugsy_last_curated_at__isnull=False
            ).order_by('-bugsy_last_curated_at')[:20]
            
            for record in recent_records:
                recent_curations.append({
                    'id': str(record.id),
                    'subdomain': record.subDomain or record.domainname or 'unknown',
                    'curated_at': record.bugsy_last_curated_at
                })
        except Exception as e:
            logger.debug(f"Could not get recent curations: {e}")
            
    except ImportError as e:
        logger.warning(f"Could not import models, using raw SQL fallback: {e}")
        # Fallback to raw SQL with error handling
        try:
            # Get database connection - try customer_eggs first (where eggrecords are)
            try:
                db = connections['customer_eggs']
            except KeyError:
                try:
                    db = connections['eggrecords']
                except KeyError:
                    db = connections['default']
            
            with db.cursor() as cursor:
                # Count technology fingerprints (with error handling)
                try:
                    cursor.execute("""
                        SELECT COUNT(*) FROM enrichment_system_technologyfingerprint
                    """)
                    stats['total_fingerprints'] = cursor.fetchone()[0] or 0
                except Exception as e:
                    logger.debug(f"Table enrichment_system_technologyfingerprint not available: {e}")
                
                # Count CVE matches (with error handling)
                try:
                    cursor.execute("""
                        SELECT COUNT(*) FROM enrichment_system_cvefingerprintmatch
                    """)
                    stats['total_cve_matches'] = cursor.fetchone()[0] or 0
                except Exception as e:
                    logger.debug(f"Table enrichment_system_cvefingerprintmatch not available: {e}")
                
                # Count curated records (have bugsy_last_curated_at)
                try:
                    cursor.execute("""
                        SELECT COUNT(*) FROM customer_eggs_eggrecords_general_models_eggrecord
                        WHERE bugsy_last_curated_at IS NOT NULL
                    """)
                    stats['total_curated'] = cursor.fetchone()[0] or 0
                except Exception as e:
                    logger.debug(f"Could not count curated records: {e}")
                
                # Count pending curation (alive, not skipped, not curated in 30 days)
                try:
                    thirty_days_ago = timezone.now() - timedelta(days=30)
                    cursor.execute("""
                        SELECT COUNT(*) FROM customer_eggs_eggrecords_general_models_eggrecord
                        WHERE "subDomain" IS NOT NULL
                        AND alive = true
                        AND "skipScan" = false
                        AND (bugsy_last_curated_at IS NULL OR bugsy_last_curated_at < %s)
                    """, [thirty_days_ago])
                    stats['pending_curation'] = cursor.fetchone()[0] or 0
                except Exception as e:
                    logger.debug(f"Could not count pending curation: {e}")
                
                # Count recent curations (last 24 hours)
                try:
                    one_day_ago = timezone.now() - timedelta(days=1)
                    cursor.execute("""
                        SELECT COUNT(*) FROM customer_eggs_eggrecords_general_models_eggrecord
                        WHERE bugsy_last_curated_at >= %s
                    """, [one_day_ago])
                    stats['recent_curations'] = cursor.fetchone()[0] or 0
                except Exception as e:
                    logger.debug(f"Could not count recent curations: {e}")
                
                # Get recent curation activity
                try:
                    cursor.execute("""
                        SELECT id, "subDomain", domainname, bugsy_last_curated_at
                        FROM customer_eggs_eggrecords_general_models_eggrecord
                        WHERE bugsy_last_curated_at IS NOT NULL
                        ORDER BY bugsy_last_curated_at DESC
                        LIMIT 20
                    """)
                    for row in cursor.fetchall():
                        recent_curations.append({
                            'id': str(row[0]),
                            'subdomain': row[1] or row[2] or 'unknown',
                            'curated_at': row[3]
                        })
                except Exception as e:
                    logger.debug(f"Could not get recent curations: {e}")
        except Exception as e:
            logger.error(f"Error loading Oak dashboard data: {e}", exc_info=True)
            context['error'] = f"Database error: {str(e)[:200]}"
    
    context['recent_curations'] = recent_curations
    
    # Check autonomous curation service status
    try:
        from artificial_intelligence.personalities.reconnaissance.oak.target_curation.autonomous_curation_service import get_instance
        autonomous_service = get_instance()
        if autonomous_service:
            stats['autonomous_service_running'] = getattr(autonomous_service, 'is_running', False)
            stats['curation_batches'] = getattr(autonomous_service, 'stats', {}).get('curation_batches', 0)
            stats['targets_processed'] = getattr(autonomous_service, 'stats', {}).get('targets_processed', 0)
    except Exception as e:
        logger.debug(f"Could not get autonomous service status: {e}")
    
    context['stats'] = stats
    
    return render(request, 'reconnaissance/oak_dashboard.html', context)


def kage_dashboard(request):
    """Kage Scout - Nmap/Port scanning database"""
    context = {
        'personality': 'kage',
        'title': 'Kage Scout Database',
        'icon': '⚡',
        'color': '#f59e0b'
    }
    
    # Get filter parameters from query string
    filter_target = request.GET.get('target', '').strip()
    filter_port = request.GET.get('port', '').strip()
    filter_service = request.GET.get('service', '').strip()
    filter_status = request.GET.get('status', '').strip()
    filter_date_from = request.GET.get('date_from', '').strip()
    filter_date_to = request.GET.get('date_to', '').strip()
    
    # Store filters in context for form persistence
    context['filters'] = {
        'target': filter_target,
        'port': filter_port,
        'service': filter_service,
        'status': filter_status,
        'date_from': filter_date_from,
        'date_to': filter_date_to
    }
    
    scans_from_eggrecords = []
    total_eggrecord_scans = 0
    
    if 'customer_eggs' in connections.databases:
        try:
            # Get scans using Django ORM with filtering
            nmap_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type__in=['kage_port_scan']
            )
            
            # Apply filters
            if filter_target:
                nmap_scans = nmap_scans.filter(target__icontains=filter_target)
            if filter_port:
                try:
                    port_int = int(filter_port)
                    nmap_scans = nmap_scans.filter(port=port_int)
                except ValueError:
                    # If port is not a number, try string match
                    nmap_scans = nmap_scans.filter(port__icontains=filter_port)
            if filter_service:
                nmap_scans = nmap_scans.filter(service_name__icontains=filter_service)
            if filter_status:
                nmap_scans = nmap_scans.filter(scan_status=filter_status)
            if filter_date_from:
                try:
                    from_date = datetime.strptime(filter_date_from, '%Y-%m-%d')
                    if timezone.is_naive(from_date):
                        from_date = timezone.make_aware(from_date)
                    nmap_scans = nmap_scans.filter(created_at__gte=from_date)
                except ValueError:
                    pass
            if filter_date_to:
                try:
                    to_date = datetime.strptime(filter_date_to, '%Y-%m-%d')
                    if timezone.is_naive(to_date):
                        to_date = timezone.make_aware(to_date)
                    # Add 1 day to include the entire end date
                    to_date = to_date + timedelta(days=1)
                    nmap_scans = nmap_scans.filter(created_at__lt=to_date)
                except ValueError:
                    pass
            
            nmap_scans = nmap_scans.order_by('-created_at')
            total_eggrecord_scans = nmap_scans.count()
            
            # Limit to 1000 records for performance (pagination will handle displaying 25 at a time)
            for scan in nmap_scans[:1000]:
                row_dict = {
                    'id': str(scan.id),
                    'target': scan.target or '',
                    'scan_type': scan.scan_type or '',
                    'scan_status': scan.scan_status or 'completed',
                    'port': scan.port,
                    'service_name': scan.service_name or '',
                    'open_ports': scan.open_ports or '',
                    'created_at': scan.created_at
                }
                serialized = _serialize_row(row_dict)
                serialized['full_data_json'] = json.dumps(serialized)
                scans_from_eggrecords.append(serialized)
        except Exception as e:
            logger.warning(f"Could not query customer_eggs database: {e}", exc_info=True)
    
    # Pagination
    paginator = Paginator(scans_from_eggrecords, 25)
    page = request.GET.get('page', 1)
    try:
        scans_page = paginator.page(page)
    except PageNotAnInteger:
        scans_page = paginator.page(1)
    except EmptyPage:
        scans_page = paginator.page(paginator.num_pages)
    
    context['scans'] = scans_page
    context['total_scans'] = total_eggrecord_scans
    context['eggrecord_scans'] = len(scans_from_eggrecords)
    context['learning_scans'] = 0
    
    # Get recent scans (last 24 hours) using Django ORM and last scan timestamp
    recent_scans_24h = 0
    last_scan_time = None
    if 'customer_eggs' in connections.databases:
        try:
            recent_time = timezone.now() - timedelta(hours=24)
            recent_scans_24h = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type__in=['kage_port_scan'],
                created_at__gte=recent_time
            ).count()
            # Get the timestamp of the most recent scan
            last_scan = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type__in=['kage_port_scan']
            ).order_by('-created_at').first()
            if last_scan:
                last_scan_time = last_scan.created_at
        except Exception as e:
            logger.debug(f"Could not query recent scans: {e}")
    
    context['recent_scans_24h'] = recent_scans_24h
    context['last_scan_time'] = last_scan_time
    
    # Get WAF detection stats using Django ORM
    if 'eggrecords' in connections.databases:
        try:
            context['waf_count'] = KageWAFDetection.objects.using('eggrecords').count()
        except Exception:
            context['waf_count'] = 0
    else:
        context['waf_count'] = 0
    
    # Get learning stats using Django ORM
    if 'eggrecords' in connections.databases:
        try:
            context['technique_count'] = KageTechniqueEffectiveness.objects.using('eggrecords').count()
        except Exception:
            context['technique_count'] = 0
    else:
        context['technique_count'] = 0
    
    return render(request, 'reconnaissance/kage_dashboard.html', context)


def kumo_dashboard(request):
    """Kumo Spider - HTTP request metadata database"""
    context = {
        'personality': 'kumo',
        'title': 'Kumo Spider Database',
        'icon': '🌊',
        'color': '#06b6d4'
    }
    
    requests_from_eggrecords = []
    
    if 'customer_eggs' in connections.databases:
        try:
            # Use Django ORM with Q objects for OR conditions
            kumo_requests = PostgresRequestMetadata.objects.using('customer_eggs').filter(
                Q(user_agent__icontains='Kumo') | Q(session_id__icontains='kumo')
            ).order_by('-created_at')[:50]
            
            for req in kumo_requests:
                row_dict = {
                    'id': str(req.id),
                    'target_url': req.url or '',
                    'request_method': req.method or 'GET',
                    'response_status': req.status_code or 0,
                    'response_time_ms': req.response_time_ms,
                    'user_agent': req.user_agent or '',
                    'timestamp': req.timestamp or req.created_at
                }
                serialized = _serialize_row(row_dict)
                serialized['full_data_json'] = json.dumps(serialized)
                requests_from_eggrecords.append(serialized)
        except Exception as e:
            logger.warning(f"Could not query customer_eggs database: {e}", exc_info=True)
    
    # Pagination
    paginator = Paginator(requests_from_eggrecords, 25)
    page = request.GET.get('page', 1)
    try:
        requests_page = paginator.page(page)
    except PageNotAnInteger:
        requests_page = paginator.page(1)
    except EmptyPage:
        requests_page = paginator.page(paginator.num_pages)
    
    context['requests'] = requests_page
    context['request_count'] = len(requests_from_eggrecords)
    context['eggrecord_requests'] = len(requests_from_eggrecords)
    context['learning_requests'] = 0
    
    # Get total request count using Django ORM
    if 'customer_eggs' in connections.databases:
        try:
            context['total_requests'] = PostgresRequestMetadata.objects.using('customer_eggs').count()
        except Exception:
            context['total_requests'] = 0
    else:
        context['total_requests'] = 0
    
    return render(request, 'reconnaissance/kumo_dashboard.html', context)


def suzu_dashboard(request):
    """Suzu (Bell) dashboard - Directory enumeration results with heuristics"""
    context = {
        'personality': 'suzu',
        'title': 'Suzu Directory Enumerator Database',
        'icon': '🔔',
        'color': '#f59e0b'
    }
    
    enumeration_results = []
    
    if 'customer_eggs' in connections.databases:
        try:
            # Try to use DirectoryEnumerationResult model (new format with heuristics)
            try:
                from artificial_intelligence.customer_eggs_eggrecords_general_models.models import DirectoryEnumerationResult
                
                # Query directory enumeration results
                # Wrap in try-except to catch database errors if table doesn't exist
                try:
                    dir_results = DirectoryEnumerationResult.objects.using('customer_eggs').order_by('-created_at')[:1000]
                    
                    # Log query result for debugging
                    result_count = dir_results.count() if hasattr(dir_results, 'count') else len(list(dir_results))
                    logger.debug(f"Suzu dashboard: Found {result_count} DirectoryEnumerationResult entries")
                    
                    seen_targets = {}
                    for result in dir_results:
                        egg_record_id = str(result.egg_record_id)
                        
                        # Get target from eggrecord if not already cached
                        if egg_record_id not in seen_targets:
                            try:
                                eggrecord = EggRecord.objects.using('customer_eggs').get(id=result.egg_record_id)
                                target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                                seen_targets[egg_record_id] = target
                            except Exception as e:
                                logger.debug(f"Could not get eggrecord {egg_record_id}: {e}")
                                target = 'unknown'
                                seen_targets[egg_record_id] = target
                        else:
                            target = seen_targets[egg_record_id]
                        
                        # Build result dict with heuristics data
                        row_dict = {
                            'id': str(result.id),
                            'target': target,
                            'path': result.discovered_path or '',
                            'status': result.path_status_code or 0,
                            'priority_score': float(result.priority_score) if result.priority_score else 0.0,
                            'priority_factors': result.priority_factors if isinstance(result.priority_factors, dict) else (json.loads(result.priority_factors) if isinstance(result.priority_factors, str) else {}),
                            'cms_detected': result.detected_cms,
                            'cms_version': result.detected_cms_version,
                            'cms_confidence': float(result.cms_detection_confidence) if result.cms_detection_confidence else 0.0,
                            'tool': result.enumeration_tool or 'unknown',
                            'wordlist': result.wordlist_used or 'default',
                            'content_length': result.path_content_length,
                            'content_type': result.path_content_type,
                            'response_time': result.path_response_time_ms,
                            'created_at': result.created_at,
                            'egg_record_id': egg_record_id
                        }
                        serialized = _serialize_row(row_dict)
                        serialized['full_data_json'] = json.dumps(serialized)
                        enumeration_results.append(serialized)
                    
                    # Get total count
                    context['total_enumerations'] = DirectoryEnumerationResult.objects.using('customer_eggs').count()
                    logger.debug(f"Suzu dashboard: Total enumerations in database: {context['total_enumerations']}")
                    
                except (ProgrammingError, OperationalError, DatabaseError) as db_error:
                    # Table doesn't exist yet - fall back to RequestMetadata
                    logger.warning(f"DirectoryEnumerationResult table not available: {db_error}, using RequestMetadata fallback")
                    raise  # Re-raise to trigger fallback handler
                
            except (ImportError, ProgrammingError, OperationalError, DatabaseError) as e:
                # Fallback: use RequestMetadata (legacy format)
                logger.warning(f"DirectoryEnumerationResult not available ({type(e).__name__}: {e}), using RequestMetadata fallback")
                suzu_requests = PostgresRequestMetadata.objects.using('customer_eggs').filter(
                    Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-')
                ).select_related('record_id').order_by('-created_at')[:100]
                
                for req in suzu_requests:
                    eggrecord = req.record_id
                    target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                    
                    row_dict = {
                        'id': str(req.id),
                        'target': target,
                        'path': req.url or '',
                        'status': req.status_code or 0,
                        'priority_score': 0.0,
                        'cms_detected': None,
                        'tool': 'legacy',
                        'wordlist': 'unknown',
                        'created_at': req.created_at,
                        'egg_record_id': str(req.record_id.id)
                    }
                    serialized = _serialize_row(row_dict)
                    serialized['full_data_json'] = json.dumps(serialized)
                    enumeration_results.append(serialized)
                
                context['total_enumerations'] = PostgresRequestMetadata.objects.using('customer_eggs').filter(
                    Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-')
                ).count()
                
        except Exception as e:
            logger.error(f"Could not query Suzu enumeration results: {e}", exc_info=True)
            context['total_enumerations'] = 0
            context['query_error'] = str(e)  # Add error to context for debugging
    
    # Pagination
    paginator = Paginator(enumeration_results, 25)
    page = request.GET.get('page', 1)
    try:
        results_page = paginator.page(page)
    except PageNotAnInteger:
        results_page = paginator.page(1)
    except EmptyPage:
        results_page = paginator.page(paginator.num_pages)
    
    context['enumeration_results'] = results_page
    context['enumeration_count'] = len(enumeration_results)
    
    if 'total_enumerations' not in context:
        context['total_enumerations'] = len(enumeration_results)
    
    # Get uploaded wordlist files
    try:
        from ryu_app.models import WordlistUpload
        uploaded_wordlists = WordlistUpload.objects.all().order_by('-created_at')[:50]
        context['uploaded_wordlists'] = uploaded_wordlists
        context['total_uploaded_wordlists'] = WordlistUpload.objects.count()
    except Exception as e:
        logger.warning(f"Could not query uploaded wordlists: {e}")
        context['uploaded_wordlists'] = []
        context['total_uploaded_wordlists'] = 0
    
    return render(request, 'reconnaissance/suzu_dashboard.html', context)


def ryu_dashboard(request):
    """Ryu Cybersecurity - Security assessment database"""
    from django.db import connections
    
    context = {
        'personality': 'ryu',
        'title': 'Ryu Cybersecurity Database',
        'icon': '🛡️',
        'color': '#10b981'
    }
    
    ryu_scans = []
    ryu_assessments = []
    
    # Get Ryu's Nmap scans
    if 'customer_eggs' in connections.databases:
        try:
            # Use Django ORM
            ryu_nmap_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='ryu_port_scan'
            ).select_related('record_id').order_by('-created_at')
            
            for scan in ryu_nmap_scans:
                eggrecord = scan.record_id
                target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                row_dict = {
                    'id': str(scan.id),
                    'record_id_id': str(scan.record_id.id),
                    'target': target,
                    'domainname': eggrecord.domainname or '',
                    'scan_type': scan.scan_type,
                    'scan_status': scan.scan_status,
                    'port': scan.port,
                    'service_name': scan.service_name,
                    'open_ports': scan.open_ports,
                    'created_at': scan.created_at,
                    'updated_at': scan.updated_at
                }
                serialized_row = _serialize_row(row_dict)
                ryu_scans.append({
                    'id': str(scan.id),
                    'target': target,
                    'scan_type': scan.scan_type or 'ryu_port_scan',
                    'scan_status': scan.scan_status or 'completed',
                    'port': str(scan.port) if scan.port else '',
                    'service_name': scan.service_name or 'N/A',
                    'open_ports': scan.open_ports or '',
                    'created_at': scan.created_at,
                    'full_data_json': json.dumps(serialized_row)
                })
        except Exception as e:
            logger.warning(f"Could not query Ryu scans: {e}", exc_info=True)
    
    # Sort by created_at
    def get_sort_key(activity):
        created_at = activity.get('created_at')
        if created_at is None:
            return timezone.make_aware(datetime.min) if timezone.is_naive(datetime.min) else datetime.min
        if timezone.is_naive(created_at):
            return timezone.make_aware(created_at)
        return created_at
    
    ryu_scans.sort(key=get_sort_key, reverse=True)
    
    # Pagination for scans
    scans_paginator = Paginator(ryu_scans, 25)
    scans_page_num = request.GET.get('scans_page', 1)
    try:
        scans_page = scans_paginator.page(scans_page_num)
    except PageNotAnInteger:
        scans_page = scans_paginator.page(1)
    except EmptyPage:
        scans_page = scans_paginator.page(scans_paginator.num_pages)
    
    # Pagination for assessments
    assessments_paginator = Paginator(ryu_assessments, 25)
    assessments_page_num = request.GET.get('assessments_page', 1)
    try:
        assessments_page = assessments_paginator.page(assessments_page_num)
    except PageNotAnInteger:
        assessments_page = assessments_paginator.page(1)
    except EmptyPage:
        assessments_page = assessments_paginator.page(assessments_paginator.num_pages)
    
    context['scans'] = scans_page
    context['assessments'] = assessments_page
    
    # Get counts using Django ORM
    if 'customer_eggs' in connections.databases:
        try:
            total_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='ryu_port_scan'
            ).count()
            
            recent_time = timezone.now() - timedelta(hours=24)
            recent_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='ryu_port_scan',
                created_at__gte=recent_time
            ).count()
            
            context['scan_count'] = total_scans
            context['scan_count_24h'] = recent_scans
            context['assessment_count'] = total_scans
            context['assessment_count_24h'] = recent_scans
            context['assessment_count_only'] = 0
            context['assessment_count_only_24h'] = 0
            context['vuln_targets'] = 0
        except Exception as e:
            logger.warning(f"Could not get Ryu stats: {e}", exc_info=True)
            context['scan_count'] = 0
            context['scan_count_24h'] = 0
            context['assessment_count'] = 0
            context['assessment_count_24h'] = 0
            context['assessment_count_only'] = 0
            context['assessment_count_only_24h'] = 0
            context['vuln_targets'] = 0
    else:
        context['scan_count'] = 0
        context['scan_count_24h'] = 0
        context['assessment_count'] = 0
        context['assessment_count_24h'] = 0
        context['assessment_count_only'] = 0
        context['assessment_count_only_24h'] = 0
        context['vuln_targets'] = 0
    
    return render(request, 'reconnaissance/ryu_dashboard.html', context)


def koga_dashboard(request):
    """Koga - Stealth Operations & Poison Testing dashboard"""
    context = {
        'personality': 'koga',
        'title': 'Koga Stealth Operations',
        'icon': '🥷',
        'color': '#7c3aed',
        'specialization': 'Stealth Operations & Poison Testing'
    }
    
    # Add placeholder stats (can be enhanced later with actual data)
    context['scan_count'] = 0
    context['scan_count_24h'] = 0
    context['stealth_operations'] = 0
    context['poison_tests'] = 0
    
    return render(request, 'reconnaissance/koga_dashboard.html', context)


def bugsy_dashboard(request):
    """Bugsy - Bug Bounty & Vulnerability Curation dashboard"""
    context = {
        'personality': 'bugsy',
        'title': 'Bugsy Bug Bounty',
        'icon': '🐛',
        'color': '#f59e0b',
        'specialization': 'Bug Bounty & Vulnerability Curation'
    }
    
    # Add placeholder stats (can be enhanced later with actual data)
    context['vulnerability_count'] = 0
    context['curation_count'] = 0
    context['bounty_count'] = 0
    
    return render(request, 'reconnaissance/bugsy_dashboard.html', context)


def koga_dashboard_redirect(request):
    """Redirect /koga/dashboard/about/ to /reconnaissance/koga/"""
    return redirect('/reconnaissance/koga/')


def bugsy_about_redirect(request):
    """Redirect /bugsy/about/ to /reconnaissance/bugsy/"""
    return redirect('/reconnaissance/bugsy/')


def surge_dashboard(request):
    """Surge Nuclei Scanner - Redirect to Surge app dashboard"""
    return redirect('surge:dashboard_about')


def monitoring_dashboard(request):
    """Comprehensive monitoring dashboard for all personalities"""
    context = {
        'personality': 'monitoring',
        'title': 'Reconnaissance Monitoring',
        'icon': '📊',
        'color': '#3b82f6'
    }
    
    # Simplified monitoring data (can be enhanced later)
    personalities = ['kage', 'kaze', 'kumo', 'suzu', 'ryu']
    monitoring_data = {}
    
    for personality in personalities:
        monitoring_data[personality] = {
            'success': True,
            'status': 'unknown',
            'last_activity': None,
            'total_scans': 0
        }
    
    context['monitoring_data'] = monitoring_data
    
    return render(request, 'reconnaissance/monitoring_dashboard.html', context)


def network_visualizer_dashboard(request):
    """Network visualizer dashboard - interactive network graph"""
    # #region agent log
    import json
    import traceback
    try:
        from django.urls import reverse, get_resolver, NoReverseMatch
        from django.conf import settings
        from django.urls import get_urlconf
        
        # Get current URLconf
        urlconf = get_urlconf()
        
        # Try to resolve the URL
        try:
            surge_url = reverse('surge:dashboard_about')
            url_resolved = True
            error_msg = None
        except NoReverseMatch as e:
            surge_url = None
            url_resolved = False
            error_msg = str(e)
        
        # Get resolver info
        resolver = get_resolver()
        namespaces = []
        if hasattr(resolver, 'namespace_dict'):
            namespaces = list(resolver.namespace_dict.keys())
        
        # Check INSTALLED_APPS
        installed_apps = getattr(settings, 'INSTALLED_APPS', [])
        surge_in_apps = 'surge' in installed_apps
        
        log_path = '/home/ego/github_public/.cursor/debug.log'
        try:
            import os
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, 'a') as f:
                f.write(json.dumps({
                    'sessionId': 'debug-session',
                    'runId': 'post-fix-detailed',
                    'hypothesisId': 'A',
                    'location': 'views.py:2271',
                    'message': 'URL resolution test - detailed',
                    'data': {
                        'url_resolved': url_resolved,
                        'resolved_url': surge_url,
                        'error': error_msg,
                        'available_namespaces': namespaces,
                        'urlconf': str(urlconf),
                        'surge_in_installed_apps': surge_in_apps,
                        'resolver_type': type(resolver).__name__
                    },
                    'timestamp': int(__import__('time').time() * 1000)
                }) + '\n')
        except (OSError, IOError):
            pass  # Silently fail if we can't write logs
    except Exception as e:
        log_path = '/home/ego/github_public/.cursor/debug.log'
        try:
            import os
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, 'a') as f:
                f.write(json.dumps({
                    'sessionId': 'debug-session',
                    'runId': 'post-fix-detailed',
                    'hypothesisId': 'A',
                    'location': 'views.py:2271',
                    'message': 'URL resolution test - exception during check',
                    'data': {
                        'error': str(e),
                        'error_type': type(e).__name__,
                        'traceback': traceback.format_exc()
                    },
                    'timestamp': int(__import__('time').time() * 1000)
                }) + '\n')
        except (OSError, IOError):
            pass  # Silently fail if we can't write logs
    # #endregion
    
    context = {
        'personality': 'network',
        'title': 'Network Mapping Visualizer',
        'icon': '🗺️',
        'color': '#8b5cf6'
    }
    return render(request, 'reconnaissance/network_visualizer.html', context)


@csrf_exempt
def network_options_api(request):
    """API endpoint to get dropdown options for eggname and projectegg"""
    from django.db import connections
    from .postgres_models import PostgresEggRecord
    
    try:
        if 'customer_eggs' not in connections.databases:
            return JsonResponse({'success': False, 'error': 'Database not configured'})
        
        # Get distinct eggnames and projecteggs
        eggnames = list(PostgresEggRecord.objects.using('customer_eggs')
                       .exclude(eggname__isnull=True)
                       .exclude(eggname='')
                       .values_list('eggname', flat=True)
                       .distinct()
                       .order_by('eggname'))
        
        projecteggs = list(PostgresEggRecord.objects.using('customer_eggs')
                          .exclude(projectegg__isnull=True)
                          .exclude(projectegg='')
                          .values_list('projectegg', flat=True)
                          .distinct()
                          .order_by('projectegg'))
        
        return JsonResponse({
            'success': True,
            'eggnames': list(eggnames),
            'projecteggs': list(projecteggs)
        })
    except Exception as e:
        logger.error(f"Error getting network options: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)})


@csrf_exempt
def network_visual_settings_api(request):
    """API endpoint to get and save visual settings for network graph"""
    if request.method == 'GET':
        # Return saved visual settings from session, or defaults
        default_settings = {
            'nodeColors': {
                'scanned': '#3b82f6',
                'unscanned': '#94a3b8',
                'cidr': '#10b981',
                'asn': '#f59e0b'
            },
            'nodeSize': 30,
            'edgeColor': '#64748b',
            'edgeWidth': 2,
            'edgeColorNetwork': '#8b5cf6',
            'edgeColorProject': '#ec4899'
        }
        
        # Get saved settings from session
        saved_settings = request.session.get('network_visual_settings', default_settings)
        
        return JsonResponse({
            'success': True,
            'settings': saved_settings
        })
    
    elif request.method == 'POST':
        # Save visual settings to session
        try:
            data = json.loads(request.body)
            settings = data.get('settings', {})
            
            # Validate and store settings
            if settings:
                request.session['network_visual_settings'] = settings
                request.session.modified = True
                return JsonResponse({
                    'success': True,
                    'message': 'Visual settings saved successfully'
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'No settings provided'
                })
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Invalid JSON data'
            })
        except Exception as e:
            logger.error(f"Error saving visual settings: {e}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    else:
        return JsonResponse({
            'success': False,
            'error': 'Method not allowed'
        }, status=405)


@csrf_exempt
def eggs_search_api(request):
    """API endpoint to search eggs for dropdown population"""
    from django.db import connections
    from .postgres_models import PostgresEggRecord
    
    try:
        if 'customer_eggs' not in connections.databases:
            return JsonResponse({'success': False, 'error': 'Database not configured'})
        
        # Get query parameters
        query = request.GET.get('q', '').strip()
        limit = int(request.GET.get('limit', 200))
        
        # Query eggrecords
        eggrecords_query = PostgresEggRecord.objects.using('customer_eggs').filter(alive=True)
        
        # Apply search filter if query provided
        if query:
            eggrecords_query = eggrecords_query.filter(
                Q(domainname__icontains=query) |
                Q(subDomain__icontains=query) |
                Q(eggname__icontains=query) |
                Q(projectegg__icontains=query)
            )
        
        # Get eggs with limit
        eggrecords = eggrecords_query.order_by('-updated_at')[:limit]
        
        # Format response
        eggs = []
        for egg in eggrecords:
            eggs.append({
                'id': str(egg.id),
                'domainname': egg.domainname or '',
                'subDomain': egg.subDomain or '',
                'eggname': egg.eggname or '',
                'projectegg': egg.projectegg or '',
                'ip_address': str(egg.ip_address) if egg.ip_address else '',
                'alive': egg.alive
            })
        
        return JsonResponse({
            'success': True,
            'eggs': eggs,
            'count': len(eggs)
        })
    except Exception as e:
        logger.error(f"Error searching eggs: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)})


@csrf_exempt
def network_graph_api(request):
    """API endpoint for network graph visualization with egg IP mapping and ASN network mapping"""
    from django.db import connections
    from .postgres_models import PostgresEggRecord, PostgresNmap
    import ipaddress
    from collections import defaultdict
    import socket
    
    try:
        # Get filter parameters
        level = request.GET.get('level', 'all')
        filter_asn = request.GET.get('filter_asn', '').strip()
        filter_cidr = request.GET.get('filter_cidr', '').strip()
        only_scanned_eggs = request.GET.get('only_scanned_eggs', 'false').lower() == 'true'
        eggname_filter = request.GET.get('eggname', '').strip()
        projectegg_filter = request.GET.get('projectegg', '').strip()
        
        # Safety: If no filters are provided, limit to 100 records to prevent huge responses
        if not filter_cidr and not eggname_filter and not projectegg_filter:
            logger.warning("Network graph API called without filters - limiting to 100 records for performance")
            max_records = 100
        else:
            max_records = 500
        
        # Try to import IP ownership validator for ASN lookups
        try:
            import sys
            import os
            # Try multiple paths for the IP ownership validator
            possible_paths = [
                '/mnt/webapps-nvme',
                '/media/ego/328010BE80108A8D2/github_public/LivingArchive-Kage-pro',
                os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            ]
            for path in possible_paths:
                if path not in sys.path:
                    sys.path.insert(0, path)
            
            from kage.ip_ownership_validator import IPOwnershipValidator
            ip_validator = IPOwnershipValidator()
            asn_available = True
        except Exception as e:
            logger.warning(f"IP ownership validator not available: {e}")
            ip_validator = None
            asn_available = False
        
        if 'customer_eggs' not in connections.databases:
            return JsonResponse({'success': False, 'error': 'Database not configured'})
        
        # Query eggrecords with filters
        eggrecords_query = PostgresEggRecord.objects.using('customer_eggs')
        
        if eggname_filter:
            eggrecords_query = eggrecords_query.filter(eggname=eggname_filter)
        if projectegg_filter:
            eggrecords_query = eggrecords_query.filter(projectegg=projectegg_filter)
        if filter_cidr:
            # Filter by CIDR range - convert to IP network and filter
            try:
                import ipaddress
                cidr_network = ipaddress.ip_network(filter_cidr, strict=False)
                # Filter IPs that are in the CIDR range
                # PostgreSQL supports CIDR operations
                eggrecords_query = eggrecords_query.extra(
                    where=["ip_address <<= %s"],
                    params=[str(cidr_network)]
                )
            except (ValueError, Exception) as e:
                logger.debug(f"Invalid CIDR filter {filter_cidr}: {e}")
        if only_scanned_eggs:
            # Only include eggs that have nmap scans
            eggrecords_query = eggrecords_query.filter(nmap_scans__isnull=False).distinct()
        
        # Limit results to prevent huge responses (max_records set above based on filters)
        eggrecords = list(eggrecords_query.select_related().prefetch_related('nmap_scans')[:max_records])
        
        # Build graph data structures
        nodes = []
        edges = []
        node_ids = set()
        scanned_ips = set()
        unscanned_ips = set()
        ip_to_asn = {}
        ip_to_cidr = {}
        ip_to_egg = {}
        ip_to_projectegg = defaultdict(set)
        asn_to_ips = defaultdict(set)
        cidr_to_ips = defaultdict(set)
        
        # Process eggrecords to build IP mapping
        for egg in eggrecords:
            # Get IP address
            ip = None
            if egg.ip_address:
                ip = str(egg.ip_address)
            elif egg.domainname:
                # Try to resolve domain (simplified - in production use proper DNS lookup)
                try:
                    ip = socket.gethostbyname(egg.domainname)
                except:
                    pass
            
            if not ip:
                continue
            
            # Check if IP has been scanned
            has_nmap = egg.nmap_scans.exists()
            if has_nmap:
                scanned_ips.add(ip)
            else:
                unscanned_ips.add(ip)
            
            # Store egg info for IP
            if ip not in ip_to_egg:
                ip_to_egg[ip] = []
            ip_to_egg[ip].append({
                'eggname': egg.eggname,
                'projectegg': egg.projectegg,
                'domainname': egg.domainname,
                'subDomain': egg.subDomain
            })
            
            # Track IPs by projectegg for creating project connections
            if egg.projectegg:
                ip_to_projectegg[egg.projectegg].add(ip)
            
            # Get ASN and CIDR for IP
            if asn_available and ip_validator:
                try:
                    ownership = ip_validator.validate_ip_ownership(ip)
                    asn = ownership.get('asn')
                    cidr = ownership.get('cidr')
                    
                    if asn:
                        ip_to_asn[ip] = asn
                        asn_to_ips[asn].add(ip)
                    if cidr:
                        ip_to_cidr[ip] = cidr
                        cidr_to_ips[cidr].add(ip)
                except Exception as e:
                    logger.debug(f"Error getting ASN for {ip}: {e}")
        
        # Build nodes
        # 1. Add IP nodes
        if level in ['all', 'ip']:
            for ip in scanned_ips:
                node_id = f"ip_{ip}"
                if node_id not in node_ids:
                    egg_info = ip_to_egg.get(ip, [])
                    label = ip
                    if egg_info:
                        eggnames = [e.get('eggname') for e in egg_info if e.get('eggname')]
                        if eggnames:
                            label = f"{ip}\n({', '.join(set(eggnames))})"
                    
                    nodes.append({
                        'id': node_id,
                        'label': label,
                        'type': 'ip',
                        'data': {
                            'ip': ip,
                            'scanned': True,
                            'asn': ip_to_asn.get(ip),
                            'cidr': ip_to_cidr.get(ip),
                            'eggs': egg_info
                        }
                    })
                    node_ids.add(node_id)
            
            for ip in unscanned_ips:
                node_id = f"ip_{ip}"
                if node_id not in node_ids:
                    egg_info = ip_to_egg.get(ip, [])
                    label = ip
                    if egg_info:
                        eggnames = [e.get('eggname') for e in egg_info if e.get('eggname')]
                        if eggnames:
                            label = f"{ip}\n({', '.join(set(eggnames))})"
                    
                    nodes.append({
                        'id': node_id,
                        'label': label,
                        'type': 'ip',
                        'data': {
                            'ip': ip,
                            'scanned': False,
                            'asn': ip_to_asn.get(ip),
                            'cidr': ip_to_cidr.get(ip),
                            'eggs': egg_info
                        }
                    })
                    node_ids.add(node_id)
        
        # 2. Add CIDR nodes
        if level in ['all', 'cidr']:
            for cidr, ips in cidr_to_ips.items():
                if filter_cidr and filter_cidr not in cidr:
                    continue
                
                node_id = f"cidr_{cidr}"
                if node_id not in node_ids:
                    scanned_count = sum(1 for ip in ips if ip in scanned_ips)
                    nodes.append({
                        'id': node_id,
                        'label': f"{cidr}\n({scanned_count}/{len(ips)} scanned)",
                        'type': 'cidr',
                        'data': {
                            'cidr': cidr,
                            'ip_count': len(ips),
                            'scanned_count': scanned_count
                        }
                    })
                    node_ids.add(node_id)
                    
                    # Add edges from IPs to CIDR
                    for ip in ips:
                        ip_node_id = f"ip_{ip}"
                        if ip_node_id in node_ids:
                            edge_id = f"{ip_node_id}_{node_id}"
                            if not any(e.get('id') == edge_id for e in edges):
                                edges.append({
                                    'id': edge_id,
                                    'source': ip_node_id,
                                    'target': node_id,
                                    'type': 'belongs_to',
                                    'label': 'belongs to'
                                })
                    
                    # Add edges between IPs in the same CIDR (network connections)
                    ip_list = list(ips)
                    for i, ip1 in enumerate(ip_list):
                        for ip2 in ip_list[i+1:]:
                            ip1_node_id = f"ip_{ip1}"
                            ip2_node_id = f"ip_{ip2}"
                            if ip1_node_id in node_ids and ip2_node_id in node_ids:
                                edge_id = f"{ip1_node_id}_{ip2_node_id}_network"
                                if not any(e.get('id') == edge_id for e in edges):
                                    # Calculate weight based on whether both IPs are scanned
                                    # Higher weight (0.8) if both scanned, medium (0.5) if mixed, lower (0.3) if both unscanned
                                    ip1_scanned = ip1 in scanned_ips
                                    ip2_scanned = ip2 in scanned_ips
                                    if ip1_scanned and ip2_scanned:
                                        weight = 0.8
                                    elif ip1_scanned or ip2_scanned:
                                        weight = 0.5
                                    else:
                                        weight = 0.3
                                    
                                    edges.append({
                                        'id': edge_id,
                                        'source': ip1_node_id,
                                        'target': ip2_node_id,
                                        'type': 'network',
                                        'label': 'same network',
                                        'weight': weight
                                    })
        
        # 3. Add ASN nodes
        if level in ['all', 'asn']:
            for asn, ips in asn_to_ips.items():
                if filter_asn and str(asn) != filter_asn:
                    continue
                
                node_id = f"asn_{asn}"
                if node_id not in node_ids:
                    scanned_count = sum(1 for ip in ips if ip in scanned_ips)
                    unscanned_count = len(ips) - scanned_count
                    
                    # Get ASN name if available
                    asn_name = f"AS{asn}"
                    if asn_available and ip_validator:
                        try:
                            # Try to get ASN name from ASN_TO_COMPANY mapping
                            from kage.ip_ownership_validator import ASN_TO_COMPANY
                            if asn in ASN_TO_COMPANY:
                                asn_info = ASN_TO_COMPANY[asn]
                                asn_name = asn_info.get('name', f"AS{asn}")
                        except:
                            pass
                    
                    nodes.append({
                        'id': node_id,
                        'label': f"{asn_name}\n({scanned_count} scanned, {unscanned_count} unscanned)",
                        'type': 'asn',
                        'data': {
                            'asn': asn,
                            'name': asn_name,
                            'ip_count': len(ips),
                            'scanned_count': scanned_count,
                            'unscanned_count': unscanned_count
                        }
                    })
                    node_ids.add(node_id)
                    
                    # Add edges from CIDRs to ASN
                    for ip in ips:
                        cidr = ip_to_cidr.get(ip)
                        if cidr:
                            cidr_node_id = f"cidr_{cidr}"
                            if cidr_node_id in node_ids:
                                edge_id = f"{cidr_node_id}_{node_id}"
                                if not any(e.get('id') == edge_id for e in edges):
                                    edges.append({
                                        'id': edge_id,
                                        'source': cidr_node_id,
                                        'target': node_id,
                                        'type': 'owned_by',
                                        'label': 'owned by'
                                    })
        
        # 4. Add edges between IPs in the same projectegg (project connections)
        for projectegg, project_ips in ip_to_projectegg.items():
            if len(project_ips) > 1:  # Only create edges if there are multiple IPs
                project_ip_list = list(project_ips)
                for i, ip1 in enumerate(project_ip_list):
                    for ip2 in project_ip_list[i+1:]:
                        ip1_node_id = f"ip_{ip1}"
                        ip2_node_id = f"ip_{ip2}"
                        if ip1_node_id in node_ids and ip2_node_id in node_ids:
                            # Check if edge already exists (might be created by CIDR network edges)
                            edge_id = f"{ip1_node_id}_{ip2_node_id}_project"
                            existing_edge = any(e.get('id') == edge_id or 
                                                (e.get('source') == ip1_node_id and e.get('target') == ip2_node_id) or
                                                (e.get('source') == ip2_node_id and e.get('target') == ip1_node_id)
                                                for e in edges)
                            if not existing_edge:
                                edges.append({
                                    'id': edge_id,
                                    'source': ip1_node_id,
                                    'target': ip2_node_id,
                                    'type': 'project',
                                    'label': f'same project: {projectegg}'
                                })
        
        # Calculate statistics
        stats = {
            'total_nodes': len(nodes),
            'total_edges': len(edges),
            'ip_nodes': sum(1 for n in nodes if n['type'] == 'ip'),
            'cidr_nodes': sum(1 for n in nodes if n['type'] == 'cidr'),
            'asn_nodes': sum(1 for n in nodes if n['type'] == 'asn'),
            'scanned_ips': len(scanned_ips),
            'unscanned_ips': len(unscanned_ips)
        }
        
        return JsonResponse({
            'success': True,
            'nodes': nodes,
            'edges': edges,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error generating network graph: {e}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)})


def eggrecord_list(request):
    """List all EggRecords with summary statistics using Django ORM"""
    import logging
    from django.db import connections
    from django.db.models import Count
    from .postgres_models import PostgresEggRecord
    
    logger = logging.getLogger(__name__)
    
    # Get filter parameters from query string
    filter_egg_id = request.GET.get('egg', '').strip()
    
    context = {
        'title': 'EggRecords Database',
        'icon': '🥚',
        'color': '#8b5cf6',
        'personality': 'eggrecords',
        'filter_egg_id': filter_egg_id
    }
    
    if 'customer_eggs' in connections.databases:
        try:
            # Build base queryset
            eggrecords_qs = PostgresEggRecord.objects.using('customer_eggs').select_related('egg_id')
            
            # Apply egg filter if provided
            if filter_egg_id:
                try:
                    eggrecords_qs = eggrecords_qs.filter(egg_id_id=filter_egg_id)
                except Exception as filter_error:
                    logger.warning(f"Error applying egg filter: {filter_error}")
            
            # Try with annotations first, fallback to simple query if annotations fail
            try:
                eggrecords_qs = eggrecords_qs.annotate(
                    nmap_count=Count('nmap_scans', distinct=True),
                    request_count=Count('http_requests', distinct=True),
                    dns_count=Count('dns_queries', distinct=True)
                ).order_by('-updated_at')
                use_annotations = True
            except Exception as annot_error:
                logger.warning(f"Annotations failed, using simple query: {annot_error}")
                eggrecords_qs = eggrecords_qs.order_by('-updated_at')
                use_annotations = False
            
            # Limit to 200 records only if no filter is applied (for performance)
            # When filtered, show all matching records (could be large, but user expects to see all)
            if not filter_egg_id:
                eggrecords_qs = eggrecords_qs[:200]
            
            # Convert queryset to list of dicts
            context['eggrecords'] = []
            for e in eggrecords_qs:
                eggrecord_dict = {
                    'id': str(e.id),
                    'subDomain': e.subDomain,
                    'domainname': e.domainname,
                    'alive': e.alive,
                    'created_at': e.created_at,
                    'updated_at': e.updated_at,
                    'eggname': getattr(e, 'eggname', None),
                    'projectegg': getattr(e, 'projectegg', None),
                    'egg_id': str(e.egg_id.id) if e.egg_id else None,
                    'egg_name': e.egg_id.eggName if e.egg_id else None,
                    'eisystem_name': e.egg_id.eisystem_in_thorm if e.egg_id else None,
                }
                if use_annotations:
                    eggrecord_dict['nmap_count'] = getattr(e, 'nmap_count', 0)
                    eggrecord_dict['request_count'] = getattr(e, 'request_count', 0)
                    eggrecord_dict['dns_count'] = getattr(e, 'dns_count', 0)
                else:
                    eggrecord_dict['nmap_count'] = 0
                    eggrecord_dict['request_count'] = 0
                    eggrecord_dict['dns_count'] = 0
                context['eggrecords'].append(eggrecord_dict)
            
            # Get filtered count for display
            if filter_egg_id:
                # If filtered, get all matching records count (not just the limited set)
                filtered_qs = PostgresEggRecord.objects.using('customer_eggs').filter(egg_id_id=filter_egg_id)
                context['filtered_count'] = filtered_qs.count()
            else:
                context['filtered_count'] = len(context['eggrecords'])
            
            context['total_count'] = len(context['eggrecords'])
            
            # Get total counts based on filter
            if filter_egg_id:
                context['total_eggrecords'] = PostgresEggRecord.objects.using('customer_eggs').filter(egg_id_id=filter_egg_id).count()
                context['alive_count'] = PostgresEggRecord.objects.using('customer_eggs').filter(egg_id_id=filter_egg_id, alive=True).count()
            else:
                context['total_eggrecords'] = PostgresEggRecord.objects.using('customer_eggs').count()
                context['alive_count'] = PostgresEggRecord.objects.using('customer_eggs').filter(alive=True).count()
            
            # Get unique eggs from the Eggs relationship for filter dropdowns
            try:
                from .postgres_models import PostgresEggs
                # Get eggs that have associated EggRecords
                eggs_with_records = PostgresEggs.objects.using('customer_eggs').filter(
                    egg_records__isnull=False
                ).distinct().values('id', 'eggName', 'eisystem_in_thorm').order_by('eggName')
                context['unique_eggs'] = list(eggs_with_records)
            except Exception as e:
                logger.warning(f"Error fetching unique eggs: {e}")
                context['unique_eggs'] = []
            context['unique_eggnames'] = []
            context['unique_projecteggs'] = []
            
            # Also keep legacy eggname/projectegg filters for backwards compatibility
            try:
                unique_eggnames = PostgresEggRecord.objects.using('customer_eggs').filter(
                    eggname__isnull=False
                ).exclude(eggname='').values_list('eggname', flat=True).distinct().order_by('eggname')
                context['unique_eggnames'] = list(unique_eggnames)
            except Exception as e:
                logger.warning(f"Error fetching unique eggnames: {e}")
                context['unique_eggnames'] = []
            
            try:
                unique_projecteggs = PostgresEggRecord.objects.using('customer_eggs').filter(
                    projectegg__isnull=False
                ).exclude(projectegg='').values_list('projectegg', flat=True).distinct().order_by('projectegg')
                context['unique_projecteggs'] = list(unique_projecteggs)
            except Exception as e:
                logger.warning(f"Error fetching unique projecteggs: {e}")
                context['unique_projecteggs'] = []
        except Exception as e:
            logger.error(f"Error fetching EggRecords: {e}", exc_info=True)
            context['error'] = str(e)
            context['eggrecords'] = []
            context['total_count'] = 0
            context['total_eggrecords'] = 0
            context['alive_count'] = 0
            context['unique_eggs'] = []
            context['unique_eggnames'] = []
            context['unique_projecteggs'] = []
    else:
        # Fallback to local SQLite
        try:
            eggrecords = EggRecord.objects.all().order_by('-updated_at')[:200]
            context['eggrecords'] = [{
                'id': str(e.id),
                'subDomain': e.subDomain,
                'domainname': e.domainname,
                'alive': e.alive,
                'created_at': e.created_at,
                'updated_at': e.updated_at,
                'eggname': getattr(e, 'eggname', None),
                'projectegg': getattr(e, 'projectegg', None),
                'nmap_count': 0,
                'request_count': 0,
                'dns_count': 0
            } for e in eggrecords]
            context['total_count'] = len(context['eggrecords'])
            context['total_eggrecords'] = EggRecord.objects.count()
            context['alive_count'] = EggRecord.objects.filter(alive=True).count()
            
            # Get unique eggnames and projecteggs for filter dropdowns (SQLite fallback)
            try:
                unique_eggnames = EggRecord.objects.filter(
                    eggname__isnull=False
                ).exclude(eggname='').values_list('eggname', flat=True).distinct().order_by('eggname')
                context['unique_eggnames'] = list(unique_eggnames)
            except Exception as e:
                logger.warning(f"Error fetching unique eggnames from SQLite: {e}")
                context['unique_eggnames'] = []
            
            try:
                unique_projecteggs = EggRecord.objects.filter(
                    projectegg__isnull=False
                ).exclude(projectegg='').values_list('projectegg', flat=True).distinct().order_by('projectegg')
                context['unique_projecteggs'] = list(unique_projecteggs)
            except Exception as e:
                logger.warning(f"Error fetching unique projecteggs from SQLite: {e}")
                context['unique_projecteggs'] = []
        except Exception as e:
            logger.error(f"Error fetching EggRecords from SQLite: {e}")
            context['error'] = str(e)
            context['eggrecords'] = []
            context['total_count'] = 0
            context['total_eggrecords'] = 0
            context['alive_count'] = 0
            context['unique_eggs'] = []
            context['unique_eggnames'] = []
            context['unique_projecteggs'] = []
    
    return render(request, 'reconnaissance/eggrecord_list.html', context)


def eggrecord_detail(request, eggrecord_id):
    """Comprehensive EggRecord detail page with all related data"""
    from django.db import connections
    
    context = {
        'eggrecord_id': eggrecord_id,
        'title': 'EggRecord Details',
        'icon': '🥚',
        'color': '#8b5cf6',
        'personality': 'eggrecords'
    }
    
    if 'customer_eggs' in connections.databases:
        try:
            # Get eggrecord using Django ORM
            try:
                eggrecord = PostgresEggRecord.objects.using('customer_eggs').get(id=eggrecord_id)
                # Get IP addresses - check both ip_address field and ip JSONB field
                ip_address_str = str(eggrecord.ip_address) if eggrecord.ip_address else None
                ip_list = []
                
                # Try to get additional IPs from the ip JSONB field
                try:
                    ip_field = getattr(eggrecord, 'ip', None)
                    if ip_field:
                        if isinstance(ip_field, list):
                            ip_list = [str(ip) for ip in ip_field if ip]
                        elif isinstance(ip_field, str):
                            import json
                            try:
                                ip_list = json.loads(ip_field) if ip_field else []
                            except (json.JSONDecodeError, TypeError):
                                ip_list = []
                    # If ip_address is set but not in ip_list, add it
                    if ip_address_str and ip_address_str not in ip_list:
                        ip_list.insert(0, ip_address_str)
                    elif not ip_address_str and ip_list:
                        # Use first IP from list as primary if ip_address is not set
                        ip_address_str = ip_list[0] if ip_list else None
                except Exception as e:
                    logger.debug(f"Could not parse IP list: {e}")
                    if ip_address_str:
                        ip_list = [ip_address_str]
                
                context['eggrecord'] = {
                    'id': str(eggrecord.id),
                    'subDomain': eggrecord.subDomain,
                    'domainname': eggrecord.domainname,
                    'ip_address': ip_address_str,
                    'ip_addresses': ip_list,  # List of all IP addresses
                    'alive': eggrecord.alive,
                    'eggname': eggrecord.eggname,
                    'projectegg': eggrecord.projectegg,
                    'created_at': eggrecord.created_at,
                    'updated_at': eggrecord.updated_at
                }
            except PostgresEggRecord.DoesNotExist:
                context['error'] = 'EggRecord not found'
                return render(request, 'reconnaissance/eggrecord_detail.html', context)
        except Exception as e:
            logger.error(f"Error fetching EggRecord: {e}", exc_info=True)
            context['error'] = str(e)
            return render(request, 'reconnaissance/eggrecord_detail.html', context)
        
        # Get related Nmap scans using Django ORM
        try:
            nmap_scans = PostgresNmap.objects.using('customer_eggs').filter(
                record_id_id=eggrecord_id
            ).order_by('-created_at')
            context['nmap_scans'] = [{
                'id': str(scan.id),
                'record_id_id': str(scan.record_id_id),
                'target': scan.target,
                'scan_type': scan.scan_type,
                'scan_status': scan.scan_status,
                'port': scan.port,
                'service_name': scan.service_name,
                'open_ports': scan.open_ports,
                'created_at': scan.created_at,
                'updated_at': scan.updated_at
            } for scan in nmap_scans]
            context['nmap_count'] = len(context['nmap_scans'])
        except Exception as e:
            logger.warning(f"Could not query Nmap: {e}", exc_info=True)
            context['nmap_scans'] = []
            context['nmap_count'] = 0
        
        # Get related RequestMetadata using Django ORM
        try:
            requests = PostgresRequestMetadata.objects.using('customer_eggs').filter(
                record_id_id=eggrecord_id
            ).order_by('-created_at')
            context['requests'] = [{
                'id': str(req.id),
                'record_id_id': str(req.record_id_id),
                'url': req.url,
                'method': req.method,
                'status_code': req.status_code,
                'created_at': req.created_at
            } for req in requests]
            context['request_count'] = len(context['requests'])
        except Exception as e:
            logger.warning(f"Could not query RequestMetadata: {e}")
            context['requests'] = []
            context['request_count'] = 0
    else:
        # Fallback to local SQLite
        try:
            eggrecord = EggRecord.objects.get(id=eggrecord_id)
            context['eggrecord'] = {
                'id': str(eggrecord.id),
                'subDomain': eggrecord.subDomain,
                'domainname': eggrecord.domainname,
                'alive': eggrecord.alive,
                'created_at': eggrecord.created_at,
                'updated_at': eggrecord.updated_at
            }
            context['nmap_scans'] = []
            context['nmap_count'] = 0
            context['requests'] = []
            context['request_count'] = 0
        except EggRecord.DoesNotExist:
            context['error'] = 'EggRecord not found'
            return render(request, 'reconnaissance/eggrecord_detail.html', context)
        except Exception as e:
            logger.error(f"Error fetching EggRecord from SQLite: {e}")
            context['error'] = str(e)
            return render(request, 'reconnaissance/eggrecord_detail.html', context)
    
    return render(request, 'reconnaissance/eggrecord_detail.html', context)


def personality_status_api(request, personality):
    """API: Get personality service status"""
    from django.db import connections
    from pathlib import Path
    import os
    
    try:
        if personality not in ['kage', 'kaze', 'kumo', 'suzu', 'ryu']:
            return JsonResponse({
                'success': False,
                'error': f'Invalid personality: {personality}'
            })
        
        # Check if daemon is running
        # Primary method: check PID file (for non-Docker setups)
        status = 'stopped'
        pid_file = Path(f'/tmp/{personality}_daemon.pid')
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 0)  # Check if process exists (signal 0 just checks)
                status = 'running'
            except (ProcessLookupError, ValueError, OSError):
                # Process doesn't exist, remove stale PID file
                try:
                    pid_file.unlink()
                except:
                    pass
                status = 'stopped'
        
        # Optional: Try health check API as secondary verification (non-blocking)
        # This is only used to confirm status, not to determine it
        # We skip this to avoid circular dependencies and connection issues
        
        response_data = {
            'success': True,
            'status': status,
            'message': f'{personality.capitalize()} is {status}',
        }
        
        # Get database stats if available using Django ORM
        if 'customer_eggs' in connections.databases:
            try:
                if personality == 'kage':
                    response_data['total_scans'] = PostgresNmap.objects.using('customer_eggs').filter(
                        scan_type__in=['kage_port_scan']
                    ).count()
                elif personality == 'kaze':
                    response_data['total_scans'] = PostgresNmap.objects.using('customer_eggs').filter(
                        scan_type='kaze_port_scan'
                    ).count()
                elif personality == 'kumo':
                    response_data['total_requests'] = PostgresRequestMetadata.objects.using('customer_eggs').filter(
                        Q(user_agent__icontains='Kumo') | Q(session_id__startswith='kumo-')
                    ).count()
                elif personality == 'suzu':
                    response_data['total_enumerations'] = PostgresRequestMetadata.objects.using('customer_eggs').filter(
                        Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-')
                    ).count()
                elif personality == 'ryu':
                    response_data['total_scans'] = PostgresNmap.objects.using('customer_eggs').filter(
                        scan_type='ryu_port_scan'
                    ).count()
            except Exception as e:
                logger.debug(f"Could not get database stats for {personality}: {e}")
        
        return JsonResponse(response_data)
    except Exception as e:
        logger.error(f"Error checking {personality} status: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'status': 'unknown',
            'error': str(e)
        })


@csrf_exempt
def personality_control_api(request, personality, action):
    """API: Control personality service (start/pause/kill)"""
    import os
    import sys
    import subprocess
    import signal
    from pathlib import Path
    
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        if personality not in ['kage', 'kaze', 'kumo', 'suzu', 'ryu']:
            return JsonResponse({
                'success': False,
                'error': f'Invalid personality: {personality}'
            })
        
        if action not in ['start', 'pause', 'resume', 'kill']:
            return JsonResponse({
                'success': False,
                'error': f'Invalid action: {action}. Must be start, pause, resume, or kill'
            })
        
        # Map personality to daemon script path
        # Try multiple methods to find project root for compatibility with Docker and local environments
        from django.conf import settings
        # Method 1: Use BASE_DIR from settings
        project_root = settings.BASE_DIR
        # Method 2: If daemons don't exist in BASE_DIR, try parent of ryu_app (more reliable)
        daemons_dir = project_root / 'daemons'
        if not daemons_dir.exists():
            # views.py is in ryu_app/, so parent.parent gets us to project root
            project_root = Path(__file__).resolve().parent.parent
            daemons_dir = project_root / 'daemons'
        
        daemon_scripts = {
            'kage': daemons_dir / 'kage_daemon.py',
            'kaze': daemons_dir / 'kaze_daemon.py',
            'kumo': daemons_dir / 'kumo_daemon.py',
            'suzu': daemons_dir / 'suzu_daemon.py',
            'ryu': daemons_dir / 'ryu_daemon.py',
        }
        
        pid_file = Path(f'/tmp/{personality}_daemon.pid')
        
        # Check if daemon is running
        def is_running():
            if not pid_file.exists():
                return False
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, 0)  # Signal 0 just checks if process exists
                return True
            except (ProcessLookupError, ValueError, OSError):
                if pid_file.exists():
                    pid_file.unlink()
                return False
        
        # Get PID if running
        def get_pid():
            if not pid_file.exists():
                return None
            try:
                return int(pid_file.read_text().strip())
            except (ValueError, OSError):
                return None
        
        # Handle different actions
        if action == 'start':
            if is_running():
                return JsonResponse({
                    'success': True,
                    'status': 'running',
                    'message': f'{personality} is already running'
                })
            
            # Find daemon script
            daemon_script = daemon_scripts.get(personality)
            if not daemon_script or not daemon_script.exists():
                # Include debug info in error message
                expected_path = str(daemon_script) if daemon_script else 'None'
                project_root_str = str(project_root)
                logger.error(f"Daemon script not found for {personality}. Expected: {expected_path}, Project root: {project_root_str}")
                return JsonResponse({
                    'success': False,
                    'error': f'Daemon script not found for {personality}',
                    'details': f'Expected path: {expected_path}, Project root: {project_root_str}'
                })
            
            # Start daemon
            try:
                process = subprocess.Popen(
                    [sys.executable, str(daemon_script)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(project_root)
                )
                
                # Wait a moment for PID file to be created and process to initialize
                import time
                time.sleep(2)  # Increased wait time to allow daemon to initialize
                
                # Check if process is still alive
                if process.poll() is not None:
                    # Process has already terminated (crashed)
                    stderr_output = process.stderr.read().decode('utf-8', errors='ignore')[:500]  # Limit error message length
                    logger.error(f"{personality} daemon crashed immediately. stderr: {stderr_output}")
                    return JsonResponse({
                        'success': False,
                        'error': f'{personality} daemon crashed on startup. Check server logs for details.',
                        'details': stderr_output if stderr_output else 'No error output captured'
                    })
                
                # Check if daemon is running (PID file exists and process is alive)
                if is_running():
                    return JsonResponse({
                        'success': True,
                        'status': 'running',
                        'message': f'{personality} started successfully'
                    })
                else:
                    # Process is alive but PID file doesn't exist - might still be initializing
                    # Check again after another short wait
                    time.sleep(1)
                    if is_running():
                        return JsonResponse({
                            'success': True,
                            'status': 'running',
                            'message': f'{personality} started successfully'
                        })
                    else:
                        # Still not running - check for errors
                        if process.poll() is not None:
                            stderr_output = process.stderr.read().decode('utf-8', errors='ignore')[:500]
                            logger.error(f"{personality} daemon failed to start. stderr: {stderr_output}")
                            return JsonResponse({
                                'success': False,
                                'error': f'{personality} failed to start. Check server logs for details.',
                                'details': stderr_output if stderr_output else 'No error output captured'
                            })
                        else:
                            # Process is running but PID file not created - might be a timing issue
                            logger.warning(f"{personality} process is running but PID file not found")
                            return JsonResponse({
                                'success': False,
                                'error': f'{personality} process started but PID file not created. Process may still be initializing.'
                            })
            except Exception as e:
                logger.error(f"Error starting {personality}: {e}", exc_info=True)
                return JsonResponse({
                    'success': False,
                    'error': f'Error starting {personality}: {str(e)}'
                })
        
        elif action == 'pause':
            if not is_running():
                return JsonResponse({
                    'success': False,
                    'error': f'{personality} is not running'
                })
            
            pid = get_pid()
            if pid:
                try:
                    os.kill(pid, signal.SIGUSR1)
                    return JsonResponse({
                        'success': True,
                        'status': 'paused',
                        'message': f'{personality} paused'
                    })
                except Exception as e:
                    logger.error(f"Error pausing {personality}: {e}", exc_info=True)
                    return JsonResponse({
                        'success': False,
                        'error': f'Error pausing {personality}: {str(e)}'
                    })
            else:
                return JsonResponse({
                    'success': False,
                    'error': f'Could not get PID for {personality}'
                })
        
        elif action == 'resume':
            if not is_running():
                return JsonResponse({
                    'success': False,
                    'error': f'{personality} is not running'
                })
            
            pid = get_pid()
            if pid:
                try:
                    os.kill(pid, signal.SIGUSR2)
                    return JsonResponse({
                        'success': True,
                        'status': 'running',
                        'message': f'{personality} resumed'
                    })
                except Exception as e:
                    logger.error(f"Error resuming {personality}: {e}", exc_info=True)
                    return JsonResponse({
                        'success': False,
                        'error': f'Error resuming {personality}: {str(e)}'
                    })
            else:
                return JsonResponse({
                    'success': False,
                    'error': f'Could not get PID for {personality}'
                })
        
        elif action == 'kill':
            if not is_running():
                return JsonResponse({
                    'success': True,
                    'status': 'stopped',
                    'message': f'{personality} is already stopped'
                })
            
            pid = get_pid()
            if pid:
                try:
                    # Try graceful shutdown first
                    os.kill(pid, signal.SIGTERM)
                    
                    # Wait for process to stop
                    import time
                    for _ in range(10):
                        if not is_running():
                            return JsonResponse({
                                'success': True,
                                'status': 'stopped',
                                'message': f'{personality} stopped successfully'
                            })
                        time.sleep(0.5)
                    
                    # Force kill if still running
                    if is_running():
                        os.kill(pid, signal.SIGKILL)
                        time.sleep(0.5)
                        return JsonResponse({
                            'success': True,
                            'status': 'stopped',
                            'message': f'{personality} force-killed'
                        })
                    else:
                        return JsonResponse({
                            'success': True,
                            'status': 'stopped',
                            'message': f'{personality} stopped successfully'
                        })
                except ProcessLookupError:
                    return JsonResponse({
                        'success': True,
                        'status': 'stopped',
                        'message': f'{personality} process not found (already stopped)'
                    })
                except Exception as e:
                    logger.error(f"Error killing {personality}: {e}", exc_info=True)
                    return JsonResponse({
                        'success': False,
                        'error': f'Error stopping {personality}: {str(e)}'
                    })
            else:
                return JsonResponse({
                    'success': False,
                    'error': f'Could not get PID for {personality}'
                })
        
    except Exception as e:
        logger.error(f"Error controlling {personality}: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


@csrf_exempt
def personality_logs_api(request, personality):
    """API: Get activity logs for a personality daemon"""
    from pathlib import Path
    
    if request.method != 'GET':
        return JsonResponse({'success': False, 'error': 'GET method required'}, status=405)
    
    try:
        if personality not in ['kage', 'kaze', 'kumo', 'suzu', 'ryu']:
            return JsonResponse({
                'success': False,
                'error': f'Invalid personality: {personality}'
            }, status=400)
        
        # Get limit from query params
        limit = int(request.GET.get('limit', 50))
        
        # Map personality to log file (check multiple possible locations)
        log_file_candidates = {
            'kage': ['/tmp/kage_daemon.log', '/tmp/kage.log'],
            'kaze': ['/tmp/kaze_daemon.log', '/tmp/kaze.log'],
            'kumo': ['/tmp/kumo_daemon.log', '/tmp/kumo.log'],
            'suzu': ['/tmp/suzu_daemon.log', '/tmp/suzu.log'],
            'ryu': ['/tmp/ryu_daemon.log', '/tmp/ryu.log'],
        }
        
        # Find the first existing log file
        log_file = None
        for log_path_str in log_file_candidates.get(personality, []):
            try:
                if os.path.exists(log_path_str) and os.path.isfile(log_path_str):
                    log_file = log_path_str
                    break
            except Exception as e:
                logger.debug(f"Error checking log path {log_path_str}: {e}")
                continue
        
        if not log_file:
            # Return empty data instead of error - log file may not exist yet
            return JsonResponse({
                'success': True,
                'data': [],
                'message': f'Log file not found for {personality}. Checked: {log_file_candidates.get(personality, [])}'
            })
        
        # Read last N lines from log file
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                # Get last 'limit' lines
                recent_lines = lines[-limit:] if len(lines) > limit else lines
                
                # Parse log entries
                log_entries = []
                for line in recent_lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try to parse timestamp and level from common log formats
                    entry = {
                        'raw': line,
                        'timestamp': '',
                        'level': 'INFO',
                        'message': line
                    }
                    
                    # Try to parse common log formats
                    # Format: "2025-12-11 16:20:00 [KAGE] INFO: message"
                    import re
                    timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    if timestamp_match:
                        entry['timestamp'] = timestamp_match.group(1)
                    
                    level_match = re.search(r'\[(ERROR|WARNING|INFO|DEBUG)\]', line)
                    if level_match:
                        entry['level'] = level_match.group(1)
                    
                    # Extract message (everything after timestamp and level)
                    message_start = max(
                        line.find(']') + 1 if ']' in line else 0,
                        line.find(':') + 1 if ':' in line else 0
                    )
                    if message_start > 0:
                        entry['message'] = line[message_start:].strip()
                    
                    log_entries.append(entry)
                
                return JsonResponse({
                    'success': True,
                    'data': log_entries,
                    'count': len(log_entries),
                    'personality': personality
                })
        except Exception as e:
            logger.error(f"Error reading log file: {e}", exc_info=True)
            return JsonResponse({
                'success': False,
                'error': f'Error reading log file: {str(e)}'
            }, status=500)
            
    except Exception as e:
        logger.error(f"Error getting logs for {personality}: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def check_egg_queue_status_api(request, egg_id):
    """API: Check if an Egg (and its EggRecords) is queued"""
    from django.db import connections
    from pathlib import Path
    
    try:
        # Simplified version - return empty status
        personalities = ['kage', 'kaze', 'kumo', 'suzu', 'ryu']
        status = {}
        
        for personality in personalities:
            status[personality] = {
                'queued': False,
                'queued_count': 0,
                'total_eggrecords': 0,
                'queued_eggrecords': []
            }
        
        return JsonResponse({
            'success': True,
            'status': status,
            'note': 'Queue status not available in simplified implementation'
        })
    except Exception as e:
        logger.error(f"Error checking queue status: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


# ============================================================================
# Terminal Execution API Endpoints (AI Agent Bridge)
# ============================================================================

@csrf_exempt
@require_http_methods(["POST"])
def terminal_execute_api(request):
    """
    API: Execute a terminal command (with optional approval workflow)
    
    POST /reconnaissance/api/terminal/execute/
    
    Request body (JSON):
        {
            "command": "ls -la",
            "working_directory": "/path/to/dir",  # Optional
            "timeout": 30,  # Optional, default: 30
            "require_approval": true,  # Optional, default: auto-detect
            "user_id": "user123",  # Optional
            "session_id": "session456",  # Optional
            "metadata": {}  # Optional
        }
    
    Returns:
        {
            "success": true,
            "request_id": "cmd_1234567890_12345",
            "status": "pending_approval" | "completed" | "failed",
            "result": { ... }  # If executed immediately
        }
    """
    try:
        from .terminal_execution_service import get_terminal_service
        
        data = json.loads(request.body)
        command = data.get('command')
        
        if not command:
            return JsonResponse({
                'success': False,
                'error': 'Command is required'
            }, status=400)
        
        service = get_terminal_service()
        
        result = service.submit_command(
            command=command,
            working_directory=data.get('working_directory'),
            timeout=data.get('timeout'),
            require_approval=data.get('require_approval'),
            user_id=data.get('user_id'),
            session_id=data.get('session_id'),
            metadata=data.get('metadata')
        )
        
        return JsonResponse(result)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        logger.error(f"Error in terminal_execute_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def terminal_approve_api(request, request_id):
    """
    API: Approve a pending command
    
    POST /reconnaissance/api/terminal/approve/<request_id>/
    
    Request body (JSON, optional):
        {
            "user_id": "user123"  # Optional
        }
    
    Returns:
        {
            "success": true,
            "request_id": "cmd_1234567890_12345",
            "result": { ... }
        }
    """
    try:
        from .terminal_execution_service import get_terminal_service
        
        data = json.loads(request.body) if request.body else {}
        service = get_terminal_service()
        
        result = service.approve_command(
            request_id=request_id,
            user_id=data.get('user_id')
        )
        
        status_code = 200 if result.get('success') else 400
        return JsonResponse(result, status=status_code)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        logger.error(f"Error in terminal_approve_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def terminal_reject_api(request, request_id):
    """
    API: Reject a pending command
    
    POST /reconnaissance/api/terminal/reject/<request_id>/
    
    Request body (JSON, optional):
        {
            "user_id": "user123"  # Optional
        }
    
    Returns:
        {
            "success": true,
            "request_id": "cmd_1234567890_12345",
            "status": "rejected"
        }
    """
    try:
        from .terminal_execution_service import get_terminal_service
        
        data = json.loads(request.body) if request.body else {}
        service = get_terminal_service()
        
        result = service.reject_command(
            request_id=request_id,
            user_id=data.get('user_id')
        )
        
        return JsonResponse(result)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        logger.error(f"Error in terminal_reject_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def terminal_pending_api(request):
    """
    API: Get all pending approval requests
    
    GET /reconnaissance/api/terminal/pending/
    
    Returns:
        {
            "success": true,
            "pending": [
                {
                    "request_id": "cmd_1234567890_12345",
                    "request": { ... }
                }
            ]
        }
    """
    try:
        from .terminal_execution_service import get_terminal_service
        
        service = get_terminal_service()
        pending = service.get_pending_approvals()
        
        return JsonResponse({
            'success': True,
            'pending': pending,
            'count': len(pending)
        })
        
    except Exception as e:
        logger.error(f"Error in terminal_pending_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def terminal_history_api(request):
    """
    API: Get command execution history
    
    GET /reconnaissance/api/terminal/history/
    
    Query params:
        - limit: Number of commands to return (default: 50, max: 500)
    
    Returns:
        {
            "success": true,
            "history": [ ... ],
            "count": 50
        }
    """
    try:
        from .terminal_execution_service import get_terminal_service
        
        limit = min(int(request.GET.get('limit', 50)), 500)
        service = get_terminal_service()
        history = service.get_command_history(limit=limit)
        
        return JsonResponse({
            'success': True,
            'history': history,
            'count': len(history)
        })
        
    except Exception as e:
        logger.error(f"Error in terminal_history_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def terminal_stats_api(request):
    """
    API: Get terminal execution service statistics
    
    GET /reconnaissance/api/terminal/stats/
    
    Returns:
        {
            "success": true,
            "stats": {
                "total_commands": 100,
                "approved_commands": 80,
                "rejected_commands": 10,
                "blocked_commands": 5,
                "failed_commands": 5,
                "pending_approvals": 2,
                "running_commands": 1,
                "history_size": 50
            }
        }
    """
    try:
        from .terminal_execution_service import get_terminal_service
        
        service = get_terminal_service()
        stats = service.get_stats()
        
        return JsonResponse({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error in terminal_stats_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def terminal_cancel_api(request, request_id):
    """
    API: Cancel a running command
    
    POST /reconnaissance/api/terminal/cancel/<request_id>/
    
    Returns:
        {
            "success": true,
            "request_id": "cmd_1234567890_12345",
            "message": "Command cancelled"
        }
    """
    try:
        from .terminal_execution_service import get_terminal_service
        
        service = get_terminal_service()
        result = service.cancel_command(request_id)
        
        status_code = 200 if result.get('success') else 404
        return JsonResponse(result, status=status_code)
        
    except Exception as e:
        logger.error(f"Error in terminal_cancel_api: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def mitre_soc2_dashboard(request):
    """MITRE ATT&CK and SOC2 compliance dashboard"""
    context = {
        'personality': 'mitre_soc2',
        'title': 'MITRE ATT&CK & SOC2 Dashboard',
        'icon': '🛡️',
        'color': '#dc2626',
        'mitre_tactics_count': 14,
        'mitre_techniques_count': 200,
        'soc2_controls_count': 67,
        'compliance_score': 85,
        'threats_detected': 0,
        'controls_active': 0,
        'last_assessment': timezone.now().strftime('%Y-%m-%d %H:%M') if timezone else 'N/A'
    }
    
    # Get actual MITRE technique mappings from recent scans
    try:
        mapper = get_mitre_mapper()
        recent_scans = []
        
        # Get recent scan results
        if 'customer_eggs' in connections.databases:
            try:
                nmap_scans = PostgresNmap.objects.using('customer_eggs').select_related('record_id').order_by('-created_at')[:100]
                for scan in nmap_scans:
                    eggrecord = scan.record_id
                    target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                    finding = {
                        'path': '',
                        'url': f"http://{target}",
                        'service_name': scan.service_name or '',
                        'description': f"{scan.scan_type} scan on {target}",
                    }
                    recent_scans.append(finding)
            except Exception as e:
                logger.warning(f"Could not query scans for MITRE mapping: {e}", exc_info=True)
        
        # Analyze and get technique counts
        if recent_scans:
            analysis = mapper.analyze_scan_results(recent_scans)
            context['mitre_techniques_count'] = analysis['summary']['total_techniques']
            context['mitre_tactics_count'] = analysis['summary']['total_tactics']
            context['threats_detected'] = analysis['summary']['high_relevance']
            context['controls_active'] = analysis['summary']['high_confidence']
    except Exception as e:
        logger.warning(f"Error in MITRE analysis: {e}", exc_info=True)
    
    return render(request, 'reconnaissance/mitre_soc2_dashboard.html', context)


def mitre_soc2_status_api(request):
    """API endpoint for MITRE ATT&CK and SOC2 status"""
    try:
        mapper = get_mitre_mapper()
        recent_scans = []
        
        # Get recent scan results
        if 'customer_eggs' in connections.databases:
            try:
                nmap_scans = PostgresNmap.objects.using('customer_eggs').select_related('record_id').order_by('-created_at')[:100]
                for scan in nmap_scans:
                    eggrecord = scan.record_id
                    target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                    finding = {
                        'path': '',
                        'url': f"http://{target}",
                        'service_name': scan.service_name or '',
                        'description': f"{scan.scan_type} scan on {target}",
                    }
                    recent_scans.append(finding)
            except Exception as e:
                logger.warning(f"Could not query scans: {e}", exc_info=True)
        
        # Analyze scan results
        analysis = mapper.analyze_scan_results(recent_scans) if recent_scans else {
            'summary': {'total_techniques': 0, 'total_tactics': 0, 'high_confidence': 0, 'high_relevance': 0},
            'techniques': [],
            'tactics': {}
        }
        
        return JsonResponse({
            'mitre_tactics': analysis['summary']['total_tactics'],
            'mitre_techniques': analysis['summary']['total_techniques'],
            'soc2_controls': 67,
            'compliance_score': 85,
            'threats_detected': analysis['summary']['high_relevance'],
            'controls_active': analysis['summary']['high_confidence'],
            'last_assessment': timezone.now().isoformat() if timezone else None,
            'techniques': analysis['techniques'][:20],  # Top 20 techniques
            'tactics': analysis['tactics']
        })
    except Exception as e:
        logger.error(f"Error in mitre_soc2_status_api: {e}", exc_info=True)
        return JsonResponse({
            'error': str(e)
        }, status=500)


@csrf_exempt
def mitre_map_finding_api(request):
    """
    API endpoint to map a specific finding to MITRE techniques.
    
    POST /reconnaissance/api/mitre-soc2/map/
    {
        "path": "/wp-admin/",
        "url": "http://example.com/wp-admin/",
        "service_name": "wordpress",
        "vulnerability_type": "authentication_bypass",
        "description": "WordPress admin panel discovered"
    }
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required'}, status=405)
    
    try:
        data = json.loads(request.body)
        mapper = get_mitre_mapper()
        
        techniques = mapper.map_finding_to_mitre_techniques(data)
        
        return JsonResponse({
            'success': True,
            'finding': data,
            'techniques': [
                {
                    'id': tech.technique_id,
                    'name': tech.technique_name,
                    'tactic': tech.tactic,
                    'confidence': tech.confidence,
                    'relevance': tech.relevance,
                    'description': tech.description
                }
                for tech in techniques
            ],
            'count': len(techniques)
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in mitre_map_finding_api: {e}", exc_info=True)
        return JsonResponse({
            'error': str(e)
        }, status=500)


def mitre_analyze_scans_api(request):
    """
    API endpoint to analyze all recent scans and return MITRE technique mappings.
    
    GET /reconnaissance/api/mitre-soc2/analyze/?limit=100
    """
    try:
        limit = int(request.GET.get('limit', 100))
        mapper = get_mitre_mapper()
        recent_scans = []
        
        # Get recent scan results
        if 'customer_eggs' in connections.databases:
            try:
                nmap_scans = PostgresNmap.objects.using('customer_eggs').select_related('record_id').order_by('-created_at')[:limit]
                for scan in nmap_scans:
                    eggrecord = scan.record_id
                    target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                    
                    # Parse open_ports if available
                    open_ports_data = []
                    if scan.open_ports:
                        try:
                            open_ports_data = json.loads(scan.open_ports) if isinstance(scan.open_ports, str) else scan.open_ports
                        except:
                            pass
                    
                    finding = {
                        'path': '',
                        'url': f"http://{target}",
                        'service_name': scan.service_name or '',
                        'description': f"{scan.scan_type} scan on {target}",
                        'target': target,
                        'port': scan.port,
                        'open_ports': open_ports_data,
                    }
                    recent_scans.append(finding)
            except Exception as e:
                logger.warning(f"Could not query scans: {e}", exc_info=True)
        
        # Analyze scan results
        analysis = mapper.analyze_scan_results(recent_scans) if recent_scans else {
            'summary': {'total_techniques': 0, 'total_tactics': 0, 'high_confidence': 0, 'high_relevance': 0},
            'techniques': [],
            'tactics': {}
        }
        
        return JsonResponse({
            'success': True,
            'scans_analyzed': len(recent_scans),
            'analysis': analysis
        })
    except Exception as e:
        logger.error(f"Error in mitre_analyze_scans_api: {e}", exc_info=True)
        return JsonResponse({
            'error': str(e)
        }, status=500)


def settings_dashboard(request):
    """Settings dashboard with GitHub update checking"""
    from pathlib import Path
    import subprocess
    
    # Get current version
    current_version = "unknown"
    current_commit = "unknown"
    try:
        # Try to get current commit hash
        result = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            current_commit = result.stdout.strip()
            current_version = current_commit
        
        # Try to get latest tag if available
        tag_result = subprocess.run(
            ['git', 'describe', '--tags', '--abbrev=0'],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=5
        )
        if tag_result.returncode == 0:
            current_version = tag_result.stdout.strip()
    except Exception as e:
        logger.debug(f"Could not determine git version: {e}")
    
    context = {
        'title': 'Settings',
        'icon': '⚙️',
        'color': '#64748b',
        'personality': 'settings',
        'current_version': current_version,
        'current_commit': current_commit,
        'repository_url': 'https://github.com/CharlesMcGowen/LivingArchive-Kage-pro',
        'repository_owner': 'CharlesMcGowen',
        'repository_name': 'LivingArchive-Kage-pro'
    }
    
    return render(request, 'reconnaissance/settings_dashboard.html', context)


@csrf_exempt
@require_http_methods(["GET"])
def github_check_updates_api(request):
    """
    API endpoint to check GitHub for updates.
    
    GET /reconnaissance/api/github/check-updates/
    
    Returns:
        JSON with latest release/tag information and comparison with current version
    """
    import requests
    import subprocess
    from pathlib import Path
    
    try:
        # Repository info
        repo_owner = 'CharlesMcGowen'
        repo_name = 'LivingArchive-Kage-pro'
        
        # Get current version
        current_version = None
        current_commit = None
        try:
            repo_path = Path(__file__).parent.parent
            result = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                current_commit = result.stdout.strip()
                current_version = current_commit
            
            # Try to get latest tag
            tag_result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            if tag_result.returncode == 0:
                current_version = tag_result.stdout.strip()
        except Exception as e:
            logger.debug(f"Could not determine current version: {e}")
        
        # Check for latest release
        latest_release = None
        latest_tag = None
        update_available = False
        
        try:
            # Try to get latest release
            release_url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/releases/latest'
            response = requests.get(release_url, timeout=10)
            
            if response.status_code == 200:
                release_data = response.json()
                latest_release = {
                    'tag_name': release_data.get('tag_name'),
                    'name': release_data.get('name'),
                    'published_at': release_data.get('published_at'),
                    'html_url': release_data.get('html_url'),
                    'body': release_data.get('body', ''),
                    'prerelease': release_data.get('prerelease', False),
                    'draft': release_data.get('draft', False)
                }
                latest_tag = latest_release['tag_name']
                
                # Compare versions (simple string comparison for tags)
                if current_version and latest_tag and latest_tag != current_version:
                    update_available = True
            elif response.status_code == 404:
                # No releases, try to get latest tag
                tags_url = f'https://api.github.com/repos/{repo_owner}/{repo_name}/tags'
                tags_response = requests.get(tags_url, params={'per_page': 1}, timeout=10)
                
                if tags_response.status_code == 200:
                    tags_data = tags_response.json()
                    if tags_data:
                        latest_tag = tags_data[0].get('name')
                        if current_version and latest_tag and latest_tag != current_version:
                            update_available = True
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to check GitHub for updates: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Failed to connect to GitHub API: {str(e)}',
                'current_version': current_version or 'unknown',
                'update_available': False
            }, status=500)
        
        return JsonResponse({
            'success': True,
            'current_version': current_version or 'unknown',
            'current_commit': current_commit or 'unknown',
            'latest_release': latest_release,
            'latest_tag': latest_tag,
            'update_available': update_available,
            'repository_url': f'https://github.com/{repo_owner}/{repo_name}'
        })
        
    except Exception as e:
        logger.error(f"Error checking GitHub updates: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e),
            'current_version': 'unknown',
            'update_available': False
        }, status=500)

