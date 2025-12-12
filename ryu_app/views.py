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
            # Convert UTC to local timezone for display
            if timezone.is_naive(value):
                # If naive, assume it's UTC and make it aware
                value = timezone.make_aware(value, dt_timezone.utc)
            # Convert to local timezone
            local_time = timezone.localtime(value)
            result[key] = local_time.strftime('%Y-%m-%d %H:%M:%S')
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
    
    scan_records = []
    
    # Try to use PostgreSQL database if available
    if 'customer_eggs' in connections.databases:
        try:
            # Get detailed scan records using Django ORM
            nmap_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='kaze_port_scan'
            ).select_related('record_id').order_by('-created_at')
            
            for scan in nmap_scans:
                eggrecord = scan.record_id
                target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                serialized_row = {
                    'id': str(scan.id),
                    'record_id_id': str(scan.record_id.id),
                    'target': target,
                    'domainname': eggrecord.domainname or '',
                    'scan_type': scan.scan_type,
                    'scan_status': scan.scan_status,
                    'port': str(scan.port) if scan.port else '',
                    'service_name': scan.service_name or 'N/A',
                    'open_ports': scan.open_ports or '',
                    'created_at': scan.created_at,
                    'updated_at': scan.updated_at
                }
                scan_records.append({
                    'id': str(scan.id),
                    'target': target,
                    'scan_type': scan.scan_type or 'kaze_port_scan',
                    'scan_status': scan.scan_status or 'completed',
                    'port': str(scan.port) if scan.port else '',
                    'service_name': scan.service_name or 'N/A',
                    'open_ports': scan.open_ports or '',
                    'created_at': scan.created_at,
                    'full_data_json': json.dumps(_serialize_row(serialized_row))
                })
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
    context['total_scans'] = len(scan_records)
    
    # Get recent scans (last 24 hours) using Django ORM
    recent_scans_24h = 0
    if 'customer_eggs' in connections.databases:
        try:
            recent_time = timezone.now() - timedelta(hours=24)
            recent_scans_24h = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type='kaze_port_scan',
                created_at__gte=recent_time
            ).count()
        except Exception as e:
            logger.debug(f"Could not query recent Kaze scans: {e}")
    else:
        try:
            recent_time = timezone.now() - timedelta(hours=24)
            recent_scans_24h = EggRecord.objects.filter(updated_at__gte=recent_time).count()
        except Exception as e:
            logger.debug(f"Could not query recent Kaze scans from SQLite: {e}")
    
    context['recent_scans_24h'] = recent_scans_24h
    
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
            
            # Get stored rules from database using Django ORM
            try:
                rules = CalculatedHeuristicsRule.objects.using('eggrecords').order_by(
                    '-confidence_score', '-sample_count'
                )[:50]
                
                stored_rules = []
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
                
                context['heuristics_rules'] = stored_rules
                context['arguments_count'] = len(set(
                    arg for rule in stored_rules 
                    for arg in (rule.get('nmap_arguments') or [])
                ))
                # Extract unique arguments from rules
                all_args = []
                for rule in stored_rules:
                    all_args.extend(rule.get('nmap_arguments', []))
                context['arguments'] = list(set(all_args))[:20]  # Top 20 unique arguments
            except Exception as e:
                logger.debug(f"Could not query calculated_heuristics_rules: {e}")
                # Fallback to calculated rules if table doesn't exist
                context['heuristics_rules'] = calculated_rules if 'calculated_rules' in locals() else []
                context['arguments_count'] = len(set(
                    arg for rule in (calculated_rules if 'calculated_rules' in locals() else [])
                    for arg in (rule.get('nmap_arguments', []))
                ))
                all_args = []
                for rule in (calculated_rules if 'calculated_rules' in locals() else []):
                    all_args.extend(rule.get('nmap_arguments', []))
                context['arguments'] = list(set(all_args))[:20]
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
                waf_details_count = WAFDetectionDetail.objects.using('eggrecords').count()
                has_enhanced_waf = waf_details_count > 0
            except Exception:
                has_enhanced_waf = False
            
            if has_enhanced_waf:
                # Use WAFDetectionDetail with aggregations
                waf_patterns_qs = WAFDetectionDetail.objects.using('eggrecords').filter(
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
                ip_techniques_qs = IPTechniqueEffectiveness.objects.using('eggrecords').annotate(
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
                decisions_qs = KageScanResult.objects.using('eggrecords').filter(
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


def kage_dashboard(request):
    """Kage Scout - Nmap/Port scanning database"""
    context = {
        'personality': 'kage',
        'title': 'Kage Scout Database',
        'icon': '⚡',
        'color': '#f59e0b'
    }
    
    scans_from_eggrecords = []
    total_eggrecord_scans = 0
    
    if 'customer_eggs' in connections.databases:
        try:
            # Get scans using Django ORM
            nmap_scans = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type__in=['kage_port_scan']
            ).order_by('-created_at')
            
            total_eggrecord_scans = nmap_scans.count()
            
            for scan in nmap_scans:
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
    
    # Get recent scans (last 24 hours) using Django ORM
    recent_scans_24h = 0
    if 'customer_eggs' in connections.databases:
        try:
            recent_time = timezone.now() - timedelta(hours=24)
            recent_scans_24h = PostgresNmap.objects.using('customer_eggs').filter(
                scan_type__in=['kage_port_scan'],
                created_at__gte=recent_time
            ).count()
        except Exception as e:
            logger.debug(f"Could not query recent scans: {e}")
    
    context['recent_scans_24h'] = recent_scans_24h
    
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
    """Suzu (Bell) dashboard - Directory enumeration results"""
    context = {
        'personality': 'suzu',
        'title': 'Suzu Directory Enumerator Database',
        'icon': '🔔',
        'color': '#f59e0b'
    }
    
    enumeration_results = []
    
    if 'customer_eggs' in connections.databases:
        try:
            # Use Django ORM with Q objects for OR conditions
            suzu_requests = PostgresRequestMetadata.objects.using('customer_eggs').filter(
                Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-')
            ).select_related('record_id').order_by('-created_at')
            
            for req in suzu_requests:
                eggrecord = req.record_id
                target = eggrecord.subDomain or eggrecord.domainname or 'unknown'
                
                row_dict = {
                    'id': str(req.id),
                    'record_id_id': str(req.record_id.id),
                    'target': target,
                    'domainname': eggrecord.domainname or '',
                    'target_url': req.url or '',
                    'request_method': req.method or 'GET',
                    'response_status': req.status_code or 0,
                    'response_headers': '',  # Not in model yet
                    'response_time_ms': req.response_time_ms,
                    'user_agent': req.user_agent or '',
                    'session_id': req.session_id or '',
                    'timestamp': req.timestamp or req.created_at,
                    'created_at': req.created_at,
                    'updated_at': req.updated_at or req.created_at
                }
                serialized_row = _serialize_row(row_dict)
                
                enumeration_metadata = {
                    'tool': 'unknown',
                    'enumeration_type': 'wordlist',
                }
                
                enumeration_results.append({
                    'id': str(req.id),
                    'target': target,
                    'path': req.url or '',
                    'status': req.status_code or 0,
                    'tool': enumeration_metadata.get('tool', 'unknown'),
                    'enumeration_type': enumeration_metadata.get('enumeration_type', 'wordlist'),
                    'created_at': req.created_at,
                    'full_data_json': json.dumps(serialized_row)
                })
        except Exception as e:
            logger.warning(f"Could not query Suzu enumeration results: {e}", exc_info=True)
    
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
    
    # Get total enumeration count using Django ORM
    if 'customer_eggs' in connections.databases:
        try:
            context['total_enumerations'] = PostgresRequestMetadata.objects.using('customer_eggs').filter(
                Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-')
            ).count()
        except Exception:
            context['total_enumerations'] = 0
    else:
        context['total_enumerations'] = 0
    
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
                                    edges.append({
                                        'id': edge_id,
                                        'source': ip1_node_id,
                                        'target': ip2_node_id,
                                        'type': 'network',
                                        'label': 'same network'
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
    from django.db import connections
    from django.db.models import Count
    from .postgres_models import PostgresEggRecord
    
    context = {
        'title': 'EggRecords Database',
        'icon': '🥚',
        'color': '#8b5cf6',
        'personality': 'eggrecords'
    }
    
    if 'customer_eggs' in connections.databases:
        try:
            # Use Django ORM with annotations for counts
            eggrecords = PostgresEggRecord.objects.using('customer_eggs').annotate(
                nmap_count=Count('nmap_scans', distinct=True),
                request_count=Count('http_requests', distinct=True),
                dns_count=Count('dns_queries', distinct=True)
            ).order_by('-updated_at')[:200]
            
            context['eggrecords'] = [{
                'id': str(e.id),
                'subDomain': e.subDomain,
                'domainname': e.domainname,
                'alive': e.alive,
                'created_at': e.created_at,
                'updated_at': e.updated_at,
                'eggname': getattr(e, 'eggname', None),
                'projectegg': getattr(e, 'projectegg', None),
                'nmap_count': e.nmap_count,
                'request_count': e.request_count,
                'dns_count': e.dns_count,
            } for e in eggrecords]
            
            context['total_count'] = len(context['eggrecords'])
            context['total_eggrecords'] = PostgresEggRecord.objects.using('customer_eggs').count()
            context['alive_count'] = PostgresEggRecord.objects.using('customer_eggs').filter(alive=True).count()
        except Exception as e:
            logger.error(f"Error fetching EggRecords: {e}", exc_info=True)
            context['error'] = str(e)
            context['eggrecords'] = []
            context['total_count'] = 0
            context['total_eggrecords'] = 0
            context['alive_count'] = 0
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
                'nmap_count': 0,
                'request_count': 0,
                'dns_count': 0
            } for e in eggrecords]
            context['total_count'] = len(context['eggrecords'])
            context['total_eggrecords'] = EggRecord.objects.count()
            context['alive_count'] = EggRecord.objects.filter(alive=True).count()
        except Exception as e:
            logger.error(f"Error fetching EggRecords from SQLite: {e}")
            context['error'] = str(e)
            context['eggrecords'] = []
            context['total_count'] = 0
            context['total_eggrecords'] = 0
            context['alive_count'] = 0
    
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
                context['eggrecord'] = {
                    'id': str(eggrecord.id),
                    'subDomain': eggrecord.subDomain,
                    'domainname': eggrecord.domainname,
                    'ip_address': str(eggrecord.ip_address) if eggrecord.ip_address else None,
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
        # Use health API endpoint - daemons call this to register their health
        status = 'stopped'
        try:
            import requests
            # Check daemon health via Django's own API endpoint
            # Daemons that are running will have registered their health
            health_url = f'http://localhost:9000/reconnaissance/api/daemon/{personality}/health/'
            try:
                response = requests.get(health_url, timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    # Only mark as running if health check succeeds AND we have a functional daemon
                    # For personalities without daemons (like suzu), the health endpoint will still work
                    # but we need to check if there's actually a daemon container
                    if data.get('status') == 'healthy' or data.get('success'):
                        # Additional check: verify daemon container exists for personalities that should have daemons
                        if personality in ['kage', 'kumo', 'ryu']:
                            # These should have daemon containers - verify via health check response
                            # If health check returns healthy, daemon is running
                            status = 'running'
                        elif personality == 'suzu':
                            # Suzu doesn't have a daemon yet, so always show as stopped
                            status = 'stopped'
                        else:
                            # For other personalities, trust the health check
                            status = 'running'
            except (requests.exceptions.RequestException, requests.exceptions.Timeout) as e:
                logger.debug(f"Could not reach daemon health endpoint: {e}")
        except Exception as e:
            logger.debug(f"Could not check daemon status via API: {e}")
        
        # Fallback: check PID file (for non-Docker setups)
        if status == 'stopped':
            pid_file = Path(f'/tmp/{personality}_daemon.pid')
            if pid_file.exists():
                try:
                    pid = int(pid_file.read_text().strip())
                    os.kill(pid, 0)  # Check if process exists
                    status = 'running'
                except (ProcessLookupError, ValueError, OSError):
                    # Process doesn't exist, remove stale PID file
                    try:
                        pid_file.unlink()
                    except:
                        pass
                    status = 'stopped'
        
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

