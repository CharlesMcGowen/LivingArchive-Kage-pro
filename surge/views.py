from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import os
import zipfile
import shutil
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Nuclei templates directory
NUCLEI_TEMPLATES_DIR = Path('/home/ego/nuclei-templates')

def dashboard(request):
    """
    Surge Dashboard - Redirects to about page
    """
    from django.shortcuts import redirect
    return redirect('surge:dashboard_about')

def dashboard_about(request):
    """
    Surge Dashboard - About Page
    Shows all information about Surge
    """
    try:
        context = {
            'personality_name': 'Surge',
            'description': 'Electric Nuclei Vulnerability Scanner',
            'specialization': 'High-Speed Nuclei Scanning',
            'status': 'active',
            'features': [
                'Real Nuclei binary execution',
                'Intelligent template selection',
                'Technology-aware scanning',
                'Kontrol team coordination',
                'Autonomous scanning service',
                'Production scanner with DB integration',
                'JSONL streaming output',
                'Comprehensive vulnerability detection'
            ],
            'current_page': 'about'
        }
        return render(request, 'surge/dashboard_about.html', context)
    except Exception as e:
        return render(request, 'error.html', {'error': str(e)})

def dashboard_controls(request):
    """
    Surge Dashboard - Controls Page
    Shows scanner controls and status
    """
    try:
        context = {
            'personality_name': 'Surge',
            'description': 'Electric Nuclei Vulnerability Scanner',
            'current_page': 'controls'
        }
        return render(request, 'surge/dashboard_controls.html', context)
    except Exception as e:
        return render(request, 'error.html', {'error': str(e)})

def api_status(request):
    """API status endpoint for Surge"""
    try:
        # Get scanner instance to check status
        try:
            from .agents.autonomous_scanner import get_instance
            scanner = get_instance()
            scanner_status = 'running' if scanner.running else 'stopped'
            stats = scanner.stats if hasattr(scanner, 'stats') else {}
        except Exception as e:
            logger.debug(f"Could not get scanner status: {e}")
            scanner_status = 'unknown'
            stats = {}
        
        return JsonResponse({
            'personality': 'Surge',
            'status': 'active',
            'specialization': 'Electric Scanning',
            'scanner_status': scanner_status,
            'stats': stats
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def api_start_scanner(request):
    """API endpoint to start Surge autonomous scanner"""
    try:
        import json
        import threading
        import asyncio
        
        body = json.loads(request.body) if request.body else {}
        batch_size = int(body.get('batch_size', 5))
        scan_type = body.get('scan_type', 'quick')
        
        from .agents.autonomous_scanner import get_instance
        scanner = get_instance()
        
        if scanner.running:
            return JsonResponse({
                'success': False,
                'message': 'Scanner is already running',
                'status': 'running'
            })
        
        # Start scanner in background thread
        def run_scanner():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                scanner.batch_size = batch_size
                scanner.scan_type = scan_type
                scanner.continuous = True  # Ensure continuous mode
                logger.info(f"🚀 Starting Surge scanner thread (batch_size={batch_size}, scan_type={scan_type}, continuous=True)")
                try:
                    loop.run_until_complete(scanner.run())
                except RuntimeError as e:
                    if "cannot schedule new futures" in str(e) or "interpreter shutdown" in str(e):
                        logger.info("⚠️  Scanner stopped due to interpreter shutdown")
                    else:
                        raise
            except Exception as e:
                logger.error(f"❌ Error running Surge scanner: {e}", exc_info=True)
                scanner.running = False
            finally:
                # Ensure scanner is marked as stopped
                scanner.running = False
                try:
                    loop.close()
                except:
                    pass
        
        thread = threading.Thread(target=run_scanner, daemon=True, name="SurgeScanner")
        thread.start()
        
        return JsonResponse({
            'success': True,
            'message': 'Surge scanner started',
            'status': 'starting',
            'batch_size': batch_size,
            'scan_type': scan_type
        })
    
    except Exception as e:
        logger.error(f"Error starting Surge scanner: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def api_stop_scanner(request):
    """API endpoint to stop Surge autonomous scanner"""
    try:
        from .agents.autonomous_scanner import get_instance
        scanner = get_instance()
        
        if not scanner.running:
            return JsonResponse({
                'success': False,
                'message': 'Scanner is not running',
                'status': 'stopped'
            })
        
        scanner.stop()
        
        return JsonResponse({
            'success': True,
            'message': 'Surge scanner stopped',
            'status': 'stopped'
        })
    
    except Exception as e:
        logger.error(f"Error stopping Surge scanner: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET"])
def api_scanner_status(request):
    """API endpoint to get Surge scanner status"""
    try:
        from .agents.autonomous_scanner import get_instance
        scanner = get_instance()
        
        return JsonResponse({
            'running': scanner.running,
            'status': 'running' if scanner.running else 'stopped',
            'stats': scanner.stats if hasattr(scanner, 'stats') else {},
            'scan_interval': scanner.scan_interval if hasattr(scanner, 'scan_interval') else None,
            'batch_size': scanner.batch_size if hasattr(scanner, 'batch_size') else None,
            'scan_type': scanner.scan_type if hasattr(scanner, 'scan_type') else None
        })
    
    except Exception as e:
        logger.error(f"Error getting scanner status: {e}", exc_info=True)
        return JsonResponse({
            'running': False,
            'status': 'error',
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET"])
def api_findings(request):
    """API endpoint to get recent vulnerability findings"""
    try:
        from django.db import connections
        import json
        from datetime import datetime, timedelta
        
        # Get query parameters
        limit = int(request.GET.get('limit', 50))
        severity = request.GET.get('severity', None)
        days = int(request.GET.get('days', 7))
        
        # Use eggrecords database
        conn = connections['eggrecords']
        
        with conn.cursor() as cursor:
            # Build query - use correct table names (plural)
            where_clauses = []
            params = []
            
            # Use discovered_at from vulnerability or scan's started_at for time filtering
            # Build INTERVAL directly in SQL (not parameterized)
            where_clauses.append("COALESCE(v.discovered_at, s.started_at, s.completed_at) > NOW() - INTERVAL '{} days'".format(days))
            
            if severity:
                where_clauses.append("v.severity::text = %s")
                params.append(severity.lower())
            
            where_clause = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # Build query - use string concatenation to avoid % formatting conflicts
            query = """
                SELECT 
                    v.id,
                    v.scan_id,
                    v.template_id,
                    v.template_name,
                    v.vulnerability_name,
                    v.severity::text,
                    v.cve_id,
                    v.cwe_id,
                    v.cvss_score,
                    v.matched_at,
                    v.description,
                    COALESCE(v.discovered_at, s.started_at, s.completed_at) as created_at,
                    s.target,
                    s.scan_type
                FROM nuclei_vulnerabilities v
                LEFT JOIN nuclei_scans s ON s.id = v.scan_id
                WHERE """ + where_clause + """
                ORDER BY COALESCE(v.discovered_at, s.started_at, s.completed_at) DESC
                LIMIT """ + str(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            findings = []
            for row in rows:
                findings.append({
                    'id': str(row[0]) if row[0] else None,
                    'scan_id': str(row[1]) if row[1] else None,
                    'template_id': row[2],
                    'template_name': row[3],
                    'vulnerability_name': row[4],
                    'severity': row[5],
                    'cve_id': row[6],
                    'cwe_id': row[7],
                    'cvss_score': float(row[8]) if row[8] else None,
                    'matched_at': row[9],
                    'description': row[10],
                    'created_at': row[11].isoformat() if row[11] else None,
                    'target': row[12],
                    'scan_type': row[13]
                })
            
            return JsonResponse({
                'success': True,
                'count': len(findings),
                'findings': findings
            })
    
    except Exception as e:
        logger.error(f"Error getting findings: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET"])
def api_finding_detail(request, finding_id):
    """API endpoint to get detailed finding information"""
    try:
        from django.db import connections
        
        conn = connections['eggrecords']
        
        with conn.cursor() as cursor:
            query = """
                SELECT 
                    v.id,
                    v.scan_id,
                    v.template_id,
                    v.template_name,
                    v.vulnerability_name,
                    v.severity::text,
                    v.vulnerability_type,
                    v.cve_id,
                    v.cwe_id,
                    v.cvss_score,
                    v.matched_at,
                    v.matcher_name,
                    v.matcher_status,
                    v.extracted_results,
                    v.description,
                    v.reference,
                    v.tags,
                    v.request_data,
                    v.response_data,
                    v.curl_command,
                    NULL as info,
                    NULL as vuln_metadata,
                    COALESCE(v.discovered_at, s.started_at, s.completed_at) as created_at,
                    s.target,
                    s.scan_type,
                    NULL as customer_name
                FROM nuclei_vulnerabilities v
                LEFT JOIN nuclei_scans s ON s.id = v.scan_id
                WHERE v.id = %s
            """
            
            cursor.execute(query, [finding_id])
            row = cursor.fetchone()
            
            if not row:
                return JsonResponse({
                    'success': False,
                    'error': 'Finding not found'
                }, status=404)
            
            # Parse JSON fields
            extracted_results = []
            tags = []
            info = {}
            vuln_metadata = {}
            reference = ""
            
            try:
                if row[13]:
                    extracted_results = json.loads(row[13]) if isinstance(row[13], str) else row[13]
                if row[16]:
                    tags = json.loads(row[16]) if isinstance(row[16], str) else row[16]
                if row[20]:
                    info = json.loads(row[20]) if isinstance(row[20], str) else row[20]
                if row[21]:
                    vuln_metadata = json.loads(row[21]) if isinstance(row[21], str) else row[21]
                if row[15]:
                    reference = json.loads(row[15]) if isinstance(row[15], str) else row[15]
            except:
                pass
            
            finding = {
                'id': str(row[0]) if row[0] else None,
                'scan_id': str(row[1]) if row[1] else None,
                'template_id': row[2],
                'template_name': row[3],
                'vulnerability_name': row[4],
                'severity': row[5],
                'vulnerability_type': row[6],
                'cve_id': row[7],
                'cwe_id': row[8],
                'cvss_score': float(row[9]) if row[9] else None,
                'matched_at': row[10],
                'matcher_name': row[11],
                'matcher_status': row[12],
                'extracted_results': extracted_results,
                'description': row[14],
                'reference': reference,
                'tags': tags,
                'request_data': row[17],
                'response_data': row[18],
                'curl_command': row[19],
                'info': info,
                'vuln_metadata': vuln_metadata,
                'created_at': row[22].isoformat() if row[22] else None,
                'target': row[23],
                'scan_type': row[24],
                'customer_name': row[25]
            }
            
            return JsonResponse({
                'success': True,
                'finding': finding
            })
    
    except Exception as e:
        logger.error(f"Error getting finding detail: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET", "POST"])
def upload_templates(request):
    """Upload Nuclei templates (files or folders)"""
    if request.method == 'GET':
        # Return upload form page
        return render(request, 'surge/upload_templates.html', {
            'personality': 'Surge',
            'templates_dir': str(NUCLEI_TEMPLATES_DIR)
        })
    
    # POST: Handle file upload
    try:
        # Ensure templates directory exists
        NUCLEI_TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
        
        uploaded_files = []
        errors = []
        
        # Handle multiple files
        if 'files' in request.FILES:
            files = request.FILES.getlist('files')
            
            for uploaded_file in files:
                try:
                    # Get file name and path
                    file_name = uploaded_file.name
                    
                    # Determine destination path
                    # If it's a .yaml or .yml file, place it in appropriate directory structure
                    if file_name.endswith(('.yaml', '.yml')):
                        # Try to preserve directory structure from filename
                        # e.g., "http/cves/CVE-2023-1234.yaml" -> /home/ego/nuclei-templates/http/cves/CVE-2023-1234.yaml
                        dest_path = NUCLEI_TEMPLATES_DIR / file_name
                        
                        # Create parent directories if needed
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Save file
                        with open(dest_path, 'wb+') as destination:
                            for chunk in uploaded_file.chunks():
                                destination.write(chunk)
                        
                        uploaded_files.append(str(dest_path.relative_to(NUCLEI_TEMPLATES_DIR)))
                        logger.info(f"Uploaded template: {dest_path}")
                    
                    # If it's a zip file, extract it
                    elif file_name.endswith('.zip'):
                        # Save zip temporarily
                        temp_zip = NUCLEI_TEMPLATES_DIR / f"temp_{file_name}"
                        with open(temp_zip, 'wb+') as destination:
                            for chunk in uploaded_file.chunks():
                                destination.write(chunk)
                        
                        # Extract zip
                        with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
                            # Extract all files maintaining directory structure
                            zip_ref.extractall(NUCLEI_TEMPLATES_DIR)
                            
                            # Get list of extracted files
                            extracted = zip_ref.namelist()
                            uploaded_files.extend([f for f in extracted if f.endswith(('.yaml', '.yml'))])
                        
                        # Remove temp zip
                        temp_zip.unlink()
                        logger.info(f"Extracted zip file: {file_name}, {len(uploaded_files)} templates")
                    
                    else:
                        errors.append(f"Unsupported file type: {file_name} (only .yaml, .yml, or .zip allowed)")
                
                except Exception as e:
                    errors.append(f"Error processing {uploaded_file.name}: {str(e)}")
                    logger.error(f"Error uploading {uploaded_file.name}: {e}", exc_info=True)
        
        # Return JSON response
        response_data = {
            'success': len(errors) == 0,
            'uploaded_count': len(uploaded_files),
            'uploaded_files': uploaded_files[:50],  # Limit to first 50
            'templates_dir': str(NUCLEI_TEMPLATES_DIR)
        }
        
        if errors:
            response_data['errors'] = errors
        
        return JsonResponse(response_data)
    
    except Exception as e:
        logger.error(f"Error in upload_templates: {e}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

def koga_about(request):
    """Koga Dashboard - About Page"""
    context = {
        'personality_name': 'Koga',
        'description': 'Stealth Operations & Poison Testing',
        'specialization': 'Stealth Operations & Poison Testing',
        'status': 'active',
        'current_page': 'about'
    }
    return render(request, 'surge/koga_about.html', context)

def koga_controls(request):
    """Koga Dashboard - Controls Page"""
    context = {
        'personality_name': 'Koga',
        'description': 'Stealth Operations & Poison Testing',
        'current_page': 'controls'
    }
    return render(request, 'surge/koga_controls.html', context)

def bugsy_about(request):
    """Bugsy Dashboard - About Page"""
    context = {
        'personality_name': 'Bugsy',
        'description': 'Bug Bounty & Vulnerability Curation',
        'specialization': 'Bug Bounty & Vulnerability Curation',
        'status': 'active',
        'current_page': 'about'
    }
    return render(request, 'surge/bugsy_about.html', context)

def bugsy_controls(request):
    """Bugsy Dashboard - Controls Page"""
    context = {
        'personality_name': 'Bugsy',
        'description': 'Bug Bounty & Vulnerability Curation',
        'current_page': 'controls'
    }
    return render(request, 'surge/bugsy_controls.html', context)
