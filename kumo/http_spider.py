#!/usr/bin/env python3
"""
Kumo HTTP Spider - Creates RequestMetaData Entries
===================================================

Migrated from EgoWebs1 enhanced_kumo_service.py
Refactored for webApps ego system with parallel threading

Kumo specializes in:
- HTTP request/response collection
- Header, cookie, and HTML extraction
- Multi-page web spidering
- Creating RequestMetaData entries for Bugsy to fingerprint
- Parallel threading (32 workers) for faster spidering

Note: Uses CPU threading (ThreadPoolExecutor), not GPU compute.
HTTP I/O operations cannot utilize GPU - threading is appropriate here.

Author: EGO Revolution - Kumo (Water Master)
Version: 2.0.0 - Parallel Threading
"""

import requests
import logging
import time
import sys
import warnings
import urllib3
import json
import re
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Suppress urllib3 SSL warnings - we detect and report SSL issues separately
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

from artificial_intelligence.personalities.reconnaissance import EGOQT_SRC  # noqa: F401

try:
    from ai_system.error_reporting_to_l import KumoErrorReporter
except ImportError:
    # Optional error reporting - create dummy class if not available
    class KumoErrorReporter:
        @staticmethod
        def report_error(error, context=None):
            logger.error(f"Error (no reporter): {error}")
import sys
import os

# Setup logging first (before Django setup)
logger = logging.getLogger(__name__)

# Setup Django (optional - only if Django is available)
# Check if Django is already configured before attempting setup
try:
    import django
    from django.apps import apps
    # Check if Django apps are already populated
    if apps.ready:
        # Django is already initialized, skip setup
        from django.db import connections
        from django.utils import timezone
        DJANGO_AVAILABLE = True
    else:
        # Django not initialized, try to set it up
        try:
            os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
            django.setup()
            from django.apps import apps
            from django.db import connections
            from django.utils import timezone
            DJANGO_AVAILABLE = True
        except RuntimeError as e:
            if "reentrant" in str(e).lower() or "populate" in str(e).lower():
                # Django is already being initialized, skip but try to import
                from django.apps import apps
                from django.db import connections
                from django.utils import timezone
                DJANGO_AVAILABLE = True
            else:
                raise
except (ImportError, AttributeError, ModuleNotFoundError):
    # Django not available or not imported yet, try to set it up
    try:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
        import django
        django.setup()
        from django.apps import apps
        from django.db import connections
        from django.utils import timezone
        DJANGO_AVAILABLE = True
    except RuntimeError as e:
        if "reentrant" in str(e).lower() or "populate" in str(e).lower():
            # Django already initialized, try to import
            try:
                from django.apps import apps
                from django.db import connections
                from django.utils import timezone
                DJANGO_AVAILABLE = True
            except ImportError:
                DJANGO_AVAILABLE = False
                apps = None
                connections = None
                timezone = None
        else:
            # Fallback to EgoQT settings if available
            try:
                sys.path.insert(0, '/mnt/webapps-nvme')
                os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EgoQT.src.django_bridge.settings')
                import django
                django.setup()
                from django.apps import apps
                from django.db import connections
                from django.utils import timezone
                DJANGO_AVAILABLE = True
            except (ImportError, ModuleNotFoundError, RuntimeError):
                DJANGO_AVAILABLE = False
                apps = None
                connections = None
                timezone = None
    except (ImportError, ModuleNotFoundError):
        DJANGO_AVAILABLE = False
        apps = None
        connections = None
        timezone = None
        logger.warning("Django not available - database features will be disabled")

logger = logging.getLogger(__name__)


class KumoHttpSpider:
    """
    Kumo's HTTP spidering service.
    Creates real RequestMetaData entries in the database for Bugsy to fingerprint.
    """
    
    def __init__(self, parallel_enabled: bool = True):
        """
        Initialize Kumo's HTTP spider.
        
        Args:
            parallel_enabled: Use parallel threading (32 workers vs 5)
        """
        self.parallel_enabled = parallel_enabled
        
        # Kumo's spidering configuration
        self.request_timeout = 10.0
        self.max_workers = 32 if self.parallel_enabled else 5
        self.max_pages_per_domain = 50
        self.spider_depth = 2
        
        # Initialize Tor proxy support (optional)
        self.tor_enabled = False
        try:
            from artificial_intelligence.personalities.reconnaissance.tor_proxy import get_tor_proxy
            self.tor_proxy = get_tor_proxy(enabled=True)
            self.tor_enabled = self.tor_proxy.is_available()
            if self.tor_enabled:
                logger.info("🔒 Tor proxy enabled for anonymous spidering")
        except Exception as e:
            logger.debug(f"Tor proxy not available: {e}")
            self.tor_proxy = None
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Kumo-Spider/2.0 (EGO Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Configure Tor proxy if available
        if self.tor_enabled and self.tor_proxy:
            proxies = self.tor_proxy.get_socks_proxy()
            if proxies:
                self.session.proxies.update(proxies)
        
        # Initialize LLM enhancer for intelligent content analysis
        self.llm_enabled = False
        try:
            from artificial_intelligence.personalities.reconnaissance.llm_enhancer import get_llm_enhancer
            self.llm_enhancer = get_llm_enhancer(enabled=True)
            self.llm_enabled = self.llm_enhancer.is_available()
            if self.llm_enabled:
                logger.info("🧠 LLM enhancer enabled for intelligent content analysis")
        except Exception as e:
            logger.debug(f"LLM enhancer not available: {e}")
            self.llm_enhancer = None
        
        logger.info(f"🌊 Kumo spider initialized ({'Parallel' if self.parallel_enabled else 'Sequential'} mode, {self.max_workers} workers, Tor: {'enabled' if self.tor_enabled else 'disabled'}, LLM: {'enabled' if self.llm_enabled else 'disabled'})")
    
    def spider_egg_record(self, egg_record_id: str, depth: int = None, write_to_db: bool = True, eggrecord_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Spider an EggRecord and create RequestMetaData entries.
        
        Args:
            egg_record_id: EggRecord UUID string to spider
            depth: Spider depth (default: 2 levels)
            write_to_db: If False, return results without writing to database (for REST API mode)
            eggrecord_data: Optional pre-fetched eggrecord data (avoids Django model lookup)
            
        Returns:
            Spider results summary
        """
        # Get full EggRecord data using Django or raw SQL
        target = None
        egg_record_data_dict = {}  # Store full eggrecord data
        
        # If eggrecord_data is provided (from daemon API), use it directly
        if eggrecord_data:
            egg_record_data_dict = eggrecord_data
            target = eggrecord_data.get('subDomain') or eggrecord_data.get('domainname')
            logger.debug(f"Using provided eggrecord data for {target}")
        else:
            try:
                EggRecord = apps.get_model('customer_eggs_eggrecords_general_models', 'EggRecord')
                try:
                    egg_record = EggRecord.objects.get(id=egg_record_id)
                    target = egg_record.subDomain or egg_record.domainname
                    # Store full eggrecord data
                    egg_record_data_dict = {
                        'id': str(egg_record.id),
                        'subDomain': egg_record.subDomain,
                        'domainname': egg_record.domainname,
                        'alive': egg_record.alive,
                        'created_at': egg_record.created_at,
                        'updated_at': egg_record.updated_at,
                    }
                except (AttributeError, Exception) as e:
                    # Django ORM not available, use raw SQL
                    logger.debug(f"Django ORM not available, using raw SQL: {e}")
                    try:
                        db = connections['customer_eggs']
                        with db.cursor() as cursor:
                            cursor.execute("""
                                SELECT id, "subDomain", domainname, alive, created_at, updated_at
                                FROM customer_eggs_eggrecords_general_models_eggrecord
                                WHERE id = %s
                                LIMIT 1
                            """, [egg_record_id])
                            row = cursor.fetchone()
                            if row:
                                columns = [col[0] for col in cursor.description]
                                egg_record_data_dict = dict(zip(columns, row))
                                target = egg_record_data_dict.get('subDomain') or egg_record_data_dict.get('domainname')
                            else:
                                logger.error(f"❌ EggRecord {egg_record_id} not found")
                                return {
                                    'success': False,
                                    'error': 'EggRecord not found',
                                    'target': egg_record_id
                                }
                    except Exception as db_error:
                        logger.error(f"Database error fetching eggrecord: {db_error}")
                        return {
                            'success': False,
                            'error': f'Database error: {db_error}',
                            'target': egg_record_id
                        }
            except (LookupError, ValueError) as e:
                logger.error(f"Model lookup error: {e}")
                return {
                    'success': False,
                    'error': f'Model lookup error: {e}',
                    'target': egg_record_id
                }
        
        if not target:
            logger.error(f"❌ Could not determine target for EggRecord {egg_record_id}")
            return {
                'success': False,
                'error': 'Could not determine target',
                'target': egg_record_id
            }
        
        # Use egg_record_data_dict throughout
        egg_record_data = egg_record_data_dict
        
        # Log full eggrecord context for debugging
        logger.debug(f"📋 Spidering eggrecord: {egg_record_data}")
        
        spider_depth = depth or self.spider_depth
        
        logger.info(f"🌊 Kumo spidering {target} (depth: {spider_depth})")
        
        start_time = time.time()
        
        # Try both HTTP and HTTPS
        urls_to_spider = [
            f"https://{target}",
            f"http://{target}"
        ]
        
        metadata_entries_created = 0
        pages_spidered = []
        request_metadata_list = []  # Collect metadata when write_to_db=False
        
        for base_url in urls_to_spider:
            try:
                # Spider from base URL
                result = self._spider_url(base_url, egg_record_id, spider_depth, write_to_db=write_to_db)
                
                if result['success']:
                    pages_spidered.extend(result['pages'])
                    metadata_entries_created += result['metadata_created']
                    # Collect request_metadata if available (when write_to_db=False)
                    if 'request_metadata' in result:
                        request_metadata_list.extend(result['request_metadata'])
                # Even if result['success'] is False, still try to collect request_metadata if available
                elif 'request_metadata' in result:
                    request_metadata_list.extend(result['request_metadata'])
                    
            except Exception as e:
                logger.error(f"❌ Failed to spider {base_url}: {e}", exc_info=True)
                # If write_to_db=False, ensure we still have metadata entry for failed spider attempt
                if not write_to_db:
                    try:
                        from django.utils import timezone
                        timestamp = timezone.now().isoformat()
                    except ImportError:
                        timestamp = datetime.now().isoformat()
                    request_metadata_list.append({
                        'target_url': base_url,
                        'request_method': 'GET',
                        'response_status': 0,
                        'response_time_ms': 0,
                        'user_agent': self.session.headers.get('User-Agent', 'Kumo/1.0'),
                        'timestamp': timestamp,
                        'javascript_analysis': {},
                        'error': f'exception: {str(e)[:100]}'
                    })
        
        duration = time.time() - start_time
        
        logger.info(f"🌊 Kumo spider complete: {len(pages_spidered)} pages, "
                   f"{metadata_entries_created} RequestMetaData entries created in {duration:.2f}s")
        
        result_dict = {
            'success': True,
            'target': target,
            'pages_spidered': len(pages_spidered),
            'metadata_entries_created': metadata_entries_created,
            'spider_duration': duration,
            'pages': pages_spidered
        }
        
        # Always include request_metadata when write_to_db=False (for API submission)
        # API requires this field even if empty - this is critical for API validation
        if not write_to_db:
            # Ensure request_metadata is always present, even if empty list
            result_dict['request_metadata'] = request_metadata_list if request_metadata_list else []
            # Log if empty to help debug
            if not request_metadata_list:
                logger.warning(f"⚠️  No request_metadata collected for {target} (all connections may have failed) - including empty list")
            else:
                logger.debug(f"✅ Collected {len(request_metadata_list)} request_metadata entries for {target}")
            # Log the actual result structure for debugging
            logger.debug(f"🔍 Result dict keys: {list(result_dict.keys())}, has request_metadata: {'request_metadata' in result_dict}")
        
        # CRITICAL: Ensure request_metadata is always in result when write_to_db=False
        # Double-check to prevent API errors
        if not write_to_db:
            if 'request_metadata' not in result_dict:
                logger.error(f"❌ CRITICAL: request_metadata missing from result for {target} - adding empty list")
                result_dict['request_metadata'] = []
            # Final validation before return
            if not isinstance(result_dict.get('request_metadata'), list):
                logger.error(f"❌ CRITICAL: request_metadata is not a list (type: {type(result_dict.get('request_metadata'))}) - fixing")
                result_dict['request_metadata'] = []
        
        return result_dict
    
    def batch_spider(self, egg_record_ids: List[str], depth: int = None) -> List[Dict]:
        """
        Batch spider multiple EggRecords.
        
        Args:
            egg_record_ids: List of EggRecord UUID strings
            depth: Spider depth
            
        Returns:
            List of spider results
        """
        logger.info(f"🌊 Kumo batch spidering {len(egg_record_ids)} targets")
        
        results = []
        for i, egg_record_id in enumerate(egg_record_ids, 1):
            logger.info(f"[{i}/{len(egg_record_ids)}] Spidering {egg_record_id}")
            result = self.spider_egg_record(egg_record_id, depth)
            results.append(result)
        
        successful = len([r for r in results if r['success']])
        total_metadata = sum(r.get('metadata_entries_created', 0) for r in results)
        
        logger.info(f"🌊 Kumo batch complete: {successful}/{len(egg_record_ids)} successful, {total_metadata} metadata entries created")
        
        return results
    
    def _spider_url(self, url: str, egg_record_id: str, depth: int, write_to_db: bool = True) -> Dict[str, Any]:
        """
        Spider a URL and create RequestMetaData entries.
        Core spidering logic extracted from EgoWebs1.
        
        Args:
            url: URL to spider
            egg_record_id: EggRecord UUID string
            depth: Maximum spider depth
            write_to_db: If False, collect metadata instead of writing to database
        """
        visited = set()
        pages = []
        metadata_created = 0
        request_metadata_list = []  # Collect metadata when write_to_db=False
        
        # Start with initial URL
        to_visit = [(url, 0)]  # (url, current_depth)
        
        while to_visit and len(pages) < self.max_pages_per_domain:
            current_url, current_depth = to_visit.pop(0)
            
            if current_url in visited or current_depth > depth:
                continue
            
            visited.add(current_url)
            
            try:
                # Make HTTP request
                response = self.session.get(
                    current_url,
                    timeout=self.request_timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                # Extract data
                headers = dict(response.headers)
                cookies = [
                    {'name': cookie.name, 'value': cookie.value, 'domain': cookie.domain}
                    for cookie in response.cookies
                ]
                html_content = response.text
                
                # Store request/response data in egg record
                import hashlib
                request_id = hashlib.md5(f"{current_url}:{time.time()}".encode()).hexdigest()
                session_id = f"kumo-{egg_record_id}"
                
                # Store cookies in response headers for Bugsy
                headers_with_cookies = headers.copy()
                if cookies:
                    headers_with_cookies['_kumo_cookies'] = cookies
                
                # Deep JavaScript analysis (performed once for both write_to_db paths)
                js_analysis = {}
                try:
                    js_analysis = self._analyze_javascript_deep(html_content, current_url)
                    # Log findings
                    if js_analysis.get('secrets_found'):
                        logger.warning(f"🔐 Found {len(js_analysis['secrets_found'])} secrets in JavaScript for {current_url}")
                    if js_analysis.get('api_endpoints'):
                        logger.info(f"🔗 Found {len(js_analysis['api_endpoints'])} API endpoints in JavaScript for {current_url}")
                except Exception as js_error:
                    logger.debug(f"JavaScript analysis failed (non-fatal): {js_error}")
                    js_analysis = {}  # Use empty dict if analysis fails
                
                # Try to create RequestMetaData entry if model exists
                # Only write if write_to_db=True (daemons should use write_to_db=False and submit via API)
                if write_to_db:
                    try:
                        # Check if RequestMetaData model exists
                        RequestMetaData = None
                        try:
                            RequestMetaData = apps.get_model('customer_eggs_eggrecords_general_models', 'RequestMetaData')
                        except (LookupError, ValueError):
                            try:
                                from customer_eggs_eggrecords_general_models.core_models.record_models import RequestMetaData
                            except ImportError:
                                try:
                                    from customer_eggs_eggrecords_general_models.core_models.research_models import RequestMetaData
                                except ImportError:
                                    RequestMetaData = None
                        
                        if RequestMetaData:
                            # Create RequestMetaData entry using Django ORM
                            try:
                                # Try to get egg_record object for ORM, or use ID string
                                try:
                                    EggRecord = apps.get_model('customer_eggs_eggrecords_general_models', 'EggRecord')
                                    egg_record_obj = EggRecord.objects.get(id=egg_record_id)
                                except (AttributeError, Exception):
                                    egg_record_obj = egg_record_id  # Use ID string as fallback
                                
                                metadata_entry = RequestMetaData.objects.create(
                                    record_id=egg_record_obj,
                                    request_id=request_id,
                                    session_id=session_id,
                                    target_url=current_url,
                                    request_method='GET',
                                    response_status=response.status_code,
                                    request_headers=headers,
                                    response_headers=headers_with_cookies,
                                    response_body=html_content[:50000],  # Limit body size
                                    response_time_ms=int(response.elapsed.total_seconds() * 1000),
                                    user_agent=self.session.headers.get('User-Agent', ''),
                                    timestamp=timezone.now()
                                )
                                metadata_created += 1
                                request_id = str(metadata_entry.id)
                            except Exception as orm_error:
                                # If ORM fails, use raw SQL
                                logger.debug(f"ORM create failed, using raw SQL: {orm_error}")
                                db = connections['customer_eggs']
                                import uuid
                                with db.cursor() as cursor:
                                    cursor.execute("""
                                        INSERT INTO customer_eggs_eggrecords_general_models_requestmetadata (
                                            id, request_id, session_id, target_url, request_method,
                                            request_headers, request_body, response_status, response_headers,
                                            response_body, response_time_ms, user_agent, referer,
                                            timestamp, record_id_id, created_at, updated_at
                                        ) VALUES (
                                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                                        )
                                    """, [
                                        str(uuid.uuid4()),
                                        request_id,
                                        session_id,
                                        current_url,
                                        'GET',
                                        json.dumps(headers),
                                        '',
                                        response.status_code,
                                        json.dumps(headers_with_cookies),
                                        html_content[:50000],
                                        int(response.elapsed.total_seconds() * 1000),
                                        self.session.headers.get('User-Agent', ''),
                                        '',
                                        timezone.now(),
                                        str(egg_record_id),
                                        timezone.now(),
                                        timezone.now()
                                    ])
                                db.commit()  # Commit the transaction to persist RequestMetaData entries
                                metadata_created += 1
                        else:
                            # Fallback: Store in images JSON field
                            request_metadata = {
                                'request_id': request_id,
                                'session_id': session_id,
                                'url': current_url,
                                'method': 'GET',
                                'status_code': response.status_code,
                                'response_time_ms': int(response.elapsed.total_seconds() * 1000),
                                'request_headers': headers,
                                'response_headers': headers_with_cookies,
                                'response_body': html_content[:10000],  # Limit body size
                                'cookies': cookies,
                                'user_agent': self.session.headers.get('User-Agent', ''),
                                'spider_agent': 'kumo',
                                'scan_session': f"kumo-{egg_record_id}",
                                'scan_stage': 'spidering',
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            # Update via raw SQL if needed
                            db = connections['customer_eggs']
                            with db.cursor() as cursor:
                                # Get current images
                                cursor.execute("""
                                    SELECT images FROM customer_eggs_eggrecords_general_models_eggrecord
                                    WHERE id = %s
                                """, [str(egg_record_id)])
                                row = cursor.fetchone()
                                current_metadata = json.loads(row[0]) if row and row[0] else []
                                current_metadata.append(request_metadata)
                                
                                # Update
                                cursor.execute("""
                                    UPDATE customer_eggs_eggrecords_general_models_eggrecord
                                    SET images = %s
                                    WHERE id = %s
                                """, [json.dumps(current_metadata), str(egg_record_id)])
                                db.commit()  # Commit the fallback update
                            
                            metadata_created += 1
                            logger.debug(f"  ✅ Stored metadata in images field (fallback)")
                    except Exception as e:
                        logger.warning(f"Could not create RequestMetaData entry: {e}")
                        metadata_created += 1  # Count as created even if fallback used
                else:
                    # When write_to_db=False, collect metadata to return via API
                    # This MUST always execute to ensure request_metadata is included
                    try:
                        from django.utils import timezone
                        timestamp = timezone.now().isoformat()
                    except ImportError:
                        timestamp = datetime.now().isoformat()
                    
                    try:
                        request_metadata_entry = {
                            'target_url': current_url,
                            'request_method': 'GET',
                            'response_status': response.status_code,
                            'response_time_ms': int(response.elapsed.total_seconds() * 1000),
                            'user_agent': self.session.headers.get('User-Agent', 'Kumo/1.0'),
                            'timestamp': timestamp,
                            'javascript_analysis': js_analysis  # Include JS analysis (may be empty dict if analysis failed)
                        }
                        request_metadata_list.append(request_metadata_entry)
                        metadata_created += 1
                    except Exception as metadata_error:
                        logger.error(f"❌ Failed to create request_metadata_entry: {metadata_error}", exc_info=True)
                        # Still try to add a minimal entry to ensure API doesn't reject
                        try:
                            request_metadata_list.append({
                                'target_url': current_url,
                                'request_method': 'GET',
                                'response_status': response.status_code if response else 0,
                                'response_time_ms': 0,
                                'user_agent': 'Kumo/1.0',
                                'timestamp': timestamp,
                                'javascript_analysis': {}
                            })
                            metadata_created += 1
                        except Exception:
                            logger.error(f"❌ CRITICAL: Could not create minimal request_metadata_entry")
                
                # Use LLM to analyze content if available
                llm_content_analysis = None
                if self.llm_enabled and self.llm_enhancer:
                    try:
                        import asyncio
                        try:
                            loop = asyncio.get_event_loop()
                        except RuntimeError:
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                        
                        llm_content_analysis = loop.run_until_complete(
                            self.llm_enhancer.analyze_http_content(
                                current_url,
                                headers,
                                html_content,
                                response.status_code
                            )
                        )
                        
                        if llm_content_analysis:
                            logger.debug(f"🧠 LLM content analysis: {llm_content_analysis.content_type}")
                            if llm_content_analysis.sensitive_data_detected:
                                logger.warning(f"   ⚠️  Sensitive data detected: {len(llm_content_analysis.sensitive_data_detected)} items")
                    except Exception as e:
                        logger.debug(f"LLM content analysis failed (non-fatal): {e}")
                
                # Parse page
                page_data = {
                    'url': current_url,
                    'status_code': response.status_code,
                    'headers': headers,
                    'cookies': cookies,
                    'content_length': len(html_content),
                    'depth': current_depth,
                    'metadata_id': request_id,  # Use request_id instead of undefined metadata.id
                    'javascript_analysis': js_analysis  # Include JS analysis
                }
                
                # Add LLM analysis if available
                if llm_content_analysis:
                    page_data['llm_analysis'] = {
                        'content_type': llm_content_analysis.content_type,
                        'security_indicators': llm_content_analysis.security_indicators,
                        'sensitive_data_detected': llm_content_analysis.sensitive_data_detected,
                        'application_structure': llm_content_analysis.application_structure,
                        'recommendations': llm_content_analysis.recommendations
                    }
                
                pages.append(page_data)
                
                # Find links to spider next
                if current_depth < depth:
                    links = self._extract_links(html_content, current_url)
                    
                    # Add links to visit queue
                    for link in links[:10]:  # Limit links per page
                        if link not in visited:
                            to_visit.append((link, current_depth + 1))
                
                logger.debug(f"  ✅ Spidered: {current_url} (depth {current_depth})")
                
            except requests.exceptions.Timeout:
                logger.debug(f"⏰ Timeout: {current_url}")
                # Still create metadata entry for failed connections when write_to_db=False
                if not write_to_db:
                    try:
                        from django.utils import timezone
                        timestamp = timezone.now().isoformat()
                    except ImportError:
                        timestamp = datetime.now().isoformat()
                    request_metadata_list.append({
                        'target_url': current_url,
                        'request_method': 'GET',
                        'response_status': 0,
                        'response_time_ms': 0,
                        'user_agent': self.session.headers.get('User-Agent', 'Kumo/1.0'),
                        'timestamp': timestamp,
                        'javascript_analysis': {},
                        'error': 'timeout'
                    })
                    metadata_created += 1
            except requests.exceptions.SSLError:
                logger.debug(f"🔒 SSL Error: {current_url}")
                # Still create metadata entry for failed connections when write_to_db=False
                if not write_to_db:
                    try:
                        from django.utils import timezone
                        timestamp = timezone.now().isoformat()
                    except ImportError:
                        timestamp = datetime.now().isoformat()
                    request_metadata_list.append({
                        'target_url': current_url,
                        'request_method': 'GET',
                        'response_status': 0,
                        'response_time_ms': 0,
                        'user_agent': self.session.headers.get('User-Agent', 'Kumo/1.0'),
                        'timestamp': timestamp,
                        'javascript_analysis': {},
                        'error': 'ssl_error'
                    })
                    metadata_created += 1
            except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout) as e:
                # Connection refused/reset are expected for unreachable hosts - log at debug level
                error_msg = str(e)
                if 'Connection refused' in error_msg or 'Connection reset' in error_msg or 'Connection aborted' in error_msg:
                    logger.debug(f"🔌 Connection failed (expected): {current_url} - {error_msg[:100]}")
                else:
                    logger.warning(f"⚠️  Connection error: {current_url} - {error_msg[:100]}")
                # Still create metadata entry for failed connections when write_to_db=False
                if not write_to_db:
                    try:
                        from django.utils import timezone
                        timestamp = timezone.now().isoformat()
                    except ImportError:
                        timestamp = datetime.now().isoformat()
                    request_metadata_list.append({
                        'target_url': current_url,
                        'request_method': 'GET',
                        'response_status': 0,
                        'response_time_ms': 0,
                        'user_agent': self.session.headers.get('User-Agent', 'Kumo/1.0'),
                        'timestamp': timestamp,
                        'javascript_analysis': {},
                        'error': 'connection_error'
                    })
                    metadata_created += 1
            except Exception as e:
                error_msg = str(e)
                # Check if it's a connection-related error
                if 'connection' in error_msg.lower() or 'refused' in error_msg.lower() or 'reset' in error_msg.lower():
                    logger.debug(f"🔌 Connection error (expected): {current_url} - {error_msg[:100]}")
                else:
                    logger.warning(f"⚠️  Error spidering {current_url}: {error_msg[:100]}")
                # Still create metadata entry for failed connections when write_to_db=False
                if not write_to_db:
                    try:
                        from django.utils import timezone
                        timestamp = timezone.now().isoformat()
                    except ImportError:
                        timestamp = datetime.now().isoformat()
                    request_metadata_list.append({
                        'target_url': current_url,
                        'request_method': 'GET',
                        'response_status': 0,
                        'response_time_ms': 0,
                        'user_agent': self.session.headers.get('User-Agent', 'Kumo/1.0'),
                        'timestamp': timestamp,
                        'javascript_analysis': {},
                        'error': 'unknown_error'
                    })
                    metadata_created += 1
        
        result = {
            'success': True,
            'pages': pages,
            'metadata_created': metadata_created,
            'urls_visited': len(visited)
        }
        
        # Always include request_metadata when write_to_db=False (for API submission)
        # API requires this field even if empty
        if not write_to_db:
            result['request_metadata'] = request_metadata_list if request_metadata_list else []
        
        return result
    
    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        """
        Extract links from HTML content.
        Core link extraction logic from EgoWebs1.
        """
        links = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all anchor tags
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                
                # Convert relative URLs to absolute
                absolute_url = urljoin(base_url, href)
                
                # Only spider same domain
                if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                    links.append(absolute_url)
            
        except Exception as e:
            logger.debug(f"Error extracting links: {e}")
        
        return links
    
    def _analyze_javascript_deep(self, html_content: str, base_url: str) -> Dict[str, Any]:
        """
        Deep JavaScript analysis: fetch external files, parse inline JS, extract secrets.
        
        Args:
            html_content: HTML content to analyze
            base_url: Base URL for resolving relative paths
            
        Returns:
            Dictionary with comprehensive JavaScript analysis
        """
        js_analysis = {
            'external_js_files': [],
            'inline_js_blocks': [],
            'event_handlers': [],
            'secrets_found': [],
            'api_endpoints': [],
            'parameters_extracted': [],
            'custom_functions': [],
            'config_objects': []
        }
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # 1. Find and fetch external JavaScript files
            for script in soup.find_all('script', src=True):
                js_url = urljoin(base_url, script['src'])
                js_file_data = {
                    'url': js_url,
                    'src': script['src'],
                    'type': script.get('type', 'text/javascript'),
                    'async': script.has_attr('async'),
                    'defer': script.has_attr('defer'),
                    'content': None,
                    'secrets': [],
                    'endpoints': [],
                    'parameters': []
                }
                
                # Fetch the JavaScript file
                try:
                    js_response = self.session.get(js_url, timeout=self.request_timeout, verify=False)
                    if js_response.status_code == 200:
                        js_content = js_response.text
                        js_file_data['content'] = js_content[:100000]  # Limit size
                        
                        # Analyze fetched JavaScript
                        js_file_data['secrets'] = self._extract_secrets_from_js(js_content)
                        js_file_data['endpoints'] = self._extract_endpoints_from_js(js_content, base_url)
                        js_file_data['parameters'] = self._extract_parameters_from_js(js_content)
                        
                        # Aggregate findings
                        js_analysis['secrets_found'].extend(js_file_data['secrets'])
                        js_analysis['api_endpoints'].extend(js_file_data['endpoints'])
                        js_analysis['parameters_extracted'].extend(js_file_data['parameters'])
                except Exception as e:
                    logger.debug(f"Could not fetch external JS {js_url}: {e}")
                
                js_analysis['external_js_files'].append(js_file_data)
            
            # 2. Find and analyze inline JavaScript
            for script in soup.find_all('script', src=False):
                if script.string:
                    inline_js = script.string.strip()
                    inline_data = {
                        'type': script.get('type', 'text/javascript'),
                        'content': inline_js[:50000],  # Limit size
                        'length': len(inline_js),
                        'secrets': self._extract_secrets_from_js(inline_js),
                        'endpoints': self._extract_endpoints_from_js(inline_js, base_url),
                        'parameters': self._extract_parameters_from_js(inline_js),
                        'functions': self._extract_functions_from_js(inline_js),
                        'configs': self._extract_config_objects_from_js(inline_js)
                    }
                    
                    js_analysis['inline_js_blocks'].append(inline_data)
                    
                    # Aggregate findings
                    js_analysis['secrets_found'].extend(inline_data['secrets'])
                    js_analysis['api_endpoints'].extend(inline_data['endpoints'])
                    js_analysis['parameters_extracted'].extend(inline_data['parameters'])
                    js_analysis['custom_functions'].extend(inline_data['functions'])
                    js_analysis['config_objects'].extend(inline_data['configs'])
            
            # 3. Find JavaScript in event handlers
            for tag in soup.find_all(attrs=lambda x: x and any(attr.startswith('on') for attr in x.keys())):
                for attr, value in tag.attrs.items():
                    if attr.startswith('on') and value:
                        handler_js = str(value)
                        handler_data = {
                            'tag': tag.name,
                            'event': attr,
                            'handler': handler_js[:1000],
                            'secrets': self._extract_secrets_from_js(handler_js),
                            'endpoints': self._extract_endpoints_from_js(handler_js, base_url)
                        }
                        
                        js_analysis['event_handlers'].append(handler_data)
                        js_analysis['secrets_found'].extend(handler_data['secrets'])
                        js_analysis['api_endpoints'].extend(handler_data['endpoints'])
            
            # Remove duplicates from aggregated lists
            js_analysis['secrets_found'] = list({s['value']: s for s in js_analysis['secrets_found']}.values())
            js_analysis['api_endpoints'] = list({e['url']: e for e in js_analysis['api_endpoints']}.values())
            js_analysis['parameters_extracted'] = list({p.get('name', ''): p for p in js_analysis['parameters_extracted']}.values())
            
        except Exception as e:
            logger.warning(f"Error in deep JavaScript analysis: {e}")
            js_analysis['error'] = str(e)
        
        return js_analysis
    
    def _extract_secrets_from_js(self, js_content: str) -> List[Dict[str, Any]]:
        """Extract secrets, API keys, tokens from JavaScript code."""
        secrets = []
        
        patterns = {
            'api_key': [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            ],
            'secret_key': [
                r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            ],
            'access_token': [
                r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            ],
            'bearer_token': [
                r'bearer["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'authorization["\']?\s*[:=]\s*["\']bearer\s+([a-zA-Z0-9_\-]{20,})["\']',
            ],
            'aws_key': [
                r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
                r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
            ],
            'jwt_token': [
                r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            ],
            'oauth_token': [
                r'oauth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']'
            ]
        }
        
        for secret_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.finditer(pattern, js_content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    value = match.group(1) if match.groups() else match.group(0)
                    start = max(0, match.start() - 50)
                    end = min(len(js_content), match.end() + 50)
                    context = js_content[start:end]
                    
                    secrets.append({
                        'type': secret_type,
                        'value': value[:100],
                        'context': context,
                        'position': match.start()
                    })
        
        return secrets
    
    def _extract_endpoints_from_js(self, js_content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract API endpoints and URLs from JavaScript code."""
        endpoints = []
        
        patterns = [
            r'(?:fetch|axios|ajax|\.get|\.post|\.put|\.delete)\s*\(\s*["\']([^"\']+)["\']',
            r'["\'](https?://[^"\']+)["\']',
            r'["\'](/[^"\']+)["\']',
            r'`(https?://[^`]+)`',
            r'`(/[^`]+)`',
            r'new\s+URL\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                url = match.group(1)
                if url.startswith('/'):
                    absolute_url = urljoin(base_url, url)
                elif url.startswith('http'):
                    absolute_url = url
                else:
                    absolute_url = urljoin(base_url, '/' + url)
                
                start = max(0, match.start() - 30)
                end = min(len(js_content), match.end() + 30)
                context = js_content[start:end]
                
                endpoints.append({
                    'url': absolute_url,
                    'original': url,
                    'context': context,
                    'position': match.start()
                })
        
        return endpoints
    
    def _extract_parameters_from_js(self, js_content: str) -> List[Dict[str, Any]]:
        """Extract parameters from JavaScript code."""
        parameters = []
        
        func_param_pattern = r'function\s+\w+\s*\(([^)]+)\)'
        matches = re.finditer(func_param_pattern, js_content)
        for match in matches:
            params_str = match.group(1)
            params = [p.strip() for p in params_str.split(',') if p.strip()]
            for param in params:
                parameters.append({
                    'name': param,
                    'type': 'function_parameter',
                    'context': match.group(0)
                })
        
        config_pattern = r'(\w+)\s*[:=]\s*["\']([^"\']+)["\']'
        matches = re.finditer(config_pattern, js_content)
        for match in matches:
            parameters.append({
                'name': match.group(1),
                'value': match.group(2)[:100],
                'type': 'config_property',
                'context': match.group(0)
            })
        
        return parameters
    
    def _extract_functions_from_js(self, js_content: str) -> List[Dict[str, Any]]:
        """Extract custom function definitions from JavaScript."""
        functions = []
        
        patterns = [
            r'function\s+(\w+)\s*\([^)]*\)\s*\{',
            r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{',
            r'let\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\{',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, js_content, re.MULTILINE)
            for match in matches:
                func_name = match.group(1)
                start = match.end()
                brace_count = 1
                end = start
                for i, char in enumerate(js_content[start:], start):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end = i + 1
                            break
                
                func_body = js_content[match.start():end][:500]
                
                functions.append({
                    'name': func_name,
                    'signature': match.group(0)[:200],
                    'body_preview': func_body,
                    'position': match.start()
                })
        
        return functions
    
    def _extract_config_objects_from_js(self, js_content: str) -> List[Dict[str, Any]]:
        """Extract configuration objects from JavaScript."""
        configs = []
        
        patterns = [
            r'const\s+(\w+)\s*=\s*\{[^}]{10,500}\}',
            r'var\s+(\w+)\s*=\s*\{[^}]{10,500}\}',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, js_content, re.DOTALL)
            for match in matches:
                config_name = match.group(1) if match.groups() else 'anonymous'
                config_body = match.group(0)[:1000]
                
                configs.append({
                    'name': config_name,
                    'content': config_body,
                    'position': match.start()
                })
        
        return configs


# Singleton instance
_kumo_spider_instance = None

def get_kumo_spider(parallel_enabled: bool = True):
    """Get Kumo spider instance (singleton)."""
    global _kumo_spider_instance
    
    if _kumo_spider_instance is None:
        _kumo_spider_instance = KumoHttpSpider(parallel_enabled=parallel_enabled)
    
    return _kumo_spider_instance

def spider_egg_record(egg_record_id: str) -> Dict[str, Any]:
    """
    Spider an EggRecord using Kumo spider.
    This function uses the main spider_egg_record method which stores results in the egg record.
    
    Args:
        egg_record_id: ID of the EggRecord to spider
        
    Returns:
        Dictionary containing spider results
    """
    try:
        # Get spider instance
        spider = get_kumo_spider()
        
        # Perform the spidering (this stores results in the egg record)
        spider_results = spider.spider_egg_record(egg_record_id)
        
        if not spider_results.get('success', False):
            logger.error(f"Spidering failed for EggRecord {egg_record_id}")
            return spider_results
        
        logger.info(f"Spidering completed for EggRecord {egg_record_id}")
        
        return {
            'target': spider_results.get('target', ''),
            'pages_spidered': spider_results.get('pages_spidered', 0),
            'metadata_entries_created': spider_results.get('metadata_entries_created', 0),
            'spider_results': spider_results
        }
        
    except Exception as e:
        logger.error(f"Error spidering EggRecord {egg_record_id}: {e}")
        raise


# Backward compatibility alias
HTTPSpider = KumoHttpSpider

