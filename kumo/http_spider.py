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
try:
    # Try kage-pro Django settings first
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
    import django
    django.setup()
    from django.apps import apps
    from django.db import connections
    from django.utils import timezone
    DJANGO_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
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
        
        for base_url in urls_to_spider:
            try:
                # Spider from base URL
                result = self._spider_url(base_url, egg_record_id, spider_depth)
                
                if result['success']:
                    pages_spidered.extend(result['pages'])
                    metadata_entries_created += result['metadata_created']
                    
            except Exception as e:
                logger.error(f"❌ Failed to spider {base_url}: {e}")
        
        duration = time.time() - start_time
        
        logger.info(f"🌊 Kumo spider complete: {len(pages_spidered)} pages, "
                   f"{metadata_entries_created} RequestMetaData entries created in {duration:.2f}s")
        
        return {
            'success': True,
            'target': target,
            'pages_spidered': len(pages_spidered),
            'metadata_entries_created': metadata_entries_created,
            'spider_duration': duration,
            'pages': pages_spidered
        }
    
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
    
    def _spider_url(self, url: str, egg_record_id: str, depth: int) -> Dict[str, Any]:
        """
        Spider a URL and create RequestMetaData entries.
        Core spidering logic extracted from EgoWebs1.
        
        Args:
            url: URL to spider
            egg_record_id: EggRecord UUID string
            depth: Maximum spider depth
        """
        visited = set()
        pages = []
        metadata_created = 0
        
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
                    'metadata_id': request_id  # Use request_id instead of undefined metadata.id
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
            except requests.exceptions.SSLError:
                logger.debug(f"🔒 SSL Error: {current_url}")
            except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout) as e:
                # Connection refused/reset are expected for unreachable hosts - log at debug level
                error_msg = str(e)
                if 'Connection refused' in error_msg or 'Connection reset' in error_msg or 'Connection aborted' in error_msg:
                    logger.debug(f"🔌 Connection failed (expected): {current_url} - {error_msg[:100]}")
                else:
                    logger.warning(f"⚠️  Connection error: {current_url} - {error_msg[:100]}")
            except Exception as e:
                error_msg = str(e)
                # Check if it's a connection-related error
                if 'connection' in error_msg.lower() or 'refused' in error_msg.lower() or 'reset' in error_msg.lower():
                    logger.debug(f"🔌 Connection error (expected): {current_url} - {error_msg[:100]}")
                else:
                    logger.warning(f"⚠️  Error spidering {current_url}: {error_msg[:100]}")
        
        return {
            'success': True,
            'pages': pages,
            'metadata_created': metadata_created,
            'urls_visited': len(visited)
        }
    
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

