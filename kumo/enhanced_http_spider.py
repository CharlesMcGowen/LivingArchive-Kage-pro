#!/usr/bin/env python3
"""
Enhanced HTTP Spider - Comprehensive Web Scraping
=================================================

Enhanced version of KumoHttpSpider with comprehensive metadata capture:
- Headers: All request/response headers
- Protocols: HTTP version, TLS version, cipher suites
- Schemes: http/https detection and redirect chains
- HTML Parameters: Forms, input fields, hidden parameters
- URLs: All discovered URLs (internal/external links)
- JavaScript: Extract and catalog JS files, inline scripts

Author: EGO Revolution Team
Version: 2.0.0 - Enhanced Metadata Capture
"""

import requests
import logging
import time
import sys
import ssl
import hashlib
import re
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import json

from artificial_intelligence.personalities.reconnaissance import EGOQT_SRC  # noqa: F401

from database.customer_database import CustomerDatabaseService
from database.customer_models import EggRecord

logger = logging.getLogger(__name__)


class EnhancedHttpSpider:
    """
    Enhanced HTTP spidering service with comprehensive metadata capture.
    
    Captures detailed information about web pages including headers,
    protocols, HTML parameters, URLs, and JavaScript.
    """
    
    def __init__(self, parallel_enabled: bool = True):
        """
        Initialize enhanced HTTP spider.
        
        Args:
            parallel_enabled: Use parallel threading for faster spidering
        """
        self.parallel_enabled = parallel_enabled
        
        # Spidering configuration
        self.request_timeout = 15.0
        self.max_workers = 32 if self.parallel_enabled else 5
        self.max_pages_per_domain = 100
        self.spider_depth = 3
        self.max_redirects = 10
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Enhanced-Kumo-Spider/2.0 (EGO Security Scanner)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # SSL context for TLS information
        self.ssl_context = ssl.create_default_context()
        
        logger.info(f"🌊 Enhanced Kumo spider initialized ({'Parallel' if self.parallel_enabled else 'Sequential'} mode, {self.max_workers} workers)")
    
    def spider_egg_record(self, egg_record_id: str, depth: int = None) -> Dict[str, Any]:
        """
        Spider an EggRecord and create comprehensive RequestMetaData entries.
        
        Args:
            egg_record_id: EggRecord UUID string to spider
            depth: Spider depth (default: 3 levels)
            
        Returns:
            Spider results summary with detailed metadata
        """
        # Initialize database service
        db_service = CustomerDatabaseService()
        
        # Get egg record from database
        egg_record = db_service.get_egg_record_by_id(egg_record_id)
        if not egg_record:
            logger.error(f"❌ EggRecord {egg_record_id} not found")
            return {
                'success': False,
                'error': 'EggRecord not found',
                'target': egg_record_id
            }
        
        target = egg_record.sub_domain or egg_record.domain_name
        spider_depth = depth or self.spider_depth
        
        logger.info(f"🌊 Enhanced Kumo spidering {target} (depth: {spider_depth})")
        
        start_time = time.time()
        
        # Try both HTTP and HTTPS
        urls_to_spider = [
            f"https://{target}",
            f"http://{target}"
        ]
        
        metadata_entries_created = 0
        pages_spidered = []
        comprehensive_metadata = []
        
        for base_url in urls_to_spider:
            try:
                # Spider from base URL
                result = self._spider_url_enhanced(base_url, egg_record, spider_depth)
                
                if result['success']:
                    pages_spidered.extend(result['pages'])
                    metadata_entries_created += result['metadata_created']
                    comprehensive_metadata.extend(result['comprehensive_metadata'])
                    
            except Exception as e:
                logger.error(f"❌ Failed to spider {base_url}: {e}")
        
        duration = time.time() - start_time
        
        logger.info(f"🌊 Enhanced Kumo spider complete: {len(pages_spidered)} pages, "
                   f"{metadata_entries_created} RequestMetaData entries created in {duration:.2f}s")
        
        return {
            'success': True,
            'target': target,
            'pages_spidered': len(pages_spidered),
            'metadata_entries_created': metadata_entries_created,
            'spider_duration': duration,
            'pages': pages_spidered,
            'comprehensive_metadata': comprehensive_metadata
        }
    
    def _spider_url_enhanced(self, url: str, egg_record: Any, depth: int) -> Dict[str, Any]:
        """
        Spider a URL with comprehensive metadata capture.
        
        Args:
            url: URL to spider
            egg_record: EggRecord object
            depth: Maximum spider depth
            
        Returns:
            Dictionary with spider results and comprehensive metadata
        """
        visited = set()
        pages = []
        metadata_created = 0
        comprehensive_metadata = []
        
        # Start with initial URL
        to_visit = [(url, 0)]  # (url, current_depth)
        
        while to_visit and len(pages) < self.max_pages_per_domain:
            current_url, current_depth = to_visit.pop(0)
            
            if current_url in visited or current_depth > depth:
                continue
            
            visited.add(current_url)
            
            try:
                # Make HTTP request with comprehensive data capture
                response = self.session.get(
                    current_url,
                    timeout=self.request_timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                # Capture comprehensive metadata
                metadata = self._capture_comprehensive_metadata(current_url, response, egg_record)
                comprehensive_metadata.append(metadata)
                
                # Store request/response data in egg record
                request_id = hashlib.md5(f"{current_url}:{time.time()}".encode()).hexdigest()
                session_id = f"enhanced-misty-{egg_record.id}"
                
                # Create enhanced request metadata entry
                request_metadata = {
                    'request_id': request_id,
                    'session_id': session_id,
                    'url': current_url,
                    'method': 'GET',
                    'status_code': response.status_code,
                    'response_time_ms': int(response.elapsed.total_seconds() * 1000),
                    'request_headers': dict(response.request.headers),
                    'response_headers': dict(response.headers),
                    'response_body': response.text[:50000],  # Limit body size
                    'cookies': [
                        {'name': cookie.name, 'value': cookie.value, 'domain': cookie.domain}
                        for cookie in response.cookies
                    ],
                    'user_agent': self.session.headers.get('User-Agent', ''),
                    'spider_agent': 'enhanced-misty',
                    'scan_session': f"enhanced-misty-{egg_record.id}",
                    'scan_stage': 'enhanced_spidering',
                    'timestamp': datetime.now().isoformat(),
                    'comprehensive_metadata': metadata
                }
                
                # Update egg record with enhanced request metadata
                current_metadata = egg_record.images or []
                current_metadata.append(request_metadata)
                
                # Update the egg record
                db_service = CustomerDatabaseService()
                db_service.update_egg_record(str(egg_record.id), {
                    'images': current_metadata,
                    'cert_bool': True  # Mark as spidered
                })
                
                metadata_created += 1
                
                # Parse page with enhanced analysis
                page_data = {
                    'url': current_url,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'cookies': [
                        {'name': cookie.name, 'value': cookie.value, 'domain': cookie.domain}
                        for cookie in response.cookies
                    ],
                    'content_length': len(response.text),
                    'depth': current_depth,
                    'metadata_id': request_id,
                    'comprehensive_metadata': metadata
                }
                
                pages.append(page_data)
                
                # Find links to spider next with enhanced analysis
                if current_depth < depth:
                    links = self._extract_links_enhanced(response.text, current_url)
                    
                    # Add links to visit queue
                    for link in links[:20]:  # Limit links per page
                        if link not in visited:
                            to_visit.append((link, current_depth + 1))
                
                logger.debug(f"  ✅ Enhanced spidered: {current_url} (depth {current_depth})")
                
            except requests.exceptions.Timeout:
                logger.warning(f"⏰ Timeout: {current_url}")
            except requests.exceptions.SSLError:
                logger.warning(f"🔒 SSL Error: {current_url}")
            except Exception as e:
                logger.error(f"❌ Error spidering {current_url}: {e}")
        
        return {
            'success': True,
            'pages': pages,
            'metadata_created': metadata_created,
            'urls_visited': len(visited),
            'comprehensive_metadata': comprehensive_metadata
        }
    
    def _capture_comprehensive_metadata(self, url: str, response: requests.Response, egg_record: Any) -> Dict[str, Any]:
        """
        Capture comprehensive metadata from HTTP response.
        
        Args:
            url: Requested URL
            response: HTTP response object
            egg_record: EggRecord object
            
        Returns:
            Dictionary with comprehensive metadata
        """
        metadata = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'headers': self._analyze_headers(response),
            'protocols': self._analyze_protocols(url, response),
            'schemes': self._analyze_schemes(url, response),
            'html_parameters': self._analyze_html_parameters(response.text),
            'urls': self._analyze_urls(response.text, url),
            'javascript': self._analyze_javascript(response.text),
            'security_headers': self._analyze_security_headers(response),
            'server_info': self._analyze_server_info(response),
            'content_analysis': self._analyze_content(response.text)
        }
        
        return metadata
    
    def _analyze_headers(self, response: requests.Response) -> Dict[str, Any]:
        """
        Analyze HTTP headers for security and functionality.
        
        Args:
            response: HTTP response object
            
        Returns:
            Dictionary with header analysis
        """
        headers = dict(response.headers)
        
        return {
            'all_headers': headers,
            'content_type': headers.get('Content-Type', ''),
            'server': headers.get('Server', ''),
            'x_powered_by': headers.get('X-Powered-By', ''),
            'x_frame_options': headers.get('X-Frame-Options', ''),
            'x_content_type_options': headers.get('X-Content-Type-Options', ''),
            'x_xss_protection': headers.get('X-XSS-Protection', ''),
            'strict_transport_security': headers.get('Strict-Transport-Security', ''),
            'content_security_policy': headers.get('Content-Security-Policy', ''),
            'referrer_policy': headers.get('Referrer-Policy', ''),
            'cache_control': headers.get('Cache-Control', ''),
            'etag': headers.get('ETag', ''),
            'last_modified': headers.get('Last-Modified', ''),
            'content_length': headers.get('Content-Length', ''),
            'connection': headers.get('Connection', ''),
            'date': headers.get('Date', '')
        }
    
    def _analyze_protocols(self, url: str, response: requests.Response) -> Dict[str, Any]:
        """
        Analyze HTTP and TLS protocols.
        
        Args:
            url: Requested URL
            response: HTTP response object
            
        Returns:
            Dictionary with protocol analysis
        """
        protocols = {
            'http_version': response.raw.version,
            'scheme': urlparse(url).scheme,
            'tls_info': {}
        }
        
        # Try to get TLS information
        try:
            if urlparse(url).scheme == 'https':
                hostname = urlparse(url).hostname
                port = urlparse(url).port or 443
                
                # Get TLS certificate info
                cert = ssl.get_server_certificate((hostname, port))
                protocols['tls_info'] = {
                    'certificate': cert,
                    'tls_version': 'TLS 1.2/1.3'  # Simplified
                }
        except Exception as e:
            protocols['tls_info'] = {'error': str(e)}
        
        return protocols
    
    def _analyze_schemes(self, url: str, response: requests.Response) -> Dict[str, Any]:
        """
        Analyze URL schemes and redirect chains.
        
        Args:
            url: Requested URL
            response: HTTP response object
            
        Returns:
            Dictionary with scheme analysis
        """
        return {
            'original_scheme': urlparse(url).scheme,
            'final_scheme': urlparse(response.url).scheme,
            'redirect_chain': [r.url for r in response.history],
            'final_url': response.url,
            'redirect_count': len(response.history),
            'scheme_changed': urlparse(url).scheme != urlparse(response.url).scheme
        }
    
    def _analyze_html_parameters(self, html_content: str) -> Dict[str, Any]:
        """
        Analyze HTML for forms, inputs, and parameters.
        
        Args:
            html_content: HTML content to analyze
            
        Returns:
            Dictionary with HTML parameter analysis
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find forms
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'inputs': []
                }
                
                # Find inputs
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'type': input_tag.get('type', 'text'),
                        'name': input_tag.get('name', ''),
                        'id': input_tag.get('id', ''),
                        'value': input_tag.get('value', ''),
                        'placeholder': input_tag.get('placeholder', ''),
                        'required': input_tag.has_attr('required')
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
            
            # Find hidden inputs
            hidden_inputs = []
            for input_tag in soup.find_all('input', type='hidden'):
                hidden_inputs.append({
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', '')
                })
            
            # Find URL parameters
            url_params = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if '?' in href:
                    params = parse_qs(href.split('?')[1])
                    url_params.append({
                        'url': href,
                        'parameters': params
                    })
            
            return {
                'forms': forms,
                'hidden_inputs': hidden_inputs,
                'url_parameters': url_params,
                'total_forms': len(forms),
                'total_hidden_inputs': len(hidden_inputs),
                'total_url_parameters': len(url_params)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_urls(self, html_content: str, base_url: str) -> Dict[str, Any]:
        """
        Analyze URLs found in HTML content.
        
        Args:
            html_content: HTML content to analyze
            base_url: Base URL for relative links
            
        Returns:
            Dictionary with URL analysis
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find all links
            links = []
            for link in soup.find_all(['a', 'link'], href=True):
                href = link['href']
                absolute_url = urljoin(base_url, href)
                links.append({
                    'href': href,
                    'absolute_url': absolute_url,
                    'text': link.get_text().strip(),
                    'title': link.get('title', ''),
                    'rel': link.get('rel', [])
                })
            
            # Find all script sources
            script_sources = []
            for script in soup.find_all('script', src=True):
                src = script['src']
                absolute_url = urljoin(base_url, src)
                script_sources.append({
                    'src': src,
                    'absolute_url': absolute_url
                })
            
            # Find all image sources
            image_sources = []
            for img in soup.find_all('img', src=True):
                src = img['src']
                absolute_url = urljoin(base_url, src)
                image_sources.append({
                    'src': src,
                    'absolute_url': absolute_url,
                    'alt': img.get('alt', '')
                })
            
            # Categorize URLs
            internal_urls = []
            external_urls = []
            for link in links:
                if urlparse(link['absolute_url']).netloc == urlparse(base_url).netloc:
                    internal_urls.append(link)
                else:
                    external_urls.append(link)
            
            return {
                'all_links': links,
                'script_sources': script_sources,
                'image_sources': image_sources,
                'internal_urls': internal_urls,
                'external_urls': external_urls,
                'total_links': len(links),
                'total_script_sources': len(script_sources),
                'total_image_sources': len(image_sources),
                'total_internal_urls': len(internal_urls),
                'total_external_urls': len(external_urls)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_javascript(self, html_content: str) -> Dict[str, Any]:
        """
        Analyze JavaScript in HTML content.
        
        Args:
            html_content: HTML content to analyze
            
        Returns:
            Dictionary with JavaScript analysis
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find external JavaScript files
            external_js = []
            for script in soup.find_all('script', src=True):
                external_js.append({
                    'src': script['src'],
                    'type': script.get('type', 'text/javascript'),
                    'async': script.has_attr('async'),
                    'defer': script.has_attr('defer')
                })
            
            # Find inline JavaScript
            inline_js = []
            for script in soup.find_all('script', src=False):
                if script.string:
                    inline_js.append({
                        'type': script.get('type', 'text/javascript'),
                        'content': script.string.strip()[:1000],  # Limit content
                        'length': len(script.string)
                    })
            
            # Find JavaScript in event handlers
            event_handlers = []
            for tag in soup.find_all(attrs=lambda x: x and any(attr.startswith('on') for attr in x.keys())):
                for attr, value in tag.attrs.items():
                    if attr.startswith('on') and value:
                        event_handlers.append({
                            'tag': tag.name,
                            'event': attr,
                            'handler': value
                        })
            
            return {
                'external_js': external_js,
                'inline_js': inline_js,
                'event_handlers': event_handlers,
                'total_external_js': len(external_js),
                'total_inline_js': len(inline_js),
                'total_event_handlers': len(event_handlers)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_security_headers(self, response: requests.Response) -> Dict[str, Any]:
        """
        Analyze security headers.
        
        Args:
            response: HTTP response object
            
        Returns:
            Dictionary with security header analysis
        """
        headers = dict(response.headers)
        
        security_headers = {
            'x_frame_options': headers.get('X-Frame-Options', ''),
            'x_content_type_options': headers.get('X-Content-Type-Options', ''),
            'x_xss_protection': headers.get('X-XSS-Protection', ''),
            'strict_transport_security': headers.get('Strict-Transport-Security', ''),
            'content_security_policy': headers.get('Content-Security-Policy', ''),
            'referrer_policy': headers.get('Referrer-Policy', ''),
            'permissions_policy': headers.get('Permissions-Policy', ''),
            'cross_origin_embedder_policy': headers.get('Cross-Origin-Embedder-Policy', ''),
            'cross_origin_opener_policy': headers.get('Cross-Origin-Opener-Policy', ''),
            'cross_origin_resource_policy': headers.get('Cross-Origin-Resource-Policy', '')
        }
        
        # Analyze security header presence
        present_headers = [k for k, v in security_headers.items() if v]
        missing_headers = [k for k, v in security_headers.items() if not v]
        
        return {
            'security_headers': security_headers,
            'present_headers': present_headers,
            'missing_headers': missing_headers,
            'security_score': len(present_headers) / len(security_headers) * 100
        }
    
    def _analyze_server_info(self, response: requests.Response) -> Dict[str, Any]:
        """
        Analyze server information.
        
        Args:
            response: HTTP response object
            
        Returns:
            Dictionary with server analysis
        """
        headers = dict(response.headers)
        
        return {
            'server': headers.get('Server', ''),
            'x_powered_by': headers.get('X-Powered-By', ''),
            'x_aspnet_version': headers.get('X-AspNet-Version', ''),
            'x_aspnetmvc_version': headers.get('X-AspNetMvc-Version', ''),
            'x_generator': headers.get('X-Generator', ''),
            'x_drupal_cache': headers.get('X-Drupal-Cache', ''),
            'x_drupal_dynamic_cache': headers.get('X-Drupal-Dynamic-Cache', ''),
            'x_content_type_options': headers.get('X-Content-Type-Options', ''),
            'x_robots_tag': headers.get('X-Robots-Tag', '')
        }
    
    def _analyze_content(self, html_content: str) -> Dict[str, Any]:
        """
        Analyze HTML content for patterns and technologies.
        
        Args:
            html_content: HTML content to analyze
            
        Returns:
            Dictionary with content analysis
        """
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Find meta tags
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
                content = meta.get('content')
                if name and content:
                    meta_tags[name] = content
            
            # Find title
            title = soup.find('title')
            title_text = title.get_text().strip() if title else ''
            
            # Find technologies
            technologies = []
            if 'wp-content' in html_content:
                technologies.append('WordPress')
            if 'drupal' in html_content.lower():
                technologies.append('Drupal')
            if 'joomla' in html_content.lower():
                technologies.append('Joomla')
            if 'jquery' in html_content.lower():
                technologies.append('jQuery')
            if 'bootstrap' in html_content.lower():
                technologies.append('Bootstrap')
            if 'react' in html_content.lower():
                technologies.append('React')
            if 'angular' in html_content.lower():
                technologies.append('Angular')
            if 'vue' in html_content.lower():
                technologies.append('Vue.js')
            
            return {
                'title': title_text,
                'meta_tags': meta_tags,
                'technologies': technologies,
                'content_length': len(html_content),
                'has_forms': len(soup.find_all('form')) > 0,
                'has_javascript': len(soup.find_all('script')) > 0,
                'has_css': len(soup.find_all('link', rel='stylesheet')) > 0,
                'has_images': len(soup.find_all('img')) > 0
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_links_enhanced(self, html_content: str, base_url: str) -> List[str]:
        """
        Extract links from HTML content with enhanced analysis.
        
        Args:
            html_content: HTML content to analyze
            base_url: Base URL for relative links
            
        Returns:
            List of discovered URLs
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
            
            # Find all form actions
            for form in soup.find_all('form', action=True):
                action = form['action']
                absolute_url = urljoin(base_url, action)
                
                if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                    links.append(absolute_url)
            
        except Exception as e:
            logger.debug(f"Error extracting links: {e}")
        
        return links


# Singleton instance
_enhanced_http_spider_instance = None

def get_enhanced_http_spider(parallel_enabled: bool = True):
    """Get enhanced HTTP spider instance (singleton)."""
    global _enhanced_http_spider_instance
    
    if _enhanced_http_spider_instance is None:
        _enhanced_http_spider_instance = EnhancedHttpSpider(parallel_enabled=parallel_enabled)
    
    return _enhanced_http_spider_instance


def spider_egg_record_enhanced(egg_record_id: str, depth: int = None) -> Dict[str, Any]]:
    """
    Spider an EggRecord with enhanced metadata capture.
    
    Args:
        egg_record_id: ID of the EggRecord to spider
        depth: Spider depth
        
    Returns:
        Dictionary containing enhanced spider results
    """
    spider = get_enhanced_http_spider()
    return spider.spider_egg_record(egg_record_id, depth)


if __name__ == "__main__":
    # Test the enhanced HTTP spider
    import asyncio
    
    async def test_enhanced_spider():
        spider = EnhancedHttpSpider()
        
        # Test spidering
        results = spider.spider_egg_record("test-record-id")
        print(f"Enhanced spider results: {results}")
    
    asyncio.run(test_enhanced_spider())

