#!/usr/bin/env python3
"""
CMS Detection Service for Suzu
Detects CMS from HTTP headers, HTML content, and path patterns
Correlates with Nmap scan data and technology fingerprints
"""

import re
import logging
from typing import Dict, List, Any, Optional
from django.db import connections

logger = logging.getLogger(__name__)


class CMSDetector:
    """
    Detects CMS from multiple sources:
    - HTTP headers (from Kumo's RequestMetaData)
    - HTML content (from Kumo's spidering)
    - Path patterns (from Suzu's enumeration)
    - Nmap service detection
    - Technology fingerprints
    """
    
    def __init__(self):
        self.cms_patterns = self._load_cms_patterns()
        logger.info("🔍 CMS detector initialized")
    
    def _load_cms_patterns(self) -> Dict[str, Dict]:
        """Load CMS detection patterns including enterprise and framework technologies"""
        return {
            'wordpress': {
                'type': 'cms',
                'headers': [
                    (r'X-Powered-By', r'WordPress'),
                    (r'Link', r'<.*wp-json.*>'),
                    (r'X-Pingback', r'.*'),
                ],
                'html': [
                    r'wp-content',
                    r'wp-includes',
                    r'wp-admin',
                    r'/wp-json/',
                    r'WordPress',
                    r'wp-embed',
                    r'wp-block',
                    r'wp-emoji',
                    r'wp-block-library',
                    # Enhanced version pattern with capture group
                    r'name=["\']generator["\'][^>]*content=["\']WordPress\s+([\d\.]+)["\']',
                ],
                'paths': [
                    '/wp-admin/',
                    '/wp-content/',
                    '/wp-includes/',
                    '/wp-login.php',
                    '/wp-config.php',
                    '/wp-cron.php',
                    '/xmlrpc.php',
                    '/wp-json/',
                    '/wp-admin/admin-ajax.php',
                ],
                'meta_tags': [
                    r'generator.*WordPress',
                    r'name=["\']generator["\'][^>]*content=["\']WordPress\s+([\d\.]+)["\']',
                ],
            },
            'drupal': {
                'type': 'cms',
                'headers': [
                    (r'X-Drupal-Cache', r'.*'),
                    (r'X-Generator', r'Drupal'),
                    (r'X-Drupal-Dynamic-Cache', r'.*'),
                ],
                'html': [
                    r'/sites/default/',
                    r'/modules/',
                    r'/themes/',
                    r'Drupal',
                    r'drupal\.js',
                    r'/core/misc/',
                    r'/core/assets/',
                ],
                'paths': [
                    '/sites/default/',
                    '/modules/',
                    '/themes/',
                    '/user/login',
                    '/admin',
                    '/update.php',
                    '/install.php',
                    '/sites/all/modules/',
                    '/sites/all/themes/',
                ],
            },
            'joomla': {
                'type': 'cms',
                'headers': [
                    (r'X-Content-Type-Options', r'.*'),
                    (r'X-Powered-By', r'Joomla'),
                ],
                'html': [
                    r'/administrator/',
                    '/components/',
                    r'Joomla',
                    r'/media/jui/',
                    r'/media/system/',
                    r'joomla\.js',
                ],
                'paths': [
                    '/administrator/',
                    '/components/',
                    '/modules/',
                    '/templates/',
                    '/configuration.php',
                    '/htaccess.txt',
                ],
            },
            'magento': {
                'type': 'e-commerce',
                'headers': [
                    (r'X-Magento-Tags', r'.*'),
                    (r'Set-Cookie', r'frontend='),
                ],
                'html': [
                    r'/skin/frontend/default/',
                    r'Magento\.version',
                    r'mage/loader\.js',
                    r'Magento',
                ],
                'paths': [
                    '/skin/frontend/',
                    '/app/etc/',
                    '/magento/',
                    '/admin/',
                ],
                'meta_tags': [
                    r'generator.*Magento',
                ],
            },
            'shopify': {
                'type': 'e-commerce',
                'headers': [
                    (r'X-Shopify-Shop-Id', r'.*'),
                    (r'X-ShopId', r'.*'),
                ],
                'html': [
                    r'/cdn/shop/',
                    r'Shopify\.theme',
                    r'content="shopify"',
                    r'shopify',
                    r'cdn.shopify.com',
                ],
                'paths': [
                    '/admin/',
                    '/cart',
                ],
            },
            'aem': {
                'type': 'cms-enterprise',
                'headers': [
                    (r'X-AEM-Edge-Delivery-Service', r'.*'),
                ],
                'html': [
                    r'/etc/clientlibs/',
                    r'/content/dam/',
                    r'/apps/',
                    r'data-sly-resource',
                ],
                'paths': [
                    '/crx/de/',
                    '/editor.html/',
                ],
                'meta_tags': [
                    r'content="Adobe Experience Manager\s+([\d\.]+)"',
                ],
            },
            'sitecore': {
                'type': 'enterprise',
                'html': [
                    r'content="Sitecore"',
                    r'/shell/Controls/Rich Text Editor/',
                ],
                'paths': [
                    '/sitecore/shell/',
                ],
            },
            'vbulletin': {
                'type': 'forum',
                'html': [
                    r'vbulletin_css',
                    r'vbulletin-core',
                ],
                'meta_tags': [
                    r'generator.*vBulletin',
                ],
            },
            'apache_struts': {
                'type': 'framework',
                'html': [
                    r'struts-menu\.js',
                ],
                'paths': [
                    r'\.action',
                    r'\.do',
                ],
            },
            'jsf': {
                'type': 'framework',
                'html': [
                    r'javax\.faces\.resource',
                ],
                'headers': [
                    (r'Set-Cookie', r'jsessionid'),
                ],
            },
        }
    
    def detect_cms_from_request_metadata(
        self, 
        request_metadata_id: str,
        response_headers: Dict[str, str],
        response_body: str
    ) -> Optional[Dict[str, Any]]:
        """
        Detect CMS from Kumo's RequestMetaData.
        
        Args:
            request_metadata_id: UUID of RequestMetaData record
            response_headers: HTTP response headers
            response_body: HTTP response body (HTML)
        
        Returns:
            {
                'cms': 'wordpress',
                'version': '6.0',
                'confidence': 0.95,
                'method': 'html',
                'signatures': ['wp-content', 'wp-includes'],
            } or None
        """
        detections = []
        
        # Check headers
        for cms_name, patterns in self.cms_patterns.items():
            for header_name, header_pattern in patterns.get('headers', []):
                if header_name in response_headers:
                    if re.search(header_pattern, response_headers[header_name], re.IGNORECASE):
                        detections.append({
                            'cms': cms_name,
                            'method': 'header',
                            'signature': f"{header_name}: {response_headers[header_name]}",
                            'confidence': 0.7,
                        })
        
        # Check HTML content
        for cms_name, patterns in self.cms_patterns.items():
            for html_pattern in patterns.get('html', []):
                if re.search(html_pattern, response_body, re.IGNORECASE):
                    detections.append({
                        'cms': cms_name,
                        'method': 'html',
                        'signature': html_pattern,
                        'confidence': 0.8,
                    })
        
        # Check meta tags
        meta_tag_pattern = r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']'
        meta_matches = re.findall(meta_tag_pattern, response_body, re.IGNORECASE)
        for meta_content in meta_matches:
            for cms_name in self.cms_patterns.keys():
                if cms_name.lower() in meta_content.lower():
                    detections.append({
                        'cms': cms_name,
                        'method': 'meta_tag',
                        'signature': meta_content,
                        'confidence': 0.9,
                    })
        
        # Aggregate detections
        if detections:
            # Group by CMS
            cms_scores = {}
            for detection in detections:
                cms = detection['cms']
                if cms not in cms_scores:
                    cms_scores[cms] = {
                        'confidence': 0.0,
                        'methods': [],
                        'signatures': [],
                    }
                cms_scores[cms]['confidence'] += detection['confidence']
                cms_scores[cms]['methods'].append(detection['method'])
                cms_scores[cms]['signatures'].append(detection['signature'])
            
            # Get highest confidence CMS
            best_cms = max(cms_scores.items(), key=lambda x: x[1]['confidence'])
            cms_name, cms_data = best_cms
            
            # Normalize confidence (max 1.0)
            confidence = min(cms_data['confidence'] / len(detections), 1.0)
            
            return {
                'cms': cms_name,
                'version': self._extract_version(cms_name, response_body, response_headers),
                'confidence': confidence,
                'method': '+'.join(set(cms_data['methods'])),
                'signatures': cms_data['signatures'],
            }
        
        return None
    
    def detect_cms_from_path(self, discovered_path: str) -> Optional[Dict[str, Any]]:
        """
        Detect CMS from discovered path patterns.
        
        Args:
            discovered_path: Path discovered by enumeration
        
        Returns:
            CMS detection dict or None
        """
        path_lower = discovered_path.lower()
        
        for cms_name, patterns in self.cms_patterns.items():
            for path_pattern in patterns.get('paths', []):
                if path_pattern in path_lower:
                    return {
                        'cms': cms_name,
                        'version': None,
                        'confidence': 0.6,  # Lower confidence for path-only detection
                        'method': 'path',
                        'signatures': [path_pattern],
                    }
        
        return None
    
    def _extract_version(self, cms_name: str, html: str, headers: Dict) -> Optional[str]:
        """
        Extract CMS version from content based on specific patterns.
        Enhanced with improved regex patterns and header-based extraction.
        """
        patterns = self.cms_patterns.get(cms_name, {})
        
        # 1. Check Meta Tags/HTML for version string with capture groups
        for pattern in patterns.get('html', []):
            # Look for explicit version capture groups (like the one added for WordPress)
            match = re.search(pattern, html, re.IGNORECASE)
            if match and len(match.groups()) > 0:
                return match.group(1).strip()
        
        # 2. Check Meta Tags specifically
        for pattern in patterns.get('meta_tags', []):
            match = re.search(pattern, html, re.IGNORECASE)
            if match and len(match.groups()) > 0:
                return match.group(1).strip()
        
        # 3. Check Headers (e.g., X-Powered-By)
        for header_name, header_pattern in patterns.get('headers', []):
            if header_name in headers:
                # Example: X-Powered-By: PHP/7.4.30 or WordPress/6.0
                version_match = re.search(r'([\d\.]+)', headers[header_name])
                if version_match:
                    return version_match.group(1).strip()
        
        # 4. CMS-specific version extraction patterns
        if cms_name == 'wordpress':
            # Check meta generator tag (enhanced pattern)
            meta_pattern = r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress\s+([\d\.]+)["\']'
            match = re.search(meta_pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
            
            # Check wp-includes/version.php
            version_pattern = r'\$wp_version\s*=\s*["\']([\d\.]+)["\']'
            match = re.search(version_pattern, html)
            if match:
                return match.group(1)
        
        elif cms_name == 'drupal':
            # Check CHANGELOG.txt or VERSION
            version_pattern = r'Drupal\s+([\d\.]+)'
            match = re.search(version_pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
            # Check X-Generator header
            if 'X-Generator' in headers:
                version_match = re.search(r'Drupal\s+([\d\.]+)', headers['X-Generator'], re.IGNORECASE)
                if version_match:
                    return version_match.group(1)
        
        elif cms_name == 'joomla':
            version_pattern = r'Joomla!?\s+([\d\.]+)'
            match = re.search(version_pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        elif cms_name == 'aem':
            # AEM version in meta tags
            aem_pattern = r'content="Adobe Experience Manager\s+([\d\.]+)"'
            match = re.search(aem_pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        elif cms_name == 'magento':
            # Magento version in JavaScript
            magento_pattern = r'Magento\.version\s*=\s*["\']([\d\.]+)["\']'
            match = re.search(magento_pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def correlate_with_nmap(
        self,
        egg_record_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        port: Optional[int] = None,
        discovered_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Correlate discovered path with Nmap scan data, specifically targeting service CPEs.
        Enhanced to support both egg_record_id and IP/port-based lookup.
        
        Args:
            egg_record_id: UUID of EggRecord (optional, for backward compatibility)
            ip_address: IP address for correlation (preferred method)
            port: Port number for correlation (preferred method)
            discovered_path: Path discovered by enumeration (optional, for logging)
        
        Returns:
            {
                'nmap_scan_id': uuid,
                'port': 80,
                'service_name': 'http',
                'service_version': 'Apache/2.4.41',
                'product': 'Apache',
                'cpe': ['cpe:/a:apache:http_server:2.4.41'],
                'source': 'Nmap_VSA'
            } or None
        """
        try:
            db = connections['customer_eggs']
            with db.cursor() as cursor:
                # Prefer IP/port-based lookup if available (more accurate)
                if ip_address and port:
                    # First try to get IP from eggrecord if we have egg_record_id
                    if egg_record_id:
                        cursor.execute("""
                            SELECT e."subDomain", e.domainname
                            FROM customer_eggs_eggrecords_general_models_eggrecord e
                            WHERE e.id = %s
                        """, [egg_record_id])
                        egg_row = cursor.fetchone()
                        if egg_row:
                            # Use domainname or subDomain as fallback
                            target_host = egg_row[1] or egg_row[0] or ip_address
                        else:
                            target_host = ip_address
                    else:
                        target_host = ip_address
                    
                    # Query by IP/port with CPE extraction
                    cursor.execute("""
                        SELECT 
                            n.id,
                            n.port,
                            n.service_name,
                            n.service_version,
                            n.open_ports,
                            n.target
                        FROM customer_eggs_eggrecords_general_models_nmap n
                        WHERE n.target = %s
                        AND n.port = %s
                        AND n.scan_status = 'completed'
                        ORDER BY n.created_at DESC
                        LIMIT 1
                    """, [target_host, port])
                else:
                    # Fallback to egg_record_id-based lookup
                cursor.execute("""
                    SELECT 
                        n.id,
                        n.port,
                        n.service_name,
                        n.service_version,
                            n.open_ports,
                            n.target
                    FROM customer_eggs_eggrecords_general_models_nmap n
                    WHERE n.record_id_id = %s
                    AND n.scan_status = 'completed'
                    AND (n.service_name ILIKE '%%http%%' OR n.port IN (80, 443, 8080, 8443))
                    ORDER BY n.created_at DESC
                    LIMIT 1
                """, [egg_record_id])
                
                row = cursor.fetchone()
                if row:
                    # Parse open_ports JSON to extract detailed service info including CPE
                    open_ports_data = None
                    cpe_list = []
                    
                    if row[4]:  # open_ports field
                        try:
                            import json
                            open_ports_data = json.loads(row[4]) if isinstance(row[4], str) else row[4]
                        except:
                            pass
                    
                    # Find matching port/service and extract CPE
                    service_info = None
                    if isinstance(open_ports_data, list):
                        for port_data in open_ports_data:
                            if isinstance(port_data, dict):
                                port_num = port_data.get('port', row[1])
                                target_port = port if port else (80 if row[1] in [80, 443, 8080, 8443] else row[1])
                                
                                if port_num == target_port or (not port and port_num in [80, 443, 8080, 8443]):
                                    service_info = port_data
                                    
                                    # Extract CPE from port data
                                    if 'cpe' in port_data:
                                        cpe_value = port_data['cpe']
                                        if isinstance(cpe_value, list):
                                            cpe_list = cpe_value
                                        elif isinstance(cpe_value, str):
                                            cpe_list = [cpe_value]
                                    break
                    
                    # Build result with CPE data
                    result = {
                        'nmap_scan_id': str(row[0]),
                        'port': row[1] or (service_info.get('port') if service_info else None),
                        'service_name': row[2] or (service_info.get('service') if service_info else None),
                        'service_version': row[3] or (service_info.get('version') if service_info else None),
                        'product': service_info.get('product') if service_info else None,
                        'cpe': cpe_list,  # CPE is critical for vulnerability analysis
                        'source': 'Nmap_VSA',
                    }
                    
                    # Add IP address if available
                    if row[5]:
                        result['ip_address'] = row[5]
                    
                    return result
        except Exception as e:
            logger.debug(f"Error correlating with Nmap: {e}")
        
        return None

