#!/usr/bin/env python3
"""
Comprehensive Technology Detector for Ash Scout
Detects technology stack including custom technologies
"""

import re
import logging
from typing import Dict, List, Any
import requests

logger = logging.getLogger(__name__)

class ComprehensiveTechDetector:
    """Comprehensive technology stack detection for Ash"""
    
    def __init__(self):
        self.logger = logger
        self.tech_patterns = self._load_tech_patterns()
    
    def _load_tech_patterns(self) -> Dict[str, Dict]:
        """Load technology detection patterns"""
        
        return {
            'frameworks': {
                'django': [r'csrfmiddlewaretoken', r'Django', r'django-admin'],
                'flask': [r'Flask', r'flask-admin', r'Werkzeug'],
                'rails': [r'Ruby on Rails', r'rails', r'Rails'],
                'laravel': [r'Laravel', r'laravel_session', r'X-Laravel'],
                'spring': [r'Spring', r'JSESSIONID', r'X-Application-Context'],
                'express': [r'Express', r'express-session', r'X-Powered-By: Express'],
                'aspnet': [r'ASP.NET', r'ASP.NET_SessionId', r'X-AspNet-Version'],
                'wordpress': [r'WordPress', r'wp-content', r'wp-includes'],
                'drupal': [r'Drupal', r'drupal', r'X-Drupal-Cache'],
                'joomla': [r'Joomla', r'joomla', r'X-Content-Type-Options']
            },
            'servers': {
                'apache': [r'Apache', r'X-Powered-By: Apache', r'Server: Apache'],
                'nginx': [r'nginx', r'X-Powered-By: nginx', r'Server: nginx'],
                'iis': [r'IIS', r'X-Powered-By: ASP.NET', r'Server: Microsoft-IIS'],
                'tomcat': [r'Tomcat', r'Apache-Coyote', r'X-Powered-By: Tomcat']
            },
            'databases': {
                'mysql': [r'MySQL', r'mysql', r'X-Powered-By: MySQL'],
                'postgresql': [r'PostgreSQL', r'postgres', r'X-Powered-By: PostgreSQL'],
                'mongodb': [r'MongoDB', r'mongodb', r'X-Powered-By: MongoDB'],
                'redis': [r'Redis', r'redis', r'X-Powered-By: Redis']
            },
            'languages': {
                'php': [r'PHP', r'X-Powered-By: PHP', r'Server: PHP'],
                'python': [r'Python', r'X-Powered-By: Python', r'Server: Python'],
                'java': [r'Java', r'X-Powered-By: Java', r'Server: Java'],
                'nodejs': [r'Node.js', r'X-Powered-By: Node.js', r'Server: Node.js'],
                'ruby': [r'Ruby', r'X-Powered-By: Ruby', r'Server: Ruby']
            }
        }
    
    async def detect_comprehensive_stack(self, target_url: str) -> Dict[str, Any]:
        """Detect comprehensive technology stack"""
        
        try:
            # Get page content and headers
            page_data = await self._fetch_page_data(target_url)
            
            detected_tech = {
                'server': self._detect_server(page_data.get('headers', None)),
                'frameworks': self._detect_frameworks(page_data['content']),
                'libraries': self._detect_libraries(page_data['content']),
                'cms': self._detect_cms(page_data['content']),
                'custom': self._detect_custom_technologies(page_data['content']),
                'versions': self._detect_versions(page_data['content'], page_data.get('headers', None))
            }
            
            return detected_tech
            
            return {}
    
    async def _fetch_page_data(self, target_url: str) -> Dict[str, Any]:
        """Fetch page data for analysis"""
        
        try:
            response = requests.get(target_url, timeout=10)
            return {
                'content': response.text,
                'headers': dict(response.headers),
                'status_code': response.status_code
            }
            return {'content': '', 'headers': {}, 'status_code': 0}
    
    def _detect_server(self, headers: Dict[str, str]) -> List[Dict]:
        """Detect server technology"""
        
        detected = []
        
        for server_type, patterns in self.tech_patterns.get('servers', None).items():
            for pattern in patterns:
                for header_name, header_value in headers.items():
                    if re.search(pattern, header_value, re.IGNORECASE):
                        detected.append({
                            'type': 'server',
                            'name': server_type,
                            'confidence': 0.9,
                            'evidence': f"{header_name}: {header_value}"
                        })
                        break
        
        return detected
    
    def _detect_frameworks(self, content: str) -> List[Dict]:
        """Detect web frameworks"""
        
        detected = []
        
        for framework, patterns in self.tech_patterns['frameworks'].items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected.append({
                        'type': 'framework',
                        'name': framework,
                        'confidence': 0.8,
                        'evidence': f"Pattern: {pattern}"
                    })
                    break
        
        return detected
    
    def _detect_libraries(self, content: str) -> List[Dict]:
        """Detect JavaScript libraries"""
        
        detected = []
        
        # Common JS libraries
        js_libraries = {
            'jquery': [r'jquery', r'jQuery', r'$\.'],
            'react': [r'React', r'react', r'ReactDOM'],
            'angular': [r'Angular', r'angular', r'ng-'],
            'vue': [r'Vue', r'vue', r'v-'],
            'bootstrap': [r'Bootstrap', r'bootstrap', r'bs-'],
            'lodash': [r'lodash', r'_\.'],
            'moment': [r'moment', r'moment\.js']
        }
        
        for library, patterns in js_libraries.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected.append({
                        'type': 'library',
                        'name': library,
                        'confidence': 0.7,
                        'evidence': f"Pattern: {pattern}"
                    })
                    break
        
        return detected
    
    def _detect_cms(self, content: str) -> List[Dict]:
        """Detect CMS systems"""
        
        detected = []
        
        cms_patterns = {
            'wordpress': [r'WordPress', r'wp-content', r'wp-includes'],
            'drupal': [r'Drupal', r'drupal', r'X-Drupal-Cache'],
            'joomla': [r'Joomla', r'joomla', r'X-Content-Type-Options'],
            'magento': [r'Magento', r'magento', r'X-Magento'],
            'shopify': [r'Shopify', r'shopify', r'X-Shopify']
        }
        
        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected.append({
                        'type': 'cms',
                        'name': cms,
                        'confidence': 0.8,
                        'evidence': f"Pattern: {pattern}"
                    })
                    break
        
        return detected
    
    def _detect_custom_technologies(self, content: str) -> List[Dict]:
        """Detect custom or rarely seen technologies"""
        
        custom_indicators = [
            'custom_framework', 'internal_api', 'proprietary',
            'company_specific', 'internal_tool'
        ]
        
        detected_custom = []
        for indicator in custom_indicators:
            if indicator in content.lower():
                detected_custom.append({
                    'type': 'custom',
                    'indicator': indicator,
                    'confidence': 0.8,
                    'evidence': f"Custom indicator: {indicator}"
                })
        
        return detected_custom
    
    def _detect_versions(self, content: str, headers: Dict[str, str]) -> List[Dict]:
        """Detect technology versions"""
        
        versions = []
        
        # Version patterns
        version_patterns = {
            'php': r'PHP/(\d+\.\d+\.\d+)',
            'apache': r'Apache/(\d+\.\d+\.\d+)',
            'nginx': r'nginx/(\d+\.\d+\.\d+)',
            'mysql': r'MySQL/(\d+\.\d+\.\d+)'
        }
        
        for tech, pattern in version_patterns.items():
            for header_name, header_value in headers.items():
                match = re.search(pattern, header_value)
                if match:
                    versions.append({
                        'technology': tech,
                        'version': match.group(1),
                        'confidence': 0.9,
                        'evidence': f"{header_name}: {header_value}"
                    })
                    break
        
        return versions
    
    async def analyze_technology_stack(self, detected_tech: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze detected technology stack for insights"""
        
        analysis = {
            'primary_framework': None,
            'server_technology': None,
            'database_technology': None,
            'security_implications': [],
            'vulnerability_potential': 0.0
        }
        
        # Determine primary framework
        if detected_tech.get('frameworks'):
            analysis.get('primary_framework', None) = detected_tech['frameworks'][0]['name']
        
        # Determine server technology
        if detected_tech.get('server'):
            analysis['server_technology'] = detected_tech['server'][0]['name']
        
        # Determine database technology
        if detected_tech.get('databases'):
            analysis['database_technology'] = detected_tech['databases'][0]['name']
        
        # Analyze security implications
        analysis['security_implications'] = self._analyze_security_implications(detected_tech)
        
        # Calculate vulnerability potential
        analysis['vulnerability_potential'] = self._calculate_vulnerability_potential(detected_tech)
        
        return analysis
    
    def _analyze_security_implications(self, detected_tech: Dict[str, Any]) -> List[str]:
        """Analyze security implications of detected technologies"""
        
        implications = []
        
        # Check for known vulnerable technologies
        vulnerable_techs = ['wordpress', 'drupal', 'joomla']
        for framework in detected_tech.get('frameworks', []):
            if framework.get('name', None).lower() in vulnerable_techs:
                implications.append(f"Known vulnerable CMS: {framework.get('name', None)}")
        
        # Check for development frameworks
        dev_frameworks = ['flask', 'express', 'rails']
        for framework in detected_tech.get('frameworks', []):
            if framework.get('name', None).lower() in dev_frameworks:
                implications.append(f"Development framework detected: {framework.get('name', None)}")
        
        # Check for custom technologies
        if detected_tech.get('custom'):
            implications.append("Custom technologies detected - potential security risks")
        
        return implications
    
    def _calculate_vulnerability_potential(self, detected_tech: Dict[str, Any]) -> float:
        """Calculate vulnerability potential based on detected technologies"""
        
        score = 0.0
        
        # Base score for having technologies
        if detected_tech.get('frameworks'):
            score += 0.3
        if detected_tech.get('server'):
            score += 0.2
        if detected_tech.get('databases'):
            score += 0.2
        
        # Bonus for vulnerable technologies
        vulnerable_techs = ['wordpress', 'drupal', 'joomla', 'php']
        for framework in detected_tech.get('frameworks', []):
            if framework.get('name', None).lower() in vulnerable_techs:
                score += 0.2
        
        # Bonus for custom technologies
        if detected_tech.get('custom'):
            score += 0.3
        
        return min(score, 1.0)  # Cap at 1.0
