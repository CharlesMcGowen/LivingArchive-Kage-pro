#!/usr/bin/env python3
"""
Working Ash Scout Service
Simplified version that works with database storage
"""

import asyncio
import requests
import logging
import hashlib
from typing import Dict, List, Any
from urllib.parse import urljoin
from asgiref.sync import sync_to_async
from bs4 import BeautifulSoup
import re

# Import the Ash Scout models
from ai_system.ai_learning.models.ai_learning_models import AshScoutData, AshScoutDataset

logger = logging.getLogger(__name__)

class WorkingAshScoutService:
    """Working Ash Scout Service with database integration"""
    
    def __init__(self):
        self.logger = logger
        
        # Common wordlist for path discovery
        self.common_wordlist = [
            'admin', 'login', 'api', 'config', 'backup', 'test',
            'dev', 'staging', 'upload', 'file', 'sql', 'db',
            'user', 'account', 'manager', 'control', 'panel',
            'dashboard', 'portal', 'system', 'app', 'web',
            'cgi', 'bin', 'www', 'public', 'private', 'secure'
        ]
        
        # High-value indicators
        self.high_value_indicators = [
            'admin', 'login', 'api', 'config', 'backup', 'test',
            'dev', 'staging', 'upload', 'file', 'sql', 'db',
            'user', 'account', 'manager', 'control', 'panel'
        ]
    
    async def execute_reconnaissance(self, target_url: str) -> Dict[str, Any]:
        """Execute reconnaissance mission"""
        
        try:
            self.logger.info(f"🔍 Starting reconnaissance for {target_url}")
            
            # Check if recently analyzed
            if await self._target_recently_analyzed(target_url):
                return {"status": "skipped", "reason": "analyzed_within_year"}
            
            # Phase 1: Technology Detection
            self.logger.info(f"🔧 Detecting technology stack for {target_url}")
            tech_stack = await self._detect_technology_stack(target_url)
            
            # Phase 2: Path Discovery
            self.logger.info(f"🎯 Executing path discovery for {target_url}")
            discovered_paths = await self._path_discovery(target_url, tech_stack)
            
            # Phase 3: Content Analysis
            self.logger.info(f"📊 Analyzing discovered content for {target_url}")
            analyzed_content = await self._analyze_content(discovered_paths)
            
            # Phase 4: Store Data
            self.logger.info(f"💾 Storing reconnaissance data for {target_url}")
            await self._store_reconnaissance_data(target_url, tech_stack, analyzed_content)
            
            return {
                "status": "completed",
                "target_url": target_url,
                "tech_stack": tech_stack,
                "discovered_paths": len(discovered_paths),
                "analyzed_content": len(analyzed_content),
                "data_points": len(analyzed_content)
            }
            
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    async def _target_recently_analyzed(self, target_url: str) -> bool:
        """Check if target was recently analyzed"""
        try:
            from datetime import datetime, timedelta
            one_year_ago = datetime.now() - timedelta(days=365)
            
            exists = await sync_to_async(AshScoutData.objects.filter(
                target_url=target_url,
                scan_date__gte=one_year_ago
            ).exists)()
            
            return exists
            return False
    
    async def _detect_technology_stack(self, target_url: str) -> Dict[str, Any]:
        """Detect technology stack of the target"""
        try:
            response = requests.get(target_url, timeout=10)
            
            tech_stack = {
                'server': response.headers.get('Server', 'Unknown'),
                'frameworks': [],
                'libraries': [],
                'cms': [],
                'custom': []
            }
            
            content = response.text.lower()
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Detect common frameworks
            framework_indicators = {
                'django': ['csrfmiddlewaretoken', 'django'],
                'flask': ['flask', 'werkzeug'],
                'rails': ['rails', 'ruby'],
                'laravel': ['laravel'],
                'wordpress': ['wp-content', 'wordpress'],
                'drupal': ['drupal'],
                'joomla': ['joomla']
            }
            
            for framework, indicators in framework_indicators.items():
                if any(indicator in content for indicator in indicators):
                    tech_stack['frameworks'].append({
                        'name': framework,
                        'confidence': 0.8,
                        'evidence': f'Content indicators: {indicators}'
                    })
            
            # Detect server technology
            server_headers = ['server', 'x-powered-by', 'x-aspnet-version']
            for header in server_headers:
                if header in headers:
                    tech_stack['server'] = headers[header]
                    break
            
            return tech_stack
            
            return {'server': 'Unknown', 'frameworks': [], 'libraries': [], 'cms': [], 'custom': []}
    
    async def _path_discovery(self, target_url: str, tech_stack: Dict) -> List[Dict]:
        """Discover paths on the target"""
        discovered_paths = []
        
        # Use tech-specific extensions
        extensions = self._get_tech_extensions(tech_stack)
        
        for word in self.common_wordlist:
            for ext in extensions:
                test_path = f"{word}.{ext}" if ext else word
                test_url = urljoin(target_url, test_path)
                
                try:
                    response = requests.get(test_url, timeout=3)
                    
                    if response.status_code not in [404, 403]:
                        discovered_paths.append({
                            'path': test_path,
                            'url': test_url,
                            'status_code': response.status_code,
                            'content_length': len(response.content) if response.content else 0,
                            'headers': dict(response.headers)
                        })
                        
                    self.logger.debug(f"Path discovery error for {test_path}: {str(e)}")
                    continue
        
        return discovered_paths
    
    def _get_tech_extensions(self, tech_stack: Dict) -> List[str]:
        """Get file extensions based on detected technology"""
        extensions = ['html', 'php', 'asp', 'aspx', 'jsp']
        
        frameworks = [f.get('name', None).lower() for f in tech_stack.get('frameworks', [])]
        
        if 'wordpress' in frameworks or 'drupal' in frameworks:
            extensions.extend(['php'])
        elif 'rails' in frameworks:
            extensions.extend(['rb'])
        elif 'aspnet' in frameworks:
            extensions.extend(['aspx', 'asp'])
        
        return extensions
    
    async def _analyze_content(self, discovered_paths: List[Dict]) -> List[Dict]:
        """Analyze discovered content for valuable information"""
        analyzed_content = []
        
        for path_data in discovered_paths:
            try:
                response = requests.get(path_data.get('url', None), timeout=10)
                
                if response.content:
                    # Basic content analysis
                    content = response.content.decode('utf-8', errors='ignore')
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Extract forms
                    forms = []
                    for form in soup.find_all('form'):
                        form_data = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'GET'),
                            'inputs': []
                        }
                        for input_tag in form.find_all('input'):
                            form_data.get('inputs', None).append({
                                'name': input_tag.get('name', ''),
                                'type': input_tag.get('type', 'text')
                            })
                        forms.append(form_data)
                    
                    # Calculate vulnerability potential
                    vulnerability_score = self._calculate_vulnerability_potential(
                        path_data, forms, content
                    )
                    
                    # Only store high-value content
                    if vulnerability_score > 0.3:
                        analyzed_content.append({
                            'url': path_data.get('url', None),
                            'status_code': path_data['status_code'],
                            'forms': forms,
                            'vulnerability_potential': vulnerability_score,
                            'content_hash': hashlib.md5(content.encode()).hexdigest(),
                            'reduced_content': self._reduce_content(content)
                        })
                
                self.logger.debug(f"Content analysis error for {path_data.get('url', None)}: {str(e)}")
                continue
        
        return analyzed_content
    
    def _calculate_vulnerability_potential(self, path_data: Dict, forms: List[Dict], content: str) -> float:
        """Calculate vulnerability potential score"""
        score = 0.0
        
        # Path-based scoring
        for indicator in self.high_value_indicators:
            if indicator in path_data['path'].lower():
                score += 0.2
        
        # Form-based scoring
        for form in forms:
            for input_data in form['inputs']:
                if input_data.get('type', None) in ['password', 'email', 'file']:
                    score += 0.1
        
        # Content-based scoring
        if 'api' in content.lower():
            score += 0.15
        
        return min(score, 1.0)
    
    def _reduce_content(self, content: str) -> str:
        """Reduce content to essential information"""
        soup = BeautifulSoup(content, 'html.parser')
        
        # Remove scripts, styles, and navigation
        for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
            tag.decompose()
        
        # Get text and clean it
        text = soup.get_text()
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Limit to first 1000 characters
        return text[:1000]
    
    async def _store_reconnaissance_data(self, target_url: str, tech_stack: Dict, analyzed_content: List[Dict]):
        """Store reconnaissance data in database"""
        try:
            for content in analyzed_content:
                # Create AshScoutData record
                scout_data = await sync_to_async(AshScoutData.objects.create)(
                    target_url=content.get('url', None),
                    http_status_code=content['status_code'],
                    technology_stack=tech_stack.get('frameworks', []),
                    discovered_paths=[content.get('url', None)],
                    vulnerability_potential_score=content['vulnerability_potential'],
                    reduced_text_content=content['reduced_content'],
                    tech_stack_focus=tech_stack.get('frameworks', [{}])[0].get('name', '') if tech_stack.get('frameworks') else '',
                    ai_generated_wordlist=self.common_wordlist,
                    ai_confidence_score=content['vulnerability_potential'],
                    extracted_forms=content['forms']
                )
                
                # Create AshScoutDataset record
                await sync_to_async(AshScoutDataset.objects.create)(
                    dataset_name=f"Ash Scout - {target_url}",
                    dataset_description=f"Reconnaissance data for {target_url}",
                    scout_source='ash_scout',
                    reconnaissance_type='web_recon',
                    tech_stack_focus=tech_stack.get('frameworks', [{}])[0].get('name', '') if tech_stack.get('frameworks') else '',
                    vulnerability_potential=content['vulnerability_potential'],
                    structured_recon_data={
                        'discovered_paths': [content.get('url', None)],
                        'technology_stack': tech_stack,
                        'forms': content['forms']
                    },
                    training_value_score=content['vulnerability_potential']
                )
                
