#!/usr/bin/env python3
"""
Heavy Ash Scout Service - AI Reconnaissance System
Integrates with AI learning system for intelligent reconnaissance
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any
from urllib.parse import urljoin
import logging
import requests
from asgiref.sync import sync_to_async

# Import Django models
from ai_system.ai_learning.models.ai_learning_models import AshScoutData, AshScoutDataset

# Import local components
from .ai_learning_wordlist_generator import AILearningWordlistGenerator
from .content_filter import HeavyContentFilter
from .tech_detector import ComprehensiveTechDetector

logger = logging.getLogger(__name__)

class HeavyAshScoutService:
    """Heavy Ash Scout Service with AI learning integration"""
    
    def __init__(self):
        self.logger = logger
        self.ai_wordlist_generator = AILearningWordlistGenerator()
        self.content_filter = HeavyContentFilter()
        self.tech_detector = ComprehensiveTechDetector()
        
    async def execute_reconnaissance(self, target_url: str) -> Dict[str, Any]:
        """Execute Ash's reconnaissance with AI learning integration"""
        
        try:
            # Check if target was analyzed within the year
            if await self._target_recently_analyzed(target_url):
                return {"status": "skipped", "reason": "analyzed_within_year"}
            
            # Phase 1: Technology Stack Detection
            self.logger.info(f"🔍 Detecting technology stack for {target_url}")
            tech_stack = await self.tech_detector.detect_comprehensive_stack(target_url)
            
            # Phase 2: Generate AI Learning Wordlist
            self.logger.info(f"🧠 Generating AI learning wordlist for {target_url}")
            ai_wordlist = await self.ai_wordlist_generator.generate_tech_focused_wordlist(tech_stack)
            
            # Phase 3: AI-Focused Path Discovery
            self.logger.info(f"🎯 Executing AI-focused path discovery for {target_url}")
            discovered_paths = await self._ai_focused_path_discovery(target_url, ai_wordlist, tech_stack)
            
            # Phase 4: High-Value Page Analysis
            self.logger.info(f"📊 Analyzing high-value pages for {target_url}")
            valuable_pages = await self._analyze_high_value_pages(discovered_paths)
            
            # Phase 5: Structured Data Extraction with Content Filtering
            self.logger.info(f"🔬 Extracting structured data for {target_url}")
            scout_data = await self._extract_structured_data(valuable_pages, tech_stack)
            
            # Phase 6: Store for AI Learning
            self.logger.info(f"💾 Storing data for AI learning for {target_url}")
            await self._store_for_ai_training(scout_data)
            
            return {
                "status": "completed",
                "data_points": len(scout_data),
                "ai_wordlist_size": len(ai_wordlist),
                "discovered_paths": len(discovered_paths)
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    @sync_to_async
    def _target_recently_analyzed(self, target_url: str) -> bool:
        """Check if target was analyzed within the year"""
        
        one_year_ago = datetime.now() - timedelta(days=365)
        
        recent_analysis = AshScoutData.objects.filter(
            target_url=target_url,
            scan_date__gte=one_year_ago
        ).exists()
        
        return recent_analysis
    
    async def _ai_focused_path_discovery(self, target_url: str, ai_wordlist: List[str], tech_stack: Dict) -> List[Dict]:
        """Execute path discovery using AI-generated wordlist"""
        
        discovered_paths = []
        
        # Configure scanning parameters
        scan_config = {
            'target': target_url,
            'wordlist': ai_wordlist,
            'extensions': self._get_tech_extensions(tech_stack),
            'timeout': 3,
            'follow_redirects': True
        }
        
        # Execute scan using AI wordlist
        results = await self._execute_ai_scan(scan_config)
        
        # Filter results for high-value paths
        high_value_paths = self._filter_high_value_paths(results)
        
        return high_value_paths
    
    def _get_tech_extensions(self, tech_stack: Dict) -> List[str]:
        """Get extensions based on technology focus"""
        
        tech_extensions = {
            'wordpress': ['php', 'html', 'js', 'css'],
            'apache': ['php', 'html', 'js', 'css', 'xml'],
            'tomcat': ['jsp', 'jspx', 'html', 'js'],
            'iis': ['asp', 'aspx', 'html', 'js'],
            'nginx': ['php', 'html', 'js', 'css']
        }
        
        # Get primary framework
        primary_framework = tech_stack.get('frameworks', [{}])[0].get('name', '').lower()
        
        return tech_extensions.get(primary_framework, ['php', 'html', 'js'])
    
    async def _execute_ai_scan(self, scan_config: Dict) -> List[Dict]:
        """Execute scan using AI wordlist"""
        
        results = []
        
        for word in scan_config.get('wordlist', None)[:1000]:  # Limit for performance
            try:
                # Build URL
                test_url = urljoin(scan_config['target'], word)
                
                # Make request
                response = requests.get(test_url, timeout=scan_config['timeout'])
                
                if response and response.status_code not in [404, 403]:
                    results.append({
                        'path': word,
                        'url': test_url,
                        'status_code': response.status_code,
                        'content_length': len(response.content) if response.content else 0,
                        'headers': dict(response.headers) if response.headers else {}
                    })
                    
            except Exception as e:
                self.logger.debug(f"Scan error for {word}: {str(e)}")
                continue
        
        return results
    
    def _filter_high_value_paths(self, results: List[Dict]) -> List[Dict]:
        """Filter paths for high vulnerability potential"""
        
        high_value_indicators = [
            'admin', 'login', 'api', 'config', 'backup', 'test',
            'dev', 'staging', 'upload', 'file', 'sql', 'db',
            'user', 'account', 'manager', 'control', 'panel'
        ]
        
        filtered_paths = []
        for result in results:
            if any(indicator in result.get('path', None).lower() for indicator in high_value_indicators):
                filtered_paths.append(result)
        
        return filtered_paths
    
    async def _analyze_high_value_pages(self, discovered_paths: List[Dict]) -> List[Dict]:
        """Analyze high-value pages for vulnerability potential"""
        
        valuable_pages = []
        
        for path_data in discovered_paths:
            try:
                # Fetch page content
                response = requests.get(path_data.get('url', None), timeout=10)
                
                if response and response.content:
                    # Apply content filtering
                    filtered_content = await self.content_filter.filter_content(
                        response.content, path_data.get('url', None)
                    )
                    
                    if filtered_content.get('is_valuable', None):
                        valuable_pages.append({
                            'url': path_data.get('url', None),
                            'status_code': path_data['status_code'],
                            'filtered_content': filtered_content,
                            'vulnerability_potential': filtered_content['vulnerability_potential']
                        })
                        
                self.logger.debug(f"Analysis error for {path_data.get('url', None)}: {str(e)}")
                continue
        
        return valuable_pages
    
    async def _extract_structured_data(self, valuable_pages: List[Dict], tech_stack: Dict) -> List[Dict]:
        """Extract structured data from valuable pages"""
        
        scout_data = []
        
        for page in valuable_pages:
            try:
                # Extract structured data
                structured_data = await self._extract_page_data(page, tech_stack)
                
                # Store in database
                scout_record = await self._create_scout_record(page, tech_stack, structured_data)
                scout_data.append(scout_record)
                
                continue
        
        return scout_data
    
    @sync_to_async
    def _create_scout_record(self, page: Dict, tech_stack: Dict, structured_data: Dict) -> AshScoutData:
        """Create scout record in database"""
        
        return AshScoutData.objects.create(
            target_url=page.get('url', None),
            http_status_code=page['status_code'],
            technology_stack=tech_stack.get('frameworks', []),
            discovered_paths=[page.get('url', None)],
            vulnerability_potential_score=page['vulnerability_potential'],
            reduced_text_content=structured_data.get('reduced_text', ''),
            tech_stack_focus=tech_stack.get('primary_framework', ''),
            ai_generated_wordlist=structured_data.get('ai_wordlist', []),
            ai_confidence_score=structured_data.get('ai_confidence', 0.0)
        )
    
    async def _extract_page_data(self, page: Dict, tech_stack: Dict) -> Dict[str, Any]:
        """Extract structured data from page"""
        
        structured_data = page.get('filtered_content', {}).get('structured_data', None)
        
        return {
            'reduced_text': page.get('filtered_content', {}).get('cleaned_content', None),
            'ai_wordlist': structured_data.get('links', []),
            'ai_confidence': page['vulnerability_potential']
        }
    
    @sync_to_async
    def _store_for_ai_training(self, scout_data: List[AshScoutData]) -> None:
        """Store data for AI training"""
        
        for data in scout_data:
            try:
                # Create AI learning dataset
                AshScoutDataset.objects.create(
                    scout_source='ash_scout',
                    reconnaissance_type='web_recon',
                    tech_stack_focus=data.tech_stack_focus,
                    vulnerability_potential=data.vulnerability_potential_score,
                    structured_recon_data={
                        'discovered_paths': data.discovered_paths,
                        'technology_stack': data.technology_stack,
                        'vulnerability_indicators': data.leakage_indicators
                    },
                    training_value_score=data.training_value_score
                )
                
                continue
    
    async def batch_reconnaissance(self, target_urls: List[str]) -> Dict[str, Any]:
        """Execute batch reconnaissance on multiple targets"""
        
        results = {
            'completed': 0,
            'failed': 0,
            'skipped': 0,
            'total': len(target_urls)
        }
        
        for target_url in target_urls:
            try:
                result = await self.execute_reconnaissance(target_url)
                
                if result['status'] == 'completed':
                    results.get('completed', None) += 1
                elif result['status'] == 'skipped':
                    results['skipped'] += 1
                else:
                    results['failed'] += 1
                    
                results['failed'] += 1
        
        return results
    
    @sync_to_async
    def get_reconnaissance_summary(self, target_url: str) -> Dict[str, Any]:
        """Get summary of reconnaissance data for a target"""
        
        try:
            # Get latest reconnaissance data
            latest_data = AshScoutData.objects.filter(
                target_url=target_url
            ).order_by('-scan_date').first()
            
            if not latest_data:
                return {"error": "No reconnaissance data found"}
            
            # Get related datasets
            datasets = AshScoutDataset.objects.filter(
                tech_stack_focus=latest_data.tech_stack_focus
            ).order_by('-dateCreated')[:10]
            
            return {
                'target_url': target_url,
                'last_scan': latest_data.scan_date,
                'vulnerability_potential': latest_data.vulnerability_potential_score,
                'tech_stack_focus': latest_data.tech_stack_focus,
                'ai_confidence': latest_data.ai_confidence_score,
                'discovered_paths': len(latest_data.discovered_paths),
                'related_datasets': len(datasets)
            }
            
            return {"error": str(e)}
