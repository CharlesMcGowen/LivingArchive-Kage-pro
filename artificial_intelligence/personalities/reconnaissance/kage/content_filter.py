#!/usr/bin/env python3
"""
Heavy Content Filter for Ash Scout
Implements robust content filtering and data reduction
"""

import re
import hashlib
from typing import Dict, List, Any
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

class HeavyContentFilter:
    """Heavy content filter for Ash Scout data processing"""
    
    def __init__(self):
        self.logger = logger
        
        # PII detection patterns
        self.pii_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
        }
        
        # High-value content indicators
        self.high_value_indicators = [
            'admin', 'login', 'api', 'config', 'backup', 'test',
            'dev', 'staging', 'upload', 'file', 'sql', 'db',
            'user', 'account', 'manager', 'control', 'panel'
        ]
        
        # Boilerplate patterns to exclude
        self.boilerplate_patterns = [
            r'<footer[^>]*>.*?</footer>',
            r'<nav[^>]*>.*?</nav>',
            r'<aside[^>]*>.*?</aside>',
            r'<header[^>]*>.*?</header>'
        ]
    
    async def filter_content(self, content: bytes, url: str) -> Dict[str, Any]:
        """Filter and process content for AI learning"""
        
        try:
            # Decode content
            text_content = content.decode('utf-8', errors='ignore')
            
            # Check for PII
            pii_detected = self._detect_pii(text_content)
            if pii_detected:
                return {
                    'is_valuable': False,
                    'reason': 'pii_detected',
                    'pii_types': pii_detected
                }
            
            # Parse HTML
            soup = BeautifulSoup(text_content, 'html.parser')
            
            # Remove boilerplate
            cleaned_content = self._remove_boilerplate(soup)
            
            # Extract structured data
            structured_data = self._extract_structured_data(soup, url)
            
            # Calculate vulnerability potential
            vulnerability_potential = self._calculate_vulnerability_potential(
                structured_data, url
            )
            
            # Check if content is valuable
            is_valuable = vulnerability_potential > 0.3
            
            return {
                'is_valuable': is_valuable,
                'vulnerability_potential': vulnerability_potential,
                'structured_data': structured_data,
                'cleaned_content': cleaned_content,
                'content_hash': hashlib.md5(cleaned_content.encode()).hexdigest()
            }
            
        except Exception as e:
            return {
                'is_valuable': False,
                'reason': 'filtering_error',
                'error': str(e)
            }
    
    def _detect_pii(self, content: str) -> List[str]:
        """Detect PII in content"""
        
        detected_pii = []
        
        for pii_type, pattern in self.pii_patterns.items():
            if re.search(pattern, content):
                detected_pii.append(pii_type)
        
        return detected_pii
    
    def _remove_boilerplate(self, soup: BeautifulSoup) -> str:
        """Remove boilerplate content"""
        
        # Remove script and style tags
        for tag in soup(['script', 'style', 'nav', 'footer', 'header']):
            tag.decompose()
        
        # Get text content
        text = soup.get_text()
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def _extract_structured_data(self, soup: BeautifulSoup, url: str) -> Dict[str, Any]:
        """Extract structured data from HTML"""
        
        structured_data = {
            'forms': [],
            'inputs': [],
            'links': [],
            'scripts': [],
            'meta_tags': []
        }
        
        # Extract forms
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET'),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data.get('inputs', None).append(input_data)
            
            structured_data.get('forms', None).append(form_data)
        
        # Extract links
        for link in soup.find_all('a', href=True):
            structured_data['links'].append({
                'href': link.get('href', None),
                'text': link.get_text().strip()
            })
        
        # Extract scripts
        for script in soup.find_all('script', src=True):
            structured_data['scripts'].append(script.get('src', None))
        
        # Extract meta tags
        for meta in soup.find_all('meta'):
            structured_data['meta_tags'].append({
                'name': meta.get('name', ''),
                'content': meta.get('content', '')
            })
        
        return structured_data
    
    def _calculate_vulnerability_potential(self, structured_data: Dict, url: str) -> float:
        """Calculate vulnerability potential score"""
        
        score = 0.0
        
        # Check for high-value indicators in URL
        for indicator in self.high_value_indicators:
            if indicator in url.lower():
                score += 0.2
        
        # Check for forms with sensitive inputs
        for form in structured_data.get('forms', None):
            for input_data in form['inputs']:
                if input_data.get('type', None) in ['password', 'email', 'file']:
                    score += 0.1
        
        # Check for API endpoints
        for link in structured_data['links']:
            if 'api' in link.get('href', None).lower():
                score += 0.15
        
        # Check for admin/management paths
        for link in structured_data['links']:
            if any(indicator in link.get('href', None).lower() for indicator in self.high_value_indicators):
                score += 0.1
        
        return min(score, 1.0)  # Cap at 1.0
    
    async def extract_high_value_content(self, content: bytes, url: str) -> Dict[str, Any]:
        """Extract high-value content for AI training"""
        
        try:
            # Filter content first
            filtered_result = await self.filter_content(content, url)
            
            if not filtered_result['is_valuable']:
                return {
                    'is_high_value': False,
                    'reason': filtered_result.get('reason', 'not_valuable')
                }
            
            # Extract additional high-value indicators
            high_value_indicators = self._extract_high_value_indicators(
                filtered_result['structured_data']
            )
            
            # Calculate training value score
            training_value = self._calculate_training_value(
                filtered_result['structured_data'],
                high_value_indicators
            )
            
            return {
                'is_high_value': True,
                'training_value_score': training_value,
                'high_value_indicators': high_value_indicators,
                'structured_data': filtered_result['structured_data'],
                'cleaned_content': filtered_result['cleaned_content']
            }
            
            return {
                'is_high_value': False,
                'reason': 'extraction_error',
                'error': str(e)
            }
    
    def _extract_high_value_indicators(self, structured_data: Dict) -> List[str]:
        """Extract high-value indicators from structured data"""
        
        indicators = []
        
        # Check forms for sensitive inputs
        for form in structured_data.get('forms', None):
            for input_data in form['inputs']:
                if input_data.get('type', None) in ['password', 'file', 'email']:
                    indicators.append(f"sensitive_input_{input_data.get('type', None)}")
        
        # Check for API endpoints
        for link in structured_data['links']:
            if 'api' in link.get('href', None).lower():
                indicators.append('api_endpoint')
        
        # Check for admin paths
        for link in structured_data['links']:
            if any(indicator in link.get('href', None).lower() for indicator in self.high_value_indicators):
                indicators.append('admin_path')
        
        return indicators
    
    def _calculate_training_value(self, structured_data: Dict, indicators: List[str]) -> float:
        """Calculate training value score for AI learning"""
        
        score = 0.0
        
        # Base score for having structured data
        if structured_data.get('forms', None):
            score += 0.2
        if structured_data['links']:
            score += 0.1
        if structured_data['scripts']:
            score += 0.1
        
        # Bonus for high-value indicators
        score += len(indicators) * 0.1
        
        return min(score, 1.0)  # Cap at 1.0
    
    async def reduce_content_for_ai_training(self, content: str) -> str:
        """Reduce content to essential information for AI training"""
        
        # Remove HTML tags
        soup = BeautifulSoup(content, 'html.parser')
        text_content = soup.get_text()
        
        # Remove extra whitespace
        text_content = re.sub(r'\s+', ' ', text_content).strip()
        
        # Limit length for AI training
        if len(text_content) > 5000:
            text_content = text_content[:5000] + "..."
        
        return text_content
    
    async def tokenize_content_for_ai(self, content: str) -> List[str]:
        """Tokenize content for AI processing"""
        
        # Simple tokenization (can be enhanced with proper NLP)
        tokens = content.split()
        
        # Remove common stop words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        tokens = [token.lower() for token in tokens if token.lower() not in stop_words]
        
        return tokens
