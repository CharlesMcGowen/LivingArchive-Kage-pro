#!/usr/bin/env python3
"""
Pattern Learner - Learns from Kumo's Spidering Data
====================================================

Analyzes Kumo's RequestMetaData to extract path patterns and generate
intelligent wordlists for Suzu's directory enumeration.
"""

import logging
import re
from typing import List, Dict, Any, Optional
from collections import Counter
from urllib.parse import urlparse
from django.db import connections

logger = logging.getLogger(__name__)


class PatternLearner:
    """
    Learns path patterns from Kumo's spidering to improve Suzu's enumeration.
    """
    
    def __init__(self):
        """Initialize pattern learner"""
        self.min_pattern_frequency = 2  # Minimum occurrences to consider a pattern
        logger.info("🧠 Pattern learner initialized")
    
    def analyze_kumo_findings(self, egg_record_id: str) -> Dict[str, Any]:
        """
        Analyze Kumo's RequestMetaData for an EggRecord to extract patterns.
        
        Args:
            egg_record_id: EggRecord UUID to analyze
        
        Returns:
            Dictionary with learned patterns:
            {
                'patterns': ['/api/', '/admin/', ...],
                'extensions': ['.php', '.asp', ...],
                'common_paths': ['/login', '/dashboard', ...],
                'technology_hints': ['wordpress', 'laravel', ...],
                'path_structure': {'depth': 2, 'separator': '/'}
            }
        """
        try:
            db = connections['customer_eggs']
            patterns = {
                'patterns': [],
                'extensions': [],
                'common_paths': [],
                'technology_hints': [],
                'path_structure': {}
            }
            
            with db.cursor() as cursor:
                # Get Kumo's RequestMetaData for this EggRecord
                cursor.execute("""
                    SELECT target_url, response_status, response_body
                    FROM customer_eggs_eggrecords_general_models_requestmetadata
                    WHERE record_id_id = %s
                    AND (session_id LIKE 'kumo-%' OR user_agent LIKE '%Kumo%')
                    AND target_url IS NOT NULL
                    ORDER BY timestamp DESC
                    LIMIT 100
                """, [egg_record_id])
                
                rows = cursor.fetchall()
                if not rows:
                    logger.debug(f"No Kumo data found for EggRecord {egg_record_id}")
                    return patterns
                
                # Extract paths and analyze
                paths = []
                extensions = []
                path_segments = []
                
                for row in rows:
                    target_url = row[0]
                    if target_url:
                        parsed = urlparse(target_url)
                        path = parsed.path
                        paths.append(path)
                        
                        # Extract path segments
                        segments = [s for s in path.split('/') if s]
                        path_segments.extend(segments)
                        
                        # Extract extensions
                        if '.' in path:
                            ext = path.split('.')[-1].lower()
                            if len(ext) <= 5:  # Reasonable extension length
                                extensions.append(ext)
                
                # Find common patterns
                segment_counter = Counter(path_segments)
                common_segments = [seg for seg, count in segment_counter.most_common(20) 
                                 if count >= self.min_pattern_frequency]
                
                # Find common path prefixes
                path_prefixes = Counter()
                for path in paths:
                    parts = path.split('/')
                    for i in range(1, min(4, len(parts))):  # Up to depth 3
                        prefix = '/'.join(parts[:i+1])
                        if prefix:
                            path_prefixes[prefix] += 1
                
                common_prefixes = [prefix for prefix, count in path_prefixes.most_common(15)
                                 if count >= self.min_pattern_frequency]
                
                # Extract extensions
                ext_counter = Counter(extensions)
                common_extensions = [ext for ext, count in ext_counter.most_common(10)]
                
                # Detect technology hints
                technology_hints = self._detect_technology(paths, rows)
                
                patterns = {
                    'patterns': common_prefixes,
                    'extensions': [f'.{ext}' for ext in common_extensions],
                    'common_paths': common_segments,
                    'technology_hints': technology_hints,
                    'path_structure': {
                        'depth': max([len(p.split('/')) for p in paths]) if paths else 2,
                        'separator': '/',
                        'total_paths_analyzed': len(paths)
                    }
                }
                
                logger.info(f"🧠 Learned {len(common_prefixes)} patterns, {len(common_extensions)} extensions from {len(paths)} Kumo paths")
                return patterns
                
        except Exception as e:
            logger.error(f"❌ Error analyzing Kumo findings: {e}")
            return {'patterns': [], 'extensions': [], 'common_paths': [], 'technology_hints': [], 'path_structure': {}}
    
    def _detect_technology(self, paths: List[str], rows: List) -> List[str]:
        """Detect technology hints from paths and response bodies"""
        hints = []
        
        # Check paths for technology indicators
        path_text = ' '.join(paths).lower()
        
        if 'wp-' in path_text or 'wordpress' in path_text:
            hints.append('wordpress')
        if 'laravel' in path_text or '/api/v' in path_text:
            hints.append('laravel')
        if '.asp' in path_text or '.aspx' in path_text:
            hints.append('asp.net')
        if '.jsp' in path_text:
            hints.append('java')
        if '/api/' in path_text:
            hints.append('api')
        if '/admin' in path_text or '/administrator' in path_text:
            hints.append('admin_panel')
        
        # Check response bodies for technology hints
        try:
            for row in rows[:10]:  # Check first 10 responses
                response_body = row[2] if len(row) > 2 else ''
                if response_body:
                    body_lower = response_body.lower()
                    if 'wordpress' in body_lower and 'wordpress' not in hints:
                        hints.append('wordpress')
                    if 'laravel' in body_lower and 'laravel' not in hints:
                        hints.append('laravel')
                    if 'drupal' in body_lower and 'drupal' not in hints:
                        hints.append('drupal')
        except Exception:
            pass
        
        return list(set(hints))  # Remove duplicates

