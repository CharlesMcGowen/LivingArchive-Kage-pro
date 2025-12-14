#!/usr/bin/env python3
"""
Wordlist Manager - Manages Wordlists for Directory Enumeration
==============================================================

Handles:
- Loading wordlists from seclist and other sources
- Generating smart wordlists based on learned patterns
- Technology-specific wordlist selection
- Database wordlist storage/retrieval
"""

import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from collections import Counter

logger = logging.getLogger(__name__)


class WordlistManager:
    """
    Manages wordlists for Suzu's directory enumeration.
    """
    
    def __init__(self, seclist_base: Optional[Path] = None, pattern_learner=None):
        """
        Initialize wordlist manager.
        
        Args:
            seclist_base: Base path to seclist wordlists
            pattern_learner: PatternLearner instance for smart wordlist generation
        """
        self.seclist_base = seclist_base or Path('/mnt/webapps-nvme/wordlists')
        self.pattern_learner = pattern_learner
        
        # Technology-specific wordlists
        self.tech_wordlists = {
            'wordpress': ['wp-admin', 'wp-content', 'wp-includes', 'wp-login.php'],
            'laravel': ['api', 'storage', 'public', 'app', 'config'],
            'asp.net': ['.aspx', '.ashx', 'bin', 'App_Data'],
            'java': ['.jsp', 'WEB-INF', 'META-INF'],
            'api': ['api', 'v1', 'v2', 'rest', 'graphql'],
            'admin_panel': ['admin', 'administrator', 'panel', 'dashboard', 'login'],
        }
        
        logger.info("📚 Wordlist manager initialized")
    
    def generate_smart_wordlist(self, learned_patterns: Dict[str, Any], base_wordlist: Optional[Path] = None) -> List[str]:
        """
        Generate a smart wordlist based on learned patterns from Kumo.
        
        Args:
            learned_patterns: Patterns learned from Kumo's spidering
            base_wordlist: Optional base wordlist file to enhance
        
        Returns:
            List of paths to enumerate
        """
        smart_wordlist = []
        
        # Start with base wordlist if provided
        if base_wordlist and base_wordlist.exists():
            try:
                with open(base_wordlist, 'r') as f:
                    base_paths = [line.strip() for line in f if line.strip()]
                    smart_wordlist.extend(base_paths[:1000])  # Limit base wordlist
            except Exception as e:
                logger.warning(f"Error loading base wordlist: {e}")
        
        # Add learned patterns
        patterns = learned_patterns.get('patterns', [])
        for pattern in patterns:
            # Extract path segments from patterns
            segments = [s for s in pattern.split('/') if s]
            smart_wordlist.extend(segments)
        
        # Add common paths from Kumo
        common_paths = learned_patterns.get('common_paths', [])
        smart_wordlist.extend(common_paths)
        
        # Add technology-specific wordlists
        tech_hints = learned_patterns.get('technology_hints', [])
        for tech in tech_hints:
            if tech in self.tech_wordlists:
                smart_wordlist.extend(self.tech_wordlists[tech])
        
        # Add extensions-based paths
        extensions = learned_patterns.get('extensions', [])
        common_segments = learned_patterns.get('common_paths', [])
        for segment in common_segments[:20]:  # Top 20
            for ext in extensions:
                smart_wordlist.append(f"{segment}{ext}")
        
        # Remove duplicates and empty strings
        smart_wordlist = list(set([p for p in smart_wordlist if p]))
        
        # Prioritize: learned patterns first, then tech-specific, then base
        prioritized = []
        prioritized.extend(patterns)
        prioritized.extend([p for p in smart_wordlist if p not in prioritized])
        
        logger.info(f"📚 Generated smart wordlist with {len(prioritized)} paths")
        return prioritized[:2000]  # Limit to 2000 paths
    
    def get_technology_wordlist(self, technology: str) -> List[str]:
        """Get technology-specific wordlist"""
        return self.tech_wordlists.get(technology.lower(), [])
    
    def load_wordlist_from_file(self, wordlist_path: Path, limit: int = 10000) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip()][:limit]
        except Exception as e:
            logger.error(f"Error loading wordlist {wordlist_path}: {e}")
            return []

