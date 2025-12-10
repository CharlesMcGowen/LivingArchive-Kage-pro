#!/usr/bin/env python3
"""
Simple Ash Scout Service - For Testing
Simplified version without database dependencies
"""

import asyncio
import requests
import logging
from typing import Dict, List, Any
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class SimpleAshScoutService:
    """Simple Ash Scout Service for testing without database"""
    
    def __init__(self):
        self.logger = logger
        
    async def execute_reconnaissance(self, target_url: str) -> Dict[str, Any]:
        """Execute simple reconnaissance without database"""
        
        try:
            self.logger.info(f"🔍 Starting simple reconnaissance for {target_url}")
            
            # Phase 1: Basic HTTP request
            response = requests.get(target_url, timeout=10)
            
            # Phase 2: Simple path discovery
            discovered_paths = await self._simple_path_discovery(target_url)
            
            # Phase 3: Basic analysis
            analysis = self._basic_analysis(response, discovered_paths)
            
            return {
                "status": "completed",
                "target_url": target_url,
                "http_status": response.status_code,
                "discovered_paths": len(discovered_paths),
                "analysis": analysis
            }
            
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    async def _simple_path_discovery(self, target_url: str) -> List[Dict]:
        """Simple path discovery without database"""
        
        common_paths = [
            'admin', 'login', 'api', 'config', 'backup', 'test',
            'dev', 'staging', 'upload', 'file', 'sql', 'db',
            'user', 'account', 'manager', 'control', 'panel'
        ]
        
        discovered_paths = []
        
        for path in common_paths:
            try:
                test_url = urljoin(target_url, path)
                response = requests.get(test_url, timeout=3)
                
                if response.status_code not in [404, 403]:
                    discovered_paths.append({
                        'path': path,
                        'url': test_url,
                        'status_code': response.status_code
                    })
                    
                self.logger.debug(f"Path discovery error for {path}: {str(e)}")
                continue
        
        return discovered_paths
    
    def _basic_analysis(self, response, discovered_paths: List[Dict]) -> Dict[str, Any]:
        """Basic analysis without database"""
        
        return {
            'content_length': len(response.content) if response.content else 0,
            'server': response.headers.get('Server', 'Unknown'),
            'high_value_paths': len([p for p in discovered_paths if p.get('status_code', None) == 200]),
            'total_paths_tested': len(discovered_paths)
        }
