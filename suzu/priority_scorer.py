#!/usr/bin/env python3
"""
Priority Scoring System for Suzu Directory Enumeration
Calculates priority scores for discovered directories based on multiple factors
Includes adaptive intelligence: learned path weights override base priorities
"""

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class DirectoryPriorityScorer:
    """
    Calculates priority scores for discovered directories based on:
    - CMS detection
    - Technology fingerprint correlation
    - Nmap service correlation
    - Path patterns (admin, api, etc.) with adaptive learning
    - Historical success rates (learned weights)
    - Status codes
    
    Features adaptive intelligence:
    - Learned path weights override base priorities
    - CMS-specific path expansion
    - Contextual weighting based on target CMS
    """
    
    def __init__(self, target_cms: Optional[str] = None):
        """
        Initialize scorer with base and learned path weights.
        
        Args:
            target_cms: Optional CMS name to load CMS-specific paths and learned weights
        """
        self.target_cms = target_cms.lower() if target_cms else None
        self.base_priority_paths = self._load_base_paths()
        
        # Load CMS-specific paths if CMS is known
        self.cms_specific_paths = {}
        if self.target_cms:
            try:
                from suzu.path_learning import get_cms_specific_paths
                self.cms_specific_paths = get_cms_specific_paths(self.target_cms)
                logger.info(f"📋 Loaded {len(self.cms_specific_paths)} CMS-specific paths for {self.target_cms}")
            except Exception as e:
                logger.debug(f"Could not load CMS-specific paths: {e}")
        
        # Load learned weights from historical data
        self.learned_path_weights = self._load_learned_weights()
        
        logger.info(f"📊 Priority scorer initialized (CMS: {self.target_cms or 'unknown'}, Learned paths: {len(self.learned_path_weights)})")
    
    def _load_base_paths(self) -> Dict[str, float]:
        """
        Load default high-priority path patterns with initial weights.
        
        Returns:
            Dictionary mapping path patterns to base weights (0.0-1.0)
        """
        paths = {
            # General High Value
            '/admin': 0.30,
            '/administrator': 0.30,
            '/api': 0.25,
            '/api/v1': 0.20,
            '/api/v2': 0.20,
            
            # Configuration/Backup Files (High Priority)
            '/.env': 0.35,
            '/config': 0.25,
            '/backup': 0.20,
            '/database': 0.20,
            '/db': 0.20,
            '/sql': 0.20,
            
            # Authentication Endpoints
            '/login': 0.20,
            '/signin': 0.20,
            '/auth': 0.20,
            '/oauth': 0.20,
            '/register': 0.15,
            
            # Control Panels
            '/dashboard': 0.25,
            '/panel': 0.25,
            '/console': 0.25,
            '/control': 0.25,
            
            # Development/Testing
            '/test': 0.15,
            '/dev': 0.15,
            '/staging': 0.15,
            '/debug': 0.20,
            
            # Version Control
            '/.git': 0.30,
            '/.svn': 0.25,
            '/.hg': 0.25,
            
            # CMS-Specific Defaults (These get boosted if CMS is detected)
            '/wp-admin': 0.40,
            '/wp-content': 0.30,
            '/wp-includes': 0.25,
            '/wp-login.php': 0.35,
            '/wp-config.php': 0.45,  # High value - config file
            '/user/login': 0.40,  # Drupal
            '/sites/default/': 0.35,  # Drupal
            '/administrator': 0.40,  # Joomla
            '/components/': 0.30,  # Joomla
        }
        return paths
    
    def _load_learned_weights(self) -> Dict[str, float]:
        """
        Loads path weights learned from historical success/failure data.
        These weights will dynamically override or boost base scores.
        
        Returns:
            Dictionary mapping path patterns to learned weights (0.0-1.0)
        """
        try:
            from suzu.path_learning import load_learned_path_weights
            weights = load_learned_path_weights(self.target_cms)
            return weights
        except ImportError:
            logger.debug("Path learning module not available; using default path weights.")
            return {}
        except Exception as e:
            logger.debug(f"Error loading learned weights: {e}")
            return {}
    
    def calculate_priority(
        self,
        discovered_path: str,
        status_code: int,
        cms_detection: Optional[Dict] = None,
        nmap_correlation: Optional[Dict] = None,
        technology_fingerprint: Optional[Dict] = None,
        content_length: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Calculate priority score (0.0-1.0) and factors, applying learned weights.
        
        Args:
            discovered_path: Path discovered by enumeration
            status_code: HTTP status code
            cms_detection: CMS detection result from CMSDetector
            nmap_correlation: Nmap scan correlation data
            technology_fingerprint: Technology fingerprint data
            content_length: Response content length
        
        Returns:
            {
                'priority_score': 0.85,
                'priority_factors': [
                    'Adaptive Path Priority (Learned): /admin (0.45)',
                    'CMS detected: wordpress',
                    'HTTP service on port 80',
                ]
            }
        """
        score = 0.0
        factors = []
        path_lower = discovered_path.lower()
        
        # --- 1. Path Priority Scoring (Base + Adaptive Override) ---
        path_score_applied = False
        
        # First check CMS-specific paths (highest priority if CMS matches)
        if cms_detection:
            cms_name = cms_detection.get('cms', '').lower()
            if cms_name in self.cms_specific_paths:
                for cms_path, cms_weight in self.cms_specific_paths.items():
                    if cms_path in path_lower:
                        # Check for learned override
                        learned_weight = self.learned_path_weights.get(discovered_path, 0.0)
                        # Use max of CMS weight or learned weight
                        path_score = max(cms_weight, learned_weight)
                        score += path_score
                        
                        if learned_weight > cms_weight:
                            factors.append(f"Adaptive Path Priority (Learned): {cms_path} ({path_score:.2f})")
                        else:
                            factors.append(f"CMS-Specific Path: {cms_path} ({path_score:.2f})")
                        
                        path_score_applied = True
                        break
        
        # Then check base priority paths
        if not path_score_applied:
            for priority_pattern, base_weight in self.base_priority_paths.items():
                if priority_pattern in path_lower:
                    # Check for learned override weight
                    learned_weight = self.learned_path_weights.get(discovered_path, 0.0)
                    
                    # Apply the maximum of the base weight or the learned weight
                    # This ensures learning can boost or suppress the priority
                    path_score = max(base_weight, learned_weight)
                    
                    score += path_score
                    
                    # Add factor explanation
                    if learned_weight > base_weight:
                        factors.append(f"Adaptive Path Priority (Learned): {priority_pattern} ({path_score:.2f})")
                    else:
                        factors.append(f"Base Path Priority: {priority_pattern} ({path_score:.2f})")
                    
                    path_score_applied = True
                    break  # Break after finding the highest matching pattern
        
        # If no pattern matched, check for learned weight for exact path
        if not path_score_applied:
            learned_weight = self.learned_path_weights.get(discovered_path, 0.0)
            if learned_weight > 0.2:  # Only apply if meaningful
                score += learned_weight
                factors.append(f"Learned Path Weight: {discovered_path} ({learned_weight:.2f})")
        
        # CMS detection boost
        if cms_detection:
            cms_confidence = cms_detection.get('confidence', 0.0)
            score += 0.2 * cms_confidence
            factors.append(f"CMS detected: {cms_detection.get('cms')} (confidence: {cms_confidence:.2f})")
        
        # Nmap service correlation
        if nmap_correlation:
            service_name = nmap_correlation.get('service_name', '').lower()
            if 'http' in service_name or 'https' in service_name:
                score += 0.15
                port = nmap_correlation.get('port', 'unknown')
                factors.append(f"HTTP service on port {port}")
            
            # Version detection adds value
            if nmap_correlation.get('service_version'):
                score += 0.05
                factors.append(f"Service version detected: {nmap_correlation.get('service_version')}")
        
        # Technology fingerprint correlation
        if technology_fingerprint:
            tech_category = technology_fingerprint.get('technology_category', '').lower()
            if tech_category == 'cms':
                score += 0.15
                factors.append(f"Technology fingerprint: {technology_fingerprint.get('technology_name')}")
            elif tech_category in ['framework', 'web_framework']:
                score += 0.1
                factors.append(f"Framework detected: {technology_fingerprint.get('technology_name')}")
        
        # Status code weighting
        if status_code == 200:
            score += 0.1
            factors.append("Status 200 (accessible)")
            
            # Large content length might indicate interesting pages
            if content_length and content_length > 10000:
                score += 0.05
                factors.append(f"Large response size: {content_length} bytes")
        elif status_code in [301, 302, 307, 308]:
            score += 0.05
            factors.append("Redirect (may be interesting)")
        elif status_code == 403:
            score += 0.08  # Forbidden can indicate protected resources
            factors.append("Status 403 (forbidden - may be protected)")
        elif status_code == 401:
            score += 0.08  # Unauthorized can indicate authentication endpoints
            factors.append("Status 401 (unauthorized - authentication endpoint)")
        elif status_code == 500:
            score += 0.03  # Server errors might reveal info
            factors.append("Status 500 (server error - may reveal info)")
        
        # File extension hints
        if any(ext in path_lower for ext in ['.php', '.jsp', '.asp', '.aspx', '.py', '.rb']):
            score += 0.05
            factors.append("Dynamic file extension detected")
        
        # Normalize to 0.0-1.0
        score = min(score, 1.0)
        
        # If no factors, add default
        if not factors:
            factors.append("Standard enumeration result")
        
        return {
            'priority_score': round(score, 3),
            'priority_factors': factors,
        }
    
    def get_priority_wordlist(
        self,
        egg_record_id: str,
        cms_detection: Optional[Dict] = None,
        technology_fingerprint: Optional[Dict] = None,
    ) -> List[str]:
        """
        Generate priority wordlist based on detected technologies and learned paths.
        
        Args:
            egg_record_id: UUID of EggRecord
            cms_detection: CMS detection result
            technology_fingerprint: Technology fingerprint data
        
        Returns:
            List of prioritized paths to enumerate (sorted by priority)
        """
        priority_paths = []
        path_weights = {}  # Track weights for sorting
        
        # CMS-specific paths (highest priority)
        if cms_detection:
            cms = cms_detection.get('cms', '').lower()
            if cms in self.cms_specific_paths:
                for path, weight in self.cms_specific_paths.items():
                    priority_paths.append(path)
                    path_weights[path] = weight
        
        # Framework-specific paths
        if technology_fingerprint:
            framework = technology_fingerprint.get('technology_name', '').lower()
            if 'laravel' in framework:
                framework_paths = ['/storage/', '/app/', '/config/']
                for path in framework_paths:
                    priority_paths.append(path)
                    path_weights[path] = 0.25
            elif 'django' in framework:
                framework_paths = ['/admin/', '/static/', '/media/']
                for path in framework_paths:
                    priority_paths.append(path)
                    path_weights[path] = 0.25
            elif 'rails' in framework:
                framework_paths = ['/assets/', '/public/']
                for path in framework_paths:
                    priority_paths.append(path)
                    path_weights[path] = 0.25
        
        # Add base priority paths
        for path, weight in self.base_priority_paths.items():
            if path not in path_weights:  # Don't override CMS-specific weights
                priority_paths.append(path)
                path_weights[path] = weight
        
        # Add learned paths (if they're not already included)
        for learned_path, learned_weight in self.learned_path_weights.items():
            if learned_path not in path_weights and learned_weight > 0.2:
                priority_paths.append(learned_path)
                path_weights[learned_path] = learned_weight
        
        # Sort by weight (highest first) and deduplicate
        priority_paths = list(set(priority_paths))
        priority_paths.sort(key=lambda p: path_weights.get(p, 0.0), reverse=True)
        
        return priority_paths

