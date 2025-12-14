#!/usr/bin/env python3
"""
Path Learning Module for Suzu
Stores and retrieves learned path weights based on historical success rates
"""

import logging
from typing import Dict, Optional
from django.db import connections
import json

logger = logging.getLogger(__name__)


def load_learned_path_weights(target_cms: Optional[str] = None) -> Dict[str, float]:
    """
    Load path weights learned from historical success/failure data.
    
    Args:
        target_cms: Optional CMS name to filter learned weights (e.g., 'wordpress', 'drupal')
    
    Returns:
        Dictionary mapping path patterns to learned weights (0.0-1.0)
    """
    learned_weights = {}
    
    try:
        db = connections['customer_eggs']
        with db.cursor() as cursor:
            # Query DirectoryEnumerationResult for historical success patterns
            # Success is defined as: status 200, high priority score, or CMS detection match
            query = """
                SELECT 
                    discovered_path,
                    AVG(priority_score) as avg_priority,
                    COUNT(*) as occurrence_count,
                    SUM(CASE WHEN path_status_code = 200 THEN 1 ELSE 0 END) as success_count,
                    SUM(CASE WHEN detected_cms IS NOT NULL THEN 1 ELSE 0 END) as cms_match_count
                FROM customer_eggs_eggrecords_general_models_directoryenumerationresult
                WHERE priority_score > 0.3
            """
            
            params = []
            if target_cms:
                query += " AND (detected_cms = %s OR detected_cms IS NULL)"
                params.append(target_cms)
            
            query += """
                GROUP BY discovered_path
                HAVING COUNT(*) >= 2  -- At least 2 occurrences to be considered learned
                ORDER BY avg_priority DESC, occurrence_count DESC
                LIMIT 100
            """
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            for row in rows:
                path = row[0]
                avg_priority = float(row[1]) if row[1] else 0.0
                occurrence_count = int(row[2]) if row[2] else 0
                success_count = int(row[3]) if row[3] else 0
                cms_match_count = int(row[4]) if row[4] else 0
                
                # Calculate learned weight based on:
                # - Average priority score (0.0-1.0)
                # - Success rate (status 200 ratio)
                # - CMS match rate (if CMS was detected)
                success_rate = success_count / occurrence_count if occurrence_count > 0 else 0.0
                cms_match_rate = cms_match_count / occurrence_count if occurrence_count > 0 else 0.0
                
                # Combined weight: prioritize paths with high priority, success rate, and CMS matches
                learned_weight = (avg_priority * 0.5) + (success_rate * 0.3) + (cms_match_rate * 0.2)
                
                # Normalize to 0.0-1.0
                learned_weight = min(learned_weight, 1.0)
                
                # Only include paths with meaningful learned weight
                if learned_weight > 0.2:
                    learned_weights[path] = learned_weight
                    logger.debug(f"Learned weight for {path}: {learned_weight:.2f} (priority: {avg_priority:.2f}, success: {success_rate:.2f}, cms: {cms_match_rate:.2f})")
        
        if learned_weights:
            logger.info(f"📚 Loaded {len(learned_weights)} learned path weights")
        else:
            logger.debug("No learned path weights found (insufficient historical data)")
    
    except Exception as e:
        logger.warning(f"Error loading learned path weights: {e}")
        # Return empty dict on error - will fall back to base weights
    
    return learned_weights


def record_path_success(
    path: str,
    egg_record_id: str,
    priority_score: float,
    status_code: int,
    cms_detected: Optional[str] = None
) -> None:
    """
    Record a path's success for future learning.
    This is called after enumeration to update learning data.
    
    Args:
        path: Discovered path
        egg_record_id: EggRecord UUID
        priority_score: Calculated priority score
        status_code: HTTP status code
        cms_detected: Detected CMS name (if any)
    """
    # This is handled automatically by DirectoryEnumerationResult model
    # The load_learned_path_weights function queries this data
    # No explicit recording needed - data is already in the database
    pass


def get_cms_specific_paths(cms_name: Optional[str] = None) -> Dict[str, float]:
    """
    Get CMS-specific path patterns with weights.
    First tries vector database, then falls back to hardcoded patterns.
    
    Args:
        cms_name: CMS name (e.g., 'wordpress', 'drupal', 'joomla')
    
    Returns:
        Dictionary mapping CMS-specific paths to weights
    """
    # Try vector database first
    try:
        from suzu.vector_path_store import VectorPathStore
        vector_store = VectorPathStore()
        
        # Get weighted paths from vector DB
        weighted_paths = vector_store.get_weighted_paths(
            cms_name=cms_name,
            limit=200,
            min_weight=0.2
        )
        
        if weighted_paths:
            # Convert to dict format
            cms_paths_dict = {item['path']: item['weight'] for item in weighted_paths}
            logger.info(f"📚 Loaded {len(cms_paths_dict)} paths from vector DB for CMS: {cms_name}")
            return cms_paths_dict
    except Exception as e:
        logger.debug(f"Vector DB not available or error: {e}, falling back to hardcoded patterns")
    
    # Fallback to hardcoded patterns
    cms_paths = {
        'wordpress': {
            '/wp-admin/': 0.45,
            '/wp-content/': 0.35,
            '/wp-includes/': 0.30,
            '/wp-login.php': 0.40,
            '/wp-config.php': 0.50,  # High value - config file
            '/wp-json/': 0.35,
            '/wp-admin/admin-ajax.php': 0.30,
            '/wp-admin/admin.php': 0.30,
            '/xmlrpc.php': 0.25,
            '/wp-cron.php': 0.20,
        },
        'drupal': {
            '/sites/default/': 0.40,
            '/modules/': 0.35,
            '/themes/': 0.30,
            '/user/login': 0.40,
            '/admin': 0.45,
            '/sites/default/files/': 0.30,
            '/sites/all/modules/': 0.30,
            '/sites/all/themes/': 0.25,
            '/update.php': 0.35,
            '/install.php': 0.30,
        },
        'joomla': {
            '/administrator/': 0.45,
            '/components/': 0.35,
            '/modules/': 0.30,
            '/templates/': 0.25,
            '/administrator/index.php': 0.40,
            '/administrator/components/': 0.35,
            '/configuration.php': 0.50,  # High value - config file
            '/htaccess.txt': 0.25,
        },
        'magento': {
            '/magento/': 0.40,
            '/admin/': 0.45,
            '/app/etc/': 0.50,  # High value - config
            '/var/': 0.30,
            '/media/': 0.25,
            '/skin/': 0.25,
        },
        'shopify': {
            '/admin/': 0.40,
            '/cart': 0.30,
            '/checkout': 0.35,
            '/account': 0.30,
        },
    }
    
    if cms_name and cms_name.lower() in cms_paths:
        return cms_paths[cms_name.lower()]
    
    # Return empty if CMS not found or None
    return {}

