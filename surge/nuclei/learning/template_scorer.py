#!/usr/bin/env python3
"""
Template Scoring Logic
======================

Calculates weighted scores for Nuclei templates to determine scan priority.
Maximizes effort-to-impact ratio by prioritizing effective templates.

Author: EGO Revolution Team
Version: 3.1.0
"""

import logging
from typing import List, Dict, Tuple, Optional
from django.db.models import F, Q

logger = logging.getLogger(__name__)

try:
    from surge.models import NucleiTemplateUsage
    DJANGO_ORM_AVAILABLE = True
except ImportError:
    DJANGO_ORM_AVAILABLE = False
    NucleiTemplateUsage = None


class TemplateScorer:
    """
    Calculates a weighted score for each Nuclei template to determine scan priority.
    
    Scoring Formula:
        Score = (W_E * Effectiveness) + (W_R * Reliability) - (W_C * ResourceCost) + (W_L * LearningBonus)
    """
    
    # --- Weight Configuration ---
    # These weights can eventually be pulled from a Kage-pro settings model
    WEIGHTS = {
        'W_EFFECTIVENESS': 0.6,  # High weight for finding vulnerabilities
        'W_RELIABILITY': 0.2,    # Moderate weight for stability
        'W_RESOURCE_COST': 0.1,  # Low weight for speed (avoiding excessively slow templates)
        'W_LEARNING_BONUS': 0.1, # Bonus for newly effective templates
    }
    
    # Thresholds
    MIN_RUNS_THRESHOLD = 5  # Minimum runs before template is considered (lowered for faster learning)
    MAX_DURATION_MS = 5000  # Treat anything over 5s as max cost
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """
        Initialize TemplateScorer with optional custom weights.
        
        Args:
            weights: Optional dictionary to override default weights
        """
        if weights:
            self.WEIGHTS.update(weights)
    
    def calculate_template_scores(self, template_ids: List[str]) -> List[Tuple[str, float]]:
        """
        Calculates the composite score for a list of templates and returns a prioritized list.
        
        Args:
            template_ids: List of template IDs to score
            
        Returns:
            List of tuples (template_id, score) sorted by score descending
        """
        if not DJANGO_ORM_AVAILABLE:
            logger.warning("Django ORM not available - returning templates in original order")
            return [(tid, 0.5) for tid in template_ids]  # Default neutral score
        
        # 1. Fetch usage data efficiently
        usage_data = NucleiTemplateUsage.objects.filter(
            template_id__in=template_ids
        ).values(
            'template_id', 
            'usage_count', 
            'success_count', 
            'failure_count',
            'average_response_time',
            'effectiveness_score',
            'last_used',
        )
        
        # Create a lookup dict for quick access
        usage_lookup = {data['template_id']: data for data in usage_data}
        
        scored_templates = []
        
        for template_id in template_ids:
            data = usage_lookup.get(template_id)
            
            # If no usage data, use default score (new templates get neutral score)
            if not data or data['usage_count'] < self.MIN_RUNS_THRESHOLD:
                score = 0.5  # Neutral score for new/untested templates
                scored_templates.append((template_id, score))
                continue
            
            # --- 2. Calculate Sub-Metrics (0.0 to 1.0) ---
            
            # A. Effectiveness (Finding Rate)
            # Higher is better: 0 = 0% find rate; 1 = 100% find rate
            usage_count = data['usage_count']
            success_count = data.get('success_count', 0)
            effectiveness = success_count / usage_count if usage_count > 0 else 0.0
            
            # Use effectiveness_score if available (pre-calculated)
            if data.get('effectiveness_score') is not None:
                effectiveness = data['effectiveness_score']
            
            # B. Reliability (Error Rate)
            # Higher is better: 1 = 0% error rate; lower as errors increase
            failure_count = data.get('failure_count', 0)
            error_rate = failure_count / usage_count if usage_count > 0 else 0.0
            reliability = max(0.0, 1.0 - error_rate)
            
            # C. Resource Cost (Inverted)
            # Higher is better (i.e., faster execution is better)
            avg_duration_ms = data.get('average_response_time', 0.0)
            if avg_duration_ms:
                # Convert seconds to milliseconds if needed
                if avg_duration_ms < 100:  # Likely in seconds
                    avg_duration_ms = avg_duration_ms * 1000
                
                duration_norm = min(avg_duration_ms, self.MAX_DURATION_MS) / self.MAX_DURATION_MS
                resource_cost = 1.0 - duration_norm
            else:
                resource_cost = 0.5  # Neutral if no timing data
            
            # D. Learning Bonus (Recency and activity bonus)
            # Bonus for templates that have been used recently or show recent success
            learning_bonus = 0.0
            if success_count > 0:
                learning_bonus = 0.1  # Base bonus for having found something
                # Additional bonus for recent usage (would need timestamp comparison)
                # For now, simple bonus based on success rate
                if effectiveness > 0.1:  # At least 10% success rate
                    learning_bonus += 0.05
            
            # --- 3. Composite Score Calculation ---
            score = (
                self.WEIGHTS['W_EFFECTIVENESS'] * effectiveness +
                self.WEIGHTS['W_RELIABILITY'] * reliability +
                self.WEIGHTS['W_RESOURCE_COST'] * resource_cost +
                self.WEIGHTS['W_LEARNING_BONUS'] * learning_bonus
            )
            
            # Ensure score is in valid range
            score = max(0.0, min(1.0, score))
            
            scored_templates.append((template_id, score))
        
        # 4. Sort in descending order by score
        final_list = sorted(scored_templates, key=lambda x: x[1], reverse=True)
        
        logger.debug(f"Scored {len(final_list)} templates (top 5: {final_list[:5]})")
        
        return final_list

    def get_prioritized_templates(self, all_templates: List[str], limit: Optional[int] = None) -> List[str]:
        """
        Returns only the template IDs in prioritized order.
        
        Args:
            all_templates: List of all template IDs to prioritize
            limit: Optional limit on number of templates to return
            
        Returns:
            List of template IDs sorted by priority (highest first)
        """
        scored = self.calculate_template_scores(all_templates)
        prioritized = [tpl_id for tpl_id, score in scored]
        
        if limit:
            return prioritized[:limit]
        
        return prioritized
    
    def get_top_templates(self, all_templates: List[str], top_n: int = 50) -> List[str]:
        """
        Get top N templates by score.
        
        Args:
            all_templates: List of all template IDs
            top_n: Number of top templates to return
            
        Returns:
            List of top N template IDs
        """
        return self.get_prioritized_templates(all_templates, limit=top_n)
