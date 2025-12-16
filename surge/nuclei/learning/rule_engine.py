#!/usr/bin/env python3
"""
Adaptation Rule Engine
======================

Applies adaptation rules based on real-time scan metrics to modify
scan configuration dynamically during execution.

Author: EGO Revolution Team
Version: 3.2.0
"""

import logging
import copy
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    from surge.models import NucleiAdaptationRule, NucleiScanSession
    from surge.nuclei.class_based_api import ScanConfig
    DJANGO_ORM_AVAILABLE = True
except ImportError:
    DJANGO_ORM_AVAILABLE = False
    NucleiAdaptationRule = None
    NucleiScanSession = None
    ScanConfig = None


class AdaptationRuleEngine:
    """
    Applies adaptation rules based on real-time scan metrics to modify 
    the next execution's ScanConfig.
    """
    
    def __init__(self):
        """Initialize the rule engine."""
        if not DJANGO_ORM_AVAILABLE:
            logger.warning("Django ORM not available - rule engine will be limited")
    
    def _evaluate_condition(self, metric_value: float, condition: str, threshold: float) -> bool:
        """
        Helper to evaluate if the metric meets the rule's condition.
        
        Args:
            metric_value: Current value of the metric
            condition: Comparison operator ('>', '<', '==', '>=', '<=', '!=')
            threshold: Value to compare against
            
        Returns:
            True if condition is met, False otherwise
        """
        if condition == '>':
            return metric_value > threshold
        elif condition == '<':
            return metric_value < threshold
        elif condition == '==':
            return abs(metric_value - threshold) < 0.001  # Float comparison
        elif condition == '>=':
            return metric_value >= threshold
        elif condition == '<=':
            return metric_value <= threshold
        elif condition == '!=':
            return abs(metric_value - threshold) >= 0.001
        else:
            logger.warning(f"Unknown condition operator: {condition}")
            return False
    
    def _apply_action(self, current_config_value: float, action_type: str, action_value: float) -> float:
        """
        Helper to apply the rule's action (MULTIPLY, SET, ADD).
        
        Args:
            current_config_value: Current value of the config field
            action_type: Type of action ('SET', 'MULTIPLY', 'ADD')
            action_value: Value to apply
            
        Returns:
            New value after applying action
        """
        if action_type == 'SET':
            return action_value
        elif action_type == 'MULTIPLY':
            return current_config_value * action_value
        elif action_type == 'ADD':
            return current_config_value + action_value
        else:
            logger.warning(f"Unknown action type: {action_type}")
            return current_config_value
    
    def _extract_metrics_from_session(self, session: Any) -> Dict[str, Any]:
        """
        Extract real-time metrics from scan session.
        
        Args:
            session: NucleiScanSession instance or dict with metrics
            
        Returns:
            Dictionary of metric names to values
        """
        metrics = {}
        
        if hasattr(session, 'total_requests'):
            metrics['total_requests'] = session.total_requests or 0
        if hasattr(session, 'completed_requests'):
            metrics['completed_requests'] = session.completed_requests or 0
        if hasattr(session, 'failed_requests'):
            metrics['failed_requests'] = session.failed_requests or 0
        if hasattr(session, 'vulnerabilities_found'):
            metrics['vulnerabilities_found'] = session.vulnerabilities_found or 0
        if hasattr(session, 'duration_seconds'):
            metrics['duration_seconds'] = session.duration_seconds or 0.0
        
        # Calculate derived metrics
        if metrics.get('completed_requests', 0) > 0 and metrics.get('duration_seconds', 0) > 0:
            metrics['requests_per_second'] = metrics['completed_requests'] / metrics['duration_seconds']
        
        if metrics.get('completed_requests', 0) > 0:
            metrics['failure_rate'] = metrics.get('failed_requests', 0) / metrics['completed_requests']
            metrics['success_rate'] = 1.0 - metrics['failure_rate']
        
        if metrics.get('total_requests', 0) > 0:
            metrics['progress_percent'] = (metrics.get('completed_requests', 0) / metrics['total_requests']) * 100.0
        
        return metrics
    
    def apply_rules(self, 
                    current_config: ScanConfig, 
                    session: Any,
                    target: Optional[str] = None) -> ScanConfig:
        """
        Fetches active rules, checks them against the session's metrics, and 
        returns a modified ScanConfig object.
        
        Args:
            current_config: Current ScanConfig to adapt
            session: NucleiScanSession instance or dict with scan metrics
            target: Optional target identifier for target-specific rules
            
        Returns:
            Adapted ScanConfig object (deep copy, original unchanged)
        """
        if not DJANGO_ORM_AVAILABLE or not ScanConfig:
            logger.warning("Cannot apply rules - Django ORM or ScanConfig not available")
            return current_config
        
        # Create a deep copy to modify, keeping the original safe
        adapted_config = copy.deepcopy(current_config)
        
        # 1. Fetch relevant rules (Global and Target-specific rules)
        rules_query = NucleiAdaptationRule.objects.filter(is_active=True)
        
        # Filter by target if provided (assuming rules have a target field)
        # For now, we'll apply all active rules
        rules = rules_query.order_by('-priority')
        
        if not rules.exists():
            logger.debug("No active adaptation rules found")
            return adapted_config
        
        # 2. Extract real-time metrics from the session
        session_metrics = self._extract_metrics_from_session(session)
        
        if not session_metrics:
            logger.warning("No metrics available from session")
            return adapted_config
        
        # 3. Iterate and apply rules
        rules_applied = []
        
        for rule in rules:
            # Parse rule conditions (assuming JSONField)
            conditions = rule.conditions if isinstance(rule.conditions, dict) else {}
            action_config = rule.action_config if isinstance(rule.action_config, dict) else {}
            
            # Check if all conditions are met
            all_conditions_met = True
            
            for metric_name, condition_data in conditions.items():
                if metric_name not in session_metrics:
                    all_conditions_met = False
                    break
                
                # Support both simple threshold and dict with operator
                if isinstance(condition_data, dict):
                    operator = condition_data.get('operator', '>')
                    threshold = condition_data.get('threshold', 0)
                else:
                    # Simple threshold, default to '>'
                    operator = '>'
                    threshold = condition_data
                
                metric_value = session_metrics[metric_name]
                
                if not self._evaluate_condition(metric_value, operator, threshold):
                    all_conditions_met = False
                    break
            
            # If all conditions met, apply the action
            if all_conditions_met:
                adaptation_type = rule.adaptation_type
                action_value = action_config.get('value', action_config.get('rate_limit', 0))
                action_type = action_config.get('action_type', 'MULTIPLY')
                
                # Map adaptation_type to config field
                config_field_map = {
                    'adjust_rate_limit': 'rate_limit',
                    'change_concurrency': 'template_concurrency',
                    'adjust_timeout': 'timeout',
                }
                
                config_field = config_field_map.get(adaptation_type)
                
                if config_field and hasattr(adapted_config, config_field):
                    current_value = getattr(adapted_config, config_field)
                    
                    new_value = self._apply_action(current_value, action_type, action_value)
                    
                    # Ensure values don't go below minimums
                    if config_field in ['rate_limit', 'template_concurrency']:
                        new_value = max(1, int(new_value))
                    elif config_field == 'timeout':
                        new_value = max(5, int(new_value))
                    
                    # Set the new value on the adapted configuration
                    setattr(adapted_config, config_field, new_value)
                    
                    rules_applied.append({
                        'rule_name': rule.rule_name,
                        'adaptation_type': adaptation_type,
                        'field': config_field,
                        'old_value': current_value,
                        'new_value': new_value,
                    })
                    
                    logger.info(f"✅ RULE APPLIED: {rule.rule_name}. Changed {config_field} from {current_value} to {new_value}")
                    
                    # Record adaptation in session if possible
                    if hasattr(session, 'apply_adaptation'):
                        session.apply_adaptation(
                            adaptation_type,
                            f"Rule: {rule.rule_name}",
                            action_config
                        )
        
        if rules_applied:
            logger.info(f"Applied {len(rules_applied)} adaptation rules")
        else:
            logger.debug("No adaptation rules matched current conditions")
        
        return adapted_config
