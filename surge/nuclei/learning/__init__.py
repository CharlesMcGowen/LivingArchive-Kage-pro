"""
Surge Nuclei Learning System
=============================

Adaptive Learning System (A.L.S.) for intelligent template prioritization
and real-time scan adaptation.

Author: EGO Revolution Team
Version: 3.0.0 - Adaptive Learning System
"""

from .template_scorer import TemplateScorer
from .rule_engine import AdaptationRuleEngine

__all__ = ['TemplateScorer', 'AdaptationRuleEngine']
