"""
Customer Eggs EggRecords General Models
======================================

Customer data models for template effectiveness tracking.
Provides models for security template effectiveness and usage analytics.

Author: EGO Revolution Team
Date: 2025-01-27
"""

# Lazy imports to avoid Django app registry issues
# Import Django models only when needed, not at module level
__all__ = [
    'TemplateEffectiveness',
    'TemplateUsage', 
    'EffectivenessMetrics'
]

def __getattr__(name):
    """Lazy import for Django models"""
    if name in __all__:
        from .core_models.template_effectiveness_models import (
            TemplateEffectiveness,
            TemplateUsage,
            EffectivenessMetrics
        )
        # Cache the imported names in globals
        globals()['TemplateEffectiveness'] = TemplateEffectiveness
        globals()['TemplateUsage'] = TemplateUsage
        globals()['EffectivenessMetrics'] = EffectivenessMetrics
        return globals().get(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
