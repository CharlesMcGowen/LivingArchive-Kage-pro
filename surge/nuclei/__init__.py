"""
Surge Nuclei Integration - Unified API
======================================

Unified Nuclei integration for all agents (Surge, Koga, Bugsy).
All agents can import from this module to access the class-based Nuclei API.

Usage:
    from surge.nuclei import NucleiEngine, AdaptiveNucleiEngine, ScanConfig, Severity
    from surge.nuclei import ConcurrentNucleiManager, ThreadSafeNucleiEngine
    
    # For any agent
    engine = NucleiEngine(config=ScanConfig(use_thread_safe=True))
    scan_id = engine.scan(["https://target.com"])
"""

# Core API - Class-based Nuclei engine
from .class_based_api import (
    NucleiEngine,
    AdaptiveNucleiEngine,
    ScanConfig,
    ScanStatus,
    Severity,
    VulnerabilityFinding,
    ScanProgress,
)

# Concurrent scanning support
from .concurrent_engine import (
    ConcurrentNucleiManager,
    ThreadSafeNucleiEngine,
    EnginePoolConfig,
)

# Learning system
from .learning import (
    TemplateScorer,
    AdaptationRuleEngine,
)

# Legacy integration (for backwards compatibility)
from .integration import SurgeNucleiIntegration

__all__ = [
    # Core API
    'NucleiEngine',
    'AdaptiveNucleiEngine',
    'ScanConfig',
    'ScanStatus',
    'Severity',
    'VulnerabilityFinding',
    'ScanProgress',
    
    # Concurrent scanning
    'ConcurrentNucleiManager',
    'ThreadSafeNucleiEngine',
    'EnginePoolConfig',
    
    # Learning system
    'TemplateScorer',
    'AdaptationRuleEngine',
    
    # Legacy
    'SurgeNucleiIntegration',
]

# Convenience function for agent initialization
def create_nuclei_engine(config: ScanConfig = None, use_adaptive: bool = False, use_thread_safe: bool = True):
    """
    Create a Nuclei engine instance for any agent.
    
    Args:
        config: Optional ScanConfig (defaults created if None)
        use_adaptive: Use AdaptiveNucleiEngine with learning system
        use_thread_safe: Use thread-safe engine for concurrent scans
        
    Returns:
        NucleiEngine or AdaptiveNucleiEngine instance
    """
    if config is None:
        config = ScanConfig(use_thread_safe=use_thread_safe)
    else:
        config.use_thread_safe = use_thread_safe
    
    if use_adaptive:
        return AdaptiveNucleiEngine(config=config)
    else:
        return NucleiEngine(config=config)

__all__.append('create_nuclei_engine')

