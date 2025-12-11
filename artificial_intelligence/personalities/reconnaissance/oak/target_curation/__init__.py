#!/usr/bin/env python3
"""
Oak Target Curation Module
===========================

Oak's target curation and intelligence coordination service.
Enriches targets with technology fingerprinting, CVE correlation, and priority scoring.

Author: EGO Revolution Team - Oak
Version: 1.0.0
"""

from .target_curation_service import OakTargetCurationService
# Optional import - autonomous service requires Bugsy which may not be available
try:
from .autonomous_curation_service import OakAutonomousCurationService, get_instance
except (ImportError, ModuleNotFoundError):
    # Bugsy services not available - autonomous curation disabled
    OakAutonomousCurationService = None
    get_instance = None

__all__ = [
    'OakTargetCurationService',
    'OakAutonomousCurationService',
    'get_instance',
]

