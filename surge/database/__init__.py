"""
Surge Database Integration
==========================
Database integration layer for scans and vulnerabilities.
Uses Django ORM exclusively.
"""

try:
    from .django_integration import surge_db, SurgeDatabaseIntegration
    __all__ = ['surge_db', 'SurgeDatabaseIntegration']
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Surge Django ORM integration not available: {e}")
    surge_db = None
    __all__ = []

