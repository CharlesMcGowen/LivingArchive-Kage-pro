"""
Surge Database Integration
==========================
Database integration layer for scans and vulnerabilities.
"""

try:
    from .sqlalchemy_integration import surge_db, SurgeSQLAlchemyIntegration
    __all__ = ['surge_db', 'SurgeSQLAlchemyIntegration']
except ImportError:
    surge_db = None
    __all__ = []

