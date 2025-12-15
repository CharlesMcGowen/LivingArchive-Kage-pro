#!/usr/bin/env python3
"""
DEPRECATED: Surge SQLAlchemy Database Integration
=================================================

This file is DEPRECATED and kept only for reference.
All functionality has been migrated to Django ORM.

See: surge/database/django_integration.py for the current implementation.

This file will be removed in a future version.
"""

import logging

logger = logging.getLogger(__name__)
logger.warning(
    "⚠️  surge/database/sqlalchemy_integration.py is DEPRECATED. "
    "Please use surge/database/django_integration.py instead. "
    "This file will be removed in a future version."
)

# Raise ImportError to prevent usage
raise ImportError(
    "SQLAlchemy integration has been removed. "
    "Please use surge/database/django_integration.py (Django ORM) instead."
)
