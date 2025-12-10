#!/usr/bin/env python3
"""
Create Ash Learning Tables
==========================

Creates the learning database tables for Ash's WAF bypass and technique learning.
Uses SQLAlchemy to create tables in PostgreSQL.
"""

import sys
import os

sys.path.insert(0, '/mnt/webapps-nvme')

# Setup Django (for database connection)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EgoQT.src.django_bridge.settings')
import django
django.setup()

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import models
from artificial_intelligence.personalities.reconnaissance.ash.scan_learning_models import (
    Base,
    TechniqueEffectiveness,
    WAFDetection,
    ScanResult
)

# Database connection
engine = None
try:
    from EgoQT.src.database import init_database, get_SessionLocal, get_engine
    init_database()
    SessionLocal = get_SessionLocal()
    try:
        engine = get_engine()
    except:
        pass
except ImportError:
    pass

if not engine:
    import os
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Get database URL
    db_user = os.getenv('DB_USER', 'postgres')
    db_password = os.getenv('DB_PASSWORD', 'postgres')
    db_host = os.getenv('DB_HOST', 'localhost')
    db_port = os.getenv('DB_PORT', '5436')
    db_name = os.getenv('EGG_DB_NAME', 'ego')
    
    database_url = f'postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
    engine = create_engine(database_url, pool_pre_ping=True)
    if 'SessionLocal' not in locals():
        SessionLocal = sessionmaker(bind=engine)


def create_tables():
    """Create all learning tables."""
    print("Creating Ash learning tables...")
    
    try:
        # Create all tables
        Base.metadata.create_all(engine)
        print("✅ Tables created successfully!")
        print("  - ash_technique_effectiveness")
        print("  - ash_waf_detections")
        print("  - ash_scan_results")
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        raise


if __name__ == '__main__':
    create_tables()

