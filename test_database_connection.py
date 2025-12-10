#!/usr/bin/env python
"""
Test script to verify database connections for LivingArchive-Kage-pro
Connects to the same databases as the port 9000 Django server
"""
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables from setup script or .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Set environment variables if not already set (for testing)
if not os.environ.get('DB_HOST'):
    os.environ['DB_HOST'] = 'localhost'
    os.environ['DB_USER'] = 'postgres'
    os.environ['DB_PASSWORD'] = 'postgres'
    os.environ['CUSTOMER_EGGS_DB_NAME'] = 'customer_eggs'
    os.environ['CUSTOMER_EGGS_DB_PORT'] = '15440'
    os.environ['EGG_DB_NAME'] = 'ego'
    os.environ['EGG_DB_PORT'] = '5436'

django.setup()

from django.db import connections

def test_connection(db_name, description):
    """Test a database connection"""
    try:
        conn = connections[db_name]
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print(f"✅ {description}")
        print(f"   Database: {db_name}")
        print(f"   PostgreSQL version: {version.split(',')[0]}")
        
        # Test querying a table if it exists
        try:
            if db_name == 'customer_eggs':
                cursor.execute("SELECT COUNT(*) FROM customer_eggs_eggrecords_general_models_eggrecord LIMIT 1;")
                count = cursor.fetchone()[0]
                print(f"   EggRecords found: {count}")
            elif db_name == 'eggrecords':
                # Check for technology_fingerprints table
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = 'technology_fingerprints'
                    )
                """)
                table_exists = cursor.fetchone()[0]
                if table_exists:
                    cursor.execute("SELECT COUNT(*) FROM technology_fingerprints LIMIT 1;")
                    count = cursor.fetchone()[0]
                    print(f"   Technology fingerprints found: {count}")
                else:
                    print(f"   Note: technology_fingerprints table not found (may need to run migrations)")
        except Exception as e:
            print(f"   Note: Could not query tables: {e}")
        
        return True
    except Exception as e:
        print(f"❌ {description} - Connection failed!")
        print(f"   Error: {e}")
        return False

if __name__ == '__main__':
    print("=" * 60)
    print("Database Connection Test")
    print("=" * 60)
    print()
    
    print("Testing connections to port 9000 server databases...")
    print()
    
    # Test customer_eggs connection
    customer_eggs_ok = test_connection('customer_eggs', 'Customer Eggs Database')
    print()
    
    # Test eggrecords connection
    eggrecords_ok = test_connection('eggrecords', 'EggRecords Database')
    print()
    
    print("=" * 60)
    if customer_eggs_ok and eggrecords_ok:
        print("✅ All database connections successful!")
        print()
        print("You can now run the Django server:")
        print("  python manage.py runserver")
    else:
        print("❌ Some connections failed. Please check:")
        print("  1. Docker containers are running")
        print("  2. Environment variables are set correctly")
        print("  3. Database credentials are correct")
    print("=" * 60)

