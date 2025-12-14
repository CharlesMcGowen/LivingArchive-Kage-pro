#!/usr/bin/env python3
"""
Quick test script to verify vector store setup
"""
import os
import sys
from pathlib import Path

# Add Onumpy to path
onumpy_path = Path('/home/ego/github_public/Onumpy')
if str(onumpy_path) not in sys.path:
    sys.path.insert(0, str(onumpy_path))

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ryu_project.settings')
import django
django.setup()

import logging
logging.basicConfig(level=logging.INFO)

print("🔍 Testing Vector Path Store Setup...\n")

# Test 1: Check imports
print("1. Checking dependencies...")
try:
    from suzu.vector_path_store import VectorPathStore
    print("   ✅ VectorPathStore import successful")
except ImportError as e:
    print(f"   ❌ Import failed: {e}")
    print("   💡 Install dependencies: pip install qdrant-client sentence-transformers numpy")
    sys.exit(1)

# Test 2: Initialize vector store
print("\n2. Initializing vector store...")
try:
    # Try to connect to Qdrant
    vector_store = VectorPathStore(vector_db_type="qdrant")
    print("   ✅ Vector store initialized")
except Exception as e:
    print(f"   ⚠️  Vector store initialization failed: {e}")
    print("   💡 Make sure Qdrant is running: docker compose up -d qdrant")
    print("   💡 Or set QDRANT_HOST and QDRANT_PORT environment variables")
    
    # Try Chroma as fallback
    try:
        print("\n   Trying ChromaDB as fallback...")
        vector_store = VectorPathStore(vector_db_type="chroma")
        print("   ✅ ChromaDB initialized successfully")
    except Exception as e2:
        print(f"   ❌ ChromaDB also failed: {e2}")
        sys.exit(1)

# Test 3: Upload test paths
print("\n3. Testing path upload...")
test_paths = [
    "/wp-admin/",
    "/wp-content/",
    "/wp-config.php",
    "/admin/",
    "/api/v1/users"
]

try:
    result = vector_store.upload_paths(
        paths=test_paths,
        wordlist_name="test_wordlist.txt",
        cms_name="wordpress",
        default_weight=0.5,
        source="test"
    )
    print(f"   ✅ Uploaded {result['uploaded']} test paths")
    print(f"   📊 Collection: {result['collection']}, Dimension: {result['total_dim']}")
except Exception as e:
    print(f"   ⚠️  Upload failed: {e}")

# Test 4: Query similar paths
print("\n4. Testing similarity search...")
try:
    similar = vector_store.find_similar_paths(
        query_path="/wp-admin/",
        cms_name="wordpress",
        limit=5,
        threshold=0.5
    )
    print(f"   ✅ Found {len(similar)} similar paths")
    for item in similar[:3]:
        print(f"      - {item['path']} (similarity: {item['similarity']:.2f}, weight: {item['weight']:.2f})")
except Exception as e:
    print(f"   ⚠️  Similarity search failed: {e}")

# Test 5: Get weighted paths
print("\n5. Testing weighted path retrieval...")
try:
    weighted = vector_store.get_weighted_paths(
        cms_name="wordpress",
        limit=10,
        min_weight=0.2
    )
    print(f"   ✅ Retrieved {len(weighted)} weighted paths")
    for item in weighted[:5]:
        print(f"      - {item['path']} (weight: {item['weight']:.2f})")
except Exception as e:
    print(f"   ⚠️  Weighted path retrieval failed: {e}")

print("\n✅ Vector store test complete!")

