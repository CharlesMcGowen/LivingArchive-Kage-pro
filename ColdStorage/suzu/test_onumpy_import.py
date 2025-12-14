#!/usr/bin/env python3
"""
Test script to diagnose Onumpy import issues
"""
import sys
import os
from pathlib import Path

print("🔍 Testing Onumpy Import...\n")

# Test 1: Check if Onumpy directory exists
print("1. Checking Onumpy directory...")
onumpy_path = Path('/home/ego/github_public/Onumpy').resolve()
print(f"   Path: {onumpy_path}")
print(f"   Exists: {onumpy_path.exists()}")
print(f"   Is directory: {onumpy_path.is_dir() if onumpy_path.exists() else False}")

# Test 2: Check if numpy_bridge.py exists
print("\n2. Checking numpy_bridge.py...")
numpy_bridge_file = onumpy_path / 'numpy_bridge.py'
print(f"   Path: {numpy_bridge_file}")
print(f"   Exists: {numpy_bridge_file.exists()}")

# Test 3: Check sys.path
print("\n3. Current sys.path (first 5 entries):")
for i, path in enumerate(sys.path[:5]):
    print(f"   [{i}] {path}")

# Test 4: Try adding to path and importing
print("\n4. Testing import...")
try:
    onumpy_str = str(onumpy_path)
    if onumpy_str not in sys.path:
        sys.path.insert(0, onumpy_str)
        print(f"   ✅ Added to sys.path: {onumpy_str}")
    else:
        print(f"   ℹ️  Already in sys.path")
    
    # Try importing
    from numpy_bridge import np
    print(f"   ✅ Import successful!")
    print(f"   Type: {type(np)}")
    print(f"   Has GPU_AVAILABLE: {hasattr(np, 'GPU_AVAILABLE')}")
    if hasattr(np, 'GPU_AVAILABLE'):
        print(f"   GPU Available: {np.GPU_AVAILABLE}")
    if hasattr(np, 'CUSTOM_NUMPY_AVAILABLE'):
        print(f"   Custom NumPy Available: {np.CUSTOM_NUMPY_AVAILABLE}")
    
except ImportError as e:
    print(f"   ❌ Import failed: {e}")
    print(f"   Error type: {type(e).__name__}")
    import traceback
    traceback.print_exc()
except Exception as e:
    print(f"   ❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()

# Test 5: Check if standard numpy works
print("\n5. Testing standard numpy fallback...")
try:
    import numpy as np_std
    print(f"   ✅ Standard numpy works: {np_std.__version__}")
except Exception as e:
    print(f"   ❌ Standard numpy also failed: {e}")

print("\n✅ Test complete!")

