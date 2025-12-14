#!/usr/bin/env python3
"""
Diagnose Onumpy import issues
"""
import sys
import os
from pathlib import Path
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

print("=" * 60)
print("Onumpy Import Diagnostic")
print("=" * 60)

# Step 1: Check path
onumpy_path = Path('/home/ego/github_public/Onumpy').resolve()
print(f"\n1. Onumpy Path: {onumpy_path}")
print(f"   Exists: {onumpy_path.exists()}")
print(f"   Is dir: {onumpy_path.is_dir() if onumpy_path.exists() else False}")

# Step 2: Check numpy_bridge.py
numpy_bridge = onumpy_path / 'numpy_bridge.py'
print(f"\n2. numpy_bridge.py: {numpy_bridge}")
print(f"   Exists: {numpy_bridge.exists()}")

# Step 3: Add to path
onumpy_str = str(onumpy_path)
if onumpy_str not in sys.path:
    sys.path.insert(0, onumpy_str)
    print(f"\n3. Added to sys.path: {onumpy_str}")
else:
    print(f"\n3. Already in sys.path at index: {sys.path.index(onumpy_str)}")

# Step 4: Try importing
print(f"\n4. Attempting import...")
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("numpy_bridge", numpy_bridge)
    if spec is None:
        print("   ❌ Could not create spec from file")
    else:
        print(f"   ✅ Spec created: {spec}")
        print(f"   Module name: {spec.name}")
        print(f"   Loader: {spec.loader}")
        
        # Try loading
        module = importlib.util.module_from_spec(spec)
        print(f"   ✅ Module object created")
        
        # Try executing
        spec.loader.exec_module(module)
        print(f"   ✅ Module executed")
        
        # Check for np
        if hasattr(module, 'np'):
            np = module.np
            print(f"   ✅ Found np: {type(np)}")
            print(f"   GPU Available: {getattr(np, 'GPU_AVAILABLE', 'N/A')}")
        else:
            print(f"   ⚠️  Module doesn't have 'np' attribute")
            print(f"   Attributes: {[a for a in dir(module) if not a.startswith('_')][:10]}")
            
except Exception as e:
    print(f"   ❌ Import failed: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

# Step 5: Try standard import
print(f"\n5. Trying standard import...")
try:
    from numpy_bridge import np
    print(f"   ✅ Standard import worked!")
    print(f"   Type: {type(np)}")
    print(f"   GPU Available: {getattr(np, 'GPU_AVAILABLE', 'N/A')}")
except Exception as e:
    print(f"   ❌ Standard import failed: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)

