#!/usr/bin/env python3
"""
Python ctypes Memory Cleanup Verification
==========================================

Tests that Python properly handles C string memory returned from Go bridge.
Verifies no memory leaks occur when repeatedly calling bridge functions.
"""

import ctypes
import sys
import gc
import resource
from pathlib import Path

# Memory tracking helper
def get_memory_usage():
    """Get current memory usage in MB"""
    try:
        # Linux-specific
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return usage.ru_maxrss / 1024  # Convert KB to MB
    except:
        return 0

def test_ctypes_memory_cleanup():
    """Test that ctypes properly manages C string memory"""
    
    print("🧪 Testing Python ctypes Memory Cleanup")
    print("=" * 60)
    
    # Try to load bridge library
    bridge_paths = [
        Path(__file__).parent / 'libnuclei_bridge.so',
        Path(__file__).parent.parent.parent.parent / 'surge_nuclei_memory_bridge' / 'libnuclei_bridge.so',
    ]
    
    bridge_lib = None
    for bridge_path in bridge_paths:
        if bridge_path.exists():
            try:
                bridge_lib = ctypes.CDLL(str(bridge_path))
                print(f"✅ Loaded bridge from: {bridge_path}")
                break
            except Exception as e:
                print(f"⚠️  Could not load {bridge_path}: {e}")
    
    if not bridge_lib:
        print("❌ Bridge library not found - skipping memory test")
        print("   Compile bridge first using: ./build.sh")
        return False
    
    # Set up function signatures
    bridge_lib.InitializeBridge.restype = ctypes.c_char_p
    bridge_lib.StartScan.restype = ctypes.c_char_p
    bridge_lib.GetScanState.restype = ctypes.c_char_p
    bridge_lib.CleanupBridge.restype = ctypes.c_char_p
    
    print("\n📊 Memory Baseline:")
    initial_memory = get_memory_usage()
    print(f"   Initial memory: {initial_memory:.2f} MB")
    
    # Test 1: Initialize/cleanup cycle
    print("\n🔄 Test 1: Initialize/Cleanup Cycle (100 iterations)")
    for i in range(100):
        result = bridge_lib.InitializeBridge()
        if result:
            # Python ctypes should automatically handle the string
            result_str = result.decode('utf-8')
            bridge_lib.CleanupBridge()
        
        if i % 20 == 0:
            gc.collect()  # Force garbage collection
            current_memory = get_memory_usage()
            print(f"   Iteration {i}: {current_memory:.2f} MB")
    
    gc.collect()
    after_test1 = get_memory_usage()
    print(f"   After test 1: {after_test1:.2f} MB")
    print(f"   Memory delta: {after_test1 - initial_memory:.2f} MB")
    
    # Test 2: Multiple GetScanState calls
    print("\n🔄 Test 2: GetScanState Calls (1000 iterations)")
    bridge_lib.InitializeBridge()
    
    for i in range(1000):
        result = bridge_lib.GetScanState()
        if result:
            result_str = result.decode('utf-8')
        
        if i % 200 == 0:
            gc.collect()
            current_memory = get_memory_usage()
            print(f"   Iteration {i}: {current_memory:.2f} MB")
    
    gc.collect()
    after_test2 = get_memory_usage()
    print(f"   After test 2: {after_test2:.2f} MB")
    print(f"   Memory delta: {after_test2 - initial_memory:.2f} MB")
    
    bridge_lib.CleanupBridge()
    
    # Final check
    gc.collect()
    final_memory = get_memory_usage()
    print(f"\n📊 Final Memory: {final_memory:.2f} MB")
    print(f"   Total increase: {final_memory - initial_memory:.2f} MB")
    
    # Evaluation
    memory_increase = final_memory - initial_memory
    if memory_increase < 10:  # Less than 10MB increase is acceptable
        print("\n✅ Memory cleanup test PASSED")
        print(f"   Memory increase ({memory_increase:.2f} MB) is within acceptable range")
        return True
    else:
        print("\n⚠️  Memory cleanup test WARNING")
        print(f"   Memory increase ({memory_increase:.2f} MB) is higher than expected")
        print("   This may indicate memory leaks - investigate further")
        return False

if __name__ == "__main__":
    success = test_ctypes_memory_cleanup()
    sys.exit(0 if success else 1)

