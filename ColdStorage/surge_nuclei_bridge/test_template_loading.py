#!/usr/bin/env python3
"""Test template loading after container restart"""
import sys
import ctypes
import json
import time

def main():
    print("🧪 Testing Template Loading After Container Restart")
    print("=" * 60)
    
    try:
        bridge = ctypes.CDLL('/app/artificial_intelligence/personalities/security/surge/surge_nuclei_memory_bridge/libnuclei_bridge.so')
        bridge.InitializeBridge.restype = ctypes.c_char_p
        bridge.StartScan.restype = ctypes.c_char_p
        bridge.GetScanState.restype = ctypes.c_char_p
        
        print("\n1. InitializeBridge...")
        r = bridge.InitializeBridge()
        result = json.loads(r.decode())
        print(f"   ✅ {result.get('message')}")
        
        if not result.get('success'):
            print("   ❌ Failed to initialize")
            return 1
        
        print("\n2. StartScan on testphp.vulnweb.com...")
        r = bridge.StartScan(ctypes.c_char_p(b'http://testphp.vulnweb.com'), ctypes.c_char_p(b'{}'))
        result = json.loads(r.decode())
        print(f"   Success: {result.get('success')}")
        print(f"   Scan ID: {result.get('scan_id')}")
        
        if not result.get('success'):
            print("   ❌ Failed to start scan")
            return 1
        
        print("\n3. Monitoring scan (20 seconds)...")
        print("   Time | Running | Requests | Vulns")
        print("   " + "-" * 40)
        
        for i in range(20):
            time.sleep(1)
            s = json.loads(bridge.GetScanState().decode())
            running = "✓" if s.get('is_running') else "✗"
            requests = s.get('total_requests', 0)
            vulns_found = s.get('vulns_found')
            vulns = len(vulns_found) if vulns_found else 0
            print(f"   {i+1:2d}s |   {running}    |   {requests:3d}   |  {vulns:2d}")
            
            if vulns > 0:
                print(f"\n   ✅ Found {vulns} vulnerabilities!")
                for v in s['vulns_found'][:3]:
                    tid = v.get('template_id', 'N/A')
                    print(f"      - {tid}")
            
            if not s.get('is_running') and i > 5:
                break
        
        s = json.loads(bridge.GetScanState().decode())
        print("\n4. Final Results:")
        print(f"   Total Requests: {s.get('total_requests')}")
        vulns_found = s.get('vulns_found')
        vuln_count = len(vulns_found) if vulns_found else 0
        print(f"   Vulnerabilities Found: {vuln_count}")
        
        if vulns_found:
            print("   ✅ SCAN SUCCESSFUL - Vulnerabilities detected!")
        else:
            print("   ⚠️  No vulnerabilities found (may be normal)")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())

