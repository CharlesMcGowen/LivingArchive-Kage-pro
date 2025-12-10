#!/usr/bin/env python3
"""
Network Analysis Tool for ASN-based IP Networks
================================================

Demonstrates the full capabilities of the IP ownership validator:
- ASN to CIDR block aggregation
- Network object construction
- Supernetting for firewall rule optimization
- Company network mapping

Author: EGO Revolution
Version: 1.0.0
"""

import sys
from pathlib import Path

# Add workspace root to path
workspace_root = Path(__file__).parent.parent.parent.parent
if str(workspace_root) not in sys.path:
    sys.path.insert(0, str(workspace_root))

# Setup Django for imports
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EgoQT.src.django_bridge.settings')
import django
django.setup()

from artificial_intelligence.personalities.reconnaissance.ash.ip_ownership_validator import (
    get_ip_validator,
    ASN_TO_COMPANY
)


def analyze_company_networks():
    """Build and analyze network objects for all known companies"""
    validator = get_ip_validator()
    
    print("🏢 Company Network Analysis")
    print("=" * 80)
    print()
    
    networks = validator.get_all_company_networks()
    
    for company_name, network_data in networks.items():
        asn = network_data['asn']
        network_obj = network_data['network']
        company_info = network_data['company_info']
        
        if 'error' in network_obj:
            print(f"❌ {company_name} (AS{asn}): {network_obj['error']}")
            continue
        
        cidr_count = len(network_obj.get('cidr_blocks', []))
        total_ips = network_obj.get('total_ips', 0)
        aggregated = network_obj.get('aggregated', False)
        
        print(f"✅ {company_name} (AS{asn})")
        print(f"   Type: {company_info.get('type', 'unknown')}")
        print(f"   CIDR Blocks: {cidr_count}")
        if network_obj.get('original_count'):
            reduction = network_obj['reduction']
            reduction_pct = (reduction / network_obj['original_count']) * 100
            print(f"   Aggregation: {network_obj['original_count']} → {network_obj['aggregated_count']} blocks ({reduction} merged, {reduction_pct:.1f}% reduction)")
        print(f"   Total IPs: {total_ips:,}")
        print(f"   Port Expectations: {company_info.get('port_expectations', 'standard')}")
        if company_info.get('common_ports'):
            print(f"   Common Ports: {company_info['common_ports']}")
        print()


def demonstrate_port_filtering():
    """Demonstrate port filtering based on IP ownership"""
    validator = get_ip_validator()
    
    print("🔍 Port Filtering Demonstration")
    print("=" * 80)
    print()
    
    test_cases = [
        ('1.1.1.1', [22, 80, 443, 8080, 8443, 3306, 5432], 'Cloudflare DNS'),
        ('8.8.8.8', [22, 80, 443, 8080, 8443, 3306, 5432], 'Google DNS'),
        ('52.84.0.0', [22, 80, 443, 8080, 8443, 3306, 5432], 'AWS IP'),
    ]
    
    for ip, ports, description in test_cases:
        ownership = validator.validate_ip_ownership(ip)
        filtered = validator.filter_ports_by_ownership(ip, ports)
        
        print(f"IP: {ip} ({description})")
        print(f"  Owned by: {ownership.get('owned_by', 'unknown')}")
        print(f"  ASN: {ownership.get('asn', 'N/A')}")
        print(f"  Port expectations: {ownership.get('port_expectations', 'standard')}")
        print(f"  Original ports: {ports}")
        print(f"  Filtered ports: {filtered}")
        if len(filtered) < len(ports):
            removed = [p for p in ports if p not in filtered]
            print(f"  Removed: {removed} (not proxied/expected)")
        print()


def demonstrate_skip_logic():
    """Demonstrate skip logic for infrastructure IPs"""
    validator = get_ip_validator()
    
    print("⏭️  Skip Logic Demonstration")
    print("=" * 80)
    print()
    
    test_ips = [
        ('1.1.1.1', 'Cloudflare DNS'),
        ('8.8.8.8', 'Google DNS'),
        ('127.0.0.1', 'Localhost'),
    ]
    
    for ip, description in test_ips:
        should_skip, reason = validator.should_skip_scan(ip)
        ownership = validator.validate_ip_ownership(ip)
        
        print(f"IP: {ip} ({description})")
        print(f"  Owned by: {ownership.get('owned_by', 'unknown')}")
        print(f"  Skip scan: {'✅ YES' if should_skip else '❌ NO'}")
        if should_skip:
            print(f"  Reason: {reason}")
        print()


if __name__ == '__main__':
    print("🌐 ASN-based Network Analysis Tool")
    print("=" * 80)
    print()
    
    # Run demonstrations
    analyze_company_networks()
    demonstrate_port_filtering()
    demonstrate_skip_logic()
    
    print("✅ Analysis complete!")

