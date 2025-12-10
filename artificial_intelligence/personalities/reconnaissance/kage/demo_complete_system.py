#!/usr/bin/env python3
"""
Complete System Demonstration
==============================

Demonstrates all features of the enhanced IP ownership system:
1. IPv4/IPv6 ASN lookups
2. CIDR aggregation (supernetting)
3. BGP real-time lookups
4. Firewall rule generation
5. Company blocklists

Run: python demo_complete_system.py
"""

import sys
import os
from pathlib import Path

# Add workspace root
workspace_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(workspace_root))

# Try to setup Django (optional - only needed for full functionality)
try:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EgoQT.src.django_bridge.settings')
    import django
    django.setup()
    django_available = True
except Exception as e:
    django_available = False
    print(f"⚠️  Django not available (some features may be limited): {e}\n")

from netaddr import cidr_merge

# Import validators (may fail if Django not available)
try:
    from artificial_intelligence.personalities.reconnaissance.ash.ip_ownership_validator import get_ip_validator
    validator_available = True
except Exception as e:
    validator_available = False
    print(f"⚠️  Validator not available: {e}\n")

try:
    from artificial_intelligence.personalities.reconnaissance.ash.firewall_rule_generator import get_firewall_generator
    firewall_available = True
except Exception as e:
    firewall_available = False
    print(f"⚠️  Firewall generator not available: {e}\n")


def demo_supernetting():
    """Demonstrate CIDR aggregation (supernetting)"""
    print("\n" + "=" * 70)
    print("🔧 Part 1: CIDR Aggregation (Supernetting)")
    print("=" * 70)
    
    # Example: Contiguous CIDR blocks that can be aggregated
    cidr_list = [
        '192.168.0.0/24',
        '192.168.1.0/24',
        '10.0.1.0/24',
        '10.0.2.0/24',
        '10.0.3.0/24',
        '10.0.4.0/24',
        '10.0.5.0/24',
        '10.0.6.0/24',
        '10.0.7.0/24',
        '10.0.8.0/24',
        '172.16.1.0/24',
        '172.16.2.0/24',
    ]
    
    print(f"\n📊 Original CIDR Blocks ({len(cidr_list)} entries):")
    for cidr in cidr_list:
        print(f"   {cidr}")
    
    # Aggregate using netaddr
    aggregated = cidr_merge(cidr_list)
    
    print(f"\n✅ Aggregated (Supernetted) CIDR Blocks ({len(aggregated)} entries):")
    for cidr in aggregated:
        print(f"   {cidr}")
    
    reduction = len(cidr_list) - len(aggregated)
    reduction_pct = (reduction / len(cidr_list) * 100) if cidr_list else 0
    
    print(f"\n📈 Optimization Results:")
    print(f"   Original: {len(cidr_list)} blocks")
    print(f"   Aggregated: {len(aggregated)} blocks")
    print(f"   Reduction: {reduction} blocks ({reduction_pct:.1f}%)")
    print(f"   → This saves {reduction} firewall rules!")


def demo_ipv6():
    """Demonstrate IPv6 support"""
    print("\n" + "=" * 70)
    print("🌐 Part 2: IPv6 CIDR Notation & Support")
    print("=" * 70)
    
    if not validator_available:
        print("\n⚠️  Validator not available - showing conceptual examples only")
        validator = None
    else:
        validator = get_ip_validator()
    
    # IPv6 test addresses
    test_ips = [
        ('2001:4860:4860::8888', 'Google DNS IPv6'),
        ('2606:4700:4700::1111', 'Cloudflare DNS IPv6'),
        ('2001:4860::/32', 'Google IPv6 block'),
        ('2606:4700::/32', 'Cloudflare IPv6 block'),
    ]
    
    print("\n📋 IPv6 Address Examples:")
    for ip, description in test_ips:
        print(f"\n   {description}:")
        print(f"   Address: {ip}")
        
        # Check if it's a network or address
        if '/' in ip:
            print(f"   Type: IPv6 Network (CIDR)")
            print(f"   Prefix: /{ip.split('/')[1]}")
        else:
            print(f"   Type: IPv6 Address")
            if validator:
                result = validator.validate_ip_ownership(ip)
                print(f"   IP Version: {result.get('ip_version', 'unknown')}")
                print(f"   Owned by: {result.get('owned_by', 'unknown')}")
            else:
                print(f"   (Validation requires validator)")
    
    print("\n📊 IPv6 CIDR Prefix Sizes:")
    print("   /32  → Large allocation (RIRs, major ISPs)")
    print("   /48  → Corporate site allocation (65,536 /64 subnets)")
    print("   /64  → Standard subnet size (LAN)")
    print("   /128 → Single host address")


def demo_bgp_lookup():
    """Demonstrate BGP real-time lookups"""
    print("\n" + "=" * 70)
    print("📡 Part 3: Real-time BGP Lookups")
    print("=" * 70)
    
    try:
        from artificial_intelligence.personalities.reconnaissance.ash.bgp_lookup_service import get_bgp_lookup_service
        
        bgp = get_bgp_lookup_service()
        
        print("\n✅ BGP Lookup Service Features:")
        print("   - Real-time ASN lookups via BGPView API")
        print("   - ASN information (name, description, prefixes)")
        print("   - Prefix lists (IPv4 and IPv6)")
        print("   - Caching (1 hour TTL)")
        print("   - Fallback to local database")
        
        print("\n💡 Usage Example:")
        print("   bgp = get_bgp_lookup_service()")
        print("   result = bgp.lookup_ip('1.1.1.1')")
        print("   # Returns: ASN, prefix, country, RIR, etc.")
        
        print("\n📊 API Endpoints:")
        print("   - BGPView: https://api.bgpview.io")
        print("   - Hurricane Electric: https://bgp.he.net (manual)")
        print("   - RIPEstat: https://stat.ripe.net (RIPE)")
        
    except Exception as e:
        print(f"\n⚠️  BGP service not available: {e}")


def demo_firewall_rules():
    """Demonstrate firewall rule generation"""
    print("\n" + "=" * 70)
    print("🔥 Part 4: Firewall Rule Generation")
    print("=" * 70)
    
    if not firewall_available:
        print("\n⚠️  Firewall generator not available - showing conceptual examples only")
        fw = None
    else:
        fw = get_firewall_generator()
    
    if fw:
        print("\n✅ Supported Firewall Formats:")
        for fmt in fw.supported_formats:
            print(f"   - {fmt}")
    else:
        print("\n✅ Supported Firewall Formats:")
        print("   - iptables")
        print("   - nftables")
        print("   - pfsense")
        print("   - ufw")
        print("   - raw_cidr")
    
    # Example: Generate rules for a hypothetical ASN
    print("\n💡 Example: Generate iptables rules")
    print("   fw = get_firewall_generator()")
    print("   rules = fw.generate_rules_for_asn(")
    print("       asn=13335,  # Cloudflare")
    print("       action='DROP',")
    print("       format='iptables',")
    print("       chain='INPUT'")
    print("   )")
    
    # Example: Company blocklist
    print("\n💡 Example: Generate company blocklist")
    print("   blocklist = fw.generate_company_blocklist(")
    print("       company_names=['Cloudflare', 'AWS'],")
    print("       action='DROP',")
    print("       format='iptables'")
    print("   )")
    
    # Show supernetting benefit
    print("\n📊 Supernetting Benefits for Firewalls:")
    print("   - Reduces rule count (faster processing)")
    print("   - Lower memory usage")
    print("   - Easier maintenance")
    print("   - Better performance on hardware firewalls")


def demo_complete_workflow():
    """Demonstrate complete workflow"""
    print("\n" + "=" * 70)
    print("🎯 Part 5: Complete Workflow Example")
    print("=" * 70)
    
    if validator_available:
        validator = get_ip_validator()
    else:
        validator = None
    
    if firewall_available:
        fw = get_firewall_generator()
    else:
        fw = None
    
    print("\n📋 Scenario: Block all Cloudflare IPs in firewall")
    print("\n1️⃣  Identify Cloudflare ASN:")
    print("   ASN: 13335 (Cloudflare)")
    
    print("\n2️⃣  Build network object (with supernetting):")
    print("   network = validator.build_network_object(13335)")
    print("   # Returns aggregated CIDR blocks")
    
    print("\n3️⃣  Generate firewall rules:")
    print("   rules = fw.generate_rules_for_asn(")
    print("       asn=13335,")
    print("       action='DROP',")
    print("       format='iptables'")
    print("   )")
    
    print("\n4️⃣  Apply rules:")
    print("   for rule in rules:")
    print("       os.system(rule)")
    
    print("\n✅ Result: All Cloudflare IPs blocked with minimal rules!")


def main():
    """Run all demonstrations"""
    print("\n" + "🚀" * 35)
    print("Enhanced IP Ownership System - Complete Demonstration")
    print("🚀" * 35)
    
    demo_supernetting()
    demo_ipv6()
    demo_bgp_lookup()
    demo_firewall_rules()
    demo_complete_workflow()
    
    print("\n" + "=" * 70)
    print("✅ Demonstration Complete!")
    print("=" * 70)
    print("\n📚 Key Takeaways:")
    print("   1. Supernetting reduces firewall rules by 40%+")
    print("   2. IPv6 support enables future-proof network management")
    print("   3. BGP lookups provide real-time routing information")
    print("   4. Firewall rules can be generated automatically")
    print("   5. Company blocklists simplify security policies")
    print()


if __name__ == '__main__':
    main()

