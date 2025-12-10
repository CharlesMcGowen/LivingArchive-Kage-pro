#!/usr/bin/env python3
"""
Test BGP Lookups and Generate Firewall Rules
=============================================

Tests:
1. Real BGP API lookups
2. Firewall rule generation for specific companies
3. IPv6 ASN prefix retrieval

Run: python test_bgp_and_firewall.py
"""

import sys
import os
from pathlib import Path

# Add workspace root
workspace_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(workspace_root))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'EgoQT.src.django_bridge.settings')
import django
django.setup()

from artificial_intelligence.personalities.reconnaissance.ash.bgp_lookup_service import get_bgp_lookup_service
from artificial_intelligence.personalities.reconnaissance.ash.firewall_rule_generator import get_firewall_generator
from artificial_intelligence.personalities.reconnaissance.ash.ipv6_asn_retriever import get_ipv6_asn_retriever


def test_bgp_lookups():
    """Test real BGP API lookups"""
    print("\n" + "=" * 70)
    print("📡 Part 1: Testing Real BGP API Lookups")
    print("=" * 70)
    
    bgp = get_bgp_lookup_service()
    
    # Test IPs
    test_ips = [
        ("1.1.1.1", "Cloudflare DNS"),
        ("8.8.8.8", "Google DNS"),
        ("208.67.222.222", "OpenDNS"),
    ]
    
    print("\n🔍 Testing IP → ASN Lookups:")
    for ip, description in test_ips:
        print(f"\n  IP: {ip} ({description})")
        result = bgp.lookup_ip(ip)
        
        if result.get('error'):
            print(f"    ❌ Error: {result['error']}")
        else:
            print(f"    ✅ ASN: {result.get('asn', 'N/A')}")
            print(f"    ✅ Prefix: {result.get('prefix', 'N/A')}")
            print(f"    ✅ Country: {result.get('country', 'N/A')}")
            print(f"    ✅ Source: {result.get('source', 'N/A')}")
    
    # Test ASN lookups
    print("\n\n🔍 Testing ASN → Information Lookups:")
    test_asns = [
        (13335, "Cloudflare"),
        (15169, "Google"),
        (36692, "OpenDNS"),
    ]
    
    for asn, name in test_asns:
        print(f"\n  ASN: AS{asn} ({name})")
        result = bgp.lookup_asn(asn)
        
        if result.get('error'):
            print(f"    ❌ Error: {result['error']}")
        else:
            print(f"    ✅ Name: {result.get('name', 'N/A')}")
            print(f"    ✅ Description: {result.get('description', 'N/A')}")
            print(f"    ✅ Country: {result.get('country', 'N/A')}")
            print(f"    ✅ IPv4 Prefixes: {len(result.get('prefixes_ipv4', []))}")
            print(f"    ✅ IPv6 Prefixes: {len(result.get('prefixes_ipv6', []))}")
            
            # Show sample prefixes
            if result.get('prefixes_ipv4'):
                print(f"    Sample IPv4: {result['prefixes_ipv4'][:3]}")
            if result.get('prefixes_ipv6'):
                print(f"    Sample IPv6: {result['prefixes_ipv6'][:3]}")


def test_ipv6_asn_retrieval():
    """Test IPv6 ASN prefix retrieval"""
    print("\n" + "=" * 70)
    print("🌐 Part 2: Testing IPv6 ASN Prefix Retrieval")
    print("=" * 70)
    
    retriever = get_ipv6_asn_retriever()
    
    # Test Cloudflare (AS13335)
    print("\n📋 Cloudflare IPv6 Prefixes (AS13335):")
    cf_result = retriever.get_asn_ipv6_prefixes(13335)
    
    print(f"  BGPView: {len(cf_result.get('bgpview', []))} prefixes")
    print(f"  WHOIS RADB: {len(cf_result.get('whois_radb', []))} prefixes")
    print(f"  WHOIS RIPE: {len(cf_result.get('whois_ripe', []))} prefixes")
    print(f"  Total Unique: {len(cf_result.get('unique_prefixes', []))} prefixes")
    
    if cf_result.get('unique_prefixes'):
        print(f"\n  Sample IPv6 Prefixes:")
        for prefix in cf_result['unique_prefixes'][:5]:
            print(f"    - {prefix}")
        if len(cf_result['unique_prefixes']) > 5:
            print(f"    ... and {len(cf_result['unique_prefixes']) - 5} more")
    
    # Test Google (AS15169)
    print("\n\n📋 Google IPv6 Prefixes (AS15169):")
    google_result = retriever.get_asn_ipv6_prefixes(15169)
    
    print(f"  Total Unique: {len(google_result.get('unique_prefixes', []))} prefixes")
    if google_result.get('unique_prefixes'):
        print(f"\n  Sample IPv6 Prefixes:")
        for prefix in google_result['unique_prefixes'][:5]:
            print(f"    - {prefix}")


def generate_firewall_rules():
    """Generate firewall rules for specific companies"""
    print("\n" + "=" * 70)
    print("🔥 Part 3: Generating Firewall Rules for Companies")
    print("=" * 70)
    
    fw = get_firewall_generator()
    
    # Generate rules for Cloudflare
    print("\n📋 Cloudflare Blocklist (AS13335):")
    print("   Generating iptables rules to block all Cloudflare IPs...")
    
    # Get IPv6 prefixes for Cloudflare
    retriever = get_ipv6_asn_retriever()
    cf_ipv6 = retriever.get_cloudflare_ipv6()
    
    # Generate IPv4 rules (using ASN)
    cf_rules_v4 = fw.generate_rules_for_asn(
        asn=13335,
        action='DROP',
        format='iptables',
        chain='INPUT',
        ip_version='ipv4'
    )
    
    # Generate IPv6 rules
    cf_rules_v6 = []
    for prefix in cf_ipv6:
        rules = fw.generate_rules_for_asn(
            asn=13335,
            action='DROP',
            format='iptables',
            chain='INPUT',
            ip_version='ipv6'
        )
        # For IPv6, we'll use the prefixes directly
        cf_rules_v6.append(f"ip6tables -A INPUT -s {prefix} -j DROP")
    
    print(f"   ✅ Generated {len(cf_rules_v4)} IPv4 rules")
    print(f"   ✅ Generated {len(cf_rules_v6)} IPv6 rules")
    
    if cf_rules_v4:
        print(f"\n   Sample IPv4 Rules (first 5):")
        for rule in cf_rules_v4[:5]:
            print(f"     {rule}")
        if len(cf_rules_v4) > 5:
            print(f"     ... and {len(cf_rules_v4) - 5} more")
    
    if cf_rules_v6:
        print(f"\n   Sample IPv6 Rules (first 5):")
        for rule in cf_rules_v6[:5]:
            print(f"     {rule}")
        if len(cf_rules_v6) > 5:
            print(f"     ... and {len(cf_rules_v6) - 5} more")
    
    # Generate company blocklist
    print("\n\n📋 Company Blocklist (Cloudflare + AWS):")
    print("   Generating unified blocklist...")
    
    blocklist = fw.generate_company_blocklist(
        company_names=['Cloudflare'],
        action='DROP',
        format='iptables',
        ip_version='both'
    )
    
    print(f"   ✅ Generated {len(blocklist.get('rules', []))} total rules")
    print(f"   Statistics:")
    stats = blocklist.get('statistics', {})
    for company, data in stats.get('companies', {}).items():
        print(f"     {company}: {data.get('rules', 0)} rules, {data.get('blocks', 0)} blocks")
    
    # Save to file
    output_file = Path(__file__).parent / 'firewall_rules_cloudflare.sh'
    with open(output_file, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# Cloudflare Blocklist - Generated Rules\n")
        f.write("# Generated by EGO Revolution\n\n")
        f.write("# IPv4 Rules\n")
        for rule in cf_rules_v4:
            f.write(f"{rule}\n")
        f.write("\n# IPv6 Rules\n")
        for rule in cf_rules_v6:
            f.write(f"{rule}\n")
    
    print(f"\n   ✅ Rules saved to: {output_file}")
    print(f"   💡 To apply: sudo bash {output_file}")


def main():
    """Run all tests"""
    print("\n" + "🚀" * 35)
    print("BGP Lookups & Firewall Rule Generation Test")
    print("🚀" * 35)
    
    try:
        test_bgp_lookups()
        test_ipv6_asn_retrieval()
        generate_firewall_rules()
        
        print("\n" + "=" * 70)
        print("✅ All Tests Complete!")
        print("=" * 70)
        print("\n📚 Summary:")
        print("   ✅ BGP API lookups tested")
        print("   ✅ IPv6 ASN prefix retrieval tested")
        print("   ✅ Firewall rules generated for Cloudflare")
        print("   ✅ Rules saved to file")
        print()
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

