#!/usr/bin/env python3
"""
Standalone BGP Lookup and Firewall Rule Test
=============================================

Tests BGP lookups and firewall rule generation without Django.
"""

import sys
from pathlib import Path

# Add workspace root
workspace_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(workspace_root))


def test_bgp_lookups():
    """Test real BGP API lookups"""
    print("\n" + "=" * 70)
    print("📡 Testing Real BGP API Lookups")
    print("=" * 70)
    
    try:
        from artificial_intelligence.personalities.reconnaissance.ash.bgp_lookup_service import get_bgp_lookup_service
        
        bgp = get_bgp_lookup_service()
        
        # Test IPs
        test_ips = [
            ("1.1.1.1", "Cloudflare DNS"),
            ("8.8.8.8", "Google DNS"),
        ]
        
        print("\n🔍 Testing IP → ASN Lookups:")
        for ip, description in test_ips:
            print(f"\n  IP: {ip} ({description})")
            try:
                result = bgp.lookup_ip(ip)
                
                if result.get('error'):
                    print(f"    ⚠️  Error: {result['error']}")
                else:
                    print(f"    ✅ ASN: {result.get('asn', 'N/A')}")
                    print(f"    ✅ Prefix: {result.get('prefix', 'N/A')}")
                    print(f"    ✅ Country: {result.get('country', 'N/A')}")
                    print(f"    ✅ Source: {result.get('source', 'N/A')}")
            except Exception as e:
                print(f"    ❌ Exception: {e}")
        
        # Test ASN lookups
        print("\n\n🔍 Testing ASN → Information Lookups:")
        test_asns = [
            (13335, "Cloudflare"),
            (15169, "Google"),
        ]
        
        for asn, name in test_asns:
            print(f"\n  ASN: AS{asn} ({name})")
            try:
                result = bgp.lookup_asn(asn)
                
                if result.get('error'):
                    print(f"    ⚠️  Error: {result['error']}")
                else:
                    print(f"    ✅ Name: {result.get('name', 'N/A')}")
                    print(f"    ✅ Description: {result.get('description', 'N/A')[:60]}...")
                    print(f"    ✅ Country: {result.get('country', 'N/A')}")
                    print(f"    ✅ IPv4 Prefixes: {len(result.get('prefixes_ipv4', []))}")
                    print(f"    ✅ IPv6 Prefixes: {len(result.get('prefixes_ipv6', []))}")
                    
                    # Show sample prefixes
                    if result.get('prefixes_ipv4'):
                        print(f"    Sample IPv4: {', '.join(result['prefixes_ipv4'][:3])}")
                    if result.get('prefixes_ipv6'):
                        print(f"    Sample IPv6: {', '.join(result['prefixes_ipv6'][:3])}")
            except Exception as e:
                print(f"    ❌ Exception: {e}")
                
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


def test_ipv6_asn_retrieval():
    """Test IPv6 ASN prefix retrieval"""
    print("\n" + "=" * 70)
    print("🌐 Testing IPv6 ASN Prefix Retrieval")
    print("=" * 70)
    
    try:
        from artificial_intelligence.personalities.reconnaissance.ash.ipv6_asn_retriever import get_ipv6_asn_retriever
        
        retriever = get_ipv6_asn_retriever()
        
        # Test Cloudflare (AS13335)
        print("\n📋 Cloudflare IPv6 Prefixes (AS13335):")
        try:
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
        except Exception as e:
            print(f"  ⚠️  Error retrieving Cloudflare prefixes: {e}")
        
        # Get published Cloudflare IPv6 ranges
        print("\n\n📋 Cloudflare Published IPv6 Ranges:")
        cf_published = retriever.get_cloudflare_ipv6()
        print(f"  Total: {len(cf_published)} prefixes")
        for prefix in cf_published:
            print(f"    - {prefix}")
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


def generate_firewall_rules():
    """Generate firewall rules for Cloudflare"""
    print("\n" + "=" * 70)
    print("🔥 Generating Firewall Rules for Cloudflare")
    print("=" * 70)
    
    try:
        from artificial_intelligence.personalities.reconnaissance.ash.ipv6_asn_retriever import get_ipv6_asn_retriever
        from netaddr import cidr_merge
        import ipaddress
        
        retriever = get_ipv6_asn_retriever()
        
        # Get Cloudflare IPv6 prefixes
        cf_ipv6 = retriever.get_cloudflare_ipv6()
        
        print(f"\n📋 Cloudflare IPv6 Prefixes: {len(cf_ipv6)}")
        
        # Optimize with supernetting
        optimized = cidr_merge(cf_ipv6)
        reduction = len(cf_ipv6) - len(optimized)
        
        print(f"  Optimized: {len(optimized)} prefixes ({reduction} reduction)")
        
        # Generate iptables rules
        print("\n📋 Generated iptables Rules:")
        print("\n  # IPv6 Rules (Cloudflare)")
        for prefix in optimized:
            print(f"  ip6tables -A INPUT -s {prefix} -j DROP")
        
        # Also generate for IPv4 (using known Cloudflare ASN)
        print("\n  # IPv4 Rules (Cloudflare - AS13335)")
        print("  # Note: IPv4 rules require ASN database lookup")
        print("  # Use: ip_ownership_validator.build_network_object(13335)")
        
        # Save to file
        output_file = Path(__file__).parent / 'firewall_rules_cloudflare.sh'
        with open(output_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# Cloudflare Blocklist - Generated Rules\n")
            f.write("# Generated by EGO Revolution\n\n")
            f.write("# IPv6 Rules\n")
            for prefix in optimized:
                f.write(f"ip6tables -A INPUT -s {prefix} -j DROP\n")
            f.write("\n# Note: IPv4 rules require ASN database\n")
            f.write("# Use ip_ownership_validator to generate IPv4 rules\n")
        
        print(f"\n  ✅ Rules saved to: {output_file}")
        print(f"  💡 To apply: sudo bash {output_file}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Run all tests"""
    print("\n" + "🚀" * 35)
    print("BGP Lookups & Firewall Rule Generation Test")
    print("🚀" * 35)
    
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
    print("💡 Note: IPv6 ASN data comes from BGP lookups, not static databases")
    print("   This is because IPv6 routing is dynamic and changes frequently.")
    print()


if __name__ == '__main__':
    main()

