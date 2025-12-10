#!/usr/bin/env python3
"""
Complete IPv6 System Demonstration
==================================

Demonstrates:
1. Modified EUI-64 algorithm (SLAAC)
2. Sequential prediction (DHCPv6)
3. Pattern-based prediction (ML/Statistical)
4. IPv6 ASN prefix retrieval
5. IPv6 CIDR aggregation for firewalls

Run: python demo_ipv6_complete.py
"""

import sys
from pathlib import Path

# Add workspace root
workspace_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(workspace_root))

from netaddr import cidr_merge
import ipaddress


def demo_modified_eui64():
    """Demonstrate Modified EUI-64 algorithm"""
    print("\n" + "=" * 70)
    print("🧬 Part 1: Modified EUI-64 Algorithm (SLAAC)")
    print("=" * 70)
    
    try:
        from artificial_intelligence.personalities.reconnaissance.ash.ipv6_prediction import get_ipv6_predictor
        
        predictor = get_ipv6_predictor()
        
        # Example MAC addresses
        test_macs = [
            ("00:11:22:33:44:55", "fe80::"),
            ("aa:bb:cc:dd:ee:ff", "2001:db8:1:1::"),
        ]
        
        print("\n📋 MAC Address → IPv6 Address Conversion:")
        print("\nAlgorithm Steps:")
        print("  1. Insert FFFE in the middle of MAC address")
        print("  2. Invert the 7th bit (U/L bit) of the first byte")
        print("  3. Combine with network prefix")
        
        for mac, prefix in test_macs:
            ipv6 = predictor.mac_to_eui64(mac, prefix)
            print(f"\n  MAC: {mac}")
            print(f"  Prefix: {prefix}")
            print(f"  IPv6: {ipv6}")
            
            # Show the math
            mac_bytes = [int(b, 16) for b in mac.replace('-', ':').split(':')]
            print(f"  MAC bytes: {mac_bytes}")
            print(f"  After FFFE insertion: {mac_bytes[:3]} [FF FE] {mac_bytes[3:]}")
            print(f"  After U/L bit inversion: First byte {mac_bytes[0]:02x} → {(mac_bytes[0] ^ 0x02):02x}")
        
    except Exception as e:
        print(f"\n⚠️  Error: {e}")


def demo_sequential_prediction():
    """Demonstrate sequential IPv6 prediction"""
    print("\n" + "=" * 70)
    print("📊 Part 2: Sequential Prediction (DHCPv6)")
    print("=" * 70)
    
    try:
        from artificial_intelligence.personalities.reconnaissance.ash.ipv6_prediction import get_ipv6_predictor
        
        predictor = get_ipv6_predictor()
        
        # Seed address
        seed = "2001:db8:1:1::100"
        
        print(f"\n📋 Sequential Prediction from Seed Address:")
        print(f"  Seed: {seed}")
        print(f"  Method: Increment IID (last 64 bits)")
        
        predictions = predictor.predict_sequential(seed, count=10)
        
        print(f"\n  Generated {len(predictions)} predictions:")
        for i, pred in enumerate(predictions[:10], 1):
            print(f"    {i}. {pred}")
        
        if len(predictions) > 10:
            print(f"    ... and {len(predictions) - 10} more")
        
    except Exception as e:
        print(f"\n⚠️  Error: {e}")


def demo_pattern_analysis():
    """Demonstrate pattern-based prediction"""
    print("\n" + "=" * 70)
    print("🔍 Part 3: Pattern Analysis (ML/Statistical)")
    print("=" * 70)
    
    try:
        from artificial_intelligence.personalities.reconnaissance.ash.ipv6_prediction import get_ipv6_predictor
        
        predictor = get_ipv6_predictor()
        
        # Simulate known addresses (with patterns)
        known_addresses = [
            "2001:db8:1:1::1",
            "2001:db8:1:1::2",
            "2001:db8:1:1::3",
            "2001:db8:1:1::10",
            "2001:db8:1:1::11",
            "2001:db8:1:1::100",
            "2001:db8:1:1::101",
        ]
        
        print(f"\n📋 Pattern Analysis:")
        print(f"  Known addresses: {len(known_addresses)}")
        for addr in known_addresses:
            print(f"    - {addr}")
        
        analysis = predictor.analyze_patterns(known_addresses)
        
        print(f"\n  Analysis Results:")
        print(f"    Total addresses: {analysis.get('total_addresses', 0)}")
        print(f"    Unique prefixes: {analysis.get('unique_prefixes', 0)}")
        print(f"    Predictable regions: {len(analysis.get('predictable_regions', []))} bits")
        print(f"    Predictability score: {analysis.get('predictability_score', 0):.2%}")
        
        # Generate candidates
        prefix = "2001:db8:1:1::/64"
        candidates = predictor.generate_candidates(prefix, analysis, max_candidates=20)
        
        print(f"\n  Generated {len(candidates)} candidate addresses:")
        for i, candidate in enumerate(candidates[:10], 1):
            print(f"    {i}. {candidate}")
        
    except Exception as e:
        print(f"\n⚠️  Error: {e}")


def demo_ipv6_asn_retrieval():
    """Demonstrate IPv6 ASN prefix retrieval"""
    print("\n" + "=" * 70)
    print("🌐 Part 4: IPv6 ASN Prefix Retrieval")
    print("=" * 70)
    
    try:
        from artificial_intelligence.personalities.reconnaissance.ash.ipv6_asn_retriever import get_ipv6_asn_retriever
        
        retriever = get_ipv6_asn_retriever()
        
        # Get Cloudflare IPv6 prefixes
        print("\n📋 Cloudflare IPv6 Prefixes:")
        cf_prefixes = retriever.get_cloudflare_ipv6()
        for prefix in cf_prefixes:
            print(f"    - {prefix}")
        
        # Get AWS IPv6 prefixes (sample)
        print(f"\n📋 AWS IPv6 Prefixes (sample):")
        aws_prefixes = retriever.get_aws_ipv6()
        print(f"    Total: {len(aws_prefixes)} prefixes")
        print(f"    Sample:")
        for prefix in aws_prefixes[:5]:
            print(f"      - {prefix}")
        if len(aws_prefixes) > 5:
            print(f"      ... and {len(aws_prefixes) - 5} more")
        
    except Exception as e:
        print(f"\n⚠️  Error: {e}")


def demo_ipv6_aggregation():
    """Demonstrate IPv6 CIDR aggregation"""
    print("\n" + "=" * 70)
    print("🔧 Part 5: IPv6 CIDR Aggregation (Supernetting)")
    print("=" * 70)
    
    # Example IPv6 prefixes (some contiguous)
    ipv6_prefixes = [
        "2001:db8:1:1::/64",
        "2001:db8:1:2::/64",
        "2001:db8:1:3::/64",
        "2001:db8:1:4::/64",
        "2001:db8:2:1::/64",
        "2001:db8:2:2::/64",
        "2606:4700:4700::/48",
        "2606:4700:4701::/48",
    ]
    
    print(f"\n📊 Original IPv6 Prefixes ({len(ipv6_prefixes)} entries):")
    for prefix in ipv6_prefixes:
        print(f"   {prefix}")
    
    # Aggregate
    aggregated = cidr_merge(ipv6_prefixes)
    
    print(f"\n✅ Aggregated IPv6 Prefixes ({len(aggregated)} entries):")
    for prefix in aggregated:
        print(f"   {prefix}")
    
    reduction = len(ipv6_prefixes) - len(aggregated)
    reduction_pct = (reduction / len(ipv6_prefixes) * 100) if ipv6_prefixes else 0
    
    print(f"\n📈 Optimization Results:")
    print(f"   Original: {len(ipv6_prefixes)} prefixes")
    print(f"   Aggregated: {len(aggregated)} prefixes")
    print(f"   Reduction: {reduction} prefixes ({reduction_pct:.1f}%)")
    print(f"   → This saves {reduction} firewall rules!")


def main():
    """Run all demonstrations"""
    print("\n" + "🚀" * 35)
    print("Complete IPv6 System - Demonstration")
    print("🚀" * 35)
    
    demo_modified_eui64()
    demo_sequential_prediction()
    demo_pattern_analysis()
    demo_ipv6_asn_retrieval()
    demo_ipv6_aggregation()
    
    print("\n" + "=" * 70)
    print("✅ Demonstration Complete!")
    print("=" * 70)
    print("\n📚 Key Takeaways:")
    print("   1. Modified EUI-64: Deterministic IPv6 from MAC addresses")
    print("   2. Sequential prediction: DHCPv6 patterns")
    print("   3. Pattern analysis: ML-based IID prediction")
    print("   4. ASN retrieval: Real-time IPv6 prefix lookups")
    print("   5. CIDR aggregation: Firewall rule optimization")
    print()


if __name__ == '__main__':
    main()

