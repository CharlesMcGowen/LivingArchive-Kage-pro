#!/usr/bin/env python3
"""
IPv6 Address Prediction System
================================

Implements mathematical prediction strategies for IPv6 addresses:
1. Modified EUI-64 algorithm (SLAAC)
2. Sequential scanning (DHCPv6)
3. Pattern-based clustering (ML/Statistical)
4. DNS-based seed harvesting

Author: EGO Revolution
Version: 1.0.0
"""

import logging
import ipaddress
from typing import List, Dict, Any, Optional, Set
import struct
import re

logger = logging.getLogger(__name__)


class IPv6Predictor:
    """
    Predict IPv6 addresses using various mathematical and statistical methods.
    """
    
    def __init__(self):
        """Initialize IPv6 predictor"""
        self.known_addresses: Set[str] = set()
        self.patterns: Dict[str, Any] = {}
        logger.info("🔮 IPv6 Predictor initialized")
    
    def mac_to_eui64(self, mac_address: str, prefix: str = "fe80::") -> str:
        """
        Convert MAC address to Modified EUI-64 Interface Identifier.
        
        Algorithm:
        1. Insert FFFE in the middle of MAC address
        2. Invert the 7th bit (U/L bit) of the first byte
        
        Args:
            mac_address: MAC address in format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
            prefix: IPv6 network prefix (default: fe80:: for link-local)
            
        Returns:
            Complete IPv6 address with Modified EUI-64 IID
            
        Example:
            MAC: 00:11:22:33:44:55
            IID: 0211:22ff:fe33:4455
            Result: fe80::211:22ff:fe33:4455
        """
        # Normalize MAC address format
        mac = mac_address.replace('-', ':').lower()
        
        # Parse MAC address bytes
        try:
            mac_bytes = [int(b, 16) for b in mac.split(':')]
            if len(mac_bytes) != 6:
                raise ValueError("Invalid MAC address format")
        except (ValueError, AttributeError) as e:
            logger.error(f"Invalid MAC address: {mac_address} - {e}")
            return None
        
        # Step 1: Insert FFFE in the middle
        # MAC: [00, 11, 22, 33, 44, 55]
        # EUI-64: [00, 11, 22, FF, FE, 33, 44, 55]
        eui64_bytes = mac_bytes[:3] + [0xFF, 0xFE] + mac_bytes[3:]
        
        # Step 2: Invert the 7th bit (U/L bit) of the first byte
        # Bit 7 (0-indexed) is the Universal/Local bit
        # Inverting means: bit ^= 0x02
        eui64_bytes[0] ^= 0x02
        
        # Convert to hex string
        eui64_hex = ':'.join([f'{b:02x}' for b in eui64_bytes])
        
        # Format as IPv6 IID (group into 16-bit chunks)
        parts = eui64_hex.split(':')
        iid = f"{parts[0]}{parts[1]}:{parts[2]}{parts[3]}:{parts[4]}{parts[5]}:{parts[6]}{parts[7]}"
        
        # Combine with prefix
        if prefix.endswith('::'):
            ipv6 = f"{prefix}{iid}"
        elif prefix.endswith(':'):
            ipv6 = f"{prefix}{iid}"
        else:
            ipv6 = f"{prefix}::{iid}"
        
        return ipv6
    
    def predict_sequential(self, seed_address: str, count: int = 100) -> List[str]:
        """
        Predict sequential IPv6 addresses (DHCPv6 pattern).
        
        Assumes addresses are assigned sequentially by incrementing the IID.
        
        Args:
            seed_address: Known IPv6 address to start from
            count: Number of addresses to predict
            
        Returns:
            List of predicted IPv6 addresses
        """
        try:
            ip = ipaddress.IPv6Address(seed_address)
            predictions = []
            
            # Extract network prefix (first 64 bits)
            network = ipaddress.IPv6Network(f"{ip}/64", strict=False)
            prefix_int = int(network.network_address) >> 64
            
            # Extract IID (last 64 bits)
            iid_int = int(ip) & 0xFFFFFFFFFFFFFFFF
            
            # Generate sequential addresses
            for i in range(1, count + 1):
                new_iid = (iid_int + i) & 0xFFFFFFFFFFFFFFFF
                new_address_int = (prefix_int << 64) | new_iid
                new_address = ipaddress.IPv6Address(new_address_int)
                predictions.append(str(new_address))
            
            logger.info(f"Generated {len(predictions)} sequential predictions from {seed_address}")
            return predictions
            
        except (ValueError, ipaddress.AddressValueError) as e:
            logger.error(f"Error in sequential prediction: {e}")
            return []
    
    def analyze_patterns(self, known_addresses: List[str]) -> Dict[str, Any]:
        """
        Analyze patterns in known IPv6 addresses to identify predictable regions.
        
        Uses entropy analysis to find non-random segments in the IID.
        
        Args:
            known_addresses: List of known active IPv6 addresses
            
        Returns:
            Dictionary with pattern analysis results
        """
        if not known_addresses:
            return {'error': 'No addresses provided'}
        
        # Extract IIDs (last 64 bits)
        iids = []
        prefixes = set()
        
        for addr_str in known_addresses:
            try:
                addr = ipaddress.IPv6Address(addr_str)
                network = ipaddress.IPv6Network(f"{addr}/64", strict=False)
                prefix = str(network.network_address)
                prefixes.add(prefix)
                
                # Extract IID (last 64 bits)
                iid_int = int(addr) & 0xFFFFFFFFFFFFFFFF
                iids.append(iid_int)
            except (ValueError, ipaddress.AddressValueError):
                continue
        
        if not iids:
            return {'error': 'No valid addresses'}
        
        # Analyze IID patterns
        # Convert to binary strings for bit-level analysis
        iid_binaries = [format(iid, '064b') for iid in iids]
        
        # Calculate entropy per bit position
        bit_entropy = []
        for bit_pos in range(64):
            ones = sum(1 for iid_bin in iid_binaries if iid_bin[bit_pos] == '1')
            zeros = len(iid_binaries) - ones
            
            # Calculate entropy (Shannon entropy)
            p1 = ones / len(iid_binaries) if iid_binaries else 0
            p0 = zeros / len(iid_binaries) if iid_binaries else 0
            
            entropy = 0
            if p1 > 0:
                entropy -= p1 * (p1.bit_length() - 1 if p1 > 0 else 0)
            if p0 > 0:
                entropy -= p0 * (p0.bit_length() - 1 if p0 > 0 else 0)
            
            bit_entropy.append(entropy)
        
        # Find low-entropy regions (predictable)
        low_entropy_threshold = 0.3
        predictable_regions = []
        
        for i, entropy in enumerate(bit_entropy):
            if entropy < low_entropy_threshold:
                predictable_regions.append(i)
        
        # Analyze nybble (4-bit) patterns
        nybble_patterns = {}
        for iid_int in iids:
            # Extract each nybble (4 bits)
            for nybble_pos in range(16):  # 64 bits / 4 = 16 nybbles
                nybble = (iid_int >> (60 - nybble_pos * 4)) & 0xF
                key = f"nybble_{nybble_pos}"
                if key not in nybble_patterns:
                    nybble_patterns[key] = []
                nybble_patterns[key].append(nybble)
        
        # Find common nybble values
        common_nybbles = {}
        for key, values in nybble_patterns.items():
            from collections import Counter
            counter = Counter(values)
            most_common = counter.most_common(1)
            if most_common:
                common_nybbles[key] = most_common[0]
        
        return {
            'total_addresses': len(known_addresses),
            'unique_prefixes': len(prefixes),
            'bit_entropy': bit_entropy,
            'predictable_regions': predictable_regions,
            'common_nybbles': common_nybbles,
            'predictability_score': 1.0 - (len(predictable_regions) / 64) if predictable_regions else 0.0
        }
    
    def generate_candidates(
        self,
        prefix: str,
        pattern_analysis: Dict[str, Any],
        max_candidates: int = 10000
    ) -> List[str]:
        """
        Generate candidate IPv6 addresses based on pattern analysis.
        
        Args:
            prefix: IPv6 network prefix (e.g., "2001:db8:1:1::/64")
            pattern_analysis: Results from analyze_patterns()
            max_candidates: Maximum number of candidates to generate
            
        Returns:
            List of candidate IPv6 addresses
        """
        try:
            network = ipaddress.IPv6Network(prefix, strict=False)
            candidates = []
            
            # Use common nybble patterns to generate candidates
            common_nybbles = pattern_analysis.get('common_nybbles', {})
            predictable_regions = pattern_analysis.get('predictable_regions', [])
            
            if not common_nybbles:
                # Fallback: generate sequential candidates
                base_iid = 0
                for nybble_pos in range(16):
                    key = f"nybble_{nybble_pos}"
                    if key in common_nybbles:
                        value, count = common_nybbles[key]
                        base_iid |= (value << (60 - nybble_pos * 4))
                
                # Generate variations
                for i in range(min(max_candidates, 1000)):
                    # Vary non-predictable bits
                    candidate_iid = base_iid
                    for bit_pos in range(64):
                        if bit_pos not in predictable_regions:
                            # Randomize this bit
                            import random
                            if random.random() > 0.5:
                                candidate_iid ^= (1 << (63 - bit_pos))
                    
                    candidate_addr = ipaddress.IPv6Address(int(network.network_address) | candidate_iid)
                    candidates.append(str(candidate_addr))
                    
                    if len(candidates) >= max_candidates:
                        break
            else:
                # Use pattern-based generation
                # Start with most common pattern
                base_iid = 0
                for nybble_pos in range(16):
                    key = f"nybble_{nybble_pos}"
                    if key in common_nybbles:
                        value, _ = common_nybbles[key]
                        base_iid |= (value << (60 - nybble_pos * 4))
                
                # Generate candidates by varying non-predictable regions
                variations = min(max_candidates, 10000)
                for i in range(variations):
                    candidate_iid = base_iid
                    
                    # Vary bits not in predictable regions
                    for bit_pos in range(64):
                        if bit_pos not in predictable_regions:
                            # Add controlled variation
                            variation = (i >> (bit_pos % 16)) & 1
                            if variation:
                                candidate_iid ^= (1 << (63 - bit_pos))
                    
                    candidate_addr = ipaddress.IPv6Address(int(network.network_address) | candidate_iid)
                    candidates.append(str(candidate_addr))
            
            logger.info(f"Generated {len(candidates)} candidate addresses for {prefix}")
            return candidates[:max_candidates]
            
        except (ValueError, ipaddress.AddressValueError) as e:
            logger.error(f"Error generating candidates: {e}")
            return []
    
    def harvest_from_dns(self, domain: str) -> List[str]:
        """
        Harvest IPv6 addresses from DNS records (AAAA records).
        
        Args:
            domain: Domain name to query
            
        Returns:
            List of IPv6 addresses found in DNS
        """
        import socket
        
        addresses = []
        
        try:
            # Query AAAA records
            results = socket.getaddrinfo(domain, None, socket.AF_INET6)
            
            for result in results:
                addr = result[4][0]
                if ipaddress.IPv6Address(addr):
                    addresses.append(addr)
            
            logger.info(f"Harvested {len(addresses)} IPv6 addresses from DNS for {domain}")
        except (socket.gaierror, ValueError) as e:
            logger.debug(f"DNS harvest error for {domain}: {e}")
        
        return addresses


# Global instance
_ipv6_predictor_instance = None

def get_ipv6_predictor() -> IPv6Predictor:
    """Get or create global IPv6 predictor instance"""
    global _ipv6_predictor_instance
    if _ipv6_predictor_instance is None:
        _ipv6_predictor_instance = IPv6Predictor()
    return _ipv6_predictor_instance

