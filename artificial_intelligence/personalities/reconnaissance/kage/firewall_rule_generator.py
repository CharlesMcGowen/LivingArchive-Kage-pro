#!/usr/bin/env python3
"""
Firewall Rule Generator
=======================

Generates optimized firewall rules from ASN-based IP networks.
Uses supernetting to minimize rule count while maintaining coverage.

Features:
- IPv4 and IPv6 support
- Automatic CIDR aggregation (supernetting)
- Multiple firewall formats (iptables, nftables, pfSense, etc.)
- Rule optimization (minimize rule count)

Author: EGO Revolution
Version: 1.0.0
"""

import logging
from typing import List, Dict, Any, Optional
from netaddr import cidr_merge
import ipaddress

logger = logging.getLogger(__name__)


class FirewallRuleGenerator:
    """
    Generate optimized firewall rules from ASN-based IP networks.
    """
    
    def __init__(self):
        """Initialize firewall rule generator"""
        self.supported_formats = ['iptables', 'nftables', 'pfsense', 'ufw', 'raw_cidr']
        logger.info("🔥 Firewall Rule Generator initialized")
    
    def generate_rules_for_asn(
        self,
        asn: int,
        action: str = 'ACCEPT',
        ip_version: str = 'ipv4',
        format: str = 'iptables',
        chain: str = 'INPUT',
        interface: Optional[str] = None
    ) -> List[str]:
        """
        Generate firewall rules for an ASN.
        
        Args:
            asn: Autonomous System Number
            action: Firewall action (ACCEPT, DROP, REJECT, etc.)
            ip_version: 'ipv4' or 'ipv6'
            format: Output format ('iptables', 'nftables', 'pfsense', 'ufw', 'raw_cidr')
            chain: iptables chain name (default: 'INPUT')
            interface: Optional network interface
            
        Returns:
            List of firewall rule strings
        """
        # Get network object from validator
        try:
            from artificial_intelligence.personalities.reconnaissance.ash.ip_ownership_validator import get_ip_validator
            
            validator = get_ip_validator()
            network_obj = validator.build_network_object(asn, ip_version=ip_version)
            
            if 'error' in network_obj:
                logger.error(f"Error building network object: {network_obj['error']}")
                return []
            
            cidr_blocks = network_obj.get('aggregated_blocks', [])
            if not cidr_blocks:
                logger.warning(f"No CIDR blocks found for ASN {asn}")
                return []
            
            # Generate rules based on format
            if format == 'iptables':
                return self._generate_iptables_rules(cidr_blocks, action, chain, interface, ip_version)
            elif format == 'nftables':
                return self._generate_nftables_rules(cidr_blocks, action, ip_version)
            elif format == 'pfsense':
                return self._generate_pfsense_rules(cidr_blocks, action, ip_version)
            elif format == 'ufw':
                return self._generate_ufw_rules(cidr_blocks, action, ip_version)
            elif format == 'raw_cidr':
                return cidr_blocks
            else:
                logger.error(f"Unsupported format: {format}")
                return []
                
        except Exception as e:
            logger.error(f"Error generating firewall rules: {e}")
            return []
    
    def _generate_iptables_rules(
        self,
        cidr_blocks: List[str],
        action: str,
        chain: str,
        interface: Optional[str],
        ip_version: str
    ) -> List[str]:
        """Generate iptables rules"""
        rules = []
        cmd = 'ip6tables' if ip_version == 'ipv6' else 'iptables'
        
        for cidr in cidr_blocks:
            rule_parts = [cmd, '-A', chain]
            
            if interface:
                rule_parts.extend(['-i', interface])
            
            rule_parts.extend(['-s', cidr, '-j', action])
            
            rules.append(' '.join(rule_parts))
        
        return rules
    
    def _generate_nftables_rules(
        self,
        cidr_blocks: List[str],
        action: str,
        ip_version: str
    ) -> List[str]:
        """Generate nftables rules"""
        rules = []
        family = 'ip6' if ip_version == 'ipv6' else 'ip'
        
        for cidr in cidr_blocks:
            rule = f"{family} saddr {cidr} {action.lower()}"
            rules.append(rule)
        
        return rules
    
    def _generate_pfsense_rules(
        self,
        cidr_blocks: List[str],
        action: str,
        ip_version: str
    ) -> List[str]:
        """Generate pfSense alias rules"""
        rules = []
        
        # pfSense uses aliases - create alias first
        alias_name = f"ASN_BLOCK_{ip_version.upper()}"
        rules.append(f"# Alias: {alias_name}")
        rules.append(f"# Action: {action}")
        rules.append("")
        
        for cidr in cidr_blocks:
            rules.append(f"{cidr}")
        
        return rules
    
    def _generate_ufw_rules(
        self,
        cidr_blocks: List[str],
        action: str,
        ip_version: str
    ) -> List[str]:
        """Generate UFW rules"""
        rules = []
        direction = 'from' if action == 'DENY' else 'to'
        
        for cidr in cidr_blocks:
            if action == 'DENY':
                rule = f"ufw deny {direction} {cidr}"
            else:
                rule = f"ufw allow {direction} {cidr}"
            rules.append(rule)
        
        return rules
    
    def generate_company_blocklist(
        self,
        company_names: List[str],
        action: str = 'DROP',
        format: str = 'iptables',
        ip_version: str = 'ipv4'
    ) -> Dict[str, Any]:
        """
        Generate firewall rules to block entire companies (e.g., all Cloudflare IPs).
        
        Args:
            company_names: List of company names (e.g., ['Cloudflare', 'AWS'])
            action: Firewall action
            format: Output format
            ip_version: 'ipv4' or 'ipv6' or 'both'
            
        Returns:
            Dictionary with rules, statistics, etc.
        """
        from artificial_intelligence.personalities.reconnaissance.ash.ip_ownership_validator import (
            get_ip_validator,
            ASN_TO_COMPANY
        )
        
        validator = get_ip_validator()
        all_rules = []
        stats = {
            'companies': {},
            'total_blocks': 0,
            'total_rules': 0
        }
        
        for company_name in company_names:
            # Find ASNs for this company
            company_asns = [
                asn for asn, info in ASN_TO_COMPANY.items()
                if info['name'].lower() == company_name.lower()
            ]
            
            if not company_asns:
                logger.warning(f"No ASNs found for company: {company_name}")
                continue
            
            company_rules = []
            total_blocks = 0
            
            for asn in company_asns:
                versions = ['ipv4', 'ipv6'] if ip_version == 'both' else [ip_version]
                
                for version in versions:
                    rules = self.generate_rules_for_asn(
                        asn=asn,
                        action=action,
                        ip_version=version,
                        format=format
                    )
                    company_rules.extend(rules)
                    total_blocks += len(rules)
            
            all_rules.extend(company_rules)
            stats['companies'][company_name] = {
                'asns': company_asns,
                'rules': len(company_rules),
                'blocks': total_blocks
            }
            stats['total_blocks'] += total_blocks
            stats['total_rules'] += len(company_rules)
        
        return {
            'rules': all_rules,
            'statistics': stats,
            'format': format,
            'action': action
        }
    
    def optimize_rules(self, cidr_blocks: List[str]) -> List[str]:
        """
        Optimize firewall rules by aggregating CIDR blocks.
        
        Uses supernetting to reduce rule count while maintaining coverage.
        Supports both IPv4 and IPv6 with separate aggregation.
        
        Args:
            cidr_blocks: List of CIDR blocks (IPv4 or IPv6)
            
        Returns:
            Optimized (aggregated) list of CIDR blocks
        """
        if not cidr_blocks:
            return []
        
        # Separate IPv4 and IPv6
        ipv4_blocks = []
        ipv6_blocks = []
        
        for cidr in cidr_blocks:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                if isinstance(network, ipaddress.IPv4Network):
                    ipv4_blocks.append(cidr)
                elif isinstance(network, ipaddress.IPv6Network):
                    ipv6_blocks.append(cidr)
            except ValueError:
                continue
        
        # Aggregate each separately
        optimized = []
        
        if ipv4_blocks:
            optimized_v4 = cidr_merge(ipv4_blocks)
            optimized.extend(optimized_v4)
            logger.debug(f"IPv4: {len(ipv4_blocks)} → {len(optimized_v4)} blocks")
        
        if ipv6_blocks:
            optimized_v6 = cidr_merge(ipv6_blocks)
            optimized.extend(optimized_v6)
            logger.debug(f"IPv6: {len(ipv6_blocks)} → {len(optimized_v6)} blocks")
        
        reduction = len(cidr_blocks) - len(optimized)
        reduction_pct = (reduction / len(cidr_blocks) * 100) if cidr_blocks else 0
        
        logger.info(f"Optimized {len(cidr_blocks)} blocks → {len(optimized)} blocks ({reduction_pct:.1f}% reduction)")
        
        return optimized
    
    def optimize_ipv6_prefixes(self, ipv6_prefixes: List[str]) -> List[str]:
        """
        Optimize IPv6 prefixes specifically for firewall rules.
        
        IPv6 prefixes are typically larger (/32, /48, /64) and benefit
        from aggregation when they're contiguous or overlapping.
        
        Args:
            ipv6_prefixes: List of IPv6 CIDR prefixes
            
        Returns:
            Optimized (aggregated) list of IPv6 prefixes
        """
        if not ipv6_prefixes:
            return []
        
        # Filter and validate IPv6 prefixes
        valid_prefixes = []
        for prefix in ipv6_prefixes:
            try:
                network = ipaddress.IPv6Network(prefix, strict=False)
                valid_prefixes.append(prefix)
            except ValueError:
                continue
        
        if not valid_prefixes:
            return []
        
        # Aggregate using netaddr
        optimized = cidr_merge(valid_prefixes)
        
        reduction = len(valid_prefixes) - len(optimized)
        reduction_pct = (reduction / len(valid_prefixes) * 100) if valid_prefixes else 0
        
        logger.info(f"Optimized {len(valid_prefixes)} IPv6 prefixes → {len(optimized)} prefixes ({reduction_pct:.1f}% reduction)")
        
        return optimized


# Global instance
_firewall_generator_instance = None

def get_firewall_generator() -> FirewallRuleGenerator:
    """Get or create global firewall rule generator instance"""
    global _firewall_generator_instance
    if _firewall_generator_instance is None:
        _firewall_generator_instance = FirewallRuleGenerator()
    return _firewall_generator_instance

