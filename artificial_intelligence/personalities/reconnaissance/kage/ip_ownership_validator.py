#!/usr/bin/env python3
"""
IP Ownership Validator using ASN Data
======================================

Validates IP address ownership using Autonomous System Number (ASN) data
to determine if an IP belongs to cloud providers, CDNs, or infrastructure.
This allows us to:
1. Skip scans on infrastructure IPs that won't yield useful results
2. Adjust port expectations (e.g., Cloudflare only proxies certain ports)
3. Speed up scanning by avoiding unnecessary work

Author: EGO Revolution
Version: 1.0.0
"""

import logging
import socket
from typing import Dict, Any, Optional, List, Set, Tuple
from pathlib import Path
import ipaddress

logger = logging.getLogger(__name__)

# Try to import netaddr for advanced network operations
try:
    import netaddr
    NETADDR_AVAILABLE = True
except ImportError:
    NETADDR_AVAILABLE = False
    netaddr = None
    logger.debug("netaddr not available - supernetting will be limited")

# Try to import pandas for large dataset operations
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None
    logger.debug("pandas not available - large dataset operations will be limited")

# Try to import pyasn
try:
    import pyasn
    PYASN_AVAILABLE = True
except ImportError:
    PYASN_AVAILABLE = False
    pyasn = None
    logger.warning("pyasn not available - IP ownership validation will be limited")


# Major ASN mappings for cloud providers and CDNs
# Based on: https://iptoasn.com/ and BGP routing data
ASN_TO_COMPANY = {
    # Amazon Web Services
    16509: {
        'name': 'Amazon/AWS',
        'type': 'cloud_hosting',
        'port_expectations': 'user_defined',
        'common_ports': [22, 80, 443, 3389, 3306, 5432],
        'skip_scan': False,
        'note': 'Ports are user-defined via Security Groups'
    },
    14618: {
        'name': 'Amazon Technologies',
        'type': 'cloud_hosting',
        'port_expectations': 'user_defined',
        'common_ports': [22, 80, 443],
        'skip_scan': False
    },
    
    # Cloudflare
    13335: {
        'name': 'Cloudflare',
        'type': 'cdn_proxy',
        'port_expectations': 'proxied_only',
        'common_ports': [80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880],
        'skip_scan': False,
        'note': 'Only proxies HTTP/HTTPS on specific ports. Other ports require Spectrum (paid)'
    },
    
    # Google Cloud Platform
    15169: {
        'name': 'Google/GCP',
        'type': 'cloud_hosting',
        'port_expectations': 'user_defined',
        'common_ports': [22, 80, 443, 3389],
        'skip_scan': False
    },
    
    # Microsoft Azure
    8075: {
        'name': 'Microsoft/Azure',
        'type': 'cloud_hosting',
        'port_expectations': 'user_defined',
        'common_ports': [22, 80, 443, 3389, 1433],
        'skip_scan': False
    },
    
    # DigitalOcean
    14061: {
        'name': 'DigitalOcean',
        'type': 'cloud_hosting',
        'port_expectations': 'user_defined',
        'common_ports': [22, 80, 443],
        'skip_scan': False
    },
    
    # Oracle Cloud
    31898: {
        'name': 'Oracle/OCI',
        'type': 'cloud_hosting',
        'port_expectations': 'user_defined',
        'common_ports': [22, 80, 443],
        'skip_scan': False
    },
    
    # Akamai
    16625: {
        'name': 'Akamai',
        'type': 'cdn_proxy',
        'port_expectations': 'proxied_only',
        'common_ports': [80, 443],
        'skip_scan': False
    },
    
    # Apple
    714: {
        'name': 'Apple Inc.',
        'type': 'business',
        'port_expectations': 'standard',
        'common_ports': [443],
        'skip_scan': True,  # Infrastructure, not customer-facing
        'note': 'Apple infrastructure - unlikely to have open ports'
    },
    
    # Major ISPs (infrastructure)
    7018: {'name': 'AT&T', 'type': 'isp', 'port_expectations': 'variable', 'skip_scan': True},
    701: {'name': 'Verizon', 'type': 'isp', 'port_expectations': 'variable', 'skip_scan': True},
    7922: {'name': 'Comcast', 'type': 'isp', 'port_expectations': 'variable', 'skip_scan': True},
}


class IPOwnershipValidator:
    """
    Validates IP address ownership using ASN data.
    """
    
    def __init__(self, asn_db_path: Optional[Path] = None):
        """
        Initialize IP ownership validator.
        
        Args:
            asn_db_path: Path to pyasn database file (ipasn.dat)
                        If None, will look in default location
        """
        self.asndb = None
        self.asn_db_path = asn_db_path
        
        if PYASN_AVAILABLE:
            self._load_asn_database()
        else:
            logger.warning("⚠️  pyasn not available - using fallback validation")
    
    def _load_asn_database(self):
        """Load ASN database for IP lookups"""
        if not PYASN_AVAILABLE:
            return
        
        # Default database locations (pyasn binary format)
        pyasn_paths = [
            self.asn_db_path,
            Path(__file__).parent / 'data' / 'ipasn.dat',
            Path('/usr/share/pyasn/ipasn.dat'),
            Path('/var/lib/pyasn/ipasn.dat'),
        ]
        
        for db_path in pyasn_paths:
            if db_path and Path(db_path).exists():
                try:
                    self.asndb = pyasn.pyasn(str(db_path))
                    logger.info(f"✅ Loaded ASN database (pyasn format): {db_path}")
                    return
                except Exception as e:
                    logger.debug(f"Could not load ASN database from {db_path}: {e}")
                    continue
        
        # Fallback: Try TSV format database
        tsv_paths = [
            Path(__file__).parent / 'data' / 'ip2asn-v4.tsv.gz',
            Path(__file__).parent / 'data' / 'ip2asn-v4.tsv',
        ]
        
        for tsv_path in tsv_paths:
            if tsv_path.exists():
                try:
                    self._load_tsv_database(tsv_path)
                    logger.info(f"✅ Loaded ASN database (TSV format): {tsv_path}")
                    return
                except Exception as e:
                    logger.debug(f"Could not load TSV database from {tsv_path}: {e}")
                    continue
        
        logger.warning("⚠️  ASN database not found - IP ownership validation will use fallback methods")
        logger.info("💡 To enable full ASN validation, ensure database exists at:")
        logger.info("   artificial_intelligence/personalities/reconnaissance/ash/data/ip2asn-v4.tsv.gz")
    
    def _load_tsv_database(self, tsv_path: Path):
        """Load TSV format ASN database for lookups (supports both IPv4 and IPv6)"""
        import gzip
        
        self.tsv_db = {}  # IPv4 ranges: {(start_ip, end_ip): asn}
        self.tsv_db_v6 = {}  # IPv6 ranges: {(start_ip, end_ip): asn}
        self.tsv_loaded = False
        
        # Check if file is gzipped
        open_func = gzip.open if str(tsv_path).endswith('.gz') else open
        mode = 'rt' if str(tsv_path).endswith('.gz') else 'r'
        
        try:
            ipv4_count = 0
            ipv6_count = 0
            
            with open_func(tsv_path, mode) as f:
                # TSV format: range_start range_end ASN country code
                for line in f:
                    if line.startswith('#'):
                        continue
                    parts = line.strip().split('\t')
                    if len(parts) >= 3:
                        try:
                            range_start = parts[0]
                            range_end = parts[1]
                            asn = int(parts[2])
                            
                            # Detect IPv4 vs IPv6
                            is_ipv6 = ':' in range_start
                            
                            if is_ipv6:
                                # IPv6 range
                                try:
                                    start_ip = int(ipaddress.IPv6Address(range_start))
                                    end_ip = int(ipaddress.IPv6Address(range_end))
                                    self.tsv_db_v6[(start_ip, end_ip)] = asn
                                    ipv6_count += 1
                                except (ValueError, ipaddress.AddressValueError):
                                    continue
                            else:
                                # IPv4 range
                                try:
                                    start_ip = int(ipaddress.IPv4Address(range_start))
                                    end_ip = int(ipaddress.IPv4Address(range_end))
                                    self.tsv_db[(start_ip, end_ip)] = asn
                                    ipv4_count += 1
                                except (ValueError, ipaddress.AddressValueError):
                                    continue
                        except (ValueError, IndexError):
                            continue
            
            self.tsv_loaded = True
            logger.info(f"✅ Loaded ASN database: {ipv4_count:,} IPv4 ranges, {ipv6_count:,} IPv6 ranges")
        except Exception as e:
            logger.error(f"Error loading TSV database: {e}")
            self.tsv_db = {}
            self.tsv_db_v6 = {}
            self.tsv_loaded = False
    
    def _lookup_asn_from_tsv(self, ip_address: str, is_ipv6: bool = False) -> Optional[int]:
        """Lookup ASN from TSV database using binary search (supports IPv4 and IPv6)"""
        if not self.tsv_loaded:
            return None
        
        # Select appropriate database
        db = self.tsv_db_v6 if is_ipv6 else self.tsv_db
        if not db:
            return None
        
        try:
            # Convert IP to integer
            if is_ipv6:
                ip_int = int(ipaddress.IPv6Address(ip_address))
                cache_attr = '_tsv_ranges_sorted_v6'
            else:
                ip_int = int(ipaddress.IPv4Address(ip_address))
                cache_attr = '_tsv_ranges_sorted'
            
            # Use binary search on sorted ranges for O(log n) performance
            if not hasattr(self, cache_attr):
                # Sort ranges by start IP for binary search
                setattr(self, cache_attr, sorted(db.keys(), key=lambda x: x[0]))
            
            sorted_ranges = getattr(self, cache_attr)
            
            # Binary search for matching range
            left, right = 0, len(sorted_ranges) - 1
            while left <= right:
                mid = (left + right) // 2
                start_ip, end_ip = sorted_ranges[mid]
                
                if start_ip <= ip_int <= end_ip:
                    return db[(start_ip, end_ip)]
                elif ip_int < start_ip:
                    right = mid - 1
                else:
                    left = mid + 1
        except Exception as e:
            logger.debug(f"TSV lookup error for {ip_address}: {e}")
        
        return None
    
    def validate_ip_ownership(self, ip_address: str) -> Dict[str, Any]:
        """
        Validate IP address ownership and return expectations.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            Dictionary with ownership info, ASN, port expectations, etc.
        """
        result = {
            'ip': ip_address,
            'owned_by': 'unknown',
            'asn': None,
            'prefix': None,
            'type': 'unknown',
            'port_expectations': 'standard',
            'common_ports': [80, 443],
            'skip_scan': False,
            'validation_method': 'none',
            'confidence': 'low'
        }
        
        # Validate IP format (IPv4 or IPv6)
        is_ipv6 = False
        try:
            # Try IPv4 first
            socket.inet_aton(ip_address)
        except socket.error:
            try:
                # Try IPv6
                socket.inet_pton(socket.AF_INET6, ip_address)
                is_ipv6 = True
            except (socket.error, OSError):
                result['error'] = 'invalid_ip_format'
                return result
        
        result['ip_version'] = 'ipv6' if is_ipv6 else 'ipv4'
        
        # Try ASN database lookup (pyasn binary format)
        if self.asndb:
            try:
                asn, prefix = self.asndb.lookup(ip_address)
                if asn:
                    result['asn'] = asn
                    result['prefix'] = str(prefix) if prefix else None
                    result['validation_method'] = 'asn_database_pyasn'
                    result['confidence'] = 'high'
                    
                    # Look up company info
                    company_info = ASN_TO_COMPANY.get(asn)
                    if company_info:
                        result.update({
                            'owned_by': company_info['name'],
                            'type': company_info.get('type', 'unknown'),
                            'port_expectations': company_info.get('port_expectations', 'standard'),
                            'common_ports': company_info.get('common_ports', [80, 443]),
                            'skip_scan': company_info.get('skip_scan', False),
                            'note': company_info.get('note', '')
                        })
                    else:
                        result['owned_by'] = f'AS{asn}'
                        result['confidence'] = 'medium'
                    
                    return result
            except Exception as e:
                logger.debug(f"ASN lookup error for {ip_address}: {e}")
        
        # For IPv6, try BGP lookup first (no static database like IPv4)
        if is_ipv6:
            try:
                from artificial_intelligence.personalities.reconnaissance.ash.bgp_lookup_service import get_bgp_lookup_service
                
                bgp_service = get_bgp_lookup_service()
                bgp_data = bgp_service.lookup_ip(ip_address)
                
                if bgp_data.get('asn') and not bgp_data.get('error'):
                    result['asn'] = bgp_data.get('asn')
                    result['validation_method'] = 'bgp_lookup'
                    result['bgp_prefix'] = bgp_data.get('prefix')
                    result['bgp_country'] = bgp_data.get('country')
                    
                    # Look up company info from ASN
                    company_info = ASN_TO_COMPANY.get(bgp_data.get('asn'))
                    if company_info:
                        result.update({
                            'owned_by': company_info['name'],
                            'type': company_info.get('type', 'unknown'),
                            'port_expectations': company_info.get('port_expectations', 'standard'),
                            'common_ports': company_info.get('common_ports', [80, 443]),
                            'note': f"IPv6 address - ASN from BGP lookup"
                        })
                    else:
                        result['owned_by'] = f"ASN {bgp_data.get('asn')}"
                    
                    return result
            except ImportError:
                logger.debug("BGP lookup service not available for IPv6")
            except Exception as e:
                logger.debug(f"BGP lookup error for IPv6: {e}")
        
        # Try TSV database lookup (fallback - primarily for IPv4)
        if hasattr(self, 'tsv_loaded') and self.tsv_loaded:
            try:
                asn = self._lookup_asn_from_tsv(ip_address, is_ipv6=is_ipv6)
                if asn:
                    result['asn'] = asn
                    result['validation_method'] = 'asn_database_tsv'
                    result['confidence'] = 'high'
                    
                    # Look up company info
                    company_info = ASN_TO_COMPANY.get(asn)
                    if company_info:
                        result.update({
                            'owned_by': company_info['name'],
                            'type': company_info.get('type', 'unknown'),
                            'port_expectations': company_info.get('port_expectations', 'standard'),
                            'common_ports': company_info.get('common_ports', [80, 443]),
                            'skip_scan': company_info.get('skip_scan', False),
                            'note': company_info.get('note', '')
                        })
                    else:
                        result['owned_by'] = f'AS{asn}'
                        result['confidence'] = 'medium'
                    
                    return result
            except Exception as e:
                logger.debug(f"TSV ASN lookup error for {ip_address}: {e}")
        
        # Fallback: Try reverse DNS for common providers
        result['validation_method'] = 'reverse_dns_fallback'
        result['confidence'] = 'low'
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            hostname_lower = hostname.lower()
            
            # Check for known provider patterns
            if 'cloudflare' in hostname_lower or 'cf-' in hostname_lower:
                result.update({
                    'owned_by': 'Cloudflare (detected via DNS)',
                    'type': 'cdn_proxy',
                    'port_expectations': 'proxied_only',
                    'common_ports': [80, 443, 2052, 2082, 8080, 8443],
                    'confidence': 'medium'
                })
            elif 'amazonaws' in hostname_lower or 'aws' in hostname_lower:
                result.update({
                    'owned_by': 'Amazon/AWS (detected via DNS)',
                    'type': 'cloud_hosting',
                    'port_expectations': 'user_defined',
                    'common_ports': [22, 80, 443],
                    'confidence': 'medium'
                })
            elif 'google' in hostname_lower or 'gcp' in hostname_lower:
                result.update({
                    'owned_by': 'Google/GCP (detected via DNS)',
                    'type': 'cloud_hosting',
                    'port_expectations': 'user_defined',
                    'common_ports': [22, 80, 443],
                    'confidence': 'medium'
                })
            elif 'azure' in hostname_lower or 'microsoft' in hostname_lower:
                result.update({
                    'owned_by': 'Microsoft/Azure (detected via DNS)',
                    'type': 'cloud_hosting',
                    'port_expectations': 'user_defined',
                    'common_ports': [22, 80, 443],
                    'confidence': 'medium'
                })
        except (socket.herror, socket.gaierror):
            # Reverse DNS failed - IP might not have PTR record
            pass
        except Exception as e:
            logger.debug(f"Reverse DNS lookup error for {ip_address}: {e}")
        
        return result
    
    def filter_ports_by_ownership(self, ip_address: str, ports: List[int]) -> List[int]:
        """
        Filter ports based on IP ownership expectations.
        
        For example, Cloudflare only proxies certain ports, so we should
        prioritize those ports when scanning Cloudflare IPs.
        
        Args:
            ip_address: IP address to check
            ports: List of ports to filter
            
        Returns:
            Filtered list of ports based on ownership expectations
        """
        ownership = self.validate_ip_ownership(ip_address)
        
        # If it's a proxied service (like Cloudflare), only scan proxied ports
        if ownership.get('port_expectations') == 'proxied_only':
            common_ports = ownership.get('common_ports', [80, 443])
            filtered = [p for p in ports if p in common_ports]
            if filtered:
                logger.info(f"🌐 {ownership['owned_by']} IP detected - filtering to proxied ports: {filtered}")
                return filtered
            else:
                # If no common ports match, return standard web ports
                return [p for p in ports if p in [80, 443]]
        
        # For user-defined ports (AWS, GCP, Azure), scan all requested ports
        # but prioritize common ones
        if ownership.get('port_expectations') == 'user_defined':
            common_ports = ownership.get('common_ports', [])
            # Prioritize common ports but don't exclude others
            prioritized = [p for p in ports if p in common_ports]
            others = [p for p in ports if p not in common_ports]
            return prioritized + others
        
        # Standard expectations - scan all ports
        return ports
    
    def should_skip_scan(self, ip_address: str) -> tuple:
        """
        Determine if we should skip scanning this IP.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Tuple of (should_skip: bool, reason: str)
        """
        ownership = self.validate_ip_ownership(ip_address)
        
        if ownership.get('skip_scan'):
            reason = f"Infrastructure IP ({ownership['owned_by']})"
            return True, reason
        
        # Additional logic: Skip if low confidence and appears to be infrastructure
        if ownership.get('confidence') == 'low' and ownership.get('type') == 'isp':
            return True, "ISP infrastructure (low confidence)"
        
        return False, ""
    
    def build_network_object(self, asn: int, ip_version: str = 'ipv4') -> Dict[str, Any]:
        """
        Build a complete network object for an ASN by aggregating all CIDR blocks.
        
        Uses supernetting to reduce the number of CIDR blocks while maintaining
        the same coverage. This is essential for firewall rules and network analysis.
        Supports both IPv4 and IPv6.
        
        Args:
            asn: Autonomous System Number
            ip_version: 'ipv4' or 'ipv6' (default: 'ipv4')
            
        Returns:
            Dictionary with aggregated CIDR blocks, total IP count, etc.
        """
        if not hasattr(self, 'tsv_db') or not self.tsv_loaded:
            return {'asn': asn, 'error': 'Database not loaded'}
        
        # Select appropriate database
        is_ipv6 = (ip_version == 'ipv6')
        db = self.tsv_db_v6 if is_ipv6 else self.tsv_db
        if not db:
            return {'asn': asn, 'error': f'{ip_version} database not loaded'}
        
        # Collect all CIDR blocks for this ASN
        cidr_blocks = []
        for (start_ip, end_ip), block_asn in db.items():
            if block_asn == asn:
                # Convert IP range to CIDR notation
                try:
                    if is_ipv6:
                        start_addr = ipaddress.IPv6Address(start_ip)
                        end_addr = ipaddress.IPv6Address(end_ip)
                    else:
                        start_addr = ipaddress.IPv4Address(start_ip)
                        end_addr = ipaddress.IPv4Address(end_ip)
                    
                    # Create network object - summarize_address_range returns iterator
                    networks = list(ipaddress.summarize_address_range(start_addr, end_addr))
                    cidr_blocks.extend([str(net) for net in networks])
                except Exception as e:
                    logger.debug(f"Error converting range to CIDR: {e}")
                    continue
        
        if not cidr_blocks:
            return {'asn': asn, 'cidr_blocks': [], 'total_ips': 0, 'aggregated': False}
        
        # Aggregate (supernet) contiguous blocks using netaddr if available
        if NETADDR_AVAILABLE and len(cidr_blocks) > 1:
            try:
                # Convert to netaddr IPNetwork objects
                networks = [netaddr.IPNetwork(cidr) for cidr in cidr_blocks]
                # Supernet (aggregate) contiguous networks
                aggregated = netaddr.cidr_merge(networks)
                aggregated_cidrs = [str(net) for net in aggregated]
                
                reduction = len(cidr_blocks) - len(aggregated_cidrs)
                logger.debug(f"ASN {asn}: Aggregated {len(cidr_blocks)} blocks → {len(aggregated_cidrs)} blocks ({reduction} reduction)")
                
                # Calculate total IP count
                total_ips = sum(net.size for net in aggregated)
                
                return {
                    'asn': asn,
                    'cidr_blocks': aggregated_cidrs,
                    'original_count': len(cidr_blocks),
                    'aggregated_count': len(aggregated_cidrs),
                    'reduction': reduction,
                    'total_ips': total_ips,
                    'aggregated': True
                }
            except Exception as e:
                logger.warning(f"Supernetting failed for ASN {asn}: {e}, using original blocks")
        
        # Fallback: Use original blocks without aggregation
        total_ips = sum(ipaddress.ip_network(cidr).num_addresses for cidr in cidr_blocks)
        
        return {
            'asn': asn,
            'cidr_blocks': cidr_blocks,
            'total_ips': total_ips,
            'aggregated': False
        }
    
    def get_all_company_networks(self) -> Dict[str, Dict[str, Any]]:
        """
        Build network objects for all known companies in ASN_TO_COMPANY.
        
        Returns:
            Dictionary mapping company names to their network objects
        """
        networks = {}
        
        for asn, company_info in ASN_TO_COMPANY.items():
            company_name = company_info['name']
            network_obj = self.build_network_object(asn)
            networks[company_name] = {
                'asn': asn,
                'company_info': company_info,
                'network': network_obj
            }
        
        return networks
    
    def is_ip_in_network(self, ip_address: str, cidr_blocks: List[str]) -> bool:
        """
        Check if an IP address belongs to any of the given CIDR blocks.
        
        Supports both IPv4 and IPv6. Uses efficient membership testing.
        
        Args:
            ip_address: IP address to check (IPv4 or IPv6)
            cidr_blocks: List of CIDR blocks (e.g., ['104.16.0.0/12', '2001:4860::/32'])
            
        Returns:
            True if IP is in any of the blocks
        """
        try:
            # Detect IP version
            is_ipv6 = ':' in ip_address
            
            if is_ipv6:
                ip = ipaddress.IPv6Address(ip_address)
            else:
                ip = ipaddress.IPv4Address(ip_address)
            
            for cidr in cidr_blocks:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    # Only check if IP version matches
                    if isinstance(ip, type(network.network_address)):
                        if ip in network:
                            return True
                except (ValueError, ipaddress.AddressValueError):
                    continue
        except (ValueError, ipaddress.AddressValueError):
            pass
        
        return False
    
    def enhance_with_bgp_data(self, ip_address: str) -> Dict[str, Any]:
        """
        Enhance IP ownership data with real-time BGP lookup.
        
        Combines local ASN database with real-time BGP routing information
        for the most up-to-date ownership data.
        
        Args:
            ip_address: IP address to enhance
            
        Returns:
            Enhanced ownership dictionary with BGP data
        """
        # Get base ownership from local database
        ownership = self.validate_ip_ownership(ip_address)
        
        # Enhance with real-time BGP data if available
        try:
            from artificial_intelligence.personalities.reconnaissance.ash.bgp_lookup_service import get_bgp_lookup_service
            
            bgp_service = get_bgp_lookup_service()
            bgp_data = bgp_service.lookup_ip(ip_address)
            
            if bgp_data.get('asn') and not bgp_data.get('error'):
                # Update with real-time BGP data
                ownership['bgp_asn'] = bgp_data.get('asn')
                ownership['bgp_prefix'] = bgp_data.get('prefix')
                ownership['bgp_country'] = bgp_data.get('country')
                ownership['bgp_source'] = bgp_data.get('source')
                ownership['bgp_enhanced'] = True
                
                # If BGP ASN differs from local, prefer BGP (more current)
                if ownership.get('asn') != bgp_data.get('asn'):
                    logger.debug(f"BGP ASN ({bgp_data.get('asn')}) differs from local ({ownership.get('asn')}) - using BGP")
                    ownership['asn'] = bgp_data.get('asn')
                    ownership['confidence'] = 'high'  # BGP is authoritative
                    
                    # Re-lookup company info with BGP ASN
                    company_info = ASN_TO_COMPANY.get(bgp_data.get('asn'))
                    if company_info:
                        ownership.update({
                            'owned_by': company_info['name'],
                            'type': company_info.get('type', 'unknown'),
                            'port_expectations': company_info.get('port_expectations', 'standard'),
                            'common_ports': company_info.get('common_ports', [80, 443]),
                        })
        except ImportError:
            logger.debug("BGP lookup service not available")
        except Exception as e:
            logger.debug(f"BGP enhancement error: {e}")
        
        return ownership


# Global validator instance
_validator_instance = None

def get_ip_validator(asn_db_path: Optional[Path] = None) -> IPOwnershipValidator:
    """Get or create global IP ownership validator instance"""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = IPOwnershipValidator(asn_db_path)
    return _validator_instance

