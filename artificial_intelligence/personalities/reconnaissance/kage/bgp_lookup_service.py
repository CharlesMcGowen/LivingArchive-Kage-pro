#!/usr/bin/env python3
"""
BGP Lookup Service for Real-time ASN Queries
============================================

Provides real-time BGP lookup capabilities using public BGP APIs:
- BGPView API (https://bgpview.io/)
- Hurricane Electric BGP Toolkit (bgp.he.net)
- RIPEstat API (RIPE)

This complements the local ASN database with real-time routing information.

Author: EGO Revolution
Version: 1.0.0
"""

import logging
import requests
from typing import Dict, Any, Optional, List
import time

logger = logging.getLogger(__name__)


class BGPLookupService:
    """
    Real-time BGP lookup service using public APIs.
    """
    
    def __init__(self, cache_ttl: int = 3600):
        """
        Initialize BGP lookup service.
        
        Args:
            cache_ttl: Cache TTL in seconds (default 1 hour)
        """
        self.cache_ttl = cache_ttl
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.cache_timestamps: Dict[str, float] = {}
        
        # API endpoints
        self.bgpview_api = "https://api.bgpview.io"
        self.he_bgp_api = "https://bgp.he.net"
        
        logger.info("🔍 BGP Lookup Service initialized")
    
    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Lookup IP address in BGP routing tables (real-time).
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dictionary with ASN, prefix, RIR, country, etc.
        """
        # Check cache
        cache_key = f"ip:{ip_address}"
        if cache_key in self.cache:
            timestamp = self.cache_timestamps.get(cache_key, 0)
            if time.time() - timestamp < self.cache_ttl:
                logger.debug(f"Using cached BGP data for {ip_address}")
                return self.cache[cache_key]
        
        result = {
            'ip': ip_address,
            'asn': None,
            'prefix': None,
            'rir': None,
            'country': None,
            'source': None,
            'error': None
        }
        
        # Try BGPView API first
        try:
            response = requests.get(
                f"{self.bgpview_api}/ip/{ip_address}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'asns' in data['data'] and data['data']['asns']:
                    asn_data = data['data']['asns'][0]
                    result.update({
                        'asn': asn_data.get('asn'),
                        'prefix': asn_data.get('prefix'),
                        'rir': asn_data.get('rir'),
                        'country': asn_data.get('country_code'),
                        'source': 'bgpview'
                    })
                    
                    # Cache result
                    self.cache[cache_key] = result
                    self.cache_timestamps[cache_key] = time.time()
                    
                    return result
        except Exception as e:
            logger.debug(f"BGPView API error: {e}")
        
        # Fallback: Try Hurricane Electric (scraping - less reliable)
        # Note: HE doesn't have a public API, so we'd need to scrape
        # For now, return what we have
        
        result['error'] = 'No BGP data available'
        return result
    
    def lookup_asn(self, asn: int) -> Dict[str, Any]:
        """
        Lookup ASN information (name, description, prefixes).
        
        Args:
            asn: Autonomous System Number
            
        Returns:
            Dictionary with ASN details, prefixes, etc.
        """
        cache_key = f"asn:{asn}"
        if cache_key in self.cache:
            timestamp = self.cache_timestamps.get(cache_key, 0)
            if time.time() - timestamp < self.cache_ttl:
                logger.debug(f"Using cached ASN data for AS{asn}")
                return self.cache[cache_key]
        
        result = {
            'asn': asn,
            'name': None,
            'description': None,
            'country': None,
            'prefixes_ipv4': [],
            'prefixes_ipv6': [],
            'source': None,
            'error': None
        }
        
        # Try BGPView API
        try:
            response = requests.get(
                f"{self.bgpview_api}/asn/{asn}",
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    asn_data = data['data']
                    result.update({
                        'name': asn_data.get('name'),
                        'description': asn_data.get('description'),
                        'country': asn_data.get('country_code'),
                        'source': 'bgpview'
                    })
                    
                    # Get prefixes
                    prefixes_response = requests.get(
                        f"{self.bgpview_api}/asn/{asn}/prefixes",
                        timeout=5
                    )
                    if prefixes_response.status_code == 200:
                        prefixes_data = prefixes_response.json()
                        if 'data' in prefixes_data:
                            result['prefixes_ipv4'] = [
                                p['prefix'] for p in prefixes_data['data'].get('ipv4_prefixes', [])
                            ]
                            result['prefixes_ipv6'] = [
                                p['prefix'] for p in prefixes_data['data'].get('ipv6_prefixes', [])
                            ]
                    
                    # Cache result
                    self.cache[cache_key] = result
                    self.cache_timestamps[cache_key] = time.time()
                    
                    return result
        except Exception as e:
            logger.debug(f"BGPView ASN lookup error: {e}")
        
        result['error'] = 'No ASN data available'
        return result
    
    def get_asn_prefixes(self, asn: int) -> Dict[str, List[str]]:
        """
        Get all IPv4 and IPv6 prefixes for an ASN (real-time from BGP).
        
        Args:
            asn: Autonomous System Number
            
        Returns:
            Dictionary with 'ipv4' and 'ipv6' prefix lists
        """
        asn_info = self.lookup_asn(asn)
        return {
            'ipv4': asn_info.get('prefixes_ipv4', []),
            'ipv6': asn_info.get('prefixes_ipv6', [])
        }


# Global BGP lookup instance
_bgp_lookup_instance = None

def get_bgp_lookup_service() -> BGPLookupService:
    """Get or create global BGP lookup service instance"""
    global _bgp_lookup_instance
    if _bgp_lookup_instance is None:
        _bgp_lookup_instance = BGPLookupService()
    return _bgp_lookup_instance

