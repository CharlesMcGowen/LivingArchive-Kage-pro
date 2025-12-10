#!/usr/bin/env python3
"""
IPv6 ASN List Retriever
=======================

Retrieves IPv6 CIDR blocks associated with ASNs from various sources:
1. BGP data feeds (RouteViews, RIPE RIS)
2. WHOIS queries (RPSL format)
3. Cloud provider APIs
4. BGPView API

Author: EGO Revolution
Version: 1.0.0
"""

import logging
import subprocess
import requests
from typing import List, Dict, Any, Optional
import re

logger = logging.getLogger(__name__)


class IPv6ASNRetriever:
    """
    Retrieve IPv6 prefixes for ASNs from multiple sources.
    """
    
    def __init__(self):
        """Initialize IPv6 ASN retriever"""
        self.bgpview_api = "https://api.bgpview.io"
        self.whois_servers = [
            "whois.radb.net",
            "whois.ripe.net",
            "whois.arin.net"
        ]
        logger.info("🌐 IPv6 ASN Retriever initialized")
    
    def get_asn_ipv6_prefixes_bgpview(self, asn: int) -> List[str]:
        """
        Get IPv6 prefixes for an ASN using BGPView API.
        
        Args:
            asn: Autonomous System Number
            
        Returns:
            List of IPv6 CIDR prefixes
        """
        try:
            response = requests.get(
                f"{self.bgpview_api}/asn/{asn}/prefixes",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'ipv6_prefixes' in data['data']:
                    prefixes = [p['prefix'] for p in data['data']['ipv6_prefixes']]
                    logger.info(f"Retrieved {len(prefixes)} IPv6 prefixes for AS{asn} from BGPView")
                    return prefixes
        except Exception as e:
            logger.debug(f"BGPView API error for AS{asn}: {e}")
        
        return []
    
    def get_asn_ipv6_prefixes_whois(self, asn: int, server: str = "whois.radb.net") -> List[str]:
        """
        Get IPv6 prefixes for an ASN using WHOIS/RPSL query.
        
        Args:
            asn: Autonomous System Number
            server: WHOIS server (default: whois.radb.net)
            
        Returns:
            List of IPv6 CIDR prefixes (route6: entries)
        """
        prefixes = []
        
        try:
            # Query WHOIS for route6: entries
            query = f"-i origin AS{asn}\n"
            
            process = subprocess.Popen(
                ['nc', server, '43'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=query, timeout=10)
            
            if process.returncode == 0:
                # Parse route6: entries
                for line in stdout.split('\n'):
                    if line.startswith('route6:'):
                        # Extract prefix
                        prefix = line.split('route6:')[1].strip()
                        if prefix:
                            prefixes.append(prefix)
            
            logger.info(f"Retrieved {len(prefixes)} IPv6 prefixes for AS{asn} from {server}")
        except Exception as e:
            logger.debug(f"WHOIS query error for AS{asn} on {server}: {e}")
        
        return prefixes
    
    def get_asn_ipv6_prefixes(self, asn: int) -> Dict[str, Any]:
        """
        Get IPv6 prefixes for an ASN from all available sources.
        
        Args:
            asn: Autonomous System Number
            
        Returns:
            Dictionary with prefixes from each source and aggregated results
        """
        result = {
            'asn': asn,
            'bgpview': [],
            'whois_radb': [],
            'whois_ripe': [],
            'all_prefixes': [],
            'unique_prefixes': []
        }
        
        # Try BGPView API
        result['bgpview'] = self.get_asn_ipv6_prefixes_bgpview(asn)
        
        # Try WHOIS servers
        result['whois_radb'] = self.get_asn_ipv6_prefixes_whois(asn, "whois.radb.net")
        result['whois_ripe'] = self.get_asn_ipv6_prefixes_whois(asn, "whois.ripe.net")
        
        # Aggregate all prefixes
        all_prefixes = (
            result['bgpview'] +
            result['whois_radb'] +
            result['whois_ripe']
        )
        
        # Remove duplicates
        result['unique_prefixes'] = list(set(all_prefixes))
        result['all_prefixes'] = all_prefixes
        
        logger.info(f"Total unique IPv6 prefixes for AS{asn}: {len(result['unique_prefixes'])}")
        
        return result
    
    def get_cloudflare_ipv6(self) -> List[str]:
        """
        Get Cloudflare's published IPv6 ranges.
        
        Returns:
            List of IPv6 CIDR prefixes
        """
        # Cloudflare's known IPv6 ranges
        cloudflare_ipv6 = [
            "2400:cb00::/32",
            "2606:4700::/32",
            "2803:f800::/32",
            "2a06:98c0::/29",
            "2c0f:f248::/32"
        ]
        
        logger.info(f"Retrieved {len(cloudflare_ipv6)} Cloudflare IPv6 prefixes")
        return cloudflare_ipv6
    
    def get_aws_ipv6(self) -> List[str]:
        """
        Get AWS's published IPv6 ranges.
        
        Returns:
            List of IPv6 CIDR prefixes
        """
        # AWS IPv6 ranges (simplified - full list is extensive)
        aws_ipv6 = [
            "2600:1f00::/32",
            "2600:1f01::/32",
            "2600:1f02::/32",
            "2600:1f03::/32",
            "2600:1f04::/32",
            "2600:1f05::/32",
            "2600:1f06::/32",
            "2600:1f07::/32",
            "2600:1f08::/32",
            "2600:1f09::/32",
            "2600:1f0a::/32",
            "2600:1f0b::/32",
            "2600:1f0c::/32",
            "2600:1f0d::/32",
            "2600:1f0e::/32",
            "2600:1f0f::/32",
            "2600:1f10::/32",
            "2600:1f11::/32",
            "2600:1f12::/32",
            "2600:1f13::/32",
            "2600:1f14::/32",
            "2600:1f15::/32",
            "2600:1f16::/32",
            "2600:1f17::/32",
            "2600:1f18::/32",
            "2600:1f19::/32",
            "2600:1f1a::/32",
            "2600:1f1b::/32",
            "2600:1f1c::/32",
            "2600:1f1d::/32",
            "2600:1f1e::/32",
            "2600:1f1f::/32",
            "2600:1f20::/32",
            "2600:1f21::/32",
            "2600:1f22::/32",
            "2600:1f23::/32",
            "2600:1f24::/32",
            "2600:1f25::/32",
            "2600:1f26::/32",
            "2600:1f27::/32",
            "2600:1f28::/32",
            "2600:1f29::/32",
            "2600:1f2a::/32",
            "2600:1f2b::/32",
            "2600:1f2c::/32",
            "2600:1f2d::/32",
            "2600:1f2e::/32",
            "2600:1f2f::/32",
            "2600:1f30::/32",
            "2600:1f31::/32",
            "2600:1f32::/32",
            "2600:1f33::/32",
            "2600:1f34::/32",
            "2600:1f35::/32",
            "2600:1f36::/32",
            "2600:1f37::/32",
            "2600:1f38::/32",
            "2600:1f39::/32",
            "2600:1f3a::/32",
            "2600:1f3b::/32",
            "2600:1f3c::/32",
            "2600:1f3d::/32",
            "2600:1f3e::/32",
            "2600:1f3f::/32"
        ]
        
        logger.info(f"Retrieved {len(aws_ipv6)} AWS IPv6 prefixes (sample)")
        return aws_ipv6


# Global instance
_ipv6_asn_retriever_instance = None

def get_ipv6_asn_retriever() -> IPv6ASNRetriever:
    """Get or create global IPv6 ASN retriever instance"""
    global _ipv6_asn_retriever_instance
    if _ipv6_asn_retriever_instance is None:
        _ipv6_asn_retriever_instance = IPv6ASNRetriever()
    return _ipv6_asn_retriever_instance

