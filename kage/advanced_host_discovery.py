#!/usr/bin/env python3
"""
Advanced Host Discovery for WAF Bypass
=======================================

Implements multiple host discovery techniques from Nmap:
- TCP SYN Ping
- TCP ACK Ping  
- UDP Ping
- ICMP Ping
- IP Protocol Ping
"""

import socket
import time
import struct
import requests
import warnings
import urllib3
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Suppress urllib3 SSL warnings - we detect and report SSL issues separately
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

logger = logging.getLogger(__name__)


class AdvancedHostDiscovery:
    """Advanced host discovery using multiple techniques."""
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
    
    def probe_tcp_syn(self, target: str, ports: List[int] = [80, 443, 22]) -> Dict[str, Any]:
        """
        TCP SYN Ping - sends SYN packets to ports.
        Often bypasses WAFs that only inspect HTTP/HTTPS.
        """
        results = []
        start_time = time.time()
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                probe_start = time.time()
                result = sock.connect_ex((target, port))
                probe_time = (time.time() - probe_start) * 1000
                sock.close()
                
                results.append({
                    'port': port,
                    'status': 'open' if result == 0 else 'filtered',
                    'response_time_ms': probe_time
                })
                
            except Exception as e:
                results.append({
                    'port': port,
                    'status': 'error',
                    'error': str(e)
                })
        
        duration = (time.time() - start_time) * 1000
        
        # Host is up if any port responded
        host_up = any(r.get('status') == 'open' for r in results)
        
        return {
            'technique': 'tcp_syn',
            'host_up': host_up,
            'ports_tested': ports,
            'results': results,
            'response_time_ms': duration
        }
    
    def probe_tcp_ack(self, target: str, ports: List[int] = [80, 443]) -> Dict[str, Any]:
        """
        TCP ACK Ping - sends ACK packets.
        Appears as established connection, bypasses stateful firewalls.
        """
        # Note: Full ACK ping requires raw sockets (root)
        # This is a simplified version using connect
        results = []
        start_time = time.time()
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                probe_start = time.time()
                result = sock.connect_ex((target, port))
                probe_time = (time.time() - probe_start) * 1000
                
                if result == 0:
                    # Send ACK (simplified - full implementation needs raw sockets)
                    sock.close()
                    results.append({
                        'port': port,
                        'status': 'open',
                        'response_time_ms': probe_time
                    })
                else:
                    sock.close()
                    results.append({
                        'port': port,
                        'status': 'filtered',
                        'response_time_ms': probe_time
                    })
                    
            except Exception as e:
                results.append({
                    'port': port,
                    'status': 'error',
                    'error': str(e)
                })
        
        duration = (time.time() - start_time) * 1000
        host_up = any(r.get('status') == 'open' for r in results)
        
        return {
            'technique': 'tcp_ack',
            'host_up': host_up,
            'ports_tested': ports,
            'results': results,
            'response_time_ms': duration
        }
    
    def probe_udp(self, target: str, ports: List[int] = [53, 161]) -> Dict[str, Any]:
        """
        UDP Ping - sends UDP packets.
        Many WAFs don't inspect UDP traffic.
        """
        results = []
        start_time = time.time()
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send UDP packet
                probe_start = time.time()
                sock.sendto(b'\x00', (target, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    probe_time = (time.time() - probe_start) * 1000
                    results.append({
                        'port': port,
                        'status': 'open',
                        'response_time_ms': probe_time
                    })
                except socket.timeout:
                    # UDP timeout might mean filtered or open
                    results.append({
                        'port': port,
                        'status': 'open|filtered',
                        'response_time_ms': self.timeout * 1000
                    })
                
                sock.close()
                
            except Exception as e:
                results.append({
                    'port': port,
                    'status': 'error',
                    'error': str(e)
                })
        
        duration = (time.time() - start_time) * 1000
        host_up = any(r.get('status') in ['open', 'open|filtered'] for r in results)
        
        return {
            'technique': 'udp',
            'host_up': host_up,
            'ports_tested': ports,
            'results': results,
            'response_time_ms': duration
        }
    
    def probe_icmp(self, target: str) -> Dict[str, Any]:
        """
        ICMP Ping - sends ICMP echo requests.
        Some WAFs allow ICMP for monitoring.
        """
        start_time = time.time()
        
        try:
            # Use system ping (simplified - full implementation needs raw sockets)
            import subprocess
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(int(self.timeout)), target],
                capture_output=True,
                timeout=self.timeout + 1
            )
            
            duration = (time.time() - start_time) * 1000
            host_up = result.returncode == 0
            
            return {
                'technique': 'icmp',
                'host_up': host_up,
                'response_time_ms': duration
            }
            
        except Exception as e:
            return {
                'technique': 'icmp',
                'host_up': False,
                'error': str(e),
                'response_time_ms': (time.time() - start_time) * 1000
            }
    
    def multi_probe_discovery(self, target: str, 
                            techniques: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Try multiple discovery techniques to bypass WAF.
        Returns first successful technique.
        """
        if techniques is None:
            techniques = ['tcp_syn_nonhttp', 'tcp_ack', 'udp_dns', 'icmp']
        
        results = []
        
        # Technique 1: TCP SYN to non-HTTP ports
        if 'tcp_syn_nonhttp' in techniques:
            probe = self.probe_tcp_syn(target, ports=[22, 25, 53, 3306])
            results.append(probe)
            if probe['host_up']:
                return {
                    'success': True,
                    'technique': 'tcp_syn_nonhttp',
                    'probe_result': probe,
                    'all_results': results
                }
        
        # Technique 2: TCP ACK
        if 'tcp_ack' in techniques:
            probe = self.probe_tcp_ack(target, ports=[80, 443])
            results.append(probe)
            if probe['host_up']:
                return {
                    'success': True,
                    'technique': 'tcp_ack',
                    'probe_result': probe,
                    'all_results': results
                }
        
        # Technique 3: UDP DNS
        if 'udp_dns' in techniques:
            probe = self.probe_udp(target, ports=[53])
            results.append(probe)
            if probe['host_up']:
                return {
                    'success': True,
                    'technique': 'udp_dns',
                    'probe_result': probe,
                    'all_results': results
                }
        
        # Technique 4: ICMP
        if 'icmp' in techniques:
            probe = self.probe_icmp(target)
            results.append(probe)
            if probe['host_up']:
                return {
                    'success': True,
                    'technique': 'icmp',
                    'probe_result': probe,
                    'all_results': results
                }
        
        # All techniques failed
        return {
            'success': False,
            'technique': None,
            'all_results': results
        }


