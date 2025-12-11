#!/usr/bin/env python3
"""
Ryu's Xatu: Network Guardian Service
Stays vigilantly connected, overseeing the integrity of network pathways
"""

import logging
import requests
import socket
import ssl
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class XatuNetworkGuardian:
    """
    Xatu: Network Guardian
    Stays vigilantly connected, overseeing the integrity of network pathways.
    Uses Miracle Eye and Psychic for network monitoring and analysis.
    """
    
    def __init__(self):
        self.logger = logger
        self.network_monitoring = {}
        self.connection_integrity = {}
        
    def miracle_eye_analysis(self, target_url: str) -> Dict[str, Any]:
        """
        Miracle Eye: Network pathway analysis
        Analyzes network pathways and connection integrity
        """
        self.logger.info(f"[Xatu] Miracle Eye analysis on: {target_url}")
        
        results = {
            'target': target_url,
            'analysis_type': 'miracle_eye',
            'timestamp': datetime.now().isoformat(),
            'network_pathways': {},
            'connection_integrity': {},
            'security_issues': [],
            'recommendations': []
        }
        
        try:
            parsed_url = urlparse(target_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            # Analyze network pathways
            results['network_pathways'] = self._analyze_network_pathways(hostname, port)
            
            # Check connection integrity
            results['connection_integrity'] = self._check_connection_integrity(hostname, port)
            
            # Identify security issues
            results['security_issues'] = self._identify_network_security_issues(target_url)
            
            # Generate recommendations
            results['recommendations'] = self._generate_network_recommendations(results)
            
        except Exception as e:
            self.logger.error(f"[Xatu] Miracle Eye analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def psychic_network_analysis(self, target_url: str) -> Dict[str, Any]:
        """
        Psychic: Deep network analysis
        Performs comprehensive network security analysis
        """
        self.logger.info(f"[Xatu] Psychic network analysis on: {target_url}")
        
        results = {
            'target': target_url,
            'analysis_type': 'psychic_network',
            'timestamp': datetime.now().isoformat(),
            'ssl_analysis': {},
            'dns_analysis': {},
            'network_security': {},
            'threat_indicators': []
        }
        
        try:
            parsed_url = urlparse(target_url)
            hostname = parsed_url.hostname
            
            # SSL/TLS analysis
            results['ssl_analysis'] = self._analyze_ssl_security(hostname)
            
            # DNS analysis
            results['dns_analysis'] = self._analyze_dns_security(hostname)
            
            # Network security assessment
            results['network_security'] = self._assess_network_security(target_url)
            
            # Identify threat indicators
            results['threat_indicators'] = self._identify_threat_indicators(target_url)
            
        except Exception as e:
            self.logger.error(f"[Xatu] Psychic network analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_network_pathways(self, hostname: str, port: int) -> Dict[str, Any]:
        """Analyze network pathways to the target"""
        pathway_analysis = {
            'hostname': hostname,
            'port': port,
            'connectivity': False,
            'response_time': 0,
            'route_trace': [],
            'network_quality': 'unknown'
        }
        
        try:
            # Test connectivity
            start_time = datetime.now()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((hostname, port))
            end_time = datetime.now()
            
            pathway_analysis['connectivity'] = result == 0
            pathway_analysis['response_time'] = (end_time - start_time).total_seconds()
            
            if pathway_analysis['response_time'] < 1:
                pathway_analysis['network_quality'] = 'excellent'
            elif pathway_analysis['response_time'] < 3:
                pathway_analysis['network_quality'] = 'good'
            elif pathway_analysis['response_time'] < 5:
                pathway_analysis['network_quality'] = 'fair'
            else:
                pathway_analysis['network_quality'] = 'poor'
            
            sock.close()
            
        except Exception as e:
            self.logger.error(f"Network pathway analysis failed: {e}")
            pathway_analysis['error'] = str(e)
        
        return pathway_analysis
    
    def _check_connection_integrity(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check the integrity of network connections"""
        integrity_check = {
            'connection_stable': False,
            'packet_loss': 0,
            'latency': 0,
            'integrity_score': 0
        }
        
        try:
            # Perform multiple connection tests
            test_results = []
            for i in range(3):
                start_time = datetime.now()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((hostname, port))
                end_time = datetime.now()
                
                test_results.append({
                    'success': result == 0,
                    'latency': (end_time - start_time).total_seconds()
                })
                sock.close()
            
            # Calculate integrity metrics
            successful_connections = sum(1 for test in test_results if test['success'])
            integrity_check['connection_stable'] = successful_connections >= 2
            integrity_check['packet_loss'] = (3 - successful_connections) / 3 * 100
            integrity_check['latency'] = sum(test['latency'] for test in test_results) / len(test_results)
            
            # Calculate integrity score
            if integrity_check['connection_stable']:
                integrity_check['integrity_score'] += 50
            if integrity_check['packet_loss'] < 10:
                integrity_check['integrity_score'] += 30
            if integrity_check['latency'] < 2:
                integrity_check['integrity_score'] += 20
            
        except Exception as e:
            self.logger.error(f"Connection integrity check failed: {e}")
            integrity_check['error'] = str(e)
        
        return integrity_check
    
    def _identify_network_security_issues(self, target_url: str) -> List[Dict[str, Any]]:
        """Identify network security issues"""
        security_issues = []
        
        try:
            parsed_url = urlparse(target_url)
            
            # Check for HTTP vs HTTPS
            if parsed_url.scheme == 'http':
                security_issues.append({
                    'type': 'insecure_protocol',
                    'description': 'HTTP connection not encrypted',
                    'severity': 'high',
                    'recommendation': 'Upgrade to HTTPS'
                })
            
            # Check for mixed content
            if parsed_url.scheme == 'https':
                try:
                    response = requests.get(target_url, timeout=10)
                    if 'http://' in response.text:
                        security_issues.append({
                            'type': 'mixed_content',
                            'description': 'Mixed HTTP/HTTPS content detected',
                            'severity': 'medium',
                            'recommendation': 'Use HTTPS for all resources'
                        })
                except:
                    pass
            
        except Exception as e:
            self.logger.error(f"Network security issue identification failed: {e}")
        
        return security_issues
    
    def _generate_network_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate network security recommendations"""
        recommendations = []
        
        # Check connection integrity
        if 'connection_integrity' in analysis_results:
            integrity = analysis_results['connection_integrity']
            if not integrity.get('connection_stable', False):
                recommendations.append("Improve network stability and reliability")
            if integrity.get('packet_loss', 0) > 5:
                recommendations.append("Address network packet loss issues")
        
        # Check for security issues
        security_issues = analysis_results.get('security_issues', [])
        for issue in security_issues:
            if issue['type'] == 'insecure_protocol':
                recommendations.append("Implement HTTPS encryption")
            elif issue['type'] == 'mixed_content':
                recommendations.append("Ensure all content uses HTTPS")
        
        return recommendations
    
    def _analyze_ssl_security(self, hostname: str) -> Dict[str, Any]:
        """Analyze SSL/TLS security"""
        ssl_analysis = {
            'ssl_enabled': False,
            'certificate_valid': False,
            'ssl_version': None,
            'cipher_suite': None,
            'security_rating': 'unknown'
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and analyze SSL
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_analysis['ssl_enabled'] = True
                    ssl_analysis['ssl_version'] = ssock.version()
                    ssl_analysis['cipher_suite'] = ssock.cipher()
                    
                    # Check certificate
                    cert = ssock.getpeercert()
                    ssl_analysis['certificate_valid'] = cert is not None
                    
                    # Determine security rating
                    if ssl_analysis['ssl_version'] in ['TLSv1.2', 'TLSv1.3']:
                        ssl_analysis['security_rating'] = 'good'
                    elif ssl_analysis['ssl_version'] in ['TLSv1.1', 'TLSv1.0']:
                        ssl_analysis['security_rating'] = 'fair'
                    else:
                        ssl_analysis['security_rating'] = 'poor'
        
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {e}")
            ssl_analysis['error'] = str(e)
        
        return ssl_analysis
    
    def _analyze_dns_security(self, hostname: str) -> Dict[str, Any]:
        """Analyze DNS security"""
        dns_analysis = {
            'dns_resolution': False,
            'dns_servers': [],
            'dnssec_enabled': False,
            'dns_security': 'unknown'
        }
        
        try:
            # Test DNS resolution
            import socket
            ip_addresses = socket.gethostbyname_ex(hostname)
            dns_analysis['dns_resolution'] = len(ip_addresses[2]) > 0
            dns_analysis['dns_servers'] = ip_addresses[2]
            
            # Basic DNS security assessment
            if dns_analysis['dns_resolution']:
                dns_analysis['dns_security'] = 'basic'
            else:
                dns_analysis['dns_security'] = 'poor'
        
        except Exception as e:
            self.logger.error(f"DNS analysis failed: {e}")
            dns_analysis['error'] = str(e)
        
        return dns_analysis
    
    def _assess_network_security(self, target_url: str) -> Dict[str, Any]:
        """Assess overall network security"""
        security_assessment = {
            'overall_rating': 'unknown',
            'encryption_status': 'unknown',
            'network_protection': 'unknown',
            'recommendations': []
        }
        
        try:
            parsed_url = urlparse(target_url)
            
            # Check encryption
            if parsed_url.scheme == 'https':
                security_assessment['encryption_status'] = 'enabled'
                security_assessment['overall_rating'] = 'good'
            else:
                security_assessment['encryption_status'] = 'disabled'
                security_assessment['overall_rating'] = 'poor'
                security_assessment['recommendations'].append('Enable HTTPS encryption')
            
            # Basic network protection assessment
            security_assessment['network_protection'] = 'basic'
        
        except Exception as e:
            self.logger.error(f"Network security assessment failed: {e}")
            security_assessment['error'] = str(e)
        
        return security_assessment
    
    def _identify_threat_indicators(self, target_url: str) -> List[Dict[str, Any]]:
        """Identify potential threat indicators"""
        threat_indicators = []
        
        try:
            # Check for suspicious patterns in URL
            if any(pattern in target_url.lower() for pattern in ['admin', 'login', 'config', 'backup']):
                threat_indicators.append({
                    'type': 'sensitive_endpoint',
                    'description': 'Sensitive endpoint detected in URL',
                    'severity': 'medium'
                })
            
            # Check for IP addresses in URL (potential direct access)
            import re
            if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', target_url):
                threat_indicators.append({
                    'type': 'direct_ip_access',
                    'description': 'Direct IP address access detected',
                    'severity': 'low'
                })
        
        except Exception as e:
            self.logger.error(f"Threat indicator identification failed: {e}")
        
        return threat_indicators
    
    def start_network_monitoring(self, target_url: str, interval_minutes: int = 30):
        """Start continuous network monitoring"""
        self.logger.info(f"[Xatu] Starting network monitoring of: {target_url}")
        
        self.network_monitoring[target_url] = {
            'interval': interval_minutes,
            'last_check': None,
            'status': 'monitoring',
            'alerts': []
        }
    
    def stop_network_monitoring(self, target_url: str):
        """Stop network monitoring"""
        if target_url in self.network_monitoring:
            del self.network_monitoring[target_url]
            self.logger.info(f"[Xatu] Stopped network monitoring: {target_url}")
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get current network monitoring status"""
        return {
            'monitoring_targets': len(self.network_monitoring),
            'targets': list(self.network_monitoring.keys()),
            'connection_integrity': self.connection_integrity
        }


