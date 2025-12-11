#!/usr/bin/env python3
"""
Ryu's Metagross: Defensive Monitor Service
Keeps an eye on defenses, evaluating threats and weaknesses
"""

import logging
import requests
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class MetagrossDefensiveMonitor:
    """
    Metagross: Defensive Monitor
    Keeps an eye on defenses, evaluating threats and weaknesses.
    Uses Zen Headbutt and Bullet Punch for defensive analysis.
    """
    
    def __init__(self):
        self.logger = logger
        self.monitoring_targets = {}
        self.defense_metrics = {}
        
    def zen_headbutt_analysis(self, target_url: str) -> Dict[str, Any]:
        """
        Zen Headbutt: Defensive structure analysis
        Analyzes the defensive posture of the target system
        """
        self.logger.info(f"[Metagross] Zen Headbutt analysis on: {target_url}")
        
        results = {
            'target': target_url,
            'analysis_type': 'zen_headbutt',
            'timestamp': datetime.now().isoformat(),
            'defensive_structure': {},
            'weak_points': [],
            'recommendations': []
        }
        
        try:
            # Analyze defensive headers
            response = requests.get(target_url, timeout=10)
            results['defensive_structure'] = self._analyze_defensive_headers(response.headers)
            
            # Identify weak points
            results['weak_points'] = self._identify_weak_points(response)
            
            # Generate defensive recommendations
            results['recommendations'] = self._generate_defensive_recommendations(results)
            
        except Exception as e:
            self.logger.error(f"[Metagross] Zen Headbutt analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def bullet_punch_analysis(self, target_url: str) -> Dict[str, Any]:
        """
        Bullet Punch: Rapid threat evaluation
        Quickly evaluates potential threats and attack vectors
        """
        self.logger.info(f"[Metagross] Bullet Punch analysis on: {target_url}")
        
        results = {
            'target': target_url,
            'analysis_type': 'bullet_punch',
            'timestamp': datetime.now().isoformat(),
            'threat_vectors': [],
            'attack_surface': {},
            'vulnerability_score': 0
        }
        
        try:
            # Identify threat vectors
            results['threat_vectors'] = self._identify_threat_vectors(target_url)
            
            # Analyze attack surface
            results['attack_surface'] = self._analyze_attack_surface(target_url)
            
            # Calculate vulnerability score
            results['vulnerability_score'] = self._calculate_vulnerability_score(results)
            
        except Exception as e:
            self.logger.error(f"[Metagross] Bullet Punch analysis failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def _analyze_defensive_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze defensive security headers"""
        defensive_analysis = {
            'security_headers': {},
            'missing_protections': [],
            'defense_score': 0
        }
        
        # Check for security headers
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1',
            'Strict-Transport-Security': 'max-age',
            'Content-Security-Policy': 'default-src',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        for header, expected_value in security_headers.items():
            if header in headers:
                defensive_analysis['security_headers'][header] = headers[header]
                defensive_analysis['defense_score'] += 15
            else:
                defensive_analysis['missing_protections'].append(header)
        
        return defensive_analysis
    
    def _identify_weak_points(self, response) -> List[Dict[str, Any]]:
        """Identify weak points in the defensive structure"""
        weak_points = []
        
        # Check for information disclosure
        if 'Server' in response.headers:
            weak_points.append({
                'type': 'information_disclosure',
                'description': 'Server version information exposed',
                'severity': 'low'
            })
        
        # Check for missing security headers
        if 'X-Content-Type-Options' not in response.headers:
            weak_points.append({
                'type': 'missing_protection',
                'description': 'X-Content-Type-Options header missing',
                'severity': 'medium'
            })
        
        # Check for weak authentication
        if 'WWW-Authenticate' in response.headers:
            weak_points.append({
                'type': 'authentication',
                'description': 'Basic authentication detected',
                'severity': 'medium'
            })
        
        return weak_points
    
    def _generate_defensive_recommendations(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate defensive recommendations"""
        recommendations = []
        
        # Check for missing protections
        if analysis_results['defensive_structure']['missing_protections']:
            recommendations.append("Implement missing security headers")
        
        # Check for weak points
        if analysis_results['weak_points']:
            recommendations.append("Address identified weak points")
        
        # Check defense score
        if analysis_results['defensive_structure']['defense_score'] < 60:
            recommendations.append("Strengthen overall defensive posture")
        
        return recommendations
    
    def _identify_threat_vectors(self, target_url: str) -> List[Dict[str, Any]]:
        """Identify potential threat vectors"""
        threat_vectors = []
        
        # Common attack paths
        attack_paths = [
            '/admin',
            '/login',
            '/api',
            '/upload',
            '/config',
            '/backup'
        ]
        
        for path in attack_paths:
            try:
                test_url = f"{target_url}{path}"
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    threat_vectors.append({
                        'path': path,
                        'accessible': True,
                        'risk_level': 'medium' if 'admin' in path or 'login' in path else 'low'
                    })
            except:
                pass
        
        return threat_vectors
    
    def _analyze_attack_surface(self, target_url: str) -> Dict[str, Any]:
        """Analyze the attack surface"""
        attack_surface = {
            'open_ports': [],
            'services': [],
            'technologies': [],
            'exposed_endpoints': []
        }
        
        # This would typically involve port scanning and service detection
        # For now, we'll do basic HTTP analysis
        try:
            response = requests.get(target_url, timeout=10)
            
            # Analyze headers for technology stack
            server_header = response.headers.get('Server', '')
            if server_header:
                attack_surface['technologies'].append(f"Server: {server_header}")
            
            # Check for exposed APIs
            if '/api' in response.text:
                attack_surface['exposed_endpoints'].append('/api')
        
        except Exception as e:
            self.logger.error(f"Attack surface analysis failed: {e}")
        
        return attack_surface
    
    def _calculate_vulnerability_score(self, results: Dict[str, Any]) -> int:
        """Calculate vulnerability score based on analysis"""
        score = 0
        
        # Add points for each threat vector
        for vector in results['threat_vectors']:
            if vector['accessible']:
                if vector['risk_level'] == 'high':
                    score += 30
                elif vector['risk_level'] == 'medium':
                    score += 20
                else:
                    score += 10
        
        # Add points for exposed technologies
        score += len(results['attack_surface']['technologies']) * 5
        
        return min(score, 100)  # Cap at 100
    
    def start_monitoring(self, target_url: str, interval_minutes: int = 60):
        """Start continuous monitoring of a target"""
        self.logger.info(f"[Metagross] Starting monitoring of: {target_url}")
        
        self.monitoring_targets[target_url] = {
            'interval': interval_minutes,
            'last_check': None,
            'status': 'monitoring'
        }
    
    def stop_monitoring(self, target_url: str):
        """Stop monitoring a target"""
        if target_url in self.monitoring_targets:
            del self.monitoring_targets[target_url]
            self.logger.info(f"[Metagross] Stopped monitoring: {target_url}")
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        return {
            'monitoring_targets': len(self.monitoring_targets),
            'targets': list(self.monitoring_targets.keys()),
            'defense_metrics': self.defense_metrics
        }


