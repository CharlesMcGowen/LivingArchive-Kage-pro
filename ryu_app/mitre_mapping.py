"""
MITRE ATT&CK Framework Mapping Module
=====================================

Maps reconnaissance findings, vulnerabilities, and discovered assets
to specific MITRE ATT&CK techniques.

This module provides intelligent mapping from agent discoveries to the
MITRE ATT&CK framework, enabling security intelligence and compliance tracking.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MITRETechnique:
    """Represents a MITRE ATT&CK technique with metadata"""
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    confidence: float  # 0.0 to 1.0
    relevance: str  # 'high', 'medium', 'low'


class MITREMapper:
    """
    Maps security findings to MITRE ATT&CK techniques.
    
    Uses pattern matching, keyword analysis, and service detection
    to identify relevant MITRE techniques for discovered assets and vulnerabilities.
    """
    
    def __init__(self):
        self.technique_mappings = self._build_technique_mappings()
        self.service_patterns = self._build_service_patterns()
        self.path_patterns = self._build_path_patterns()
        self.vulnerability_patterns = self._build_vulnerability_patterns()
    
    def _build_technique_mappings(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Comprehensive mapping of findings to MITRE techniques.
        
        Structure:
        {
            'pattern_type': [
                {
                    'pattern': regex or string,
                    'techniques': [
                        {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'confidence': 0.9}
                    ]
                }
            ]
        }
        """
        return {
            'wordpress': [
                {
                    'pattern': r'/wp-admin|wp-login|wp-config',
                    'techniques': [
                        {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'confidence': 0.8},
                        {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'confidence': 0.7},
                        {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.9},
                    ]
                },
                {
                    'pattern': r'wp-content/uploads|wp-includes',
                    'techniques': [
                        {'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery', 'confidence': 0.8},
                        {'id': 'T1070', 'name': 'Indicator Removal on Host', 'tactic': 'Defense Evasion', 'confidence': 0.6},
                    ]
                },
            ],
            'api_endpoints': [
                {
                    'pattern': r'/api/v\d+|/rest/api|/graphql|/odata',
                    'techniques': [
                        {'id': 'T1505', 'name': 'Server Software Component', 'tactic': 'Persistence', 'confidence': 0.8},
                        {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'confidence': 0.9},
                        {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.85},
                    ]
                },
                {
                    'pattern': r'/api/admin|/api/users|/api/config',
                    'techniques': [
                        {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'confidence': 0.9},
                        {'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery', 'confidence': 0.8},
                    ]
                },
            ],
            'admin_panels': [
                {
                    'pattern': r'/admin|/administrator|/management|/console',
                    'techniques': [
                        {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'confidence': 0.9},
                        {'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery', 'confidence': 0.85},
                        {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.8},
                    ]
                },
            ],
            'file_disclosure': [
                {
                    'pattern': r'\.git|\.env|\.config|\.bak|\.old|backup',
                    'techniques': [
                        {'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery', 'confidence': 0.9},
                        {'id': 'T1552', 'name': 'Unsecured Credentials', 'tactic': 'Credential Access', 'confidence': 0.85},
                        {'id': 'T1070', 'name': 'Indicator Removal on Host', 'tactic': 'Defense Evasion', 'confidence': 0.7},
                    ]
                },
            ],
            'database_services': [
                {
                    'pattern': r'mysql|postgresql|mongodb|redis|elasticsearch',
                    'techniques': [
                        {'id': 'T1505', 'name': 'Server Software Component', 'tactic': 'Persistence', 'confidence': 0.8},
                        {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'confidence': 0.7},
                        {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.75},
                    ]
                },
            ],
            'ssh_services': [
                {
                    'pattern': r'ssh|openssh',
                    'techniques': [
                        {'id': 'T1021', 'name': 'Remote Services', 'tactic': 'Lateral Movement', 'confidence': 0.9},
                        {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'confidence': 0.85},
                        {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.8},
                    ]
                },
            ],
            'ftp_services': [
                {
                    'pattern': r'ftp|vsftpd|proftpd',
                    'techniques': [
                        {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'confidence': 0.8},
                        {'id': 'T1021', 'name': 'Remote Services', 'tactic': 'Lateral Movement', 'confidence': 0.75},
                        {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.8},
                    ]
                },
            ],
            'web_servers': [
                {
                    'pattern': r'apache|nginx|iis|tomcat',
                    'techniques': [
                        {'id': 'T1505', 'name': 'Server Software Component', 'tactic': 'Persistence', 'confidence': 0.7},
                        {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'confidence': 0.8},
                        {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.75},
                    ]
                },
            ],
            'sensitive_paths': [
                {
                    'pattern': r'/\.git/|/\.env|/config\.|/backup|/dump|/sql',
                    'techniques': [
                        {'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery', 'confidence': 0.95},
                        {'id': 'T1552', 'name': 'Unsecured Credentials', 'tactic': 'Credential Access', 'confidence': 0.9},
                    ]
                },
            ],
        }
    
    def _build_service_patterns(self) -> Dict[str, List[str]]:
        """Service name patterns for common technologies"""
        return {
            'wordpress': ['wordpress', 'wp-', 'wp_'],
            'drupal': ['drupal'],
            'joomla': ['joomla'],
            'magento': ['magento'],
            'shopify': ['shopify'],
            'api': ['api', 'rest', 'graphql', 'odata', 'soap'],
            'database': ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'cassandra'],
            'remote_access': ['ssh', 'rdp', 'vnc', 'telnet'],
            'file_transfer': ['ftp', 'sftp', 'tftp'],
        }
    
    def _build_path_patterns(self) -> Dict[str, List[str]]:
        """Path patterns that indicate specific attack vectors"""
        return {
            'admin': ['/admin', '/administrator', '/wp-admin', '/manager', '/console'],
            'api': ['/api/', '/rest/', '/graphql', '/odata', '/v1/', '/v2/'],
            'config': ['/.env', '/config.php', '/config.json', '/.config', '/settings'],
            'backup': ['/backup', '/backups', '/dump', '/.bak', '/.old'],
            'git': ['/.git/', '/.git/config', '/.gitignore'],
        }
    
    def _build_vulnerability_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Vulnerability type to MITRE technique mappings"""
        return {
            'sql_injection': [
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.95},
                {'id': 'T1505', 'name': 'Server Software Component', 'tactic': 'Persistence', 'confidence': 0.8},
            ],
            'xss': [
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.9},
                {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution', 'confidence': 0.85},
            ],
            'rce': [
                {'id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution', 'confidence': 0.95},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.9},
            ],
            'lfi': [
                {'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery', 'confidence': 0.9},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.85},
            ],
            'authentication_bypass': [
                {'id': 'T1078', 'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'confidence': 0.95},
                {'id': 'T1190', 'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access', 'confidence': 0.9},
            ],
            'credential_exposure': [
                {'id': 'T1552', 'name': 'Unsecured Credentials', 'tactic': 'Credential Access', 'confidence': 0.95},
                {'id': 'T1083', 'name': 'File and Directory Discovery', 'tactic': 'Discovery', 'confidence': 0.85},
            ],
        }
    
    def map_finding_to_mitre_techniques(
        self,
        finding: Dict[str, Any],
        finding_type: Optional[str] = None
    ) -> List[MITRETechnique]:
        """
        Maps a security finding to relevant MITRE ATT&CK techniques.
        
        Args:
            finding: Dictionary containing finding details with keys like:
                - 'path' or 'url': Path or URL discovered
                - 'service_name': Service name detected
                - 'vulnerability_type': Type of vulnerability
                - 'description': Description of the finding
            finding_type: Optional explicit type ('wordpress', 'api', 'vulnerability', etc.)
        
        Returns:
            List of MITRETechnique objects sorted by confidence (highest first)
        """
        techniques = []
        technique_ids_seen = set()
        
        # Extract relevant fields
        path = finding.get('path', '') or finding.get('url', '') or finding.get('matched_path', '') or ''
        url = finding.get('url', '') or finding.get('matched_url', '') or ''
        service_name = (finding.get('service_name', '') or '').lower()
        vulnerability_type = (finding.get('vulnerability_type', '') or '').lower()
        description = (finding.get('description', '') or finding.get('vulnerability_name', '') or '').lower()
        full_text = f"{path} {url} {service_name} {description}".lower()
        
        # Check vulnerability patterns first (highest priority)
        if vulnerability_type:
            for vuln_type, tech_list in self.vulnerability_patterns.items():
                if vuln_type in vulnerability_type:
                    for tech in tech_list:
                        tech_id = tech['id']
                        if tech_id not in technique_ids_seen:
                            techniques.append(MITRETechnique(
                                technique_id=tech_id,
                                technique_name=tech['name'],
                                tactic=tech['tactic'],
                                description=f"Mapped from {vuln_type} vulnerability",
                                confidence=tech['confidence'],
                                relevance='high'
                            ))
                            technique_ids_seen.add(tech_id)
        
        # Check path/URL patterns
        for category, pattern_list in self.technique_mappings.items():
            for pattern_item in pattern_list:
                pattern = pattern_item['pattern']
                if isinstance(pattern, str):
                    # Try as regex
                    try:
                        if re.search(pattern, full_text, re.IGNORECASE):
                            for tech in pattern_item['techniques']:
                                tech_id = tech['id']
                                if tech_id not in technique_ids_seen:
                                    techniques.append(MITRETechnique(
                                        technique_id=tech_id,
                                        technique_name=tech['name'],
                                        tactic=tech['tactic'],
                                        description=f"Mapped from {category} pattern",
                                        confidence=tech['confidence'],
                                        relevance='high' if tech['confidence'] > 0.8 else 'medium'
                                    ))
                                    technique_ids_seen.add(tech_id)
                    except re.error:
                        # Fallback to simple string matching
                        if pattern.lower() in full_text:
                            for tech in pattern_item['techniques']:
                                tech_id = tech['id']
                                if tech_id not in technique_ids_seen:
                                    techniques.append(MITRETechnique(
                                        technique_id=tech_id,
                                        technique_name=tech['name'],
                                        tactic=tech['tactic'],
                                        description=f"Mapped from {category} pattern",
                                        confidence=tech['confidence'] * 0.8,  # Lower confidence for simple match
                                        relevance='medium'
                                    ))
                                    technique_ids_seen.add(tech_id)
        
        # Check service name patterns
        if service_name:
            for service_type, patterns in self.service_patterns.items():
                for pattern in patterns:
                    if pattern in service_name:
                        # Find matching techniques
                        if service_type in self.technique_mappings:
                            for pattern_item in self.technique_mappings[service_type]:
                                for tech in pattern_item['techniques']:
                                    tech_id = tech['id']
                                    if tech_id not in technique_ids_seen:
                                        techniques.append(MITRETechnique(
                                            technique_id=tech_id,
                                            technique_name=tech['name'],
                                            tactic=tech['tactic'],
                                            description=f"Mapped from {service_type} service",
                                            confidence=tech['confidence'] * 0.7,  # Lower confidence for service-only match
                                            relevance='medium'
                                        ))
                                        technique_ids_seen.add(tech_id)
                        break
        
        # Sort by confidence (highest first)
        techniques.sort(key=lambda x: x.confidence, reverse=True)
        
        return techniques
    
    def analyze_scan_results(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes a list of scan results and returns MITRE technique mappings.
        
        Args:
            scan_results: List of scan result dictionaries
        
        Returns:
            Dictionary with:
                - 'techniques': List of unique techniques found
                - 'tactics': Grouped techniques by tactic
                - 'summary': Summary statistics
        """
        all_techniques = []
        tactics_map = {}
        
        for result in scan_results:
            techniques = self.map_finding_to_mitre_techniques(result)
            all_techniques.extend(techniques)
        
        # Deduplicate by technique_id, keeping highest confidence
        unique_techniques = {}
        for tech in all_techniques:
            if tech.technique_id not in unique_techniques:
                unique_techniques[tech.technique_id] = tech
            elif tech.confidence > unique_techniques[tech.technique_id].confidence:
                unique_techniques[tech.technique_id] = tech
        
        # Group by tactic
        for tech in unique_techniques.values():
            if tech.tactic not in tactics_map:
                tactics_map[tech.tactic] = []
            tactics_map[tech.tactic].append({
                'id': tech.technique_id,
                'name': tech.technique_name,
                'confidence': tech.confidence,
                'relevance': tech.relevance
            })
        
        return {
            'techniques': [
                {
                    'id': tech.technique_id,
                    'name': tech.technique_name,
                    'tactic': tech.tactic,
                    'confidence': tech.confidence,
                    'relevance': tech.relevance
                }
                for tech in sorted(unique_techniques.values(), key=lambda x: x.confidence, reverse=True)
            ],
            'tactics': tactics_map,
            'summary': {
                'total_techniques': len(unique_techniques),
                'total_tactics': len(tactics_map),
                'high_confidence': len([t for t in unique_techniques.values() if t.confidence > 0.8]),
                'high_relevance': len([t for t in unique_techniques.values() if t.relevance == 'high']),
            }
        }


# Global instance
_mitre_mapper = None


def get_mitre_mapper() -> MITREMapper:
    """Get or create the global MITRE mapper instance"""
    global _mitre_mapper
    if _mitre_mapper is None:
        _mitre_mapper = MITREMapper()
    return _mitre_mapper


def map_finding_to_mitre_techniques(finding: Dict[str, Any], finding_type: Optional[str] = None) -> List[MITRETechnique]:
    """Convenience function to map a finding to MITRE techniques"""
    mapper = get_mitre_mapper()
    return mapper.map_finding_to_mitre_techniques(finding, finding_type)







