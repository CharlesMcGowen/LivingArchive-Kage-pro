#!/usr/bin/env python3
"""
Ash Enhanced Reconnaissance Service
==================================

Integrates professional security tools with Ash's reconnaissance capabilities.
Uses dirsearch, Amass, truffleHog, hashcat, and BloodHound for comprehensive reconnaissance.
"""

import logging
import subprocess
import os
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class AshEnhancedReconnaissanceService:
    """
    Enhanced Ash reconnaissance service integrating professional security tools.
    Combines traditional reconnaissance with advanced enumeration and credential harvesting.
    """
    
    def __init__(self):
        self.tools_path = r"C:\Users\charl\Desktop\ego\tools"
        self.dirsearch_path = os.path.join(self.tools_path, "dirsearch", "dirsearch.py")
        self.amass_path = os.path.join(self.tools_path, "Amass")
        self.trufflehog_path = os.path.join(self.tools_path, "truffleHog", "truffleHog", "truffleHog.py")
        self.hashcat_path = os.path.join(self.tools_path, "hashcat-6.1.1", "hashcat.exe")
        self.bloodhound_path = os.path.join(self.tools_path, "BloodHound")
        
        logger.info("[AshEnhancedRecon] Initialized with professional reconnaissance tools")
    
    def comprehensive_reconnaissance(self, target_url: str) -> Dict[str, Any]:
        """
        Perform comprehensive reconnaissance using multiple professional tools.
        
        Args:
            target_url: Target URL to reconnoiter
        
        Returns:
            Comprehensive reconnaissance results
        """
        logger.info(f"[AshEnhancedRecon] Starting comprehensive reconnaissance of: {target_url}")
        
        results = {
            'target_url': target_url,
            'timestamp': datetime.now().isoformat(),
            'tools_used': [],
            'findings': {},
            'success': True
        }
        
        try:
            # 1. Directory enumeration
            logger.info("[AshEnhancedRecon] Phase 1: Directory enumeration")
            dirsearch_results = self._run_dirsearch_comprehensive(target_url)
            results['findings']['directory_enumeration'] = dirsearch_results
            results['tools_used'].append('dirsearch')
            
            # 2. Subdomain enumeration
            logger.info("[AshEnhancedRecon] Phase 2: Subdomain enumeration")
            domain = urlparse(target_url).netloc
            amass_results = self._run_amass_comprehensive(domain)
            results['findings']['subdomain_enumeration'] = amass_results
            results['tools_used'].append('Amass')
            
            # 3. Secret scanning
            logger.info("[AshEnhancedRecon] Phase 3: Secret scanning")
            trufflehog_results = self._run_trufflehog_comprehensive(target_url)
            results['findings']['secret_scanning'] = trufflehog_results
            results['tools_used'].append('truffleHog')
            
            # 4. Password cracking
            logger.info("[AshEnhancedRecon] Phase 4: Password cracking")
            hashcat_results = self._run_hashcat_for_secrets(trufflehog_results)
            results['findings']['password_cracking'] = hashcat_results
            results['tools_used'].append('hashcat')
            
            # 5. Active Directory reconnaissance (if applicable)
            logger.info("[AshEnhancedRecon] Phase 5: Active Directory reconnaissance")
            bloodhound_results = self._run_bloodhound_reconnaissance(domain)
            results['findings']['active_directory_recon'] = bloodhound_results
            results['tools_used'].append('BloodHound')
            
            # 6. Generate reconnaissance report
            logger.info("[AshEnhancedRecon] Phase 6: Report generation")
            report = self._generate_reconnaissance_report(results)
            results['findings']['reconnaissance_report'] = report
            
            logger.info(f"[AshEnhancedRecon] Reconnaissance complete. Tools used: {len(results['tools_used'])}")
            
        except Exception as e:
            logger.error(f"[AshEnhancedRecon] Error during reconnaissance: {e}")
            results['success'] = False
            results['error'] = str(e)
        
        return results
    
    def _run_dirsearch_comprehensive(self, target_url: str) -> Dict[str, Any]:
        """Run comprehensive directory enumeration."""
        try:
            output_dir = os.path.join(self.tools_path, "dirsearch", "reports", "ash_recon")
            os.makedirs(output_dir, exist_ok=True)
            
            # Run dirsearch with comprehensive settings
            cmd = [
                "python", self.dirsearch_path,
                "-u", target_url,
                "-o", os.path.join(output_dir, f"ash_recon_{int(time.time())}.json"),
                "--format", "json",
                "--threads", "20",
                "--timeout", "15",
                "--max-retries", "3",
                "--recursive", "2",
                "--extensions", "php,asp,aspx,jsp,html,htm,txt,pdf,doc,docx"
            ]
            
            logger.info(f"[AshEnhancedRecon] Running comprehensive dirsearch: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes max
                cwd=os.path.dirname(self.dirsearch_path)
            )
            
            # Parse results
            directories = []
            files = []
            endpoints = []
            
            if result.returncode == 0:
                try:
                    # Try to parse JSON output
                    output_file = os.path.join(output_dir, f"ash_recon_{int(time.time())}.json")
                    if os.path.exists(output_file):
                        with open(output_file, 'r') as f:
                            data = json.load(f)
                            for item in data:
                                if item.get('status') in ['200', '301', '302', '403']:
                                    endpoints.append(item)
                except:
                    # Fallback to stdout parsing
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if any(status in line for status in ['200', '301', '302', '403']):
                            endpoints.append(line.strip())
            
            return {
                'success': result.returncode == 0,
                'endpoints': endpoints,
                'count': len(endpoints),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'tool': 'dirsearch_comprehensive'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'tool': 'dirsearch_comprehensive'
            }
    
    def _run_amass_comprehensive(self, domain: str) -> Dict[str, Any]:
        """Run comprehensive subdomain enumeration."""
        try:
            output_dir = os.path.join(self.tools_path, "Amass", "reports", "ash_recon")
            os.makedirs(output_dir, exist_ok=True)
            
            # Run Amass with comprehensive settings
            cmd = [
                "amass", "enum",
                "-d", domain,
                "-o", os.path.join(output_dir, f"ash_recon_{int(time.time())}.txt"),
                "-silent",
                "-passive",
                "-active"
            ]
            
            logger.info(f"[AshEnhancedRecon] Running comprehensive Amass: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1200,  # 20 minutes max
                cwd=self.amass_path
            )
            
            # Parse subdomains
            subdomains = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                subdomains = [line.strip() for line in lines if line.strip() and '.' in line]
            
            # Categorize subdomains
            admin_subdomains = [s for s in subdomains if 'admin' in s.lower()]
            api_subdomains = [s for s in subdomains if 'api' in s.lower()]
            dev_subdomains = [s for s in subdomains if any(dev in s.lower() for dev in ['dev', 'test', 'staging'])]
            
            return {
                'success': result.returncode == 0,
                'subdomains': subdomains,
                'admin_subdomains': admin_subdomains,
                'api_subdomains': api_subdomains,
                'dev_subdomains': dev_subdomains,
                'total_count': len(subdomains),
                'admin_count': len(admin_subdomains),
                'api_count': len(api_subdomains),
                'dev_count': len(dev_subdomains),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'tool': 'amass_comprehensive'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'tool': 'amass_comprehensive'
            }
    
    def _run_trufflehog_comprehensive(self, target_url: str) -> Dict[str, Any]:
        """Run comprehensive secret scanning."""
        try:
            output_dir = os.path.join(self.tools_path, "truffleHog", "reports", "ash_recon")
            os.makedirs(output_dir, exist_ok=True)
            
            cmd = [
                "python", self.trufflehog_path,
                "--json",
                target_url
            ]
            
            logger.info(f"[AshEnhancedRecon] Running comprehensive truffleHog: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes max
                cwd=os.path.dirname(self.trufflehog_path)
            )
            
            # Parse secrets by category
            all_secrets = []
            api_keys = []
            passwords = []
            tokens = []
            credentials = []
            
            if result.returncode == 0:
                try:
                    secrets = json.loads(result.stdout) if result.stdout else []
                    for secret in secrets:
                        all_secrets.append(secret)
                        reason = secret.get('reason', '').lower()
                        
                        if 'api' in reason or 'key' in reason:
                            api_keys.append(secret)
                        elif 'password' in reason or 'pass' in reason:
                            passwords.append(secret)
                        elif 'token' in reason:
                            tokens.append(secret)
                        elif 'credential' in reason or 'auth' in reason:
                            credentials.append(secret)
                except:
                    # Fallback to text parsing
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip():
                            all_secrets.append(line.strip())
            
            return {
                'success': result.returncode == 0,
                'all_secrets': all_secrets,
                'api_keys': api_keys,
                'passwords': passwords,
                'tokens': tokens,
                'credentials': credentials,
                'total_count': len(all_secrets),
                'api_key_count': len(api_keys),
                'password_count': len(passwords),
                'token_count': len(tokens),
                'credential_count': len(credentials),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'tool': 'trufflehog_comprehensive'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'tool': 'trufflehog_comprehensive'
            }
    
    def _run_hashcat_for_secrets(self, trufflehog_results: Dict) -> Dict[str, Any]:
        """Run hashcat to crack discovered secrets."""
        try:
            secrets = trufflehog_results.get('all_secrets', [])
            if not secrets:
                return {
                    'success': True,
                    'message': 'No secrets to crack',
                    'cracked_secrets': [],
                    'tool': 'hashcat'
                }
            
            # Create wordlist from discovered secrets
            wordlist_file = os.path.join(self.tools_path, "hashcat-6.1.1", "ash_wordlist.txt")
            with open(wordlist_file, 'w') as f:
                for secret in secrets:
                    if isinstance(secret, dict) and 'secret' in secret:
                        f.write(secret['secret'] + '\n')
                    elif isinstance(secret, str):
                        f.write(secret + '\n')
            
            # Run hashcat with multiple attack modes
            cracked_secrets = []
            
            # Mode 0: Dictionary attack
            cmd_dict = [
                self.hashcat_path,
                "-a", "0",
                "-m", "0",  # MD5
                wordlist_file,
                "--force"
            ]
            
            result_dict = subprocess.run(
                cmd_dict,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=os.path.dirname(self.hashcat_path)
            )
            
            if result_dict.returncode == 0:
                lines = result_dict.stdout.split('\n')
                for line in lines:
                    if ':' in line and len(line.split(':')) == 2:
                        cracked_secrets.append(line.strip())
            
            return {
                'success': True,
                'cracked_secrets': cracked_secrets,
                'count': len(cracked_secrets),
                'stdout': result_dict.stdout,
                'stderr': result_dict.stderr,
                'tool': 'hashcat'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'tool': 'hashcat'
            }
    
    def _run_bloodhound_reconnaissance(self, domain: str) -> Dict[str, Any]:
        """Run BloodHound for Active Directory reconnaissance."""
        try:
            # Check if BloodHound is available
            if not os.path.exists(self.bloodhound_path):
                return {
                    'success': False,
                    'message': 'BloodHound not available',
                    'tool': 'BloodHound'
                }
            
            output_dir = os.path.join(self.tools_path, "BloodHound", "reports", "ash_recon")
            os.makedirs(output_dir, exist_ok=True)
            
            # Run BloodHound collectors (if available)
            cmd = [
                "python", os.path.join(self.bloodhound_path, "Collectors", "BloodHound.py"),
                "-d", domain,
                "-u", "anonymous",
                "-p", "anonymous",
                "-dc", f"dc.{domain}",
                "-c", "All"
            ]
            
            logger.info(f"[AshEnhancedRecon] Running BloodHound: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minutes max
                cwd=self.bloodhound_path
            )
            
            # Parse BloodHound results
            ad_findings = []
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ['user', 'group', 'computer', 'domain']):
                        ad_findings.append(line.strip())
            
            return {
                'success': result.returncode == 0,
                'ad_findings': ad_findings,
                'count': len(ad_findings),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'tool': 'BloodHound'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'tool': 'BloodHound'
            }
    
    def _generate_reconnaissance_report(self, results: Dict) -> Dict[str, Any]:
        """Generate comprehensive reconnaissance report."""
        report = {
            'summary': {
                'target': results['target_url'],
                'tools_used': len(results['tools_used']),
                'timestamp': results['timestamp']
            },
            'findings': {},
            'attack_vectors': [],
            'recommendations': []
        }
        
        # Analyze directory enumeration results
        dirsearch = results['findings'].get('directory_enumeration', {})
        if dirsearch.get('success'):
            report['findings']['endpoints'] = dirsearch.get('endpoints', [])
            report['attack_vectors'].append("Directory traversal and endpoint discovery")
            report['recommendations'].append("Test discovered endpoints for vulnerabilities")
        
        # Analyze subdomain enumeration results
        amass = results['findings'].get('subdomain_enumeration', {})
        if amass.get('success'):
            report['findings']['subdomains'] = amass.get('subdomains', [])
            report['findings']['admin_subdomains'] = amass.get('admin_subdomains', [])
            report['findings']['api_subdomains'] = amass.get('api_subdomains', [])
            report['attack_vectors'].append("Subdomain takeover and lateral movement")
            report['recommendations'].append("Test subdomains for takeover vulnerabilities")
        
        # Analyze secret scanning results
        trufflehog = results['findings'].get('secret_scanning', {})
        if trufflehog.get('success'):
            report['findings']['secrets'] = trufflehog.get('all_secrets', [])
            report['findings']['api_keys'] = trufflehog.get('api_keys', []) if trufflehog else []
            report['findings']['passwords'] = trufflehog.get('passwords', [])
            report['attack_vectors'].append("Credential harvesting and API abuse")
            report['recommendations'].append("Use discovered credentials for authentication bypass")
        
        # Analyze password cracking results
        hashcat = results['findings'].get('password_cracking', {})
        if hashcat.get('success'):
            report['findings']['cracked_secrets'] = hashcat.get('cracked_secrets', [])
            report['attack_vectors'].append("Password-based attacks")
            report['recommendations'].append("Use cracked passwords for system access")
        
        # Analyze Active Directory results
        bloodhound = results['findings'].get('active_directory_recon', {})
        if bloodhound and bloodhound.get('success'):
            report['findings']['ad_findings'] = bloodhound.get('ad_findings', []) if bloodhound else []
            report['attack_vectors'].append("Active Directory lateral movement")
            report['recommendations'].append("Use AD findings for privilege escalation")
        
        return report


# Global instance
ash_enhanced_recon = AshEnhancedReconnaissanceService()
