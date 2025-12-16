#!/usr/bin/env python3
"""
Surge Nuclei Integration
=======================

Real Nuclei vulnerability scanning integration for Surge.
Replaces simulation with actual Nuclei scanning capabilities.

Author: EGO Revolution Team
Version: 1.0.0
"""

import sys
import asyncio
import subprocess
import json
import tempfile
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

class SurgeNucleiIntegration:
    """Real Nuclei vulnerability scanning integration."""
    
    def __init__(self):
        self.logger = self._setup_logger()
        self.nuclei_path = self._find_nuclei()
        self.templates_path = self._setup_templates()
        
        # Technology-based template mapping (simplified Bugsy integration)
        self.technology_templates = {
            'wordpress': ['http/exposed-panels/wordpress/'],
            'joomla': ['http/exposed-panels/joomla/'],
            'drupal': ['http/exposed-panels/drupal/'],
            'magento': ['http/exposed-panels/magento/'],
            'apache': ['http/misconfiguration/apache/'],
            'nginx': ['http/misconfiguration/nginx/'],
            'iis': ['http/misconfiguration/iis/'],
            'tomcat': ['http/exposed-panels/tomcat/'],
            'jenkins': ['http/exposed-panels/jenkins/'],
            'grafana': ['http/exposed-panels/grafana/'],
            'kibana': ['http/exposed-panels/kibana/'],
            'prometheus': ['http/exposed-panels/prometheus/'],
            'elasticsearch': ['http/misconfiguration/elasticsearch/'],
        }
        
    def _setup_logger(self):
        """Setup logging for the integration."""
        import logging
        logger = logging.getLogger('SurgeNuclei')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('⚡ [%(asctime)s] %(levelname)s: %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger
    
    def _find_nuclei(self) -> str:
        """Find Nuclei executable."""
        # Try Docker-mounted binary first (production)
        container_paths = [
            '/app/artificial_intelligence/personalities/security/surge/nuclei',
            '/app/surge/nuclei',
        ]
        
        # Try local binary (development)
        local_path = '/mnt/webapps-nvme/artificial_intelligence/personalities/security/surge/nuclei'
        
        # Try common locations
        possible_paths = [
            '/usr/local/bin/nuclei',
            '/usr/bin/nuclei',
            '/opt/nuclei/nuclei',
            'nuclei'  # In PATH
        ]
        
        # Check all paths
        for path in container_paths + [local_path] + possible_paths:
            if os.path.exists(path):
                try:
                    result = subprocess.run([path, '-version'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.logger.info(f"Found Nuclei at: {path}")
                        return path
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    continue
        
        # If not found, try to install
        self.logger.warning("Nuclei not found, attempting to install...")
        return self._install_nuclei()
    
    def _install_nuclei(self) -> str:
        """Install Nuclei if not found."""
        try:
            # Install using go install
            self.logger.info("Installing Nuclei...")
            subprocess.run([
                'go', 'install', '-v', 
                'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
            ], check=True, timeout=300)
            
            # Try to find the installed binary
            go_bin = os.path.expanduser('~/go/bin/nuclei')
            if os.path.exists(go_bin):
                self.logger.info(f"Nuclei installed at: {go_bin}")
                return go_bin
            else:
                # Try in PATH
                return 'nuclei'
                
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.error(f"Failed to install Nuclei: {e}")
            return 'nuclei'  # Fallback to PATH
    
    def _setup_templates(self) -> str:
        """Setup Nuclei templates directory."""
        # Nuclei has built-in templates via -update-templates
        # We don't need a custom templates directory
        # Return empty string to indicate use built-in templates
        return ""
    
    def _ensure_url_with_protocol(self, domain: str) -> str:
        """
        Ensure domain has http:// or https:// protocol.
        Prefer https:// for better scan coverage.
        
        Args:
            domain: Domain name (may or may not have protocol)
            
        Returns:
            URL with protocol
        """
        domain = domain.strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            return domain
        # Default to https:// for modern web scanning
        return f"https://{domain}"
    
    async def scan_domain(self, domain: str, scan_type: str = "comprehensive", egg_record: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Scan domain using the new class-based API (NO subprocess calls).

        Args:
            domain: The target URL/domain to scan.
            scan_type: Defines the template configuration (e.g., "comprehensive").
            egg_record: Optional data about the target from the ORM.
        
        Returns:
            A dictionary containing scan results and statistics.
        """
        # 1. Imports from the new API structure
        from .class_based_api import NucleiEngine, ScanConfig, Severity
        
        # Ensure domain has protocol (https://)
        url = self._ensure_url_with_protocol(domain)
        self.logger.info(f"🔍 Nuclei scanning: {url} (using class-based API)")
        
        # 2. Configure Scan
        # Map scan_type to template tags
        template_tags = self._get_template_tags_for_scan_type(scan_type, egg_record)
        
        # Determine severity levels based on scan type
        if scan_type == "comprehensive":
            severity_levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        elif scan_type == "critical_only":
            severity_levels = [Severity.CRITICAL, Severity.HIGH]
        else:
            severity_levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
        
        config = ScanConfig(
            template_tags=template_tags,
            severity_levels=severity_levels,
            rate_limit=10,
            use_thread_safe=True
        )
        
        engine = NucleiEngine(config=config)
        vulnerabilities = []
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # 3. Setup Callback
        def on_vulnerability(finding):
            # Parse vulnerability using existing helper method
            parsed_vuln = self._parse_nuclei_result({
                'template_id': finding.template_id,
                'template': finding.template_name,
                'info': finding.metadata,
                'matched-at': finding.matched_at,
            })
            vulnerabilities.append(parsed_vuln)
            
            # Count by severity
            severity = finding.severity.value.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Log each vulnerability
            self.logger.info(f"🎯 Found vulnerability: {finding.template_id} ({finding.severity.value}) on {url}")
        
        engine.on_vulnerability.append(on_vulnerability)
        
        # 4. Execute Scan
        scan_id = engine.scan([url])
        
        # 5. Wait for Completion
        # Use a loop to wait for the engine to signal completion
        while engine.status.value not in ['completed', 'failed']:
            await asyncio.sleep(0.1)
        
        engine.close()
        
        # 6. Return Structured Result
        result = {
            'domain': url,
            'scan_type': scan_type,
            'scan_id': scan_id,
            'scan_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities_by_severity': severity_counts,
            'vulnerabilities': vulnerabilities,
            'status': engine.status.value,
        }
        
        # Get metrics if available
        try:
            state = engine.get_state()
            result['metrics'] = {
                'total_requests': state.get('total_requests', 0),
                'completed_requests': state.get('completed_requests', 0),
                'vulnerabilities_found': state.get('vulnerabilities_found', 0),
            }
        except:
            pass
        
        self.logger.info(f"✅ Nuclei scan completed: {len(vulnerabilities)} vulnerabilities found")
        return result
    
    def _get_template_tags_for_scan_type(self, scan_type: str, egg_record: Optional[Dict] = None) -> List[str]:
        """
        Get template tags based on scan type and optional egg record data.
        
        Args:
            scan_type: Type of scan (comprehensive, critical_only, web_only, intelligent)
            egg_record: Optional egg record with technology fingerprinting data
            
        Returns:
            List of template tags
        """
        if scan_type == "intelligent" and egg_record:
            # Use intelligent template selection based on technology detection
            return self._get_intelligent_templates("", egg_record)
        elif scan_type == "comprehensive":
            return ['cve', 'exposures', 'vulnerabilities']
        elif scan_type == "critical_only":
            return ['cve', 'vulnerabilities']
        elif scan_type == "web_only":
            return ['exposures', 'vulnerabilities', 'technologies']
        else:
            return ['cve', 'vulnerabilities']
    
    def _parse_nuclei_result(self, nuclei_result: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Nuclei JSON result into standardized format compatible with store_vulnerabilities."""
        return {
            'template-id': nuclei_result.get('template_id', 'unknown'),
            'template': nuclei_result.get('template', ''),
            'info': nuclei_result.get('info', {}),
            'type': nuclei_result.get('type', ''),
            'matched-at': nuclei_result.get('matched-at', ''),
            'matcher-name': nuclei_result.get('matcher-name', ''),
            'matcher-status': nuclei_result.get('matcher-status', ''),
            'extracted-results': nuclei_result.get('extracted-results', []),
            'request': nuclei_result.get('request', ''),
            'response': nuclei_result.get('response', ''),
            'curl-command': nuclei_result.get('curl-command', ''),
            'metadata': nuclei_result.get('metadata', {}),
            'raw_result': nuclei_result
        }
    
    def _get_nuclei_version(self) -> str:
        """Get Nuclei version."""
        try:
            result = subprocess.run([self.nuclei_path, '-version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
        return "unknown"
    
    async def scan_multiple_domains(self, domains: List[str], scan_type: str = "comprehensive") -> List[Dict[str, Any]]:
        """Scan multiple domains concurrently."""
        self.logger.info(f"🎯 Starting concurrent scan of {len(domains)} domains")
        
        # Limit concurrency to avoid overwhelming targets
        semaphore = asyncio.Semaphore(3)
        
        async def scan_with_semaphore(domain):
            async with semaphore:
                return await self.scan_domain(domain, scan_type)
        
        tasks = [scan_with_semaphore(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Scan task failed: {result}")
            else:
                valid_results.append(result)
        
        return valid_results
    
    def _get_intelligent_templates(self, domain: str, egg_record: Dict[str, Any]) -> List[str]:
        """
        Get intelligent template recommendations based on technology detection.
        
        Returns template tags (not CLI flags) for use with ScanConfig.
        
        Args:
            domain: Domain being scanned
            egg_record: Egg record dict with domainname, customer info
            
        Returns:
            List of template tags (e.g., ['cve', 'wordpress', 'rce'])
        """
        try:
            # Extract technology hints from domain name
            domain_lower = domain.lower()
            technologies = []
            
            # Simple keyword matching from domain
            if hasattr(self, 'technology_templates'):
                for tech, templates in self.technology_templates.items():
                    if tech in domain_lower:
                        technologies.append(tech)
            
            # Always include CVEs and vulnerabilities as baseline (return tags, not CLI flags)
            result = ['cve', 'vulnerabilities']
            
            # Add technology-specific tags if detected
            if technologies:
                result.extend(technologies)
                self.logger.info(f"🎯 Intelligent templates for {domain}: {len(technologies)} tech-specific tags added")
            else:
                self.logger.debug(f"No technology-specific templates for {domain}, using comprehensive scan")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error generating intelligent templates: {e}")
            # Fallback to comprehensive scan (return tags)
            return ['cve', 'exposures', 'vulnerabilities']
    
    def get_scan_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get statistics from scan results."""
        total_domains = len(results)
        successful_scans = len([r for r in results if r['status'] == 'completed'])
        failed_scans = len([r for r in results if r['status'] == 'failed'])
        
        total_vulnerabilities = sum(r['total_vulnerabilities'] for r in results)
        
        severity_breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for result in results:
            for severity, count in result['vulnerabilities_by_severity'].items():
                severity_breakdown[severity] += count
        
        # Get unique vulnerability types
        vuln_types = set()
        for result in results:
            for vuln in result['vulnerabilities']:
                vuln_types.add(vuln['template_id'])
        
        return {
            'total_domains': total_domains,
            'successful_scans': successful_scans,
            'failed_scans': failed_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'severity_breakdown': severity_breakdown,
            'unique_vulnerability_types': len(vuln_types),
            'scan_timestamp': datetime.now().isoformat()
        }

async def main():
    """Main function for testing."""
    print("⚡ SURGE NUCLEI INTEGRATION TEST")
    print("=" * 50)
    
    nuclei = SurgeNucleiIntegration()
    
    # Test domains
    test_domains = [
        "httpbin.org",
        "example.com",
        "httpbin.org/get"
    ]
    
    print(f"🎯 Testing Nuclei integration with {len(test_domains)} domains")
    print(f"Nuclei path: {nuclei.nuclei_path}")
    print(f"Templates path: {nuclei.templates_path}")
    print()
    
    # Scan domains
    results = await nuclei.scan_multiple_domains(test_domains, "comprehensive")
    
    # Show results
    stats = nuclei.get_scan_statistics(results)
    print(f"📊 Scan Statistics:")
    print(f"   Domains scanned: {stats['total_domains']}")
    print(f"   Successful: {stats['successful_scans']}")
    print(f"   Failed: {stats['failed_scans']}")
    print(f"   Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"   Severity breakdown: {stats['severity_breakdown']}")
    print(f"   Unique vulnerability types: {stats['unique_vulnerability_types']}")
    
    print(f"\n🔍 Detailed Results:")
    for result in results:
        print(f"   {result['domain']}:")
        print(f"      Status: {result['status']}")
        print(f"      Vulnerabilities: {result['total_vulnerabilities']}")
        if result['vulnerabilities_by_severity']:
            for severity, count in result['vulnerabilities_by_severity'].items():
                if count > 0:
                    print(f"         {severity.capitalize()}: {count}")
        print()

if __name__ == "__main__":
    asyncio.run(main())
