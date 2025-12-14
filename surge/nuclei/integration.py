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
        Scan a domain using Nuclei with intelligent template selection.
        
        Args:
            domain: Domain to scan
            scan_type: Scan type (comprehensive, critical_only, web_only, intelligent)
            egg_record: Optional egg record dict with tech fingerprinting data
            
        Returns:
            Scan results dict
        """
        # Ensure domain has protocol (https://)
        url = self._ensure_url_with_protocol(domain)
        self.logger.info(f"🔍 Nuclei scanning: {url}")
        
        # Intelligent template selection based on technology detection
        if scan_type == "intelligent" and egg_record:
            severity_flags = ["-s", "critical,high,medium,low,info"]
            template_flags = self._get_intelligent_templates(url, egg_record)
        elif scan_type == "comprehensive":
            severity_flags = ["-s", "critical,high,medium,low,info"]
            template_flags = ["-t", "http/cves/", "-t", "http/exposures/", "-t", "http/vulnerabilities/"]
        elif scan_type == "critical_only":
            severity_flags = ["-s", "critical,high"]
            template_flags = ["-t", "http/cves/", "-t", "http/vulnerabilities/"]
        elif scan_type == "web_only":
            severity_flags = ["-s", "critical,high,medium,low,info"]
            template_flags = ["-t", "http/exposures/", "-t", "http/vulnerabilities/", "-t", "http/technologies/"]
        else:
            severity_flags = ["-s", "critical,high,medium"]
            template_flags = ["-t", "http/cves/", "-t", "http/vulnerabilities/"]
        
        try:
            # Build Nuclei command WITHOUT timeout flag - let Nuclei run to completion
            # Use -jsonl for stdout streaming instead of -jle which doesn't write until completion
            cmd = [
                self.nuclei_path,
                "-u", url,  # Use URL with protocol
                "-jsonl",  # JSONL output to stdout for streaming
                "-nc",  # No color (remove ANSI codes)
                # Removed: "-timeout", "30" - let Nuclei CLI handle its own timeouts if needed
                "-retries", "1",
                "-rate-limit", "10",
                "-concurrency", "5",
                # Removed "-silent" - it suppresses JSONL output!
            ] + severity_flags + template_flags
            
            self.logger.info(f"Running: {' '.join(cmd)}")
            
            # Run Nuclei scan with working directory set to where templates live
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd='/home/ego'  # Templates are relative to /home/ego/nuclei-templates
            )
            
            # Read stdout with timeout
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600.0)
            except asyncio.TimeoutError:
                self.logger.error(f"Nuclei scan timeout after 10 minutes for {url}")
                process.kill()
                await process.wait()
                raise Exception("Nuclei scan timeout after 10 minutes")
            
            # Debug: Log stdout/stderr sizes
            stdout_len = len(stdout) if stdout else 0
            stderr_len = len(stderr) if stderr else 0
            self.logger.debug(f"📊 Nuclei output for {url}: stdout={stdout_len} bytes, stderr={stderr_len} bytes")
            
            # Log stderr if there are warnings/errors
            if stderr:
                stderr_text = stderr.decode('utf-8', errors='ignore')
                if 'ERR' in stderr_text or 'WRN' in stderr_text or 'FTL' in stderr_text:
                    self.logger.warning(f"⚠️ Nuclei stderr for {url}: {stderr_text[:500]}")
            
            # Parse results from stdout (JSONL format, one JSON object per line)
            vulnerabilities = []
            json_parse_failures = 0
            non_empty_lines = 0
            
            if stdout:
                stdout_text = stdout.decode('utf-8', errors='ignore')
                lines = stdout_text.splitlines()
                self.logger.debug(f"📝 Parsing {len(lines)} lines from stdout for {url}")
                
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    if line:
                        non_empty_lines += 1
                        try:
                            vuln = json.loads(line)
                            parsed_vuln = self._parse_nuclei_result(vuln)
                            vulnerabilities.append(parsed_vuln)
                            
                            # Log each successfully parsed vulnerability
                            vuln_id = parsed_vuln.get('template-id', 'unknown')
                            vuln_severity = parsed_vuln.get('info', {}).get('severity', 'unknown')
                            self.logger.info(f"🎯 Found vulnerability: {vuln_id} ({vuln_severity}) on {url}")
                            
                        except json.JSONDecodeError as e:
                            json_parse_failures += 1
                            # Log first few parse failures for debugging
                            if json_parse_failures <= 3:
                                self.logger.warning(f"⚠️ JSON parse error on line {line_num} for {url}: {str(e)[:100]}")
                                self.logger.debug(f"   Failed line content: {line[:200]}")
                            continue
            else:
                self.logger.warning(f"⚠️ Empty stdout from Nuclei for {url}")
            
            # Log parsing statistics
            if json_parse_failures > 0:
                self.logger.warning(f"⚠️ {json_parse_failures} JSON parse failures for {url} (out of {non_empty_lines} non-empty lines)")
            
            # Count by severity
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for vuln in vulnerabilities:
                severity = vuln.get('info', {}).get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            result = {
                'domain': url,  # Store URL with protocol
                'scan_type': scan_type,
                'scan_time': datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerabilities_by_severity': severity_counts,
                'vulnerabilities': vulnerabilities,
                'nuclei_version': self._get_nuclei_version(),
                'status': 'completed'
            }
            
            self.logger.info(f"✅ Nuclei scan completed: {len(vulnerabilities)} vulnerabilities found")
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Nuclei scan failed for {url}: {e}")
            return {
                'domain': url,  # Store URL with protocol
                'scan_type': scan_type,
                'scan_time': datetime.now().isoformat(),
                'total_vulnerabilities': 0,
                'vulnerabilities_by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'vulnerabilities': [],
                'error': str(e),
                'status': 'failed'
            }
    
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
        
        Simplified Bugsy-style integration without Django dependencies.
        
        Args:
            domain: Domain being scanned
            egg_record: Egg record dict with domainname, customer info
            
        Returns:
            List of -t template flags for Nuclei
        """
        try:
            # Extract technology hints from domain name
            domain_lower = domain.lower()
            technologies = []
            
            # Simple keyword matching from domain
            for tech, templates in self.technology_templates.items():
                if tech in domain_lower:
                    technologies.extend(templates)
            
            # Always include CVEs and vulnerabilities as baseline
            result = ["-t", "http/cves/", "-t", "http/vulnerabilities/"]
            
            # Add technology-specific templates if detected
            if technologies:
                for template in set(technologies):  # Deduplicate
                    result.extend(["-t", template])
                
                self.logger.info(f"🎯 Intelligent templates for {domain}: {len(technologies)} tech-specific templates added")
            else:
                self.logger.debug(f"No technology-specific templates for {domain}, using comprehensive scan")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error generating intelligent templates: {e}")
            # Fallback to comprehensive scan
            return ["-t", "http/cves/", "-t", "http/exposures/", "-t", "http/vulnerabilities/"]
    
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
