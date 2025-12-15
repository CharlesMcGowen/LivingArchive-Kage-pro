"""
Django ORM Database Integration for Surge Nuclei Scanner
========================================================

Modern Django ORM-based database integration for Surge.
Replaces SQLAlchemy with native Django ORM.

Author: EGO Revolution Team
Version: 3.0.0 - Django ORM Migration
"""

import logging
from datetime import datetime, timezone as dt_timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
from django.db import transaction
from django.utils import timezone

from ..models import (
    NucleiScan, NucleiVulnerability, SurgeKontrolDeployment,
    ScanStatus, ScanSeverity
)

logger = logging.getLogger(__name__)


@dataclass
class SurgeScanResult:
    """Represents a Surge Nuclei scan result for database storage."""
    target: str
    vulnerabilities: List[Dict[str, Any]]
    scan_duration: float
    scan_type: str
    kontrol_deployed: List[str]
    timestamp: datetime
    output_file: str


class SurgeDatabaseIntegration:
    """
    Django ORM-based database integration for Surge.
    
    Uses native Django ORM for proper database operations.
    Provides high-level API for Surge scanning operations.
    """
    
    def __init__(self):
        """Initialize Surge Django ORM integration."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("⚡ Surge Django ORM Integration initialized")
    
    def create_scan(
        self, 
        target: str, 
        scan_type: str, 
        templates: List[str] = None,
        egg_id: str = None,
        scan_parameters: Dict[str, Any] = None
    ) -> NucleiScan:
        """
        Create a new scan record.
        
        Args:
            target: Target URL/domain
            scan_type: Type of scan (comprehensive, quick, stealth)
            templates: List of Nuclei templates to use
            egg_id: Related Kontrol AI egg ID
            scan_parameters: Additional scan parameters
            
        Returns:
            NucleiScan object
        """
        try:
            # Extract domain from target
            parsed = urlparse(target if target.startswith('http') else f'http://{target}')
            domain = parsed.netloc or target
            
            scan = NucleiScan.objects.create(
                target=target,
                target_domain=domain,
                scan_type=scan_type,
                templates_used=templates or [],
                scan_parameters=scan_parameters or {},
                egg_id=egg_id,
                status=ScanStatus.PENDING
            )
            
            self.logger.info(f"✅ Created scan record: {scan.id} for {target}")
            return scan
            
        except Exception as e:
            self.logger.error(f"❌ Error creating scan: {e}", exc_info=True)
            raise
    
    def start_scan(self, scan_id: int, kontrol: List[str] = None) -> None:
        """
        Mark scan as started and record deployed Kontrol.
        
        Args:
            scan_id: Scan ID
            kontrol: List of Kontrol names deployed
        """
        try:
            scan = NucleiScan.objects.get(id=scan_id)
            scan.status = ScanStatus.RUNNING
            scan.started_at = timezone.now()
            scan.save(update_fields=['status', 'started_at'])
            
            # Create Kontrol deployment records
            if kontrol:
                deployments = []
                for kontrol_name in kontrol:
                    deployment = SurgeKontrolDeployment(
                        scan=scan,
                        kontrol_name=kontrol_name,
                        kontrol_role=self._get_kontrol_role(kontrol_name),
                        kontrol_type='electric'
                    )
                    deployments.append(deployment)
                
                # Bulk create for efficiency
                SurgeKontrolDeployment.objects.bulk_create(deployments, ignore_conflicts=True)
            
            self.logger.info(f"⚡ Scan {scan_id} started with {len(kontrol or [])} Kontrol")
            
        except NucleiScan.DoesNotExist:
            self.logger.error(f"❌ Scan {scan_id} not found")
            raise
        except Exception as e:
            self.logger.error(f"❌ Error starting scan: {e}", exc_info=True)
            raise
    
    @transaction.atomic
    def store_vulnerabilities(self, scan_id: int, vulnerabilities: List[Dict[str, Any]]) -> int:
        """
        Store vulnerability findings for a scan.
        
        Args:
            scan_id: Scan ID
            vulnerabilities: List of vulnerability data from Nuclei
            
        Returns:
            Number of vulnerabilities stored
        """
        stored_count = 0
        
        try:
            scan = NucleiScan.objects.get(id=scan_id)
            
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            vuln_objects = []
            for vuln_data in vulnerabilities:
                # Extract vulnerability details from Nuclei output
                info = vuln_data.get('info', {})
                severity_str = self._map_severity(info.get('severity', 'unknown'))
                
                vuln = NucleiVulnerability(
                    scan=scan,
                    template_id=vuln_data.get('template-id', 'unknown'),
                    template_name=vuln_data.get('template', ''),
                    vulnerability_name=info.get('name', 'Unknown Vulnerability'),
                    severity=severity_str,
                    vulnerability_type=vuln_data.get('type', ''),
                    cve_id=self._extract_cve(info),
                    cwe_id=self._extract_cwe(info),
                    cvss_score=self._extract_cvss(info),
                    matched_at=vuln_data.get('matched-at', ''),
                    matcher_name=vuln_data.get('matcher-name', ''),
                    matcher_status=vuln_data.get('matcher-status'),
                    extracted_results=vuln_data.get('extracted-results', []),
                    description=info.get('description', ''),
                    reference=str(info.get('reference', [])) if info.get('reference') else None,
                    tags=info.get('tags', []),
                    request_data=vuln_data.get('request', ''),
                    response_data=vuln_data.get('response', ''),
                    curl_command=vuln_data.get('curl-command', ''),
                    info=info,
                    vuln_metadata=vuln_data.get('metadata', {})
                )
                vuln_objects.append(vuln)
                stored_count += 1
                
                # Count severity
                if severity_str in severity_counts:
                    severity_counts[severity_str] += 1
            
            # Bulk create vulnerabilities for efficiency
            if vuln_objects:
                NucleiVulnerability.objects.bulk_create(vuln_objects)
            
            # Update scan summary counts
            scan.total_vulnerabilities = stored_count
            scan.critical_count = severity_counts['critical']
            scan.high_count = severity_counts['high']
            scan.medium_count = severity_counts['medium']
            scan.low_count = severity_counts['low']
            scan.info_count = severity_counts['info']
            scan.save(update_fields=[
                'total_vulnerabilities', 'critical_count', 'high_count',
                'medium_count', 'low_count', 'info_count'
            ])
            
            self.logger.info(f"✅ Stored {stored_count} vulnerabilities for scan {scan_id}")
            self.logger.info(f"   Critical: {severity_counts['critical']}, High: {severity_counts['high']}, "
                           f"Medium: {severity_counts['medium']}, Low: {severity_counts['low']}, Info: {severity_counts['info']}")
            return stored_count
            
        except NucleiScan.DoesNotExist:
            self.logger.error(f"❌ Scan {scan_id} not found")
            raise
        except Exception as e:
            self.logger.error(f"❌ Error storing vulnerabilities: {e}", exc_info=True)
            raise
    
    def update_kontrol_metrics(
        self, 
        scan_id: int, 
        kontrol_name: str, 
        findings_count: int = 0,
        performance_metrics: Dict[str, Any] = None
    ) -> None:
        """
        Update performance metrics for a deployed Kontrol.
        
        Args:
            scan_id: Scan ID
            kontrol_name: Kontrol name
            findings_count: Number of findings from this Kontrol
            performance_metrics: Performance metrics dictionary
        """
        try:
            deployment = SurgeKontrolDeployment.objects.filter(
                scan_id=scan_id,
                kontrol_name=kontrol_name
            ).first()
            
            if deployment:
                deployment.findings_count = findings_count
                deployment.performance_metrics = performance_metrics or {}
                deployment.save(update_fields=['findings_count', 'performance_metrics'])
                self.logger.info(f"⚡ Updated metrics for {kontrol_name} in scan {scan_id}")
            
        except Exception as e:
            self.logger.error(f"❌ Error updating Kontrol metrics: {e}", exc_info=True)
    
    def complete_scan(
        self, 
        scan_id: int, 
        output_file: str = None, 
        success: bool = True,
        error_message: str = None
    ) -> None:
        """
        Mark scan as completed.
        
        Args:
            scan_id: Scan ID
            output_file: Path to output file
            success: Whether scan completed successfully
            error_message: Error message if failed
        """
        try:
            scan = NucleiScan.objects.get(id=scan_id)
            scan.status = ScanStatus.COMPLETED if success else ScanStatus.FAILED
            completed_at = timezone.now()
            scan.completed_at = completed_at
            
            if scan.started_at:
                duration = (completed_at - scan.started_at).total_seconds()
                scan.scan_duration = max(duration, 0.0)
            
            scan.output_file = output_file
            
            if error_message and not success:
                # Store error in scan parameters
                if not scan.scan_parameters:
                    scan.scan_parameters = {}
                scan.scan_parameters['error_message'] = error_message
            
            scan.save()
            
            self.logger.info(f"✅ Scan {scan_id} completed ({scan.status}) - "
                           f"Duration: {scan.scan_duration:.2f}s, "
                           f"Vulnerabilities: {scan.total_vulnerabilities}")
            
        except NucleiScan.DoesNotExist:
            self.logger.error(f"❌ Scan {scan_id} not found")
            raise
        except Exception as e:
            self.logger.error(f"❌ Error completing scan: {e}", exc_info=True)
            raise
    
    def get_scan_results(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get scan results including all vulnerabilities.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Dictionary with scan details and vulnerabilities
        """
        try:
            scan = NucleiScan.objects.select_related().prefetch_related(
                'vulnerabilities', 'kontrol_deployments'
            ).get(id=scan_id)
            
            vulnerabilities = scan.vulnerabilities.all()
            kontrol_deployments = scan.kontrol_deployments.all()
            
            return {
                'scan': self._scan_to_dict(scan),
                'vulnerabilities': [self._vuln_to_dict(v) for v in vulnerabilities],
                'kontrol_deployments': [self._deployment_to_dict(d) for d in kontrol_deployments],
                'summary': {
                    'total_vulnerabilities': scan.total_vulnerabilities,
                    'critical': scan.critical_count,
                    'high': scan.high_count,
                    'medium': scan.medium_count,
                    'low': scan.low_count,
                    'info': scan.info_count,
                    'kontrol_count': len(kontrol_deployments)
                }
            }
            
        except NucleiScan.DoesNotExist:
            return None
    
    def get_recent_scans(self, limit: int = 10, target: str = None) -> List[Dict[str, Any]]:
        """
        Get recent scans, optionally filtered by target.
        
        Args:
            limit: Maximum number of scans to return
            target: Optional target filter
            
        Returns:
            List of scan dictionaries
        """
        queryset = NucleiScan.objects.all()
        
        if target:
            queryset = queryset.filter(target__icontains=target)
        
        scans = queryset.order_by('-started_at')[:limit]
        return [self._scan_to_dict(scan) for scan in scans]
    
    def get_vulnerability_statistics(self) -> Dict[str, Any]:
        """
        Get overall vulnerability statistics.
        
        Returns:
            Dictionary with statistics
        """
        from django.db.models import Count, Q
        
        # Total scans
        total_scans = NucleiScan.objects.count()
        
        # Total vulnerabilities
        total_vulns = NucleiVulnerability.objects.count()
        
        # Severity breakdown
        severity_stats = {}
        for severity_value, severity_label in ScanSeverity.choices:
            count = NucleiVulnerability.objects.filter(severity=severity_value).count()
            severity_stats[severity_value] = count
        
        # Most common vulnerabilities
        common_vulns = NucleiVulnerability.objects.values('vulnerability_name').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        return {
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': severity_stats,
            'most_common_vulnerabilities': [
                {'name': item['vulnerability_name'], 'count': item['count']}
                for item in common_vulns
            ]
        }
    
    def _map_severity(self, severity_str: str) -> str:
        """Map Nuclei severity string to ScanSeverity choice value."""
        # Map to choice values directly (strings)
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
            'informational': 'info',
        }
        return severity_map.get(severity_str.lower(), 'unknown')
    
    def _extract_cve(self, info: Dict) -> Optional[str]:
        """Extract CVE ID from info."""
        classification = info.get('classification', {})
        cve_id = classification.get('cve-id')
        if isinstance(cve_id, list):
            return cve_id[0] if cve_id else None
        return cve_id
    
    def _extract_cwe(self, info: Dict) -> Optional[str]:
        """Extract CWE ID from info."""
        classification = info.get('classification', {})
        cwe_list = classification.get('cwe-id', [])
        if isinstance(cwe_list, list):
            return cwe_list[0] if cwe_list else None
        return cwe_list
    
    def _extract_cvss(self, info: Dict) -> Optional[float]:
        """Extract CVSS score from info."""
        classification = info.get('classification', {})
        cvss = classification.get('cvss-score')
        if cvss:
            try:
                return float(cvss)
            except (ValueError, TypeError):
                pass
        return None
    
    def _get_kontrol_role(self, kontrol_name: str) -> str:
        """Get role for a Kontrol based on its name."""
        roles = {
            'Sparky': 'basic_scanner',
            'Thunder': 'advanced_analyzer',
            'Powerhouse': 'power_scanner',
            'Bolt': 'agile_scanner',
            'Detector': 'magnetic_detector',
            'Explosive': 'explosive_scanner',
            'Recon': 'elite_reconnaissance'
        }
        return roles.get(kontrol_name, 'scanner')
    
    def _scan_to_dict(self, scan: NucleiScan) -> Dict[str, Any]:
        """Convert NucleiScan model to dictionary."""
        return {
            'id': str(scan.id),
            'target': scan.target,
            'target_domain': scan.target_domain,
            'scan_type': scan.scan_type,
            'status': scan.status,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'scan_duration': scan.scan_duration,
            'total_vulnerabilities': scan.total_vulnerabilities,
            'critical_count': scan.critical_count,
            'high_count': scan.high_count,
            'medium_count': scan.medium_count,
            'low_count': scan.low_count,
            'info_count': scan.info_count,
            'templates_used': scan.templates_used,
            'scan_parameters': scan.scan_parameters,
            'pokemon_deployed': scan.pokemon_deployed,
            'output_file': scan.output_file,
            'log_file': scan.log_file,
            'egg_id': scan.egg_id,
            'created_at': scan.created_at.isoformat() if scan.created_at else None,
            'updated_at': scan.updated_at.isoformat() if scan.updated_at else None,
        }
    
    def _vuln_to_dict(self, vuln: NucleiVulnerability) -> Dict[str, Any]:
        """Convert NucleiVulnerability model to dictionary."""
        return {
            'id': str(vuln.id),
            'scan_id': str(vuln.scan_id),
            'template_id': vuln.template_id,
            'template_name': vuln.template_name,
            'vulnerability_name': vuln.vulnerability_name,
            'severity': vuln.severity,
            'vulnerability_type': vuln.vulnerability_type,
            'cve_id': vuln.cve_id,
            'cwe_id': vuln.cwe_id,
            'cvss_score': float(vuln.cvss_score) if vuln.cvss_score else None,
            'matched_at': vuln.matched_at,
            'matcher_name': vuln.matcher_name,
            'matcher_status': vuln.matcher_status,
            'description': vuln.description,
            'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None,
        }
    
    def _deployment_to_dict(self, deployment: SurgeKontrolDeployment) -> Dict[str, Any]:
        """Convert SurgeKontrolDeployment model to dictionary."""
        return {
            'id': str(deployment.id),
            'scan_id': str(deployment.scan_id),
            'kontrol_name': deployment.kontrol_name,
            'kontrol_role': deployment.kontrol_role,
            'kontrol_type': deployment.kontrol_type,
            'findings_count': deployment.findings_count,
            'performance_metrics': deployment.performance_metrics,
            'deployed_at': deployment.deployed_at.isoformat() if deployment.deployed_at else None,
        }


# Global instance
surge_db = SurgeDatabaseIntegration()


# Convenience functions
def create_scan(target: str, scan_type: str = 'comprehensive', **kwargs) -> NucleiScan:
    """Convenience function to create a scan."""
    return surge_db.create_scan(target, scan_type, **kwargs)


def get_scan_results(scan_id: int) -> Optional[Dict[str, Any]]:
    """Convenience function to get scan results."""
    return surge_db.get_scan_results(scan_id)


def get_recent_scans(limit: int = 10, target: str = None) -> List[Dict[str, Any]]:
    """Convenience function to get recent scans."""
    return surge_db.get_recent_scans(limit, target)
