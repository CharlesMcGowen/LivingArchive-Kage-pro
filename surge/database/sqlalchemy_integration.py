#!/usr/bin/env python3
"""
Surge SQLAlchemy Database Integration
====================================

Modern SQLAlchemy-based database integration for Surge Nuclei scanning.
Replaces psycopg2 direct connections with proper ORM using EgoLlama infrastructure.

Author: EGO Revolution Team
Version: 2.0.0 - SQLAlchemy Migration
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

# Import EgoLlama SQLAlchemy setup
import sys
from pathlib import Path

# Add EgoLlama to path for imports
egollama_root = Path('/mnt/webapps-nvme/EgoLlama')
if egollama_root.exists():
    sys.path.insert(0, str(egollama_root))
else:
    # Try Docker path
    egollama_docker = Path('/app/egollama')
    if egollama_docker.exists():
        sys.path.insert(0, str(egollama_docker))

from database import SessionLocal, engine, Base
from vulnerability_models import (
    NucleiScan, NucleiVulnerability, SurgeKontrolDeployment, NucleiTemplate,
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


class SurgeSQLAlchemyIntegration:
    """
    Modern SQLAlchemy-based database integration for Surge.
    
    Uses EgoLlama's SQLAlchemy setup for proper ORM operations.
    Provides high-level API for Surge scanning operations.
    """
    
    def __init__(self):
        """Initialize Surge SQLAlchemy integration."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("⚡ Surge SQLAlchemy Integration initialized")
        
        # Create tables if they don't exist
        try:
            Base.metadata.create_all(bind=engine)
            self.logger.info("✅ Vulnerability tables created/verified")
        except Exception as e:
            self.logger.error(f"❌ Error creating tables: {e}")
    
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
        db = SessionLocal()
        try:
            # Extract domain from target
            from urllib.parse import urlparse
            parsed = urlparse(target if target.startswith('http') else f'http://{target}')
            domain = parsed.netloc or target
            
            scan = NucleiScan(
                target=target,
                target_domain=domain,
                scan_type=scan_type,
                templates_used=templates or [],
                scan_parameters=scan_parameters or {},
                egg_id=egg_id,
                status=ScanStatus.PENDING
            )
            
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            self.logger.info(f"✅ Created scan record: {scan.id} for {target}")
            return scan
            
        except Exception as e:
            db.rollback()
            self.logger.error(f"❌ Error creating scan: {e}")
            raise
        finally:
            db.close()
    
    def start_scan(self, scan_id: int, kontrol: List[str] = None) -> None:
        """
        Mark scan as started and record deployed Kontrol.
        
        Args:
            scan_id: Scan ID
            kontrol: List of Kontrol names deployed
        """
        db = SessionLocal()
        try:
            scan = db.query(NucleiScan).filter(NucleiScan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                timestamp = datetime.now(timezone.utc)
                scan.started_at = timestamp
                scan.kontrol_deployed = kontrol or []
                
                # Create Kontrol deployment records
                if kontrol:
                    for kontrol_name in kontrol:
                        deployment = SurgeKontrolDeployment(
                            scan_id=scan_id,
                            kontrol_name=kontrol_name,
                            kontrol_role=self._get_kontrol_role(kontrol_name),
                            kontrol_type='electric'
                        )
                        db.add(deployment)
                
                db.commit()
                self.logger.info(f"⚡ Scan {scan_id} started with {len(kontrol or [])} Kontrol")
            
        except Exception as e:
            db.rollback()
            self.logger.error(f"❌ Error starting scan: {e}")
            raise
        finally:
            db.close()
    
    def store_vulnerabilities(self, scan_id: int, vulnerabilities: List[Dict[str, Any]]) -> int:
        """
        Store vulnerability findings for a scan.
        
        Args:
            scan_id: Scan ID
            vulnerabilities: List of vulnerability data from Nuclei
            
        Returns:
            Number of vulnerabilities stored
        """
        db = SessionLocal()
        stored_count = 0
        
        try:
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            for vuln_data in vulnerabilities:
                # Extract vulnerability details from Nuclei output
                info = vuln_data.get('info', {})
                severity = self._map_severity(info.get('severity', 'unknown'))
                
                vuln = NucleiVulnerability(
                    scan_id=scan_id,
                    template_id=vuln_data.get('template-id', 'unknown'),
                    template_name=vuln_data.get('template', ''),
                    vulnerability_name=info.get('name', 'Unknown Vulnerability'),
                    severity=severity,
                    vulnerability_type=vuln_data.get('type', ''),
                    cve_id=self._extract_cve(info),
                    cwe_id=self._extract_cwe(info),
                    cvss_score=self._extract_cvss(info),
                    matched_at=vuln_data.get('matched-at', ''),
                    matcher_name=vuln_data.get('matcher-name', ''),
                    matcher_status=vuln_data.get('matcher-status'),
                    extracted_results=vuln_data.get('extracted-results', []),
                    description=info.get('description', ''),
                    reference=str(info.get('reference', [])),
                    tags=info.get('tags', []),
                    request_data=vuln_data.get('request', ''),
                    response_data=vuln_data.get('response', ''),
                    curl_command=vuln_data.get('curl-command', ''),
                    info=info,
                    vuln_metadata=vuln_data.get('metadata', {})
                )
                
                db.add(vuln)
                stored_count += 1
                
                # Count severity
                severity_str = severity.value
                if severity_str in severity_counts:
                    severity_counts[severity_str] += 1
            
            # Update scan summary counts
            scan = db.query(NucleiScan).filter(NucleiScan.id == scan_id).first()
            if scan:
                scan.total_vulnerabilities = stored_count
                scan.critical_count = severity_counts['critical']
                scan.high_count = severity_counts['high']
                scan.medium_count = severity_counts['medium']
                scan.low_count = severity_counts['low']
                scan.info_count = severity_counts['info']
            
            db.commit()
            self.logger.info(f"✅ Stored {stored_count} vulnerabilities for scan {scan_id}")
            self.logger.info(f"   Critical: {severity_counts['critical']}, High: {severity_counts['high']}, "
                           f"Medium: {severity_counts['medium']}, Low: {severity_counts['low']}, Info: {severity_counts['info']}")
            return stored_count
            
        except Exception as e:
            db.rollback()
            self.logger.error(f"❌ Error storing vulnerabilities: {e}")
            raise
        finally:
            db.close()
    
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
        db = SessionLocal()
        try:
            deployment = db.query(SurgeKontrolDeployment).filter(
                SurgeKontrolDeployment.scan_id == scan_id,
                SurgeKontrolDeployment.kontrol_name == kontrol_name
            ).first()
            
            if deployment:
                deployment.findings_count = findings_count
                deployment.performance_metrics = performance_metrics or {}
                db.commit()
                self.logger.info(f"⚡ Updated metrics for {kontrol_name} in scan {scan_id}")
            
        except Exception as e:
            db.rollback()
            self.logger.error(f"❌ Error updating Kontrol metrics: {e}")
        finally:
            db.close()
    
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
        db = SessionLocal()
        try:
            scan = db.query(NucleiScan).filter(NucleiScan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.COMPLETED if success else ScanStatus.FAILED
                completed_at = datetime.now(timezone.utc)
                scan.completed_at = completed_at
                
                if scan.started_at:
                    started_at = scan.started_at
                    if started_at.tzinfo is None:
                        started_at = started_at.replace(tzinfo=timezone.utc)
                    duration = (completed_at - started_at).total_seconds()
                    scan.scan_duration = max(duration, 0.0)
                scan.output_file = output_file
                
                if error_message and not success:
                    # Store error in scan parameters
                    if not scan.scan_parameters:
                        scan.scan_parameters = {}
                    scan.scan_parameters['error_message'] = error_message
                
                db.commit()
                self.logger.info(f"✅ Scan {scan_id} completed ({scan.status.value}) - "
                               f"Duration: {scan.scan_duration:.2f}s, "
                               f"Vulnerabilities: {scan.total_vulnerabilities}")
            
        except Exception as e:
            db.rollback()
            self.logger.error(f"❌ Error completing scan: {e}")
            raise
        finally:
            db.close()
    
    def get_scan_results(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get scan results including all vulnerabilities.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Dictionary with scan details and vulnerabilities
        """
        db = SessionLocal()
        try:
            scan = db.query(NucleiScan).filter(NucleiScan.id == scan_id).first()
            if not scan:
                return None
            
            vulnerabilities = db.query(NucleiVulnerability).filter(
                NucleiVulnerability.scan_id == scan_id
            ).all()
            
            kontrol_deployments = db.query(SurgeKontrolDeployment).filter(
                SurgeKontrolDeployment.scan_id == scan_id
            ).all()
            
            return {
                'scan': scan.to_dict(),
                'vulnerabilities': [v.to_dict() for v in vulnerabilities],
                'kontrol_deployments': [p.to_dict() for p in kontrol_deployments],
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
            
        finally:
            db.close()
    
    def get_recent_scans(self, limit: int = 10, target: str = None) -> List[Dict[str, Any]]:
        """
        Get recent scans, optionally filtered by target.
        
        Args:
            limit: Maximum number of scans to return
            target: Optional target filter
            
        Returns:
            List of scan dictionaries
        """
        db = SessionLocal()
        try:
            query = db.query(NucleiScan)
            
            if target:
                query = query.filter(NucleiScan.target.contains(target))
            
            scans = query.order_by(NucleiScan.started_at.desc()).limit(limit).all()
            return [scan.to_dict() for scan in scans]
            
        finally:
            db.close()
    
    def get_vulnerability_statistics(self) -> Dict[str, Any]:
        """
        Get overall vulnerability statistics.
        
        Returns:
            Dictionary with statistics
        """
        db = SessionLocal()
        try:
            from sqlalchemy import func as sql_func
            
            # Total scans
            total_scans = db.query(sql_func.count(NucleiScan.id)).scalar()
            
            # Total vulnerabilities
            total_vulns = db.query(sql_func.count(NucleiVulnerability.id)).scalar()
            
            # Severity breakdown
            severity_stats = {}
            for severity in ScanSeverity:
                count = db.query(sql_func.count(NucleiVulnerability.id)).filter(
                    NucleiVulnerability.severity == severity
                ).scalar()
                severity_stats[severity.value] = count
            
            # Most common vulnerabilities
            common_vulns = db.query(
                NucleiVulnerability.vulnerability_name,
                sql_func.count(NucleiVulnerability.id).label('count')
            ).group_by(
                NucleiVulnerability.vulnerability_name
            ).order_by(
                sql_func.count(NucleiVulnerability.id).desc()
            ).limit(10).all()
            
            return {
                'total_scans': total_scans,
                'total_vulnerabilities': total_vulns,
                'severity_breakdown': severity_stats,
                'most_common_vulnerabilities': [
                    {'name': name, 'count': count}
                    for name, count in common_vulns
                ]
            }
            
        finally:
            db.close()
    
    def _map_severity(self, severity_str: str) -> ScanSeverity:
        """Map Nuclei severity string to enum."""
        severity_map = {
            'critical': ScanSeverity.CRITICAL,
            'high': ScanSeverity.HIGH,
            'medium': ScanSeverity.MEDIUM,
            'low': ScanSeverity.LOW,
            'info': ScanSeverity.INFO,
            'informational': ScanSeverity.INFO,
        }
        return severity_map.get(severity_str.lower(), ScanSeverity.UNKNOWN)
    
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


# Global instance
surge_db = SurgeSQLAlchemyIntegration()


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

