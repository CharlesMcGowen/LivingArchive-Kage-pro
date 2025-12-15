"""
Django ORM Models for Surge Nuclei Scanner
==========================================

Models for storing Nuclei scan results and vulnerabilities.
Replaces SQLAlchemy models with native Django ORM.
"""

from django.db import models
from django.utils import timezone


class ScanStatus(models.TextChoices):
    """Scan execution status choices"""
    PENDING = 'pending', 'Pending'
    RUNNING = 'running', 'Running'
    COMPLETED = 'completed', 'Completed'
    FAILED = 'failed', 'Failed'


class ScanSeverity(models.TextChoices):
    """Vulnerability severity levels"""
    CRITICAL = 'critical', 'Critical'
    HIGH = 'high', 'High'
    MEDIUM = 'medium', 'Medium'
    LOW = 'low', 'Low'
    INFO = 'info', 'Info'
    UNKNOWN = 'unknown', 'Unknown'


class NucleiScan(models.Model):
    """Represents a Nuclei vulnerability scan"""
    
    # Target information
    target = models.CharField(max_length=2048, db_index=True, help_text="Target URL or IP address")
    target_domain = models.CharField(max_length=255, null=True, blank=True, db_index=True, help_text="Extracted domain name")
    scan_type = models.CharField(max_length=50, help_text="Scan type: comprehensive, quick, stealth")
    
    # Scan configuration
    templates_used = models.JSONField(default=list, blank=True, help_text="List of Nuclei template IDs used")
    scan_parameters = models.JSONField(default=dict, blank=True, help_text="Additional scan parameters")
    pokemon_deployed = models.JSONField(default=list, blank=True, help_text="List of Pokemon/Kontrol agents deployed")
    
    # Scan execution
    status = models.CharField(
        max_length=20,
        choices=ScanStatus.choices,
        default=ScanStatus.PENDING,
        db_index=True,
        help_text="Current scan status"
    )
    started_at = models.DateTimeField(default=timezone.now, db_index=True, help_text="When the scan started")
    completed_at = models.DateTimeField(null=True, blank=True, help_text="When the scan completed")
    scan_duration = models.FloatField(null=True, blank=True, help_text="Scan duration in seconds")
    
    # Results summary
    total_vulnerabilities = models.IntegerField(default=0, help_text="Total vulnerabilities found")
    critical_count = models.IntegerField(default=0, help_text="Number of critical vulnerabilities")
    high_count = models.IntegerField(default=0, help_text="Number of high severity vulnerabilities")
    medium_count = models.IntegerField(default=0, help_text="Number of medium severity vulnerabilities")
    low_count = models.IntegerField(default=0, help_text="Number of low severity vulnerabilities")
    info_count = models.IntegerField(default=0, help_text="Number of informational findings")
    
    # Output files
    output_file = models.CharField(max_length=1024, null=True, blank=True, help_text="Path to scan output file")
    log_file = models.CharField(max_length=1024, null=True, blank=True, help_text="Path to scan log file")
    
    # Integration with Pokemon AI
    egg_id = models.CharField(max_length=36, null=True, blank=True, db_index=True, help_text="Related Kontrol AI egg ID")
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True, help_text="When the scan record was created")
    updated_at = models.DateTimeField(auto_now=True, help_text="When the scan record was last updated")
    
    class Meta:
        db_table = 'nuclei_scans'
        indexes = [
            models.Index(fields=['status', 'started_at']),
            models.Index(fields=['target']),
            models.Index(fields=['egg_id']),
        ]
        ordering = ['-started_at']
        verbose_name = 'Nuclei Scan'
        verbose_name_plural = 'Nuclei Scans'
    
    def __str__(self):
        return f"NucleiScan({self.id}): {self.target} - {self.status}"


class NucleiVulnerability(models.Model):
    """Represents a vulnerability found by Nuclei"""
    
    scan = models.ForeignKey(
        NucleiScan,
        on_delete=models.CASCADE,
        related_name='vulnerabilities',
        db_index=True,
        help_text="The scan that found this vulnerability"
    )
    
    # Vulnerability identification
    template_id = models.CharField(max_length=255, db_index=True, help_text="Nuclei template ID")
    template_name = models.CharField(max_length=500, null=True, blank=True, help_text="Human-readable template name")
    vulnerability_name = models.CharField(max_length=500, help_text="Name of the vulnerability")
    
    # Severity and classification
    severity = models.CharField(
        max_length=20,
        choices=ScanSeverity.choices,
        default=ScanSeverity.UNKNOWN,
        db_index=True,
        help_text="Vulnerability severity level"
    )
    vulnerability_type = models.CharField(max_length=100, null=True, blank=True, db_index=True, help_text="Type/category of vulnerability")
    cve_id = models.CharField(max_length=50, null=True, blank=True, db_index=True, help_text="CVE identifier if applicable")
    cwe_id = models.CharField(max_length=50, null=True, blank=True, help_text="CWE identifier if applicable")
    cvss_score = models.FloatField(null=True, blank=True, help_text="CVSS score if available")
    
    # Technical details
    matched_at = models.CharField(max_length=2048, help_text="URL or endpoint where vulnerability was found")
    matcher_name = models.CharField(max_length=255, null=True, blank=True, help_text="Nuclei matcher that triggered")
    matcher_status = models.CharField(max_length=50, null=True, blank=True, help_text="Matcher status code")
    extracted_results = models.JSONField(default=list, blank=True, help_text="Extracted data from matchers")
    
    # Vulnerability details
    description = models.TextField(null=True, blank=True, help_text="Detailed description of the vulnerability")
    reference = models.TextField(null=True, blank=True, help_text="References and links")
    tags = models.JSONField(default=list, blank=True, help_text="Tags associated with the vulnerability")
    
    # Request/Response data
    request_data = models.TextField(null=True, blank=True, help_text="HTTP request that triggered the vulnerability")
    response_data = models.TextField(null=True, blank=True, help_text="HTTP response from the server")
    curl_command = models.TextField(null=True, blank=True, help_text="cURL command to reproduce")
    
    # Metadata from Nuclei
    info = models.JSONField(default=dict, blank=True, help_text="Template info metadata")
    vuln_metadata = models.JSONField(default=dict, blank=True, help_text="Additional vulnerability metadata")
    
    # Timestamps
    discovered_at = models.DateTimeField(default=timezone.now, db_index=True, help_text="When the vulnerability was discovered")
    
    class Meta:
        db_table = 'nuclei_vulnerabilities'
        indexes = [
            models.Index(fields=['scan', 'severity']),
            models.Index(fields=['template_id']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['discovered_at']),
        ]
        ordering = ['-discovered_at']
        verbose_name = 'Nuclei Vulnerability'
        verbose_name_plural = 'Nuclei Vulnerabilities'
    
    def __str__(self):
        return f"{self.vulnerability_name} ({self.severity})"


class SurgeKontrolDeployment(models.Model):
    """Tracks Kontrol team deployments for scans"""
    
    scan = models.ForeignKey(
        NucleiScan,
        on_delete=models.CASCADE,
        related_name='kontrol_deployments',
        db_index=True,
        help_text="The scan this Kontrol was deployed for"
    )
    kontrol_name = models.CharField(max_length=100, help_text="Name of the Kontrol agent")
    kontrol_role = models.CharField(max_length=100, null=True, blank=True, help_text="Role of the Kontrol agent")
    kontrol_type = models.CharField(max_length=50, default='electric', help_text="Type of Kontrol (electric, etc.)")
    findings_count = models.IntegerField(default=0, help_text="Number of findings from this Kontrol")
    performance_metrics = models.JSONField(default=dict, blank=True, help_text="Performance metrics for this deployment")
    deployed_at = models.DateTimeField(default=timezone.now, help_text="When the Kontrol was deployed")
    
    class Meta:
        db_table = 'surge_kontrol_deployments'
        unique_together = [['scan', 'kontrol_name']]
        indexes = [
            models.Index(fields=['scan', 'kontrol_name']),
        ]
        verbose_name = 'Surge Kontrol Deployment'
        verbose_name_plural = 'Surge Kontrol Deployments'
    
    def __str__(self):
        return f"{self.kontrol_name} on scan {self.scan_id}"
