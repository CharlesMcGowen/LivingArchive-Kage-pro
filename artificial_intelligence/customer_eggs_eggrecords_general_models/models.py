"""
Django ORM Models for Customer Eggs EggRecords General Models
=============================================================
Converted from SQLAlchemy to Django ORM for better Django integration.
These models match the existing database schema.
"""

from django.db import models
import uuid
import re


class EggRecord(models.Model):
    """
    EggRecord model - represents a target subdomain/domain for scanning.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subDomain = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    domainname = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    alive = models.BooleanField(default=True, null=False, db_index=True)
    skipScan = models.BooleanField(default=False, null=False, db_index=True)
    bugsy_priority_score = models.FloatField(null=True, blank=True, db_index=True)
    bugsy_curation_metadata = models.JSONField(null=True, blank=True)
    bugsy_last_curated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_eggrecord'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['subDomain']),
            models.Index(fields=['domainname']),
            models.Index(fields=['alive']),
            models.Index(fields=['skipScan']),
            models.Index(fields=['bugsy_priority_score']),
        ]
        verbose_name = 'Egg Record'
        verbose_name_plural = 'Egg Records'
    
    def __str__(self):
        return f"{self.subDomain or self.domainname or str(self.id)}"


class Nmap(models.Model):
    """
    Nmap model - stores Nmap scan results.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    md5 = models.CharField(max_length=255, null=False, blank=False)
    target = models.CharField(max_length=255, null=False, blank=False)
    scan_type = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    scan_stage = models.CharField(max_length=100, null=True, blank=True)
    scan_status = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    port = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    service_name = models.CharField(max_length=100, null=True, blank=True)
    service_version = models.CharField(max_length=255, null=True, blank=True)
    open_ports = models.TextField(null=True, blank=True)  # JSON/Text field for open ports array
    scan_command = models.TextField(null=True, blank=True)
    name = models.CharField(max_length=255, null=True, blank=True)
    hostname = models.CharField(max_length=255, null=True, blank=True)
    date = models.DateTimeField(null=True, blank=True)
    record_id_id = models.UUIDField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(null=False, auto_now_add=True)
    updated_at = models.DateTimeField(null=False, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_nmap'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['scan_type']),
            models.Index(fields=['scan_status']),
            models.Index(fields=['port']),
            models.Index(fields=['record_id_id']),
        ]
        verbose_name = 'Nmap Scan'
        verbose_name_plural = 'Nmap Scans'
    
    def __str__(self):
        return f"Nmap scan: {self.target} ({self.scan_type})"


class TechnologyFingerprint(models.Model):
    """
    TechnologyFingerprint model - stores technology detection results.
    
    Created by Oak's fingerprinting service.
    Can be linked to Nmap scans and RequestMetaData for traceability.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    egg_record_id = models.UUIDField(null=False, db_index=True)
    nmap_scan_id = models.UUIDField(null=True, blank=True, db_index=True)
    request_metadata_id = models.UUIDField(null=True, blank=True, db_index=True)
    technology_name = models.CharField(max_length=255, null=False, blank=False, db_index=True)
    technology_version = models.CharField(max_length=100, null=True, blank=True)
    technology_category = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    confidence_score = models.FloatField(null=False, default=0.0, db_index=True)
    detection_method = models.CharField(max_length=100, null=True, blank=True)
    raw_detection_data = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'enrichment_system_technologyfingerprint'
        managed = True  # Enable migrations to create table
        indexes = [
            models.Index(fields=['egg_record_id']),
            models.Index(fields=['technology_name']),
            models.Index(fields=['technology_category']),
            models.Index(fields=['confidence_score']),
        ]
        verbose_name = 'Technology Fingerprint'
        verbose_name_plural = 'Technology Fingerprints'
    
    def __str__(self):
        return f"TechnologyFingerprint: {self.technology_name} (confidence: {self.confidence_score})"


class CVEFingerprintMatch(models.Model):
    """
    CVEFingerprintMatch model - stores CVE matches for technology fingerprints.
    
    Links technology fingerprints to known CVEs with match confidence.
    Created by Oak's CVE matching service.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    egg_record_id = models.UUIDField(null=False, db_index=True)
    technology_fingerprint_id = models.UUIDField(null=True, blank=True, db_index=True)  # Optional - can match without fingerprint
    cve_id = models.CharField(max_length=50, null=False, blank=False, db_index=True)  # e.g., "CVE-2023-1234"
    cve_severity = models.CharField(max_length=20, null=True, blank=True, db_index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cve_cvss_score = models.FloatField(null=True, blank=True, db_index=True)  # CVSS score (0.0-10.0)
    technology_name = models.CharField(max_length=255, null=True, blank=True, db_index=True)  # Technology from fingerprint
    match_confidence = models.FloatField(null=False, default=0.0, db_index=True)
    nuclei_template_available = models.BooleanField(default=False, db_index=True)  # Whether Nuclei template exists
    nuclei_template_ids = models.JSONField(null=True, blank=True, default=list)  # Array of template IDs
    recommended_for_scanning = models.BooleanField(default=True, db_index=True)  # Whether to recommend for scanning
    bugsy_confidence_notes = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'enrichment_system_cvefingerprintmatch'
        managed = True  # Enable migrations to create table
        indexes = [
            models.Index(fields=['egg_record_id']),
            models.Index(fields=['technology_fingerprint_id']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['cve_severity']),
            models.Index(fields=['cve_cvss_score']),
            models.Index(fields=['match_confidence']),
            models.Index(fields=['recommended_for_scanning']),
            models.Index(fields=['nuclei_template_available']),
        ]
        verbose_name = 'CVE Fingerprint Match'
        verbose_name_plural = 'CVE Fingerprint Matches'
    
    def __str__(self):
        return f"CVEFingerprintMatch: {self.cve_id} (confidence: {self.match_confidence})"


class RequestMetaData(models.Model):
    """
    RequestMetaData model - stores HTTP request/response metadata.
    
    Created by Kumo's HTTP spidering service.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id_id = models.UUIDField(null=True, blank=True, db_index=True)
    request_id = models.CharField(max_length=255, null=False, blank=False)
    session_id = models.CharField(max_length=255, null=False, blank=False)
    target_url = models.CharField(max_length=2048, null=False, blank=False)
    request_method = models.CharField(max_length=10, null=False, blank=False)
    request_headers = models.JSONField(null=False, default=dict)
    request_body = models.TextField(null=True, blank=True)
    response_status = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(null=False, default=dict)
    response_body = models.TextField(null=True, blank=True)
    response_time_ms = models.FloatField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=False, blank=False)
    referer = models.CharField(max_length=255, null=True, blank=True)
    timestamp = models.DateTimeField(null=False, blank=False)
    created_at = models.DateTimeField(null=False, auto_now_add=True)
    updated_at = models.DateTimeField(null=False, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_requestmetadata'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['record_id_id']),
            models.Index(fields=['target_url']),
            models.Index(fields=['response_status']),
        ]
        verbose_name = 'Request Metadata'
        verbose_name_plural = 'Request Metadata'
    
    def __str__(self):
        return f"RequestMetaData: {self.target_url} (status: {self.response_status})"


class DNSQuery(models.Model):
    """
    DNSQuery model - stores DNS query results for an EggRecord.
    
    Represents DNS resolution data including A, AAAA, CNAME, MX, TXT, NS records.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id_id = models.UUIDField(null=False, db_index=True)
    md5 = models.CharField(max_length=255, null=False, blank=False)
    A = models.GenericIPAddressField(null=True, blank=True, protocol='IPv4')  # IPv4 address
    AAAA = models.CharField(max_length=255, null=False, default='')  # IPv6 address
    NS = models.TextField(null=False, default='')  # Name server records
    CNAME = models.TextField(null=False, default='')  # Canonical name records
    r = models.TextField(null=False, default='')  # Additional records
    MX = models.TextField(null=False, default='')  # Mail exchange records
    TXT = models.TextField(null=False, default='')  # Text records
    ANY = models.TextField(null=False, default='')  # Any type records
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_dnsquery'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['record_id_id']),
            models.Index(fields=['md5']),
        ]
        verbose_name = 'DNS Query'
        verbose_name_plural = 'DNS Queries'
    
    def __str__(self):
        return f"DNSQuery: {self.record_id_id}"


class DNSAuthority(models.Model):
    """
    DNSAuthority model - stores DNS authority section data for an EggRecord.
    
    Represents authoritative DNS records (NS records, SOA, etc.).
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id_id = models.UUIDField(null=False, db_index=True)
    md5 = models.CharField(max_length=255, null=False, blank=False)
    A = models.GenericIPAddressField(null=True, blank=True, protocol='IPv4')  # IPv4 address
    AAAA = models.CharField(max_length=255, null=False, default='')  # IPv6 address
    NS = models.CharField(max_length=255, null=False, default='')  # Name server records
    CNAME = models.CharField(max_length=255, null=False, default='')  # Canonical name records
    r = models.CharField(max_length=255, null=False, default='')  # Additional records
    MX = models.TextField(null=False, default='')  # Mail exchange records
    TXT = models.TextField(null=False, default='')  # Text records
    ANY = models.CharField(max_length=255, null=False, default='')  # Any type records
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_dnsauthority'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['record_id_id']),
            models.Index(fields=['md5']),
        ]
        verbose_name = 'DNS Authority'
        verbose_name_plural = 'DNS Authorities'
    
    def __str__(self):
        return f"DNSAuthority: {self.record_id_id}"


class Eggs(models.Model):
    """
    Eggs model - parent domain model.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.AutoField(primary_key=True)
    domainname = models.CharField(max_length=255, null=False, unique=True, db_index=True)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_eggs'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['domainname']),
        ]
        verbose_name = 'Eggs'
        verbose_name_plural = 'Eggs'
    
    def __str__(self):
        return f"Eggs: {self.domainname}"


class RyuAssessment(models.Model):
    """
    RyuAssessment model - stores security threat assessments by Ryu.
    
    Each assessment correlates findings from Kage (Nmap scans) and Kumo (HTTP spidering)
    to provide comprehensive security analysis.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id_id = models.UUIDField(null=False, db_index=True)
    risk_level = models.CharField(max_length=50, null=False, blank=False, db_index=True)
    threat_summary = models.TextField(null=True, blank=True)
    vulnerabilities = models.JSONField(null=True, blank=True)  # JSONB fallback to JSON
    attack_vectors = models.JSONField(null=True, blank=True)  # JSONB fallback to JSON
    remediation_priorities = models.JSONField(null=True, blank=True)  # JSONB fallback to JSON
    narrative = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(null=False, auto_now_add=True)
    updated_at = models.DateTimeField(null=False, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        # LEGACY TABLE NAME: Requires database migration from jadeassessment to ryuassessment for legal compliance
        db_table = 'customer_eggs_eggrecords_general_models_jadeassessment'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['record_id_id']),
            models.Index(fields=['risk_level']),
            models.Index(fields=['record_id_id', 'risk_level']),  # Combined index
        ]
        verbose_name = 'Ryu Assessment'
        verbose_name_plural = 'Ryu Assessments'
    
    def __str__(self):
        return f"RyuAssessment: {self.record_id_id} (risk: {self.risk_level})"


class HTTPRequestResponse(models.Model):
    """
    HTTPRequestResponse model - stores HTTP exchange data.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    egg_record_id = models.UUIDField(null=False, db_index=True)
    request_url = models.CharField(max_length=2048, null=True, blank=True)
    request_method = models.CharField(max_length=10, null=True, blank=True)
    request_headers = models.JSONField(null=True, blank=True)
    request_body = models.TextField(null=True, blank=True)
    response_status = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(null=True, blank=True)
    response_body = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_httprequestresponse'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['egg_record_id']),
            models.Index(fields=['response_status']),
        ]
        verbose_name = 'HTTP Request Response'
        verbose_name_plural = 'HTTP Request Responses'
    
    def __str__(self):
        return f"HTTPRequestResponse: {self.request_url} (status: {self.response_status})"


class SecurityPayload(models.Model):
    """
    SecurityPayload model - stores base payload templates (SQL injection, XSS, etc.).
    
    These are TEMPLATES that Sabrina will mutate for specific targets.
    Many may never work as-is and require mutations/refactoring.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.BigAutoField(primary_key=True)
    payload = models.TextField(null=False, blank=False)
    payload_hash = models.CharField(max_length=64, null=False, blank=False, unique=True, db_index=True)  # SHA256 for uniqueness
    payload_type = models.CharField(max_length=100, null=True, blank=True, db_index=True)  # sql_injection, xss, etc.
    source = models.CharField(max_length=100, null=True, blank=True, db_index=True)  # "PayloadsAllTheThings", etc.
    source_file_path = models.TextField(null=True, blank=True)
    source_category = models.CharField(max_length=200, null=True, blank=True)
    source_url = models.CharField(max_length=500, null=True, blank=True)
    title = models.CharField(max_length=500, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    bypass_techniques = models.JSONField(null=True, blank=True)  # Array of techniques
    target_technology = models.JSONField(null=True, blank=True)  # Array of technologies
    encoding_methods = models.JSONField(null=True, blank=True)  # Array of encoding methods
    tags = models.JSONField(null=True, blank=True)  # Array of tags
    effectiveness_score = models.FloatField(null=True, blank=True, default=0.0, db_index=True)  # 0.0-1.0
    usage_count = models.IntegerField(null=True, blank=True, default=0, db_index=True)
    success_count = models.IntegerField(null=True, blank=True, default=0)
    failure_count = models.IntegerField(null=True, blank=True, default=0)
    ai_confidence = models.FloatField(null=True, blank=True, default=0.0)
    is_template = models.BooleanField(default=True, db_index=True)  # Always True for this table
    has_been_mutated = models.BooleanField(default=False, db_index=True)
    likely_ineffective = models.BooleanField(default=False, db_index=True)
    sabrina_approved = models.BooleanField(default=False)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_securitypayload'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['payload_hash']),
            models.Index(fields=['payload_type']),
            models.Index(fields=['effectiveness_score', 'usage_count']),
            models.Index(fields=['payload_type', 'effectiveness_score']),
        ]
        constraints = [
            models.UniqueConstraint(fields=['payload_hash'], name='uq_securitypayload_payload_hash'),
        ]
        verbose_name = 'Security Payload'
        verbose_name_plural = 'Security Payloads'
    
    def __str__(self):
        return f"SecurityPayload: {self.payload_type} (hash: {self.payload_hash[:8]}...)"


class PayloadMutation(models.Model):
    """
    PayloadMutation model - tracks mutated/refactored versions of SecurityPayload templates.
    
    Sabrina mutates base templates for specific targets, adding escapes, encoding,
    JavaScript injection, etc. This model tracks the full lineage and performance.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.BigAutoField(primary_key=True)
    template_id = models.BigIntegerField(null=False, db_index=True)  # FK to SecurityPayload
    mutated_payload = models.TextField(null=False, blank=False)
    mutated_payload_hash = models.CharField(max_length=64, null=False, blank=False, unique=True, db_index=True)  # SHA256
    mutation_type = models.CharField(max_length=50, null=False, blank=False, db_index=True)  # encoding, escape, etc.
    mutation_description = models.TextField(null=True, blank=True)
    mutation_details = models.JSONField(null=True, blank=True)  # Detailed tracking JSON
    escape_method_applied = models.BooleanField(default=False, db_index=True)
    escape_method_type = models.CharField(max_length=50, null=True, blank=True)
    escape_method_details = models.JSONField(null=True, blank=True)
    target_url = models.TextField(null=True, blank=True)
    target_environment = models.CharField(max_length=200, null=True, blank=True, db_index=True)
    target_waf = models.CharField(max_length=100, null=True, blank=True)
    target_tech_stack = models.JSONField(null=True, blank=True)  # Array of technologies
    generation_tools = models.JSONField(null=True, blank=True)  # Array of tools
    testing_tools = models.JSONField(null=True, blank=True)  # Array of tools
    effectiveness_score = models.FloatField(null=True, blank=True, default=0.0, db_index=True)  # 0.0-1.0
    usage_count = models.IntegerField(null=True, blank=True, default=0)
    success_count = models.IntegerField(null=True, blank=True, default=0)
    failure_count = models.IntegerField(null=True, blank=True, default=0)
    ai_confidence = models.FloatField(null=True, blank=True, default=0.0)
    is_successful = models.BooleanField(default=False, db_index=True)
    exploitation_verified = models.BooleanField(default=False)
    sabrina_approved = models.BooleanField(default=False)
    parent_mutation_id = models.BigIntegerField(null=True, blank=True)  # FK to PayloadMutation
    mutation_depth = models.IntegerField(default=0)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    first_exploitation_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_payloadmutation'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['template_id']),
            models.Index(fields=['mutated_payload_hash']),
            models.Index(fields=['mutation_type']),
            models.Index(fields=['template_id', 'is_successful']),
            models.Index(fields=['mutation_type', 'is_successful']),
            models.Index(fields=['effectiveness_score', 'usage_count']),
        ]
        constraints = [
            models.UniqueConstraint(fields=['mutated_payload_hash'], name='uq_payloadmutation_hash'),
        ]
        verbose_name = 'Payload Mutation'
        verbose_name_plural = 'Payload Mutations'
    
    def __str__(self):
        return f"PayloadMutation: {self.mutation_type} (template: {self.template_id}, success: {self.is_successful})"


class DirectoryEnumerationResult(models.Model):
    """
    DirectoryEnumerationResult model - stores Suzu's directory enumeration results.
    
    Links discovered paths to Nmap scan data, technology fingerprints, and CMS detection.
    Enables priority-based enumeration and correlation with other reconnaissance data.
    Converted from SQLAlchemy to Django ORM.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    egg_record_id = models.UUIDField(null=False, db_index=True)
    
    # Directory enumeration data
    discovered_path = models.CharField(max_length=2048, null=False, blank=False, db_index=True)
    path_status_code = models.IntegerField(null=True, blank=True, db_index=True)
    path_content_length = models.IntegerField(null=True, blank=True)
    path_content_type = models.CharField(max_length=255, null=True, blank=True)
    path_response_time_ms = models.FloatField(null=True, blank=True)
    
    # Correlation with Nmap scan data
    nmap_scan_id = models.UUIDField(null=True, blank=True, db_index=True)
    correlated_port = models.IntegerField(null=True, blank=True, db_index=True)
    correlated_service_name = models.CharField(max_length=100, null=True, blank=True)
    correlated_service_version = models.CharField(max_length=255, null=True, blank=True)
    correlated_product = models.CharField(max_length=255, null=True, blank=True)
    correlated_os_details = models.JSONField(null=True, blank=True)  # OS detection from Nmap
    correlated_cpe = models.JSONField(null=True, blank=True)  # Array of CPE strings
    
    # Technology fingerprinting correlation
    technology_fingerprint_id = models.UUIDField(null=True, blank=True, db_index=True)
    detected_cms = models.CharField(max_length=100, null=True, blank=True, db_index=True)  # WordPress, Drupal, etc.
    detected_cms_version = models.CharField(max_length=50, null=True, blank=True)
    detected_framework = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    detected_framework_version = models.CharField(max_length=50, null=True, blank=True)
    
    # CMS detection from Kumo's spidering
    cms_detection_method = models.CharField(max_length=50, null=True, blank=True)  # 'header', 'html', 'path', 'combined'
    cms_detection_confidence = models.FloatField(null=True, blank=True, default=0.0, db_index=True)
    cms_detection_signatures = models.JSONField(null=True, blank=True)  # Matched patterns
    
    # Priority scoring
    priority_score = models.FloatField(null=False, default=0.0, db_index=True)  # 0.0-1.0
    priority_factors = models.JSONField(null=True, blank=True)  # Breakdown of scoring factors
    
    # Request metadata correlation (from Kumo)
    request_metadata_id = models.UUIDField(null=True, blank=True, db_index=True)
    correlated_headers = models.JSONField(null=True, blank=True)  # HTTP headers from Kumo
    correlated_html_entities = models.JSONField(null=True, blank=True)  # HTML meta tags, etc.
    
    # Enumeration metadata
    enumeration_tool = models.CharField(max_length=50, null=True, blank=True)  # 'dirsearch', 'gobuster', 'ffuf'
    wordlist_used = models.CharField(max_length=255, null=True, blank=True)
    enumeration_depth = models.IntegerField(null=True, blank=True, default=1)
    
    # Timestamps
    discovered_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'customer_eggs_eggrecords_general_models_directoryenumerationresult'
        managed = True  # Will create table via migration
        indexes = [
            models.Index(fields=['egg_record_id']),
            models.Index(fields=['discovered_path']),
            models.Index(fields=['path_status_code']),
            models.Index(fields=['priority_score']),
            models.Index(fields=['detected_cms']),
            models.Index(fields=['correlated_port']),
            models.Index(fields=['egg_record_id', 'priority_score']),  # For priority queries
            models.Index(fields=['egg_record_id', 'detected_cms']),  # For CMS-based queries
        ]
        verbose_name = 'Directory Enumeration Result'
        verbose_name_plural = 'Directory Enumeration Results'
    
    def __str__(self):
        return f"DirectoryEnumerationResult: {self.discovered_path} (priority: {self.priority_score:.2f})"


class NucleiTemplate(models.Model):
    """
    NucleiTemplate model - stores Nuclei vulnerability scanning template metadata.
    
    Created by Oak's template registry service to enable correlation between:
    - Technology fingerprints and templates
    - CVE matches and templates
    - EggRecords and appropriate vulnerability scanning templates
    
    This model allows Oak to make intelligent inferences about which templates
    to use for scanning based on detected technologies and CVEs.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    template_id = models.CharField(max_length=500, unique=True, null=False, blank=False, db_index=True)
    template_path = models.CharField(max_length=1000, null=False, blank=False)
    template_name = models.CharField(max_length=500, null=True, blank=True)
    cve_id = models.CharField(max_length=50, null=True, blank=True, db_index=True)  # e.g., "CVE-2025-55182"
    technology = models.CharField(max_length=200, null=True, blank=True, db_index=True)  # e.g., "wordpress", "apache"
    tags = models.JSONField(null=False, default=list)  # Array of tags like ["cve", "wordpress", "rce"]
    severity = models.CharField(max_length=20, null=True, blank=True, db_index=True)  # critical, high, medium, low, info
    author = models.CharField(max_length=200, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    reference = models.TextField(null=True, blank=True)  # Newline-separated URLs
    classification = models.JSONField(null=True, blank=True, default=dict)  # Contains cve-id, cwe-id, etc.
    raw_content = models.TextField(null=True, blank=True)  # Full YAML content
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    indexed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'enrichment_system_nucleitemplate'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['template_id']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['technology']),
            models.Index(fields=['severity']),
            # Note: GIN index on tags is created via raw SQL in template_registry_service
        ]
        verbose_name = 'Nuclei Template'
        verbose_name_plural = 'Nuclei Templates'
    
    def __str__(self):
        return f"NucleiTemplate: {self.template_id} ({self.template_name or 'Unnamed'})"
    
    def get_cve_ids(self) -> list:
        """
        Extract all CVE IDs from this template.
        
        Returns:
            List of CVE IDs found in cve_id field, classification, or tags
        """
        cve_ids = []
        
        # Check direct cve_id field
        if self.cve_id:
            cve_ids.append(self.cve_id.upper())
        
        # Check classification JSON
        if self.classification:
            cve_id_from_class = self.classification.get('cve-id')
            if cve_id_from_class:
                if isinstance(cve_id_from_class, list):
                    cve_ids.extend([cve.upper() for cve in cve_id_from_class if cve])
                elif isinstance(cve_id_from_class, str):
                    cve_ids.append(cve_id_from_class.upper())
        
        # Check tags for CVE references
        if self.tags:
            for tag in self.tags:
                if isinstance(tag, str):
                    tag_upper = tag.upper()
                    if tag_upper.startswith('CVE-') or 'CVE-' in tag_upper:
                        # Extract CVE from tag
                        cve_match = re.search(r'CVE[-\s]?(\d{4})[-\s]?(\d{4,})', tag_upper)
                        if cve_match:
                            cve_ids.append(f"CVE-{cve_match.group(1)}-{cve_match.group(2)}")
        
        # Deduplicate and return
        return sorted(list(set(cve_ids)))
    
    def get_technologies(self) -> list:
        """
        Extract all technology names from this template.
        
        Returns:
            List of technology names found in technology field or tags
        """
        technologies = []
        
        # Check direct technology field
        if self.technology:
            technologies.append(self.technology.lower())
        
        # Check tags for common technologies
        if self.tags:
            common_techs = [
                'apache', 'nginx', 'iis', 'wordpress', 'drupal', 'joomla',
                'mysql', 'postgres', 'mongodb', 'redis', 'tomcat', 'jetty',
                'jenkins', 'grafana', 'kibana', 'elasticsearch', 'nextjs',
                'react', 'nodejs', 'php', 'python', 'ruby', 'java', 'dotnet'
            ]
            for tag in self.tags:
                if isinstance(tag, str):
                    tag_lower = tag.lower()
                    for tech in common_techs:
                        if tech in tag_lower and tech not in technologies:
                            technologies.append(tech)
        
        return sorted(list(set(technologies)))
    
    def get_template_info(self) -> dict:
        """
        Get comprehensive template information for correlation.
        
        Returns:
            Dict with template metadata for Oak's inference engine
        """
        return {
            'template_id': self.template_id,
            'template_name': self.template_name,
            'cve_ids': self.get_cve_ids(),
            'technologies': self.get_technologies(),
            'tags': self.tags or [],
            'severity': self.severity,
            'author': self.author,
            'description': self.description,
            'classification': self.classification or {},
            'template_path': self.template_path,
        }
    
    @classmethod
    def find_by_cve(cls, cve_id: str, severity: str = None) -> models.QuerySet:
        """
        Find templates matching a specific CVE ID.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2025-55182")
            severity: Optional severity filter
            
        Returns:
            QuerySet of matching templates
        """
        cve_upper = cve_id.upper()
        queryset = cls.objects.filter(
            models.Q(cve_id__iexact=cve_upper) |
            models.Q(classification__cve_id__icontains=cve_upper) |
            models.Q(tags__icontains=cve_upper)
        )
        
        if severity:
            queryset = queryset.filter(severity__iexact=severity.lower())
        
        return queryset.order_by('-severity', 'template_name')
    
    @classmethod
    def find_by_technology(cls, technology: str, severity: str = None) -> models.QuerySet:
        """
        Find templates matching a specific technology.
        
        Args:
            technology: Technology name (e.g., "wordpress", "apache")
            severity: Optional severity filter
            
        Returns:
            QuerySet of matching templates
        """
        tech_lower = technology.lower()
        queryset = cls.objects.filter(
            models.Q(technology__iexact=tech_lower) |
            models.Q(tags__icontains=tech_lower)
        )
        
        if severity:
            queryset = queryset.filter(severity__iexact=severity.lower())
        
        return queryset.order_by('-severity', 'template_name')
    
    @classmethod
    def find_by_cve_and_technology(cls, cve_id: str, technology: str, severity: str = None) -> models.QuerySet:
        """
        Find templates matching both a CVE ID and technology.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2025-55182")
            technology: Technology name (e.g., "nextjs")
            severity: Optional severity filter
            
        Returns:
            QuerySet of matching templates
        """
        cve_upper = cve_id.upper()
        tech_lower = technology.lower()
        
        queryset = cls.objects.filter(
            (
                models.Q(cve_id__iexact=cve_upper) |
                models.Q(classification__cve_id__icontains=cve_upper) |
                models.Q(tags__icontains=cve_upper)
            ) &
            (
                models.Q(technology__iexact=tech_lower) |
                models.Q(tags__icontains=tech_lower)
            )
        )
        
        if severity:
            queryset = queryset.filter(severity__iexact=severity.lower())
        
        return queryset.order_by('-severity', 'template_name')
    
    @classmethod
    def find_for_egg_record(cls, egg_record_id: str, technology_fingerprints: list = None, 
                           cve_matches: list = None) -> models.QuerySet:
        """
        Find recommended templates for an EggRecord based on technology fingerprints and CVE matches.
        
        This is the main correlation method used by Oak for inference.
        
        Args:
            egg_record_id: UUID of the EggRecord
            technology_fingerprints: List of TechnologyFingerprint objects or dicts with 'technology_name'
            cve_matches: List of CVEFingerprintMatch objects or dicts with 'cve_id'
            
        Returns:
            QuerySet of recommended templates, ordered by relevance
        """
        # Import here to avoid circular imports
        TechnologyFingerprint = cls._get_related_model('TechnologyFingerprint')
        CVEFingerprintMatch = cls._get_related_model('CVEFingerprintMatch')
        
        # If objects not provided, fetch from database
        if technology_fingerprints is None:
            technology_fingerprints = list(
                TechnologyFingerprint.objects.filter(egg_record_id=egg_record_id)
                .values('technology_name', 'technology_category', 'confidence_score')
            )
        
        if cve_matches is None:
            cve_matches = list(
                CVEFingerprintMatch.objects.filter(egg_record_id=egg_record_id)
                .values('cve_id', 'match_confidence', 'nuclei_template_ids')
            )
        
        # Build query for templates matching technologies or CVEs
        from django.db.models import Q
        query = Q()
        
        # Add technology matches
        for tech_fp in technology_fingerprints:
            tech_name = tech_fp.get('technology_name') if isinstance(tech_fp, dict) else tech_fp.technology_name
            if tech_name:
                query |= Q(technology__iexact=tech_name.lower()) | Q(tags__icontains=tech_name.lower())
        
        # Add CVE matches
        for cve_match in cve_matches:
            cve_id = cve_match.get('cve_id') if isinstance(cve_match, dict) else cve_match.cve_id
            if cve_id:
                cve_upper = cve_id.upper()
                query |= (
                    Q(cve_id__iexact=cve_upper) |
                    Q(classification__cve_id__icontains=cve_upper) |
                    Q(tags__icontains=cve_upper)
                )
        
        if query:
            return cls.objects.filter(query).distinct().order_by('-severity', 'template_name')
        else:
            return cls.objects.none()
    
    @classmethod
    def _get_related_model(cls, model_name: str):
        """Helper to get related models without circular imports."""
        from django.apps import apps
        return apps.get_model('customer_eggs_eggrecords_general_models', model_name)
    
    @classmethod
    def find_by_tags(cls, tags: list, match_all: bool = False) -> models.QuerySet:
        """
        Find templates matching specific tags.
        
        Args:
            tags: List of tag strings to search for
            match_all: If True, template must contain all tags; if False, any tag matches
            
        Returns:
            QuerySet of matching templates
        """
        from django.db.models import Q
        
        if not tags:
            return cls.objects.none()
        
        query = Q()
        for tag in tags:
            tag_lower = tag.lower()
            tag_query = Q(tags__icontains=tag_lower)
            if match_all:
                query &= tag_query
            else:
                query |= tag_query
        
        return cls.objects.filter(query).distinct().order_by('-severity', 'template_name')
