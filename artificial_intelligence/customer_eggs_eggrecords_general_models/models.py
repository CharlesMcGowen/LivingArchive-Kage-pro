"""
Django ORM Models for Customer Eggs EggRecords General Models
=============================================================
Converted from SQLAlchemy to Django ORM for better Django integration.
These models match the existing database schema.
"""

from django.db import models
import uuid


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
        managed = False  # Table exists, don't create migrations
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
    technology_fingerprint_id = models.UUIDField(null=False, db_index=True)
    cve_id = models.CharField(max_length=50, null=False, blank=False, db_index=True)  # e.g., "CVE-2023-1234"
    match_confidence = models.FloatField(null=False, default=0.0, db_index=True)
    nuclei_template_ids = models.JSONField(null=False, default=list)  # Array of template IDs
    bugsy_confidence_notes = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True, auto_now_add=True)
    updated_at = models.DateTimeField(null=True, blank=True, auto_now=True)
    
    class Meta:
        app_label = 'customer_eggs_eggrecords_general_models'
        db_table = 'enrichment_system_cvefingerprintmatch'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['egg_record_id']),
            models.Index(fields=['technology_fingerprint_id']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['match_confidence']),
        ]
        verbose_name = 'CVE Fingerprint Match'
        verbose_name_plural = 'CVE Fingerprint Matches'
    
    def __str__(self):
        return f"CVEFingerprintMatch: {self.cve_id} (confidence: {self.match_confidence})"


class RequestMetaData(models.Model):
    """
    RequestMetaData model - stores HTTP request/response metadata.
    
    Created by Misty's HTTP spidering service.
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


class JadeAssessment(models.Model):
    """
    JadeAssessment model - stores security threat assessments by Jade.
    
    Each assessment correlates findings from Ash (Nmap scans) and Misty (HTTP spidering)
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
        db_table = 'customer_eggs_eggrecords_general_models_jadeassessment'
        managed = False  # Table exists, don't create migrations
        indexes = [
            models.Index(fields=['record_id_id']),
            models.Index(fields=['risk_level']),
            models.Index(fields=['record_id_id', 'risk_level']),  # Combined index
        ]
        verbose_name = 'Jade Assessment'
        verbose_name_plural = 'Jade Assessments'
    
    def __str__(self):
        return f"JadeAssessment: {self.record_id_id} (risk: {self.risk_level})"


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
