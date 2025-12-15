"""
Django models for PostgreSQL customer_eggs database.
These models map to the existing PostgreSQL tables.
"""
from django.db import models
from django.contrib.postgres.fields import ArrayField
import uuid
import json


class PostgresEggs(models.Model):
    """Model for customer_eggs_eggrecords_general_models_eggs table"""
    id = models.UUIDField(primary_key=True)
    eggGroup = models.CharField(max_length=100)
    eggName = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    domainScope = models.JSONField()
    Ipv4Scope = models.JSONField()
    Ipv6Scope = models.JSONField()
    urlScope = models.JSONField()
    eisystem_in_thorm = models.CharField(max_length=100, unique=True)
    URLCustomer = models.CharField(max_length=500)
    notes = models.TextField()
    OutOfScopeString = models.TextField()
    pokemon_name = models.CharField(max_length=50)
    pokemon_emoji = models.CharField(max_length=10)
    pokemonAvatar = models.CharField(max_length=255)
    pokemon_type = models.CharField(max_length=20)
    pokemon_experience = models.IntegerField()
    pokemon_level = models.IntegerField()
    pokemon_stats = models.JSONField()
    pokemon_tier = models.CharField(max_length=10)
    skipScan = models.BooleanField()
    reconOnly = models.BooleanField()
    passiveAttack = models.BooleanField()
    agressiveAttack = models.BooleanField()
    is_active = models.BooleanField()
    eggLaidDate = models.DateTimeField()
    lastEggScan = models.DateTimeField(null=True, blank=True)
    toScanDate = models.DateTimeField(null=True, blank=True)
    endToScanDate = models.DateTimeField(null=True, blank=True)
    customDaysUntilNextScan = models.IntegerField()
    outofscope = models.JSONField()
    subDomainWildCards = models.JSONField()
    FoundTLD = models.JSONField()
    egg_assigned_date = models.DateTimeField(null=True, blank=True)
    egg_stage = models.CharField(max_length=20)
    domain_count = models.IntegerField()
    hatching_threshold = models.IntegerField()
    egg_laid_date = models.DateTimeField()
    hatched_date = models.DateTimeField(null=True, blank=True)
    attack = models.IntegerField()
    defense = models.IntegerField()
    speed = models.IntegerField()
    special_attack = models.IntegerField()
    special_defense = models.IntegerField()
    hp = models.IntegerField()
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
    default_rescan_interval_days = models.IntegerField()
    scan_coordination_enabled = models.BooleanField()
    max_concurrent_scans = models.IntegerField()
    preferred_scan_hours = models.JSONField()
    timezone = models.CharField(max_length=50)
    scan_frequency_rules = models.JSONField()
    total_scans_performed = models.IntegerField()
    last_project_scan = models.DateTimeField(null=True, blank=True)
    customer_context = models.JSONField()
    customer_industry = models.CharField(max_length=100)
    engagement_duration = models.CharField(max_length=50)
    project_type = models.CharField(max_length=50)
    report_format_preference = models.CharField(max_length=50)
    business_relationship_id = models.UUIDField(null=True, blank=True)
    wallace_report = models.TextField()
    wallace_report_generated_at = models.DateTimeField(null=True, blank=True)
    wallace_report_status = models.CharField(max_length=20)
    
    class Meta:
        db_table = 'customer_eggs_eggrecords_general_models_eggs'
        managed = False
        ordering = ['eggName']
    
    def __str__(self):
        return f"{self.eggName} ({self.eisystem_in_thorm})"


class PostgresEggRecord(models.Model):
    """Model for customer_eggs_eggrecords_general_models_eggrecord table"""
    id = models.UUIDField(primary_key=True)
    egg_id = models.ForeignKey(
        PostgresEggs,
        on_delete=models.SET_NULL,
        db_column='egg_id_id',
        related_name='egg_records',
        null=True,
        blank=True
    )
    subDomain = models.CharField(max_length=255, null=True, blank=True, db_column='subDomain')
    domainname = models.CharField(max_length=255, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    ip = models.JSONField(default=list, blank=True, null=True)  # JSONB field for multiple IPs
    alive = models.BooleanField(default=True)
    eggname = models.CharField(max_length=255, null=True, blank=True)
    projectegg = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'customer_eggs_eggrecords_general_models_eggrecord'
        managed = False  # Don't create/delete tables, they already exist
        ordering = ['-updated_at']
    
    def __str__(self):
        return self.subDomain or self.domainname or self.ip_address or str(self.id)


class PostgresNmap(models.Model):
    """Model for customer_eggs_eggrecords_general_models_nmap table"""
    id = models.UUIDField(primary_key=True)
    record_id = models.ForeignKey(
        PostgresEggRecord,
        on_delete=models.CASCADE,
        db_column='record_id_id',
        related_name='nmap_scans'
    )
    target = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50)
    open_ports = models.TextField(null=True, blank=True)  # JSON stored as text
    service_name = models.CharField(max_length=255, null=True, blank=True)
    scan_status = models.CharField(max_length=50, default='completed')
    port = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'customer_eggs_eggrecords_general_models_nmap'
        managed = False
        ordering = ['-created_at']
    
    @property
    def open_ports_list(self):
        """Parse open_ports JSON string to list"""
        if self.open_ports:
            try:
                return json.loads(self.open_ports)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    def __str__(self):
        return f"{self.target} - {self.scan_type}"


class PostgresRequestMetadata(models.Model):
    """Model for customer_eggs_eggrecords_general_models_requestmetadata table"""
    id = models.UUIDField(primary_key=True)
    record_id = models.ForeignKey(
        PostgresEggRecord,
        on_delete=models.CASCADE,
        db_column='record_id_id',
        related_name='http_requests'
    )
    # Map to actual database columns
    url = models.URLField(max_length=2048, db_column='target_url', null=True, blank=True)
    method = models.CharField(max_length=10, default='GET', db_column='request_method', null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True, db_column='response_status')
    user_agent = models.CharField(max_length=512, null=True, blank=True)
    session_id = models.CharField(max_length=255, null=True, blank=True)
    response_time_ms = models.IntegerField(null=True, blank=True)
    timestamp = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'customer_eggs_eggrecords_general_models_requestmetadata'
        managed = False
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.method} {self.url}"


class PostgresDNSQuery(models.Model):
    """Model for customer_eggs_eggrecords_general_models_dnsquery table"""
    id = models.UUIDField(primary_key=True)
    record_id = models.ForeignKey(
        PostgresEggRecord,
        on_delete=models.CASCADE,
        db_column='record_id_id',
        related_name='dns_queries'
    )
    query_type = models.CharField(max_length=10)  # A, AAAA, MX, etc.
    result = models.TextField()
    created_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'customer_eggs_eggrecords_general_models_dnsquery'
        managed = False
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.query_type} query for {self.record_id}"


class PostgresJadeAssessment(models.Model):
    """Model for customer_eggs_eggrecords_general_models_jadeassessment table"""
    id = models.UUIDField(primary_key=True)
    record_id = models.ForeignKey(
        PostgresEggRecord,
        on_delete=models.CASCADE,
        db_column='record_id_id',
        related_name='jade_assessments'
    )
    risk_level = models.CharField(max_length=50)
    threat_summary = models.TextField(null=True, blank=True)
    vulnerabilities = models.JSONField(null=True, blank=True)
    attack_vectors = models.JSONField(null=True, blank=True)
    remediation_priorities = models.JSONField(null=True, blank=True)
    narrative = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(null=False)
    updated_at = models.DateTimeField(null=False)
    
    class Meta:
        db_table = 'customer_eggs_eggrecords_general_models_jadeassessment'
        managed = False
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Jade Assessment for {self.record_id} - {self.risk_level}"


class PostgresRyuPortFindings(models.Model):
    """Model for ryu_port_findings table"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    eggrecord_id = models.ForeignKey(
        PostgresEggRecord,
        on_delete=models.CASCADE,
        db_column='eggrecord_id',
        related_name='ryu_port_findings'
    )
    ports_found = ArrayField(models.IntegerField())  # PostgreSQL integer[] array
    scan_type = models.CharField(max_length=50, default='targeted', null=True, blank=True)
    source_ports = models.JSONField(default=dict, null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'ryu_port_findings'
        managed = False
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Ryu Port Findings for {self.eggrecord_id} - {self.scan_type}"


class PostgresScanCoordination(models.Model):
    """Model for scan_coordination table"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    eggrecord_id = models.OneToOneField(
        PostgresEggRecord,
        on_delete=models.CASCADE,
        db_column='eggrecord_id',
        related_name='scan_coordination',
        unique=True
    )
    claim_agent = models.CharField(max_length=20, null=True, blank=True)
    claim_in = models.DateTimeField(null=True, blank=True)
    claim_out = models.DateTimeField(null=True, blank=True)
    ryu_scan = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'scan_coordination'
        managed = False
        ordering = ['-claim_in']
    
    def __str__(self):
        return f"Scan Coordination for {self.eggrecord_id} - {self.claim_agent or 'unclaimed'}"

