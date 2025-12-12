"""
Django models for PostgreSQL customer_eggs database.
These models map to the existing PostgreSQL tables.
"""
from django.db import models
import uuid
import json


class PostgresEggRecord(models.Model):
    """Model for customer_eggs_eggrecords_general_models_eggrecord table"""
    id = models.UUIDField(primary_key=True)
    subDomain = models.CharField(max_length=255, null=True, blank=True, db_column='subDomain')
    domainname = models.CharField(max_length=255, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
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

