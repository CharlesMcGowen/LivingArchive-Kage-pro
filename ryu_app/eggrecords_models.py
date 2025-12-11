"""
Django models for PostgreSQL eggrecords database.
These models map to the existing PostgreSQL tables for learning/heuristics data.
"""
from django.db import models
import json


class KageWAFDetection(models.Model):
    """Model for ash_waf_detections table (legacy table name preserved for database compatibility)"""
    id = models.AutoField(primary_key=True)
    waf_type = models.CharField(max_length=255, null=True, blank=True)
    bypass_successful = models.BooleanField(null=True, blank=True)
    confidence = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    detected_at = models.DateTimeField(null=True, blank=True)
    target = models.CharField(max_length=255, null=True, blank=True)
    
    class Meta:
        db_table = 'ash_waf_detections'
        managed = False
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.waf_type} - {self.target}"


class KageTechniqueEffectiveness(models.Model):
    """Model for ash_technique_effectiveness table (legacy table name preserved for database compatibility)"""
    id = models.AutoField(primary_key=True)
    target_pattern = models.CharField(max_length=255, null=True, blank=True)
    waf_type = models.CharField(max_length=255, null=True, blank=True)
    technique_name = models.CharField(max_length=255, null=True, blank=True)
    success_count = models.IntegerField(default=0)
    failure_count = models.IntegerField(default=0)
    last_success = models.DateTimeField(null=True, blank=True)
    last_failure = models.DateTimeField(null=True, blank=True)
    last_updated = models.DateTimeField(null=True, blank=True)
    technique_metadata = models.JSONField(null=True, blank=True)
    
    class Meta:
        db_table = 'ash_technique_effectiveness'
        managed = False
        ordering = ['-last_updated']
    
    @property
    def success_rate(self):
        """Calculate success rate percentage"""
        total = self.success_count + self.failure_count
        if total > 0:
            return round(100.0 * self.success_count / total, 2)
        return 0.0
    
    def __str__(self):
        return f"{self.technique_name} - {self.target_pattern}"


class CalculatedHeuristicsRule(models.Model):
    """Model for calculated_heuristics_rules table"""
    id = models.AutoField(primary_key=True)
    rule_pattern = models.CharField(max_length=255)
    nmap_arguments = models.JSONField(null=True, blank=True)  # JSONB in PostgreSQL
    recommended_technique = models.CharField(max_length=255, null=True, blank=True)
    confidence_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    success_rate = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    sample_count = models.IntegerField(default=0)
    last_updated = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'calculated_heuristics_rules'
        managed = False
        ordering = ['-confidence_score', '-sample_count']
    
    @property
    def nmap_arguments_list(self):
        """Get nmap_arguments as list"""
        if self.nmap_arguments:
            if isinstance(self.nmap_arguments, str):
                try:
                    return json.loads(self.nmap_arguments)
                except (json.JSONDecodeError, TypeError):
                    return []
            return self.nmap_arguments if isinstance(self.nmap_arguments, list) else []
        return []
    
    def __str__(self):
        return f"{self.rule_pattern} - {self.recommended_technique}"


class WAFDetectionDetail(models.Model):
    """Model for waf_detection_details table"""
    id = models.AutoField(primary_key=True)
    waf_type = models.CharField(max_length=255, null=True, blank=True)
    waf_version = models.CharField(max_length=255, null=True, blank=True)
    waf_product = models.CharField(max_length=255, null=True, blank=True)
    confidence = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    detected_at = models.DateTimeField(null=True, blank=True)
    target = models.CharField(max_length=255, null=True, blank=True)
    
    class Meta:
        db_table = 'waf_detection_details'
        managed = False
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.waf_type} {self.waf_version} - {self.target}"


class IPTechniqueEffectiveness(models.Model):
    """Model for ip_technique_effectiveness table"""
    id = models.AutoField(primary_key=True)
    asn = models.CharField(max_length=50, null=True, blank=True)
    cidr_block = models.CharField(max_length=50, null=True, blank=True)
    ipv6_prefix = models.CharField(max_length=100, null=True, blank=True)
    waf_type = models.CharField(max_length=255, null=True, blank=True)
    technique_name = models.CharField(max_length=255, null=True, blank=True)
    success_count = models.IntegerField(default=0)
    failure_count = models.IntegerField(default=0)
    avg_scan_duration = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    last_updated = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'ip_technique_effectiveness'
        managed = False
        ordering = ['-last_updated']
    
    @property
    def success_rate(self):
        """Calculate success rate percentage"""
        total = self.success_count + self.failure_count
        if total > 0:
            return round(100.0 * self.success_count / total, 2)
        return 0.0
    
    def __str__(self):
        return f"{self.technique_name} - {self.asn or self.cidr_block}"


class TechnologyFingerprint(models.Model):
    """Model for technology_fingerprints table"""
    id = models.AutoField(primary_key=True)
    technology_type = models.CharField(max_length=255, null=True, blank=True)
    product = models.CharField(max_length=255, null=True, blank=True)
    version = models.CharField(max_length=255, null=True, blank=True)
    target = models.CharField(max_length=255, null=True, blank=True)
    detected_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'technology_fingerprints'
        managed = False
        ordering = ['-detected_at']
    
    def __str__(self):
        return f"{self.technology_type} {self.product} {self.version} - {self.target}"


class KageScanResult(models.Model):
    """Model for ash_scan_results table (legacy table name preserved for database compatibility)"""
    id = models.AutoField(primary_key=True)
    target = models.CharField(max_length=255, null=True, blank=True)
    technique_used = models.CharField(max_length=255, null=True, blank=True)
    waf_detected = models.BooleanField(null=True, blank=True)
    waf_type = models.CharField(max_length=255, null=True, blank=True)
    open_ports_found = models.IntegerField(null=True, blank=True)
    bypass_successful = models.BooleanField(null=True, blank=True)
    scan_duration = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    scanned_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'ash_scan_results'
        managed = False
        ordering = ['-scanned_at']
    
    def __str__(self):
        return f"{self.target} - {self.technique_used}"

