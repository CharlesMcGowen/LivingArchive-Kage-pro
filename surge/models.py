"""
Surge Django Models
===================

Django ORM models for Surge vulnerability scanning, including:
- Nuclei template usage tracking
- Learning system for adaptive scanning
- Performance metrics
- Agent control and adaptation
"""

from django.db import models
from django.utils import timezone
import uuid


class NucleiTemplateUsage(models.Model):
    """
    Tracks Nuclei template usage for learning and optimization.
    Enables adaptive template selection based on historical performance.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Template identification
    template_id = models.CharField(max_length=500, db_index=True)
    template_path = models.CharField(max_length=1000, null=True, blank=True)
    
    # Usage statistics
    usage_count = models.IntegerField(default=0, db_index=True)
    success_count = models.IntegerField(default=0)
    failure_count = models.IntegerField(default=0)
    
    # Performance metrics
    average_response_time = models.FloatField(null=True, blank=True, help_text="Average response time in seconds")
    average_match_time = models.FloatField(null=True, blank=True, help_text="Average time to match in seconds")
    success_rate = models.FloatField(default=0.0, db_index=True, help_text="Success rate (0.0-1.0)")
    
    # Effectiveness scoring
    effectiveness_score = models.FloatField(default=0.0, db_index=True, help_text="Overall effectiveness score")
    false_positive_rate = models.FloatField(default=0.0, help_text="False positive rate")
    
    # Context tracking
    technologies_detected = models.JSONField(default=list, help_text="Technologies this template works well with")
    cve_ids = models.JSONField(default=list, help_text="CVE IDs this template detects")
    severity_distribution = models.JSONField(default=dict, help_text="Distribution of severities found")
    
    # Learning metadata
    last_used = models.DateTimeField(null=True, blank=True, db_index=True)
    last_success = models.DateTimeField(null=True, blank=True)
    adaptation_count = models.IntegerField(default=0, help_text="Number of times template was adapted")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'surge_nuclei_template_usage'
        indexes = [
            models.Index(fields=['template_id', 'success_rate']),
            models.Index(fields=['effectiveness_score', '-last_used']),
            models.Index(fields=['usage_count', 'success_rate']),
        ]
        verbose_name = 'Nuclei Template Usage'
        verbose_name_plural = 'Nuclei Template Usages'
    
    def __str__(self):
        return f"{self.template_id} (usage: {self.usage_count}, success: {self.success_rate:.2%})"
    
    def update_success(self, response_time=None, match_time=None):
        """Update statistics after successful template execution."""
        self.success_count += 1
        self.usage_count += 1
        self.last_success = timezone.now()
        self.last_used = timezone.now()
        
        if response_time:
            if self.average_response_time:
                self.average_response_time = (self.average_response_time + response_time) / 2
            else:
                self.average_response_time = response_time
        
        if match_time:
            if self.average_match_time:
                self.average_match_time = (self.average_match_time + match_time) / 2
            else:
                self.average_match_time = match_time
        
        self.success_rate = self.success_count / self.usage_count if self.usage_count > 0 else 0.0
        self.save(update_fields=['success_count', 'usage_count', 'last_success', 'last_used',
                                'average_response_time', 'average_match_time', 'success_rate'])
    
    def update_failure(self):
        """Update statistics after failed template execution."""
        self.failure_count += 1
        self.usage_count += 1
        self.last_used = timezone.now()
        
        self.success_rate = self.success_count / self.usage_count if self.usage_count > 0 else 0.0
        self.save(update_fields=['failure_count', 'usage_count', 'last_used', 'success_rate'])


class NucleiScanSession(models.Model):
    """
    Tracks individual Nuclei scan sessions for learning and adaptation.
    Enables on-the-fly scan adjustments based on real-time feedback.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Scan identification
    scan_id = models.CharField(max_length=100, unique=True, db_index=True)
    egg_record_id = models.UUIDField(null=True, blank=True, db_index=True)
    target = models.CharField(max_length=500, db_index=True)
    
    # Scan configuration (stored as JSON for flexibility)
    scan_config = models.JSONField(default=dict, help_text="Scan configuration parameters")
    templates_used = models.JSONField(default=list, help_text="List of template IDs used")
    
    # Real-time state
    status = models.CharField(max_length=50, default='queued', db_index=True,
                             choices=[
                                 ('queued', 'Queued'),
                                 ('running', 'Running'),
                                 ('paused', 'Paused'),
                                 ('completed', 'Completed'),
                                 ('failed', 'Failed'),
                                 ('cancelled', 'Cancelled'),
                             ])
    
    # Progress tracking
    total_requests = models.IntegerField(default=0)
    completed_requests = models.IntegerField(default=0)
    successful_requests = models.IntegerField(default=0)
    failed_requests = models.IntegerField(default=0)
    
    # Results
    vulnerabilities_found = models.IntegerField(default=0)
    vulnerabilities_data = models.JSONField(default=list, help_text="Vulnerability findings")
    
    # Adaptation tracking
    adaptations_applied = models.JSONField(default=list, help_text="List of adaptations made during scan")
    adaptation_reasons = models.JSONField(default=dict, help_text="Reasons for each adaptation")
    
    # Performance metrics
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    duration_seconds = models.FloatField(null=True, blank=True)
    
    # Learning data
    learning_insights = models.JSONField(default=dict, help_text="Insights for future scans")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'surge_nuclei_scan_session'
        indexes = [
            models.Index(fields=['status', '-created_at']),
            models.Index(fields=['egg_record_id', '-created_at']),
            models.Index(fields=['target', '-created_at']),
        ]
        verbose_name = 'Nuclei Scan Session'
        verbose_name_plural = 'Nuclei Scan Sessions'
    
    def __str__(self):
        return f"Scan {self.scan_id} - {self.target} ({self.status})"
    
    def apply_adaptation(self, adaptation_type, reason, config_changes):
        """Record an adaptation made during the scan."""
        self.adaptations_applied.append({
            'type': adaptation_type,
            'timestamp': timezone.now().isoformat(),
            'config_changes': config_changes,
        })
        self.adaptation_reasons[adaptation_type] = reason
        self.save(update_fields=['adaptations_applied', 'adaptation_reasons'])


class NucleiAdaptationRule(models.Model):
    """
    Learning rules for adaptive Nuclei scanning.
    Defines when and how to adapt scans based on conditions.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Rule identification
    rule_name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True)
    
    # Conditions (stored as JSON for flexibility)
    conditions = models.JSONField(default=dict, help_text="Conditions that trigger this adaptation")
    
    # Actions
    adaptation_type = models.CharField(max_length=100, choices=[
        ('adjust_rate_limit', 'Adjust Rate Limit'),
        ('change_concurrency', 'Change Concurrency'),
        ('switch_templates', 'Switch Templates'),
        ('pause_scan', 'Pause Scan'),
        ('prioritize_templates', 'Prioritize Templates'),
        ('skip_target', 'Skip Target'),
    ])
    action_config = models.JSONField(default=dict, help_text="Configuration for the adaptation action")
    
    # Learning metrics
    trigger_count = models.IntegerField(default=0)
    success_count = models.IntegerField(default=0)
    effectiveness_score = models.FloatField(default=0.0)
    
    # Status
    is_active = models.BooleanField(default=True, db_index=True)
    priority = models.IntegerField(default=0, db_index=True, help_text="Higher priority rules evaluated first")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_triggered = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'surge_nuclei_adaptation_rule'
        indexes = [
            models.Index(fields=['is_active', '-priority']),
            models.Index(fields=['adaptation_type', 'is_active']),
        ]
        verbose_name = 'Nuclei Adaptation Rule'
        verbose_name_plural = 'Nuclei Adaptation Rules'
    
    def __str__(self):
        return f"{self.rule_name} ({self.adaptation_type})"


class NucleiAgentControl(models.Model):
    """
    Real-time control interface for Nuclei agents.
    Enables on-the-fly scan adjustments and agent coordination.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Agent identification
    agent_name = models.CharField(max_length=100, db_index=True, choices=[
        ('surge', 'Surge'),
        ('koga', 'Koga'),
        ('bugsy', 'Bugsy'),
    ])
    scan_session_id = models.UUIDField(null=True, blank=True, db_index=True)
    
    # Control commands
    command = models.CharField(max_length=100, choices=[
        ('pause', 'Pause Scan'),
        ('resume', 'Resume Scan'),
        ('adjust_rate', 'Adjust Rate Limit'),
        ('change_concurrency', 'Change Concurrency'),
        ('switch_templates', 'Switch Templates'),
        ('prioritize', 'Prioritize Templates'),
        ('skip', 'Skip Target'),
        ('cancel', 'Cancel Scan'),
    ])
    command_params = models.JSONField(default=dict, help_text="Parameters for the command")
    
    # Status
    status = models.CharField(max_length=50, default='pending', choices=[
        ('pending', 'Pending'),
        ('executing', 'Executing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ])
    
    # Results
    execution_result = models.JSONField(default=dict, help_text="Result of command execution")
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'surge_nuclei_agent_control'
        indexes = [
            models.Index(fields=['agent_name', 'status', '-created_at']),
            models.Index(fields=['scan_session_id', 'status']),
        ]
        verbose_name = 'Nuclei Agent Control'
        verbose_name_plural = 'Nuclei Agent Controls'
    
    def __str__(self):
        return f"{self.agent_name} - {self.command} ({self.status})"
