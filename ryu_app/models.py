"""
Django models for Ryu Cybersecurity app.
"""
from django.db import models
import uuid


class Project(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class Customer(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='customers')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['name', 'project']
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.project.name})"


class EggRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='eggrecords', null=True, blank=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='eggrecords', null=True, blank=True)
    
    # Target information
    subDomain = models.CharField(max_length=255, null=True, blank=True)
    domainname = models.CharField(max_length=255, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    cidr = models.CharField(max_length=50, null=True, blank=True)  # For CIDR ranges like "192.168.1.0/24"
    
    # Obfuscation fields
    eggname = models.CharField(max_length=255, null=True, blank=True, help_text="Optional customer name/identifier provided by user")
    projectegg = models.CharField(max_length=255, null=True, blank=True, help_text="Auto-generated code name from phase list used to obfuscate eggname")
    
    alive = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.subDomain or self.domainname or self.ip_address or str(self.id)


class WordlistUpload(models.Model):
    """Track wordlist uploads to Suzu vector database"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    wordlist_name = models.CharField(max_length=255, db_index=True)
    filename = models.CharField(max_length=255)
    cms_name = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    source = models.CharField(max_length=50, default='uploaded')
    paths_count = models.IntegerField(default=0)
    uploaded_count = models.IntegerField(default=0)
    failed_count = models.IntegerField(default=0)
    file_hash = models.CharField(max_length=64, null=True, blank=True, db_index=True, help_text="SHA256 hash of file content for deduplication")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['wordlist_name', 'created_at']),
            models.Index(fields=['cms_name', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.wordlist_name} ({self.uploaded_count} paths) - {self.created_at.strftime('%Y-%m-%d %H:%M')}"

