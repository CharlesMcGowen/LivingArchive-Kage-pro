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

