#!/usr/bin/env python3
"""
Reconnaissance Discovery Signals
==================================

Automatic curation when Ash/Jade/Kage discover subdomains.
Oak curates all subdomain discoveries with technology fingerprinting and vulnerability intelligence.

Architecture:
    Discovery → EggRecord → Oak Curation → Technology Fingerprinting → CVE Match → Scan Recommendations

Author: EGO Revolution Team
Version: 1.0.0
Migrated to Kage-pro: 2024
"""

import logging
from django.db.models.signals import post_save
from django.db.models import Q
from django.dispatch import receiver
from django.utils import timezone

logger = logging.getLogger(__name__)


@receiver(post_save, sender='customer_eggs_eggrecords_general_models.EggRecord')
def discovery_to_oak_curation(sender, instance, created, **kwargs):
    """
    When Ash, Jade, or Kage discover a new subdomain, Oak automatically curates it.
    
    Flow:
        1. Discovery agents create EggRecord (subdomain)
        2. Oak triggers curation workflow
        3. Oak performs fingerprinting
        4. Oak correlates CVEs and builds metadata
        5. Scan recommendations generated for Surge
    
    This is Oak's "automatic curation" - enriching every discovery with vulnerability intelligence.
    """
    if not created:
        return
    
    # Only process new subdomain discoveries
    if not instance.subDomain:
        return
    
    # Check if this is from discovery system
    discovery_metadata = getattr(instance, 'discovery_metadata', None) or {}
    discovered_by = discovery_metadata.get('discovered_by', 'unknown')
    
    # Accept discoveries from Ash, Jade, Kage, or any reconnaissance agent
    if discovered_by not in ['ash', 'jade', 'kage', 'ash_jade_discovery', 'reconnaissance']:
        # Not from our discovery system, skip
        return
    
    try:
        logger.info(f"🌳 Oak: New {discovered_by} discovery → {instance.subDomain}")
        
        # Trigger immediate Oak curation workflow
        # Import from new Kage-pro location
        from artificial_intelligence.personalities.reconnaissance.oak.target_curation.target_curation_service import (
            OakTargetCurationService
        )
        
        curation_service = OakTargetCurationService()
        
        # Queue for curation (async processing)
        curation_result = curation_service.queue_subdomain_for_curation(
            egg_record=instance,
            discovery_source=discovered_by,
            priority='normal'  # 'high' for critical targets
        )
        
        if curation_result['success']:
            logger.info(f"✅ Oak: Queued {instance.subDomain} for curation")
            logger.info(f"   Discovery: {discovered_by} | Queue position: {curation_result.get('queue_position')}")
        else:
            logger.warning(f"⚠️ Oak: Failed to queue {instance.subDomain}: {curation_result.get('error')}")
        
    except Exception as e:
        logger.error(f"❌ Oak: Discovery curation failed for {instance.subDomain}: {e}", exc_info=True)


@receiver(post_save, sender='customer_eggs_eggrecords_general_models.TechnologyFingerprint')
def fingerprint_to_cve_correlation(sender, instance, created, **kwargs):
    """
    When Oak creates a TechnologyFingerprint, automatically correlate with CVEs.
    
    Flow:
        TechnologyFingerprint → CVE Database Query → CVEFingerprintMatch → Scan Recommendations
    
    This ensures every fingerprint immediately gets CVE intelligence.
    Correlates technology fingerprints with Nuclei templates that have matching CVE IDs.
    """
    if not created:
        return
    
    # Skip low-confidence fingerprints
    if hasattr(instance, 'confidence_score') and instance.confidence_score < 0.5:
        logger.debug(f"🌳 Oak: Skipping low-confidence fingerprint ({instance.confidence_score:.2f})")
        return
    
    try:
        from django.db import connections, transaction
        from artificial_intelligence.customer_eggs_eggrecords_general_models.models import (
            NucleiTemplate, CVEFingerprintMatch
        )
        import uuid as uuid_lib
        
        tech_name = instance.technology_name.lower() if instance.technology_name else ''
        if not tech_name:
            return
        
        # Map common protocol/service names to technology keywords for template matching
        tech_mapping = {
            'http': ['http', 'web', 'cms', 'wordpress', 'drupal', 'joomla'],
            'https': ['https', 'ssl', 'tls', 'web', 'cms'],
            'ftp': ['ftp', 'file'],
            'ssh': ['ssh', 'linux', 'unix'],
            'mysql': ['mysql', 'database', 'db'],
            'postgresql': ['postgres', 'postgresql', 'database', 'db'],
            'mongodb': ['mongodb', 'database', 'db'],
            'redis': ['redis', 'database', 'cache'],
            'dns': ['dns', 'domain'],
            'smtp': ['smtp', 'mail', 'email'],
            'imap': ['imap', 'mail', 'email'],
            'pop3': ['pop3', 'mail', 'email'],
            'wordpress': ['wordpress', 'wp', 'cms'],
            'apache': ['apache', 'httpd', 'web'],
            'nginx': ['nginx', 'web'],
            'tomcat': ['tomcat', 'apache', 'java'],
        }
        
        # Get search keywords for this technology
        search_keywords = tech_mapping.get(tech_name, [tech_name])
        
        # Find Nuclei templates matching this technology that have CVE IDs
        # Try multiple matching strategies since templates may not have technology field populated
        matching_templates = NucleiTemplate.objects.none()
        
        # Strategy 1: Match by technology field (if populated)
        matching_templates |= NucleiTemplate.objects.filter(
            technology__iexact=tech_name
        ).exclude(cve_id__isnull=True).exclude(cve_id='')
        
        # Strategy 2: Match by tags containing technology keywords
        for keyword in search_keywords:
            matching_templates |= NucleiTemplate.objects.filter(
                tags__icontains=keyword
            ).exclude(cve_id__isnull=True).exclude(cve_id='')
        
        # Strategy 3: Match by template_id containing technology name
        matching_templates |= NucleiTemplate.objects.filter(
            template_id__icontains=tech_name
        ).exclude(cve_id__isnull=True).exclude(cve_id='')
        
        # Strategy 4: Match by template_name containing technology name
        matching_templates |= NucleiTemplate.objects.filter(
            template_name__icontains=tech_name
        ).exclude(cve_id__isnull=True).exclude(cve_id='')
        
        # Remove duplicates and limit
        matching_templates = matching_templates.distinct()[:20]
        
        if not matching_templates.exists():
            logger.debug(f"🌳 Oak: No CVE templates found for technology '{tech_name}' (tried keywords: {search_keywords})")
            return
        
        cve_matches_created = 0
        
        # Create CVEFingerprintMatch records for each matching CVE template
        with transaction.atomic(using='eggrecords'):
            try:
                db = connections['eggrecords']
            except KeyError:
                db = connections['default']
            
            for template in matching_templates:
                cve_id = template.cve_id.upper() if template.cve_id else None
                if not cve_id:
                    continue
                
                # Check if CVE match already exists
                existing_match = CVEFingerprintMatch.objects.filter(
                    egg_record_id=instance.egg_record_id,
                    cve_id=cve_id,
                    technology_fingerprint_id=instance.id
                ).first()
                
                if existing_match:
                    continue  # Already matched
                
                # Calculate match confidence based on template match
                match_confidence = instance.confidence_score if hasattr(instance, 'confidence_score') else 0.7
                
                # Check if Nuclei template exists for this CVE
                nuclei_template_available = True
                nuclei_template_ids = [template.template_id]
                
                # Create CVEFingerprintMatch record
                cve_match = CVEFingerprintMatch.objects.create(
                    egg_record_id=instance.egg_record_id,
                    technology_fingerprint_id=instance.id,
                    cve_id=cve_id,
                    cve_severity=template.severity.upper() if template.severity else 'UNKNOWN',
                    cve_cvss_score=0.0,  # Would need CVE database for actual CVSS
                    technology_name=tech_name,
                    match_confidence=match_confidence,
                    nuclei_template_available=nuclei_template_available,
                    nuclei_template_ids=nuclei_template_ids,
                    recommended_for_scanning=True
                )
                
                cve_matches_created += 1
                logger.debug(f"🌳 Oak: Created CVE match {cve_id} for {tech_name} (confidence: {match_confidence:.2f})")
        
        if cve_matches_created > 0:
            logger.info(f"🌳 Oak: Created {cve_matches_created} CVE match(es) for fingerprint '{tech_name}'")
        
    except ImportError as e:
        logger.debug(f"🌳 Oak: CVE correlation models not available: {e}")
    except Exception as e:
        logger.error(f"❌ Oak: Fingerprint CVE correlation failed: {e}", exc_info=True)


# Signal initialization
def initialize_reconnaissance_signals():
    """Initialize discovery → Oak curation signals."""
    logger.info("🔌 Reconnaissance→Oak discovery signals initialized")
    logger.info("   EggRecord creation → Oak curation workflow")
    logger.info("   TechnologyFingerprint → CVE correlation")

