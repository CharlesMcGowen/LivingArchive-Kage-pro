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
    Note: CVE correlation is handled by Bugsy's CVE intelligence service (still in main codebase).
    """
    if not created:
        return
    
    # Skip low-confidence fingerprints
    if hasattr(instance, 'confidence_score') and instance.confidence_score < 0.5:
        logger.debug(f"🌳 Oak: Skipping low-confidence fingerprint ({instance.confidence_score:.2f})")
        return
    
    try:
        # CVE correlation is handled by Bugsy's CVE intelligence service
        # This signal is here for future enhancements or custom logic
        logger.debug(f"🌳 Oak: Technology fingerprint created → CVE correlation will be handled by Bugsy service")
        
    except Exception as e:
        logger.error(f"❌ Oak: Fingerprint CVE correlation failed: {e}", exc_info=True)


# Signal initialization
def initialize_reconnaissance_signals():
    """Initialize discovery → Oak curation signals."""
    logger.info("🔌 Reconnaissance→Oak discovery signals initialized")
    logger.info("   EggRecord creation → Oak curation workflow")
    logger.info("   TechnologyFingerprint → CVE correlation")

