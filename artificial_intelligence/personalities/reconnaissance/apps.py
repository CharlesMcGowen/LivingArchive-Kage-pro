"""
Reconnaissance App Configuration
=================================
Django app configuration for the reconnaissance personality.
Starts Oak coordinator service automatically when Django is ready.
"""

from django.apps import AppConfig
import logging
import sys
import threading

logger = logging.getLogger(__name__)


class ReconnaissanceConfig(AppConfig):
    """Reconnaissance app configuration"""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'artificial_intelligence.personalities.reconnaissance'
    verbose_name = 'Reconnaissance Team'
    
    def ready(self):
        """Initialize Oak coordinator service when Django app is ready"""
        # Only run in main process (not in migrations, tests, etc.)
        if 'migrate' in sys.argv or 'makemigrations' in sys.argv:
            return
        
        # Skip if running in test mode
        if 'test' in sys.argv:
            return
        
        # Import signals to register them
        try:
            import artificial_intelligence.personalities.reconnaissance.signals  # noqa: F401
        except ImportError:
            logger.warning("Could not import reconnaissance signals")
        
        # Start Oak service in background thread
        try:
            from artificial_intelligence.personalities.reconnaissance.oak.service import OakService
            
            oak_service = OakService()
            oak_thread = threading.Thread(
                target=oak_service.run,
                daemon=True,
                name='OakService'
            )
            oak_thread.start()
            
            logger.info("🌳 Oak coordinator service started (Django app ready)")
        except ImportError as e:
            logger.warning(f"Could not import Oak service: {e}")
        except Exception as e:
            logger.warning(f"Could not start Oak service: {e}", exc_info=True)
        
        # Start Oak autonomous curation service
        try:
            from artificial_intelligence.personalities.reconnaissance.oak.target_curation.autonomous_curation_service import get_instance
            
            curation_service = get_instance()
            curation_service.start_service()
            
            logger.info("🌳 Oak autonomous curation service started (Django app ready)")
        except ImportError as e:
            logger.warning(f"Could not import Oak autonomous curation service: {e}")
        except Exception as e:
            logger.warning(f"Could not start Oak autonomous curation service: {e}", exc_info=True)

