from django.apps import AppConfig
import logging
import threading
import os

logger = logging.getLogger(__name__)

# Global flag to prevent multiple starts (Django can call ready() multiple times in dev mode)
_scanner_started = False
_start_lock = threading.Lock()


class SurgeConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'surge'
    verbose_name = 'Surge Nuclei Scanner'
    
    def ready(self):
        """Start Surge autonomous scanner when Django is ready"""
        global _scanner_started
        
        # Prevent multiple starts (Django's auto-reloader calls ready() twice in dev mode)
        with _start_lock:
            if _scanner_started:
                logger.debug("⚡ Surge scanner already started, skipping duplicate start")
                return
            _scanner_started = True
        
        # Only run in the main process (not in management commands like migrate, shell, etc.)
        import sys
        run_commands = ['runserver', 'gunicorn', 'uwsgi', 'daphne']
        if any(cmd in ' '.join(sys.argv) for cmd in run_commands):
            # Start scanner in a background thread to avoid blocking Django startup
            try:
                from surge.agents.autonomous_scanner import get_instance
                import asyncio
                
                def start_scanner_thread():
                    """Start the scanner in a background thread with its own event loop"""
                    try:
                        scanner = get_instance()
                        if not scanner.running:
                            logger.info("⚡ Starting Surge autonomous scanner (background thread)...")
                            # Create a new event loop for this thread
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                            try:
                                loop.run_until_complete(scanner.run())
                            except Exception as e:
                                logger.error(f"❌ Error running Surge scanner: {e}", exc_info=True)
                            finally:
                                loop.close()
                        else:
                            logger.info("⚡ Surge autonomous scanner already running")
                    except ImportError as e:
                        logger.warning(f"Could not import Surge autonomous scanner: {e}")
                    except Exception as e:
                        logger.warning(f"Could not start Surge autonomous scanner: {e}", exc_info=True)
                
                # Start scanner in a daemon thread (will terminate when main process exits)
                scanner_thread = threading.Thread(target=start_scanner_thread, daemon=True, name="SurgeScanner")
                scanner_thread.start()
                
                logger.info("⚡ Surge autonomous scanner thread started (Django app ready)")
            except ImportError as e:
                logger.debug(f"Surge scanner components not available: {e}")
            except Exception as e:
                logger.warning(f"Could not start Surge autonomous scanner: {e}", exc_info=True)

