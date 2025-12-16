"""
Custom middleware to disable CSRF for daemon API endpoints
API endpoints don't need CSRF protection as they're not browser-based.
"""
from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger(__name__)


class DisableCSRFForDaemonAPI(MiddlewareMixin):
    """
    Middleware to completely disable CSRF checks for daemon API endpoints.
    Sets the _dont_enforce_csrf_checks flag before CSRF middleware runs.
    This runs BEFORE CsrfViewMiddleware, so we can disable CSRF checks.
    """
    
    def process_request(self, request):
        # Disable CSRF for all API endpoints (daemon and Suzu APIs)
        # No authentication required in development stage
        api_paths = [
            '/reconnaissance/api/daemon/',
            '/reconnaissance/api/suzu/',
            '/reconnaissance/api/kage/',
            '/reconnaissance/api/kaze/',
            '/reconnaissance/api/kumo/',
            '/reconnaissance/api/ryu/',
            '/reconnaissance/api/oak/',
        ]
        
        if any(request.path.startswith(path) for path in api_paths):
            # Set MULTIPLE flags to ensure CSRF is disabled
            # Django CSRF middleware checks _dont_enforce_csrf_checks
            setattr(request, '_dont_enforce_csrf_checks', True)
            # Also set csrf_exempt attribute
            setattr(request, 'csrf_exempt', True)
            # Force CSRF to be skipped
            setattr(request, 'csrf_processing_done', True)
            logger.info(f"✅ CSRF DISABLED for API: {request.path} (method: {request.method})")
        return None
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Also set in process_view as backup (runs after process_request, before CSRF middleware)
        api_paths = [
            '/reconnaissance/api/daemon/',
            '/reconnaissance/api/suzu/',
            '/reconnaissance/api/kage/',
            '/reconnaissance/api/kaze/',
            '/reconnaissance/api/kumo/',
            '/reconnaissance/api/ryu/',
            '/reconnaissance/api/oak/',
        ]
        
        if any(request.path.startswith(path) for path in api_paths):
            # Set MULTIPLE flags to ensure CSRF is disabled
            setattr(request, '_dont_enforce_csrf_checks', True)
            setattr(request, 'csrf_exempt', True)
            setattr(request, 'csrf_processing_done', True)
            logger.info(f"✅ CSRF BYPASS CONFIRMED in process_view: {request.path} (method: {request.method})")
        return None
