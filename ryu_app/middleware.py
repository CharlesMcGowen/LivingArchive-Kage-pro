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
    """
    
    def process_request(self, request):
        # Disable CSRF for all daemon API endpoints
        if request.path.startswith('/reconnaissance/api/daemon/'):
            # Set the flag that Django's CSRF middleware checks
            setattr(request, '_dont_enforce_csrf_checks', True)
            logger.info(f"CSRF disabled for daemon API: {request.path} (method: {request.method})")
        return None
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Also set in process_view as backup (runs after process_request)
        if request.path.startswith('/reconnaissance/api/daemon/'):
            setattr(request, '_dont_enforce_csrf_checks', True)
            logger.debug(f"CSRF bypass confirmed in process_view: {request.path}")
        return None

