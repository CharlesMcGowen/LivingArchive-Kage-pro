"""
Context processors for ryu_app templates.
"""
from django.urls import reverse, NoReverseMatch


def surge_urls(request):
    """
    Add surge dashboard URL to template context.
    This ensures the URL is available even if namespace resolution fails.
    Always returns a valid URL to prevent template errors.
    """
    try:
        surge_dashboard_url = reverse('surge:dashboard_about')
    except (NoReverseMatch, Exception):
        # Fallback URL if namespace resolution fails
        # This ensures the template always has a valid URL
        surge_dashboard_url = '/surge/about/'
    
    return {
        'surge_dashboard_url': surge_dashboard_url,
    }
