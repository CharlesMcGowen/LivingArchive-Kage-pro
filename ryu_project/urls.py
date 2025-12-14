"""
URL configuration for ryu_project.
"""
from django.contrib import admin
from django.urls import path, include
from ryu_app import views as ryu_views
import json
import os

# #region agent log
try:
    # Test if surge.urls can be imported
    from surge import urls as surge_urls
    surge_app_name = getattr(surge_urls, 'app_name', None)
    log_path = '/home/ego/github_public/.cursor/debug.log'
    try:
        import os
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'a') as f:
            f.write(json.dumps({
                'sessionId': 'debug-session',
                'runId': 'urlconf-load',
                'hypothesisId': 'B',
                'location': 'ryu_project/urls.py:import',
                'message': 'Surge URLs module import test',
                'data': {'imported': True, 'app_name': surge_app_name, 'has_urlpatterns': hasattr(surge_urls, 'urlpatterns')},
                'timestamp': int(__import__('time').time() * 1000)
            }) + '\n')
    except (OSError, IOError):
        pass  # Silently fail if we can't write logs
except Exception as e:
    log_path = '/home/ego/github_public/.cursor/debug.log'
    try:
        import os
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'a') as f:
            f.write(json.dumps({
                'sessionId': 'debug-session',
                'runId': 'urlconf-load',
                'hypothesisId': 'B',
                'location': 'ryu_project/urls.py:import',
                'message': 'Surge URLs module import FAILED',
                'data': {'error': str(e), 'error_type': type(e).__name__},
                'timestamp': int(__import__('time').time() * 1000)
            }) + '\n')
    except (OSError, IOError):
        pass  # Silently fail if we can't write logs
# #endregion

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('ryu_app.urls')),
    path('reconnaissance/', include(('ryu_app.urls', 'ryu_app'), namespace='reconnaissance')),
    path('surge/', include(('surge.urls', 'surge'), namespace='surge')),  # Surge Nuclei Scanner
    # Redirects for compatibility with expected URLs
    path('koga/dashboard/about/', ryu_views.koga_dashboard_redirect, name='koga_redirect'),
    path('koga/dashboard/', ryu_views.koga_dashboard_redirect, name='koga_dashboard_redirect'),
    path('koga/', ryu_views.koga_dashboard_redirect, name='koga_root_redirect'),
    path('bugsy/about/', ryu_views.bugsy_about_redirect, name='bugsy_about_redirect'),
    path('bugsy/', ryu_views.bugsy_about_redirect, name='bugsy_root_redirect'),
]

# #region agent log
# Log after urlpatterns are defined
log_path = '/home/ego/github_public/.cursor/debug.log'
try:
    import os
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'a') as f:
        f.write(json.dumps({
            'sessionId': 'debug-session',
            'runId': 'urlconf-load',
            'hypothesisId': 'B',
            'location': 'ryu_project/urls.py:urlpatterns',
            'message': 'URL patterns defined',
            'data': {'pattern_count': len(urlpatterns), 'surge_pattern_index': next((i for i, p in enumerate(urlpatterns) if 'surge' in str(p)), None)},
            'timestamp': int(__import__('time').time() * 1000)
        }) + '\n')
except (OSError, IOError):
    pass  # Silently fail if we can't write logs
# #endregion

