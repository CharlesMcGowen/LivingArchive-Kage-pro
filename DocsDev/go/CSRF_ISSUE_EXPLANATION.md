# CSRF Issue Explanation

## Why We Have a CSRF Issue

### The Problem

Django's CSRF (Cross-Site Request Forgery) protection is designed to prevent malicious websites from making unauthorized requests to your Django server. By default, Django requires a CSRF token for all POST requests.

### Why It's Happening

1. **Django CSRF Middleware Execution Order**
   - CSRF middleware (`CsrfViewMiddleware`) runs during `process_view`
   - It checks for CSRF token **before** the view is called
   - If no token is found, it returns 403 **immediately**
   - Our bypass middleware may run, but CSRF middleware might check first

2. **External HTTP Requests vs Test Client**
   - Django test client: Bypasses some security checks internally
   - Real HTTP requests: Go through full middleware stack
   - CSRF middleware is more strict with real HTTP requests

3. **Multiple Bypass Attempts Not Working**
   - `@csrf_exempt` decorator: Should work, but may not be recognized
   - URL-level `csrf_exempt()`: Should work, but middleware might check first
   - Custom middleware: Sets `_dont_enforce_csrf_checks`, but timing might be wrong

### Root Cause

The CSRF middleware is checking the request **before** our bypass mechanisms can take effect, or the `_dont_enforce_csrf_checks` attribute isn't being checked properly by Django's CSRF middleware.

## Solutions

### Option 1: Disable CSRF for Daemon Endpoints (Recommended)

Modify Django settings to exclude daemon API paths from CSRF protection:

```python
# In settings.py
CSRF_TRUSTED_ORIGINS = ['*']  # Not recommended for production
# OR better:
CSRF_EXEMPT_PATHS = [
    r'^/reconnaissance/api/daemon/.*',
]
```

### Option 2: Use API Key Authentication

Instead of CSRF, use API key authentication for daemon endpoints:

```python
# In daemon_api.py
def check_api_key(request):
    api_key = request.headers.get('X-API-Key')
    return api_key == settings.DAEMON_API_KEY
```

### Option 3: Fix Middleware Order

Ensure our middleware runs **before** CSRF middleware and sets the flag correctly:

```python
# Middleware should set flag in process_request (earlier)
def process_request(self, request):
    if request.path.startswith('/reconnaissance/api/daemon/'):
        request._dont_enforce_csrf_checks = True
    return None
```

### Option 4: Use Django's Built-in CSRF Exempt

Django has a built-in way to exempt views. The issue might be that we need to use it differently:

```python
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

@method_decorator(csrf_exempt, name='dispatch')
```

## Why Test Client Works But HTTP Doesn't

- **Test Client**: Django's test client can bypass CSRF internally for testing
- **Real HTTP**: Goes through full security stack, CSRF middleware is active
- **Middleware Timing**: CSRF middleware might check before our bypass runs

## Current Status

- ✅ `@csrf_exempt` decorator: Present on view
- ✅ URL-level exempt: Applied in urls.py
- ✅ Custom middleware: Created and in MIDDLEWARE
- ❌ Still getting 403: Middleware execution order or timing issue

## Recommended Fix

The most reliable solution is to **modify Django settings** to exclude daemon API paths from CSRF protection entirely, or use **API key authentication** instead of relying on CSRF bypass mechanisms.


