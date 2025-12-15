"""
Django settings for Ryu Cybersecurity project.
"""

from pathlib import Path
import os

# Try to load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, skip
    pass

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-ryu-cybersecurity-key-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'ryu_app',
    'surge',  # Surge Nuclei Scanner (integrated)
    'artificial_intelligence.customer_eggs_eggrecords_general_models',  # Core models (EggRecord, Nmap, etc.)
    # Add Oak and reconnaissance apps if available
    # 'artificial_intelligence.personalities.coordination.oak',  # Oak target curation
    'artificial_intelligence.personalities.reconnaissance',  # Nmap agents (Kage, Kaze, etc.) - Oak template correlation
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'ryu_app.middleware.DisableCSRFForDaemonAPI',  # Disable CSRF for daemon API endpoints (before CSRF middleware)
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# CSRF settings - API endpoints don't need CSRF protection
CSRF_TRUSTED_ORIGINS = []  # Daemon API endpoints bypass CSRF via middleware

ROOT_URLCONF = 'ryu_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'ryu_app.context_processors.surge_urls',  # Add surge URLs to all templates
            ],
        },
    },
]

WSGI_APPLICATION = 'ryu_project.wsgi.application'

# Database - PostgreSQL is the default (no SQLite to avoid corruption issues)
# DB_HOST is required - set it in environment variables or .env file
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_USER = os.environ.get('DB_USER', 'postgres')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'postgres')

# Default database (primary Django database)
# Uses customer_eggs as default since it's the main working database
# Use customer_eggs as the primary database (port 15440 is available)
# All databases point to the same working PostgreSQL instance
WORKING_DB_PORT = os.environ.get('CUSTOMER_EGGS_DB_PORT', '15440')
WORKING_DB_NAME = os.environ.get('CUSTOMER_EGGS_DB_NAME', 'customer_eggs')

# Connection pool settings to reduce connection exhaustion
# CONN_MAX_AGE in seconds: 0 = always close, None = unlimited, or set to pool time (e.g., 600 = 10 min)
DEFAULT_CONN_MAX_AGE = int(os.environ.get('DJANGO_CONN_MAX_AGE', '600'))  # 10 minutes default
# Customer Eggs gets its own pool with higher limit since it's most frequently used
CUSTOMER_EGGS_CONN_MAX_AGE = int(os.environ.get('CUSTOMER_EGGS_CONN_MAX_AGE', '600'))  # 10 minutes

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': WORKING_DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': WORKING_DB_PORT,
        'CONN_MAX_AGE': DEFAULT_CONN_MAX_AGE,  # Enable connection pooling (10 min default)
        'CONN_HEALTH_CHECKS': True,  # Enable health checks to detect stale connections
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'prefer',
            'application_name': 'livingarchive_kage_pro_default',
            # Limit max connections per application to prevent exhaustion
            'options': '-c statement_timeout=30000',  # 30 second statement timeout
        },
    },
    # Customer Eggs database (actual EggRecord tables - Nmap, RequestMetadata)
    # This is the PRIMARY database with MOST traffic - separate connection pool
    # Configured with dedicated pool settings to handle high load
    'customer_eggs': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': WORKING_DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': WORKING_DB_PORT,
        'CONN_MAX_AGE': CUSTOMER_EGGS_CONN_MAX_AGE,  # Dedicated pool with connection reuse (10 min default)
        'CONN_HEALTH_CHECKS': True,  # Enable health checks for connection pool
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'prefer',
            'application_name': 'livingarchive_customer_eggs_pooled',
            # Optimized options for high-traffic database
            'options': '-c statement_timeout=30000 -c idle_in_transaction_session_timeout=60000',
        },
        # Additional pool configuration (handled by Django's CONN_MAX_AGE)
        'ATOMIC_REQUESTS': False,  # Don't wrap in transaction by default for better performance
    },
    # EggRecords database (used for learning, heuristics, WAF detections)
    # Points to same working database - lower traffic, shorter connection lifetime
    'eggrecords': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': WORKING_DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': WORKING_DB_PORT,
        'CONN_MAX_AGE': DEFAULT_CONN_MAX_AGE,  # Use default pool (10 min)
        'CONN_HEALTH_CHECKS': True,
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'prefer',
            'application_name': 'livingarchive_eggrecords',
            'options': '-c statement_timeout=30000',
        },
    },
    # Oak Knowledge database (for Oak coordination and task queue)
    # Points to same working database - lower traffic, shorter connection lifetime
    'oak_knowledge': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': WORKING_DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': WORKING_DB_PORT,
        'CONN_MAX_AGE': DEFAULT_CONN_MAX_AGE,  # Use default pool (10 min)
        'CONN_HEALTH_CHECKS': True,
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'prefer',
            'application_name': 'livingarchive_oak_knowledge',
            'options': '-c statement_timeout=30000',
        },
    },
}

# Database Router for PostgreSQL models
DATABASE_ROUTERS = ['ryu_app.db_router.PostgresRouter']

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# File upload settings - allow large wordlist files
# Remove limits to allow files of any size
DATA_UPLOAD_MAX_MEMORY_SIZE = None  # No limit - stream to disk for large files
FILE_UPLOAD_MAX_MEMORY_SIZE = None  # No limit - stream to disk for large files
DATA_UPLOAD_MAX_NUMBER_FIELDS = None  # No limit on form fields
DATA_UPLOAD_MAX_NUMBER_FILES = None  # No limit on number of files

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

