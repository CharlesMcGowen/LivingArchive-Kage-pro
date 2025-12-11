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
    # Add Oak and reconnaissance apps if available
    # 'artificial_intelligence.personalities.coordination.oak',  # Oak target curation
    # 'artificial_intelligence.personalities.reconnaissance',  # Nmap agents (Kage, Kaze, etc.)
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

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': WORKING_DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': WORKING_DB_PORT,
        'CONN_MAX_AGE': 0,
        'CONN_HEALTH_CHECKS': False,  # Disable health checks to allow startup
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'prefer',
            'application_name': 'livingarchive_kage_pro',
        },
    },
    # Customer Eggs database (actual EggRecord tables - Nmap, RequestMetadata)
    # This is the primary database that daemons use
    'customer_eggs': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': WORKING_DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': WORKING_DB_PORT,
        'CONN_MAX_AGE': 0,
        'CONN_HEALTH_CHECKS': False,  # Disable health checks to allow startup
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'prefer',
            'application_name': 'livingarchive_customer_eggs',
        },
    },
    # EggRecords database (used for learning, heuristics, WAF detections)
    # Points to same working database
    'eggrecords': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': WORKING_DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': WORKING_DB_PORT,
        'CONN_MAX_AGE': 0,
        'CONN_HEALTH_CHECKS': False,  # Disable health checks to allow startup
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'prefer',
            'application_name': 'livingarchive_eggrecords',
        },
    },
    # Oak Knowledge database (for Oak coordination and task queue)
    # Points to same working database
    'oak_knowledge': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': WORKING_DB_NAME,
        'USER': DB_USER,
        'PASSWORD': DB_PASSWORD,
        'HOST': DB_HOST,
        'PORT': WORKING_DB_PORT,
        'CONN_MAX_AGE': 0,
        'CONN_HEALTH_CHECKS': False,  # Disable health checks to allow startup
        'OPTIONS': {
            'connect_timeout': 10,
            'sslmode': 'prefer',
            'application_name': 'livingarchive_oak_knowledge',
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

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

