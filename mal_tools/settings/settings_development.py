from datetime import timedelta
from os.path import dirname, abspath, join

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ##### DEBUG CONFIGURATION ###############################
DEBUG = True

# allow all hosts during development
ALLOWED_HOSTS = ['*']

MIDDLEWARE = [
    'Users.middlewares.token_refresh_middleware.TokenRefreshMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# fetch the project_root
DJANGO_ROOT = dirname(dirname(abspath(__file__)))
PROJECT_ROOT = dirname(DJANGO_ROOT)
# collect static files here
STATIC_ROOT = join(PROJECT_ROOT, 'run', 'static')

# collect media files here
MEDIA_ROOT = join(PROJECT_ROOT, 'media')
MEDIA_URL = '/media/'

# look for static assets here
STATICFILES_DIRS = [
    join(PROJECT_ROOT, 'static'),
]

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True
