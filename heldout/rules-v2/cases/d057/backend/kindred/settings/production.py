import os

from .base import *  # noqa: F401,F403

DEBUG = False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = ["api.kindred.chat"]

INSTALLED_APPS += ["corsheaders"]  # noqa: F405
MIDDLEWARE.insert(0, "corsheaders.middleware.CorsMiddleware")  # noqa: F405

CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "kindred",
        "USER": "kindred_app",
        "PASSWORD": "Wq7tLm3vRz9pXc2nKb8sHd5f",
        "HOST": "pg-primary.data.kindred.internal",
        "PORT": "5432",
        "CONN_MAX_AGE": 60,
    }
}

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
