from .celery import app as celery_app
from mail_integration.tasks import *

__all__ = ("celery_app",)