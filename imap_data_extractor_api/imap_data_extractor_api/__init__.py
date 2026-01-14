from .celery import app as celery_app
# from mail_integration.tasks import process_gmail_message

__all__ = ("celery_app",)