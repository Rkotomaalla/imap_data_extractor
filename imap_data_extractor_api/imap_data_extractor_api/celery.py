# imap_data_extractor_api/celery.py
import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "imap_data_extractor_api.settings")

app = Celery("imap_data_extractor_api")

# Charger la configuration depuis settings.py
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-découverte des tasks dans chaque app Django
app.autodiscover_tasks()