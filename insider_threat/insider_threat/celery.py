import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'insider_threat.settings')
app = Celery('insider_threat')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()