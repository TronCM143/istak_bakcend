from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from celery.schedules import crontab
# celery.py



os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'istak_backend.settings')

app = Celery('istak_backend')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks()
app.conf.beat_schedule = {
    "notify-due-items-daily": {
        "task": "istak_backend.tasks.notify_due_items",
        "schedule": crontab(hour=8, minute=0),  # every day at 8 AM
    },
    # For testing: runs every 1 minute
    "test-notify-every-minute": {
        "task": "istak_backend.tasks.notify_due_items",
        "schedule": crontab(minute="*/1"),
    },
}
