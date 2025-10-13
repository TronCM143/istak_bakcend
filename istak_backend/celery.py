import os
from celery import Celery
from celery.schedules import crontab

# set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'istak_backend.settings')

app = Celery('istak_backend')

# load config from Django settings, using CELERY_ prefix
app.config_from_object('django.conf:settings', namespace='CELERY')

# auto-discover tasks inside all installed apps
app.autodiscover_tasks()

# Hardcoded Celery Beat schedule
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
