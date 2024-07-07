from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# set the default Django setting module for the 'celery' progrma.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'system.settings')

app = Celery('system')

# using string means the worker doesn't have to serialize
# the configuration object to child processes
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load the task nodules from all registered Django app configs
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
