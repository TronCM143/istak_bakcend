web: gunicorn istak_backend.wsgi:application -b 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120 --max-requests 500 --max-requests-jitter 50
