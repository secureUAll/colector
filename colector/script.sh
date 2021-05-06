#!/bin/bash


exec celery -A celery_worker worker -l info &
exec python3 colector.py &
exec python3 dumb_worker.py
