#!/bin/bash

exec python3 colector.py &
exec python3 dumb_worker.py
