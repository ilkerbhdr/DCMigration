"""Gunicorn WSGI entry point."""
# Gevent monkey-patch — tüm import'lardan ÖNCE yapılmalı
from gevent import monkey
monkey.patch_all()

import os
from database import init_db

# DB ve dizinleri başlangıçta oluştur
init_db()

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(os.path.join(DATA_DIR, "exports"), exist_ok=True)

from app import app  # noqa: E402
