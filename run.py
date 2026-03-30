"""Simple threaded Flask server — gevent/gunicorn sorunlarını bypass eder.

3-4 kullanıcı için threaded Flask yeterli.
SSE stream'ler Flask'ın threading modunda çalışır.
"""
import os
from database import init_db

# DB başlat
init_db()

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(os.path.join(DATA_DIR, "exports"), exist_ok=True)

from app import app  # noqa: E402

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        threaded=True,
    )
