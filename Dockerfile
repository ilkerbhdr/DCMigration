FROM python:3.11-slim

WORKDIR /app

# Sistem bağımlılıkları (SSH client için)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Python bağımlılıkları
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyaları
COPY *.py ./
COPY templates/ ./templates/
COPY static/ ./static/

# Data dizini (DB + exports)
RUN mkdir -p /app/data/exports

EXPOSE 5000

# Gunicorn + gevent worker (SSE desteği)
CMD ["python", "run.py"]
