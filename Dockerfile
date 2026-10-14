FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Runtime dependencies only (no pytest/httpx in the image).
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Run as an unprivileged user; /data holds the SQLite file (mounted volume).
RUN useradd --system --uid 10001 --no-create-home identityguard \
    && mkdir /data && chown identityguard /data \
    && chmod +x /usr/local/bin/docker-entrypoint.sh
USER identityguard

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
