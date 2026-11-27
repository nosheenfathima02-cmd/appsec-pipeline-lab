# Hardened container: pinned slim base, non-root user, no secrets baked in, healthcheck
FROM python:3.12-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 appuser
COPY app.py .
USER appuser
EXPOSE 5002
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5002/search')"
CMD ["python", "app.py"]
