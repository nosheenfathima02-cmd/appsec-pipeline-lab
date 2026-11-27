# Intentionally weak container (training): unpinned base, runs as root, secret in image
FROM python:latest
ENV CLIENTNOTES_SECRET=dev-secret-123
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5001
CMD ["python", "app.py"]
