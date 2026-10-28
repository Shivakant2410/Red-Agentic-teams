FROM python:3.12-alpine

WORKDIR /app
COPY server.py /app/server.py
COPY probe.py /app/probe.py
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=2s --timeout=1s --retries=10 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=0.5)"]
CMD ["python", "-u", "/app/server.py"]
