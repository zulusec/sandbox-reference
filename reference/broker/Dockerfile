FROM python:3.12-slim

COPY broker.py /app/broker.py

RUN mkdir -p /var/log/broker && chown 10001:10001 /var/log/broker

USER 10001:10001

ENTRYPOINT ["python3", "/app/broker.py"]
