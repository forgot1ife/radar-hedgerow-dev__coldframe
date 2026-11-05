# python:3.12-slim, pinned so rebuilds are reproducible
FROM docker.io/library/python@sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177
RUN useradd --uid 10001 --no-create-home decoy && mkdir /logs /tls && chown decoy /logs
# A fresh self-signed certificate per build, so deployments do not share one.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=SM800A" \
      -keyout /tls/key.pem -out /tls/cert.pem 2>/dev/null && chown -R decoy /tls && chmod 400 /tls/key.pem
COPY honeypot.py /app/honeypot.py
USER decoy
ENV LOG_PATH=/logs/events.jsonl CERT_FILE=/tls/cert.pem KEY_FILE=/tls/key.pem \
    HTTP_PORT=8080 HTTPS_PORT=8443
EXPOSE 8080 8443
CMD ["python3", "-I", "/app/honeypot.py"]
