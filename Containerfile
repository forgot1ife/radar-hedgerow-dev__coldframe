# python:3.12-slim, pinned so rebuilds are reproducible
FROM docker.io/library/python@sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177
RUN useradd --uid 10001 --no-create-home decoy && mkdir /logs /tls && chown decoy /logs
# Fresh keys per build, so deployments do not share one. Issuer and subject
# follow real AK-SM 800A units: a "SelfSigned-DanfossSM800A" CA and a 1-year leaf.
RUN cd /tls && \
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -sha256 -keyout ca.key -out ca.pem \
      -subj "/C=US/ST=MD/L=Baltimore/O=Danfoss/OU=Certificate_Authority/CN=SelfSigned-DanfossSM800A" 2>/dev/null && \
    openssl req -newkey rsa:2048 -nodes -keyout key.pem -out leaf.csr -subj "/CN=DanfossSM800A" 2>/dev/null && \
    openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 365 -sha256 -out cert.pem 2>/dev/null && \
    rm ca.key leaf.csr ca.srl && chown -R decoy /tls && chmod 400 key.pem
COPY honeypot.py /app/honeypot.py
USER decoy
ENV LOG_PATH=/logs/events.jsonl CERT_FILE=/tls/cert.pem KEY_FILE=/tls/key.pem \
    HTTP_PORT=8080 HTTPS_PORT=8443
EXPOSE 8080 8443
CMD ["python3", "-I", "/app/honeypot.py"]
