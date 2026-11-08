# python:3.12-slim, pinned so rebuilds are reproducible
FROM docker.io/library/python@sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177
RUN useradd --uid 10001 --no-create-home decoy && mkdir /logs /tls && chown decoy /logs
# Fresh keys per build, so deployments do not share one. Issuer and subject
# follow real AK-SM 800A units: a "SelfSigned-DanfossSM800A" CA and a 1-year leaf.
# Validity is backdated to random days (CA 2-7 years ago, leaf 1-11 months ago)
# so the certificate does not reveal when the decoy was built.
RUN cd /tls && \
    set -- $(python3 -I -c "import random,datetime as d; n=d.datetime.now(d.timezone.utc).replace(microsecond=0); f=lambda t:t.strftime('%Y%m%d%H%M%SZ'); c=n-d.timedelta(days=random.randint(730,2555),seconds=random.randint(0,86399)); l=n-d.timedelta(days=random.randint(30,330),seconds=random.randint(0,86399)); print(f(c),f(c+d.timedelta(days=3650)),f(l),f(l+d.timedelta(days=365)))") && \
    printf '[ca]\ndefault_ca=d\n[d]\ndatabase=index.txt\nnew_certs_dir=.\nserial=serial\ndefault_md=sha256\npolicy=p\nunique_subject=no\n[p]\ncountryName=optional\nstateOrProvinceName=optional\nlocalityName=optional\norganizationName=optional\norganizationalUnitName=optional\ncommonName=supplied\n[v3_ca]\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nbasicConstraints=critical,CA:true\n[leaf]\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > ca.cnf && \
    touch index.txt && openssl rand -hex 16 > serial && \
    openssl req -new -newkey rsa:2048 -nodes -keyout ca.key -out ca.csr \
      -subj "/C=US/ST=MD/L=Baltimore/O=Danfoss/OU=Certificate_Authority/CN=SelfSigned-DanfossSM800A" 2>/dev/null && \
    openssl ca -batch -config ca.cnf -selfsign -keyfile ca.key -in ca.csr -out ca.pem -notext \
      -extensions v3_ca -startdate $1 -enddate $2 2>/dev/null && \
    openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out leaf.csr -subj "/CN=DanfossSM800A" 2>/dev/null && \
    openssl ca -batch -config ca.cnf -cert ca.pem -keyfile ca.key -in leaf.csr -out cert.pem -notext \
      -extensions leaf -startdate $3 -enddate $4 2>/dev/null && \
    rm -f ca.key ca.csr leaf.csr ca.cnf index.txt* serial* *.pem.old [0-9A-F]*.pem && \
    chown -R decoy /tls && chmod 400 key.pem
COPY honeypot.py /app/honeypot.py
USER decoy
ENV LOG_PATH=/logs/events.jsonl CERT_FILE=/tls/cert.pem KEY_FILE=/tls/key.pem \
    HTTP_PORT=8080 HTTPS_PORT=8443
EXPOSE 8080 8443
CMD ["python3", "-I", "/app/honeypot.py"]
