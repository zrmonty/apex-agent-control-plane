# Reference provider image. Build with approved base digests in production.
ARG RUNTIME_IMAGE=python:3.12-slim
FROM ${RUNTIME_IMAGE}
WORKDIR /app
COPY apex_reference_providers /app/apex_reference_providers
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
ENV PYTHONPATH=/app
ENV APEX_SERVICE=clickhouse_projection
# Required at runtime: cert/key/client-ca paths via env or flags.
ENTRYPOINT ["python", "-m", "apex_reference_providers"]
CMD ["clickhouse_projection", "--bind", "0.0.0.0", "--port", "8443", \
     "--cert", "/run/secrets/server_cert", "--key", "/run/secrets/server_key", \
     "--client-ca", "/run/secrets/client_ca", "--data-dir", "/var/lib/apex"]
