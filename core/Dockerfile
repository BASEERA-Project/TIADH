FROM python:3.12-slim

# uv drives the install so the image gets exactly what core/uv.lock pins.
RUN pip install --no-cache-dir uv

WORKDIR /app

# The build context is the repository root (see docker-compose.yml). `core`
# depends on the sibling `common` package, so both trees are copied in with
# their layout preserved.
COPY common ./common
COPY core ./core

WORKDIR /app/core
RUN uv sync --frozen --no-dev

# Run straight out of the synced environment — no uv needed at runtime.
ENV PATH="/app/core/.venv/bin:$PATH"

# HONEYPOT_DB_PATH is the shared database. Override this at runtime to point at
# the same file the dashboard reads.
ENV HONEYPOT_DB_PATH=/app/data/honeypot_aggregator.db
ENV HONEYPOT_EXPORT_DIR=/app/data/exports
RUN mkdir -p /app/data

# One container, the whole aggregator: collector + enricher + alert/export
# cycle. `serve` creates the schema on startup, so there is no init step, and
# uvicorn handles SIGTERM, so `docker stop` shuts all three down gracefully.
#
# No --host/--port on the command: the bind address comes from COLLECTOR_HOST /
# COLLECTOR_PORT and defaults to 0.0.0.0:8000, so compose's `environment:` block
# can move the port without rebuilding the image. Leave the host at 0.0.0.0 —
# inside the container's own network namespace, a loopback bind would make the
# published port unreachable. EXPOSE is documentation for the default; what a
# container actually publishes is compose's `ports:`.
EXPOSE 8000
CMD ["python", "main.py", "serve"]
