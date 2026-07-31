FROM python:3.12-slim

# uv drives the install so the image gets exactly what core/uv.lock pins.
RUN pip install --no-cache-dir uv

WORKDIR /app

# The build context is the repository root (see docker-compose.yml). The
# collector is part of the `core` project, and `core` depends on the sibling
# `common` package, so both trees are copied in with their layout preserved.
COPY common ./common
COPY core ./core

WORKDIR /app/core
RUN uv sync --frozen --no-dev

# Run straight out of the synced environment — no uv needed at runtime.
ENV PATH="/app/core/.venv/bin:$PATH"

# HONEYPOT_DB_PATH is the shared database. Override this at runtime to point at
# the same file the enricher, the alert engine and the dashboard use.
ENV HONEYPOT_DB_PATH=/app/data/honeypot_aggregator.db
RUN mkdir -p /app/data

WORKDIR /app/core/collector
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
