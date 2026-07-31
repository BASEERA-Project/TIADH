FROM python:3.12-slim
WORKDIR /app

# The build context is the repository root (see docker-compose.yml) so that the
# shared `common` package can be installed alongside the collector. The layout
# is preserved inside the image, which is what makes the `-e ../common` line in
# requirements.txt resolve here exactly as it does in a local checkout.
COPY common ./common
COPY Part2_Central_Collector_API ./Part2_Central_Collector_API

WORKDIR /app/Part2_Central_Collector_API
RUN pip install --no-cache-dir -r requirements.txt

# HONEYPOT_DB_PATH is the shared database. Override this at runtime to point at
# the same file the enricher, the alert engine and the dashboard use.
ENV HONEYPOT_DB_PATH=/app/data/honeypot_aggregator.db

RUN mkdir -p /app/data
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
