FROM python:3.12-slim

# uv drives the install so the image gets exactly what dashboard/uv.lock pins.
RUN pip install --no-cache-dir uv

WORKDIR /app

# The build context is the repository root (see docker-compose.yml). `dashboard`
# depends on the sibling `common` package, so both trees are copied in with
# their layout preserved.
COPY common ./common
COPY dashboard ./dashboard

WORKDIR /app/dashboard
# --extra serve adds waitress. Flask's own server is fine for a demo, but a
# container is the "left running" case the README already points at waitress for.
RUN uv sync --frozen --no-dev --extra serve

# Run straight out of the synced environment — no uv needed at runtime.
ENV PATH="/app/dashboard/.venv/bin:$PATH"

# HONEYPOT_DB_PATH is the database the aggregator writes. This path is the mount
# point of the shared tiadh_db volume, so both containers read one file; a
# dashboard pointed anywhere else renders an empty setup screen.
ENV HONEYPOT_DB_PATH=/app/data/honeypot_aggregator.db
RUN mkdir -p /app/data

# The one default that has to differ from the host. The dashboard binds loopback
# on purpose — it renders attacker IPs, session transcripts and the outbound
# feed — but inside the container's own network namespace a loopback bind would
# make the published port unreachable. The decision that default protects is not
# lost, it moves outward: compose publishes to 127.0.0.1, so exposing this to the
# lab network is still something someone types.
ENV DASHBOARD_HOST=0.0.0.0
ENV DASHBOARD_PORT=8050

# Documentation for the default; what a container actually publishes is
# compose's `ports:`.
EXPOSE 8050

# waitress, not `main.py` — the same app factory, behind a server meant to stay
# up. Shell form with `exec` so DASHBOARD_HOST/DASHBOARD_PORT can move the bind
# address from compose's `environment:` block without a rebuild, while the shell
# still hands its process over rather than sitting between waitress and its
# signals.
#
# Run this with an init process — compose does (`init: true`), `docker run` needs
# `--init`. Unlike uvicorn in core/Dockerfile, waitress installs no SIGTERM
# handler, and the kernel does not deliver a default-disposition signal to PID 1,
# so without one `docker stop` waits out its whole grace period and then SIGKILLs.
#
# Threaded workers are safe here: app/db.py opens one read-only handle per
# request and releases it on teardown.
CMD ["sh", "-c", "exec waitress-serve --call --host \"$DASHBOARD_HOST\" --port \"$DASHBOARD_PORT\" app:create_app"]
