FROM python:3.12-slim
WORKDIR /app

# Install Part 2 dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Part 2 application
COPY app ./app

# Copy Part 4 so Part 2 can import its Database class at runtime.
# In a shared-volume deployment you can remove this COPY and set
# PART4_PATH to the mounted path instead.
COPY ../part4_storage_alerting ./part4_storage_alerting

# Install Part 4 dependencies (needed for its Database class)
RUN pip install --no-cache-dir -r ./part4_storage_alerting/requirements.txt

# HONEYPOT_DB_PATH is the shared database. Override this at runtime to
# point at the same file used by Parts 3, 4 and 5.
ENV HONEYPOT_DB_PATH=/app/data/honeypot_aggregator.db
ENV PART4_PATH=/app/part4_storage_alerting

RUN mkdir -p /app/data
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
