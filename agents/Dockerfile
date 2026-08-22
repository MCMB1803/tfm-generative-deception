FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persona cache, virtual filesystem seed and JSONL telemetry live here.
RUN mkdir -p /app/data/logs
VOLUME ["/app/data"]

EXPOSE 8000

# Single worker on purpose: session state is in-process, and multiple workers
# would each hold a different view of the same attacker session.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
