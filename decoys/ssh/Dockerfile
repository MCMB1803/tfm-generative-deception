FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Persistent SSH host key: a fingerprint that changes on restart is a tell.
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 2222

CMD ["python", "-u", "ssh_server.py"]
