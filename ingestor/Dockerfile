FROM python:3.12-slim

RUN apt-get update && apt-get install -y wget && \
    wget -qO /usr/local/bin/goflow2 \
      https://github.com/netsampler/goflow2/releases/download/v2.2.6/goflow2-2.2.6-linux-amd64 && \
    chmod +x /usr/local/bin/goflow2 && \
    apt-get remove -y wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ingestor.py .

CMD ["python", "ingestor.py"]
