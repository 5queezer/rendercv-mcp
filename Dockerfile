FROM python:3.12-slim-bookworm

WORKDIR /app

# Dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Source
COPY mcp_server/ mcp_server/
COPY server.py .
COPY examples/ examples/

ENV PORT=8080
EXPOSE 8080

CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT} --log-level info"]
