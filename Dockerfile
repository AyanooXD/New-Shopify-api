FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core.py .
COPY api.py .

EXPOSE 8080

# Use shell form so $PORT gets expanded by the shell
CMD uvicorn api:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1
