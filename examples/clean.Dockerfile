# Secrets are mounted at runtime, never baked into layers.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/
ENV APP_ENV=production
EXPOSE 8000
CMD ["python", "-m", "src.app"]
