# A deliberately leaky Dockerfile. Every placeholder below is fake --
# run `python secret_timeline.py examples/vulnerable.Dockerfile` to see
# exactly which layer introduces each secret.
FROM python:3.12-slim
WORKDIR /app
ARG BUILD_TOKEN=demo-token-placeholder
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY .env /app/.env
ENV AWS_SECRET_ACCESS_KEY=DEMO_PLACEHOLDER_VALUE
ENV APP_ENV=production
RUN curl -u deploy:DEMO_PASSWORD https://artifacts.internal.example.com/pkg.tar.gz -o pkg.tar.gz \
    && tar xzf pkg.tar.gz && rm pkg.tar.gz
COPY . .
EXPOSE 8000
CMD ["python", "app.py"]
