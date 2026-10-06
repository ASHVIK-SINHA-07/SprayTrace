# Two stages: build the dashboard with Node, then serve it from the Python API
# as one container. A single unit means one thing to deploy and no CORS or
# cross-origin configuration in production.

FROM node:20-alpine AS frontend
WORKDIR /build
COPY src/frontend/package*.json ./
RUN npm ci
COPY src/frontend/ ./
RUN npm run build

FROM python:3.13-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY configs/ ./configs/
COPY docs/ ./docs/
COPY --from=frontend /build/dist ./static

# Generate the dataset at build time so the image is self-contained and every
# container starts from identical, reproducible data (seed 42).
RUN python -m src.scripts.generate_data

# Run as a non-root user: the container is internet-facing and nothing here
# needs privileges.
RUN useradd --create-home --uid 10001 spraytrace \
    && chown -R spraytrace:spraytrace /app
USER spraytrace

EXPOSE 8000
ENV SPRAYTRACE_STATIC=/app/static

# Azure Container Apps sets PORT; default to 8000 for local runs.
CMD ["sh", "-c", "uvicorn src.backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
