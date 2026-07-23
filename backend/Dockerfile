FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:${PATH}"

WORKDIR /app

RUN groupadd --system leakshield && useradd --system --gid leakshield --home /app leakshield

COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.8.15 \
    && uv sync --frozen --no-dev

COPY --chown=leakshield:leakshield app ./app

USER leakshield

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

