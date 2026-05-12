FROM ghcr.io/astral-sh/uv:python3.12-alpine3.23

WORKDIR /app

COPY uv.lock pyproject.toml /app/

RUN uv sync --locked

COPY . /app

CMD ["uv", "run", "fastapi", "dev"]