FROM python:3.12-alpine3.23

COPY --from=ghcr.io/astral-sh/uv:python3.12-alpine3.23 /uv /uvx /bin/

COPY . /app

ENV UV_NO_DEV=1

WORKDIR /app
RUN uv sync --locked

ENV PORT = 8080
EXPOSE 8080


CMD ["fastapi", "dev"]