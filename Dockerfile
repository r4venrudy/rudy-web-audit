FROM python:3.12-slim-bookworm AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY rudy_web_audit ./rudy_web_audit
COPY tests ./tests
RUN python -m unittest discover -s tests -v && python -m pip wheel --no-cache-dir --wheel-dir /wheels .
FROM python:3.12-slim-bookworm
LABEL org.opencontainers.image.source="https://github.com/r4venrudy/rudy-web-audit"           org.opencontainers.image.description="HTTP/TLS evidence audit CLI"           org.opencontainers.image.licenses="MIT"
COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/*.whl && rm -r /wheels && useradd --uid 10001 --create-home rudy && mkdir /data && chown rudy:rudy /data
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /data
ENTRYPOINT ["rudy-web-audit"]
CMD ["--help"]
