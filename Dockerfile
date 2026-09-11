FROM python:3.11-slim

# libmagic1 enables python-magic; optional but improves binary detection.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY sbomx ./sbomx

# Install core + SBOM/binary extras. Drop [all] to slim the image.
RUN pip install --no-cache-dir ".[all]" || pip install --no-cache-dir .

# Non-root user for the API.
RUN useradd -m sbomx
USER sbomx

EXPOSE 8000
ENTRYPOINT ["sbomx"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
