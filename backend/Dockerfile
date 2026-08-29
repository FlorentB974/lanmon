FROM python:3.11-slim-bookworm AS builder

# Build dependencies stay in this stage and are never copied into the image
# that runs the application.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv --without-pip /opt/venv

COPY requirements.txt /tmp/requirements.txt

# Install into a self-contained virtualenv without retaining pip itself.
RUN pip install --no-cache-dir --target=/opt/venv/lib/python3.11/site-packages \
        -r /tmp/requirements.txt

# Some binary wheels include Cython sources and unstripped symbols for
# development. Neither is needed to import or run the installed extensions.
RUN find /opt/venv -type f \( -name '*.c' -o -name '*.h' -o -name '*.pyc' \) -delete \
    && find /opt/venv -type f -name '*.so' -exec strip --strip-unneeded {} +

FROM python:3.11-slim-bookworm AS runtime

WORKDIR /app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Only install command-line tools used by the scanner. Development headers,
# compilers, nmap, and package-manager caches stay out of the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        arp-scan \
        iputils-ping \
        net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

COPY app ./app

# Expose the API port
EXPOSE 8250

# Run the application
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8250"]
