FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for scapy, nmap, and building Python packages
RUN apt-get update && apt-get install -y \
    nmap \
    libpcap-dev \
    net-tools \
    iputils-ping \
    arp-scan \
    gcc \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the API port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
