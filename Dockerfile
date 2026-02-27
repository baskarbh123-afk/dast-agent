# DAST Agent - Advanced Bug Bounty Automation Tool
# Only use against targets you have explicit authorization to test.

FROM python:3.11-slim

LABEL maintainer="baskarbh123-afk"
LABEL description="DAST Agent - Advanced Bug Bounty Automation Tool"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        libxml2-dev \
        libxslt1-dev \
        gcc \
        libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create reports output directory
RUN mkdir -p /app/reports

# Set volume for reports output
VOLUME ["/app/reports"]

# Set entrypoint
ENTRYPOINT ["python", "main.py"]

# Default: show help
CMD ["--help"]
