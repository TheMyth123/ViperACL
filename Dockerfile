FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (including ping for preflight network reachability checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose web application port
EXPOSE 8000

# Start ViperACL platform
CMD ["python3", "viperacl.py", "--host", "0.0.0.0", "--port", "8000", "--no-bootstrap-db"]
