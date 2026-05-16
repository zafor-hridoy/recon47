FROM python:3.11-slim

LABEL maintainer="Xaff"
LABEL description="Recon47 - Automated Reconnaissance & Vulnerability Scanner"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep tag_name | cut -d'"' -f4 | sed 's/v//')_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    || echo "Nuclei installation skipped"

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Default output directory
RUN mkdir -p /app/recon47_output

ENTRYPOINT ["python", "recon47.py"]
CMD ["--help"]
