FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    git \
    golang-go \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install directory enumeration tools for Suzu
# Install ffuf (Fast web fuzzer) - download latest release
RUN FFUF_VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') \
    && wget -q "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_amd64.tar.gz" \
    && tar -xzf ffuf_*.tar.gz \
    && mv ffuf /usr/local/bin/ \
    && chmod +x /usr/local/bin/ffuf \
    && rm -f ffuf_*.tar.gz || echo "ffuf installation failed, continuing..."

# Install gobuster (Directory/file brute-forcing tool)
RUN go install github.com/OJ/gobuster/v3@latest \
    && cp /root/go/bin/gobuster /usr/local/bin/ \
    && chmod +x /usr/local/bin/gobuster || echo "gobuster installation failed, continuing..."

# Install dirsearch (Python-based web path scanner)
RUN git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch \
    && chmod +x /opt/dirsearch/dirsearch.py \
    && ln -sf /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch || echo "dirsearch installation failed, continuing..."

# Copy requirements and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source code
COPY daemons/ /app/daemons/
COPY kage/ /app/kage/
COPY kumo/ /app/kumo/
COPY ryu/ /app/ryu/
COPY artificial_intelligence/ /app/artificial_intelligence/
COPY *.py /app/
COPY __init__.py /app/

# Add project root to Python path
ENV PYTHONPATH=/app

# Set default command (can be overridden in docker-compose)
CMD ["python3", "/app/daemons/kage_daemon.py"]

