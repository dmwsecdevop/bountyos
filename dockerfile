FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl wget git unzip nmap dnsutils whois ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.7_linux_amd64.zip -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

RUN wget https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_1.6.10_linux_amd64.zip -O /tmp/httpx.zip \
    && unzip /tmp/httpx.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip

RUN wget https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.7_linux_amd64.zip -O /tmp/subfinder.zip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
EXPOSE 8080

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080"]
