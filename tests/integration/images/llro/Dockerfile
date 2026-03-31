FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN python -m pip install --no-cache-dir /app

COPY tests/integration/images/llro/run-llro-test.sh /usr/local/bin/run-llro-test.sh
RUN chmod +x /usr/local/bin/run-llro-test.sh
