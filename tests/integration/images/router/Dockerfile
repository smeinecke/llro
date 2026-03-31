FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iptables iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY tests/integration/images/router/run-router.sh /usr/local/bin/run-router.sh
RUN chmod +x /usr/local/bin/run-router.sh
