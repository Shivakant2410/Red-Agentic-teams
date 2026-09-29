# Kali Rolling sandbox for authorized red-team work.
#
# Ships a broad offensive toolset (kali-linux-headless) plus the pieces our egress
# firewall needs (iptables, ipset, dnsutils). The container starts by locking down
# outbound traffic to the RoE allowlist (see entrypoint.sh), then idles so the host
# can `docker exec` individual tool commands into it.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        kali-linux-headless \
        iptables \
        ipset \
        dnsutils \
        iproute2 \
        ca-certificates \
        curl \
        wget \
        git \
        python3 \
        jq \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for running tools; firewall setup still needs root via the entrypoint.
RUN useradd -m -s /bin/bash operator || true

WORKDIR /work
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
