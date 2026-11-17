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
        seclists \
    && rm -rf /var/lib/apt/lists/*

# Requirement-driven tool layer: the egress firewall blocks package downloads
# INSIDE the container (by design), so on-requirement provisioning rebuilds
# the image with EXTRA_TOOLS instead — build traffic runs on the host network,
# outside the RoE boundary, and the layer is cached per toolset.
ARG EXTRA_TOOLS=""
RUN if [ -n "$EXTRA_TOOLS" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends $EXTRA_TOOLS \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# Non-root user for running tools; firewall setup still needs root via the entrypoint.
RUN useradd -m -s /bin/bash operator || true

WORKDIR /work
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
