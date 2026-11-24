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

# Non-root user for running tools; firewall setup still needs root via the
# entrypoint. Idempotent: create operator only if absent, and ensure a home dir
# exists either way. Then make /work operator-owned so docker-exec'd tools can
# write output files (nmap -oN, gobuster -o) without hitting a root-owned dir.
# Kali's base image already ships an `operator` *group* (a standard Debian
# system group), so a bare `useradd operator` fails on the group-name clash and
# the user is never created. Reuse that group with -g, and only create the user
# if it is genuinely absent. chown by numeric uid:gid so it works regardless.
RUN id -u operator >/dev/null 2>&1 || useradd -m -s /bin/bash -g operator operator; \
    mkdir -p /home/operator /work; \
    chown -R operator:operator /home/operator /work
WORKDIR /work
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# Strip CR: on a Windows checkout git may give entrypoint.sh CRLF endings, which
# turn the shebang into `/usr/bin/env bash\r` — the container then dies with
# "env: bash\r: No such file or directory" (exit 127), never prints "ready", and
# the host tears the sandbox down. Normalise to LF, then ASSERT no CR remains so
# a stale/mis-cached layer can never ship a broken entrypoint silently.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh \
    && if grep -q $'\r' /usr/local/bin/entrypoint.sh; then \
         echo 'FATAL: entrypoint still has CR after strip' >&2; exit 1; fi \
    && head -1 /usr/local/bin/entrypoint.sh | od -c | head -1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
