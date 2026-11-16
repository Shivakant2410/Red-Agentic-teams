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

# Modern recon set that kali-linux-headless leaves out. nuclei backs our nuclei_scan
# tool (it failed on every call without it). httpx-toolkit is ProjectDiscovery's probe;
# plain `httpx` in this image is the unrelated Python HTTP client. seclists adds ~1.9 GB
# but is the wordlist set every content-discovery tool here expects.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nuclei \
        subfinder \
        katana \
        dnsx \
        naabu \
        httpx-toolkit \
        feroxbuster \
        dirsearch \
        arjun \
        getallurls \
        testssl.sh \
        seclists \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for running tools; firewall setup still needs root via the entrypoint.
# Debian already ships an "operator" group (gid 37), so join it explicitly; no `|| true`,
# a missing user must break the build (every kali_exec runs as this user).
RUN useradd -m -s /bin/bash -g operator operator

# nuclei downloads its templates on first use, which the egress firewall blocks at run
# time (GitHub is never in scope). Fetch them now, into the operator user's home, so
# scans work offline; nuclei_scan passes -duc so it never tries to update mid-run.
RUN su operator -s /bin/bash -c "nuclei -update-templates -silent" \
    && test -n "$(ls -A /home/operator/.local/nuclei-templates)"

# The container runs with no-new-privileges, which refuses to exec any binary carrying
# file capabilities ("Operation not permitted"). Strip them so nmap runs unprivileged
# (TCP connect scans, -sT; SYN/raw scans stay unavailable to the non-root user). Kali's
# /usr/bin/nmap wrapper forces --privileged for non-root, and /etc/profile.d/nmap.sh
# exports NMAP_PRIVILEGED (set at all = privileged), both assuming those caps; replace the
# wrapper with a pass-through and drop the profile script (kali_exec uses `bash -lc`).
RUN setcap -r /usr/lib/nmap/nmap && setcap -r /usr/bin/fping \
    && printf '#!/bin/sh\nexec /usr/lib/nmap/nmap "$@"\n' > /usr/bin/nmap \
    && rm -f /etc/profile.d/nmap.sh

WORKDIR /work
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
# Strip CRLF in case of a Windows checkout made before .gitattributes pinned eol=lf.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
