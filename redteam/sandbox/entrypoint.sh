#!/usr/bin/env bash
# Sandbox entrypoint: lock down egress to the RoE allowlist, then idle.
#
# Environment:
#   ALLOWED_CIDRS  space-separated list of IPs/CIDRs the sandbox may reach
#   DNS_SERVERS    space-separated resolvers to allow on port 53
#
# The firewall is default-DROP on OUTPUT. If we cannot install the rules, we EXIT
# non-zero rather than run wide open — fail closed.
set -euo pipefail

echo "[sandbox] applying egress allowlist..."

# Requires NET_ADMIN. If iptables isn't usable, refuse to start.
if ! iptables -L >/dev/null 2>&1; then
    echo "[sandbox] FATAL: cannot manage iptables (need --cap-add=NET_ADMIN). Refusing to start." >&2
    exit 90
fi

# Flush and set default policies.
iptables -F OUTPUT
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP

# Loopback + established/related return traffic.
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS to the configured resolvers only (so tools can resolve in-scope names).
for dns in ${DNS_SERVERS:-1.1.1.1}; do
    iptables -A OUTPUT -p udp --dport 53 -d "$dns" -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d "$dns" -j ACCEPT
done

# The scope allowlist.
count=0
for cidr in ${ALLOWED_CIDRS:-}; do
    iptables -A OUTPUT -d "$cidr" -j ACCEPT
    count=$((count + 1))
done
echo "[sandbox] egress locked: ${count} allowed destination(s), default DROP."

if [ "$count" -eq 0 ]; then
    echo "[sandbox] WARNING: no allowed destinations — sandbox has no outbound reach."
fi

# Drop the ability of the operator user to change these rules is enforced by running
# tools as non-root; the host also blocks firewall commands at the kali_exec layer.
echo "[sandbox] ready."
exec sleep infinity
