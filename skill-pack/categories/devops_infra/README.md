# DevOps & Service APIs (Docker/HashiCorp/Registry)

**CWE-284, CWE-668** · 6 skill(s) · folder `categories/devops_infra/`

## Skills in this shelf

- `redteam/Docker daemon API unauthenticated` (CWE-668)
- `infra/Docker Registry v2 catalog unauth` (CWE-668)
- `infra/Portainer API unauth status` (CWE-200)
- `infra/Consul agent members unauth API` (CWE-306)
- `infra/Nomad API unauth jobs list` (CWE-306)
- `infra/Vault sys/health unauth disclosure` (CWE-200)

## Technique

Unauthenticated service APIs: Docker daemon (equal to host root), Docker Registry catalog, Portainer, Consul members, Nomad jobs, Vault health — infrastructure-map primitives.

## Proof design (why it is falsifiable)

Product-specific JSON shapes (Platform.Name, repositories[], X-Nomad-Index headers, initialized/sealed flags) — ACL-blocked responses lack them.

## Bypass variants / escalation ("think more beats level")

- Docker daemon -> -v /:/host container escape (with authorization)
- Registry catalog -> image manifest pull -> secret layer carving
- Nomad/Consul -> job/service topology for lateral planning
- Vault health -> seal status decides brute vs pivot
- Sibling APIs: Kubernetes dashboard, Portainer tunnels, Nitro/Enclave helpers

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/misconfiguration/, http/technologies/
- HackTricks book — Docker/Consul/Nomad/Vault pentesting

## False positives to rule out

Health endpoints intentionally public — report as exposure with context, conditions stay exact.
