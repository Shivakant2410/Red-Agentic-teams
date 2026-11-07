# Kubernetes & Cluster Components

**CWE-284, MITRE T1613** · 4 skill(s) · folder `categories/kubernetes/`

## Skills in this shelf

- `redteam/Kubelet read-only PodList API` (CWE-284)
- `infra/Kubernetes API anonymous version disclosure` (CWE-306)
- `infra/Kubelet read-only 10255 metrics` (CWE-306)
- `redteam/etcd unauth key-value read` (CWE-306)

## Technique

Cluster discovery without auth: kubelet 10250 PodList, kubelet 10255 metrics, anonymous kube-apiserver version, etcd key-value read — the T1613 discovery ladder into pod secrets.

## Proof design (why it is falsifiable)

API-shaped responses: kind PodList JSON, # HELP metric families, gitVersion fields, etcd node arrays. 403/ACL responses fail.

## Bypass variants / escalation ("think more beats level")

- kubelet exec/run endpoints (write-tier, only with explicit authorization)
- etcd secrets dump -> service-account token extraction
- PodList -> projected token paths -> cluster-role pivot
- Metrics -> pod names -> port-forward pivots
- Sibling components: cAdvisor, dashboard, CoreDNS metrics

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — Kubernetes pentesting
- projectdiscovery/nuclei-templates — http/misconfiguration/kubernetes/

## False positives to rule out

Read-only port disabled but metrics misrouted — each port is its own skill, no cross-assumption.
