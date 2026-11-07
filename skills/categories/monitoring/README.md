# Monitoring Endpoints

**CWE-200** · 2 skill(s) · folder `categories/monitoring/`

## Skills in this shelf

- `elite/Prometheus metrics endpoint exposure` (CWE-200)
- `redteam/Apache mod_status server-status exposed` (CWE-200)

## Technique

Prometheus /metrics and Apache mod_status server-status: metrics/hosts/requests disclosure that maps the internal topology for free.

## Proof design (why it is falsifiable)

Format anchors: # HELP/# TYPE lines and Apache Server Status headers — random HTML fails.

## Bypass variants / escalation ("think more beats level")

- Metric-name harvesting -> upstream hostnames, queues, alert hooks
- mod_status -> per-vhost request lines (session tokens in URLs)
- Sibling: Node exporter, pprof endpoints, Spring actuator/metrics

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/exposures/ (prometheus, apache status)
- HackTricks book — monitoring endpoints

## False positives to rule out

Metrics gated behind auth — status condition handles it.
