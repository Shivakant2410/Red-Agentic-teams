# Cloud Object-Store Misconfiguration

**CWE-732, MITRE T1530** · 1 skill(s) · folder `categories/cloud_storage/`

## Skills in this shelf

- `redteam/S3-GCS public bucket listing` (CWE-732)

## Technique

Public bucket listing (ListBucketResult XML with enumerable keys) on S3/GCS shapes.

## Proof design (why it is falsifiable)

Provider-shaped XML with <ListBucketResult> AND <Key> — ACL-denied buckets return AccessDenied XML which fails both.

## Bypass variants / escalation ("think more beats level")

- Key harvesting -> targeted download of .sql/.env/.pem objects
- Bucket policy probing via HEAD on specific keys
- Subdomain/CNAME correlation for takeover-adjacent findings
- GCS signed-URL leakage in logs/referrers

## Sources (copied & rewritten into our proof-first DSL)

- HackTricks book — S3/GCS misconfigurations
- projectdiscovery/nuclei-templates — http/cloud/

## False positives to rule out

ListBucketResult with zero keys — still counts as listing-enabled; keep both conditions.
