# CI/CD (Jenkins)

**CWE-668** · 2 skill(s) · folder `categories/ci_cd/`

## Skills in this shelf

- `redteam/Jenkins unauth job enumeration` (CWE-668)
- `redteam/Jenkins script console unauth` (CWE-306)

## Technique

Jenkins unauthenticated API enumeration (jobs tree) and script-console reachability — pipeline and internal-hostname disclosure, then RCE-adjacent staging.

## Proof design (why it is falsifiable)

"jobs" array JSON for enumeration; script-console title/anchor for the console. 403 HTML fails.

## Bypass variants / escalation ("think more beats level")

- jobs enum -> console access on misconfigured agents
- Script console -> Groovy RCE (with explicit authorization)
- Jenkins metadata endpoints (/whoAmI, /unsafe diagnostic endpoints)
- Sibling CI: GitLab runners API, GitHub Actions runner registration

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/exposures/ (jenkins)
- HackTricks book — Jenkins pentesting

## False positives to rule out

Auth-walled consoles — conditions require the anonymous payload to succeed.
