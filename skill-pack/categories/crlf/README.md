# CRLF / HTTP Response Header Injection

**CWE-113** · 1 skill(s) · folder `categories/crlf/`

## Skills in this shelf

- `web/CRLF response-header injection` (CWE-113)

## Technique

%0d%0a inside a reflected path splits a fresh header into the response — the gateway primitive behind cache poisoning, session fixation via injected Set-Cookie, and XSS via injected headers.

## Proof design (why it is falsifiable)

header_regex finds the injected X-Crlproof header; benign path cannot add it.

## Bypass variants / escalation ("think more beats level")

- Set-Cookie injection for session fixation
- Response-splitting into a full second response (XSS body)
- Header injection in redirect Locations and download filenames
- Client-side CRLF via window.open/location payloads

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — CRLF Injection
- HackTricks book — HTTP header injection

## False positives to rule out

Proxies that strip/normalize the split — negative control on the same gateway catches this.
