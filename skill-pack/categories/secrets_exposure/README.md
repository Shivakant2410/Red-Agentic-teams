# Source, Config & Secret Exposure

**CWE-538, CWE-312, MITRE T1552.001** · 9 skill(s) · folder `categories/secrets_exposure/`

## Skills in this shelf

- `redteam/.git source disclosure chain` (CWE-538)
- `redteam/.env dotenv secrets exposure` (CWE-538)
- `web/.DS_Store mac resource exposure` (CWE-538)
- `web/.svn working-copy wc.db exposure` (CWE-538)
- `web/Backup archive misplacement exposure` (CWE-538)
- `web/JS source map disclosure` (CWE-540)
- `redteam/MinIO bootstrap verify env disclosure` (CWE-200)
- `redteam/Spring Boot actuator heapdump` (CWE-200)
- `redteam/Spring Boot actuator env leak` (CWE-200)

## Technique

World-readable artifacts that hand over the codebase and its credentials: .git reassembly (HEAD + logs/HEAD), dotenv files, VCS metadata (.DS_Store, .svn wc.db), backup archives, source maps, heap/env dumps (actuator heapdump, MinIO bootstrap env).

## Proof design (why it is falsifiable)

Chained structural markers: ref: refs/heads/ + 40-hex commit hashes; dotenv KEY= shapes; SQLite/Bud1 magics; JAVA PROFILE heap magic. Benign 404s fail.

## Bypass variants / escalation ("think more beats level")

- git-dumper-style full reassembly from the exposed .git
- wc.db -> pristine file reconstruction for SVN
- Source-map reverse engineering to original TS/JSX
- Heapdump credential carving (strings + regex over dumps)
- IDE/rsync/temp-file sweep list (.idea/, .ssh/, *.swp, .bak, ~)

## Sources (copied & rewritten into our proof-first DSL)

- projectdiscovery/nuclei-templates — http/exposures/
- danielmiessler/SecLists — discovery file lists
- HackTricks book — .git/.svn exposure

## False positives to rule out

404 SPA fallbacks — the structural marker conditions separate SPA HTML from real artifacts.
