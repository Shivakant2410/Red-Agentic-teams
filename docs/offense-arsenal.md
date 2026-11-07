# The Offense Arsenal — skills before guards

**Directive behind this doc:** we shipped the guard layer first (cell-card gates, judge
calibration, pin-drift alarms, e-processes, SPRT). That was backwards. A red-team agent
that can't recon a target, map its surface, pick a pre-exploit search, and chain post-exploit
access does not need fancy statistics yet. This doc re-orders the world: **recon → attack
surface mapping → pre-exploitation → post-exploitation**, and only then the guard stack.

Every technique below passes three checks before it earns a place:

1. **Is anyone actually using it?** — named tool or paper with adoption evidence
   (stars, citations, venue, or "it ships in the default pipeline").
2. **Is it required for us?** — a specific module gap in this repo, with file names.
3. **Why this math?** — the exact technique the tool/paper uses, not a generic algorithm.

References at §8 were all opened during research (Nov 2026).

---

## 0. Honest gap audit — what we have vs what offense needs

Measured against the field's standard pipeline (§1). Line counts are from the repo today.

| Skill stage | Field benchmark | Our module | State | Gap |
|---|---|---|---|---|
| Passive recon | Amass: OSINT + CT logs + permutations into an asset graph | `recon/passive.py` (207 ln) | robots/sitemap/OpenAPI only | No DNS/CT/perm layer, output is a list not a graph |
| Content discovery | ffuf/feroxbuster: wordlists + recursion, ordered by empirical frequency | — | missing entirely | No active path discovery, no stopping rule |
| Surface model | Amass Open Asset Model; BloodHound graph DB | `inventory.py` (146 ln), `graph_view.py` | list-like AssetInventory | No edges, no path queries, no centrality |
| Pre-exploit search | EcoFuzz/MOPT (bandit-scheduled fuzzing), TAP (pruned tree search), Rainbow Teaming (MAP-Elites) | `attack_tree.py` (385 ln), `bandit.py` | tree exists but no search loop; bandit exists but feeds nothing offensive | No prune-expand loop, no diversity archive |
| LLM-attack algorithms | GCG (gradient), TAP (tree), Rainbow (QD archive) | `llmred/strategies.py` | static strategy list | The three field-standard search algorithms absent |
| Post-ex chaining | TruffleHog validate+analyze; BloodHound path finding; Caldera failure recovery | `tools/postex.py` (283 ln) | extract/try/prove primitives | No validation, no path finding, no failure recovery loop |
| Stage-level planning | PentestGPT 3-module decomposition; PentestEval stage benchmark | `planner.py` (96 ln) | thin methodology engine | Not stage-decomposed; end-to-end agents fail (31% success, PentestEval) |

**Conclusion:** the skills are the gap, not the statistics. Everything below is chosen to
close these rows, in this order.

---

## 1. The pipeline the field actually runs

Practitioner standard chain (bug bounty / pentest automation, many guides converge on it):
**subfinder → httpx → nuclei → nmap**, wrapped by frameworks (xpfarm and friends), with the
pain points reported by operators: dead-host waste, WAF noise, no dedup against last run,
triage before thinking. Inside AI red teaming the standard search algorithms are TAP,
Rainbow Teaming, and GCG; inside post-ex the standards are TruffleHog (secret chaining),
BloodHound (AD path finding), PMapper (cloud privesc), and MITRE Caldera (adversary
emulation with a failure-recovery layer).

Two structural lessons from the evidence:

- **Every mature tool is graph-first.** Amass (Open Asset Model graph DB), BloodHound
  (Neo4j), PMapper (directed IAM graph). Our inventory is a list. That is the single
  biggest architectural gap.
- **Every mature search is budget-aware and diversity-aware.** EcoFuzz reallocates energy
  by bandit statistics; TAP prunes subtrees that a cheap evaluator says are hopeless;
  Rainbow Teaming keeps a diversity archive so the next probe is different, not just good.
  Our planner is a 96-line methodology loop. Second-biggest gap.

---

## 2. RECON — frequency priors, coverage estimation, and the graph

### 2.1 Frequency-ordered priors (Nmap, SecLists) — **required, build Week 1**

- **Who uses it:** Nmap scans "the most common 1,000 ports" by default — a list ordered by
  empirical frequency of open-ness across the internet; its `-r` flag exists precisely
  because default scan order is randomized for IDS-diversity. Content discovery tools
  (ffuf, feroxbuster) and SecLists are wordlists *ordered by how often real sites contain
  the entry*. This is the industry's oldest deployed prior.
- **Why it matters to us:** `recon/passive.py` probes a static common-path list with no
  notion of ranking. A prior column turns our crawler from "try everything in a file" into
  "spend the request budget where open-ness is likely": `P(path | technology signals)`.
- **Conversion:** add `prior: float` to the discovery wordlists; order the frontier by
  prior × cheap-reachability (host alive, path prefix observed in sitemap/JS). ~80 lines
  in `recon/passive.py` + a data file. This is Nmap's trick applied to web content.

### 2.2 Content discovery with a stopping rule (STADS / coverage extrapolation) — **required, Week 1-2**

- **Who uses it:** STADS (Böhme et al., 2018, "Software Testing as Species Discovery") made
  coverage estimation a *species-discovery* problem with estimators that run **during** the
  campaign; "Extrapolating Coverage Rate in Greybox Fuzzing" (Liyanage et al., 2024, 21+
  citations) extrapolates coverage growth; NDSS Fuzzing Workshop 2026 evaluates estimators
  under coverage feedback. Fuzzers use this to decide when more testing stops paying.
- **Why it matters to us:** our recon has no stopping rule — it either under-crawls or
  burns budget. The same estimator answers our question directly: after n probes with
  u unique paths found (f1 = singletons), the missing-mass estimate is
  `f1/n` (Good–Turing): the probability the *next* probe hits something new. When that
  drops below ε (e.g. 2%), move on. This is a theorem-backed "recon is done" signal we
  currently don't have anywhere.
- **Conversion:** `recon/discovery.py` — track `(n, u, f1)` per host; expose
  `missing_mass()`; stop rule `missing_mass < ε` or budget. Emit it into findings so the
  report can say "surface explored to 98% (est.)". ~120 lines, zero new deps.

### 2.3 Asset graph, not asset list (Amass Open Asset Model) — **required, Week 2**

- **Who uses it:** OWASP Amass v5 stores every discovered asset in a graph-backed asset
  database (Open Asset Model: DNS names, IPs, netblocks, ASNs as nodes, relationships as
  edges) so runs compose and can be diffed over time. This is Amass's defining feature —
  "more than a subdomain enumeration tool".
- **Why it matters to us:** `inventory.py` accumulates objects without relationships; the
  planner cannot ask "which asset sits on the path to the auth endpoints". Chains are the
  product of a red team; chains live in graphs.
- **Conversion:** AssetInventory gains typed edges: `resolves_to`, `serves`, `references`,
  `authenticates_with`, `leaks`. Populate from our existing data (OpenAPI refs already
  parsed in `recon/passive.py`; template hits in `tools/template_search.py`). ~1 day.

---

## 3. ATTACK SURFACE MAPPING — escalation is graph traversal

### 3.1 Shortest-path-to-objective queries (BloodHound, PMapper) — **required, Week 2-3**

- **Who uses it:** BloodHound (SpecterOps) turned AD privilege escalation into a *graph
  traversal problem* — every user/group/ACL is a node/edge in Neo4j and the killer feature
  is shortest-path Cypher queries from any foothold to Domain Admin. PMapper (NCC Group,
  1.6k stars) does the same for AWS: builds a directed graph of IAM principals and answers
  `preset privesc *` queries. Both are default red-team tooling; "attack path analysis" is
  its own product category.
- **Why it matters to us:** we have `attack_tree.py` with `technique_cost()` — the cost
  model for edge weights — but no graph to walk and no query. Adding a cost-weighted
  directed graph over our inventory turns "what do I try next" from vibes into Dijkstra:
  cheapest known path from current foothold to each objective.
- **Conversion:** `AttackGraph` in `graph_view.py`: nodes = assets/credentials/privileges,
  edge = technique with cost from `technique_cost()`; query `cheapest_path(state, goal)`.
  Add betweenness (networkx) as a chokepoint score to rank which asset to capture first.
  ~2 days.

### 3.2 Post-ex relevance (preview)

BloodHound/PMapper prove the same math powers post-ex: lateral movement planning is
shortest paths, again. Building §3.1 first means post-ex inherits it for free (§5.2).

---

## 4. PRE-EXPLOITATION — the three field-standard search algorithms

These are not "extra math": they are the three algorithms every serious LLM-attack
system shipped in the last three years. Our `llmred/` currently uses none of them.

### 4.1 Bandit-scheduled fuzzing (EcoFuzz, MOPT) — **required, Week 2**

- **Who uses it:** EcoFuzz (USENIX Security 2020) models AFL's power schedule as an
  **adversarial multi-armed bandit** and reallocates energy toward seeds whose reward is
  "probability of yielding a new path" — result: **214% of AFL's path coverage with 32%
  fewer test cases**. MOPT (USENIX Security 2019) tunes the mutation-operator distribution
  by particle swarm optimization. This is the most-cited math transfer in fuzzing, and
  fuzzing is the most productive vulnerability-discovery technique there is.
- **Why it matters to us:** we already run a Beta-Bernoulli bandit (`bandit.py`) — but it
  currently routes probing, not attack generation. The EcoFuzz shape maps 1:1 onto our
  arms: which nuclei template family / probe payload family / LLM strategy to spend the
  next request on, with reward = "yielded a finding or new surface". We are the exact
  consumer this paper describes; we just haven't pointed the bandit at discovery.
- **Conversion:** register template/payload families as arms in `bandit.py`; reward =
  new-surface OR confirmed-finding (our `falsify.py` decides confirmation). ~150 lines.

### 4.2 Tree search with pruning (TAP) — **required, Week 3**

- **Who uses it:** TAP — "Tree of Attacks with Pruning" (Mehrotra et al., **NeurIPS 2024**,
  1000+ citations, authors include Anthropic's Kassianik/Nelson and Yaron Singer) is the
  published state of the art for black-box LLM jailbreak generation: an attacker LLM
  iteratively refines candidate prompts in a tree; a cheap evaluator **prunes branches
  unlikely to succeed before they cost target queries**; >80% attack success on GPT-4-Turbo
  and GPT-4o with fewer queries than PAIR. Ships in PyRIT-family tooling and many forks.
- **Why it matters to us:** `attack_tree.py` is a *deterministic reasoning tree* — no
  expand/evaluate/prune loop over LLM-generated attacks. TAP is precisely that loop, and
  pruning is what makes it affordable: our request budget is the scarcest resource.
- **Conversion:** `llmred/tap.py`: expand top-k children per node via mutator LLM;
  score with our judge only when a cheap heuristic (few tokens, on-topic) passes; prune
  below threshold; depth-first with backoff on branches; count queries to the target as
  the cost currency. ~300 lines, reuses `llmred/` judge + multiseed.

### 4.3 Quality-diversity archive (Rainbow Teaming = MAP-Elites) — **required, Week 3-4**

- **Who uses it:** Rainbow Teaming (Meta, **NeurIPS 2024**) casts adversarial prompt
  generation as a **quality-diversity problem**: a MAP-Elites archive indexed by
  (risk category × attack style); each iteration selects a parent, mutates it with an LLM,
  evaluates with a judge, and replaces the cell if better. >90% attack success across
  Llama models; produced transferable prompts against GPT-4o; the archive doubles as a
  synthetic fine-tuning dataset. Applied to cybersecurity and QA domains too.
- **Why it matters to us:** greedy search finds the same class of bug repeatedly; MAP-Elites
  guarantees *coverage of attack styles* — the property our `coverage.py` wants but never
  operationalizes. Our swarm of specialists (`specialists.py`) defines natural archive
  categories already.
- **Conversion:** `llmred/archive.py`: cells = (OWASP class or risk category) × (attack
  style); keep best confirmed finding per cell; selection biased toward *empty* cells.
  This single structure gives diversity with a guarantee, and its archive dump is a
  defensible coverage artifact for reports. ~250 lines.

### 4.4 Gradient search over tokens (GCG) — **optional, behind a capability gate**

- **Who uses it:** GCG (Zou et al. 2023, "Universal and Transferable Adversarial Attacks
  on Aligned Language Models") minimizes cross-entropy of a target response by greedy
  coordinate descent over discrete tokens (top-k gradient candidates, random-batch
  verification). Shipping adoption: promptfoo implements it as a red-team strategy;
  it is the reference name in transfer attacks.
- **Why it matters to us:** it needs **logits** — only available when the target backend is
  open weights. Our `llm/` backends include local/open-weight options, so it's buildable,
  but it is strictly last among the three: black-box methods (TAP, Rainbow) cover closed
  targets, which are our primary case.
- **Conversion:** `llmred/gcg.py` guarded by `target.capabilities.logits`. ~350 lines.
  Defer unless an open-weight engagement lands first.

### 4.5 BOLA/IDOR object enumeration (OWASP API1:2023) — **required, Week 3**

- **Who uses it:** OWASP API Security Top 10 ranks Broken Object Level Authorization
  **#1 (API1:2023)**: exploitability easy, prevalence *widespread*, and — per practitioner
  writeups — most scanners can't detect it; the working method is the 5-request pattern
  (capture request → extract object ID → mint substitute ID → replay as-is → compare).
- **Why it matters to us:** `tools/authsession.py` (263 ln) and `tools/logic.py` (194 ln)
  handle auth and logic probes but never do systematic object-ID substitution with
  two-account verification. This is the highest-yield automated web bug; skipping it is
  malpractice for a web/API red-team agent.
- **Conversion:** `tools/bola.py`: harvest IDs from traffic (`traffic.py`), enumerate
  substitutes (sequential / UUID-near), replay in an isolated session, confirm with
  differential response comparison (our `independent_verify.py` does the second look).
  ~200 lines.

---

## 5. POST-EXPLOITATION — chaining, path-finding, and failure recovery

### 5.1 Secret chaining with validation (TruffleHog) — **required, Week 4**

- **Who uses it:** TruffleHog (Truffle Security; the de-facto standard secret scanner)
  pipeline is explicit: **Discovery → Classification (800+ detector types) → Validation
  (log in to confirm the secret is live) → Analysis (enumerate what the credential can
  access)**. Validation is their differentiator: unverified secrets are noise.
- **Why it matters to us:** `tools/postex.py` extracts secrets and tries them raw
  (`ExtractSecretsTool`, `TryCredentialTool`) — no classification, no structured
  validation, no capability analysis. "Found an AWS key" is a finding; "the key is live
  and can read S3 bucket X" is a *proven* finding, and our `proof.py`/`independent_verify.py`
  standards demand the second.
- **Conversion:** upgrade postex with (a) detector classification table (name→type→probe),
  (b) safe validation probes per type reusing `verify.py`, (c) capability query stubs
  (list-buckets/list-roles) as post-ex skills in `skills.py`. ~250 lines.

### 5.2 Path finding from foothold to objective — **required, Week 4** (inherits §3.1)

- **Who uses it:** BloodHound again — after the foothold, the question "what is the path
  from this shell to Domain Admin" is the same shortest-path query. PMapper's
  `preset privesc *` is the cloud equivalent.
- **Why it matters to us:** once §3.1's AttackGraph exists, post-ex becomes: insert
  foothold node (stolen creds from §5.1 become edges), re-run `cheapest_path`, propose the
  next hop as the planner's recommendation. This closes the recon→pre-ex→post-ex loop on
  one shared data structure. ~150 lines once the graph exists.

### 5.3 Failure recovery loop (Caldera end-to-end emulation) — **required, Week 4**

- **Who uses it:** MITRE Caldera executes ATT&CK Abilities through Agents; the 2026
  end-to-end emulation paper (arXiv 2607.14566) adds a **Failure Recovery Layer**: classify
  failures into four types (syntax_error / dependency_error / missing_env / timeout) by
  regex patterns, then repair with an LLM prompt that includes the *accumulated revision
  history*. Rationale: in attack simulation the same command succeeds or fails on subtle
  environment differences, and early failures cascade.
- **Why it matters to us:** our `tools/postex.py` + `retest.py` have no recovery loop;
  a failed exploit step currently just dies. The Caldera pattern is cheap (regex
  classification + prompt with history) and directly raises step-completion rates.
- **Conversion:** `tools/recovery.py`: classify execution failures (we already stream
  stdout/stderr in `sandbox/`), attach revision history from `memory.py`, propose repair,
  bounded retries. ~180 lines.

### 5.4 Stage-decomposed planning (PentestGPT / PentestEval) — **required, Week 2-3**

- **Who uses it:** PentestGPT (arXiv 2308.06782, 530+ citations, 4.7k stars) attributes
  its gains (+228.6% task completion over raw GPT-3.5) to **three self-interacting modules
  (reasoning / generation / parsing)** that fight context loss through stage decomposition.
  PentestEval (arXiv 2512.14233) benchmarked 9 LLMs across decomposed pentest stages:
  **end-to-end pipelines reach only 31% success** — the field's measurement of how hard
  naive end-to-end planning fails, and why stage-level design wins.
- **Why it matters to us:** `planner.py` (96 ln) is a flat loop; `killchain.py` has stages
  but the planner doesn't drive them as a state machine. Our own live-fire sessions show
  the same failure mode PentestEval measures: the agent re-explores instead of advancing
  stage.
- **Conversion:** planner becomes a stage machine aligned with `killchain.py` stages:
  per-stage goal, per-stage exit test (deterministic where possible), context pack per
  stage (not the whole history). ~1 day. This is the cheapest big win in the whole doc.

---

## 6. What we are NOT building now — the guards are deferred

Explicitly parked until skills A2-A5 ship (per owner directive: offense before guardrails,
policies/boundaries out of scope):

- e-processes / anytime-valid dashboards, SPRT verdicts, CUSUM/BOCPD drift alarms
  (`math-arsenal-2.md` §§3-5) — the math is validated but the skills come first.
- judge calibration upgrades beyond current `judgecalib.py`.
- policy/boundary-framed red-team paper content — not relevant to the build.
- PSRO/CFR game-theoretic planning, Wasserstein DRO (§§12, 14) — later-phase, unchanged.

They are not cancelled; they are behind the skills in the build order.

## 7. Build order (evidence-first, offense-first)

| Week | Build | Closes gap | Evidence anchor |
|---|---|---|---|
| 1 | Frequency priors in content discovery + missing-mass stopping rule (`recon/discovery.py`) | §2.1, §2.2 | Nmap top-1000; STADS 2018; Liyanage 2024 |
| 2 | Asset graph with typed edges (Amass OAM-style); stage-machine planner | §2.3, §5.4 | Amass v5; PentestGPT; PentestEval 31% |
| 3 | AttackGraph cheapest-path + betweenness; bandit-armed template/payload scheduling; BOLA tool | §3.1, §4.1, §4.5 | BloodHound; PMapper; EcoFuzz; OWASP API1 |
| 4 | TAP loop; MAP-Elites archive; postex validation + recovery loop (+ GCG only if open-weight target) | §4.2, §4.3, §5.1, §5.3 | TAP NeurIPS'24; Rainbow Teaming NeurIPS'24; TruffleHog; Caldera E2E |

Weeks 1-4 produce an agent that reconnoiters, maps, searches, and chains. The guard stack
then plugs into a system that has something to guard.

## 8. References (opened Nov 2026)

1. Nmap Network Scanning — Port Selection Data and Strategies (default top-1000, ordering): https://nmap.org/book/performance-port-selection.html
2. STADS: Software Testing as Species Discovery (Böhme, ACM TOSEM 2018; discovery probability = Good–Turing f1/n): https://arxiv.org/abs/1803.02130
3. Extrapolating Coverage Rate in Greybox Fuzzing (Liyanage et al., 2024): https://dl.acm.org/doi/10.1145/3597503.3639198
4. Evaluating Impact of Coverage Feedback on Estimators (NDSS Fuzzing Workshop 2026): https://www.ndss-symposium.org/wp-content/uploads/fuzzing2026-10.pdf
5. Amass — attack surface intelligence, asset DB / Open Asset Model: https://hackviser.com/tactics/tools/amass and OWASP Amass docs
6. BloodHound CE attack-path guide (graph traversal, shortest path to DA): https://hivesecurity.gitlab.io/blog/bloodhound-practical-guide-ad-attack-paths
7. PMapper (NCC Group) — IAM graph + privesc presets: https://github.com/nccgroup/pmapper
8. EcoFuzz: adversarial MAB power schedule (USENIX Sec 2020): https://www.usenix.org/conference/usenixsecurity20/presentation/yue
9. MOPT: mutation scheduling by PSO (USENIX Sec 2019): https://www.usenix.org/conference/usenixsecurity19/presentation/lyu
10. TAP: Tree of Attacks with Pruning (NeurIPS 2024): https://arxiv.org/abs/2312.02119
11. Rainbow Teaming: MAP-Elites for adversarial prompts (NeurIPS 2024): https://arxiv.org/html/2402.16822v1
12. GCG: Universal and Transferable Adversarial Attacks (Zou et al., 2023); promptfoo strategy page: https://www.promptfoo.dev/docs/red-team/strategies/gcg
13. TruffleHog: discovery/classification/validation/analysis pipeline: https://github.com/trufflesecurity/trufflehog
14. OWASP API Security Top 10 (2023) — API1 BOLA: https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization
15. PentestGPT (arXiv 2308.06782; 4.7k stars): https://arxiv.org/abs/2308.06782
16. PentestEval: stage-level pentest benchmark (31% end-to-end success): https://arxiv.org/abs/2512.14233
17. Fully Automated End-to-End Adversary Emulation (Caldera failure-recovery layer): https://arxiv.org/html/2607.14566v1
18. Ghanem et al., Hierarchical RL for automated pentesting of large networks (Journal of Intelligent Information Systems, 2023; 111+ citations): https://link.springer.com/article/10.1007/s10844-022-00738-0
