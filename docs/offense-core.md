# Offense-core — the product is the attack, the guard is plumbing

Status: positioning correction, Nov 2026. Preceded by `offense-arsenal.md` (the
skills-first build order) and `ROADMAP.md` (Gen-2 history). This document settles
what the product IS, module by module, and why that changed.

## 1. The problem, stated with evidence

We say "red-team agentic system" and ship a document set that reads like an agent
platform with a conscience:

- The README's second section is literally titled *How "give it all of Kali" stays
  safe*. The attack has to wait until section "Learned technique selection" — page
  three of its own README — to learn what the product does to a target.
- The layout block lists `config.py`, `scope.py`, `ratelimit.py`, `audit.py` before
  any attack capability. Hygiene opens the inventory.
- ROADMAP's "where the project already leads" claims five differentiators: scope
  firewall, proof-first pipeline, fail-safe degradation, auditability,
  cross-run learning. Four of five are reliability features. A generic LLM agent
  framework could ship the same list.
- Meanwhile the genuinely offensive code — frequency-prior content discovery with a
  missing-mass stop rule (`recon/discovery.py`), the competitive-intel asset radar
  (`recon/assetgraph.py` + `tools/asset_radar.py`), the bandit-armed attack tree,
  the swarm chain recon→exploit→verify→access→logic — is presented as platform
  features, not as the product itself.
- The phase branches merged to main (B1–C1) read as defensive phases in their own
  names: "detection scheduler", "OPSEC eval". No document reframes them as what
  they actually are: instruments of offensive tradecraft (§3).

A buyer reading our materials cannot tell whether they are getting an autonomous
attacker or a well-guarded chatbot. That ambiguity is the genericness the product
keeps being accused of.

## 2. The honest inventory

Every module in `redteam/`, classified. Three tiers:

**OFFENSE-CORE** — if you deleted it, the system would stop being able to attack.

| Module | Attack function |
|---|---|
| `recon/discovery.py` | Frequency-prior content discovery; STADS missing-mass stop rule decides when the dir/page hunt is done |
| `recon/assetgraph.py` + `tools/asset_radar.py` | Typed-edge asset graph answering one question first: what is this org building that it hasn't announced (CT freshness diffing, codename triangulation, version-ahead-of-live, flag leaks, staging mirrors) |
| `recon/passive.py`, `recon/static_source.py` | Passive and source-recon collection feeding the radar |
| `attack_tree.py` + `bandit.py` | Technique selection with learned per-endpoint-shape win rates (Thompson sampling) |
| `orchestrator.py`, `killchain.py` | The swarm chain: recon → exploit → verify → access → logic |
| `agent.py`, `run.py`, `cli.py` | The tool-use loop and the run assembly line the attack executes through |
| `tools/kali.py` | `kali_exec` — the full Kali offensive toolset (nmap, ffuf, sqlmap, gobuster, nuclei, …) |
| `tools/nuclei.py`, `tools/template_search.py` | Template-driven vuln scanning as leads into the proof pipeline |
| `tools/spa_recon.py` | Login-gated SPA surface extraction (the ARTEX champion technique) |
| `tools/jwt.py`, `tools/authsession.py`, `tools/logic.py` | JWT checklist, session/auth probing, business-logic attacks |
| `tools/postex.py` | Post-exploitation step library |
| `tools/browser.py`, `tools/http.py`, `tools/discovery.py`, `tools/asset_radar.py` | Execution surfaces the attacks run through |
| `llmred/` | LLM-target attack campaigns: strategies, multiseed, objectives, detectors, regression |
| `findings.py`, `verify.py`, `falsify.py`, `credit.py`, `proof.py` | Proof pipeline — the offensive evidence discipline: nothing counts until independently confirmed on the wire |
| `access.py`, `capabilities.py`, `objective.py` | Access holding, capability accounting, objective scoring |
| `inventory.py`, `tools/surface.py` | Attack-surface map the attack plans against |
| `intel/` (EPSS, KEV snapshots) | Exploit prioritization from real-world exploitation data |

**OFFENSE-ENABLING** — tradecraft amplifiers; the attack degrades without them but
still exists.

| Module | Amplification |
|---|---|
| `memory.py`, `memory_backend/` | Cross-run attack playbook: which CWE classes proved out, which oracles work, app-shape patterns |
| `reflection.py` | Strategist re-ranks the attack tree between rounds |
| `skills.py`, `specialists.py`, `tools/skill_tools.py` | Distilled technique packs and the specialist swarm |
| `priors.py`, `knowledge.py` | Corroborated per-node knowledge, technique priors |
| `toolfuzz.py` | Tool-argument robustness for the agent's own weapons |
| `importers/assets.py` | RoE-intersection asset feed seeding the radar |
| `traffic.py`, `graph_view.py` | Wire evidence and the layered attack graph (asset→endpoint→access→finding) |
| `llm/` (gateway, providers, openrouter) | Model transport with failover |
| `memory_backend/app_patterns.py` | Endpoint-shape vocabulary the bandit's context shares |

**HYGIENE** — containment, observability, transport. Necessary, deployable, and
NOT the identity. These exist so real teams can run the product; none of them
would be a reason to choose it.

`scope.py`, `sandbox/` (egress firewall), `ratelimit.py`, `audit.py`, approval
gates, `pinning.py`, `swarmguard.py`, `secrets.py`, `events.py`, `server.py`,
`dashboard/`, `config.py`, `session.py`, `proxy.py`, `parsers.py`, `report.py`,
`retest.py`, `bench/`, `coverage.py`, `stats.py`, `judgecalib.py`, `cellcard.py`,
`selfprobe.py`.

## 3. Reframe: B1–C1 are offense instruments, not safety phases

The phase branches merged to main carry defensive-sounding names and offensive
substance. When main merges into this branch, these modules enter the offense-core
tier under their real function:

| Phase | Defensive reading (wrong) | Offensive function (correct) |
|---|---|---|
| B1 agentic adapter | "tool harness" | Verdicts measure real tool invocation — the attack is graded on what it actually executed |
| B2 dynamics layer | "formal methods" | Formal adversary models as *measuring instruments* for attack behavior |
| B3 detection-belief filter | "defender scheduler" | The red team's POMDP model of the defender: plan moves by detection risk — evasion tradecraft, quantified |
| B4 OPSEC eval | "compliance harness" | Grades the agent's own tradecraft: dwell without tripping alarms, attributed per decision |
| B5 strategy memory | "config store" | Campaign-level attack directives with TTLs — the playbook that survives across engagements |
| C1 collective intelligence | "moderation layer" | Swarm attack coordination: hypothesis registry = shared target hypotheses, research forum = peer review of exploit ideas, event replay = attack forensics |

The reframing is not spin — each of these was built to make the attack better, and
the phase names hid it. The guard-adjacent subsystems inside them (quarantine,
integrity) remain hygiene-tier plumbing.

## 4. What stays non-negotiable, and why that isn't softness

Authorization-first stays: the RoE intersection, the egress firewall, the approval
gates, the append-only audit. This is not a concession; it is what separates a
deployable offensive product from malware. Cobalt Strike ships a license
agreement, Commando ships an authorized-targets check, and every serious red-team
platform gates execution on engagement terms — that gating is industry-standard
*tradecraft hygiene*, not the product thesis. What changes is only the billing:
the guard moves below the attack in every document, and stops being marketed as a
differentiator. The attack capability is the differentiator.

## 5. Concrete changes this correction makes

1. **README** — leads with what the agent does to a target (§ the attack story);
   containment moves to a plumbing section titled for what it is.
2. **ROADMAP** — "where the project already leads" now leads with attack
   differentiators (recon with a stop rule, competitive-intel radar, proof-first
   exploitation, compounding learning); containment appears as an enabler note.
3. **Build order** — `offense-arsenal.md` §7 remains the only roadmap that counts
   until the offensive gap list is closed. Week 1 (recon: priors, stop rule,
   radar) is shipped; Week 2 is stage-machine planning + asset-graph consumers
   (cheapest-path over the radar's typed edges).
4. **Merge discipline** — main (B1–C1) merges into this branch as offense
   instruments per §3; any future phase that cannot state its offensive function
   in one sentence does not enter the roadmap.
5. **Docs voice rule** — no document opens with containment. If a section exists
   to limit the attack, it sits after the section that describes the attack.
