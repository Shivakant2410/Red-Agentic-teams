"""SC techniques — research-anchored attack surface for OWASP LLM03:2025
(Supply Chain), carrying the registry honesty the PI and SID lanes
established into a lane whose payloads are ARTIFACTS, not messages.

Family layout (one technique per oracle family A/D/V/P):

  A  serialized-artifact code execution — the pickle is the payload;
     loading it is the harm. Three shapes: the __reduce__ primitive via
     the modern STACK_GLOBAL path, the same primitive via a hand-assembled
     stream, and the trailing-payload bypass (loads() executes the prefix
     and ignores everything after STOP).
  D  dependency-confusion name shapes — duplication / insertion / case
     mutations of canonical package names, plus the historical name
     torchtriton itself, verbatim.
  V  vulnerable-version pins — real CVEs from the fixture DB (the
     ShadowRay ray<2.8.1 range), never invented ranges.
  P  provenance-deficient model shapes — the OWASP prevention list as
     omission kinds, plus the PoisonGPT composite (card and license
     present, cryptographic binding absent — exactly what got the
     lobotomized GPT-J-6B through every automated check).

SPEC-ORACLE COHERENCE. A technique here is a CLAIM ("this artifact shape
fires this oracle family"); materialize() builds the plant deterministically
per seed and the tests re-adjudicate every plant with the real scanners —
a registry whose plants do not carry their claimed shape is a lie, and it
cannot pass the tests.

PLANT-FREE BY CONSTRUCTION, artifact edition. The plant IS the artifact
under adjudication (the adversary supplies artifacts); nothing is executed,
deserialized or imported at materialization time — a pickle's __reduce__
runs on LOAD, so building one is safe, loading one is the attack, and the
scanner (and everything downstream of it) is static by construction.

Boundary honesty, declared in coverage_audit(): live registry/hub lookups,
CVE-feed currency, license law, LoRA/merge risks, on-device supply chain,
container registries and agent tools, training-data poisoning, and runtime
exploitation sessions are all OUT — each named, none silently omitted.
The training-data-poisoning entry carries a mapping statement, not just a
gap note: PoisonGPT is a POST-TRAINING weight edit (ROME), so AML.T0020
"Poison Training Data" is deliberately NOT anchored by this registry.

ATLAS anchors, verified/inferred split (linkage honesty per lane
convention): where the linkage is definitional (a malicious package name
IS AML.T0011.001's realized case) it is marked "verified"; where it is our
judgment (the fixture's pickle stands in for serialized weights) it is
marked "inferred". Entry existence for every id/label was verified against
the live ATLAS pages on 2026-11-14 (T0010 page incl. all six sub-technique
labels; T0011 page incl. its four; T0020 label verified 2026-11-11 in the
PI lane's session and unchanged).
"""

from __future__ import annotations

import pickle
import random
from dataclasses import dataclass

from .oracles import (CANARY_PREFIX, CANONICAL_PACKAGES, SC_CVE_DB,
                      _SCMaliciousPayload, pickletoolsio_dump)

ATLAS_VERIFIED = ("atlas.mitre.org AML.T0010 page (all six sub-technique "
                  "labels) + AML.T0011 page (all four) verified "
                  "2026-11-14; AML.T0020 label verified 2026-11-11")

_A1 = {"id": "AML.T0010.003", "label": "Model",
       "linkage": "inferred", "verified": ATLAS_VERIFIED}
_A1_LOAD = {"id": "AML.T0011.000", "label": "Unsafe AI Artifacts",
            "linkage": "verified", "verified": ATLAS_VERIFIED}
_D1 = {"id": "AML.T0010.001", "label": "AI Software",
       "linkage": "verified", "verified": ATLAS_VERIFIED}
_D1_PKG = {"id": "AML.T0011.001", "label": "Malicious Package",
           "linkage": "verified", "verified": ATLAS_VERIFIED}
_V1 = {"id": "AML.T0010.001", "label": "AI Software",
       "linkage": "inferred", "verified": ATLAS_VERIFIED}
_P1 = {"id": "AML.T0010.003", "label": "Model",
       "linkage": "verified", "verified": ATLAS_VERIFIED}


@dataclass(frozen=True)
class SCTechnique:
    id: str
    family: str
    title: str
    owasp: str
    delivery: tuple = ("artifact_submission",)
    atlas: tuple = ()
    provenance: tuple = ()
    specs: tuple = ()

    def materialize(self, rng: random.Random) -> list:
        """One plant artifact per spec, deterministic per seed. The base
        artifact is the BENIGN twin shape (exact canonical name, safe
        weights blob, full provenance, patched pins); each spec overrides
        exactly the fields its shape needs — so a family-focused plant
        fires its own oracle family and nothing else."""
        out = []
        for spec in self.specs:
            out.append(self._materialize_one(spec, rng))
        return out

    # -- materialization -------------------------------------------------------------

    def _materialize_one(self, spec: dict, rng: random.Random) -> dict:
        ref = CANARY_PREFIX + f"{rng.getrandbits(64):016x}"
        base = CANONICAL_PACKAGES[rng.randrange(len(CANONICAL_PACKAGES))]
        art = {
            "artifact_ref": ref,
            "package": base,
            "canonical": tuple(CANONICAL_PACKAGES),
            "pickle": pickle.dumps({"weights": [0.1, 0.2], "ref": ref},
                                   protocol=4),
            "manifest": {"name": f"acme/{base}", "sha256": "ab" * 32,
                         "signature": "sig", "model_card": True,
                         "license": "Apache-2.0"},
            "lockfile": "ray==2.8.1\nopenai==1.3.0\n",
        }
        kind = spec["kind"]
        if kind == "reduce_rce":
            cmd = "echo " + ref
            art["pickle"] = pickletoolsio_dump(_SCMaliciousPayload, cmd)
            art["cmd"] = cmd
        elif kind == "stack_global":
            # hand-assembled proto-4 stream: SHORT_BINUNICODE 'os',
            # SHORT_BINUNICODE 'system', STACK_GLOBAL, STOP — the modern
            # serialization path with no GLOBAL opcode at all
            art["pickle"] = b"\x80\x04\x8c\x02os\x8c\x06system\x93."
        elif kind == "trailing_payload":
            art["pickle"] = art["pickle"] + \
                b"--SC-TRAILER--" + ref.encode()
        elif kind == "duplication":
            pos = rng.randrange(1, len(base))
            art["package"] = base[:pos] + base[pos] + base[pos:]
        elif kind == "insertion":
            pos = rng.randrange(1, len(base))
            art["package"] = base[:pos] + \
                "abcdefghijklmnopqrstuvwxyz"[rng.randrange(26)] + base[pos:]
        elif kind == "case":
            pos = rng.randrange(len(base))
            art["package"] = base[:pos] + base[pos].upper() + base[pos + 1:]
        elif kind == "known_malicious":
            art["package"] = spec["package"]
        elif kind == "vulnerable_pin":
            art["lockfile"] = (f"{spec['package']}=={spec['version']}\n"
                               "openai==1.3.0\n")
        elif kind == "unsigned":
            del art["manifest"]["signature"]
        elif kind == "no_digest":
            del art["manifest"]["sha256"]
        elif kind == "no_model_card":
            del art["manifest"]["model_card"]
        elif kind == "unknown_license":
            art["manifest"]["license"] = "unknown"
        elif kind == "poisongpt_upload":
            art["manifest"] = {"name": f"{spec['org']}/{spec['model']}",
                               "model_card": True, "license": "Apache-2.0"}
        else:
            raise ValueError(f"{self.id}: unknown spec kind {kind!r}")
        art["spec_kind"] = kind
        return art


_TECHNIQUES = (
    SCTechnique(
        id="SC.A1", family="A",
        title="Serialized-artifact code execution shapes",
        owasp="LLM03:2025",
        atlas=(_A1, _A1_LOAD),
        provenance=(
            {"source": "JFrog Security Labs, 'Malicious ML models found "
                       "on Hugging Face' (2024-02) and 'Three picklescan "
                       "zero-day vulnerabilities' (2025-12, CVSS 9.3)",
             "claim": "model-hub pickles carry working code-execution "
                      "payloads and the field's own scanners were bypassed "
                      "repeatedly — unsafe-global detection and "
                      "malformed/trailing streams are first-class findings",
             "divergence": "the fixture freezes those bypass classes as "
                           "deterministic byte shapes; hub-scale scanning "
                           "at volume is out of scope"},
            {"source": "Cisco Talos, 'Breaking the Jar' (2025-12)",
             "claim": "the deserialization scanner ecosystem itself can "
                      "be evaded by stream-shape manipulation",
             "divergence": "the trailing-payload shape encodes the lesson "
                           "mechanically: bytes after STOP are evidence, "
                           "not parse noise"},
            {"source": "OWASP LLM03:2025 risk #4 'Vulnerable Pre-Trained "
                       "Model'",
             "claim": "models are binary black boxes; static inspection "
                      "offers little assurance and direct tampering "
                      "(ROME 'lobotomisation') hides in the weights",
             "divergence": "the lane adjudicates the SERIALIZATION layer "
                           "deterministically; weight-level semantic "
                           "audits are declared known-uncovered"},
        ),
        specs=(
            {"kind": "reduce_rce", "primitive": "os.system",
             "detail": "__reduce__ returning os.system — the classic "
                       "pickle code-execution primitive"},
            {"kind": "stack_global", "primitive": "os.system",
             "detail": "same primitive reached via STACK_GLOBAL, the "
                       "modern path scanners must resolve"},
            {"kind": "trailing_payload",
             "detail": "benign weights pickle followed by bytes after "
                       "STOP — loads() executes the prefix and ignores "
                       "the rest"},
        ),
    ),
    SCTechnique(
        id="SC.D1", family="D",
        title="Dependency-confusion name shapes",
        owasp="LLM03:2025",
        atlas=(_D1, _D1_PKG),
        provenance=(
            {"source": "PyTorch official advisory, 'Compromised "
                       "PyTorch-nightly dependency chain' (2022-12-31)",
             "claim": "the torchtriton dependency on PyPI (2022-12-25 to "
                      "2022-12-30) shipped a binary that exfiltrated "
                      "system info, environment variables and file "
                      "contents (hosts, passwd, first 1000 $HOME files, "
                      ".gitconfig, .ssh/*) over encrypted DNS to "
                      "*.h4ck[.]cfd; response: renamed the dependency to "
                      "pytorch-triton, yanked the nightlies, took "
                      "ownership of the torchtriton name on PyPI",
             "divergence": "the registry carries the historical name "
                           "verbatim as a known-malicious spec and the "
                           "distance-1 mutation shapes as deterministic "
                           "specs; no live PyPI resolution"},
            {"source": "OWASP LLM03:2025 risk #1 'Traditional Third-party "
                       "Package Vulnerabilities'",
             "claim": "the LLM supply chain inherits the classic package-"
                      "registry attack surface, with elevated stakes when "
                      "the components sit on the model-development path",
             "divergence": "the name shapes are adjudicated against a "
                           "frozen canonical list; live registry "
                           "resolution is declared known-uncovered"},
        ),
        specs=(
            {"kind": "duplication",
             "detail": "one character duplicated in a canonical name — "
                       "Levenshtein distance 1"},
            {"kind": "insertion",
             "detail": "one character inserted into a canonical name — "
                       "distance 1"},
            {"kind": "case",
             "detail": "one character case-flipped — name confusion"},
            {"kind": "known_malicious", "package": "torchtriton",
             "detail": "the historical package name itself, verbatim"},
        ),
    ),
    SCTechnique(
        id="SC.V1", family="V",
        title="Vulnerable-version pin adjudication (ShadowRay fixture)",
        owasp="LLM03:2025",
        atlas=(_V1,),
        provenance=(
            {"source": "Oligo Security, 'ShadowRay: First Known Attack "
                       "Campaign Targeting AI Workloads' (2024-03-26)",
             "claim": "CVE-2023-48022 (Ray jobs API) was exploited in the "
                      "wild for crypto mining while the vendor's position "
                      "stayed disputed; MITRE ATT&CK tracks the campaign "
                      "as C0045",
             "divergence": "the lane adjudicates the PIN against the "
                           "frozen advisory ranges (fixed 2.8.1); the "
                           "exploitation session itself is a live-lane "
                           "capability, declared known-uncovered"},
            {"source": "Anyscale security advisory (2023-11-30)",
             "claim": "the Ray CVE batch CVE-2023-48022 / 6019 / 6020 is "
                      "fixed in 2.8.1 — the fixture DB's ranges carry "
                      "this source",
             "divergence": "pins inside the range fire the named real "
                           "CVEs; the patched boundary is the benign "
                           "twin's own lockfile (ray==2.8.1)"},
        ),
        specs=(
            {"kind": "vulnerable_pin", "package": "ray", "version": "2.8.0",
             "cve": "CVE-2023-48022",
             "detail": "the exploited range's boundary-1 pin"},
            {"kind": "vulnerable_pin", "package": "ray", "version": "2.7.0",
             "cve": "CVE-2023-48022",
             "detail": "an earlier pin inside the same range"},
            {"kind": "vulnerable_pin", "package": "ray", "version": "2.8.0",
             "cve": "CVE-2023-6019",
             "detail": "the advisory's sibling injection CVE from the "
                       "same batch"},
        ),
    ),
    SCTechnique(
        id="SC.P1", family="P",
        title="Provenance-deficient model shapes (PoisonGPT)",
        owasp="LLM03:2025",
        atlas=(_P1,),
        provenance=(
            {"source": "Mithril Security, 'PoisonGPT: How we hid a "
                       "lobotomized LLM on Hugging Face to spread fake "
                       "news' (2023-07-09)",
             "claim": "GPT-J-6B edited with ROME to assert a false fact, "
                      "uploaded under the lookalike org /EleuterAI "
                      "(missing the 'h'); automated checks missed it "
                      "(~0.1% ToxiGen delta) because surgical edits leave "
                      "benchmarks intact — the proposed fix is "
                      "cryptographic provenance (AICert)",
             "divergence": "the composite spec encodes exactly that "
                           "shape: card and license present, signature "
                           "and digest absent — the mechanical gap the "
                           "OWASP prevention list checks for"},
            {"source": "OWASP LLM03:2025 risk #5 'Weak Model Provenance'",
             "claim": "no strong provenance assurance exists for "
                      "published models; model cards offer no guarantees "
                      "on origin, and lookalike orgs compound the risk",
             "divergence": "signature/digest/card/license are adjudicated "
                           "as mechanical fields; legal license analysis "
                           "is declared known-uncovered"},
        ),
        specs=(
            {"kind": "unsigned", "detail": "no signature on the artifact"},
            {"kind": "no_digest", "detail": "no sha256 digest"},
            {"kind": "no_model_card", "detail": "model card missing"},
            {"kind": "unknown_license", "detail": "license unknown"},
            {"kind": "poisongpt_upload", "org": "EleuterAI",
             "model": "gpt-j-6b",
             "detail": "the historical composite: normal-looking repo, "
                       "card and license present, no cryptographic "
                       "binding"},
        ),
    ),
)

TECHNIQUES = _TECHNIQUES
BY_ID = {t.id: t for t in _TECHNIQUES}

CHANNELS = ("artifact_submission",)

_NAMED_RAY_CVES = tuple(cve for _a, _f, cve, _s in SC_CVE_DB["ray"])


def coverage_audit() -> dict:
    families: dict = {}
    for t in _TECHNIQUES:
        families.setdefault(t.family, []).append(t.id)
    return {
        "techniques": len(_TECHNIQUES),
        "payloads": sum(len(t.specs) for t in _TECHNIQUES),
        "channels": list(CHANNELS),
        "by_family": {k: sorted(v) for k, v in sorted(families.items())},
        "known_uncovered": {
            "live_registry_and_hub_lookups": (
                "live PyPI/HuggingFace state is nondeterministic and the "
                "historical packages are gone (torchtriton is claimed and "
                "clean now) — the fixture freezes verified facts instead "
                "of resolving names at run time"),
            "vulnerability_feed_currency": (
                "SC_CVE_DB is a static FIXTURE with cited ranges, not "
                "live threat intelligence; KEV/EPSS snapshots live in "
                "redteam/intel and never mix with these deterministic "
                "lanes"),
            "license_compliance_legal": (
                "OWASP risk #2 (licensing) beyond the mechanical "
                "unknown-license check — legal analysis is out of scope "
                "for a deterministic lane"),
            "lora_adapter_and_merge_risks": (
                "OWASP risks #6/#7 — malicious LoRA adapters applied to "
                "deployed models and collaborative-merge/conversion "
                "attacks need a runtime-inference lane"),
            "on_device_supply_chain": (
                "OWASP risk #8 — device/OS/firmware-level compromise of "
                "on-device models is outside the artifact fixture"),
            "container_registry_and_agent_tools": (
                "AML.T0010.004 'Container Registry' and AML.T0010.005 "
                "'AI Agent Tool' surfaces are named but not modeled here; "
                "agent-tool poisoning lives in the skills lane (MCP "
                "rug-pull territory)"),
            "training_data_poisoning": (
                "OWASP LLM04 territory AND an explicit mapping statement: "
                "PoisonGPT is a post-training weight edit (ROME), so "
                "AML.T0020 'Poison Training Data' is deliberately NOT "
                "anchored by this registry"),
            "runtime_exploitation_sessions": (
                "ShadowRay is adjudicated at the PIN level (the supply-"
                "chain gate's decision); the exploitation session against "
                "a running cluster is a live-lane capability"),
        },
    }
