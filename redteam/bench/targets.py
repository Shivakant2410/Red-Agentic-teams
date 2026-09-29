"""Known-vulnerable benchmark targets you run locally (and therefore may test).

Each target ships a docker image, a base URL, and a ground-truth vulnerability list. The
ground truth is intentionally small and high-confidence — enough to measure find-rate and
false-positive rate meaningfully without pretending to enumerate every planted bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .scoring import GroundTruthVuln


@dataclass
class BenchTarget:
    name: str
    image: str
    container_port: int
    host_port: int
    base_url: str
    ground_truth: list[GroundTruthVuln] = field(default_factory=list)
    # The red-team scoreboard: what winning looks like on this target.
    objective: dict = field(default_factory=dict)

    def docker_run(self, container_name: str) -> list[str]:
        return ["docker", "run", "-d", "--rm", "--name", container_name,
                "-p", f"{self.host_port}:{self.container_port}", self.image]


JUICE_SHOP = BenchTarget(
    name="OWASP Juice Shop",
    image="bkimminich/juice-shop",
    container_port=3000, host_port=3000,
    base_url="http://localhost:3000",
    ground_truth=[
        GroundTruthVuln("js-sqli-login", "injection", "CWE-89", "/rest/user/login", "critical"),
        GroundTruthVuln("js-idor-basket", "idor", "CWE-639", "/rest/basket/", "high"),
        GroundTruthVuln("js-xss-search", "xss", "CWE-79", "/#/search", "medium"),
        GroundTruthVuln("js-broken-access-admin", "access_control", "CWE-284", "/#/administration", "high"),
        GroundTruthVuln("js-sensitive-ftp", "sensitive_data", "CWE-200", "/ftp", "medium"),
    ],
    objective={
        "name": "Compromise the shop: take over an account and exfiltrate confidential data",
        "description": "Demonstrate an external attacker can authenticate, escalate to "
                       "administrator, and retrieve confidential files from the server.",
        "success_criteria": [
            {"id": "foothold", "kind": "host_access", "target": "app-session",
             "description": "Authenticate as any application user (a valid session token)"},
            {"id": "admin", "kind": "privilege", "target": "admin",
             "description": "Authenticate as the administrator account"},
            {"id": "loot", "kind": "data_access", "target": "confidential-doc",
             "description": "Retrieve the contents of a confidential document from the server"},
        ],
    },
)

DVWA = BenchTarget(
    name="DVWA",
    image="vulnerables/web-dvwa",
    container_port=80, host_port=8081,
    base_url="http://localhost:8081",
    ground_truth=[
        GroundTruthVuln("dvwa-sqli", "injection", "CWE-89", "/vulnerabilities/sqli", "high"),
        GroundTruthVuln("dvwa-xss-reflected", "xss", "CWE-79", "/vulnerabilities/xss_r", "medium"),
        GroundTruthVuln("dvwa-cmd-injection", "injection", "CWE-78", "/vulnerabilities/exec", "critical"),
        GroundTruthVuln("dvwa-file-inclusion", "misconfig", "CWE-98", "/vulnerabilities/fi", "high"),
    ],
)

REGISTRY = {"juice-shop": JUICE_SHOP, "dvwa": DVWA}


def get_target(name: str) -> BenchTarget:
    if name not in REGISTRY:
        raise KeyError(f"unknown benchmark target {name!r}; known: {list(REGISTRY)}")
    return REGISTRY[name]
