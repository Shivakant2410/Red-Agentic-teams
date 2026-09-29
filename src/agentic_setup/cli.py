"""Command-line interface for model discovery, qualification, and routing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .authorization import evaluate_authorization_fixtures
from .benchmark import evaluate_cors_fixture_results, evaluate_local_header_benchmark
from .config import load_local_environment
from .models import ModelCatalog, fetch_catalog
from .local_assessment import Finding, LocalAssessmentAgent, TargetScopeError
from .lab_runner import DockerLabRunner, LabRunnerError
from .openrouter import OpenRouterClient, OpenRouterError
from .qualification import PHASES, QualificationStore
from .router import AllModelsUnavailableError, ModelRouter, NoQualifiedModelsError
from .usage import UsageLimitExceeded, UsageStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-setup",
        description="Discover and route among explicitly qualified free models.",
    )
    parser.add_argument("--state-dir", type=Path, default=Path(".state"))
    commands = parser.add_subparsers(dest="command", required=True)

    models = commands.add_parser("models", help="Discover and manage model records")
    model_commands = models.add_subparsers(dest="models_command", required=True)
    model_commands.add_parser("sync", help="Fetch and cache the OpenRouter text catalog")
    model_commands.add_parser("list", help="List cached free text model candidates")

    qualify = model_commands.add_parser("qualify", help="Record benchmark qualification")
    qualify.add_argument("--model-id", required=True)
    qualify.add_argument("--phase", choices=PHASES, required=True)
    qualify.add_argument("--score", required=True, type=float)
    qualify.add_argument("--run-id", required=True)
    qualify.add_argument("--evaluator-version", required=True)

    complete = commands.add_parser("complete", help="Send a phase-scoped completion")
    complete.add_argument("--phase", choices=PHASES, required=True)
    complete.add_argument("--prompt", required=True)
    complete.add_argument("--max-candidates", type=int, default=3)
    complete.add_argument("--max-tokens", type=int, default=1024)
    agent = commands.add_parser(
        "agent", help="Run the local-only read-only assessment workflow"
    )
    agent_commands = agent.add_subparsers(dest="agent_command", required=True)
    agent_run = agent_commands.add_parser("run", help="Assess a local lab origin")
    agent_run.add_argument(
        "--confirm-local-lab",
        action="store_true",
        help="Confirm assessment of the disposable isolated Docker lab",
    )
    agent_run.add_argument(
        "--use-model",
        action="store_true",
        help="Enable qualified free-model planning, analysis, and report roles",
    )
    agent_run.add_argument(
        "--share-local-evidence",
        action="store_true",
        help="Explicitly allow sending response metadata to OpenRouter",
    )
    agent_run.add_argument("--max-candidates", type=int, default=1)
    commands.add_parser("usage", help="Show local OpenRouter request/token/cost usage")
    benchmark = commands.add_parser("benchmark", help="Run a local synthetic quality benchmark")
    benchmark_commands = benchmark.add_subparsers(dest="benchmark_name", required=True)
    benchmark_commands.add_parser(
        "local-header",
        help="Run synthetic header-posture cases without Docker",
    )
    benchmark_commands.add_parser(
        "local-cors",
        help="Run the safe and intentionally misconfigured disposable CORS labs",
    )
    benchmark_commands.add_parser(
        "local-authz",
        help="Run cross-tenant object-authorization checks in disposable API labs",
    )
    return parser


def main() -> int:
    load_local_environment()
    args = build_parser().parse_args()
    catalog_path = args.state_dir / "catalog.json"
    qualification_path = args.state_dir / "qualified_models.json"
    usage_store = UsageStore(args.state_dir / "usage.sqlite3")

    try:
        if args.command == "usage":
            for period in ("today", "month"):
                summary = usage_store.summary(period)
                print(
                    f"{period.title()} UTC: {summary.requests} requests, "
                    f"{summary.prompt_tokens} prompt tokens, "
                    f"{summary.completion_tokens} completion tokens, "
                    f"${summary.known_cost_usd:.8f} known cost, "
                    f"{summary.unknown_cost_requests} unknown-cost requests"
                )
                for model_id, requests, cost in usage_store.requests_by_model(period):
                    print(f"  {model_id}: {requests} requests, ${cost:.8f}")
            print("Usage includes this application's requests only; check OpenRouter for account-wide totals.")
            return 0
        if args.command == "benchmark" and args.benchmark_name == "local-header":
            metrics = evaluate_local_header_benchmark()
            print(metrics.to_json())
            if metrics.false_positive_rate >= 0.02:
                print(
                    "Benchmark target not met: false-positive rate must be below 2%.",
                    file=sys.stderr,
                )
                return 5
            return 0
        if args.command == "benchmark" and args.benchmark_name == "local-cors":
            runner = DockerLabRunner()
            safe_report = runner.run_assessment(
                LocalAssessmentAgent(),
                cors_profile="safe",
            )
            vulnerable_report = runner.run_assessment(
                LocalAssessmentAgent(),
                cors_profile="reflected-credentials",
            )
            metrics = evaluate_cors_fixture_results(safe_report, vulnerable_report)
            print(metrics.to_json())
            if metrics.false_positive_rate >= 0.02 or metrics.false_negative:
                print("Local CORS fixture benchmark target not met.", file=sys.stderr)
                return 5
            return 0
        if args.command == "benchmark" and args.benchmark_name == "local-authz":
            runner = DockerLabRunner()
            safe_report = runner.run_authorization_assessment("safe")
            vulnerable_report = runner.run_authorization_assessment(
                "broken-owner-check"
            )
            metrics = evaluate_authorization_fixtures(
                safe_report,
                vulnerable_report,
            )
            print(metrics.to_json())
            if metrics.false_positive_rate >= 0.02 or metrics.false_negative:
                print(
                    "Local object-authorization fixture benchmark target not met.",
                    file=sys.stderr,
                )
                return 5
            return 0

        if args.command == "models" and args.models_command == "sync":
            catalog = fetch_catalog()
            catalog.save(catalog_path)
            print(f"Cached {len(catalog.models)} text models ({len(catalog.free_text_models())} free).")
            print(f"Catalog timestamp: {catalog.fetched_at}")
            return 0

        if args.command == "models" and args.models_command == "list":
            catalog = ModelCatalog.load(catalog_path)
            qualifications = QualificationStore(qualification_path)
            qualified_by_id: dict[str, list[str]] = {}
            for record in qualifications.all():
                qualified_by_id.setdefault(record.model_id, []).append(
                    f"{record.phase} (score {record.score:.3f})"
                )
            print(f"Catalog timestamp: {catalog.fetched_at}")
            for model in catalog.free_text_models():
                phases = qualified_by_id.get(model.model_id, [])
                qualification = f"qualified phases: {', '.join(phases)}" if phases else "not qualified"
                print(
                    f"{model.model_id}\tcontext={model.context_length}\t"
                    f"tools={model.supports_tools}\t{qualification}"
                )
            return 0

        if args.command == "models" and args.models_command == "qualify":
            catalog = ModelCatalog.load(catalog_path)
            free_model_ids = {model.model_id for model in catalog.free_text_models()}
            if args.model_id not in free_model_ids:
                raise ValueError(
                    "Model must be present in the cached free-model catalog before qualification"
                )
            store = QualificationStore(qualification_path)
            record = store.add(
                args.model_id,
                args.phase,
                args.score,
                args.run_id,
                args.evaluator_version,
            )
            print(
                f"Recorded {record.model_id} for {record.phase}: "
                f"{record.score:.3f} (run {record.run_id})."
            )
            return 0

        if args.command == "complete":
            catalog = ModelCatalog.load(catalog_path)
            store = QualificationStore(qualification_path)
            router = ModelRouter(
                catalog,
                store,
                usage_store,
                OpenRouterClient(),
                max_candidates=args.max_candidates,
                daily_request_limit=_positive_env_int(
                    "OPENROUTER_DAILY_REQUEST_LIMIT", 50
                ),
                max_output_tokens=_positive_env_int(
                    "OPENROUTER_MAX_OUTPUT_TOKENS", 1024
                ),
            )
            result = router.complete(
                phase=args.phase,
                messages=[{"role": "user", "content": args.prompt}],
                max_tokens=args.max_tokens,
            )
            print(
                json.dumps(
                    {
                        "model": result.completion.model_id,
                        "phase": result.phase,
                        "fallback_count": result.fallback_count,
                        "response_id": result.completion.response_id,
                        "usage": result.completion.usage,
                        "content": result.completion.content,
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "agent" and args.agent_command == "run":
            if not args.confirm_local_lab:
                raise ValueError(
                    "Pass --confirm-local-lab to create and assess the disposable lab"
                )
            if args.use_model and not args.share_local_evidence:
                raise ValueError(
                    "--use-model requires --share-local-evidence because the metadata "
                    "will be sent to an external provider"
                )
            model_summary = None
            model_plan = None
            model_analysis = None
            if args.use_model:
                catalog = ModelCatalog.load(catalog_path)
                store = QualificationStore(qualification_path)
                router = ModelRouter(
                    catalog,
                    store,
                    usage_store,
                    OpenRouterClient(),
                    max_candidates=args.max_candidates,
                    daily_request_limit=_positive_env_int(
                        "OPENROUTER_DAILY_REQUEST_LIMIT", 50
                    ),
                    max_output_tokens=_positive_env_int(
                        "OPENROUTER_MAX_OUTPUT_TOKENS", 1024
                    ),
                )

                def plan(paths: tuple[str, ...]) -> str:
                    result = router.complete(
                        phase="planning",
                        messages=[
                            {
                                "role": "system",
                                "content": (
                                    "Choose a subset of the allowed local read-only GET paths. "
                                    "Return only JSON with keys paths and rationale. "
                                    "Do not invent paths, hosts, commands, or tests."
                                ),
                            },
                            {
                                "role": "user",
                                "content": json.dumps({"allowed_paths": paths}),
                            },
                        ],
                        max_tokens=192,
                    )
                    return result.completion.content

                def summarize(evidence: list[dict[str, object]]) -> str:
                    result = router.complete(
                        phase="reporting",
                        messages=[
                            {
                                "role": "system",
                                "content": (
                                    "Summarize only the supplied local HTTP metadata. "
                                    "Do not suggest exploit steps or claim unverified "
                                    "vulnerabilities. Clearly label uncertainty."
                                ),
                            },
                            {
                                "role": "user",
                                "content": json.dumps(evidence, sort_keys=True),
                            },
                        ],
                        max_tokens=256,
                    )
                    return result.completion.content

                def analyze(
                    evidence: list[dict[str, object]],
                    candidates: tuple[Finding, ...],
                ) -> str:
                    result = router.complete(
                        phase="analysis",
                        messages=[
                            {
                                "role": "system",
                                "content": (
                                    "Review supplied HTTP metadata and candidate check IDs. "
                                    "Return JSON with only supported_check_ids. Select only "
                                    "IDs listed in the candidates. You cannot invent findings."
                                ),
                            },
                            {
                                "role": "user",
                                "content": json.dumps(
                                    {
                                        "evidence": evidence,
                                        "candidates": [
                                            {
                                                "check_id": finding.check_id,
                                                "title": finding.title,
                                                "evidence": finding.evidence,
                                            }
                                            for finding in candidates
                                        ],
                                    },
                                    sort_keys=True,
                                ),
                            },
                        ],
                        max_tokens=256,
                    )
                    return result.completion.content

                model_plan = plan
                model_analysis = analyze
                model_summary = summarize
            report = DockerLabRunner().run_assessment(
                LocalAssessmentAgent(),
                model_summary=model_summary,
                model_plan=model_plan,
                model_analysis=model_analysis,
            )
            print(report.to_json())
            return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, TargetScopeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except (OpenRouterError, NoQualifiedModelsError, AllModelsUnavailableError) as error:
        print(f"Request failed: {error}", file=sys.stderr)
        return 3
    except UsageLimitExceeded as error:
        print(f"Usage limit reached: {error}", file=sys.stderr)
        return 4
    except LabRunnerError as error:
        print(f"Local lab failed: {error}", file=sys.stderr)
        return 6

    return 2


def _positive_env_int(name: str, default: int) -> int:
    import os

    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if parsed < 1:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
