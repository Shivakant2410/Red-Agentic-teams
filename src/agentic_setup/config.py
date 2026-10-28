"""Environment loading for local command-line runs."""

from pathlib import Path

from dotenv import load_dotenv


def load_local_environment(project_root: Path | None = None) -> None:
    """Load the project .env without overriding explicit process environment."""
    root = project_root or Path.cwd()
    load_dotenv(root / ".env", override=False)
