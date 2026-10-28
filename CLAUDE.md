# CLAUDE.md

Project-level guidance for Claude Code in this repo.

See **[AGENTS.md](AGENTS.md)** for the full codebase map (layout of `redteam/` vs
`src/agentic_setup/`, tools, tests, conventions). Read that first instead of
re-exploring the tree — update it when the structure changes instead of letting it
drift.

## Scope / safety reminders specific to this repo

- This is an **authorized-use** offensive security tool. Never weaken or bypass scope
  enforcement (`redteam/scope.py`, `redteam/sandbox/egress.py`) "to make it work" —
  those are the actual safety boundary, not advisory.
- Don't suggest `--yes-to-all` outside isolated labs.
- `config/engagement.yaml` (gitignored) holds real signed-scope data — never commit it,
  never print its contents into a PR/issue.

## Workflow

- `pytest -q` before considering a change done.
- Prefer editing the narrowly relevant module over broad refactors — this is a small,
  dense codebase (~20k lines across ~90 files); check `AGENTS.md` for which of the two
  packages (`redteam/` vs `src/agentic_setup/`) a task belongs to before searching.
