@AGENTS.md

## Commands

```bash
# Install dependencies
pipenv install --dev

# Install pre-commit hooks (run once after clone)
pre-commit install

# Run tests (from repo root)
pytest tests/

# Run black formatter check
black --check -l 119 -t py311 .

# Run mypy
mypy turnpike/

# Start dev server (Flask reloader)
FLASK_ENV=development ./run-server.sh
```

## Pre-commit Hooks

Hooks run automatically on `git commit`: black (line length 119, py311), trailing-whitespace, end-of-file-fixer, debug-statements, mypy. CI re-runs them via GitHub Actions on every PR. Fix all hook failures before pushing.

## CI (Konflux PR Check)

`konflux-pr-check.sh` is what runs in the Konflux/Tekton `turnpike-web` pipeline: it installs deps, runs `black --check`, then `pytest`. Tests must pass from the repo root — nginx builder tests rely on relative `sys.path` appends.

## Notes for Claude Code

- Run `pytest tests/` from the repo root, not a subdirectory.
- `config.py` executes at import time; new required env vars will break test collection unless passed via `create_app(test_config)`.
- Default branch is `master`, not `main`.
