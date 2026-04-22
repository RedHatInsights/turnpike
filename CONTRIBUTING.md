# Contributing to Turnpike

## Getting started

```bash
git clone https://github.com/RedHatInsights/turnpike.git
cd turnpike
pipenv install --dev
pre-commit install
```

## Development workflow

1. Branch from `master`.
2. Make your changes.
3. Run tests: `pytest tests/` (must run from the repo root).
4. Fix any formatting issues: `black -l 119 -t py311 .`
5. Fix any type errors: `mypy turnpike/`
6. Pre-commit hooks run automatically on `git commit` and enforce all of the above.
7. Open a pull request against `master`.

## CI checks

The `turnpike-web` Konflux pipeline runs on every PR and must pass before merging:
- `black --check` (line length 119, Python 3.11 target)
- `pytest tests/`

GitHub Actions additionally run pre-commit hooks, JSON/YAML validation, and a security image scan (Anchore Grype + Syft SBOM) on pushes to `master`.

## Adding a backend route

Adding or modifying a backend route does **not** require a code change. Routes are defined in the `turnpike-routes` ConfigMap in app-interface. See the backend YAML schema in `docs/api-contracts-guidelines.md` and the README for examples.

## Writing a new plugin

Subclass `TurnpikePlugin` (from `turnpike.plugin`) for general policy plugins, or `TurnpikeAuthPlugin` for authentication plugins. Add your class's dotted path to `PLUGIN_CHAIN` or `AUTH_PLUGIN_CHAIN` in the deployment config.

See `docs/testing-guidelines.md` for how to write tests for new plugins, and `docs/security-guidelines.md` for the plugin chain security invariants to follow.

## Dependency management

Dependencies are managed with **pipenv** (`Pipfile` / `Pipfile.lock`). Pin new dependencies to exact versions in `Pipfile`. After updating, run `pipenv lock` and commit both files.

Automated dependency updates are handled by MintMaker and Dependabot. Their PRs are labeled `bot` automatically and use the commit prefix `chore(deps):` — do not merge them manually unless CI is failing.

## Commit style

- Keep commit messages concise and in the imperative mood.
- Dependency bumps: `chore(deps): update <package> to <version>`
- For everything else, describe what changed and why (the "why" matters more than the "what").

## Further reading

- [AGENTS.md](AGENTS.md) — Architecture, conventions, and common pitfalls for this repo
- [docs/testing-guidelines.md](docs/testing-guidelines.md) — Detailed testing conventions
- [docs/security-guidelines.md](docs/security-guidelines.md) — Security rules for plugin development
