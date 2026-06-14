# Contributing to ServeX Guard

Thanks for considering a contribution! ServeX Guard follows an
**Issue-first** process to keep the roadmap focused and avoid
wasted effort on both sides.

## Process

1. **Open an Issue first** — describe the bug or feature using
   the appropriate template. This applies to ALL changes,
   including documentation.
2. **Wait for maintainer feedback** — usually within 48 hours.
   The maintainer will label it `approved` if it's a good fit.
3. **Fork and branch** — once approved:
   - `feature/short-description` for new features
   - `fix/short-description` for bug fixes
4. **Develop** — follow the code style guide below.
5. **Submit a PR** referencing the Issue (`Closes #123`).
6. **Review** — CI must pass, 80%+ coverage maintained.
   The maintainer reviews and merges or requests changes.

PRs opened without a prior approved Issue may be closed and
the author asked to open one first. This isn't personal — it
protects the project's direction and avoids contributors
spending time on work that won't be merged.

## Branch strategy

Currently (solo maintainer phase):
```
main           ← protected, production-ready, CI required
feature/xxx    ← new features, merged via PR to main
fix/xxx        ← bug fixes, merged via PR to main
```

A `develop` integration branch will be introduced once the
project has multiple active contributors working in parallel.
Until then, `main` is the single source of truth and every
merge must pass CI.

## Development setup

```bash
git clone https://github.com/YOUR_USERNAME/ServeX-Guard.git
cd ServeX-Guard
pip install -e ".[dev]"
pytest tests/ -v
```

## Code style

- Python 3.10+ type hints everywhere (`str | None`, `list[dict]`)
- Google-style docstrings on all public functions
- `ruff check servexguard/ tests/` must pass with no errors
- New features require tests — minimum 1 test per new public function
- Coverage must stay at or above 80% (`pytest --cov=servexguard --cov-fail-under=80`)
- One feature or fix per PR — keep PRs focused and reviewable

## Good first issues

Look for issues labeled `good first issue` — these are scoped
tasks that don't require deep familiarity with the codebase.

## Reporting security vulnerabilities

Do NOT open a public Issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Questions

- **Issues** — for bugs and approved feature proposals with clear scope
- **Discussions** — for "I want to build X, is this a good idea?"
  or general questions about the project
