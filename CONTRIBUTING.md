# Contributing

## Setup

```bash
uv sync
git config core.hooksPath .githooks   # enables the commit-msg policy hook
```

## Before every commit

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest --cov
```

## Rules

- **Detection changes need evidence:** a unit test, a benign look-alike
  scenario, and an updated `docs/EVALUATION.md` (the `test_scenarios.py` lock
  fails otherwise).
- **No unverified claims:** documentation reports measured results only.
- **Commits:** imperative, scoped subjects (`portscan: report open ports`).
  Commits are authored by humans. AI co-author/attribution trailers are
  rejected by the `commit-msg` hook.
- **Signed commits:** commits on `main` are SSH-signed and show as
  "Verified" on GitHub. Setup: `git config gpg.format ssh`,
  `git config user.signingkey <key.pub>`, `git config commit.gpgsign true`,
  and register the key on GitHub as a *signing* key.
- **Third-party code and data:** keep the original license and attribution.
  Do not commit captures you are not allowed to redistribute.
