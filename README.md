### Supply Chain Detector

A lightweight, pluggable scanner that vets npm packages and GitHub repos for supply‑chain risks. It combines static analysis, metadata heuristics, secrets discovery, SBOM and license checks, lockfile/script integrity, and typosquatting signals to produce a unified risk score and report.

- Key features:
  - Static analysis via Semgrep
  - Metadata heuristics (deps, versions, red flags)
  - Secrets scanning (regex + entropy)
  - SBOM generation with basic license policy checks
  - Lockfile and install-script integrity checks
  - Typosquatting and maintainer hygiene signals
  - Reports in Markdown and JSON; CI-friendly exit codes

- Quick start:
  - Install: `pip install semgrep requests urllib3`
  - Scan GitHub: `python main.py github:OWNER/REPO --download --format=both`
  - Scan local: `python main.py path\to\package --format=json`
  - CI gate: `python main.py github:OWNER/REPO --download --format=json --fail-on=4`

- Outputs:
  - Reports saved to `reports/` (`.md` and/or `.json`)
  - Exit code 1 if risk ≥ `--fail-on`, else 0

- Why it’s useful:
  - Catches risky install-time behavior early
  - Surfaces leaked secrets and high-entropy tokens
  - Highlights repo/package hygiene issues
  - Produces actionable, auditable reports for PRs and CI pipelines
