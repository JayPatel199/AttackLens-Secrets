# AttackLens Secrets: Git History Secret & Sensitive Data Scanner

Part of a series: [AttackLens](https://github.com/JayPatel199/attacklens) (detection) · [AttackLens Red](https://github.com/JayPatel199/AttackLens-Red) (attack simulation) · [AttackLens Auto](https://github.com/JayPatel199/AttackLens-Auto) (automation) · **AttackLens Secrets** (secure development, this repo)

Scans a codebase and its **full Git commit history**, not just the current files, for leaked secrets: AWS keys, Slack webhooks, private keys, and credentials embedded in connection string URLs. Detects both known patterns (regex) and unknown-but-random-looking strings (entropy analysis), then produces a severity-ranked report distinguishing secrets that are still live in the code from ones that only exist in history.

## Why Git history matters
Deleting a secret from a file does **not** remove it from the project. Every version ever committed remains permanently recoverable with `git log` or `git show`, unless the history itself is rewritten. This tool proves that by scanning a real test case: a password committed, then "fixed" in a later commit, it still shows up as a finding.

## Results at a glance
- Detects 7 categories of secrets: AWS keys, Slack webhooks, private keys, generic passwords, generic API keys, credentials-in-URLs, and high-entropy strings
- Distinguishes **active** (currently in the code) from **historical-only** findings, so triage knows what needs immediate rotation
- SHA-256 fingerprinting lets two findings be compared without ever exposing the real secret value
- Tested against a purpose-built sample repo with a provably recoverable deleted password

## Bugs I found and fixed while building this
Real engineering, not just following steps:
1. **Credentials embedded in URLs were missed entirely.** My first regex only caught `password = "..."` style assignments, not `postgres://user:pass@host` connection strings, a very common real-world leak location. Fixed by adding a dedicated URL-credential pattern.
2. **Redacted matches were indistinguishable from each other.** Truncating to "first 4 + last 4 characters" meant a real secret and its redacted placeholder could show the identical preview, making it impossible to confirm if two findings were the same or different. Fixed by adding a SHA-256 fingerprint to every finding.
3. **GitHub's own push protection blocked early pushes** because the first version of my report stored raw-looking matches. Fixed by redacting all previews before they're ever written to disk, a real lesson in why committing scan output requires the same care as committing code.

## How it works
```mermaid
flowchart LR
    A[Target repo] --> B[Scan working directory]
    A --> C[Scan full git history]
    B --> D[Regex + entropy detection]
    C --> D
    D --> E[Severity scoring + fingerprinting]
    E --> F[HTML report]
```

## Tools used
Python, GitPython, regex, Shannon entropy analysis, SHA-256 fingerprinting, Jinja2.

## How to run it yourself
```bash
git clone https://github.com/JayPatel199/AttackLens-Secrets.git
cd AttackLens-Secrets
pip install gitpython jinja2
python scanner.py /path/to/any/git/repo
python report.py
```

## Limitations
- Entropy-based detection can produce false positives on long random-looking but harmless strings (e.g. hashes, UUIDs already meant to be public)
- Regex patterns cover common secret formats but not every possible credential shape
- This tool flags *candidates* for review; it does not confirm a key is still valid or in active use

Author: Jay Patel
