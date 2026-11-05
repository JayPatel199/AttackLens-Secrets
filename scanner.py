import os, re, math, json, sys
from collections import Counter
from datetime import datetime, timezone
import git
import hashlib

PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "Generic Password Assignment": r"(?i)(password|passwd|pwd)\s*=\s*['\"]([^'\"]{6,})['\"]",
    "Private Key Header": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Credential in URL (connection string)": r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/]+:[^\s@/]{6,}@[^\s/]+",
    "Generic API Key": r"(?i)(api[_-]?key|secret[_-]?key)\s*=\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
}

def shannon_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

def find_high_entropy_strings(text, min_length=20, threshold=4.3):
    findings = []
    candidates = re.findall(r"['\"]([A-Za-z0-9+/_\-]{%d,})['\"]" % min_length, text)
    for c in candidates:
        e = shannon_entropy(c)
        if e >= threshold:
            findings.append((c, round(e, 2)))
    return findings

def scan_text(text, source_label):
    findings = []
    for name, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text):
            full = match.group(0)
            findings.append({"type": name,
                              "match": full[:4] + "..." + full[-4:] if len(full) > 10 else "[REDACTED]",
                              "fingerprint": hashlib.sha256(full.encode()).hexdigest()[:10],
                              "source": source_label, "method": "regex"})
    for secret, entropy in find_high_entropy_strings(text):
        findings.append({"type": "High-entropy string (possible secret)",
                          "match": secret[:4] + "..." + secret[-4:] if len(secret) > 10 else "[REDACTED]", "entropy": entropy,
                          "source": source_label, "method": "entropy"})
    return findings

def scan_working_directory(repo_path):
    all_findings = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != ".git"]
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    text = f.read()
                all_findings.extend(scan_text(text, f"working_dir:{os.path.relpath(fpath, repo_path)}"))
            except Exception:
                continue
    return all_findings

def scan_git_history(repo_path):
    all_findings = []
    repo = git.Repo(repo_path)
    commits = list(repo.iter_commits("--all"))
    print(f"Scanning {len(commits)} commits in history...")
    for commit in commits:
        try:
            diff_text = repo.git.show(commit.hexsha)
        except Exception:
            continue
        all_findings.extend(scan_text(diff_text, f"commit:{commit.hexsha[:8]} ({commit.message.strip()[:50]})"))
    return all_findings

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/workspaces/test-target-repo"
    print(f"Scanning working directory of {target} ...")
    wd_findings = scan_working_directory(target)
    print(f"Scanning full git history of {target} ...")
    history_findings = scan_git_history(target)

    all_findings = wd_findings + history_findings
    seen = set()
    unique = []
    for f in all_findings:
        key = (f["type"], f["match"], f["source"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    report = {"target": target, "scanned_at": datetime.now(timezone.utc).isoformat(),
              "total_findings": len(unique), "findings": unique}
    with open("results/secrets_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nDone. {len(unique)} potential secrets found.")
    for f in unique:
        extra = f" (entropy {f['entropy']})" if "entropy" in f else ""
        print(f"  [{f['type']}]{extra} in {f['source']}: {f['match']}")
    print("\nSaved to results/secrets_report.json")
