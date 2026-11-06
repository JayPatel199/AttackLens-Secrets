# Severity ranking: how dangerous each finding type is if it's real,
# based on blast radius if the secret were actually exploited.
SEVERITY_MAP = {
    "Private Key Header": "critical",
    "AWS Secret Access Key": "critical",
    "AWS Access Key ID": "high",
    "Credential in URL (connection string)": "high",
    "Generic API Key": "high",
    "Slack Webhook": "medium",
    "Generic Password Assignment": "medium",
    "High-entropy string (possible secret)": "low",
}

def score_finding(finding):
    severity = SEVERITY_MAP.get(finding["type"], "low")
    # A finding still sitting in the working directory (current files) is worse
    # than one that only exists in history, since it's actively exploitable right now.
    location_multiplier = "active" if finding["source"].startswith("working_dir") else "historical"
    return severity, location_multiplier
