"""
Feed file loader.

Reads the JSON output produced by the sophos-policy-checker and normalises
it into a flat list of finding dicts that the enrichment engine can consume.

Expected input format (sophos-policy-checker /analyze response body):
{
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "Firewall Rules",
      "title": "Any-to-Any Accept Rules",
      "detail": "...",
      "recommendation": "...",
      "references": ["T1190", "TA0008"],
      "affected_rules": ["Rule-01", ...],
      "scores": {...}
    },
    ...
  ],
  "summary": { ... }
}

You can also feed a plain list of findings at the top level.

Usage:
    from feedfile import load_findings
    findings = load_findings("findings.json")
"""

import json
from pathlib import Path


def load_findings(path: str) -> list[dict]:
    """
    Load findings from a JSON file produced by sophos-policy-checker.
    Returns a normalised list of finding dicts.
    Raises FileNotFoundError or ValueError for bad input.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Feed file not found: {path}")

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # Accept both {"findings": [...]} and bare [...]
    if isinstance(data, list):
        raw = data
    elif isinstance(data, dict):
        raw = data.get("findings", [])
        if not raw:
            # Some versions nest under a different key
            for key in ("results", "checks", "audit"):
                if key in data:
                    raw = data[key]
                    break
    else:
        raise ValueError("Unexpected JSON structure in feed file.")

    if not raw:
        raise ValueError("No findings found in feed file.")

    normalised = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        normalised.append({
            "severity":       item.get("severity", "INFO"),
            "category":       item.get("category", "General"),
            "title":          item.get("title", "Unnamed Finding"),
            "detail":         item.get("detail", ""),
            "recommendation": item.get("recommendation", ""),
            # references can be ATT&CK IDs like "T1190" or plain text refs
            "references":     item.get("references", []),
            "affected_rules": item.get("affected_rules", []),
            "affected_systems": item.get("affected_systems", []),
        })

    return normalised


def extract_technique_ids(finding: dict) -> list[str]:
    """
    Extract ATT&CK technique IDs (T#### or TA####) from a finding's references list.
    """
    import re
    pattern = re.compile(r"\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b", re.IGNORECASE)
    ids = []
    for ref in finding.get("references", []):
        matches = pattern.findall(str(ref))
        ids.extend(m.upper() for m in matches)
    return list(dict.fromkeys(ids))  # deduplicate, preserve order
