"""
NVD (National Vulnerability Database) scraper via the NVD REST API v2.

Searches for CVEs related to a finding by keyword queries derived from
the finding title and MITRE ATT&CK technique IDs.
NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import time
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "scenario-scraper/1.0 (security-research)"})

_cache: dict[str, list[dict]] = {}

# Map common finding keywords to focused NVD keyword queries
_KEYWORD_MAP = {
    "any-to-any": "firewall bypass",
    "cleartext": "cleartext credentials",
    "telnet": "telnet unencrypted",
    "ftp": "ftp plaintext",
    "snmp": "SNMP community string",
    "pptp": "PPTP VPN vulnerability",
    "des": "DES weak encryption",
    "3des": "triple DES vulnerability",
    "md5": "MD5 collision IPSec",
    "sha-1": "SHA-1 collision TLS",
    "logjam": "Diffie-Hellman weak group",
    "psk": "IPSec pre-shared key",
    "logging disabled": "firewall audit log bypass",
    "tls 1.0": "TLS 1.0 POODLE BEAST",
    "ssl vpn": "SSL VPN authentication bypass",
    "wan": "WAN exposure firewall",
}


def _keyword_for_finding(title: str) -> str:
    """Derive a useful NVD keyword query from a finding title."""
    lower = title.lower()
    for key, query in _KEYWORD_MAP.items():
        if key in lower:
            return query
    # Generic fallback: first 4 words of the title
    words = title.split()[:4]
    return " ".join(words)


def search_cves(keyword: str, max_results: int = 5) -> list[dict]:
    """
    Query NVD for CVEs matching keyword.
    Returns simplified list of CVE dicts.
    """
    if keyword in _cache:
        return _cache[keyword]

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
        "startIndex": 0,
        "keywordExactMatch": False,
    }

    try:
        r = _SESSION.get(NVD_API, params=params, timeout=20)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])

        results = []
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})

            # Pull CVSS v3.1 score if available, fall back to v3.0, then v2
            score = None
            severity = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "")
                    break

            results.append({
                "cve_id": cve_id,
                "description": desc[:400],
                "cvss_score": score,
                "cvss_severity": severity,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published", "")[:10],
            })

        _cache[keyword] = results
        time.sleep(6.5)  # NVD rate limit without API key: 5 req/30s → must wait ≥6s
        return results

    except Exception:
        return []


def enrich_finding(finding_title: str) -> list[dict]:
    """Convenience wrapper: derive keyword from title and return CVEs."""
    keyword = _keyword_for_finding(finding_title)
    return search_cves(keyword)
