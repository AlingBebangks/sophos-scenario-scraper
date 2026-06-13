"""
MITRE ATT&CK scraper via TAXII 2.1 + caxii fallback to attack.mitre.org HTML.

Fetches technique details, procedure examples (real-world usage), and
mitigations for a given list of ATT&CK technique IDs (e.g. ["T1190", "T1040"]).
"""

import re
import time
import requests
from bs4 import BeautifulSoup

# MITRE ATT&CK TAXII 2.1 public server
TAXII_ROOT = "https://attack-taxii.mitre.org/api/v21"
COLLECTION_ENTERPRISE = "x-mitre-collection--1f5565b5-a0e5-420b-b0a4-6c6a3cd34b18"

_SESSION = requests.Session()
_SESSION.headers.update({
    "Accept": "application/taxii+json;version=2.1",
    "User-Agent": "scenario-scraper/1.0 (security-research)",
})

# In-process cache so repeated lookups for the same technique are free
_cache: dict[str, dict] = {}


def _taxii_objects(technique_id: str) -> list[dict]:
    """Query TAXII for STIX objects matching a technique external_id."""
    url = (
        f"{TAXII_ROOT}/collections/{COLLECTION_ENTERPRISE}/objects/"
        f"?match[external_references.external_id]={technique_id}"
    )
    try:
        r = _SESSION.get(url, timeout=15)
        r.raise_for_status()
        return r.json().get("objects", [])
    except Exception:
        return []


def _html_fallback(technique_id: str) -> dict:
    """
    Scrape attack.mitre.org page for a technique when TAXII returns nothing.
    Returns partial data: description, procedure_examples, mitigations.
    """
    # Handle sub-techniques like T1078.003
    path = technique_id.replace(".", "/")
    url = f"https://attack.mitre.org/techniques/{path}/"
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": "scenario-scraper/1.0"})
        if r.status_code != 200:
            return {}
        soup = BeautifulSoup(r.text, "lxml")

        description = ""
        desc_div = soup.select_one(".description-body")
        if desc_div:
            description = desc_div.get_text(" ", strip=True)

        procedures: list[dict] = []
        proc_table = None
        for h2 in soup.find_all("h2"):
            if "Procedure Examples" in h2.get_text():
                proc_table = h2.find_next("table")
                break
        if proc_table:
            for row in proc_table.select("tbody tr"):
                cells = row.find_all("td")
                if len(cells) >= 3:
                    procedures.append({
                        "actor": cells[0].get_text(strip=True),
                        "name": cells[1].get_text(strip=True),
                        "usage": cells[2].get_text(" ", strip=True),
                    })

        mitigations: list[dict] = []
        mit_table = None
        for h2 in soup.find_all("h2"):
            if "Mitigation" in h2.get_text():
                mit_table = h2.find_next("table")
                break
        if mit_table:
            for row in mit_table.select("tbody tr"):
                cells = row.find_all("td")
                if len(cells) >= 2:
                    mitigations.append({
                        "id": cells[0].get_text(strip=True),
                        "description": cells[1].get_text(" ", strip=True),
                    })

        return {
            "technique_id": technique_id,
            "url": url,
            "description": description[:800],
            "procedure_examples": procedures[:5],
            "mitigations": mitigations[:4],
            "source": "html_scrape",
        }
    except Exception:
        return {}


def fetch_technique(technique_id: str) -> dict:
    """
    Return enrichment data for a single ATT&CK technique ID.
    Tries TAXII first, falls back to HTML scraping.
    """
    technique_id = technique_id.strip().upper()
    if technique_id in _cache:
        return _cache[technique_id]

    result: dict = {
        "technique_id": technique_id,
        "name": "",
        "description": "",
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        "procedure_examples": [],
        "mitigations": [],
        "source": "none",
    }

    objects = _taxii_objects(technique_id)
    technique_obj = next(
        (o for o in objects if o.get("type") == "attack-pattern"), None
    )

    if technique_obj:
        result["name"] = technique_obj.get("name", "")
        result["description"] = technique_obj.get("description", "")[:800]
        result["source"] = "taxii"

        # Procedure examples come from relationship objects linking to attack-pattern
        rel_objects = [o for o in objects if o.get("type") == "relationship"
                       and o.get("relationship_type") == "uses"
                       and o.get("target_ref") == technique_obj.get("id")]
        for rel in rel_objects[:5]:
            src_id = rel.get("source_ref", "")
            src_obj = next((o for o in objects if o.get("id") == src_id), None)
            if src_obj:
                result["procedure_examples"].append({
                    "actor": src_obj.get("name", "Unknown"),
                    "usage": rel.get("description", "")[:300],
                })

        # Mitigations
        mit_rels = [o for o in objects if o.get("type") == "relationship"
                    and o.get("relationship_type") == "mitigates"
                    and o.get("target_ref") == technique_obj.get("id")]
        for rel in mit_rels[:4]:
            mit_obj = next((o for o in objects if o.get("id") == rel.get("source_ref")), None)
            if mit_obj:
                result["mitigations"].append({
                    "id": mit_obj.get("name", ""),
                    "description": rel.get("description", "")[:300],
                })

    # TAXII gave us nothing useful — fall back to HTML
    if not result["name"] or not result["description"]:
        fallback = _html_fallback(technique_id)
        if fallback:
            result.update(fallback)

    _cache[technique_id] = result
    time.sleep(0.3)  # be polite to upstream servers
    return result


def fetch_techniques(technique_ids: list[str]) -> list[dict]:
    """Fetch multiple techniques, deduplicating IDs first."""
    seen: set[str] = set()
    results = []
    for tid in technique_ids:
        tid = tid.strip().upper()
        if tid and tid not in seen:
            seen.add(tid)
            results.append(fetch_technique(tid))
    return results
