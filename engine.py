"""
Enrichment engine.

For each finding loaded from the feed file:
  1. Extract ATT&CK technique IDs from references
  2. Fetch technique details + procedure examples from MITRE ATT&CK (TAXII → HTML fallback)
  3. Search NVD for related CVEs
  4. Scrape security news for real-world incident stories

Returns a list of enriched finding dicts ready for report generation.
"""

from feedfile import extract_technique_ids
from scrapers.mitre import fetch_techniques
from scrapers.nvd import enrich_finding as nvd_enrich
from scrapers.news import fetch_news
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn


def enrich(findings: list[dict], verbose: bool = True) -> list[dict]:
    """
    Enrich a list of normalised findings with scenario data.
    Returns enriched copies (originals untouched).
    """
    enriched = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        transient=True,
        disable=not verbose,
    ) as progress:
        task = progress.add_task("Enriching findings...", total=len(findings))

        for finding in findings:
            ef = dict(finding)

            # --- MITRE ATT&CK -------------------------------------------------
            technique_ids = extract_technique_ids(finding)
            ef["mitre_techniques"] = []
            if technique_ids:
                progress.update(task, description=f"[cyan]MITRE: {', '.join(technique_ids)}")
                techniques = fetch_techniques(technique_ids)
                ef["mitre_techniques"] = techniques

            # --- NVD CVEs -----------------------------------------------------
            progress.update(task, description=f"[cyan]NVD: {finding['title'][:40]}")
            ef["cves"] = nvd_enrich(finding["title"])

            # --- News articles ------------------------------------------------
            progress.update(task, description=f"[cyan]News: {finding['title'][:40]}")
            ef["news_articles"] = fetch_news(finding["title"])

            # Build a combined scenario narrative for quick reading
            ef["scenario_summary"] = _build_scenario_summary(ef)

            enriched.append(ef)
            progress.advance(task)

    return enriched


def _build_scenario_summary(ef: dict) -> str:
    """
    Produce a short plain-text scenario paragraph from enriched data.
    Used in both JSON output and HTML report.
    """
    lines = []

    techs = ef.get("mitre_techniques", [])
    if techs:
        names = [f"{t['technique_id']} ({t['name']})" for t in techs if t.get("name")]
        if names:
            lines.append(f"Attack techniques: {', '.join(names)}.")

        # First procedure example
        for t in techs:
            procs = t.get("procedure_examples", [])
            if procs:
                p = procs[0]
                actor = p.get("actor", "Unknown actor")
                usage = p.get("usage", "")
                if usage:
                    lines.append(f"Real-world use: {actor} — {usage[:200]}")
                break

    cves = ef.get("cves", [])
    if cves:
        top = cves[0]
        score_str = f"CVSS {top['cvss_score']} {top['cvss_severity']}" if top.get("cvss_score") else ""
        lines.append(f"Related CVE: {top['cve_id']} {score_str} — {top['description'][:180]}")

    news = ef.get("news_articles", [])
    if news:
        a = news[0]
        lines.append(f"Incident reference: \"{a['title']}\" ({a['source']}, {a['date']}).")

    return " ".join(lines) if lines else "No scenario data retrieved."
