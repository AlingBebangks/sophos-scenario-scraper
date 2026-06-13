#!/usr/bin/env python3
"""
scenario-scraper — CLI entry point

Usage:
    python main.py findings.json
    python main.py findings.json --no-news
    python main.py findings.json --severity CRITICAL HIGH
    python main.py findings.json --out-dir /tmp/reports
    python main.py --demo                  # runs against built-in demo findings

Output (written to ./output/ by default):
    enriched_<timestamp>.json
    report_<timestamp>.html
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table

console = Console()


# ---------------------------------------------------------------------------
# Demo / sample findings so you can test without a real sophos export
# ---------------------------------------------------------------------------
DEMO_FINDINGS = [
    {
        "severity": "CRITICAL",
        "category": "Firewall Rules",
        "title": "Any-to-Any Accept Rules",
        "detail": "Rules accepting traffic from any source to any destination bypass network segmentation.",
        "recommendation": "Replace with least-privilege rules specifying explicit sources, destinations, and services.",
        "references": ["T1190", "TA0008"],
        "affected_rules": ["Rule-01", "Rule-07"],
    },
    {
        "severity": "CRITICAL",
        "category": "VPN",
        "title": "PPTP VPN Enabled — Protocol is Cryptographically Broken",
        "detail": "PPTP uses RC4-40/128 and MS-CHAPv2, both completely broken; handshakes crackable in <24h.",
        "recommendation": "Migrate all PPTP tunnels to IKEv2/IPSec or OpenVPN with AES-256.",
        "references": ["T1040", "T1078"],
        "affected_rules": [],
    },
    {
        "severity": "HIGH",
        "category": "Firewall Rules",
        "title": "Insecure/Legacy Service Protocols",
        "detail": "Firewall rules explicitly permit Telnet, FTP, TFTP, and SNMPv1/v2.",
        "recommendation": "Replace with SSH, SFTP/FTPS, and SNMPv3 with authentication and privacy.",
        "references": ["T1040", "T1557"],
        "affected_rules": ["Rule-03", "Rule-12"],
    },
    {
        "severity": "HIGH",
        "category": "VPN",
        "title": "SSL VPN Allows Deprecated TLS Versions",
        "detail": "TLS 1.0/1.1 and SSL 3.0 are enabled, exposing connections to POODLE, BEAST, and CRIME.",
        "recommendation": "Enforce TLS 1.2 minimum; prefer TLS 1.3.",
        "references": ["T1557"],
        "affected_rules": [],
    },
    {
        "severity": "MEDIUM",
        "category": "Logging",
        "title": "Accept Rules with Logging Disabled",
        "detail": "Traffic permitted by these rules is not logged, making forensic investigation impossible.",
        "recommendation": "Enable logging on all accept rules; forward logs to a central SIEM.",
        "references": ["T1562.008", "T1070"],
        "affected_rules": ["Rule-05", "Rule-09", "Rule-14"],
    },
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Enrich sophos-policy-checker findings with real-world scenario data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("feedfile", nargs="?", help="Path to findings JSON from sophos-policy-checker")
    p.add_argument("--demo", action="store_true", help="Run against built-in demo findings")
    p.add_argument(
        "--severity", nargs="+", metavar="SEV",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Filter to specific severities only",
    )
    p.add_argument("--no-news", action="store_true", help="Skip news article scraping")
    p.add_argument("--no-nvd", action="store_true", help="Skip NVD CVE lookup")
    p.add_argument("--no-mitre", action="store_true", help="Skip MITRE ATT&CK lookup")
    p.add_argument("--out-dir", default=None, help="Override output directory (default: ./output/)")
    p.add_argument("--json-only", action="store_true", help="Write JSON output only, skip HTML")
    p.add_argument("--html-only", action="store_true", help="Write HTML output only, skip JSON")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # --- Load findings -------------------------------------------------------
    if args.demo:
        findings = DEMO_FINDINGS
        console.print("[bold cyan]Running in DEMO mode with built-in findings.[/]")
    elif args.feedfile:
        from feedfile import load_findings
        try:
            findings = load_findings(args.feedfile)
            console.print(f"[green]Loaded {len(findings)} findings from[/] [bold]{args.feedfile}[/]")
        except (FileNotFoundError, ValueError) as e:
            console.print(f"[bold red]Error:[/] {e}")
            sys.exit(1)
    else:
        console.print("[bold red]Error:[/] Provide a feed file path or use --demo.")
        sys.exit(1)

    # --- Filter by severity --------------------------------------------------
    if args.severity:
        findings = [f for f in findings if f.get("severity") in args.severity]
        console.print(f"[yellow]Filtered to {len(findings)} findings ({', '.join(args.severity)})[/]")

    if not findings:
        console.print("[yellow]No findings to process.[/]")
        sys.exit(0)

    # --- Patch engine based on flags -----------------------------------------
    # Monkey-patch scrapers to no-ops if skipped
    if args.no_mitre:
        import scrapers.mitre as _m
        _m.fetch_techniques = lambda ids: []
    if args.no_nvd:
        import scrapers.nvd as _n
        _n.enrich_finding = lambda title: []
    if args.no_news:
        import scrapers.news as _nw
        _nw.fetch_news = lambda title, **kw: []

    # --- Enrich --------------------------------------------------------------
    console.print(f"\n[bold]Enriching [cyan]{len(findings)}[/cyan] findings...[/]")
    from engine import enrich
    enriched = enrich(findings, verbose=True)

    # --- Write outputs -------------------------------------------------------
    import report as rpt

    if args.out_dir:
        rpt.OUTPUT_DIR = Path(args.out_dir)

    paths = []
    if not args.html_only:
        jp = rpt.write_json(enriched)
        paths.append(("JSON", jp))
    if not args.json_only:
        hp = rpt.write_html(enriched)
        paths.append(("HTML", hp))

    # --- Summary table -------------------------------------------------------
    console.print()
    tbl = Table(title="Output Files", show_header=True, header_style="bold cyan")
    tbl.add_column("Type", style="bold")
    tbl.add_column("Path")
    for ftype, fpath in paths:
        tbl.add_row(ftype, str(fpath))
    console.print(tbl)

    # Quick findings summary
    tbl2 = Table(title="Findings Processed", show_header=True, header_style="bold")
    tbl2.add_column("Severity")
    tbl2.add_column("Count", justify="right")
    sev_colors = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green", "INFO": "blue"}
    from collections import Counter
    for sev, cnt in sorted(Counter(f["severity"] for f in enriched).items()):
        color = sev_colors.get(sev, "white")
        tbl2.add_row(f"[{color}]{sev}[/]", str(cnt))
    console.print(tbl2)

    if not args.json_only:
        console.print(f"\n[bold green]Open your report:[/] file://{paths[-1][1].resolve()}")


if __name__ == "__main__":
    main()
