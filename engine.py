"""
Enrichment engine.

For each finding:
  1. Fetch up to 2 MITRE ATT&CK technique details + procedure examples
  2. Fetch up to 2 related CVEs from NVD
  3. Scrape up to 2 real-world incident news articles
  4. Build a use-case narrative — real-world if data exists, theoretical if not
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from feedfile import extract_technique_ids
from scrapers.mitre import fetch_techniques
from scrapers.nvd import enrich_finding as nvd_enrich
from scrapers.news import fetch_news
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn


# ---------------------------------------------------------------------------
# Per-finding fetch helpers — called by both CLI and web server
# ---------------------------------------------------------------------------

def _fetch_mitre(technique_ids: list[str]) -> list[dict]:
    if not technique_ids:
        return []
    return fetch_techniques(technique_ids)


def _fetch_nvd(title: str) -> list[dict]:
    return nvd_enrich(title)


def _fetch_news(title: str) -> list[dict]:
    return fetch_news(title)


# ---------------------------------------------------------------------------
# Theoretical scenario templates
# Keyed by lowercase keywords found in the finding title.
# ---------------------------------------------------------------------------

_THEORETICAL = {
    "any-to-any": (
        "An attacker who gains a foothold on any internal host — via phishing, "
        "drive-by download, or compromised credential — can move laterally to any "
        "other segment without encountering a firewall boundary. Because no zone "
        "separation exists, ransomware or an APT can pivot from a workstation to "
        "domain controllers, OT networks, or backup infrastructure in a single hop, "
        "maximising blast radius with no additional exploitation required."
    ),
    "wan": (
        "An unauthenticated attacker scanning the internet can reach services "
        "that should only be accessible internally. By targeting known CVEs or "
        "weak credentials on exposed services, they establish an initial foothold "
        "without needing to bypass perimeter controls — the firewall rule itself "
        "provides the entry point."
    ),
    "telnet": (
        "An attacker with passive access to the network (e.g., via a compromised "
        "switch or ARP spoofing) captures Telnet sessions in plaintext using tools "
        "like Wireshark or tcpdump. Credentials harvested this way grant direct "
        "administrative access to the target device with no further exploitation needed."
    ),
    "ftp": (
        "FTP transmits credentials and file contents in cleartext. An attacker "
        "performing a man-in-the-middle attack on the same network segment can "
        "silently capture login credentials and exfiltrate or tamper with "
        "transferred files — including configuration backups or sensitive data."
    ),
    "snmp": (
        "An attacker enumerating the network sends SNMP GET requests using the "
        "default 'public' community string. This reveals detailed device topology, "
        "interface configurations, and routing tables — intelligence used to plan "
        "targeted lateral movement or to identify high-value assets for exploitation."
    ),
    "pptp": (
        "An attacker who captures a PPTP VPN handshake (via passive sniffing or "
        "an evil twin access point) can crack MS-CHAPv2 offline using tools such "
        "as Hashcat within hours on commodity hardware. The recovered credentials "
        "then provide full VPN access as a legitimate user, bypassing all "
        "perimeter controls."
    ),
    "ssl vpn": (
        "A remote attacker targets the SSL VPN portal with credential stuffing "
        "using breach-dump username/password pairs. Without MFA, a single valid "
        "credential provides network-level access equivalent to an on-site employee, "
        "enabling lateral movement to internal systems, file shares, and databases."
    ),
    "tls 1.0": (
        "An attacker performing a POODLE or BEAST attack downgrades the TLS "
        "negotiation to SSL 3.0 or TLS 1.0, then decrypts session cookies or "
        "authentication tokens from the VPN stream. This allows session hijacking "
        "without requiring the user's password."
    ),
    "logging": (
        "An attacker who compromises an internal host exfiltrates data or moves "
        "laterally over days without triggering any alerts, because the permitting "
        "firewall rules generate no log entries. Forensic reconstruction after "
        "discovery is impossible — incident responders cannot determine what was "
        "accessed, when, or from where."
    ),
    "des": (
        "An attacker recording encrypted VPN traffic decrypts it offline using "
        "DES or 3DES brute-force on modern GPU hardware. Once decrypted, the "
        "attacker gains access to all data transmitted over the tunnel — including "
        "credentials, internal API calls, and sensitive files — without ever "
        "touching the target network directly."
    ),
    "weak diffie": (
        "An attacker exploiting the Logjam vulnerability downgrades the IPSec "
        "key exchange to a 512-bit DH group and performs a precomputed discrete "
        "logarithm attack to recover session keys. All traffic protected by the "
        "affected tunnel is then decryptable in near real-time."
    ),
    "psk": (
        "An attacker who captures the IKE handshake performs an offline dictionary "
        "or brute-force attack against the pre-shared key. A weak or reused PSK "
        "can be cracked within minutes, compromising every tunnel that shares it "
        "and allowing the attacker to impersonate either VPN endpoint."
    ),
    "nat": (
        "A misconfigured NAT rule exposes an internal service to the internet "
        "under the assumption that NAT provides security by obscurity. An attacker "
        "scanning the public IP discovers the forwarded port and exploits an "
        "unpatched vulnerability on the internal service, bypassing all intended "
        "perimeter controls."
    ),
    "admin": (
        "An attacker who gains access to the management interface — through "
        "credential stuffing, a default password, or a session hijacking attack — "
        "can reconfigure firewall rules, create backdoor VPN accounts, disable "
        "logging, and exfiltrate the entire configuration. Management plane "
        "compromise renders all other security controls ineffective."
    ),
    "certificate": (
        "An attacker performs a man-in-the-middle attack against SSL/TLS sessions "
        "using a fraudulent certificate. If certificate validation is weak or "
        "disabled, clients accept the forged certificate silently, allowing the "
        "attacker to decrypt, read, and re-encrypt all traffic in transit."
    ),
    "disabled": (
        "A disabled deny rule that was intended to block a specific traffic class "
        "allows that traffic to fall through to a more permissive default policy. "
        "An attacker who discovers this gap — through network scanning — can "
        "exploit the unguarded path to reach systems that should be protected."
    ),
}

_GENERIC_THEORETICAL = (
    "This misconfiguration reduces the effective security posture of the firewall "
    "by expanding the attack surface beyond what is operationally necessary. "
    "An attacker who discovers this weakness through reconnaissance — network "
    "scanning, traffic analysis, or configuration exposure — can exploit it to "
    "gain unauthorised access, move laterally, or exfiltrate data with reduced "
    "likelihood of detection. Resolving this finding closes a concrete attack path "
    "that would otherwise require no vulnerability exploitation to abuse."
)


def _theoretical_scenario(finding: dict) -> str:
    """Return a theoretical attack scenario tailored to the finding title."""
    lower = finding.get("title", "").lower() + " " + finding.get("detail", "").lower()
    for keyword, scenario in _THEORETICAL.items():
        if keyword in lower:
            return scenario
    return _GENERIC_THEORETICAL


# ---------------------------------------------------------------------------
# Scenario narrative builder
# ---------------------------------------------------------------------------

def _build_scenario_summary(ef: dict) -> str:
    """
    Build a concise use-case narrative.
    Uses real-world data where available; falls back to theoretical scenario.
    """
    has_real_data = (
        any(t.get("procedure_examples") for t in ef.get("mitre_techniques", []))
        or ef.get("cves")
        or ef.get("news_articles")
    )

    lines = []

    # ATT&CK technique names (always include if present)
    techs = ef.get("mitre_techniques", [])
    if techs:
        names = [f"{t['technique_id']} ({t['name']})" for t in techs if t.get("name")]
        if names:
            lines.append(f"Attack techniques: {', '.join(names)}.")

    if has_real_data:
        # Real-world procedure example (max 1)
        for t in techs:
            procs = t.get("procedure_examples", [])
            if procs:
                p = procs[0]
                actor = p.get("actor", "Unknown threat actor")
                usage = p.get("usage", "")[:250]
                if usage:
                    lines.append(f"Real-world use: {actor} — {usage}")
                break

        # Top CVE (max 1)
        cves = ef.get("cves", [])
        if cves:
            c = cves[0]
            score_str = f"CVSS {c['cvss_score']} {c['cvss_severity']}" if c.get("cvss_score") else ""
            lines.append(f"Related CVE: {c['cve_id']} {score_str} — {c['description'][:180]}")

        # Top news article (max 1)
        news = ef.get("news_articles", [])
        if news:
            a = news[0]
            lines.append(f"Incident reference: \"{a['title']}\" ({a['source']}, {a['date']}).")

    else:
        # No scraped data — use theoretical scenario
        ef["scenario_type"] = "theoretical"
        lines.append("Theoretical scenario: " + _theoretical_scenario(ef))

    ef.setdefault("scenario_type", "real-world" if has_real_data else "theoretical")
    return " ".join(lines) if lines else _theoretical_scenario(ef)


# ---------------------------------------------------------------------------
# Main enrichment loop
# ---------------------------------------------------------------------------

def enrich(findings: list[dict], verbose: bool = True) -> list[dict]:
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

            technique_ids = extract_technique_ids(finding)
            if technique_ids:
                progress.update(task, description=f"[cyan]MITRE: {', '.join(technique_ids)}")
            ef["mitre_techniques"] = _fetch_mitre(technique_ids)

            progress.update(task, description=f"[cyan]NVD: {finding['title'][:40]}")
            ef["cves"] = _fetch_nvd(finding["title"])

            progress.update(task, description=f"[cyan]News: {finding['title'][:40]}")
            ef["news_articles"] = _fetch_news(finding["title"])

            ef["scenario_summary"] = _build_scenario_summary(ef)

            enriched.append(ef)
            progress.advance(task)

    return enriched
