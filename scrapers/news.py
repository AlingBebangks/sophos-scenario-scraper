"""
Security news scraper.

Targets The Hacker News and BleepingComputer search pages to find
real-world breach/incident stories that match a finding's topic.
Returns article title, URL, date, and a short excerpt.
"""

import time
import requests
from bs4 import BeautifulSoup

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
})

_cache: dict[str, list[dict]] = {}

# Search query templates per common finding keyword
_TOPIC_MAP = {
    "any-to-any": "firewall misconfiguration breach",
    "wan": "firewall internet exposure breach",
    "telnet": "telnet credential theft attack",
    "ftp": "ftp data breach plaintext",
    "snmp": "SNMP amplification attack",
    "pptp": "PPTP VPN cracked attack",
    "ssl vpn": "SSL VPN vulnerability exploit",
    "logging": "firewall logging bypass breach",
    "cleartext": "cleartext credentials stolen",
    "weak encryption": "weak encryption VPN attack",
    "psk": "IPSec pre-shared key attack",
    "tls 1.0": "POODLE BEAST TLS exploit",
    "nat": "NAT bypass firewall exploit",
    "admin": "firewall admin interface exploit",
    "certificate": "SSL certificate attack MITM",
}


def _topic_for_finding(title: str) -> str:
    lower = title.lower()
    for key, query in _TOPIC_MAP.items():
        if key in lower:
            return query
    words = title.split()[:3]
    return " ".join(words) + " attack breach"


def _scrape_thehackernews(query: str) -> list[dict]:
    url = f"https://thehackernews.com/search?q={requests.utils.quote(query)}"
    try:
        r = _SESSION.get(url, timeout=15)
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, "lxml")
        articles = []
        for item in soup.select("div.body-post")[:4]:
            title_el = item.select_one("h2.home-title, h2, .story-title")
            link_el = item.select_one("a.story-link, a")
            date_el = item.select_one("span.h-datetime, span.date")
            excerpt_el = item.select_one("div.home-desc, p")

            title = title_el.get_text(strip=True) if title_el else ""
            link = link_el["href"] if link_el and link_el.get("href") else ""
            date = date_el.get_text(strip=True) if date_el else ""
            excerpt = excerpt_el.get_text(" ", strip=True)[:250] if excerpt_el else ""

            if title and link:
                articles.append({
                    "source": "The Hacker News",
                    "title": title,
                    "url": link if link.startswith("http") else f"https://thehackernews.com{link}",
                    "date": date,
                    "excerpt": excerpt,
                })
        return articles
    except Exception:
        return []


def _scrape_bleepingcomputer(query: str) -> list[dict]:
    url = f"https://www.bleepingcomputer.com/search/?q={requests.utils.quote(query)}"
    try:
        r = _SESSION.get(url, timeout=15)
        if r.status_code != 200:
            return []
        soup = BeautifulSoup(r.text, "lxml")
        articles = []
        for item in soup.select("ul.bc-list li, article")[:4]:
            title_el = item.select_one("h4 a, h3 a, a.bc-title")
            date_el = item.select_one("li.bc-news-date, span.date, time")
            excerpt_el = item.select_one("p")

            title = title_el.get_text(strip=True) if title_el else ""
            link = title_el["href"] if title_el and title_el.get("href") else ""
            date = date_el.get_text(strip=True) if date_el else ""
            excerpt = excerpt_el.get_text(" ", strip=True)[:250] if excerpt_el else ""

            if title and link:
                articles.append({
                    "source": "BleepingComputer",
                    "title": title,
                    "url": link if link.startswith("http") else f"https://www.bleepingcomputer.com{link}",
                    "date": date,
                    "excerpt": excerpt,
                })
        return articles
    except Exception:
        return []


def fetch_news(finding_title: str, max_total: int = 2) -> list[dict]:
    """
    Scrape news articles relevant to a finding title.
    Returns up to max_total articles from multiple sources.
    """
    query = _topic_for_finding(finding_title)
    if query in _cache:
        return _cache[query]

    results: list[dict] = []
    results += _scrape_thehackernews(query)
    time.sleep(0.5)
    results += _scrape_bleepingcomputer(query)

    combined = results[:max_total]
    _cache[query] = combined
    return combined
