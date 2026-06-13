"""
Report generator.

Takes enriched findings and writes:
  - output/enriched_<timestamp>.json   — full machine-readable data
  - output/report_<timestamp>.html     — human-readable scenario report
"""

import json
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

OUTPUT_DIR = Path(__file__).parent / "output"
TEMPLATE_DIR = Path(__file__).parent / "templates"


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _severity_counts(findings: list[dict]) -> dict:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    # Return in severity order, only non-zero
    return {s: counts[s] for s in order if s in counts}


def write_json(enriched: list[dict]) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = _timestamp()
    path = OUTPUT_DIR / f"enriched_{ts}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)
    return path


def write_html(enriched: list[dict]) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = _timestamp()
    path = OUTPUT_DIR / f"report_{ts}.html"

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    tmpl = env.get_template("report.html")

    html = tmpl.render(
        findings=enriched,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        severity_counts=_severity_counts(enriched),
    )
    path.write_text(html, encoding="utf-8")
    return path
