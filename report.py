"""
Report generator.

Takes enriched findings and writes:
  - output/enriched_<timestamp>.json   — full machine-readable data
  - output/report_<timestamp>.html     — human-readable scenario report
  - output/report_<timestamp>.pdf      — PDF export of the HTML report
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


def _render_html(enriched: list[dict]) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    tmpl = env.get_template("report.html")
    return tmpl.render(
        findings=enriched,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        severity_counts=_severity_counts(enriched),
    )


def write_html(enriched: list[dict]) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts = _timestamp()
    path = OUTPUT_DIR / f"report_{ts}.html"
    path.write_text(_render_html(enriched), encoding="utf-8")
    return path


def write_pdf(enriched: list[dict], html_path: Path | None = None) -> Path:
    """
    Convert the enriched HTML report to PDF using WeasyPrint.
    If html_path is given it reads from that file; otherwise renders fresh.
    Returns path to the written PDF.
    """
    from weasyprint import HTML, CSS

    OUTPUT_DIR.mkdir(exist_ok=True)

    if html_path and html_path.exists():
        html_string = html_path.read_text(encoding="utf-8")
        base_url = str(html_path.parent)
    else:
        html_string = _render_html(enriched)
        base_url = str(OUTPUT_DIR)

    # Inject print-friendly overrides: white background, dark text
    print_css = CSS(string="""
        @page { margin: 15mm 12mm; size: A4; }
        body { background: #fff !important; color: #111 !important; font-size: 11px; }
        header { background: #1a2340 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .finding-card { border: 1px solid #ccc !important; background: #fafafa !important; break-inside: avoid; }
        .card-header { background: #f0f0f0 !important; }
        .technique-item, .news-item { background: #f5f5f5 !important; }
        .sev-CRITICAL { background: #c0392b !important; color: #fff !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .sev-HIGH     { background: #e67e22 !important; color: #fff !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .sev-MEDIUM   { background: #f1c40f !important; color: #000 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .sev-LOW      { background: #27ae60 !important; color: #fff !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .sev-INFO     { background: #2980b9 !important; color: #fff !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        a { color: #1a5fbc !important; }
        p.detail, p.scenario, .technique-desc, .proc-item, .news-excerpt, table.cve-table td { color: #333 !important; }
        .section-label { color: #1a5fbc !important; }
        .card-header h2, .technique-name { color: #111 !important; }
        .category, .muted, .news-meta, .job-token { color: #555 !important; }
        footer { color: #777 !important; border-top: 1px solid #ccc !important; }
    """)

    # Derive PDF path from html_path timestamp if available
    if html_path:
        pdf_path = html_path.with_suffix(".pdf")
    else:
        pdf_path = OUTPUT_DIR / f"report_{_timestamp()}.pdf"

    HTML(string=html_string, base_url=base_url).write_pdf(
        pdf_path, stylesheets=[print_css]
    )
    return pdf_path
