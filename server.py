#!/usr/bin/env python3
"""
Scenario Scraper — Web Server (port 3001)

Endpoints:
  GET  /                        Upload UI
  POST /enrich                  Upload findings JSON → start enrichment job
  GET  /status/{token}          Poll job status (JSON)
  GET  /result/{token}/report   View enriched HTML report
  GET  /result/{token}/json     Download enriched JSON
  GET  /health                  Health check
"""

import sys
import uuid
import json
import asyncio
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Optional

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates

import feedfile as ff
import engine as eng
import report as rpt

# ---------------------------------------------------------------------------
app = FastAPI(title="Sophos Scenario Scraper", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Thread pool — enrichment is CPU+IO bound, not async-friendly
_executor = ThreadPoolExecutor(max_workers=2)

# In-memory job store  { token: { status, message, html_path, json_path, created_at } }
_jobs: dict[str, dict] = {}

MAX_UPLOAD_MB = 10


# ---------------------------------------------------------------------------
# Background enrichment task
# ---------------------------------------------------------------------------

def _run_enrichment(token: str, raw_bytes: bytes, skip_nvd: bool, skip_news: bool, skip_mitre: bool) -> None:
    """Runs in a thread. Updates _jobs[token] as it progresses."""
    try:
        _jobs[token]["status"] = "parsing"
        _jobs[token]["message"] = "Parsing findings feed..."

        import io, json as _json
        try:
            data = _json.loads(raw_bytes.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid JSON: {e}")

        # Normalise using feedfile loader logic (accepts dict or list)
        if isinstance(data, list):
            raw_findings = data
        elif isinstance(data, dict):
            raw_findings = data.get("findings") or data.get("results") or data.get("checks") or []
        else:
            raise ValueError("Unexpected JSON structure.")

        if not raw_findings:
            raise ValueError("No findings found in uploaded file.")

        findings = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            findings.append({
                "severity":       item.get("severity", "INFO"),
                "category":       item.get("category", "General"),
                "title":          item.get("title", "Unnamed Finding"),
                "detail":         item.get("detail", ""),
                "recommendation": item.get("recommendation", ""),
                "references":     item.get("references", []),
                "affected_rules": item.get("affected_rules", []),
                "affected_systems": item.get("affected_systems", []),
            })

        _jobs[token]["total"] = len(findings)
        _jobs[token]["status"] = "enriching"

        # Patch scrapers based on skip flags
        if skip_mitre:
            import scrapers.mitre as _m
            _m.fetch_techniques = lambda ids: []
        if skip_nvd:
            import scrapers.nvd as _n
            _n.enrich_finding = lambda title: []
        if skip_news:
            import scrapers.news as _nw
            _nw.fetch_news = lambda title, **kw: []

        enriched = []
        for i, finding in enumerate(findings, 1):
            _jobs[token]["message"] = f"Enriching finding {i}/{len(findings)}: {finding['title'][:45]}"
            _jobs[token]["progress"] = i

            ef = dict(finding)
            technique_ids = ff.extract_technique_ids(finding)
            ef["mitre_techniques"] = eng._fetch_mitre(technique_ids) if not skip_mitre else []
            ef["cves"] = eng._fetch_nvd(finding["title"]) if not skip_nvd else []
            ef["news_articles"] = eng._fetch_news(finding["title"]) if not skip_news else []
            ef["scenario_summary"] = eng._build_scenario_summary(ef)
            enriched.append(ef)

        _jobs[token]["status"] = "writing"
        _jobs[token]["message"] = "Writing output files..."

        json_path = rpt.write_json(enriched)
        html_path = rpt.write_html(enriched)

        _jobs[token]["status"] = "done"
        _jobs[token]["message"] = f"Complete — {len(enriched)} findings enriched."
        _jobs[token]["html_path"] = str(html_path)
        _jobs[token]["json_path"] = str(json_path)
        _jobs[token]["finding_count"] = len(enriched)

    except Exception as e:
        _jobs[token]["status"] = "error"
        _jobs[token]["message"] = str(e)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat()}


@app.get("/", response_class=HTMLResponse)
async def ui(request: Request):
    return templates.TemplateResponse("ui.html", {"request": request})


@app.post("/enrich")
async def enrich(
    request: Request,
    file: UploadFile = File(...),
    skip_nvd: bool = False,
    skip_news: bool = False,
    skip_mitre: bool = False,
):
    content = await file.read()
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {MAX_UPLOAD_MB} MB limit.")
    if not content:
        raise HTTPException(400, "Empty file.")

    token = uuid.uuid4().hex
    _jobs[token] = {
        "status": "queued",
        "message": "Job queued...",
        "progress": 0,
        "total": 0,
        "html_path": None,
        "json_path": None,
        "created_at": datetime.now().isoformat(),
    }

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        _executor,
        _run_enrichment,
        token, content, skip_nvd, skip_news, skip_mitre,
    )

    return JSONResponse({"token": token})


@app.get("/status/{token}")
def status(token: str):
    job = _jobs.get(token)
    if not job:
        raise HTTPException(404, "Job not found.")
    return JSONResponse(job)


@app.get("/result/{token}/report", response_class=HTMLResponse)
def result_html(token: str):
    job = _jobs.get(token)
    if not job:
        raise HTTPException(404, "Job not found.")
    if job["status"] != "done":
        raise HTTPException(425, "Job not complete yet.")
    html_path = Path(job["html_path"])
    if not html_path.exists():
        raise HTTPException(500, "Report file missing.")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/result/{token}/json")
def result_json(token: str):
    job = _jobs.get(token)
    if not job:
        raise HTTPException(404, "Job not found.")
    if job["status"] != "done":
        raise HTTPException(425, "Job not complete yet.")
    json_path = Path(job["json_path"])
    if not json_path.exists():
        raise HTTPException(500, "JSON file missing.")
    return FileResponse(
        path=str(json_path),
        media_type="application/json",
        filename=json_path.name,
    )


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=3001, reload=False)
