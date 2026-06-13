# scenario-scraper

Enriches **sophos-policy-checker** audit findings with real-world attack scenarios sourced from:

| Source | What it provides |
|--------|-----------------|
| MITRE ATT&CK (TAXII 2.1) | Technique details, procedure examples (real threat actor usage), mitigations |
| NVD API v2 | Related CVEs with CVSS scores |
| The Hacker News / BleepingComputer | Breach/incident articles matching each finding |

Output is a standalone **HTML report** + **JSON file** you can review independently of the main checker.

---

## Setup (Kali Linux)

```bash
cd ~/AIVAPT/scenario-scraper
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Option 1 — Feed it your actual sophos-policy-checker findings

Export findings from the checker as JSON, then:

```bash
python main.py /path/to/findings.json
```

The checker's `/analyze` endpoint returns a JSON body — save it:

```bash
curl -s -X POST http://localhost:8000/analyze \
     -F "file=@your_sophos_config.xml" \
     | python3 -c "import sys,json; d=json.load(sys.stdin); json.dump(d,open('findings.json','w'),indent=2)"

python main.py findings.json
```

### Option 2 — Use the included sample feed file

```bash
python main.py sample_findings.json
```

### Option 3 — Demo mode (no file needed)

```bash
python main.py --demo
```

---

## Flags

| Flag | Effect |
|------|--------|
| `--severity CRITICAL HIGH` | Only enrich findings at these severity levels |
| `--no-news` | Skip The Hacker News / BleepingComputer scraping |
| `--no-nvd` | Skip NVD CVE lookup |
| `--no-mitre` | Skip MITRE ATT&CK lookup |
| `--json-only` | Write JSON output only |
| `--html-only` | Write HTML report only |
| `--out-dir /path` | Override output directory |

---

## Feed File Format

The tool reads the JSON body from sophos-policy-checker's `/analyze` endpoint directly.
See `sample_findings.json` for the expected structure.

Each finding needs at minimum:
- `severity` — CRITICAL / HIGH / MEDIUM / LOW / INFO
- `title` — finding name (drives NVD + news keyword search)
- `references` — list containing ATT&CK IDs like `"T1190"`, `"TA0008"`

---

## Output

Files are written to `./output/` (or `--out-dir`):

```
output/
  enriched_20260614_143022.json   ← full data, machine-readable
  report_20260614_143022.html     ← dark-theme report, open in browser
```

Open the HTML file directly in Firefox/Chromium — no server needed.

---

## Project Layout

```
scenario-scraper/
  main.py                 ← CLI entry point
  feedfile.py             ← JSON feed loader + ATT&CK ID extractor
  engine.py               ← Enrichment orchestrator
  report.py               ← JSON + HTML writer
  scrapers/
    mitre.py              ← MITRE ATT&CK TAXII 2.1 + HTML fallback
    nvd.py                ← NVD REST API v2
    news.py               ← The Hacker News + BleepingComputer scraper
  templates/
    report.html           ← Jinja2 HTML report template
  output/                 ← Generated reports land here
  sample_findings.json    ← Example feed file
```
