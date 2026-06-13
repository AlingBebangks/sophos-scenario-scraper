#!/usr/bin/env bash
# Setup script for Kali Linux
set -e

echo "[*] Checking Python version..."
python3 --version

echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Creating output directory..."
mkdir -p output

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           Sophos Scenario Scraper — Ready                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  ── Web UI (recommended) ──────────────────────────────"
echo ""
echo "    source venv/bin/activate"
echo "    python3 server.py"
echo "    # Open http://localhost:3001 in your browser"
echo ""
echo "  ── CLI (alternative) ─────────────────────────────────"
echo ""
echo "    source venv/bin/activate"
echo "    python3 main.py sample_findings.json     # sample data"
echo "    python3 main.py --demo                   # built-in demo"
echo "    python3 main.py findings.json --no-nvd   # skip slow CVE lookup"
echo ""
echo "  Reports are written to ./output/"
echo ""
