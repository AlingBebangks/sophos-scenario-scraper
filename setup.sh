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
echo "[+] Setup complete. To run:"
echo ""
echo "    source venv/bin/activate"
echo "    python main.py sample_findings.json     # test with sample data"
echo "    python main.py --demo                   # built-in demo findings"
echo "    python main.py your_findings.json       # real sophos-checker output"
echo ""
echo "    # Skip slow NVD waits during testing:"
echo "    python main.py sample_findings.json --no-nvd"
echo ""
echo "[*] Reports are written to ./output/"
