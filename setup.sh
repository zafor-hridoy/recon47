#!/bin/bash
# Recon47 - Quick Setup Script for Kali Linux
# Author: Xaff

echo ""
echo "  🔱 Recon47 - Setup Script"
echo "  ========================="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Install with: sudo apt install python3"
    exit 1
fi

echo "[*] Creating virtual environment..."
python3 -m venv venv

echo "[*] Activating virtual environment..."
source venv/bin/activate

echo "[*] Installing dependencies..."
pip install -r requirements.txt

echo ""
echo "[✓] Setup complete!"
echo ""
echo "  To use Recon47:"
echo "    source venv/bin/activate"
echo "    python3 recon47.py -t <target>"
echo ""
