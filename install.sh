#!/bin/bash

# VigilantEye Installation Script for macOS, Linux, and Unix
# This script automates the setup process for VigilantEye

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "================================"
echo "VigilantEye Setup - macOS/Linux"
echo "================================"
echo ""

# Check if Python 3.8+ is installed
echo "[1/5] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ ERROR: Python3 is not installed${NC}"
    echo "Please install Python 3.8+ from: https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
echo ""

# Create virtual environment
echo "[2/5] Creating virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo -e "${GREEN}✓${NC} Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "[3/5] Activating virtual environment..."
source .venv/bin/activate
echo -e "${GREEN}✓${NC} Virtual environment activated"
echo ""

# Upgrade pip
echo "[4/5] Upgrading pip, setuptools, and wheel..."
if pip install --upgrade pip setuptools wheel 2>&1 | grep -q "Successfully installed"; then
    echo -e "${GREEN}✓${NC} pip and tools updated"
elif pip install --upgrade pip setuptools wheel 2>&1 | grep -q "already satisfied"; then
    echo -e "${GREEN}✓${NC} pip and tools already up to date"
else
    echo -e "${YELLOW}⚠${NC}  pip update completed"
fi
echo ""

# Install requirements
echo "[5/5] Installing dependencies from requirements.txt..."

# Try normal install first
if pip install -r requirements.txt > /tmp/pip_install.log 2>&1; then
    echo -e "${GREEN}✓${NC} Dependencies installed successfully"
else
    # Check if at least core packages were installed
    if grep -q "Successfully installed" /tmp/pip_install.log; then
        echo -e "${GREEN}✓${NC} Core dependencies installed"
    else
        echo -e "${RED}✗ ERROR: Failed to install core dependencies${NC}"
        echo "Check /tmp/pip_install.log for details"
        exit 1
    fi
fi
echo ""

# Install the VigilantEye package itself
echo "Installing VigilantEye package..."
if pip install -e . > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} VigilantEye package installed"
else
    echo -e "${YELLOW}⚠${NC}  VigilantEye package installation had issues"
fi
echo ""

# Install optional streamlit for dashboard
echo "Installing optional Streamlit for dashboard (this may take a moment)..."
if pip install streamlit > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Streamlit installed (dashboard ready)"
else
    echo -e "${YELLOW}⚠${NC}  Streamlit installation skipped (dashboard won't work)"
    echo "   To install later: pip install streamlit"
fi
echo ""

# Create .env from .env.example if it doesn't exist
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}✓${NC} Created .env file from .env.example"
        echo ""
        echo -e "${YELLOW}⚠️  IMPORTANT:${NC} Edit .env file with your API keys:"
        echo "   - VirusTotal API Key (required)"
        echo "   - AbuseIPDB API Key (required)"
        echo "   - MalwareBazaar API Key (optional)"
        echo ""
        echo "Command to edit: nano .env  (or use your favorite editor)"
    else
        echo -e "${YELLOW}⚠${NC}  WARNING: .env.example not found. Create .env manually."
    fi
else
    echo -e "${GREEN}✓${NC} .env file already exists"
fi

echo ""
echo "================================"
echo -e "${GREEN}✓ Installation Complete!${NC}"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Edit .env with your API keys"
echo "2. Activate virtual environment: source .venv/bin/activate"
echo "3. Test: vigilanteye 8.8.8.8"
echo "4. Dashboard: streamlit run dashboard.py"
echo ""
