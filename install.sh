#!/bin/bash

# VigilantEye Installation Script for macOS, Linux, and Unix
# This script automates the setup process for VigilantEye

# Don't exit on error for optional steps
set +e

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
echo "[1/6] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ ERROR: Python3 is not installed${NC}"
    echo "Please install Python 3.8+ from: https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
echo ""

# Upgrade pip
echo "[2/6] Upgrading pip, setuptools, and wheel..."
BREAK_SYSTEM_PACKAGES=""
# Check if we need --break-system-packages flag (Arch Linux, etc.)
if python3 -m pip install --help 2>&1 | grep -q "break-system-packages"; then
    # Try to install without it first
    if ! python3 -m pip install --user --upgrade pip setuptools wheel > /dev/null 2>&1; then
        BREAK_SYSTEM_PACKAGES="--break-system-packages"
    fi
fi

if [ "$EUID" -eq 0 ]; then
    # Running as root
    python3 -m pip install ${BREAK_SYSTEM_PACKAGES} --upgrade pip setuptools wheel > /dev/null 2>&1
else
    # Not root, use --user flag
    python3 -m pip install --user ${BREAK_SYSTEM_PACKAGES} --upgrade pip setuptools wheel > /dev/null 2>&1
fi
echo -e "${GREEN}✓${NC} pip and tools updated"
echo ""

# Install requirements
echo "[3/6] Installing dependencies from requirements.txt..."

# Create .local/lib directory if it doesn't exist (for --user installs)
if [ "$EUID" -ne 0 ]; then
    mkdir -p ~/.local/lib/python3.*/site-packages 2>/dev/null || true
fi

# Try normal install first
if [ "$EUID" -eq 0 ]; then
    # Running as root, install system-wide
    if python3 -m pip install ${BREAK_SYSTEM_PACKAGES} -r requirements.txt > /tmp/pip_install.log 2>&1; then
        echo -e "${GREEN}✓${NC} Dependencies installed successfully"
    else
        if grep -q "Successfully installed" /tmp/pip_install.log; then
            echo -e "${GREEN}✓${NC} Core dependencies installed"
        else
            echo -e "${RED}✗ ERROR: Failed to install core dependencies${NC}"
            echo "Check /tmp/pip_install.log for details"
            exit 1
        fi
    fi
else
    # Not root, use --user flag
    if python3 -m pip install --user ${BREAK_SYSTEM_PACKAGES} -r requirements.txt > /tmp/pip_install.log 2>&1; then
        echo -e "${GREEN}✓${NC} Dependencies installed successfully"
    else
        if grep -q "Successfully installed" /tmp/pip_install.log; then
            echo -e "${GREEN}✓${NC} Core dependencies installed"
        else
            echo -e "${RED}✗ ERROR: Failed to install core dependencies${NC}"
            echo "Check /tmp/pip_install.log for details"
            exit 1
        fi
    fi
fi
echo ""

# Install wrapper scripts (this works without pip package installation)
echo "[4/6] Installing wrapper scripts..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Determine installation directory
if [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

# Make wrapper scripts executable
if [ -f "$SCRIPT_DIR/vigilanteye_wrapper.sh" ] && [ -f "$SCRIPT_DIR/vg_wrapper.sh" ]; then
    chmod +x "$SCRIPT_DIR/vigilanteye_wrapper.sh"
    chmod +x "$SCRIPT_DIR/vg_wrapper.sh"
    
    # Copy wrapper scripts to installation directory
    cp "$SCRIPT_DIR/vigilanteye_wrapper.sh" "$INSTALL_DIR/vigilanteye"
    cp "$SCRIPT_DIR/vg_wrapper.sh" "$INSTALL_DIR/vg"
    
    # Update the wrapper scripts to point to the correct directory
    sed -i "s|VIGILANTEYE_DIR=.*|VIGILANTEYE_DIR=\"$SCRIPT_DIR\"|g" "$INSTALL_DIR/vigilanteye" 2>/dev/null || \
    sed -i '' "s|VIGILANTEYE_DIR=.*|VIGILANTEYE_DIR=\"$SCRIPT_DIR\"|g" "$INSTALL_DIR/vigilanteye" 2>/dev/null || true
    sed -i "s|VIGILANTEYE_DIR=.*|VIGILANTEYE_DIR=\"$SCRIPT_DIR\"|g" "$INSTALL_DIR/vg" 2>/dev/null || \
    sed -i '' "s|VIGILANTEYE_DIR=.*|VIGILANTEYE_DIR=\"$SCRIPT_DIR\"|g" "$INSTALL_DIR/vg" 2>/dev/null || true
    
    chmod +x "$INSTALL_DIR/vigilanteye"
    chmod +x "$INSTALL_DIR/vg"
    
    echo -e "${GREEN}✓${NC} Wrapper scripts installed to $INSTALL_DIR"
else
    echo -e "${YELLOW}⚠${NC}  Wrapper scripts not found, skipping..."
fi
echo ""

# Add to PATH if not root and not already in PATH
if [ "$EUID" -ne 0 ]; then
    echo "[5/6] Configuring PATH..."
    SHELL_RC=""
    if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ] || [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    fi
    
    if [ -n "$SHELL_RC" ]; then
        if ! grep -q '\.local/bin' "$SHELL_RC" 2>/dev/null; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
            echo -e "${GREEN}✓${NC} Added ~/.local/bin to PATH in $SHELL_RC"
        else
            echo -e "${GREEN}✓${NC} PATH already configured in $SHELL_RC"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  Could not detect shell RC file. Manually add to your shell config:"
        echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
else
    echo "[5/6] PATH configuration skipped (running as root)"
fi
echo ""

# Try to install package (optional, wrapper scripts work without it)
echo "[6/6] Installing VigilantEye package (optional)..."
if [ "$EUID" -eq 0 ]; then
    # Running as root, install system-wide
    if python3 -m pip install ${BREAK_SYSTEM_PACKAGES} -e . > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} VigilantEye package installed system-wide"
    else
        echo -e "${YELLOW}⚠${NC}  Package installation skipped (wrapper scripts will work)"
    fi
else
    # Not root, try with --user flag
    if python3 -m pip install --user ${BREAK_SYSTEM_PACKAGES} -e . > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} VigilantEye package installed for current user"
    else
        echo -e "${YELLOW}⚠${NC}  Package installation skipped (wrapper scripts will work)"
    fi
fi
echo ""

# Install optional streamlit for dashboard
echo "Installing optional Streamlit for dashboard (this may take a moment)..."
if [ "$EUID" -eq 0 ]; then
    python3 -m pip install ${BREAK_SYSTEM_PACKAGES} streamlit > /dev/null 2>&1
else
    python3 -m pip install --user ${BREAK_SYSTEM_PACKAGES} streamlit > /dev/null 2>&1
fi
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} Streamlit installed (dashboard ready)"
else
    echo -e "${YELLOW}⚠${NC}  Streamlit installation skipped (dashboard won't work)"
    echo "   To install later: python3 -m pip install --user streamlit"
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
echo "2. Restart your terminal or run: source ~/.zshrc  (or source ~/.bashrc)"
echo "3. Test the command: vigilanteye 8.8.8.8"
echo "   Or use the short alias: vg 8.8.8.8"
echo "4. Dashboard: streamlit run dashboard.py"
echo ""
echo -e "${GREEN}Commands 'vigilanteye' and 'vg' are now available!${NC}"
echo ""
