#!/bin/bash
# Install VigilantEye wrapper scripts to system PATH
# This allows using 'vigilanteye' and 'vg' commands without pip

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================"
echo "VigilantEye Wrapper Installation"
echo "================================"
echo ""

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ ERROR: Python3 is not installed${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
echo ""

# Determine installation directory
if [ "$EUID" -eq 0 ]; then
    # Running as root, install to /usr/local/bin
    INSTALL_DIR="/usr/local/bin"
    echo "Installing to system directory: $INSTALL_DIR"
else
    # Not root, install to ~/.local/bin
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    echo "Installing to user directory: $INSTALL_DIR"
    
    # Check if ~/.local/bin is in PATH
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo -e "${YELLOW}⚠${NC}  $INSTALL_DIR is not in your PATH"
        echo ""
        echo "Add this to your ~/.bashrc or ~/.zshrc:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
        echo "Then run: source ~/.bashrc  (or source ~/.zshrc)"
        echo ""
    fi
fi

# Make wrapper scripts executable
chmod +x "$SCRIPT_DIR/vigilanteye_wrapper.sh"
chmod +x "$SCRIPT_DIR/vg_wrapper.sh"

# Copy wrapper scripts to installation directory
echo "Installing wrapper scripts..."
cp "$SCRIPT_DIR/vigilanteye_wrapper.sh" "$INSTALL_DIR/vigilanteye"
cp "$SCRIPT_DIR/vg_wrapper.sh" "$INSTALL_DIR/vg"

# Update the wrapper scripts to point to the correct directory
sed -i "s|SCRIPT_DIR=.*|SCRIPT_DIR=\"$SCRIPT_DIR\"|g" "$INSTALL_DIR/vigilanteye"
sed -i "s|SCRIPT_DIR=.*|SCRIPT_DIR=\"$SCRIPT_DIR\"|g" "$INSTALL_DIR/vg"

chmod +x "$INSTALL_DIR/vigilanteye"
chmod +x "$INSTALL_DIR/vg"

echo -e "${GREEN}✓${NC} Wrapper scripts installed"
echo ""

# Check if dependencies are installed
echo "Checking Python dependencies..."
python3 -c "import rich, aiohttp, requests, dotenv, whois, nest_asyncio" 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓${NC} All dependencies are installed"
else
    echo -e "${YELLOW}⚠${NC}  Some dependencies are missing"
    echo "   Install them with: pip3 install -r requirements.txt"
    echo "   Or: python3 -m pip install -r requirements.txt"
fi
echo ""

echo "================================"
echo -e "${GREEN}✓ Installation Complete!${NC}"
echo "================================"
echo ""
echo "You can now use:"
echo "  vigilanteye 8.8.8.8"
echo "  vg 8.8.8.8"
echo ""
echo "Note: If commands are not found, restart your terminal"
echo "      or add $INSTALL_DIR to your PATH"
echo ""
