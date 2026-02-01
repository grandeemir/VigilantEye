#!/bin/bash

# VigilantEye Uninstall Script
# This script removes all VigilantEye components from the system

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check for --force flag
FORCE_MODE=false
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
    FORCE_MODE=true
fi

echo "================================"
echo "VigilantEye Uninstall"
echo "================================"
echo ""
echo -e "${YELLOW}⚠ WARNING: This will remove all VigilantEye components!${NC}"
echo ""

if [ "$FORCE_MODE" = false ]; then
    read -p "Are you sure you want to continue? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Uninstall cancelled."
        exit 0
    fi
else
    echo "Force mode enabled. Proceeding with uninstall..."
fi

echo ""
echo "Removing VigilantEye components..."
echo ""

# Remove wrapper scripts
echo "[1/5] Removing wrapper scripts..."
REMOVED_SCRIPTS=0

if [ -f "$HOME/.local/bin/vigilanteye" ]; then
    rm -f "$HOME/.local/bin/vigilanteye"
    echo -e "${GREEN}✓${NC} Removed ~/.local/bin/vigilanteye"
    REMOVED_SCRIPTS=1
fi

if [ -f "$HOME/.local/bin/vg" ]; then
    rm -f "$HOME/.local/bin/vg"
    echo -e "${GREEN}✓${NC} Removed ~/.local/bin/vg"
    REMOVED_SCRIPTS=1
fi

if [ -f "/usr/local/bin/vigilanteye" ]; then
    if [ "$EUID" -eq 0 ]; then
        rm -f "/usr/local/bin/vigilanteye"
        echo -e "${GREEN}✓${NC} Removed /usr/local/bin/vigilanteye"
        REMOVED_SCRIPTS=1
    else
        echo -e "${YELLOW}⚠${NC}  /usr/local/bin/vigilanteye exists but requires root to remove"
    fi
fi

if [ -f "/usr/local/bin/vg" ]; then
    if [ "$EUID" -eq 0 ]; then
        rm -f "/usr/local/bin/vg"
        echo -e "${GREEN}✓${NC} Removed /usr/local/bin/vg"
        REMOVED_SCRIPTS=1
    else
        echo -e "${YELLOW}⚠${NC}  /usr/local/bin/vg exists but requires root to remove"
    fi
fi

if [ $REMOVED_SCRIPTS -eq 0 ]; then
    echo -e "${YELLOW}⚠${NC}  No wrapper scripts found"
fi
echo ""

# Remove Python packages
echo "[2/5] Removing Python packages..."
BREAK_SYSTEM_PACKAGES=""
if python3 -m pip uninstall --help 2>&1 | grep -q "break-system-packages"; then
    # Check if we need the flag
    BREAK_SYSTEM_PACKAGES="--break-system-packages"
fi

# Try to uninstall vigilanteye package
if python3 -m pip show vigilanteye > /dev/null 2>&1; then
    if [ "$EUID" -eq 0 ]; then
        python3 -m pip uninstall -y ${BREAK_SYSTEM_PACKAGES} vigilanteye > /dev/null 2>&1
    else
        python3 -m pip uninstall -y --user ${BREAK_SYSTEM_PACKAGES} vigilanteye > /dev/null 2>&1
    fi
    echo -e "${GREEN}✓${NC} Removed vigilanteye package"
else
    echo -e "${YELLOW}⚠${NC}  vigilanteye package not found"
fi
echo ""

# Remove dependencies (optional - ask user)
echo "[3/5] Removing dependencies..."
if [ "$FORCE_MODE" = false ]; then
    read -p "Remove all VigilantEye dependencies? (yes/no): " remove_deps
else
    remove_deps="yes"
    echo "Force mode: Removing all dependencies..."
fi

if [ "$remove_deps" = "yes" ]; then
    DEPS=("python-dotenv" "rich" "aiohttp" "python-whois" "nest-asyncio")
    for dep in "${DEPS[@]}"; do
        if python3 -m pip show "$dep" > /dev/null 2>&1; then
            if [ "$EUID" -eq 0 ]; then
                python3 -m pip uninstall -y ${BREAK_SYSTEM_PACKAGES} "$dep" > /dev/null 2>&1
            else
                python3 -m pip uninstall -y --user ${BREAK_SYSTEM_PACKAGES} "$dep" > /dev/null 2>&1
            fi
            echo -e "${GREEN}✓${NC} Removed $dep"
        fi
    done
else
    echo -e "${YELLOW}⚠${NC}  Keeping dependencies installed"
fi
echo ""

# Remove cache and data files
echo "[4/5] Removing cache and data files..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/cache.json" ]; then
    rm -f "$SCRIPT_DIR/cache.json"
    echo -e "${GREEN}✓${NC} Removed cache.json"
fi

# Ask about .env file
if [ -f "$SCRIPT_DIR/.env" ]; then
    if [ "$FORCE_MODE" = false ]; then
        read -p "Remove .env file (contains API keys)? (yes/no): " remove_env
    else
        remove_env="yes"
        echo "Force mode: Removing .env file..."
    fi
    
    if [ "$remove_env" = "yes" ]; then
        rm -f "$SCRIPT_DIR/.env"
        echo -e "${GREEN}✓${NC} Removed .env file"
    else
        echo -e "${YELLOW}⚠${NC}  Keeping .env file"
    fi
fi
echo ""

# Remove PATH entry (optional)
echo "[5/5] Cleaning up PATH..."
SHELL_RC=""
if [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

if [ -n "$SHELL_RC" ]; then
    if [ "$FORCE_MODE" = false ]; then
        read -p "Remove ~/.local/bin from PATH in $SHELL_RC? (yes/no): " remove_path
    else
        remove_path="yes"
        echo "Force mode: Removing PATH entry..."
    fi
    
    if [ "$remove_path" = "yes" ]; then
        # Remove the PATH line
        sed -i '/export PATH=.*\.local\/bin/d' "$SHELL_RC" 2>/dev/null || \
        sed -i '' '/export PATH=.*\.local\/bin/d' "$SHELL_RC" 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Removed PATH entry from $SHELL_RC"
    else
        echo -e "${YELLOW}⚠${NC}  Keeping PATH entry"
    fi
else
    echo -e "${YELLOW}⚠${NC}  Shell RC file not found"
fi
echo ""

echo "================================"
echo -e "${GREEN}✓ Uninstall Complete!${NC}"
echo "================================"
echo ""
echo "VigilantEye has been removed from your system."
echo "Note: The source code directory was not removed."
echo "      If you want to remove it, delete the directory manually."
echo ""
