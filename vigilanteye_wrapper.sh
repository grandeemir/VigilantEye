#!/bin/bash
# VigilantEye wrapper script - works without pip installation
# This script allows running vigilanteye/vg commands directly

# Find the VigilantEye directory
# First, try to find it relative to this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If script is in .local/bin, find the actual VigilantEye directory
if [[ "$SCRIPT_DIR" == *".local/bin"* ]]; then
    # Try common locations
    if [ -d "$HOME/VigilantEye" ]; then
        VIGILANTEYE_DIR="$HOME/VigilantEye"
    elif [ -d "/home/emir/VigilantEye" ]; then
        VIGILANTEYE_DIR="/home/emir/VigilantEye"
    else
        # Try to find it by looking for core/runner.py
        VIGILANTEYE_DIR=$(find "$HOME" -name "runner.py" -path "*/core/runner.py" -type f 2>/dev/null | head -1 | xargs dirname | xargs dirname)
        if [ -z "$VIGILANTEYE_DIR" ]; then
            echo "Error: Could not find VigilantEye directory"
            exit 1
        fi
    fi
else
    # Script is in VigilantEye directory
    VIGILANTEYE_DIR="$SCRIPT_DIR"
fi

PYTHON_SCRIPT="$VIGILANTEYE_DIR/core/runner.py"

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed or not in PATH"
    exit 1
fi

# Check if the script exists
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "Error: Could not find runner.py at $PYTHON_SCRIPT"
    exit 1
fi

# Run the Python script with all arguments, adding VigilantEye directory to PYTHONPATH
export PYTHONPATH="$VIGILANTEYE_DIR:$PYTHONPATH"
exec python3 "$PYTHON_SCRIPT" "$@"
