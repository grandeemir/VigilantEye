"""VigilantEye - Threat Intelligence Aggregator
Entry point for the CLI application.
"""
import sys
import os

# Ensure the package directory is in the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.runner import main

if __name__ == "__main__":
    main()
