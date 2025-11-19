"""ThreatIntelApp - CLI entrypoint (upgraded).

Usage:
    python app.py <resource>
    python app.py --interactive
"""
import argparse
import os
import sys
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from core.utils import detect_input_type, cache_get, cache_set, format_and_display
from core import collector

load_dotenv()

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

console = Console()

def print_logo():
    logo = """
    ███    ██ ██ ██      ██   ██  █████  ███    ██ ███████ ███████
    ████   ██ ██ ██      ██   ██ ██   ██ ████   ██ ██      ██     
    ██ ██  ██ ██ ██      ███████ ███████ ██ ██  ██ █████   █████  
    ██  ██ ██ ██ ██      ██   ██ ██   ██ ██  ██ ██ ██      ██     
    ██   ████ ██ ███████ ██   ██ ██   ██ ██   ████ ███████ ███████
    """
    console.print(Panel(logo, title="[bold red]VigilantEye[/bold red]", subtitle="Threat Intelligence Aggregator", style="bold green"))

def show_help():
    help_text = """
    Usage: vigilanteye [OPTIONS] <RESOURCE>

    Options:
      --interactive    Start interactive mode
      --json           Output results in JSON format
      --detailed       Show detailed information
      --help           Show this message and exit

    Examples:
      vigilanteye 8.8.8.8 --detailed
      vigilanteye https://example.com --json
    """
    console.print(help_text)

def query_all(resource: str, rtype: str) -> None:
    """Query configured sources and display enriched JSON/table output."""
    cache_key = f"enriched:{rtype}:{resource}"
    enriched = cache_get(cache_key)
    if not enriched:
        enriched = collector.enrich(resource, rtype)
        if enriched:
            cache_set(cache_key, enriched)

    # display
    format_and_display(resource, rtype, enriched, json_output=False)

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--help", action="store_true", help="Show help message")
    args, unknown = parser.parse_known_args()

    print_logo()

    if args.help:
        show_help()
        sys.exit(0)

    p = argparse.ArgumentParser(description="ThreatIntelApp — query VT and AbuseIPDB")
    p.add_argument("resource", nargs="?", help="IP, domain, URL, or file hash")
    p.add_argument("--interactive", action="store_true", help="Prompt for input")
    p.add_argument("--json", action="store_true", help="Print full JSON output instead of table")
    p.add_argument("--detailed", action="store_true", help="Show detailed per-engine verdicts and reports")
    args = p.parse_args()

    if not args.resource and not args.interactive:
        p.print_help()
        sys.exit(1)

    if args.interactive:
        resource = input("Enter IP / domain / URL / hash: ").strip()
    else:
        resource = args.resource.strip()

    rtype = detect_input_type(resource)
    if rtype == "unknown":
        print("Could not detect the resource type. Provide a valid IP, domain, URL, or hash.")
        sys.exit(2)

    try:
        # support json flag
        enriched = None
        cache_key = f"enriched:{rtype}:{resource}"
        enriched = cache_get(cache_key)
        if not enriched:
            enriched = collector.enrich(resource, rtype)
            if enriched:
                cache_set(cache_key, enriched)

        format_and_display(resource, rtype, enriched, json_output=args.json, detailed=args.detailed)
    except Exception as e:
        print(f"Unhandled error: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()