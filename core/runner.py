"""ThreatIntelApp - CLI entrypoint (upgraded).

Usage:
    python app.py <resource>
    python app.py --interactive
"""
import argparse
import os
import sys
import random  # Added for dynamic color changes
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from core.utils import detect_input_type, cache_get, cache_set, format_and_display
from core import collector
from languages import get_text  # Removed multi-language support

load_dotenv()

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

console = Console()
LANG = "en"  # Default to English

def get_random_color():
    colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white", "bright_red", "bright_green", "bright_yellow", "bright_blue", "bright_magenta", "bright_cyan", "bright_white"]
    return random.choice(colors)

def print_logo():
    logo = """
    
▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
▐ ██▒   █▓ ██▓  ▄████  ██▓ ██▓    ▄▄▄       ███▄    █ ▄▄▄█████▓▓█████▓██   ██▓▓█████ ▌
▐▓██░   █▒▓██▒ ██▒ ▀█▒▓██▒▓██▒   ▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▒██  ██▒▓█   ▀ ▌
▐ ▓██  █▒░▒██▒▒██░▄▄▄░▒██▒▒██░   ▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░▒███    ▒██ ██░▒███   ▌
▐  ▒██ █░░░██░░▓█  ██▓░██░▒██░   ░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄  ░ ▐██▓░▒▓█  ▄ ▌
▐   ▒▀█░  ░██░░▒▓███▀▒░██░░██████▒▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ ░▒████▒ ░ ██▒▓░░▒████▒▌
▐   ░ ▐░  ░▓   ░▒   ▒ ░▓  ░ ▒░▓  ░▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░  ██▒▒▒ ░░ ▒░ ░▌
▐   ░ ░░   ▒ ░  ░   ░  ▒ ░░ ░ ▒  ░ ▒   ▒▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░▓██ ░▒░  ░ ░  ░▌
▐     ░░   ▒ ░░ ░   ░  ▒ ░  ░ ░    ░   ▒      ░   ░ ░   ░         ░   ▒ ▒ ░░     ░   ▌
▐      ░   ░        ░  ░      ░  ░     ░  ░         ░             ░  ░░ ░        ░  ░▌
▐     ░                                                               ░ ░            ▌
▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌

    """
    color = get_random_color()
    console.print(logo, style=f"bold {color}")

def show_help(full=False):
    """Show help in selected language"""
    usage = "Usage: vigilanteye [OPTIONS] <RESOURCE>"
    options = "Options:"
    interactive = "--interactive    Start interactive mode"
    json_opt = "--json           Output results in JSON format"
    detailed = "--detailed       Show detailed information"
    help_opt = "--help           Show this help message"

    help_text = f"""
{usage}
  cli_usage

{options}
  {interactive}
  {json_opt}
  {detailed}
  {help_opt}
"""

    if full:
        examples = "Examples:"
        resource_types = "Resource Types:"
        warning = "Warning:"
        ip_addr = "• IP Address: 8.8.8.8 veya 2001:4860:4860::8888"
        domain = "• Domain: example.com, google.com"
        url = "• URL: https://example.com/path"
        hash_str = "• Hash: MD5 (32 chr), SHA-1 (40 chr), SHA-256 (64 chr)"
        api_keys = "• API keys must be in the .env file"
        cache_ttl = "• Data is cached locally after first query (1 hour TTL)"

        help_text += f"""

{examples}
  vigilanteye 8.8.8.8                    
  vigilanteye 8.8.8.8 --detailed
  vigilanteye 8.8.8.8 --detailed --json
  vigilanteye https://example.com
  vigilanteye 9f2b267b8e986d5edc2d00df3d1a1d55 --detailed
  vigilanteye google.com --json
  vigilanteye --interactive
  vigilanteye --interactive --json
  vigilanteye --interactive --detailed
  vigilanteye --interactive --detailed --json
  


{resource_types}
  {ip_addr}
  {domain}
  {url}
  {hash_str}

{warning}
  {api_keys}
  {cache_ttl}
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
    print_logo()
    
    # Parse arguments WITHOUT -h/--help processing (we handle it manually)
    parser = argparse.ArgumentParser(add_help=False, description="VigilantEye - Threat Intelligence CLI")
    parser.add_argument("resource", nargs="?", default=None, help="IP, domain, URL, or file hash")
    parser.add_argument("--interactive", action="store_true", help="Prompt for input")
    parser.add_argument("--json", action="store_true", help="Print full JSON output")
    parser.add_argument("--detailed", action="store_true", help="Show detailed information")
    parser.add_argument("--help", "-h", action="store_true", help="Show help message")
    
    args = parser.parse_args()

    if args.help:
        show_help(full=True)
        sys.exit(0)

    if not args.resource and not args.interactive:
        show_help(full=False)
        sys.exit(1)

    if args.interactive:
        prompt = get_text("en", "enter_indicator")
        resource = input(prompt).strip()
    else:
        resource = args.resource.strip()

    rtype = detect_input_type(resource)
    if rtype == "unknown":
        error_msg = get_text("en", "invalid_resource")
        print(error_msg)
        sys.exit(2)

    try:
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