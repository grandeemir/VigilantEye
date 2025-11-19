"""VigilantEye CLI - Terminal-based Threat Intelligence Aggregator"""

import argparse
import os
import sys
from dotenv import load_dotenv
from rich.console import Console
from rich.text import Text

from core.utils import detect_input_type, cache_get, cache_set, format_and_display
from core import collector

# Load environment variables
load_dotenv()

console = Console()

LOGO = r"""
     __   ___  ___
    / /  / _ \/  _|__  ______ ____
   / /  / /_)_/ /|  _ \/ ___/ '__  \
  / /  / _, _/ / | (_) / /  / / / /
 /_/  /_/ |_/_/  \___/_/  /_/ /_/
  _________ ________
  \_   _   //  _____|
   |  |   |/   \___
   |  |   |\_   \  |
   |  |    |__/   /
   |__|    |_____/

╔════════════════════════════════════════════════╗
║        VIGILANT EYE - Threat Intelligence      ║
║  Fast. Parallel. Multi-Source Enrichment.      ║
╚════════════════════════════════════════════════╝
"""


def print_logo():
    """Print ASCII logo to console."""
    console.print(LOGO, style="bold cyan")


def print_usage_examples():
    """Print usage examples."""
    examples = """
[bold cyan]QUICK START[/bold cyan]

  [yellow]vigilanteye[/yellow] [green]8.8.8.8[/green]                    Query an IP address
  [yellow]vigilanteye[/yellow] [green]google.com[/green]                  Query a domain
  [yellow]vigilanteye[/yellow] [green]"https://example.com"[/green]      Query a URL
  [yellow]vigilanteye[/yellow] [green]d41d8cd98f00b204e9800998ecf8427e[/green]  Query a file hash

[bold cyan]OUTPUT MODES[/bold cyan]

  [yellow]vigilanteye[/yellow] [green]8.8.8.8[/green] [blue]--json[/blue]        Full JSON output with all details
  [yellow]vigilanteye[/yellow] [green]8.8.8.8[/green] [blue]--detailed[/blue]     Show comprehensive threat analysis
  [yellow]vigilanteye[/yellow] [green]8.8.8.8[/green]                    Show summary threat report

[bold cyan]INTERACTIVE MODE[/bold cyan]

  [yellow]vigilanteye[/yellow] [blue]--interactive[/blue]             Prompt for queries (one at a time)

[bold cyan]API COVERAGE[/bold cyan]

  ✓ VirusTotal              (95+ antivirus engines)
  ✓ AbuseIPDB               (15M+ abuse reports)
  ✓ URLhaus                 (malicious URL detection)
  ✓ Malware Bazaar          (hash-based malware DB)
  ✓ IP Geolocation          (city, country, ASN)
  ✓ WHOIS Enrichment        (domain registration info)

[bold cyan]FEATURES[/bold cyan]

  • Parallel async API calls for speed
  • Automatic input type detection (IP/domain/URL/hash)
  • Local caching (1-hour TTL)
  • Risk scoring from multiple sources
  • Detailed per-engine verdicts
  • Comprehensive threat reports

[bold cyan]CONFIGURATION[/bold cyan]

  Required: Copy .env.example to .env and add API keys
    - VIRUSTOTAL_API_KEY      (required)
    - ABUSEIPDB_API_KEY       (required)
    - IPINFO_API_KEY          (optional)
    - MALWAREBAZAAR_API_KEY   (optional)

[bold cyan]EXAMPLES[/bold cyan]

  # Check if Google's DNS is trustworthy
  $ vigilanteye 8.8.8.8

  # Get detailed analysis with all sources
  $ vigilanteye google.com --detailed

  # Export results as JSON for processing
  $ vigilanteye "https://example.com" --json

  # Check a suspicious file hash
  $ vigilanteye abc123def456 --detailed
"""
    console.print(examples)


def query_all(resource: str, rtype: str, json_output: bool = False, detailed: bool = False) -> None:
    """Query configured sources and display enriched output."""
    cache_key = f"enriched:{rtype}:{resource}"
    enriched = cache_get(cache_key)
    if not enriched:
        enriched = collector.enrich(resource, rtype)
        if enriched:
            cache_set(cache_key, enriched)

    # Display results
    format_and_display(resource, rtype, enriched, json_output=json_output, detailed=detailed)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="vigilanteye",
        description="VigilantEye - Fast multi-source threat intelligence aggregator",
        epilog="For more info: vigilanteye --help",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False  # We'll handle help manually to show our custom format
    )

    # Custom help/usage arguments
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and examples")
    
    # Main arguments
    parser.add_argument("resource", nargs="?", help="IP address, domain name, URL, or file hash")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode - prompt for queries")
    parser.add_argument("-j", "--json", action="store_true", help="Output results as JSON")
    parser.add_argument("-d", "--detailed", action="store_true", help="Show comprehensive detailed analysis")
    
    args = parser.parse_args()

    # Print logo on startup
    print_logo()

    # Handle help flag
    if args.help or (not args.resource and not args.interactive):
        print_usage_examples()
        parser.print_help()
        sys.exit(0)

    # Interactive mode
    if args.interactive:
        while True:
            try:
                resource = input("\n[cyan]Enter IP / domain / URL / hash (or 'quit' to exit):[/cyan] ").strip()
                if resource.lower() in ("quit", "exit", "q"):
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                if not resource:
                    continue

                rtype = detect_input_type(resource)
                if rtype == "unknown":
                    console.print("[red]✗ Could not detect type. Provide: IP, domain, URL, or hash[/red]")
                    continue

                query_all(resource, rtype, json_output=args.json, detailed=args.detailed)
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted by user[/yellow]")
                break
    else:
        # Single query mode
        resource = args.resource.strip()
        rtype = detect_input_type(resource)
        if rtype == "unknown":
            console.print("[red]✗ Could not detect the resource type.[/red]")
            console.print("[yellow]Provide a valid IP, domain, URL, or file hash.[/yellow]")
            sys.exit(1)

        query_all(resource, rtype, json_output=args.json, detailed=args.detailed)


if __name__ == "__main__":
    main()
