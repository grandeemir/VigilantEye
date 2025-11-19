"""ThreatIntelApp - CLI entrypoint (upgraded).

Usage:
    python app.py <resource>
    python app.py --interactive
"""
import argparse
import os
import sys
from dotenv import load_dotenv

from core.utils import detect_input_type, cache_get, cache_set, format_and_display
from core import collector

load_dotenv()

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

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