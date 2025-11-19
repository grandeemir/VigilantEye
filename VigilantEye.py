"""ThreatIntelApp - CLI entrypoint.

Usage:
    python main.py <resource>

The app auto-detects the type and queries VirusTotal (and AbuseIPDB for IPs).
"""
import argparse
import os
import sys

from dotenv import load_dotenv

from utils import detect_input_type, cache_get, cache_set, compute_overall_score, format_and_display
import vt
import abuseipdb

load_dotenv()

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")


def query_all(resource: str, rtype: str) -> None:
    """Query configured sources and display results."""
    # VirusTotal cache key
    vt_cache_key = f"vt:{rtype}:{resource}"
    vt_data = cache_get(vt_cache_key)
    if not vt_data:
        vt_data = vt.query_virus_total(resource, rtype, VT_KEY)
        if vt_data:
            cache_set(vt_cache_key, vt_data)

    abuse_data = None
    if rtype == "ip":
        abuse_cache_key = f"abuseipdb:ip:{resource}"
        abuse_data = cache_get(abuse_cache_key)
        if not abuse_data:
            abuse_data = abuseipdb.query_abuseipdb(resource, ABUSE_KEY)
            if abuse_data:
                cache_set(abuse_cache_key, abuse_data)

    # normalize fields for scoring
    vt_stats = None
    if isinstance(vt_data, dict):
        vt_stats = vt_data.get("last_analysis_stats")

    abuse_score = None
    if isinstance(abuse_data, dict):
        abuse_score = abuse_data.get("abuseConfidenceScore")

    overall = compute_overall_score(vt_stats, abuse_score)

    format_and_display(resource, rtype, vt_data, abuse_data, overall)


def main():
    p = argparse.ArgumentParser(description="ThreatIntelApp — query VT and AbuseIPDB")
    p.add_argument("resource", nargs="?", help="IP, domain, URL, or file hash")
    p.add_argument("--interactive", action="store_true", help="Prompt for input")
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
        query_all(resource, rtype)
    except Exception as e:
        print(f"Unhandled error: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()
