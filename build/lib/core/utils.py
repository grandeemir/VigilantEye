"""Utility helpers: input detection, caching, scoring, and display.

This module centralizes helpers used by the upgraded app.
"""
import re
import json
import time
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

CACHE_FILE = Path(__file__).parent.parent / "cache.json"
CACHE_TTL = 60 * 60  # 1 hour default

console = Console()


def _unix_to_readable(unix_ts: Any) -> str:
    """Convert UNIX timestamp to readable datetime string."""
    try:
        if isinstance(unix_ts, (int, float)):
            return datetime.fromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass
    return str(unix_ts)


def detect_input_type(value: str) -> str:
    """Return one of: ip, domain, url, hash, unknown"""
    value = value.strip()
    ipv4 = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    ipv6 = re.compile(r"^[0-9a-fA-F:]+$")
    domain = re.compile(r"^(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

    if ipv4.match(value) or (":" in value and ipv6.match(value)):
        return "ip"

    if value.startswith("http://") or value.startswith("https://"):
        return "url"

    if domain.match(value):
        return "domain"

    # hashes: md5(32), sha1(40), sha256(64)
    if re.fullmatch(r"[A-Fa-f0-9]{32}", value) or re.fullmatch(r"[A-Fa-f0-9]{40}", value) or re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "hash"

    return "unknown"


def _read_cache() -> Dict[str, Any]:
    if not CACHE_FILE.exists():
        return {}
    try:
        with CACHE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_cache(data: Dict[str, Any]) -> None:
    try:
        with CACHE_FILE.open("w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def cache_get(key: str, max_age: int = CACHE_TTL) -> Optional[Any]:
    store = _read_cache()
    entry = store.get(key)
    if not entry:
        return None
    ts = entry.get("ts", 0)
    if time.time() - ts > max_age:
        return None
    return entry.get("data")


def cache_set(key: str, data: Any) -> None:
    store = _read_cache()
    store[key] = {"ts": time.time(), "data": data}
    _write_cache(store)


def compute_overall_score(vt_data: Optional[dict], abuse_data: Optional[dict], ipgeo: Optional[dict] = None) -> float:
    """Compute a simple risk score 0-100 combining multiple sources.

    - VirusTotal: proportion of malicious detections weighted
    - AbuseIPDB: abuseConfidenceScore (0-100)
    - ASN risk: flag known bad ASNs (simple heuristic)
    """
    scores = []

    if vt_data and isinstance(vt_data, dict):
        stats = vt_data.get("last_analysis_stats") or {}
        total = sum(stats.values()) if isinstance(stats, dict) else 0
        malicious = 0
        if isinstance(stats, dict):
            malicious = stats.get("malicious", 0) + 0.5 * stats.get("suspicious", 0)
        vt_score = (malicious / total * 100) if total > 0 else 0.0
        scores.append(vt_score)

    if abuse_data and isinstance(abuse_data, dict):
        acs = abuse_data.get("abuseConfidenceScore")
        try:
            acs_f = float(acs) if acs is not None else 0.0
        except Exception:
            acs_f = 0.0
        scores.append(acs_f)

    # ASN heuristic: increase risk for bogon or suspicious ASNs (placeholder)
    asn_risk = 0.0
    if vt_data and isinstance(vt_data, dict):
        asn = vt_data.get("asn")
        if asn and isinstance(asn, str):
            if asn.lower().startswith("as") or any(x in asn.lower() for x in ("bogon", "reserved")):
                asn_risk = 50.0
    if asn_risk:
        scores.append(asn_risk)

    if not scores:
        return 0.0
    return sum(scores) / len(scores)


def format_and_display(resource: str, rtype: str, enriched: dict, json_output: bool = False, detailed: bool = False) -> None:
    """Display the enriched JSON as a table or print JSON.

    `enriched` is expected to contain data from VT, AbuseIPDB, IPGeo, WHOIS and `overall_score`.
    If `detailed=True`, show per-engine verdicts and detailed reports.
    """
    if json_output:
        print(json.dumps(enriched, indent=2, ensure_ascii=False))
        return

    tbl = Table(title=f"ThreatIntelApp Report — {resource} ({rtype})")
    tbl.add_column("Source", style="cyan", no_wrap=True)
    tbl.add_column("Field", style="magenta")
    tbl.add_column("Value", style="white")

    vt = enriched.get("virustotal")
    if vt and not vt.get("error"):
        stats = vt.get("last_analysis_stats") or {}
        tbl.add_row("VirusTotal", "Malicious", str(stats.get("malicious", "-")))
        tbl.add_row("VirusTotal", "Suspicious", str(stats.get("suspicious", "-")))
        tbl.add_row("VirusTotal", "Undetected", str(stats.get("undetected", "-")))
        tbl.add_row("VirusTotal", "Harmless", str(stats.get("harmless", "-")))
        tbl.add_row("VirusTotal", "Reputation", str(vt.get("reputation", "-")))
        tbl.add_row("VirusTotal", "Country", str(vt.get("country", "-")))
        tbl.add_row("VirusTotal", "ASN", str(vt.get("asn", "-")))
        tbl.add_row("VirusTotal", "Owner", str(vt.get("as_owner", "-")))
        
        # Tags
        tags = vt.get("tags")
        if tags:
            tbl.add_row("VirusTotal", "Tags", ", ".join(tags[:5]) + ("..." if len(tags) > 5 else ""))
        
        # Details tab information
        last_analysis_date = vt.get("last_analysis_date")
        if last_analysis_date:
            tbl.add_row("VirusTotal", "Last Analysis", _unix_to_readable(last_analysis_date))
        
        first_submission_date = vt.get("first_submission_date")
        if first_submission_date:
            tbl.add_row("VirusTotal", "First Submission", str(first_submission_date))
        
        last_submission_date = vt.get("last_submission_date")
        if last_submission_date:
            tbl.add_row("VirusTotal", "Last Submission", str(last_submission_date))
        
        # Categories (community categorization)
        categories = vt.get("categories")
        if categories and isinstance(categories, dict):
            cat_str = ", ".join(list(categories.keys())[:3]) + ("..." if len(categories) > 3 else "")
            tbl.add_row("VirusTotal", "Categories", cat_str)
        
        # Community votes
        votes = vt.get("votes")
        if votes and isinstance(votes, dict):
            malicious_votes = votes.get("malicious", 0)
            harmless_votes = votes.get("harmless", 0)
            if malicious_votes or harmless_votes:
                tbl.add_row("VirusTotal", "Votes", f"Malicious: {malicious_votes}, Harmless: {harmless_votes}")
        
        # Per-engine detections (show malicious/suspicious only)
        results = vt.get("last_analysis_results") or {}
        malicious_engines = []
        suspicious_engines = []
        for engine, verdict in results.items():
            category = verdict.get("category", "")
            if category == "malicious":
                malicious_engines.append(engine)
            elif category == "suspicious":
                suspicious_engines.append(engine)
        
        if malicious_engines:
            tbl.add_row("VirusTotal", "Malicious Engines", ", ".join(malicious_engines[:3]) + ("..." if len(malicious_engines) > 3 else ""))
        if suspicious_engines:
            tbl.add_row("VirusTotal", "Suspicious Engines", ", ".join(suspicious_engines[:3]) + ("..." if len(suspicious_engines) > 3 else ""))
    else:
        tbl.add_row("VirusTotal", "Info", "No data" if not vt else vt.get("error", "No data"))

    abuse = enriched.get("abuseipdb")
    if abuse and not abuse.get("error"):
        tbl.add_row("AbuseIPDB", "Abuse Score", str(abuse.get("abuseConfidenceScore", "-")))
        tbl.add_row("AbuseIPDB", "Total Reports", str(abuse.get("totalReports", "-")))
        tbl.add_row("AbuseIPDB", "ISP", str(abuse.get("isp", "-")))
        tbl.add_row("AbuseIPDB", "Usage Type", str(abuse.get("usageType", "-")))
        tbl.add_row("AbuseIPDB", "Country", str(abuse.get("countryCode", "-")))
        
        # Recent reports
        reports = abuse.get("reports")
        if reports:
            report_summary = f"{len(reports)} report(s) found"
            recent = reports[:2] if isinstance(reports, list) else []
            if recent:
                categories = [str(r.get("category", "")) for r in recent if isinstance(r, dict)]
                if categories:
                    report_summary += f" - Categories: {', '.join(categories)}"
            tbl.add_row("AbuseIPDB", "Recent Reports", report_summary)
    else:
        tbl.add_row("AbuseIPDB", "Info", "No data" if not abuse else abuse.get("error", "No data"))

    # URLhaus (for URLs)
    urlhaus = enriched.get("urlhaus")
    if urlhaus and not urlhaus.get("error"):
        if urlhaus.get("query_status") == "ok":
            tbl.add_row("URLhaus", "Status", str(urlhaus.get("url_status", "-")))
            tbl.add_row("URLhaus", "Last Online", str(urlhaus.get("last_online", "-")))
            threat = urlhaus.get("threat")
            if threat:
                tbl.add_row("URLhaus", "Threat", str(threat))
            tags = urlhaus.get("tags")
            if tags and isinstance(tags, list):
                tbl.add_row("URLhaus", "Tags", ", ".join(tags[:3]) + ("..." if len(tags) > 3 else ""))
        else:
            tbl.add_row("URLhaus", "Info", "URL not found in URLhaus database")
    
    # Malware Bazaar (for hashes)
    malwarebazaar = enriched.get("malwarebazaar")
    if malwarebazaar and not malwarebazaar.get("error"):
        if malwarebazaar.get("query_status") == "ok":
            tbl.add_row("Malware Bazaar", "File Name", str(malwarebazaar.get("file_name", "-")))
            tbl.add_row("Malware Bazaar", "File Type", str(malwarebazaar.get("file_type", "-")))
            tbl.add_row("Malware Bazaar", "File Size", str(malwarebazaar.get("file_size", "-")))
            tags = malwarebazaar.get("tags")
            if tags and isinstance(tags, list):
                tbl.add_row("Malware Bazaar", "Tags", ", ".join(tags[:3]) + ("..." if len(tags) > 3 else ""))
        else:
            tbl.add_row("Malware Bazaar", "Info", "Hash not found in Malware Bazaar database")

    ipgeo = enriched.get("ipgeo")
    if ipgeo:
        tbl.add_row("IPGeo", "City", str(ipgeo.get("city", "-")))
        tbl.add_row("IPGeo", "Region", str(ipgeo.get("region", "-")))
        tbl.add_row("IPGeo", "Country", str(ipgeo.get("country", "-")))
        tbl.add_row("IPGeo", "Org", str(ipgeo.get("org", "-")))
        loc = ipgeo.get("loc")
        if loc:
            tbl.add_row("IPGeo", "Location", str(loc))
    
    whois = enriched.get("whois")
    if whois:
        tbl.add_row("WHOIS", "Registrar", str(whois.get("registrar", "-")))
        tbl.add_row("WHOIS", "Creation", str(whois.get("creation_date", "-")))
        tbl.add_row("WHOIS", "Expiry", str(whois.get("expiration_date", "-")))
        ns = whois.get("name_servers")
        if ns:
            tbl.add_row("WHOIS", "Name Servers", ", ".join(ns[:2]) + ("..." if len(ns) > 2 else ""))

    tbl.add_row("Summary", "Overall Threat Score", f"{enriched.get('overall_score', 0):.1f} / 100")
    console.print(tbl)
    
    # Detailed view: per-engine verdicts and full reports
    if detailed:
        console.print("\n")
        
        # VirusTotal Details Section
        vt = enriched.get("virustotal")
        if vt and not vt.get("error"):
            console.print("[bold cyan]VirusTotal Details[/bold cyan]")
            details_tbl = Table()
            details_tbl.add_column("Field", style="magenta")
            details_tbl.add_column("Value", style="white")
            
            last_analysis_date = vt.get("last_analysis_date")
            if last_analysis_date:
                details_tbl.add_row("Last Analysis Date", _unix_to_readable(last_analysis_date))
            
            first_submission_date = vt.get("first_submission_date")
            if first_submission_date:
                details_tbl.add_row("First Submission", _unix_to_readable(first_submission_date))
            
            last_submission_date = vt.get("last_submission_date")
            if last_submission_date:
                details_tbl.add_row("Last Submission", _unix_to_readable(last_submission_date))
            
            meaningful_name = vt.get("meaningful_name")
            if meaningful_name:
                details_tbl.add_row("Meaningful Name", str(meaningful_name))
            
            categories = vt.get("categories")
            if categories and isinstance(categories, dict):
                cat_list = [f"{k}: {v}" for k, v in list(categories.items())[:5]]
                details_tbl.add_row("Categories", "\n".join(cat_list))
            
            votes = vt.get("votes")
            if votes and isinstance(votes, dict):
                malicious_votes = votes.get("malicious", 0)
                harmless_votes = votes.get("harmless", 0)
                details_tbl.add_row("Community Votes", f"Malicious: {malicious_votes}, Harmless: {harmless_votes}")
            
            whois = vt.get("whois")
            if whois:
                details_tbl.add_row("WHOIS Data", str(whois)[:80])
            
            console.print(details_tbl)
            console.print("\n")
        
        # VirusTotal per-engine verdicts
        vt = enriched.get("virustotal")
        if vt and not vt.get("error"):
            results = vt.get("last_analysis_results") or {}
            if results:
                console.print("[bold cyan]VirusTotal Engine Verdicts (Detailed)[/bold cyan]")
                engine_tbl = Table()
                engine_tbl.add_column("Engine", style="cyan")
                engine_tbl.add_column("Category", style="magenta")
                engine_tbl.add_column("Result", style="white")
                
                # Sort by category (malicious first)
                sorted_engines = sorted(results.items(), 
                    key=lambda x: (x[1].get("category") != "malicious", x[1].get("category") != "suspicious"))
                
                for engine, verdict in sorted_engines[:20]:  # Show top 20
                    category = verdict.get("category", "unknown")
                    result = verdict.get("result", "N/A")
                    engine_tbl.add_row(engine, category, result)
                
                console.print(engine_tbl)
        
        # AbuseIPDB detailed reports
        abuse = enriched.get("abuseipdb")
        if abuse and not abuse.get("error"):
            reports = abuse.get("reports")
            if reports and isinstance(reports, list) and len(reports) > 0:
                console.print("\n[bold cyan]AbuseIPDB Detailed Reports[/bold cyan]")
                report_tbl = Table()
                report_tbl.add_column("Date", style="cyan")
                report_tbl.add_column("Category", style="magenta")
                report_tbl.add_column("Comment", style="white")
                
                for report in reports[:10]:  # Show top 10 reports
                    if isinstance(report, dict):
                        date = report.get("reportedAt", "N/A")
                        category = str(report.get("category", ""))
                        comment = report.get("comment", "")[:50]  # Truncate comment
                        report_tbl.add_row(date, category, comment)
                
                console.print(report_tbl)
        
        # AbuseIPDB Additional Details
        abuse = enriched.get("abuseipdb")
        if abuse and not abuse.get("error"):
            console.print("\n[bold cyan]AbuseIPDB Additional Details[/bold cyan]")
            abuse_details_tbl = Table()
            abuse_details_tbl.add_column("Field", style="magenta")
            abuse_details_tbl.add_column("Value", style="white")
            
            # Show whitelisted status
            is_whitelisted = abuse.get("isWhitelisted")
            if is_whitelisted is not None:
                abuse_details_tbl.add_row("Whitelisted", str(is_whitelisted))
            
            # Show last reported date
            last_reported = abuse.get("lastReportedAt")
            if last_reported:
                abuse_details_tbl.add_row("Last Reported", str(last_reported))
            
            # Show hostnames
            hostnames = abuse.get("hostnames")
            if hostnames and isinstance(hostnames, list) and len(hostnames) > 0:
                abuse_details_tbl.add_row("Hostnames", "\n".join(hostnames[:5]))
            
            # Show country name
            country_name = abuse.get("countryName")
            if country_name:
                abuse_details_tbl.add_row("Country Name", str(country_name))
            
            # Show domain
            domain = abuse.get("domain")
            if domain:
                abuse_details_tbl.add_row("Domain", str(domain))
            
            abuse_details_tbl.add_row("Abuse Score", str(abuse.get("abuseConfidenceScore", "N/A")))
            abuse_details_tbl.add_row("Total Reports", str(abuse.get("totalReports", "N/A")))
            abuse_details_tbl.add_row("ISP", str(abuse.get("isp", "N/A")))
            abuse_details_tbl.add_row("Usage Type", str(abuse.get("usageType", "N/A")))
            
            console.print(abuse_details_tbl)
        
        # WHOIS Full Details
        whois = enriched.get("whois")
        if whois and isinstance(whois, dict) and len(whois) > 0:
            console.print("\n[bold cyan]WHOIS Full Details[/bold cyan]")
            whois_tbl = Table()
            whois_tbl.add_column("Field", style="magenta")
            whois_tbl.add_column("Value", style="white")
            
            # Registrar
            registrar = whois.get("registrar")
            if registrar:
                whois_tbl.add_row("Registrar", str(registrar))
            
            # Dates
            creation_date = whois.get("creation_date")
            if creation_date:
                whois_tbl.add_row("Creation Date", str(creation_date))
            
            expiration_date = whois.get("expiration_date")
            if expiration_date:
                whois_tbl.add_row("Expiration Date", str(expiration_date))
            
            # Name servers
            name_servers = whois.get("name_servers")
            if name_servers and isinstance(name_servers, list):
                whois_tbl.add_row("Name Servers", "\n".join(name_servers[:10]))
            
            # Emails
            emails = whois.get("emails")
            if emails and isinstance(emails, list):
                whois_tbl.add_row("Contact Emails", "\n".join(emails[:5]))
            
            # Status
            status = whois.get("status")
            if status and isinstance(status, list):
                whois_tbl.add_row("Domain Status", "\n".join(status[:3]))
            
            # Updated date
            updated_date = whois.get("updated_date")
            if updated_date:
                whois_tbl.add_row("Updated Date", str(updated_date))
            
            console.print(whois_tbl)
        
        # URLhaus Detailed Information
        urlhaus = enriched.get("urlhaus")
        if urlhaus and not urlhaus.get("error") and urlhaus.get("query_status") == "ok":
            console.print("\n[bold cyan]URLhaus Details[/bold cyan]")
            urlhaus_tbl = Table()
            urlhaus_tbl.add_column("Field", style="magenta")
            urlhaus_tbl.add_column("Value", style="white")
            
            urlhaus_tbl.add_row("URL", str(urlhaus.get("url", "-")))
            urlhaus_tbl.add_row("Status", str(urlhaus.get("url_status", "-")))
            urlhaus_tbl.add_row("Last Online", str(urlhaus.get("last_online", "-")))
            
            threat = urlhaus.get("threat")
            if threat:
                urlhaus_tbl.add_row("Threat Type", str(threat))
            
            tags = urlhaus.get("tags")
            if tags and isinstance(tags, list):
                urlhaus_tbl.add_row("Tags", ", ".join(tags))
            
            payloads = urlhaus.get("payloads")
            if payloads and isinstance(payloads, list) and len(payloads) > 0:
                payload_list = [p.get("payload_type", "unknown") if isinstance(p, dict) else str(p) for p in payloads[:5]]
                urlhaus_tbl.add_row("Payloads", ", ".join(payload_list) + ("..." if len(payloads) > 5 else ""))
            
            console.print(urlhaus_tbl)
        
        # Malware Bazaar Detailed Information
        malwarebazaar = enriched.get("malwarebazaar")
        if malwarebazaar and not malwarebazaar.get("error") and malwarebazaar.get("query_status") == "ok":
            console.print("\n[bold cyan]Malware Bazaar Details[/bold cyan]")
            mw_tbl = Table()
            mw_tbl.add_column("Field", style="magenta")
            mw_tbl.add_column("Value", style="white")
            
            mw_tbl.add_row("File Name", str(malwarebazaar.get("file_name", "-")))
            mw_tbl.add_row("File Type", str(malwarebazaar.get("file_type", "-")))
            mw_tbl.add_row("File Size", str(malwarebazaar.get("file_size", "-")))
            
            mw_tbl.add_row("SHA256", str(malwarebazaar.get("sha256", "-"))[:80])
            mw_tbl.add_row("MD5", str(malwarebazaar.get("md5", "-"))[:80])
            
            tags = malwarebazaar.get("tags")
            if tags and isinstance(tags, list):
                mw_tbl.add_row("Tags", ", ".join(tags[:5]) + ("..." if len(tags) > 5 else ""))
            
            first_submission = malwarebazaar.get("first_submission")
            if first_submission:
                mw_tbl.add_row("First Submission", str(first_submission))
            
            last_submission = malwarebazaar.get("last_submission")
            if last_submission:
                mw_tbl.add_row("Last Submission", str(last_submission))
            
            console.print(mw_tbl)


if __name__ == "__main__":
    console.print("core.utils module for ThreatIntelApp")



if __name__ == "__main__":
    console.print("core.utils module for ThreatIntelApp")