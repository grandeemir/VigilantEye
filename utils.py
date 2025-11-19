"""Utility helpers: env loading, input detection, caching, display helpers.

This module centralizes small helpers so adding more sources is easy.
"""
import re
import json
import time
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

CACHE_FILE = Path(__file__).parent / "cache.json"
CACHE_TTL = 60 * 60  # 1 hour default

console = Console()


def detect_input_type(value: str) -> str:
    """Return one of: ip, domain, url, hash, unknown"""
    value = value.strip()
    # IPv4
    ipv4 = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    # Basic IPv6 (not exhaustive)
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


def compute_overall_score(vt_stats: Optional[dict], abuse_score: Optional[float]) -> float:
    """Combine VirusTotal and AbuseIPDB indicators into 0-100 score.

    The function is intentionally simple and tunable.
    """
    scores = []

    if vt_stats:
        # vt_stats expected to be last_analysis_stats dict
        total = sum(vt_stats.values()) if isinstance(vt_stats, dict) else 0
        malicious = 0
        if isinstance(vt_stats, dict):
            malicious = vt_stats.get("malicious", 0) + 0.5 * vt_stats.get("suspicious", 0)
        vt_score = (malicious / total * 100) if total > 0 else 0.0
        scores.append(vt_score)

    if abuse_score is not None:
        scores.append(float(abuse_score))

    if not scores:
        return 0.0

    return sum(scores) / len(scores)


def format_and_display(resource: str, rtype: str, vt_data: Optional[dict], abuse_data: Optional[dict], overall_score: float) -> None:
    """Render a summary table using rich."""
    tbl = Table(title=f"ThreatIntelApp Report — {resource} ({rtype})")
    tbl.add_column("Source", style="cyan", no_wrap=True)
    tbl.add_column("Field", style="magenta")
    tbl.add_column("Value", style="white")

    # VirusTotal
    if vt_data:
        stats = vt_data.get("last_analysis_stats") or {}
        tbl.add_row("VirusTotal", "Malicious", str(stats.get("malicious", "-")))
        tbl.add_row("VirusTotal", "Suspicious", str(stats.get("suspicious", "-")))
        tbl.add_row("VirusTotal", "Undetected", str(stats.get("undetected", "-")))
        tbl.add_row("VirusTotal", "Country", str(vt_data.get("country", "-")))
        tbl.add_row("VirusTotal", "ASN", str(vt_data.get("asn", "-")))
        tbl.add_row("VirusTotal", "Owner", str(vt_data.get("owner", "-")))
    else:
        tbl.add_row("VirusTotal", "Info", "No data or query not supported")

    # AbuseIPDB
    if abuse_data:
        tbl.add_row("AbuseIPDB", "Abuse Score", str(abuse_data.get("abuseConfidenceScore", "-")))
        tbl.add_row("AbuseIPDB", "Total Reports", str(abuse_data.get("totalReports", "-")))
        tbl.add_row("AbuseIPDB", "ISP", str(abuse_data.get("isp", "-")))
        tbl.add_row("AbuseIPDB", "Usage Type", str(abuse_data.get("usageType", "-")))
    else:
        tbl.add_row("AbuseIPDB", "Info", "No data (only for IPs) or missing key")

    tbl.add_row("Summary", "Overall Threat Score", f"{overall_score:.1f} / 100")

    console.print(tbl)


if __name__ == "__main__":
    console.print("This module provides helpers for ThreatIntelApp.")
