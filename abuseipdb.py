"""AbuseIPDB helper functions.

This module queries AbuseIPDB for IP reputation data.
"""
import requests
from typing import Optional, Dict, Any


def query_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> Optional[Dict[str, Any]]:
    """Query AbuseIPDB for an IP address.

    Returns a dict with keys: abuseConfidenceScore, totalReports, isp, usageType, raw
    """
    if not api_key:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        # set both headers to be tolerant to header name differences
        "Key": api_key,
        "X-API-Key": api_key,
    }
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        d = data.get("data", {})
        result = {
            "abuseConfidenceScore": d.get("abuseConfidenceScore"),
            "totalReports": d.get("totalReports"),
            "isp": d.get("isp"),
            "usageType": d.get("usageType"),
            "raw": data,
        }
        return result
    except requests.HTTPError as e:
        return {"error": f"HTTP error: {e}", "status_code": getattr(e.response, "status_code", None)}
    except Exception as e:
        return {"error": str(e)}
