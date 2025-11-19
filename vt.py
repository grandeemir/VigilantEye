"""VirusTotal v3 helper functions.

Functions here query VirusTotal and return normalized dicts used by the main app.
"""
import base64
import requests
from typing import Optional, Dict, Any


def _url_id_for_url(url: str) -> str:
    # VirusTotal expects a URL id which is base64 urlsafe of the URL without padding
    raw = url.encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return b64


def query_virus_total(resource: str, resource_type: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Query VirusTotal v3 for the resource.

    resource_type: "ip", "domain", "url", "hash"
    Returns a dict with keys: last_analysis_stats, country, asn, owner, raw
    """
    if not api_key:
        return None

    headers = {"x-apikey": api_key}

    base = "https://www.virustotal.com/api/v3"

    endpoint = None
    target = resource
    if resource_type == "ip":
        endpoint = f"/ip_addresses/{resource}"
    elif resource_type == "domain":
        endpoint = f"/domains/{resource}"
    elif resource_type == "hash":
        endpoint = f"/files/{resource}"
    elif resource_type == "url":
        target = _url_id_for_url(resource)
        endpoint = f"/urls/{target}"
    else:
        return None

    try:
        resp = requests.get(base + endpoint, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})

        result = {
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            "owner": attrs.get("as_owner") or attrs.get("owner") or attrs.get("network_owner"),
            "raw": data,
        }
        return result
    except requests.HTTPError as e:
        # propagate a minimal message for caller to handle
        return {"error": f"HTTP error: {e}", "status_code": getattr(e.response, "status_code", None)}
    except Exception as e:
        return {"error": str(e)}
