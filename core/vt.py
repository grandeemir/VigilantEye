"""VirusTotal helpers (async + sync wrappers).

Provides `query_virus_total` synchronous wrapper and `async_query_virus_total` async function.
Fetches detailed attributes: last_analysis_stats, last_analysis_results (per engine), reputation,
tags, as_owner, country, asn and returns a normalized dict.
"""
import asyncio
import base64
from typing import Dict, Any

import aiohttp
import requests


def _url_id_for_url(url: str) -> str:
    raw = url.encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


async def async_query_virus_total(session: aiohttp.ClientSession, resource: str, resource_type: str, api_key: str) -> Dict[str, Any]:
    if not api_key:
        return {"error": "missing_api_key"}

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
        return {"error": "unsupported_type"}

    url = base + endpoint
    try:
        async with session.get(url, headers=headers) as resp:
            text = await resp.text()
            if resp.status >= 400:
                return {"error": f"HTTP {resp.status}", "status": resp.status, "text": text}
            data = await resp.json()

        attrs = data.get("data", {}).get("attributes", {})

        result: Dict[str, Any] = {
            # Summary stats
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "last_analysis_results": attrs.get("last_analysis_results"),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags"),
            "as_owner": attrs.get("as_owner") or attrs.get("network_owner"),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            
            # Details tab info
            "last_analysis_date": attrs.get("last_analysis_date"),
            "first_submission_date": attrs.get("first_submission_date"),
            "last_submission_date": attrs.get("last_submission_date"),
            "meaningful_name": attrs.get("meaningful_name"),
            "categories": attrs.get("categories"),
            
            # Votes (community) - use total_votes if votes is missing
            "votes": attrs.get("votes") or attrs.get("total_votes"),
            
            # Extra metadata
            "whois": attrs.get("whois"),
            "whois_date": attrs.get("whois_date"),
            "tld": attrs.get("tld"),
            "public_dns": attrs.get("public_dns"),
            
            # For domains
            "last_dns_records": attrs.get("last_dns_records"),
            "registrar": attrs.get("registrar"),
            
            "raw": data,
        }
        return result
    except (asyncio.TimeoutError, asyncio.CancelledError):
        return {"error": "timeout"}
    except RuntimeError as e:
        if "Timeout context manager" in str(e):
            # Known aiohttp + nest_asyncio compat issue, try with requests fallback
            return _query_virus_total_sync(resource, resource_type, api_key)
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def _query_virus_total_sync(resource: str, resource_type: str, api_key: str) -> Dict[str, Any]:
    """Synchronous fallback for aiohttp + nest_asyncio issues."""
    if not api_key:
        return {"error": "missing_api_key"}

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
        return {"error": "unsupported_type"}

    url = base + endpoint
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code >= 400:
            return {"error": f"HTTP {resp.status_code}", "status": resp.status_code, "text": resp.text}
        data = resp.json()

        attrs = data.get("data", {}).get("attributes", {})

        result: Dict[str, Any] = {
            "last_analysis_stats": attrs.get("last_analysis_stats"),
            "last_analysis_results": attrs.get("last_analysis_results"),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags"),
            "as_owner": attrs.get("as_owner") or attrs.get("network_owner"),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "first_submission_date": attrs.get("first_submission_date"),
            "last_submission_date": attrs.get("last_submission_date"),
            "meaningful_name": attrs.get("meaningful_name"),
            "categories": attrs.get("categories"),
            "votes": attrs.get("votes") or attrs.get("total_votes"),
            "whois": attrs.get("whois"),
            "whois_date": attrs.get("whois_date"),
            "tld": attrs.get("tld"),
            "public_dns": attrs.get("public_dns"),
            "last_dns_records": attrs.get("last_dns_records"),
            "registrar": attrs.get("registrar"),
            "raw": data,
        }
        return result
    except requests.Timeout:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def query_virus_total(resource: str, resource_type: str, api_key: str) -> Dict[str, Any]:
    """Synchronous wrapper that runs the async query in an event loop."""
    try:
        import nest_asyncio
        nest_asyncio.apply()
    except Exception:
        pass

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await async_query_virus_total(session, resource, resource_type, api_key)

    loop = asyncio.get_event_loop()
    # run until complete regardless of loop state
    return loop.run_until_complete(_run())