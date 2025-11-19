"""Abuse.ch helpers (URLhaus, Malware Bazaar).

Provides async + sync wrappers for abuse.ch API queries.
URLhaus: No API key required
Malware Bazaar: API key required (optional)
PhishTank: No longer supported (API key deprecated)
"""
import asyncio
from typing import Dict, Any, Optional

import aiohttp


async def async_query_urlhaus(session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
    """Query URLhaus API for malicious URL information.
    
    URLhaus doesn't require API key - completely free access.
    """
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    params = {"url": url}
    
    try:
        async with session.get(endpoint, params=params, timeout=20) as resp:
            text = await resp.text()
            if resp.status >= 400:
                return {"error": f"HTTP {resp.status}", "status": resp.status}
            data = await resp.json()

        result: Dict[str, Any] = {
            "query_status": data.get("query_status"),
            "url": data.get("url"),
            "url_status": data.get("url_status"),
            "last_online": data.get("last_online"),
            "threat": data.get("threat"),
            "tags": data.get("tags"),
            "larted": data.get("larted"),
            "payloads": data.get("payloads"),
            "raw": data,
        }
        return result
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


async def async_query_malwarebazaar(session: aiohttp.ClientSession, query_type: str, query_value: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Query Malware Bazaar API for malware hash information.
    
    query_type: 'hash' (MD5/SHA256), 'tag', etc.
    query_value: the actual value to search for
    api_key: optional API key for higher rate limits
    """
    endpoint = "https://api.abuse.ch/api/v1/"
    
    data = {
        "query": "get_info",
        f"search_{query_type}": query_value,
    }
    
    try:
        async with session.post(endpoint, data=data, timeout=20) as resp:
            text = await resp.text()
            if resp.status >= 400:
                return {"error": f"HTTP {resp.status}", "status": resp.status}
            result = await resp.json()

        # Structure response
        response: Dict[str, Any] = {
            "query_status": result.get("query_status"),
            "data": result.get("data"),
            "raw": result,
        }
        
        if result.get("query_status") == "ok" and isinstance(result.get("data"), list):
            data_list = result.get("data", [])
            if data_list:
                # Extract first result details
                first_item = data_list[0] if isinstance(data_list, list) else data_list
                response.update({
                    "sha256": first_item.get("sha256") if isinstance(first_item, dict) else None,
                    "md5": first_item.get("md5") if isinstance(first_item, dict) else None,
                    "sha1": first_item.get("sha1") if isinstance(first_item, dict) else None,
                    "file_name": first_item.get("file_name") if isinstance(first_item, dict) else None,
                    "file_size": first_item.get("file_size") if isinstance(first_item, dict) else None,
                    "file_type": first_item.get("file_type") if isinstance(first_item, dict) else None,
                    "tags": first_item.get("tags") if isinstance(first_item, dict) else None,
                    "first_submission": first_item.get("first_submission") if isinstance(first_item, dict) else None,
                    "last_submission": first_item.get("last_submission") if isinstance(first_item, dict) else None,
                })
        
        return response
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def query_urlhaus(url: str) -> Dict[str, Any]:
    """Sync wrapper for URLhaus query."""
    try:
        import nest_asyncio
        nest_asyncio.apply()
    except Exception:
        pass

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await async_query_urlhaus(session, url)

    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run())


def query_malwarebazaar(query_type: str, query_value: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Sync wrapper for Malware Bazaar query."""
    try:
        import nest_asyncio
        nest_asyncio.apply()
    except Exception:
        pass

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await async_query_malwarebazaar(session, query_type, query_value, api_key)

    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run())

