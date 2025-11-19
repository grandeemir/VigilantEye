"""IP Geolocation enrichment (ipinfo.io, ipapi).

Provides async functions and sync wrappers for compatibility.
"""
from typing import Optional, Dict, Any
import asyncio
import aiohttp
from config.env import IPINFO_KEY, IPAPI_KEY


async def async_query_ipinfo(session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
    url = f"https://ipinfo.io/{ip}/json"
    params = {}
    if IPINFO_KEY:
        params["token"] = IPINFO_KEY
    try:
        async with session.get(url, params=params) as resp:
            if resp.status >= 400:
                return {"error": f"HTTP {resp.status}"}
            return await resp.json()
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


async def async_query_ipapi(session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
    url = f"https://ipapi.co/{ip}/json/"
    try:
        async with session.get(url) as resp:
            if resp.status >= 400:
                return {"error": f"HTTP {resp.status}"}
            return await resp.json()
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def query_ipinfo(ip: str) -> Dict[str, Any]:
    import nest_asyncio
    nest_asyncio.apply()
    async def _run():
        async with aiohttp.ClientSession() as session:
            return await async_query_ipinfo(session, ip)
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run())


def query_ipapi(ip: str) -> Dict[str, Any]:
    import nest_asyncio
    nest_asyncio.apply()
    async def _run():
        async with aiohttp.ClientSession() as session:
            return await async_query_ipapi(session, ip)
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run())
