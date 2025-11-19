"""AbuseIPDB helpers (async + sync wrappers).

Provides detailed summary and report list for IP addresses.
"""
import asyncio
from typing import Dict, Any, Optional

import aiohttp


async def async_query_abuseipdb(session: aiohttp.ClientSession, ip: str, api_key: str, max_age_days: int = 90) -> Dict[str, Any]:
    if not api_key:
        return {"error": "missing_api_key"}

    check_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": f"x-apikey:{api_key}"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days}
    try:
        async with session.get(check_url, headers=headers, params=params) as resp:
            text = await resp.text()
            if resp.status >= 400:
                return {"error": f"HTTP {resp.status}", "status": resp.status, "text": text}
            data = await resp.json()

        d = data.get("data", {})
        result: Dict[str, Any] = {
            # Main fields
            "abuseConfidenceScore": d.get("abuseConfidenceScore"),
            "totalReports": d.get("totalReports"),
            "isp": d.get("isp"),
            "usageType": d.get("usageType"),
            "domain": d.get("domain"),
            "countryCode": d.get("countryCode"),
            
            # Additional details
            "ipAddress": d.get("ipAddress"),
            "isWhitelisted": d.get("isWhitelisted"),
            "lastReportedAt": d.get("lastReportedAt"),
            "countryName": d.get("countryName"),
            "hostnames": d.get("hostnames"),
            "totalReportsCount": d.get("totalReports"),  # Backup name
            
            "raw": data,
        }

        # Try fetching reports list (may be paginated); AbuseIPDB has /reports endpoint
        reports_url = "https://api.abuseipdb.com/api/v2/reports"
        params_reports = {"ip": ip}
        try:
            async with session.get(reports_url, headers=headers, params=params_reports) as r2:
                if r2.status == 200:
                    repj = await r2.json()
                    result["reports"] = repj.get("data") or repj.get("reports")
                else:
                    result["reports_error"] = f"HTTP {r2.status}"
        except Exception as _e:
            result.setdefault("reports_error", str(_e))

        return result
    except asyncio.TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}


def query_abuseipdb(ip: str, api_key: str, max_age_days: int = 90) -> Dict[str, Any]:
    try:
        import nest_asyncio
        nest_asyncio.apply()
    except Exception:
        pass

    async def _run():
        async with aiohttp.ClientSession() as session:
            return await async_query_abuseipdb(session, ip, api_key, max_age_days)

    loop = asyncio.get_event_loop()
    return loop.run_until_complete(_run())