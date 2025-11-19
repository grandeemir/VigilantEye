"""Collector orchestrates parallel API calls and returns an enriched JSON object."""
import asyncio
import socket
from typing import Dict, Any

import aiohttp

from config import env
from core import vt, abuseipdb, ipgeo, whois, abuse_ch
from core.utils import compute_overall_score, detect_input_type


def _resolve_domain_to_ip(domain: str) -> str:
    """Try to resolve domain to IP for AbuseIPDB lookup."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return None


async def gather_enrichment(resource: str, rtype: str) -> Dict[str, Any]:
    async with aiohttp.ClientSession() as session:
        tasks = {}

        # VirusTotal - use sync version due to aiohttp + nest_asyncio compat issues
        from core.vt import _query_virus_total_sync
        vt_result = _query_virus_total_sync(resource, rtype, env.VT_KEY)
        tasks['vt'] = asyncio.sleep(0)  # Dummy task
        
        # AbuseIPDB for IPs, or resolve domain to IP
        abuse_ip = None
        if rtype == 'ip':
            abuse_ip = resource
        elif rtype == 'domain':
            # Try to resolve domain to IP for abuse lookup
            try:
                abuse_ip = _resolve_domain_to_ip(resource)
            except Exception:
                abuse_ip = None

        if abuse_ip:
            tasks['abuse'] = asyncio.create_task(abuseipdb.async_query_abuseipdb(session, abuse_ip, env.ABUSE_KEY))

        # IP geolocation and WHOIS
        if rtype == 'ip':
            tasks['ipinfo'] = asyncio.create_task(ipgeo.async_query_ipinfo(session, resource))
            tasks['ipapi'] = asyncio.create_task(ipgeo.async_query_ipapi(session, resource))
        else:
            tasks['whois'] = asyncio.create_task(whois.async_query_whois(resource))

        # abuse.ch integrations
        if rtype == 'url':
            tasks['urlhaus'] = asyncio.create_task(abuse_ch.async_query_urlhaus(session, resource))
        elif rtype == 'hash':
            tasks['malwarebazaar'] = asyncio.create_task(abuse_ch.async_query_malwarebazaar(session, 'hash', resource, env.MALWAREBAZAAR_KEY))

        results = {'vt': vt_result}
        for name, task in tasks.items():
            if name == 'vt':
                continue
            try:
                results[name] = await task
            except Exception as e:
                results[name] = {"error": str(e)}

        # Normalize ipgeo: prefer ipinfo then ipapi
        ipgeo_data = None
        if rtype == 'ip':
            ipgeo_data = results.get('ipinfo') or results.get('ipapi')

        vt_data = results.get('vt')
        abuse_data = results.get('abuse')
        whois_data = results.get('whois')
        urlhaus_data = results.get('urlhaus')
        malwarebazaar_data = results.get('malwarebazaar')

        overall = compute_overall_score(vt_data, abuse_data, ipgeo_data)

        enriched = {
            'query': resource,
            'type': rtype,
            'resolved_ip': abuse_ip if rtype == 'domain' else None,
            'virustotal': vt_data,
            'abuseipdb': abuse_data,
            'ipgeo': ipgeo_data,
            'whois': whois_data,
            'urlhaus': urlhaus_data,
            'malwarebazaar': malwarebazaar_data,
            'overall_score': overall,
            'raw': results,
        }
        return enriched


def enrich(resource: str, rtype: str) -> Dict[str, Any]:
    try:
        loop = asyncio.get_running_loop()
        # If we're already in a running loop, use nest_asyncio
        import nest_asyncio
        nest_asyncio.apply()
    except RuntimeError:
        # No loop running, create a new one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    try:
        return loop.run_until_complete(gather_enrichment(resource, rtype))
    finally:
        if not asyncio.get_event_loop().is_running():
            loop.close()
