"""WHOIS enrichment (async wrapper over `python-whois`)."""
from typing import Dict, Any
import asyncio
import whois


async def async_query_whois(domain: str) -> Dict[str, Any]:
    # python-whois is synchronous; run in threadpool
    loop = asyncio.get_event_loop()
    def _run():
        try:
            w = whois.whois(domain)
            # normalize keys - convert datetime to string
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            
            # Handle list of dates or single date
            if isinstance(creation_date, list) and creation_date:
                creation_date = str(creation_date[0])
            else:
                creation_date = str(creation_date) if creation_date else None
                
            if isinstance(expiration_date, list) and expiration_date:
                expiration_date = str(expiration_date[0])
            else:
                expiration_date = str(expiration_date) if expiration_date else None
            
            return {
                "registrar": w.registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "name_servers": w.name_servers if hasattr(w, 'name_servers') else [],
                "emails": w.emails if hasattr(w, 'emails') else [],
                "raw": w.text if hasattr(w, 'text') else None,
            }
        except Exception as e:
            return {"error": str(e)}
    return await loop.run_in_executor(None, _run)


def query_whois(domain: str) -> Dict[str, Any]:
    import nest_asyncio
    nest_asyncio.apply()
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(async_query_whois(domain))