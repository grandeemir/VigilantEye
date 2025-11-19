<div align="center">
  
VigilantEye ThreatIntel App
================

</div>


▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
▐ ██▒   █▓ ██▓  ▄████  ██▓ ██▓    ▄▄▄       ███▄    █ ▄▄▄█████▓▓█████▓██   ██▓▓█████ ▌
▐▓██░   █▒▓██▒ ██▒ ▀█▒▓██▒▓██▒   ▒████▄     ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▒██  ██▒▓█   ▀ ▌
▐ ▓██  █▒░▒██▒▒██░▄▄▄░▒██▒▒██░   ▒██  ▀█▄  ▓██  ▀█ ██▒▒ ▓██░ ▒░▒███    ▒██ ██░▒███   ▌
▐  ▒██ █░░░██░░▓█  ██▓░██░▒██░   ░██▄▄▄▄██ ▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄  ░ ▐██▓░▒▓█  ▄ ▌
▐   ▒▀█░  ░██░░▒▓███▀▒░██░░██████▒▓█   ▓██▒▒██░   ▓██░  ▒██▒ ░ ░▒████▒ ░ ██▒▓░░▒████▒▌
▐   ░ ▐░  ░▓   ░▒   ▒ ░▓  ░ ▒░▓  ░▒▒   ▓▒█░░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░  ██▒▒▒ ░░ ▒░ ░▌
▐   ░ ░░   ▒ ░  ░   ░  ▒ ░░ ░ ▒  ░ ▒   ▒▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░▓██ ░▒░  ░ ░  ░▌
▐     ░░   ▒ ░░ ░   ░  ▒ ░  ░ ░    ░   ▒      ░   ░ ░   ░         ░   ▒ ▒ ░░     ░   ▌
▐      ░   ░        ░  ░      ░  ░     ░  ░         ░             ░  ░░ ░        ░  ░▌
▐     ░                                                               ░ ░            ▌
▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌


<div align="center">
Simple terminal threat intelligence aggregator using VirusTotal, MalwareBazaar, URLHaus, and AbuseIPDB.
</div>


Setup
-----

1. Create a virtual environment and install dependencies:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

2. Copy `.env.example` to `.env` and populate the API keys.

Usage
-----

### Quick Start

Run the app with the `vigilanteye` command:

```sh
# Display help with language selection
vigilanteye --help

# Basic usage - will prompt for language selection (en, tr, de)
vigilanteye 8.8.8.8

# Interactive mode (prompt for queries)
vigilanteye --interactive

# JSON output (full enriched data with all fields)
vigilanteye 8.8.8.8 --json

# Detailed view (all available details from each source)
vigilanteye 8.8.8.8 --detailed

# Test with URL (URLhaus, VirusTotal)
vigilanteye "https://www.google.com" --detailed

# Test with hash (VirusTotal, Malware Bazaar)
vigilanteye "9f2b267b8e986d5edc2d00df3d1a1d55" --detailed

# Combine flags
vigilanteye google.com --detailed --json
```

### Multi-Language Support

When you run `vigilanteye`, you'll be prompted to select your language:

```
Select your language / Dil seçiniz / Wählen Sie Ihre Sprache:
[en] English
[tr] Türkçe
[de] Deutsch
Choice: 
```

Simply enter:
- **en** for English
- **tr** for Türkçe (Turkish)
- **de** for Deutsch (German)

All help messages and interface text will be displayed in your selected language!

**Detailed Mode Includes:**
- VirusTotal Details tab with analysis date, categories, community votes
- Per-engine verdicts table (top 20 engines sorted by threat level)
- AbuseIPDB additional details (whitelist status, last reported date, hostnames)
- AbuseIPDB detailed reports table with timestamps and categories
- WHOIS full details (registrar, dates, name servers, emails, status)
- URLhaus details (URL status, threat types, payloads) - for URLs
- Malware Bazaar details (file metadata, hashes, tags, dates) - for hashes

Streamlit dashboard:

```sh
streamlit run dashboard.py
```

Features
--------

- **VirusTotal Integration**: 
  - Last analysis stats (malicious/suspicious/undetected/harmless counts)
  - Per-engine verdicts with detection categories
  - Reputation score and tags
  - Country, ASN, network owner
  - **Details Tab**: Last analysis date, categories (community classification), community votes, WHOIS data
- **AbuseIPDB Integration**: 
  - Abuse confidence score, total reports, ISP, usage type, country
  - Detailed abuse report list with timestamps and categories
  - **Additional Details**: Whitelisted status, last reported date, hostnames, domain information
- **abuse.ch Integration** (URLhaus, Malware Bazaar):
  - **URLhaus**: Detect malicious URLs, last online status, threat types, payloads (no API key needed)
  - **Malware Bazaar**: Hash-based malware detection, file metadata, tags, submission dates (optional API key)
- **IP Geolocation**: City, region, country, organization (via ipinfo.io/ipapi.co)
- **WHOIS Enrichment**: 
  - Registrar, creation date, expiration date
  - Name servers (all), contact emails (all)
  - Domain status, updated date
- **Domain Resolution**: Automatically resolve domains to IPs for AbuseIPDB lookup
- **Parallel API Calls**: Async requests for fast enrichment
- **Local Caching**: Avoid redundant API calls (1-hour TTL)
- **Detailed Reporting**: 
  - VirusTotal Details tab with analysis date, categories, community votes
  - Per-engine verdicts table (top 20 engines sorted by threat level)
  - AbuseIPDB detailed reports table with timestamps and categories
  - AbuseIPDB additional details (whitelist status, hostnames, domain)
  - WHOIS full details (registrar, dates, name servers, emails, status)
  - URLhaus details (status, threat types, payloads)
  - Malware Bazaar details (file metadata, hashes, tags, submission dates)
- **Risk Scoring**: Combined threat score from multiple sources

