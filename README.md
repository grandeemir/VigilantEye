ThreatIntelApp
================

Simple terminal threat intelligence aggregator using VirusTotal and AbuseIPDB.

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

Run the app and pass an IP/domain/URL/hash, or run without args to be prompted:

```sh
python main.py 8.8.8.8
python main.py --interactive
```

Example
-------

Query an IP and get a summarized report in the terminal.
