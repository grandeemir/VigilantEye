<div align="center">

# VigilantEye — Terminal Threat Intelligence Aggregator

</div>

VigilantEye collects and enriches threat intelligence from multiple sources (VirusTotal, abuse.ch's URLhaus and MalwareBazaar, AbuseIPDB, WHOIS and IP geolocation services) and presents results in short/detailed human-readable views or machine-friendly JSON.

**📖 [Quick Installation Guide →](INSTALL.md)**

**Quick Start**

- **Requirements:** Python 3.8+ and `pip`.

**One-Command Setup**

Choose the script for your operating system:

**macOS / Linux:**
```sh
chmod +x install.sh
./install.sh
``

**Windows (PowerShell/Command Prompt):**
```cmd
install.bat
```

The script will:
1. Check Python installation
2. Create a virtual environment
3. Install all dependencies
4. Create `.env` file from `.env.example`

After installation, edit `.env` with your API keys (VirusTotal, AbuseIPDB, optional MalwareBazaar).

Then activate and test:

```sh
source .venv/bin/activate    # macOS/Linux
# or .venv\Scripts\activate.bat  # Windows

vigilanteye 8.8.8.8
```

### If you don't want to write this code every time, you should also run this code.

** MacOs/Linux

```sh
echo "source $PWD/.venv/bin/activate" >> ~/.zshrc
```

** Windows

```sh
@echo off
call .venv\Scripts\activate.bat
vigilanteye %*
```
### also for windows

You can make the vigilanteye command globally executable by adding this file to PATH.
Adding to PATH
vigilanteye.batTo add the vigilanteye.bat file to PATH, follow these steps:
vigilanteye.batSave the vigilanteye.bat file to a directory (e.g., C:\VigilantEye).
To add this directory to PATH:
Open the “Environment Variables” settings from the Start menu.
Under “System Variables,” edit the “Path” option.
Add the C:\VigilantEye directory.

---

**Usage (CLI)**

- Show help: `vigilanteye --help`
- Basic query (prompts for language selection): `vigilanteye 8.8.8.8`
- Interactive mode: `vigilanteye --interactive`
- JSON output: `vigilanteye 8.8.8.8 --json`
- Detailed output: `vigilanteye 8.8.8.8 --detailed`
- URL test: `vigilanteye "https://example.com" --detailed`
- Hash test: `vigilanteye "9f2b267b8e986d5edc2d00df3d1a1d55" --detailed`

The tool resolves domains to IPs for IP-based lookups (AbuseIPDB), routes URL checks to URLhaus, and sends hashes to VirusTotal / MalwareBazaar where applicable.

**Optional: Streamlit Dashboard**

```sh
streamlit run dashboard.py
```

**Key Features**

- **VirusTotal integration:** analysis summaries, per-engine verdicts, tags, reputation and detailed results.
- **AbuseIPDB integration:** abuse confidence score, total reports, ISP, usage type and detailed report list.
- **abuse.ch (URLhaus & MalwareBazaar):** malicious URL and file indicators; URLhaus payload and status info.
- **WHOIS & IP geolocation:** registrar, dates, nameservers, contact emails, and geo/ASN info.
- **Domain resolution:** automatic domain -> IP resolution for relevant lookups.
- **Parallel async calls:** fast data collection using asynchronous requests.
- **Local caching:** reduces repeated API calls with a 1-hour TTL.
- **Output modes:** short, detailed human-readable views and machine-friendly JSON.
- **Risk scoring:** a combined threat score derived from multiple sources (heuristic).

**Configuration**

- Store API keys and environment configuration in `.env`. See `.env.example` for expected variables.

**Developer Notes**

- Command-line interface supports multiple languages (`en`, `tr`, `de`) and prompts for language selection on first run.
- Project layout: integrations live under `core/` (`abuseipdb.py`, `vt.py`, `abuse_ch.py`, `whois.py`, `ipgeo.py`) and the runner/CLI logic is implemented in `runner.py`.

**Quick Examples**

```sh
# Basic IP query
vigilanteye 8.8.8.8

# Detailed JSON output for a domain
vigilanteye example.com --detailed --json

# Start the dashboard
streamlit run dashboard.py
```

**Contributing**

PRs are welcome. Please open an issue first or check existing issues before submitting major changes.

**License**

See the repository `LICENSE` file for license details.

---

