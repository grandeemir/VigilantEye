"""Environment and config loader for ThreatIntelApp."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root directory
project_root = Path(__file__).parent.parent
env_file = project_root / ".env"
load_dotenv(dotenv_path=env_file)

VT_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_KEY = os.getenv("IPINFO_API_KEY")
IPAPI_KEY = os.getenv("IPAPI_API_KEY")
WHOIS_KEY = os.getenv("WHOIS_API_KEY")

# abuse.ch APIs
URLHAUS_KEY = os.getenv("URLHAUS_API_KEY")  # URLhaus - no API key required (free)
MALWAREBAZAAR_KEY = os.getenv("MALWAREBAZAAR_API_KEY")  # Malware Bazaar - optional but recommended

