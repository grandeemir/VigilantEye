"""Multi-language support for VigilantEye"""

LANGUAGES = {
    "en": {
        "language": "English",
        "select_language": "Select your language / Dil seçiniz / Wählen Sie Ihre Sprache:\n[en] English\n[tr] Türkçe\n[de] Deutsch\nChoice: ",
        "invalid_choice": "Invalid choice. Please enter 'en', 'tr', or 'de'.",
        "usage": "Usage: vigilanteye [OPTIONS] <RESOURCE>",
        "options": "Options:",
        "interactive": "Start interactive mode",
        "json": "Output results in JSON format",
        "detailed": "Show detailed information",
        "help": "Show this help message",
        "examples": "Examples:",
        "resource_types": "Resource Types:",
        "data_sources": "Data Sources:",
        "warning": "Warning:",
        "ip_address": "IP Address",
        "domain": "Domain",
        "url": "URL",
        "hash": "Hash",
        "virustotal": "VirusTotal - Malware and threat analysis",
        "abuseipdb": "AbuseIPDB - IP reputation and network abuse reports",
        "whois": "WHOIS - Domain and IP ownership information",
        "abuse_ch": "abuse.ch - URLhaus and Malware Bazaar data",
        "geolocation": "Geolocation - IP geography and ISP information",
        "api_keys": "API keys must be in the .env file",
        "cache_ttl": "Data is cached locally after first query (1 hour TTL)",
        "enter_indicator": "Enter IP / domain / URL / hash: ",
        "invalid_resource": "Could not detect the resource type. Provide a valid IP, domain, URL, or hash.",
    },
    "tr": {
        "language": "Türkçe",
        "select_language": "Dil seçiniz / Select your language / Wählen Sie Ihre Sprache:\n[en] English\n[tr] Türkçe\n[de] Deutsch\nSeçim: ",
        "invalid_choice": "Geçersiz seçim. Lütfen 'en', 'tr' veya 'de' girin.",
        "usage": "Kullanım: vigilanteye [SEÇENEKLER] <KAYNAK>",
        "options": "Seçenekler:",
        "interactive": "Etkileşimli mod başlat (kullanıcıdan giriş iste)",
        "json": "Sonuçları JSON formatında göster",
        "detailed": "Detaylı bilgileri göster",
        "help": "Bu yardım mesajını göster",
        "examples": "Örnekler:",
        "resource_types": "Kaynak Türleri:",
        "data_sources": "Veri Kaynakları:",
        "warning": "Uyarı:",
        "ip_address": "IP Adresi",
        "domain": "Domain",
        "url": "URL",
        "hash": "Hash",
        "virustotal": "VirusTotal - Kötü amaçlı yazılım ve tehdit analizi",
        "abuseipdb": "AbuseIPDB - IP reputasyonu ve ağ istismarı raporları",
        "whois": "WHOIS - Domain ve IP sahiplik bilgisi",
        "abuse_ch": "abuse.ch - URLhaus ve Malware Bazaar verisi",
        "geolocation": "Geolocation - IP coğrafyası ve ISP bilgisi",
        "api_keys": "API anahtarları .env dosyasında bulunmalıdır",
        "cache_ttl": "İlk sorgudan sonra veriler yerel olarak cachelenir (1 saat TTL)",
        "enter_indicator": "IP / domain / URL / hash girin: ",
        "invalid_resource": "Kaynak türü algılanamadı. Lütfen geçerli bir IP, domain, URL veya hash sağlayın.",
    },
    "de": {
        "language": "Deutsch",
        "select_language": "Wählen Sie Ihre Sprache / Select your language / Dil seçiniz:\n[en] English\n[tr] Türkçe\n[de] Deutsch\nAuswahl: ",
        "invalid_choice": "Ungültige Auswahl. Bitte geben Sie 'en', 'tr' oder 'de' ein.",
        "usage": "Verwendung: vigilanteye [OPTIONEN] <RESSOURCE>",
        "options": "Optionen:",
        "interactive": "Interaktiven Modus starten",
        "json": "Ergebnisse im JSON-Format ausgeben",
        "detailed": "Detaillierte Informationen anzeigen",
        "help": "Diese Hilfemeldung anzeigen",
        "examples": "Beispiele:",
        "resource_types": "Ressourcentypen:",
        "data_sources": "Datenquellen:",
        "warning": "Warnung:",
        "ip_address": "IP-Adresse",
        "domain": "Domain",
        "url": "URL",
        "hash": "Hash",
        "virustotal": "VirusTotal - Malware- und Bedrohungsanalyse",
        "abuseipdb": "AbuseIPDB - IP-Reputation und Netzwerkmissbrauchsberichte",
        "whois": "WHOIS - Domain- und IP-Eigentumsinfo",
        "abuse_ch": "abuse.ch - URLhaus und Malware Bazaar Daten",
        "geolocation": "Geolocation - IP-Geographie und ISP-Informationen",
        "api_keys": "API-Schlüssel müssen in der .env-Datei vorhanden sein",
        "cache_ttl": "Nach der ersten Abfrage werden Daten lokal zwischengespeichert (1 Stunde TTL)",
        "enter_indicator": "IP / Domain / URL / Hash eingeben: ",
        "invalid_resource": "Ressourcentyp konnte nicht erkannt werden. Bitte geben Sie eine gültige IP, Domain, URL oder einen Hash an.",
    },
}

def get_language():
    """Prompt user to select language and return language code"""
    print()
    lang_code = input(LANGUAGES["en"]["select_language"]).strip().lower()
    
    if lang_code not in LANGUAGES:
        print(LANGUAGES["en"]["invalid_choice"])
        return get_language()
    
    return lang_code

def get_text(lang_code, key):
    """Get translated text for a key in specified language"""
    if lang_code not in LANGUAGES:
        lang_code = "en"
    return LANGUAGES[lang_code].get(key, LANGUAGES["en"].get(key, key))
