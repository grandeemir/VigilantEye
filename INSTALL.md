# Quick Installation Guide

This guide provides the fastest way to install and run VigilantEye on your system.

## For macOS and Linux Users

Open Terminal and run:

```bash
cd /path/to/VigilantEye
chmod +x install.sh
./install.sh
```

Then activate the virtual environment:
```bash
source .venv/bin/activate
```

## For Windows Users

Open Command Prompt or PowerShell and run:

```cmd
cd C:\path\to\VigilantEye
install.bat
```

## Configuration

1. After installation, edit the `.env` file with your API keys:

```bash
# Linux/macOS
nano .env

# Windows (or use any text editor)
notepad .env
```

2. Add your API keys:
   - **VirusTotal:** Get from https://www.virustotal.com/gui/home/upload
   - **AbuseIPDB:** Get from https://www.abuseipdb.com/api
   - **Optional - MalwareBazaar:** Get from https://www.malwarebazaar.org/api/

3. Save the file and you're ready to go!

## Usage

After setup and activation, you can immediately use VigilantEye:

```bash
# Show help
vigilanteye --help

# Basic threat check (IP, domain, URL, or hash)
vigilanteye 8.8.8.8

# Interactive mode
vigilanteye --interactive

# Detailed JSON output
vigilanteye example.com --detailed --json

# Optional: Start the dashboard
streamlit run dashboard.py
```

## Troubleshooting

**Python not found:**
- Install Python 3.8+ from https://www.python.org/downloads/
- Windows: Make sure "Add Python to PATH" is checked during installation

**pip install fails:**
- Try: `pip install --upgrade pip` before running the script again
- On Linux/Mac: May need `sudo` or use `python3 -m pip` instead

**Virtual environment activation fails:**
- macOS/Linux: Use `source .venv/bin/activate`
- Windows: Use `.venv\Scripts\activate.bat`

## Next Steps

1. Edit `.env` with your API keys
2. Test with: `vigilanteye 8.8.8.8`
3. Try detailed mode: `vigilanteye example.com --detailed`
4. For dashboard: `streamlit run dashboard.py`

## Support

If you encounter issues:
1. Check that Python 3.8+ is installed
2. Ensure `.env` file has valid API keys
3. Try reinstalling: Delete `.venv` folder and run the script again
4. Check GitHub issues for known problems
