# Quick Installation Guide

This guide provides the fastest way to install and run VigilantEye on your system.

**Note:** VigilantEye works system-wide without requiring a virtual environment!

## For macOS and Linux Users

Open Terminal and run:

```bash
cd /path/to/VigilantEye
chmod +x install.sh
./install.sh
```

After installation, **restart your terminal** or run:
```bash
source ~/.zshrc    # for zsh
# or
source ~/.bashrc   # for bash
```

## For Windows Users

Open Command Prompt or PowerShell and run:

```cmd
cd C:\path\to\VigilantEye
install.bat
```

After installation, **restart your terminal** or command prompt.

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

After installation, you can immediately use VigilantEye from anywhere in your terminal:

```bash
# Show help
vigilanteye --help
# or use the short alias:
vg --help

# Basic threat check (IP, domain, URL, or hash)
vigilanteye 8.8.8.8
vg 8.8.8.8

# Interactive mode
vigilanteye --interactive
vg --interactive

# Detailed JSON output
vigilanteye example.com --detailed --json
vg example.com --detailed --json

# Uninstall VigilantEye from system
vigilanteye --destroy
vg --destroy

# Optional: Start the dashboard
streamlit run dashboard.py
```

## Troubleshooting

**Python not found:**
- Install Python 3.8+ from https://www.python.org/downloads/
- Windows: Make sure "Add Python to PATH" is checked during installation

**pip install fails:**
- Try: `python3 -m pip install --upgrade pip` before running the script again
- On Arch Linux: May need `--break-system-packages` flag (handled automatically by install script)
- On Linux/Mac: May need `sudo` or use `python3 -m pip` instead

**Commands not found after installation:**
- Restart your terminal or run: `source ~/.zshrc` (or `source ~/.bashrc`)
- Check if `~/.local/bin` is in your PATH: `echo $PATH | grep .local/bin`
- Manually add to PATH: `export PATH="$HOME/.local/bin:$PATH"` (add to ~/.zshrc or ~/.bashrc)

**Arch Linux / externally-managed-environment error:**
- The install script automatically handles this with `--break-system-packages` flag
- If issues persist, run: `python3 -m pip install --user --break-system-packages -r requirements.txt`

## Next Steps

1. Edit `.env` with your API keys
2. Restart your terminal (or run `source ~/.zshrc` / `source ~/.bashrc`)
3. Test with: `vigilanteye 8.8.8.8` or `vg 8.8.8.8`
4. Try detailed mode: `vg example.com --detailed`
5. For dashboard: `streamlit run dashboard.py`

## Uninstallation

To completely remove VigilantEye from your system:

```bash
vigilanteye --destroy
# or
vg --destroy
# or manually:
bash uninstall.sh
```

This removes all components including commands, packages, cache, and PATH entries.

## Support

If you encounter issues:
1. Check that Python 3.8+ is installed
2. Ensure `.env` file has valid API keys
3. Try reinstalling: Run `./install.sh` again (no need to delete anything)
4. Check that `~/.local/bin` is in your PATH
5. Check GitHub issues for known problems
