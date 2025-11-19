@echo off
REM VigilantEye Installation Script for Windows
REM This script automates the setup process for VigilantEye

setlocal enabledelayedexpansion

color 0A
echo ================================
echo VigilantEye Setup - Windows
echo ================================
echo.

REM Check if Python is installed
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.8+ from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [OK] Python !PYTHON_VERSION! found
echo.

REM Create virtual environment
echo [2/5] Creating virtual environment...
if exist ".venv" (
    echo [OK] Virtual environment already exists
) else (
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created
)
echo.

REM Activate virtual environment
echo [3/5] Activating virtual environment...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)
echo [OK] Virtual environment activated
echo.

REM Upgrade pip
echo [4/5] Upgrading pip, setuptools, and wheel...
python -m pip install --upgrade pip setuptools wheel >nul 2>&1
if errorlevel 1 (
    echo [WARNING] pip upgrade had issues, continuing anyway...
) else (
    echo [OK] pip and tools updated
)
echo.

REM Install requirements
echo [5/5] Installing dependencies...
pip install -r requirements.txt >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    echo Check pip and try: pip install -r requirements.txt
    pause
    exit /b 1
)
echo [OK] Core dependencies installed
echo.

REM Install the VigilantEye package itself
echo Installing VigilantEye package...
pip install -e . >nul 2>&1
if errorlevel 1 (
    echo [WARNING] VigilantEye package installation had issues
) else (
    echo [OK] VigilantEye package installed
)
echo.

REM Install optional streamlit for dashboard
echo Installing optional Streamlit for dashboard...
pip install streamlit >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Streamlit installation skipped (dashboard won't work^)
    echo To install later: pip install streamlit
) else (
    echo [OK] Streamlit installed (dashboard ready^)
)
echo.

REM Create .env from .env.example if it doesn't exist
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo [OK] Created .env file from .env.example
        echo.
        echo [IMPORTANT] Edit .env file with your API keys:
        echo    - VirusTotal API Key (required^)
        echo    - AbuseIPDB API Key (required^)
        echo    - MalwareBazaar API Key (optional^)
        echo.
        echo Command to edit: notepad .env  (or use any text editor^)
    ) else (
        echo [WARNING] .env.example not found. Create .env manually.
    )
) else (
    echo [OK] .env file already exists
)

echo.
echo ================================
echo [SUCCESS] Installation Complete!
echo ================================
echo.
echo Next steps:
echo 1. Edit .env with your API keys
echo 2. Activate: .venv\Scripts\activate.bat
echo 3. Test: vigilanteye 8.8.8.8
echo 4. Dashboard: streamlit run dashboard.py
echo.
pause
