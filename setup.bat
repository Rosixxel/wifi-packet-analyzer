@echo off
REM WiFi Packet Analyzer Setup Script for Windows
REM This script installs all required dependencies

echo.
echo ========================================
echo WiFi Packet Analyzer - Setup Wizard
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://www.python.org
    pause
    exit /b 1
)

echo [SUCCESS] Python is installed
python --version
echo.

REM Check for administrator privileges
net session >nul 2>&1
if errorlevel 1 (
    echo [WARNING] This script requires Administrator privileges
    echo Please run this as Administrator
    pause
    exit /b 1
)

echo [SUCCESS] Running with Administrator privileges
echo.

REM Install pip dependencies
echo [*] Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install Python dependencies
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Python dependencies installed!
echo.

REM Check for Npcap
echo [*] Checking for Npcap installation...
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Nmap\Npcap" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Npcap is not installed
    echo.
    echo Npcap is REQUIRED for packet capture on Windows
    echo.
    echo Would you like to download Npcap now? (Y/N)
    set /p install_npcap=Enter choice: 
    
    if /i "%install_npcap%"=="Y" (
        echo [*] Opening Npcap download page...
        start https://nmap.org/npcap/
        echo.
        echo Please install Npcap with these settings:
        echo - Choose "Install Npcap in WinPcap API-compatible Mode"
        echo - Allow installation of packet capture driver
        echo.
        pause
    )
) else (
    echo [SUCCESS] Npcap is installed!
)

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To start the analyzer, run:
echo   python wifi_analyzer.py
echo.
echo For help, run:
echo   python wifi_analyzer.py -h
echo.
echo To list available interfaces, run:
echo   python wifi_analyzer.py --list-interfaces
echo.
pause
