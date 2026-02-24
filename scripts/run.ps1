# FEPD Run Script - PowerShell
# Quick launcher for FEPD application

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  FEPD - Forensic Evidence Parser Dashboard" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path "venv")) {
    Write-Host "ERROR: Virtual environment not found!" -ForegroundColor Red
    Write-Host "Please run installation first: .\scripts\install.ps1" -ForegroundColor Yellow
    exit 1
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1

# Check if main.py exists
if (-not (Test-Path "main.py")) {
    Write-Host "ERROR: main.py not found!" -ForegroundColor Red
    exit 1
}

# Run application
Write-Host "Starting FEPD..." -ForegroundColor Green
Write-Host ""
python main.py

# Deactivate on exit
deactivate
