# FEPD Installation Script - PowerShell
# Installs FEPD and dependencies in a virtual environment

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  FEPD Installation Script" -ForegroundColor Cyan
Write-Host "  Forensic Evidence Parser Dashboard" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check Python version
Write-Host "[1/7] Checking Python installation..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Python not found. Please install Python 3.10 or higher." -ForegroundColor Red
    exit 1
}

Write-Host "Found: $pythonVersion" -ForegroundColor Green

# Parse version
$versionMatch = $pythonVersion -match "Python (\d+)\.(\d+)"
if ($versionMatch) {
    $major = [int]$Matches[1]
    $minor = [int]$Matches[2]
    
    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
        Write-Host "ERROR: Python 3.10 or higher required. Found: $pythonVersion" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "WARNING: Could not parse Python version" -ForegroundColor Yellow
}

# Create virtual environment
Write-Host ""
Write-Host "[2/7] Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "Virtual environment already exists. Skipping..." -ForegroundColor Green
} else {
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
    Write-Host "Virtual environment created successfully" -ForegroundColor Green
}

# Activate virtual environment
Write-Host ""
Write-Host "[3/7] Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1
Write-Host "Virtual environment activated" -ForegroundColor Green

# Upgrade pip
Write-Host ""
Write-Host "[4/7] Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Failed to upgrade pip" -ForegroundColor Yellow
} else {
    Write-Host "pip upgraded successfully" -ForegroundColor Green
}

# Install requirements
Write-Host ""
Write-Host "[5/7] Installing dependencies..." -ForegroundColor Yellow
Write-Host "This may take several minutes..." -ForegroundColor Cyan
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install dependencies" -ForegroundColor Red
    exit 1
}
Write-Host "Dependencies installed successfully" -ForegroundColor Green

# Create .env from example
Write-Host ""
Write-Host "[6/7] Creating configuration..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Write-Host ".env file already exists. Skipping..." -ForegroundColor Green
} else {
    Copy-Item ".env.example" ".env"
    Write-Host ".env file created from template" -ForegroundColor Green
    Write-Host "Please review and customize .env for your environment" -ForegroundColor Cyan
}

# Create necessary directories
Write-Host ""
Write-Host "[7/7] Creating directories..." -ForegroundColor Yellow
$dirs = @("logs", "data/cases", "data/workspace", "reports")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "Created: $dir" -ForegroundColor Green
    }
}

# Installation complete
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "To run FEPD:" -ForegroundColor Cyan
Write-Host "  1. Activate virtual environment: .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "  2. Run application: python main.py" -ForegroundColor White
Write-Host ""
Write-Host "For offline installation:" -ForegroundColor Cyan
Write-Host "  pip download -r requirements.txt -d ./offline_packages" -ForegroundColor White
Write-Host ""
Write-Host "Documentation: README.md" -ForegroundColor Cyan
Write-Host "Configuration: .env" -ForegroundColor Cyan
Write-Host ""
