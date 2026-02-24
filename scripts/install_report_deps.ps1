# FEPD Report Generation - Installation Script
# This script installs the required dependency for PDF report generation

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "FEPD - PDF Report Generation Setup" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python not found! Please install Python first." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Installing ReportLab library for PDF generation..." -ForegroundColor Yellow
Write-Host ""

# Install reportlab
try {
    python -m pip install --upgrade reportlab
    Write-Host ""
    Write-Host "✓ ReportLab installed successfully!" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "✗ Failed to install ReportLab" -ForegroundColor Red
    Write-Host "Please try manually: pip install reportlab" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Installation Complete!" -ForegroundColor Green
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""
Write-Host "You can now generate professional PDF reports from FEPD." -ForegroundColor Green
Write-Host "Navigate to: File → Generate Report (or use Report tab)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Documentation: docs/Report_Generation_Guide.md" -ForegroundColor Yellow
Write-Host ""
