@echo off
REM FEPD Launcher - Ensures venv is activated
REM This script activates the virtual environment and runs FEPD

echo ========================================
echo FEPD - Forensic Evidence Processing
echo ========================================
echo.

REM Check if venv exists
if not exist ".venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found!
    echo Please create it first:
    echo   python -m venv .venv
    echo   .venv\Scripts\activate
    echo   pip install -r requirements.txt
    pause
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call .venv\Scripts\activate.bat

REM Check if ML libraries are installed
python -c "import sklearn, tensorflow" 2>nul
if errorlevel 1 (
    echo.
    echo WARNING: ML libraries not installed!
    echo Installing required packages...
    pip install scikit-learn tensorflow pandas numpy
)

REM Run FEPD
echo.
echo Starting FEPD...
echo.
python main.py

REM Keep window open if error occurs
if errorlevel 1 (
    echo.
    echo ERROR: FEPD crashed!
    pause
)
