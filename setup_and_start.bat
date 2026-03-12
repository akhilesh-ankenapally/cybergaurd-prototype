@echo off
echo ============================================================
echo   CyberGuard - Setup and Start
echo ============================================================
echo.

:: Step 1: Install dependencies
echo [1/3] Installing Python dependencies...
pip install -r backend\requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: pip install failed. Make sure Python 3.9+ is installed.
    pause
    exit /b 1
)

:: Step 2: Train model
echo.
echo [2/3] Training AI model (downloads dataset automatically)...
python backend\model_training.py
if %errorlevel% neq 0 (
    echo ERROR: Model training failed. Check your internet connection.
    pause
    exit /b 1
)

:: Step 3: Start API server
echo.
echo [3/3] Starting CyberGuard API Server...
echo       API will be available at: http://localhost:8000
echo       API Docs:                 http://localhost:8000/docs
echo.
python backend\api_server.py
