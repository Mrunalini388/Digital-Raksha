@echo off
REM Digital Raksha Deployment Script for Google Cloud Platform

echo 🛡️ Digital Raksha Deployment Script
echo =====================================

REM Check if gcloud is installed
gcloud version >nul 2>&1
if errorlevel 1 (
    echo ❌ Google Cloud SDK not found. Please install it first:
    echo    https://cloud.google.com/sdk/docs/install
    pause
    exit /b 1
)

REM Check if user is authenticated
gcloud auth list --filter=status:ACTIVE --format="value(account)" >nul 2>&1
if errorlevel 1 (
    echo 🔐 Please authenticate with Google Cloud:
    gcloud auth login
)

REM Set project
echo 📋 Setting up project...
set /p PROJECT_ID="Enter your Google Cloud Project ID: "
gcloud config set project %PROJECT_ID%

REM Enable required APIs
echo 🔧 Enabling required APIs...
gcloud services enable appengine.googleapis.com
gcloud services enable cloudbuild.googleapis.com

REM Deploy to App Engine
echo 🚀 Deploying to Google App Engine...
gcloud app deploy app.yaml --quiet

REM Get the deployed URL
echo ✅ Deployment complete!
echo 🌐 Your app is available at:
gcloud app browse

echo.
echo 📋 Next steps:
echo 1. Update your browser extension to use the deployed URL
echo 2. Test the API endpoints
echo 3. Configure environment variables if needed
echo.
echo 🔗 API Endpoints:
echo    Health: https://%PROJECT_ID%.appspot.com/health
echo    Scan: https://%PROJECT_ID%.appspot.com/scan
echo    Stats: https://%PROJECT_ID%.appspot.com/stats

pause
