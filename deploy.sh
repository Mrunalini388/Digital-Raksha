#!/bin/bash

# Digital Raksha Deployment Script for Google Cloud Platform

echo "🛡️ Digital Raksha Deployment Script"
echo "====================================="

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Google Cloud SDK not found. Please install it first:"
    echo "   https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if user is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
    echo "🔐 Please authenticate with Google Cloud:"
    gcloud auth login
fi

# Set project (replace with your project ID)
echo "📋 Setting up project..."
read -p "Enter your Google Cloud Project ID: " PROJECT_ID
gcloud config set project $PROJECT_ID

# Enable required APIs
echo "🔧 Enabling required APIs..."
gcloud services enable appengine.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# Deploy to App Engine
echo "🚀 Deploying to Google App Engine..."
gcloud app deploy app.yaml --quiet

# Get the deployed URL
echo "✅ Deployment complete!"
echo "🌐 Your app is available at:"
gcloud app browse

echo ""
echo "📋 Next steps:"
echo "1. Update your browser extension to use the deployed URL"
echo "2. Test the API endpoints"
echo "3. Configure environment variables if needed"
echo ""
echo "🔗 API Endpoints:"
echo "   Health: https://your-project-id.appspot.com/health"
echo "   Scan: https://your-project-id.appspot.com/scan"
echo "   Stats: https://your-project-id.appspot.com/stats"
