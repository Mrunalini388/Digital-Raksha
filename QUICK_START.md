# 🚀 Quick Start: Deploy Digital Raksha to Google Cloud

## ⚡ 5-Minute Deployment

### 1. Push to GitHub
```bash
# Initialize git (if not done)
git init
git add .
git commit -m "Digital Raksha v2.0 - Enhanced Security Scanner"

# Create GitHub repo and push
git remote add origin https://github.com/yourusername/digital-raksha.git
git branch -M main
git push -u origin main
```

### 2. Deploy to Google Cloud
```bash
# Install Google Cloud SDK (if not installed)
# Download from: https://cloud.google.com/sdk/docs/install

# Authenticate
gcloud auth login

# Create project
gcloud projects create digital-raksha-2024
gcloud config set project digital-raksha-2024

# Enable APIs
gcloud services enable appengine.googleapis.com

# Deploy (Windows)
deploy.bat

# OR Deploy manually
gcloud app deploy app.yaml
```

### 3. Update Extension
1. **Get your app URL**:
   ```bash
   gcloud app browse
   ```

2. **Update `frontend/background.js`**:
   ```javascript
   const API_URL = "https://your-project-id.appspot.com/scan";
   ```

3. **Reload extension** in Chrome

## ✅ Done!

Your Digital Raksha is now live on Google Cloud! 🎉

**App URL**: `https://your-project-id.appspot.com`
**Health Check**: `https://your-project-id.appspot.com/health`

## 🔧 Optional: Add VirusTotal API

1. Get API key from: https://www.virustotal.com/gui/my-apikey
2. Set in Google Cloud Console > App Engine > Settings > Environment Variables
3. Add: `VIRUSTOTAL_API_KEY=your_key_here`

## 📊 Monitor Your App

- **Logs**: `gcloud app logs tail -s default`
- **Console**: https://console.cloud.google.com/appengine
- **Metrics**: View in Google Cloud Console

---

**Need help?** Check `DEPLOYMENT_GUIDE.md` for detailed instructions! 🛡️
