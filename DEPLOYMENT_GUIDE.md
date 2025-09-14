# 🚀 Digital Raksha Deployment Guide

## 📋 Prerequisites

### 1. Google Cloud Platform Setup
- [ ] Google Cloud account (free tier available)
- [ ] Google Cloud SDK installed
- [ ] Project created in Google Cloud Console

### 2. Local Development
- [ ] Python 3.11+ installed
- [ ] Git installed
- [ ] Chrome/Chromium browser

## 🌐 Step-by-Step Deployment

### Step 1: Prepare Your Repository

1. **Initialize Git repository** (if not already done):
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Digital Raksha v2.0"
   ```

2. **Create GitHub repository**:
   - Go to GitHub.com
   - Click "New repository"
   - Name it "digital-raksha"
   - Make it public (for free hosting)
   - Don't initialize with README (we already have one)

3. **Push to GitHub**:
   ```bash
   git remote add origin https://github.com/yourusername/digital-raksha.git
   git branch -M main
   git push -u origin main
   ```

### Step 2: Google Cloud Setup

1. **Install Google Cloud SDK**:
   - Download from: https://cloud.google.com/sdk/docs/install
   - Follow installation instructions for your OS

2. **Authenticate with Google Cloud**:
   ```bash
   gcloud auth login
   gcloud auth application-default login
   ```

3. **Create a new project**:
   ```bash
   gcloud projects create digital-raksha-2024
   gcloud config set project digital-raksha-2024
   ```

4. **Enable required APIs**:
   ```bash
   gcloud services enable appengine.googleapis.com
   gcloud services enable cloudbuild.googleapis.com
   ```

### Step 3: Deploy to Google App Engine

#### Option A: Quick Deploy (Windows)
```bash
# Run the deployment script
deploy.bat
```

#### Option B: Manual Deploy
```bash
# Deploy to App Engine
gcloud app deploy app.yaml

# Get your app URL
gcloud app browse
```

### Step 4: Update Browser Extension

1. **Update the API URL** in your extension:
   - Open `frontend/background.js`
   - Change `API_URL` to your deployed URL:
   ```javascript
   const API_URL = "https://your-project-id.appspot.com/scan";
   ```

2. **Reload the extension**:
   - Go to `chrome://extensions/`
   - Click the refresh button on your extension

## 🔧 Configuration

### Environment Variables (Optional)

Set these in Google Cloud Console under App Engine > Settings:

```bash
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
BLOCK_THRESHOLD=4.0
SCAN_CACHE_TTL=300
```

### Custom Domain (Optional)

1. **Add custom domain** in Google Cloud Console
2. **Update CORS settings** in `server.py` if needed
3. **Update extension** with new domain

## 📊 Monitoring

### View Logs
```bash
gcloud app logs tail -s default
```

### Check Status
```bash
gcloud app describe
```

### View Metrics
- Go to Google Cloud Console
- Navigate to App Engine > Instances
- View performance metrics

## 🔄 Updates and Maintenance

### Deploy Updates
```bash
# Make your changes
git add .
git commit -m "Update: description of changes"
git push origin main

# Deploy to App Engine
gcloud app deploy app.yaml
```

### Rollback (if needed)
```bash
gcloud app versions list
gcloud app services set-traffic default --splits=VERSION_NUMBER=1
```

## 💰 Cost Management

### Google Cloud Free Tier Limits
- **App Engine**: 28 frontend instance hours per day
- **Bandwidth**: 1 GB per day
- **Storage**: 5 GB
- **API Calls**: 1,000 per day

### Optimize for Free Tier
- **Instance scaling**: Set to 1-2 instances max
- **Caching**: Use in-memory cache (already implemented)
- **Efficient code**: Minimal resource usage

## 🐛 Troubleshooting

### Common Issues

1. **Deployment fails**:
   ```bash
   gcloud app logs tail -s default
   ```

2. **Extension can't connect**:
   - Check CORS settings
   - Verify API URL is correct
   - Check browser console for errors

3. **High memory usage**:
   - Reduce cache size
   - Optimize ML model loading
   - Check for memory leaks

### Debug Mode

Run locally for debugging:
```bash
python server.py
```

## 📈 Performance Optimization

### Backend Optimizations
- ✅ **Caching**: In-memory cache with TTL
- ✅ **Efficient ML**: Lazy loading of models
- ✅ **Error Handling**: Graceful fallbacks
- ✅ **Logging**: Structured monitoring

### Frontend Optimizations
- ✅ **Lazy Loading**: Load components on demand
- ✅ **Caching**: Store settings and history locally
- ✅ **Efficient UI**: Minimal DOM updates
- ✅ **Error Handling**: User-friendly error messages

## 🔒 Security Considerations

### Production Security
- ✅ **HTTPS Only**: All communications encrypted
- ✅ **Input Validation**: Comprehensive URL validation
- ✅ **Error Handling**: No sensitive data in errors
- ✅ **CORS**: Proper cross-origin settings

### Extension Security
- ✅ **Permissions**: Minimal required permissions
- ✅ **Content Security**: Safe content script execution
- ✅ **Data Privacy**: No personal data collection

## 📞 Support

### Getting Help
- **GitHub Issues**: Report bugs and request features
- **Google Cloud Support**: For deployment issues
- **Documentation**: Check this guide and README

### Useful Commands
```bash
# Check deployment status
gcloud app describe

# View recent logs
gcloud app logs tail -s default --limit=50

# List all versions
gcloud app versions list

# Set traffic to specific version
gcloud app services set-traffic default --splits=VERSION=1
```

## 🎉 Success!

Once deployed, your Digital Raksha system will be available at:
- **API**: `https://your-project-id.appspot.com`
- **Health Check**: `https://your-project-id.appspot.com/health`
- **Scan Endpoint**: `https://your-project-id.appspot.com/scan`

Your browser extension will automatically use the deployed backend for real-time URL security analysis!

---

**Happy Deploying!** 🚀✨
