# 🛡️ Digital Raksha - Advanced URL Security Scanner

A comprehensive browser extension and backend service that provides real-time URL security analysis using advanced machine learning and rule-based detection.

## ✨ Features

### 🔍 Enhanced Detection
- **5-Level Threat Classification**: SAFE, LOW, MEDIUM, HIGH, CRITICAL
- **Typosquatting Detection**: Identifies domain name variations
- **Domain Reputation Analysis**: TLD and pattern analysis
- **Advanced Feature Extraction**: 20+ sophisticated URL features
- **Confidence Scoring**: Multi-factor confidence assessment
- **VirusTotal Integration**: External threat intelligence

### 🎨 Modern Frontend
- **Beautiful Popup UI**: Professional, responsive design
- **Threat Level Indicators**: Color-coded visual alerts
- **Voice Alerts**: Natural language announcements
- **Settings Management**: Comprehensive configuration
- **Analytics Dashboard**: Scan history and statistics
- **Real-time Notifications**: Smart popup alerts

### ⚙️ Advanced Backend
- **RESTful API**: Clean, documented endpoints
- **Intelligent Caching**: Performance optimization
- **Error Handling**: Robust error management
- **Logging**: Structured monitoring
- **Scalable Architecture**: Cloud-ready deployment

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Chrome/Chromium browser
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/digital-raksha.git
   cd digital-raksha
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the backend server**
   ```bash
   python server.py
   ```

4. **Load the browser extension**
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the `frontend/` folder

## 🌐 Deployment

### Google Cloud Platform (Free Tier)

1. **Install Google Cloud SDK**
   ```bash
   # Download from: https://cloud.google.com/sdk/docs/install
   gcloud init
   ```

2. **Deploy to App Engine**
   ```bash
   gcloud app deploy
   ```

3. **Access your application**
   ```bash
   gcloud app browse
   ```

### Environment Variables
```bash
# Optional: VirusTotal API for enhanced detection
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Optional: Adjust detection sensitivity
BLOCK_THRESHOLD=4.0

# Optional: Cache duration in seconds
SCAN_CACHE_TTL=300
```

## 📖 API Documentation

### Endpoints

#### `POST /scan`
Scan a URL for security threats.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "hostname": "example.com",
  "safe": true,
  "threat_level": "SAFE",
  "risk_score": 0.5,
  "confidence": 0.8,
  "threats": [],
  "message": "✅ Safe browsing!",
  "evidence": []
}
```

#### `GET /health`
Check server health and version.

#### `GET /stats`
Get server statistics and cache information.

#### `GET /config`
Get current server configuration.

## 🔧 Configuration

### Threat Level Thresholds
- **CRITICAL**: Risk score ≥ 8 or (≥ 6 with high confidence)
- **HIGH**: Risk score ≥ 5 or (≥ 3 with medium confidence)
- **MEDIUM**: Risk score ≥ 3 or (≥ 1 with low confidence)
- **LOW**: Risk score ≥ 1
- **SAFE**: Risk score < 1

### Extension Settings
- **Auto-block**: Enable/disable automatic blocking
- **Voice Alerts**: Toggle voice announcements
- **Threat Sensitivity**: Low, Medium, High, Strict
- **Alert Duration**: 2-10 seconds
- **Detailed Alerts**: Show/hide detailed information

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Browser       │    │   Backend       │    │   ML Models     │
│   Extension     │◄──►│   Server        │◄──►│   (Optional)    │
│                 │    │                 │    │                 │
│ • Popup UI      │    │ • URL Analysis  │    │ • URL Classifier│
│ • Content Script│    │ • Rule Engine   │    │ • HTML Analyzer │
│ • Settings      │    │ • ML Integration│    │ • Feature Extr. │
│ • History       │    │ • Caching       │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🛠️ Development

### Project Structure
```
digital-raksha/
├── frontend/              # Browser extension
│   ├── popup.html        # Main popup interface
│   ├── popup.js          # Popup functionality
│   ├── content.js        # Content script
│   ├── background.js     # Background service worker
│   ├── settings.html     # Settings page
│   ├── settings.js       # Settings functionality
│   ├── history.html      # Analytics dashboard
│   ├── history.js        # History functionality
│   └── manifest.json     # Extension manifest
├── detector.py           # Enhanced URL detector
├── server.py             # Flask backend server
├── requirements.txt      # Python dependencies
├── app.yaml             # Google App Engine config
└── README.md            # This file
```

### Adding New Features
1. **Backend**: Add new detection methods in `detector.py`
2. **API**: Add new endpoints in `server.py`
3. **Frontend**: Update UI components in `frontend/`
4. **Testing**: Test with various URLs and threat levels

## 📊 Performance

- **Response Time**: < 2 seconds average
- **Cache Hit Rate**: > 80% for repeated scans
- **Memory Usage**: < 100MB per instance
- **CPU Usage**: < 50% average load

## 🔒 Security

- **HTTPS Only**: All communications encrypted
- **Input Validation**: Comprehensive URL validation
- **Rate Limiting**: Built-in request throttling
- **Error Handling**: Secure error responses
- **Privacy**: No personal data collection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **VirusTotal** for threat intelligence API
- **scikit-learn** for machine learning capabilities
- **Flask** for the web framework
- **Chrome Extensions API** for browser integration

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/digital-raksha/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/digital-raksha/discussions)
- **Email**: support@digitalraksha.com

---

**Digital Raksha** - Protecting your digital journey, one URL at a time! 🛡️✨
