# 🛡️ Digital Raksha - Advanced URL Security Scanner

A comprehensive browser extension and backend service that provides real-time URL security analysis using advanced machine learning and rule-based detection.

## Features

### 🔍 Enhanced Detection
- **5-Level Threat Classification**: SAFE, LOW, MEDIUM, HIGH, CRITICAL
- **Typosquatting Detection**: Identifies domain name variations
- **Domain Reputation Analysis**: TLD and pattern analysis
- **Advanced Feature Extraction**: 20+ sophisticated URL features
- **Confidence Scoring**: Multi-factor confidence assessment
- **VirusTotal Integration**: External threat intelligence

###  Modern Frontend
- **Beautiful Popup UI**: Professional, responsive design
- **Threat Level Indicators**: Color-coded visual alerts
- **Voice Alerts**: Natural language announcements
- **Settings Management**: Comprehensive configuration
- **Analytics Dashboard**: Scan history and statistics
- **Real-time Notifications**: Smart popup alerts

###  Advanced Backend
- **RESTful API**: Clean, documented endpoints
- **Intelligent Caching**: Performance optimization
- **Error Handling**: Robust error management
- **Logging**: Structured monitoring
- **Scalable Architecture**: Cloud-ready deployment

##  Quick Start

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

## Configuration

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

## Architecture

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




---

**Digital Raksha** - Protecting your digital journey, one URL at a time! 🛡️✨
