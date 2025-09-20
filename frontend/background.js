const DEFAULT_BACKEND = "https://digital-raksha-2.onrender.com/scan";

let SETTINGS = {
    serverUrl: DEFAULT_BACKEND,
    autoBlock: true,
    keepHistory: true
};


// Load settings from sync storage
async function loadSettings() {
    try {
        let result = {};
        try {
            result = await chrome.storage.sync.get(['serverUrl', 'autoBlock', 'keepHistory']);
        } catch {}
        if (!result || Object.keys(result).length === 0) {
            try {
                result = await chrome.storage.local.get(['serverUrl', 'autoBlock', 'keepHistory']);
            } catch {}
        }
        SETTINGS.serverUrl = result.serverUrl || SETTINGS.serverUrl;
        SETTINGS.autoBlock = result.autoBlock !== false;
        SETTINGS.keepHistory = result.keepHistory !== false;
    } catch (e) {
        // Keep defaults
    }
}

// Listen for settings updates from settings page
chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === 'SETTINGS_UPDATE' && msg.settings) {
        SETTINGS.serverUrl = msg.settings.serverUrl || SETTINGS.serverUrl;
        SETTINGS.autoBlock = msg.settings.autoBlock !== false;
        SETTINGS.keepHistory = msg.settings.keepHistory !== false;
    }
});

// Initialize settings on service worker start
loadSettings();

// Enhanced blocking logic
function shouldBlockSite(data, threatLevel) {
    // Always block critical threats
    if (threatLevel === 'critical') return true;
    
    // Block high threats if auto-block is enabled
    if (threatLevel === 'high' && SETTINGS.autoBlock) return true;
    
    // Block if explicitly marked unsafe
    if (!data.safe && SETTINGS.autoBlock) return true;
    
    return false;
}

function blockSite(tabId, data, threatLevel) {
    const threatText = data.threat_label || data.threats?.join(', ') || 'security threat';
    const riskScore = data.risk_score || data.score || 0;
    const confidence = data.confidence || 0;
    
    const warningHtml = `
<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Digital Raksha Security Warning</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            color: white;
            margin: 0;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
        }
        .container {
            max-width: 600px;
            text-align: center;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        .icon {
            font-size: 80px;
            margin-bottom: 20px;
        }
        h1 {
            font-size: 32px;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }
        .threat-level {
            background: rgba(255, 255, 255, 0.2);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            font-size: 18px;
            font-weight: bold;
        }
        .details {
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: left;
        }
        .detail-row {
            display: flex;
            justify-content: space-between;
            margin: 10px 0;
            padding: 5px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        .buttons {
            margin-top: 30px;
        }
        .btn {
            background: rgba(255, 255, 255, 0.2);
            color: white;
            border: 2px solid rgba(255, 255, 255, 0.3);
            padding: 12px 24px;
            margin: 0 10px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        .btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }
        .btn.primary {
            background: rgba(255, 255, 255, 0.9);
            color: #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">${threatLevel === 'critical' ? '🚨' : '⚠️'}</div>
        <h1>Security Threat Blocked</h1>
        <div class="threat-level">
            ${threatLevel.toUpperCase()} RISK DETECTED
        </div>
        <div class="details">
            <div class="detail-row">
                <span>Risk Score:</span>
                <span>${riskScore.toFixed(1)}/10</span>
            </div>
            <div class="detail-row">
                <span>Confidence:</span>
                <span>${Math.round(confidence * 100)}%</span>
            </div>
            <div class="detail-row">
                <span>Threats:</span>
                <span>${data.threats?.length || 0} detected</span>
            </div>
        </div>
        <p><strong>Reason:</strong> ${threatText}</p>
        <p>This page was blocked by Digital Raksha to protect your security.</p>
        <div class="buttons">
            <button class="btn" onclick="history.back()">← Go Back</button>
            <button class="btn primary" onclick="proceedAnyway()">⚠️ Proceed Anyway</button>
        </div>
    </div>
    <script>
        function proceedAnyway() {
            if (confirm('Are you sure you want to proceed? This site may be dangerous.')) {
                // This would need to be handled by the extension
                history.back();
            }
        }
    </script>
</body>
</html>`;
    
    const dataUrl = "data:text/html;charset=utf-8," + encodeURIComponent(warningHtml);
    chrome.tabs.update(tabId, { url: dataUrl });
}

// Store scan history
async function storeScanHistory(data, url) {
    try {
        if (!SETTINGS.keepHistory) return;
        // Get existing history
        const result = await chrome.storage.local.get(['scanHistory']);
        let history = result.scanHistory || [];
        
        // Create history entry
        const level = (data.threat_level || (data.safe ? 'safe' : 'high')).toLowerCase();
        const historyEntry = {
            url: url,
            hostname: data.hostname || new URL(url).hostname,
            threatLevel: level,
            threat_level: level,
            riskScore: data.risk_score || data.score || 0,
            confidence: data.confidence || 0,
            threats: data.threats || [],
            safe: data.safe,
            timestamp: new Date().toISOString(),
            evidence: data.evidence || []
        };
        
        // Add to history (prepend to keep newest first)
        history.unshift(historyEntry);
        
        // Keep only last 1000 entries to prevent storage bloat
        if (history.length > 1000) {
            history = history.slice(0, 1000);
        }
        
        // Save back to storage
        await chrome.storage.local.set({ scanHistory: history });
        
    } catch (err) {
        console.error('Failed to store scan history:', err);
    }
}

chrome.webNavigation.onCompleted.addListener(async (details) => {
    if (details.frameId !== 0) return; // main frame only
    const url = details.url;
    if (!/^https?:\/\//i.test(url)) return; // only http/https

    try {
        // Use fetch with mode 'cors' to avoid CORS issues
        const res = await fetch(SETTINGS.serverUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
            mode: "cors"
        });

        // Check if response is OK
        if (!res.ok) throw new Error(`Server responded with ${res.status}`);

        const data = await res.json();

        // Enhanced threat level-based alerting
        const threatLevel = data.threat_level?.toLowerCase() || (data.safe ? 'safe' : 'high');
        const riskScore = data.risk_score || data.score || 0;
        
        // Send appropriate alert based on threat level
        if (threatLevel === 'critical') {
            chrome.tabs.sendMessage(details.tabId, {
                type: "ALERT_CRITICAL",
                data
            });
        } else if (!data.safe) {
            chrome.tabs.sendMessage(details.tabId, {
                type: "ALERT_UNSAFE",
                data
            });
        } else if (data.safe && riskScore > 0) {
            chrome.tabs.sendMessage(details.tabId, {
                type: "ALERT_INFO",
                data
            });
        }

        // Enhanced blocking logic based on threat level and user settings
        const shouldBlock = shouldBlockSite(data, threatLevel);
        
        if (shouldBlock) {
            // Show alert first, then block
            setTimeout(() => {
                blockSite(details.tabId, data, threatLevel);
            }, 1500);
        }

        // Store scan history
        await storeScanHistory(data, url);
    } catch (err) {
        console.error("Auto-scan error:", err);
    }
});







