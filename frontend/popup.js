// Enhanced popup.js with modern UI and detailed analysis
class DigitalRakshaPopup {
    constructor() {
        this.API_URL = "https://digital-raksha-2.onrender.com/scan";
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadSettings();
    }

    setupEventListeners() {
        document.getElementById("scanBtn").addEventListener("click", () => this.scanCurrentTab());
        document.getElementById("settingsBtn").addEventListener("click", () => this.openSettings());
        document.getElementById("historyBtn").addEventListener("click", () => this.openHistory());
    }

    async loadSettings() {
        try {
            const result = await chrome.storage.sync.get(['threatLevel', 'voiceEnabled', 'autoBlock']);
            this.settings = {
                threatLevel: result.threatLevel || 'medium',
                voiceEnabled: result.voiceEnabled !== false,
                autoBlock: result.autoBlock !== false
            };
        } catch (err) {
            this.settings = {
                threatLevel: 'medium',
                voiceEnabled: true,
                autoBlock: true
            };
        }
    }

    async scanCurrentTab() {
        const scanBtn = document.getElementById("scanBtn");
        const loading = document.getElementById("loading");
        const result = document.getElementById("result");

        // Show loading state
        scanBtn.disabled = true;
        scanBtn.textContent = "🔄 Scanning...";
        loading.style.display = "block";
        result.style.display = "none";

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (!tab || !tab.url) {
                throw new Error("No active tab found");
            }

            const response = await fetch(this.API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: tab.url })
            });

            if (!response.ok) {
                throw new Error(`Server error: ${response.status}`);
            }

            const data = await response.json();
            this.displayResults(data, tab.url);

        } catch (err) {
            this.displayError(err.message);
        } finally {
            // Reset button state
            scanBtn.disabled = false;
            scanBtn.textContent = "🔍 Scan Current Tab";
            loading.style.display = "none";
        }
    }

    displayResults(data, url) {
        const result = document.getElementById("result");
        const threatLevel = data.threat_level?.toLowerCase() || (data.safe ? 'safe' : 'high');
        const confidence = data.confidence || 0;
        const riskScore = data.risk_score || data.score || 0;

        // Create threat level display
        const threatLevelHtml = this.createThreatLevelHtml(threatLevel, data.message);
        
        // Create details section
        const detailsHtml = this.createDetailsHtml(data, url, confidence, riskScore);
        
        // Create threats list
        const threatsHtml = this.createThreatsHtml(data.threats || []);
        
        // Create actions
        const actionsHtml = this.createActionsHtml(data, url);

        result.innerHTML = `
            ${threatLevelHtml}
            ${detailsHtml}
            ${threatsHtml}
            ${actionsHtml}
        `;

        result.style.display = "block";
    }

    createThreatLevelHtml(level, message) {
        const emojis = {
            safe: "✅",
            low: "ℹ️",
            medium: "⚡",
            high: "⚠️",
            critical: "🚨"
        };

        return `
            <div class="threat-level ${level}">
                ${emojis[level] || "❓"} ${level.toUpperCase()}
                <div style="font-size: 14px; margin-top: 5px; opacity: 0.9;">
                    ${message}
                </div>
            </div>
        `;
    }

    createDetailsHtml(data, url, confidence, riskScore) {
        const hostname = data.hostname || new URL(url).hostname;
        const evidenceCount = data.evidence?.length || 0;
        const confidencePercent = Math.round(confidence * 100);

        return `
            <div class="details">
                <div class="detail-row">
                    <span class="detail-label">🌐 Hostname</span>
                    <span class="detail-value">${hostname}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">📊 Risk Score</span>
                    <span class="detail-value">${riskScore.toFixed(1)}/10</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">🎯 Confidence</span>
                    <span class="detail-value">${confidencePercent}%</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">🔍 Evidence</span>
                    <span class="detail-value">${evidenceCount} indicators</span>
                </div>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${confidencePercent}%"></div>
                </div>
            </div>
        `;
    }

    createThreatsHtml(threats) {
        if (!threats || threats.length === 0) {
            return `
                <div class="threats-list">
                    <h4>✅ No Threats Detected</h4>
                    <div class="threat-item" style="border-left-color: #4CAF50;">
                        This URL appears to be safe based on our analysis.
                    </div>
                </div>
            `;
        }

        const threatItems = threats.map(threat => `
            <div class="threat-item">
                ${threat}
            </div>
        `).join('');

        return `
            <div class="threats-list">
                <h4>⚠️ Detected Threats (${threats.length})</h4>
                ${threatItems}
            </div>
        `;
    }

    createActionsHtml(data, url) {
        const isUnsafe = !data.safe;
        const canProceed = isUnsafe && this.settings.autoBlock;

        return `
            <div class="actions">
                ${isUnsafe ? `
                    <button class="action-btn secondary" onclick="window.close()">
                        🚫 Block & Close
                    </button>
                    ${canProceed ? `
                        <button class="action-btn primary" onclick="this.proceedAnyway('${url}')">
                            ⚠️ Proceed Anyway
                        </button>
                    ` : ''}
                ` : `
                    <button class="action-btn primary" onclick="this.openUrl('${url}')">
                        🌐 Visit Site
                    </button>
                `}
                <button class="action-btn secondary" onclick="this.reportIssue('${url}')">
                    📝 Report Issue
                </button>
            </div>
        `;
    }

    displayError(message) {
        const result = document.getElementById("result");
        result.innerHTML = `
            <div class="error">
                <strong>❌ Scan Failed</strong><br>
                ${message}<br><br>
                <small>Make sure the Digital Raksha server is running on port 5000</small>
            </div>
        `;
        result.style.display = "block";
    }

    // Action methods
    proceedAnyway(url) {
        chrome.tabs.update({ url: url });
        window.close();
    }

    openUrl(url) {
        chrome.tabs.update({ url: url });
        window.close();
    }

    reportIssue(url) {
        const subject = `Digital Raksha False Positive Report - ${url}`;
        const body = `URL: ${url}\n\nPlease describe the issue:\n\n`;
        const mailtoUrl = `mailto:support@digitalraksha.com?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
        window.open(mailtoUrl);
    }

    openSettings() {
        // Open settings page (to be implemented)
        chrome.tabs.create({ url: chrome.runtime.getURL('settings.html') });
    }

    openHistory() {
        // Open history page (to be implemented)
        chrome.tabs.create({ url: chrome.runtime.getURL('history.html') });
    }
}

// Initialize the popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new DigitalRakshaPopup();
});
