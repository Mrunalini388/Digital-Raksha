// Enhanced content.js with modern alerts and threat level indicators
class DigitalRakshaAlert {
    constructor() {
        this.setupMessageListener();
        this.loadSettings();
    }

    async loadSettings() {
        try {
            const result = await chrome.storage.sync.get(['voiceEnabled', 'alertDuration', 'showDetailedAlerts']);
            this.settings = {
                voiceEnabled: result.voiceEnabled !== false,
                alertDuration: result.alertDuration || 5000,
                showDetailedAlerts: result.showDetailedAlerts !== false
            };
        } catch (err) {
            this.settings = {
                voiceEnabled: true,
                alertDuration: 5000,
                showDetailedAlerts: true
            };
        }
    }

    setupMessageListener() {
        chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
            switch (msg.type) {
                case "ALERT_UNSAFE":
                    this.showUnsafeAlert(msg.data);
                    break;
                case "ALERT_INFO":
                    this.showInfoAlert(msg.data);
                    break;
                case "ALERT_CRITICAL":
                    this.showCriticalAlert(msg.data);
                    break;
            }
        });
    }

    showUnsafeAlert(data) {
        const threatLevel = data.threat_level?.toLowerCase() || 'high';
        const popup = this.createAlertPopup(data, threatLevel, 'unsafe');
        document.body.appendChild(popup);
        
        // Enhanced voice alert
        if (this.settings.voiceEnabled) {
            this.playVoiceAlert(data, threatLevel);
        }

        // Auto-remove after duration
        setTimeout(() => {
            if (popup.parentNode) {
                popup.remove();
            }
        }, this.settings.alertDuration);
    }

    showInfoAlert(data) {
        const popup = this.createAlertPopup(data, 'low', 'info');
        document.body.appendChild(popup);
        
        if (this.settings.voiceEnabled) {
            this.playVoiceAlert(data, 'low');
        }

        setTimeout(() => {
            if (popup.parentNode) {
                popup.remove();
            }
        }, this.settings.alertDuration * 0.7);
    }

    showCriticalAlert(data) {
        const popup = this.createAlertPopup(data, 'critical', 'critical');
        document.body.appendChild(popup);
        
        if (this.settings.voiceEnabled) {
            this.playVoiceAlert(data, 'critical');
        }

        // Critical alerts stay longer
        setTimeout(() => {
            if (popup.parentNode) {
                popup.remove();
            }
        }, this.settings.alertDuration * 2);
    }

    createAlertPopup(data, threatLevel, alertType) {
        const popup = document.createElement("div");
        popup.id = "digital-raksha-alert";
        
        // Base styles
        Object.assign(popup.style, {
            position: "fixed",
            top: "20px",
            right: "20px",
            width: "350px",
            maxWidth: "90vw",
            zIndex: "999999",
            borderRadius: "12px",
            boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
            fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
            fontSize: "14px",
            lineHeight: "1.4",
            overflow: "hidden",
            animation: "slideInRight 0.5s ease-out"
        });

        // Add CSS animation
        if (!document.getElementById('digital-raksha-styles')) {
            const style = document.createElement('style');
            style.id = 'digital-raksha-styles';
            style.textContent = `
                @keyframes slideInRight {
                    from { transform: translateX(100%); opacity: 0; }
                    to { transform: translateX(0); opacity: 1; }
                }
                @keyframes pulse {
                    0% { transform: scale(1); }
                    50% { transform: scale(1.02); }
                    100% { transform: scale(1); }
                }
            `;
            document.head.appendChild(style);
        }

        // Configure based on threat level
        const config = this.getThreatConfig(threatLevel, alertType);
        Object.assign(popup.style, config.styles);

        // Create content
        popup.innerHTML = this.createAlertContent(data, threatLevel, config);

        // Add close button
        const closeBtn = document.createElement("button");
        closeBtn.innerHTML = "×";
        closeBtn.style.cssText = `
            position: absolute;
            top: 8px;
            right: 8px;
            background: none;
            border: none;
            color: inherit;
            font-size: 20px;
            cursor: pointer;
            opacity: 0.7;
            padding: 0;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
        `;
        closeBtn.onclick = () => popup.remove();
        popup.appendChild(closeBtn);

        return popup;
    }

    getThreatConfig(threatLevel, alertType) {
        const configs = {
            safe: {
                styles: {
                    background: "linear-gradient(135deg, #4CAF50, #45a049)",
                    color: "white",
                    border: "2px solid #2E7D32"
                },
                icon: "✅",
                title: "Safe Site"
            },
            low: {
                styles: {
                    background: "linear-gradient(135deg, #FFC107, #FF8F00)",
                    color: "white",
                    border: "2px solid #F57F17"
                },
                icon: "ℹ️",
                title: "Low Risk"
            },
            medium: {
                styles: {
                    background: "linear-gradient(135deg, #FF9800, #F57C00)",
                    color: "white",
                    border: "2px solid #E65100"
                },
                icon: "⚡",
                title: "Medium Risk"
            },
            high: {
                styles: {
                    background: "linear-gradient(135deg, #FF5722, #D32F2F)",
                    color: "white",
                    border: "2px solid #C62828",
                    animation: "pulse 2s infinite"
                },
                icon: "⚠️",
                title: "High Risk"
            },
            critical: {
                styles: {
                    background: "linear-gradient(135deg, #F44336, #C62828)",
                    color: "white",
                    border: "2px solid #B71C1C",
                    animation: "pulse 1s infinite"
                },
                icon: "🚨",
                title: "CRITICAL THREAT"
            }
        };

        return configs[threatLevel] || configs.high;
    }

    createAlertContent(data, threatLevel, config) {
        const confidence = data.confidence || 0;
        const riskScore = data.risk_score || data.score || 0;
        const threats = data.threats || [];
        const evidenceCount = data.evidence?.length || 0;

        let content = `
            <div style="padding: 20px 20px 20px 20px;">
                <div style="display: flex; align-items: center; margin-bottom: 12px;">
                    <span style="font-size: 24px; margin-right: 10px;">${config.icon}</span>
                    <div>
                        <div style="font-weight: bold; font-size: 16px;">${config.title}</div>
                        <div style="font-size: 12px; opacity: 0.9;">Digital Raksha Protection</div>
                    </div>
                </div>
        `;

        if (this.settings.showDetailedAlerts) {
            content += `
                <div style="background: rgba(255,255,255,0.1); padding: 12px; border-radius: 8px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Risk Score:</span>
                        <span style="font-weight: bold;">${riskScore.toFixed(1)}/10</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span>Confidence:</span>
                        <span style="font-weight: bold;">${Math.round(confidence * 100)}%</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Evidence:</span>
                        <span style="font-weight: bold;">${evidenceCount} indicators</span>
                    </div>
                </div>
            `;
        }

        if (threats.length > 0) {
            content += `
                <div style="margin-bottom: 12px;">
                    <div style="font-weight: bold; margin-bottom: 6px; font-size: 13px;">Detected Issues:</div>
                    <div style="font-size: 12px; line-height: 1.3;">
                        ${threats.slice(0, 3).map(threat => `• ${threat}`).join('<br>')}
                        ${threats.length > 3 ? `<br>• ... and ${threats.length - 3} more` : ''}
                    </div>
                </div>
            `;
        }

        content += `
                <div style="font-size: 12px; opacity: 0.9; text-align: center;">
                    ${data.message || 'Security analysis completed'}
                </div>
            </div>
        `;

        return content;
    }

    playVoiceAlert(data, threatLevel) {
        const threats = data.threats || [];
        const threatText = threats.length > 0 ? threats.slice(0, 2).join(', ') : 'security issues';
        
        const messages = {
            safe: "This site appears to be safe.",
            low: `Low risk detected. ${threatText}.`,
            medium: `Medium risk warning. ${threatText} detected.`,
            high: `High risk alert. ${threatText} detected. Proceed with caution.`,
            critical: `Critical security threat detected. ${threatText}. This site is dangerous.`
        };

        const message = messages[threatLevel] || messages.high;
        const utterance = new SpeechSynthesisUtterance(message);
        
        // Configure voice
        utterance.rate = 0.9;
        utterance.pitch = 1.0;
        utterance.volume = 0.8;
        
        // Use a more natural voice if available
        const voices = speechSynthesis.getVoices();
        const preferredVoice = voices.find(voice => 
            voice.lang.startsWith('en') && voice.name.includes('Natural')
        ) || voices.find(voice => voice.lang.startsWith('en'));
        
        if (preferredVoice) {
            utterance.voice = preferredVoice;
        }

        // Play the alert
        speechSynthesis.speak(utterance);
    }
}

// Initialize the alert system
new DigitalRakshaAlert();


