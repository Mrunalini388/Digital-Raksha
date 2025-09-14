// Enhanced settings.js for Digital Raksha
class DigitalRakshaSettings {
    constructor() {
        this.defaultSettings = {
            autoBlock: true,
            voiceEnabled: true,
            showDetailedAlerts: true,
            threatLevel: 'medium',
            alertDuration: 5000,
            enableML: true,
            keepHistory: true,
            serverUrl: 'http://127.0.0.1:5000/scan'
        };
        
        this.init();
    }

    async init() {
        await this.loadSettings();
        this.setupEventListeners();
        this.updateUI();
    }

    setupEventListeners() {
        // Alert duration range slider
        const alertDurationSlider = document.getElementById('alertDuration');
        const alertDurationValue = document.getElementById('alertDurationValue');
        
        alertDurationSlider.addEventListener('input', (e) => {
            const value = parseInt(e.target.value);
            alertDurationValue.textContent = `${value / 1000}s`;
        });

        // Auto-save on toggle changes
        document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
            checkbox.addEventListener('change', () => this.saveSettings());
        });

        document.querySelectorAll('select, input[type="text"]').forEach(input => {
            input.addEventListener('change', () => this.saveSettings());
        });
    }

    async loadSettings() {
        try {
            const result = await chrome.storage.sync.get(Object.keys(this.defaultSettings));
            this.settings = { ...this.defaultSettings, ...result };
        } catch (err) {
            console.error('Failed to load settings:', err);
            this.settings = { ...this.defaultSettings };
        }
    }

    updateUI() {
        // Update checkboxes
        document.getElementById('autoBlock').checked = this.settings.autoBlock;
        document.getElementById('voiceEnabled').checked = this.settings.voiceEnabled;
        document.getElementById('showDetailedAlerts').checked = this.settings.showDetailedAlerts;
        document.getElementById('enableML').checked = this.settings.enableML;
        document.getElementById('keepHistory').checked = this.settings.keepHistory;

        // Update select
        document.getElementById('threatLevel').value = this.settings.threatLevel;

        // Update range slider
        const alertDurationSlider = document.getElementById('alertDuration');
        const alertDurationValue = document.getElementById('alertDurationValue');
        alertDurationSlider.value = this.settings.alertDuration;
        alertDurationValue.textContent = `${this.settings.alertDuration / 1000}s`;

        // Update text input
        document.getElementById('serverUrl').value = this.settings.serverUrl;
    }

    async saveSettings() {
        try {
            // Collect current form values
            const newSettings = {
                autoBlock: document.getElementById('autoBlock').checked,
                voiceEnabled: document.getElementById('voiceEnabled').checked,
                showDetailedAlerts: document.getElementById('showDetailedAlerts').checked,
                threatLevel: document.getElementById('threatLevel').value,
                alertDuration: parseInt(document.getElementById('alertDuration').value),
                enableML: document.getElementById('enableML').checked,
                keepHistory: document.getElementById('keepHistory').checked,
                serverUrl: document.getElementById('serverUrl').value
            };

            // Validate settings
            if (!this.validateSettings(newSettings)) {
                this.showStatus('Invalid settings detected. Please check your inputs.', 'error');
                return;
            }

            // Save to storage
            await chrome.storage.sync.set(newSettings);
            this.settings = { ...this.settings, ...newSettings };

            // Update background script with new settings
            this.updateBackgroundScript();

            this.showStatus('Settings saved successfully!', 'success');
            
            // Auto-hide success message
            setTimeout(() => {
                this.hideStatus();
            }, 3000);

        } catch (err) {
            console.error('Failed to save settings:', err);
            this.showStatus('Failed to save settings. Please try again.', 'error');
        }
    }

    validateSettings(settings) {
        // Validate server URL
        try {
            new URL(settings.serverUrl);
        } catch {
            return false;
        }

        // Validate alert duration
        if (settings.alertDuration < 1000 || settings.alertDuration > 30000) {
            return false;
        }

        // Validate threat level
        const validThreatLevels = ['low', 'medium', 'high', 'strict'];
        if (!validThreatLevels.includes(settings.threatLevel)) {
            return false;
        }

        return true;
    }

    async updateBackgroundScript() {
        try {
            // Send settings update to background script
            chrome.runtime.sendMessage({
                type: 'SETTINGS_UPDATE',
                settings: this.settings
            });
        } catch (err) {
            console.error('Failed to update background script:', err);
        }
    }

    async resetSettings() {
        if (confirm('Are you sure you want to reset all settings to default values?')) {
            try {
                await chrome.storage.sync.clear();
                this.settings = { ...this.defaultSettings };
                this.updateUI();
                this.showStatus('Settings reset to default values.', 'success');
                
                setTimeout(() => {
                    this.hideStatus();
                }, 3000);
            } catch (err) {
                console.error('Failed to reset settings:', err);
                this.showStatus('Failed to reset settings.', 'error');
            }
        }
    }

    exportSettings() {
        try {
            const settingsData = {
                version: '1.0',
                timestamp: new Date().toISOString(),
                settings: this.settings
            };

            const dataStr = JSON.stringify(settingsData, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            
            const link = document.createElement('a');
            link.href = URL.createObjectURL(dataBlob);
            link.download = `digital-raksha-settings-${new Date().toISOString().split('T')[0]}.json`;
            link.click();
            
            this.showStatus('Settings exported successfully!', 'success');
            
            setTimeout(() => {
                this.hideStatus();
            }, 3000);
        } catch (err) {
            console.error('Failed to export settings:', err);
            this.showStatus('Failed to export settings.', 'error');
        }
    }

    importSettings() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        
        input.onchange = async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            try {
                const text = await file.text();
                const data = JSON.parse(text);
                
                if (!data.settings || !data.version) {
                    throw new Error('Invalid settings file format');
                }

                // Validate imported settings
                if (!this.validateSettings(data.settings)) {
                    throw new Error('Invalid settings in file');
                }

                // Apply settings
                await chrome.storage.sync.set(data.settings);
                this.settings = { ...this.defaultSettings, ...data.settings };
                this.updateUI();
                
                this.showStatus('Settings imported successfully!', 'success');
                
                setTimeout(() => {
                    this.hideStatus();
                }, 3000);
            } catch (err) {
                console.error('Failed to import settings:', err);
                this.showStatus('Failed to import settings. Invalid file format.', 'error');
            }
        };
        
        input.click();
    }

    showStatus(message, type) {
        const status = document.getElementById('status');
        status.textContent = message;
        status.className = `status ${type}`;
        status.style.display = 'block';
    }

    hideStatus() {
        const status = document.getElementById('status');
        status.style.display = 'none';
    }
}

// Initialize settings when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new DigitalRakshaSettings();
});

// Global functions for button onclick handlers
function saveSettings() {
    // This will be handled by the class instance
}

function resetSettings() {
    // This will be handled by the class instance
}

function exportSettings() {
    // This will be handled by the class instance
}

function importSettings() {
    // This will be handled by the class instance
}
