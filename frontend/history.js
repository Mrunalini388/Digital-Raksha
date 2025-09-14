// Enhanced history.js for Digital Raksha
class DigitalRakshaHistory {
    constructor() {
        this.history = [];
        this.filteredHistory = [];
        this.currentFilter = 'all';
        this.searchTerm = '';
        
        this.init();
    }

    async init() {
        await this.loadHistory();
        this.setupEventListeners();
        this.updateStats();
        this.renderHistory();
    }

    setupEventListeners() {
        // Search input
        const searchInput = document.getElementById('searchInput');
        searchInput.addEventListener('input', (e) => {
            this.searchTerm = e.target.value.toLowerCase();
            this.filterHistory();
        });

        // Filter buttons
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                // Update active button
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                
                // Update filter
                this.currentFilter = e.target.dataset.filter;
                this.filterHistory();
            });
        });
    }

    async loadHistory() {
        try {
            const result = await chrome.storage.local.get(['scanHistory']);
            this.history = result.scanHistory || [];
            
            // Sort by timestamp (newest first)
            this.history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
        } catch (err) {
            console.error('Failed to load history:', err);
            this.history = [];
        }
    }

    filterHistory() {
        this.filteredHistory = this.history.filter(item => {
            // Apply search filter
            if (this.searchTerm) {
                const matchesSearch = 
                    item.url.toLowerCase().includes(this.searchTerm) ||
                    item.hostname.toLowerCase().includes(this.searchTerm) ||
                    (item.threats && item.threats.some(threat => 
                        threat.toLowerCase().includes(this.searchTerm)
                    ));
                if (!matchesSearch) return false;
            }

            // Apply threat level filter
            if (this.currentFilter !== 'all') {
                const threatLevel = item.threat_level?.toLowerCase() || 
                    (item.safe ? 'safe' : 'high');
                return threatLevel === this.currentFilter;
            }

            return true;
        });
    }

    updateStats() {
        const stats = {
            total: this.history.length,
            safe: 0,
            low: 0,
            medium: 0,
            high: 0,
            critical: 0
        };

        this.history.forEach(item => {
            const threatLevel = item.threat_level?.toLowerCase() || 
                (item.safe ? 'safe' : 'high');
            
            switch (threatLevel) {
                case 'safe':
                    stats.safe++;
                    break;
                case 'low':
                    stats.low++;
                    break;
                case 'medium':
                    stats.medium++;
                    break;
                case 'high':
                    stats.high++;
                    break;
                case 'critical':
                    stats.critical++;
                    break;
            }
        });

        // Update stat cards
        document.getElementById('totalScans').textContent = stats.total;
        document.getElementById('safeScans').textContent = stats.safe;
        document.getElementById('lowRiskScans').textContent = stats.low;
        document.getElementById('mediumRiskScans').textContent = stats.medium;
        document.getElementById('highRiskScans').textContent = stats.high;
        document.getElementById('criticalScans').textContent = stats.critical;
    }

    renderHistory() {
        const historyList = document.getElementById('historyList');
        
        if (this.filteredHistory.length === 0) {
            historyList.innerHTML = `
                <div class="no-data">
                    <h3>No scan history found</h3>
                    <p>Start browsing to see your security scan history here</p>
                </div>
            `;
            return;
        }

        const historyHTML = this.filteredHistory.map(item => {
            const threatLevel = item.threat_level?.toLowerCase() || 
                (item.safe ? 'safe' : 'high');
            const riskScore = item.risk_score || item.score || 0;
            const confidence = item.confidence || 0;
            const scanTime = new Date(item.timestamp).toLocaleString();
            
            const threatIcons = {
                safe: '✅',
                low: 'ℹ️',
                medium: '⚡',
                high: '⚠️',
                critical: '🚨'
            };

            return `
                <div class="history-item">
                    <div class="threat-icon">${threatIcons[threatLevel] || '❓'}</div>
                    <div class="url-info">
                        <div class="url" title="${item.url}">${this.truncateUrl(item.url, 60)}</div>
                        <div class="hostname">${item.hostname}</div>
                    </div>
                    <div class="threat-details">
                        <div class="threat-level ${threatLevel}">${threatLevel.toUpperCase()}</div>
                        <div class="risk-score">${riskScore.toFixed(1)}/10</div>
                        <div class="scan-time">${scanTime}</div>
                    </div>
                </div>
            `;
        }).join('');

        historyList.innerHTML = historyHTML;
    }

    truncateUrl(url, maxLength) {
        if (url.length <= maxLength) return url;
        return url.substring(0, maxLength - 3) + '...';
    }

    async refreshHistory() {
        const historyList = document.getElementById('historyList');
        historyList.innerHTML = `
            <div class="loading">
                <div class="spinner"></div>
                <p>Refreshing scan history...</p>
            </div>
        `;

        await this.loadHistory();
        this.updateStats();
        this.filterHistory();
        this.renderHistory();
    }

    exportHistory() {
        try {
            const exportData = {
                version: '1.0',
                timestamp: new Date().toISOString(),
                totalScans: this.history.length,
                history: this.history.map(item => ({
                    url: item.url,
                    hostname: item.hostname,
                    threatLevel: item.threat_level || (item.safe ? 'safe' : 'high'),
                    riskScore: item.risk_score || item.score || 0,
                    confidence: item.confidence || 0,
                    threats: item.threats || [],
                    timestamp: item.timestamp,
                    safe: item.safe
                }))
            };

            const dataStr = JSON.stringify(exportData, null, 2);
            const dataBlob = new Blob([dataStr], { type: 'application/json' });
            
            const link = document.createElement('a');
            link.href = URL.createObjectURL(dataBlob);
            link.download = `digital-raksha-history-${new Date().toISOString().split('T')[0]}.json`;
            link.click();
            
            this.showNotification('History exported successfully!', 'success');
        } catch (err) {
            console.error('Failed to export history:', err);
            this.showNotification('Failed to export history.', 'error');
        }
    }

    async clearHistory() {
        if (confirm('Are you sure you want to clear all scan history? This action cannot be undone.')) {
            try {
                await chrome.storage.local.remove(['scanHistory']);
                this.history = [];
                this.filteredHistory = [];
                this.updateStats();
                this.renderHistory();
                
                this.showNotification('History cleared successfully!', 'success');
            } catch (err) {
                console.error('Failed to clear history:', err);
                this.showNotification('Failed to clear history.', 'error');
            }
        }
    }

    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 10000;
            animation: slideInRight 0.3s ease-out;
            max-width: 300px;
        `;
        
        if (type === 'success') {
            notification.style.background = '#28a745';
        } else {
            notification.style.background = '#dc3545';
        }
        
        notification.textContent = message;
        document.body.appendChild(notification);
        
        // Auto-remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease-in';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        }, 3000);
    }
}

// Initialize history when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new DigitalRakshaHistory();
});

// Global functions for button onclick handlers
function refreshHistory() {
    // This will be handled by the class instance
}

function exportHistory() {
    // This will be handled by the class instance
}

function clearHistory() {
    // This will be handled by the class instance
}
