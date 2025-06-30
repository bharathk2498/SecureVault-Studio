/**
 * SecureVault Studio - Main Application Controller
 * Handles UI interactions and coordinates between different modules
 */

class SecureVaultApp {
    constructor() {
        this.passwordAnalyzer = new PasswordAnalyzer();
        this.cryptoUtils = new CryptoUtils();
        this.currentTab = 'hash';
        this.isPasswordVisible = false;
        
        this.init();
    }

    /**
     * Initialize the application
     */
    init() {
        this.setupEventListeners();
        this.updatePasswordAnalysis(); // Initial empty analysis
        this.showTab('hash'); // Show default tab
        
        // Add some visual flair
        this.addLoadingAnimations();
        
        console.log('🔐 SecureVault Studio initialized successfully!');
    }

    /**
     * Setup all event listeners
     */
    setupEventListeners() {
        // Password analysis
        const passwordInput = document.getElementById('passwordInput');
        if (passwordInput) {
            passwordInput.addEventListener('input', () => this.updatePasswordAnalysis());
            passwordInput.addEventListener('paste', () => {
                setTimeout(() => this.updatePasswordAnalysis(), 10);
            });
        }

        // Hash generation
        const hashInput = document.getElementById('hashInput');
        const hashAlgorithm = document.getElementById('hashAlgorithm');
        if (hashInput) {
            hashInput.addEventListener('input', () => this.generateHash());
        }
        if (hashAlgorithm) {
            hashAlgorithm.addEventListener('change', () => this.generateHash());
        }

        // CIDR calculation
        const cidrInput = document.getElementById('cidrInput');
        if (cidrInput) {
            cidrInput.addEventListener('input', () => this.calculateCIDR());
        }

        // Base64 operations
        const base64Input = document.getElementById('base64Input');
        if (base64Input) {
            base64Input.addEventListener('input', () => this.clearBase64Output());
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyboardShortcuts(e));
    }

    /**
     * Handle keyboard shortcuts
     */
    handleKeyboardShortcuts(e) {
        // Ctrl/Cmd + K to focus password input
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const passwordInput = document.getElementById('passwordInput');
            if (passwordInput) {
                passwordInput.focus();
                passwordInput.select();
            }
        }

        // Escape to clear all inputs
        if (e.key === 'Escape') {
            this.clearAllInputs();
        }
    }

    /**
     * Update password analysis in real-time
     */
    updatePasswordAnalysis() {
        const passwordInput = document.getElementById('passwordInput');
        const password = passwordInput ? passwordInput.value : '';
        
        const analysis = this.passwordAnalyzer.analyze(password);
        
        // Update strength meter
        this.updateStrengthMeter(analysis);
        
        // Update metrics
        this.updatePasswordMetrics(analysis);
        
        // Update breach status
        this.updateBreachStatus(analysis);
        
        // Update tips
        this.updatePasswordTips(analysis);
    }

    /**
     * Update strength meter visualization
     */
    updateStrengthMeter(analysis) {
        const strengthFill = document.getElementById('strengthFill');
        const strengthLabel = document.getElementById('strengthLabel');
        const strengthScore = document.getElementById('strengthScore');
        
        if (!strengthFill || !strengthLabel || !strengthScore) return;

        // Animate the fill
        strengthFill.style.width = analysis.score + '%';
        strengthScore.textContent = analysis.score;
        strengthLabel.textContent = analysis.level;

        // Update colors based on strength
        strengthFill.className = 'strength-fill';

        if (analysis.score < 20) {
            strengthFill.classList.add('strength-weak');
        } else if (analysis.score < 40) {
            strengthFill.classList.add('strength-weak');
        } else if (analysis.score < 60) {
            strengthFill.classList.add('strength-fair');
        } else if (analysis.score < 80) {
            strengthFill.classList.add('strength-good');
        } else if (analysis.score < 95) {
            strengthFill.classList.add('strength-strong');
        } else {
            strengthFill.classList.add('strength-excellent');
        }
    }

    /**
     * Update password metrics display
     */
    updatePasswordMetrics(analysis) {
        const elements = {
            lengthMetric: analysis.length,
            entropyMetric: Math.round(analysis.entropy),
            complexityMetric: analysis.complexity,
            timeMetric: analysis.crackTime
        };

        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value;
                
                // Add pulse animation for updates
                element.style.transform = 'scale(1.1)';
                setTimeout(() => {
                    element.style.transform = 'scale(1)';
                }, 150);
            }
        });
    }

    /**
     * Update breach status display
     */
    updateBreachStatus(analysis) {
        const breachStatus = document.getElementById('breachStatus');
        if (!breachStatus) return;
        
        if (analysis.length === 0) {
            breachStatus.innerHTML = '<span class="status-indicator status-safe"></span>Breach status: Enter password to check';
            breachStatus.className = 'breach-status';
        } else if (analysis.commonality === 'breached') {
            breachStatus.innerHTML = '<span class="status-indicator status-danger"></span>⚠️ COMPROMISED - Found in breach database';
            breachStatus.className = 'breach-status breach-compromised';
        } else if (analysis.commonality === 'similar_to_breached') {
            breachStatus.innerHTML = '<span class="status-indicator status-warning"></span>⚠️ SIMILAR - Resembles breached passwords';
            breachStatus.className = 'breach-status breach-warning';
        } else {
            breachStatus.innerHTML = '<span class="status-indicator status-safe"></span>✅ SAFE - Not found in breach database';
            breachStatus.className = 'breach-status breach-safe';
        }
    }

    /**
     * Update password improvement tips
     */
    updatePasswordTips(analysis) {
        const tipsList = document.getElementById('tipsList');
        const passwordTips = document.getElementById('passwordTips');
        
        if (!tipsList || !passwordTips) return;

        tipsList.innerHTML = '';
        
        if (analysis.suggestions && analysis.suggestions.length > 0) {
            passwordTips.style.display = 'block';
            analysis.suggestions.forEach(suggestion => {
                const li = document.createElement('li');
                li.textContent = suggestion;
                tipsList.appendChild(li);
            });
        } else {
            passwordTips.style.display = 'none';
        }
    }

    /**
     * Toggle password visibility
     */
    togglePasswordVisibility() {
        const passwordInput = document.getElementById('passwordInput');
        const toggleBtn = document.querySelector('.toggle-visibility');
        
        if (!passwordInput || !toggleBtn) return;

        this.isPasswordVisible = !this.isPasswordVisible;
        
        if (this.isPasswordVisible) {
            passwordInput.type = 'text';
            toggleBtn.textContent = '🙈';
        } else {
            passwordInput.type = 'password';
            toggleBtn.textContent = '👁️';
        }
    }

    /**
     * Generate hash from input
     */
    async generateHash() {
        const hashInput = document.getElementById('hashInput');
        const hashAlgorithm = document.getElementById('hashAlgorithm');
        const hashOutput = document.getElementById('hashOutput');
        
        if (!hashInput || !hashAlgorithm || !hashOutput) return;

        const text = hashInput.value;
        const algorithm = hashAlgorithm.value;

        if (!text.trim()) {
            hashOutput.textContent = 'Hash will appear here...';
            return;
        }

        try {
            hashOutput.textContent = 'Generating hash...';
            const hash = await this.cryptoUtils.generateHash(text, algorithm);
            hashOutput.textContent = hash;
        } catch (error) {
            hashOutput.textContent = `Error: ${error.message}`;
            hashOutput.style.color = '#ff4757';
            setTimeout(() => {
                hashOutput.style.color = '#00ff88';
            }, 3000);
        }
    }

    /**
     * Switch between tabs in crypto toolkit
     */
    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`${tabName}-tab`).classList.add('active');

        this.currentTab = tabName;
    }

    /**
     * Base64 encode
     */
    encodeBase64() {
        const base64Input = document.getElementById('base64Input');
        const base64Output = document.getElementById('base64Output');
        
        if (!base64Input || !base64Output) return;

        const text = base64Input.value;
        if (!text.trim()) {
            base64Output.textContent = 'Please enter text to encode';
            return;
        }

        try {
            const encoded = this.cryptoUtils.encodeBase64(text);
            base64Output.textContent = encoded;
        } catch (error) {
            base64Output.textContent = `Encoding failed: ${error.message}`;
        }
    }

    /**
     * Base64 decode
     */
    decodeBase64() {
        const base64Input = document.getElementById('base64Input');
        const base64Output = document.getElementById('base64Output');
        
        if (!base64Input || !base64Output) return;

        const base64 = base64Input.value;
        if (!base64.trim()) {
            base64Output.textContent = 'Please enter base64 to decode';
            return;
        }

        try {
            const decoded = this.cryptoUtils.decodeBase64(base64);
            base64Output.textContent = decoded;
        } catch (error) {
            base64Output.textContent = `Decoding failed: ${error.message}`;
        }
    }

    /**
     * Clear base64 output when input changes
     */
    clearBase64Output() {
        const base64Output = document.getElementById('base64Output');
        if (base64Output) {
            base64Output.textContent = 'Result will appear here...';
        }
    }

    /**
     * Calculate CIDR network information
     */
    calculateCIDR() {
        const cidrInput = document.getElementById('cidrInput');
        const cidrMetrics = document.getElementById('cidrMetrics');
        
        if (!cidrInput || !cidrMetrics) return;

        const cidr = cidrInput.value.trim();
        
        if (!cidr) {
            cidrMetrics.style.display = 'none';
            return;
        }

        try {
            const info = this.cryptoUtils.calculateCIDR(cidr);
            
            document.getElementById('networkAddr').textContent = info.networkAddr;
            document.getElementById('broadcastAddr').textContent = info.broadcastAddr;
            document.getElementById('hostCount').textContent = info.hostCount.toLocaleString();
            document.getElementById('subnetMask').textContent = info.subnetMask;
            
            cidrMetrics.style.display = 'grid';
        } catch (error) {
            cidrMetrics.style.display = 'none';
        }
    }

    /**
     * Copy text to clipboard
     */
    async copyToClipboard(elementId) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const text = element.textContent;
        if (!text || text.includes('will appear here') || text.includes('failed')) {
            return;
        }

        try {
            await navigator.clipboard.writeText(text);
            
            // Visual feedback
            const originalText = element.textContent;
            element.textContent = '✅ Copied!';
            element.style.color = '#00ff88';
            
            setTimeout(() => {
                element.textContent = originalText;
                element.style.color = '';
            }, 1500);
        } catch (error) {
            console.error('Copy failed:', error);
        }
    }

    /**
     * Clear all inputs
     */
    clearAllInputs() {
        const inputs = document.querySelectorAll('.input-field');
        const outputs = document.querySelectorAll('.hash-output');
        
        inputs.forEach(input => {
            input.value = '';
        });
        
        outputs.forEach(output => {
            output.textContent = output.textContent.includes('Hash') ? 'Hash will appear here...' : 'Result will appear here...';
        });

        // Reset password analysis
        this.updatePasswordAnalysis();
        
        // Hide CIDR metrics
        const cidrMetrics = document.getElementById('cidrMetrics');
        if (cidrMetrics) {
            cidrMetrics.style.display = 'none';
        }
    }

    /**
     * Add loading animations and visual flair
     */
    addLoadingAnimations() {
        // Add entrance animations to cards
        const cards = document.querySelectorAll('.card');
        cards.forEach((card, index) => {
            card.style.animationDelay = `${index * 0.1}s`;
        });

        // Add hover effects to metrics
        const metrics = document.querySelectorAll('.metric');
        metrics.forEach(metric => {
            metric.addEventListener('mouseenter', () => {
                metric.style.transform = 'translateY(-3px) scale(1.05)';
            });
            
            metric.addEventListener('mouseleave', () => {
                metric.style.transform = 'translateY(0) scale(1)';
            });
        });
    }

    /**
     * Show specific tab content
     */
    showTab(tabName) {
        this.switchTab(tabName);
    }
}

// Global functions for HTML onclick handlers
function togglePasswordVisibility() {
    if (window.app) {
        window.app.togglePasswordVisibility();
    }
}

function generateHash() {
    if (window.app) {
        window.app.generateHash();
    }
}

function switchTab(tabName) {
    if (window.app) {
        window.app.switchTab(tabName);
    }
}

function encodeBase64() {
    if (window.app) {
        window.app.encodeBase64();
    }
}

function decodeBase64() {
    if (window.app) {
        window.app.decodeBase64();
    }
}

function copyToClipboard(elementId) {
    if (window.app) {
        window.app.copyToClipboard(elementId);
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new SecureVaultApp();
});

// Add global error handling
window.addEventListener('error', (e) => {
    console.error('Global error:', e.error);
});

window.addEventListener('unhandledrejection', (e) => {
    console.error('Unhandled promise rejection:', e.reason);
});
