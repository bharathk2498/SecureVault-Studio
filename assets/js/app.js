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
                // Delay to allow paste to complete
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

        // Copy button functionality
        document.addEventListener('click', (e) => {
            if (e.target.textContent === 'Copy Result' || e.target.textContent === 'Copy') {
                this.handleCopyClick(e);
            }
        });
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
        const strengthClasses = ['strength-weak', 'strength-fair', 'strength-good', 'strength-strong', 'strength-excellent'];
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

        const statusIndicator = breachStatus.querySelector('.status-indicator');
        
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
     * Clear hash output
     */
    clearHash() {
        const hashInput = document.getElementById('hashInput');
        const hashOutput = document.getElementById('hashOutput');
        
        if (hashInput) hashInput.value = '';
        if (hashOutput) hashOutput.textContent = 'Hash will appear here...';
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
     * Encrypt text
     */
    async encryptText() {
        const encryptInput = document.getElementById('encryptInput');
        const encryptKey = document.getElementById('encryptKey');
        const encryptOutput = document.getElementById('encryptOutput');
        
        if (!encryptInput || !encryptKey || !encryptOutput) return;

        const text = encryptInput.value;
        const key = encryptKey.value;

        if (!text.trim() || !key.trim()) {
            encryptOutput.textContent = 'Please enter both text and encryption key';
            return;
        }

        try {
            encryptOutput.textContent = 'Encrypting...';
            const encrypted = await this.cryptoUtils.encryptText(text, key);
            encryptOutput.textContent = encrypted;
        } catch (error) {
            encryptOutput.textContent = `Encryption failed: ${error.message}`;
            encryptOutput.style.color = '#ff4757';
            setTimeout(() => {
                encryptOutput.style.color = '#00ff88';
            }, 3000);
        }
    }

    /**
     * Decrypt text
     */
    async decryptText() {
        const encryptInput = document.getElementById('encryptInput');
        const encryptKey = document.getElementById('encryptKey');
        const encryptOutput = document.getElementById('encryptOutput');
        
        if (!encryptInput || !encryptKey || !encryptOutput) return;

        const encryptedText = encryptInput.value;
        const key = encryptKey.value;

        if (!encryptedText.trim() || !key.trim()) {
            encryptOutput.textContent = 'Please enter both encrypted text and decryption key';
            return;
        }

        try {
            encryptOutput.textContent = 'Decrypting...';
            const decrypted = await this.cryptoUtils.decryptText(encryptedText, key);
            encryptOutput.textContent = decrypted;
        } catch (error) {
            encryptOutput.textContent = `Decryption failed: ${error.message}`;
            encryptOutput.style.color = '#ff4757';
            setTimeout(() => {
                encryptOutput.style.color = '#00ff88';
            }, 3000);
        }
    }

    /**
     * Generate random encryption key
     */
    generateRandomKey() {
        const encryptKey = document.getElementById('encryptKey');
        if (!encryptKey) return;

        try {
            const randomKey = this.cryptoUtils.generateRandomKey(32);
            encryptKey.value = randomKey;
            encryptKey.type = 'text'; // Show the generated key
            
            // Add visual feedback
            encryptKey.style.background = 'rgba(0, 255, 136, 0.1)';
            setTimeout(() => {
                encryptKey.style.background = '';
            }, 1000);
        } catch (error) {
            console.error('Key generation failed:', error);
        }
    }

    /**
     * Generate RSA key pair
     */
    async generateKeyPair() {
        const keyDisplay = document.getElementById('keyDisplay');
        if (!keyDisplay) return;

        try {
            keyDisplay.innerHTML = 'Generating RSA key pair...';
            const keys = await this.cryptoUtils.generateRSAKeyPair();
            
            keyDisplay.innerHTML = `
                <div style="margin-bottom: 15px;">
                    <strong>Public Key:</strong>
                    <div style="font-family: monospace; font-size: 0.8rem; word-break: break-all; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; margin-top: 5px;">
                        ${keys.publicKey}
                    </div>
                </div>
                <div>
                    <strong>Private Key:</strong>
                    <div style="font-family: monospace; font-size: 0.8rem; word-break: break-all; background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; margin-top: 5px;">
                        ${keys.privateKey}
                    </div>
                </div>
            `;
        } catch (error) {
            keyDisplay.textContent = `Key generation failed: ${error.message}`;
        }
    }

    /**
     * Sign text with RSA key
     */
    async signText() {
        const signInput = document.getElementById('signInput');
        const signOutput = document.getElementById('signOutput');
        
        if (!signInput || !signOutput) return;

        const text = signInput.value;
        if (!text.trim()) {
            signOutput.textContent = 'Please enter text to sign';
            return;
        }

        try {
            signOutput.textContent = 'Signing...';
            const signature = await this.cryptoUtils.signText(text);
            signOutput.textContent = `Signature: ${signature}`;
        } catch (error) {
            signOutput.textContent = `Signing failed: ${error.message}`;
        }
    }

    /**
     * Verify signature
     */
    async verifySignature() {
        const signInput = document.getElementById('signInput');
        const signOutput = document.getElementById('signOutput');
        
        if (!signInput || !signOutput) return;

        const text = signInput.value;
        const signatureMatch = signOutput.textContent.match(/Signature: (.+)/);
        
        if (!text.trim()) {
            signOutput.textContent = 'Please enter text to verify';
            return;
        }

        if (!signatureMatch) {
            signOutput.textContent = 'No signature found to verify';
            return;
        }

        try {
            const signature = signatureMatch[1];
            const isValid = await this.cryptoUtils.verifySignature(text, signature);
            signOutput.textContent = `Signature verification: ${isValid ? '✅ VALID' : '❌ INVALID'}`;
        } catch (error) {
            signOutput.textContent = `Verification failed: ${error.message}`;
        }
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
            // You could show error message here if desired
        }
    }

    /**
     * Generate random password
     */
    generateRandomPassword() {
        const randomLength = document.getElementById('randomLength');
        const randomOutput = document.getElementById('randomOutput');
        
        if (!randomLength || !randomOutput) return;

        try {
            const length = parseInt(randomLength.value) || 16;
            const password = this.cryptoUtils.generateRandomPassword(length);
            randomOutput.textContent = password;
        } catch (error) {
            randomOutput.textContent = `Generation failed: ${error.message}`;
        }
    }

    /**
     * Generate random hex
     */
    generateRandomHex() {
        const randomLength = document.getElementById('randomLength');
        const randomOutput = document.getElementById('randomOutput');
        
        if (!randomLength || !randomOutput) return;

        try {
            const length = parseInt(randomLength.value) || 16;
            const hex = this.cryptoUtils.generateRandomHex(length);
            randomOutput.textContent = hex;
        } catch (error) {
            randomOutput.textContent = `Generation failed: ${error.message}`;
        }
    }

    /**
     * Generate UUID
     */
    generateRandomUUID() {
        const randomOutput = document.getElementById('randomOutput');
        if (!randomOutput) return;

        try {
            const uuid = this.cryptoUtils.generateUUID();
            randomOutput.textContent = uuid;
        } catch (error) {
            randomOutput.textContent = `Generation failed: ${error.message}`;
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
            // Fallback for older browsers
            this.fallbackCopyToClipboard(text);
        }
    }

    /**
     * Fallback copy method for older browsers
     */
    fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            console.log('Text copied to clipboard');
        } catch (error) {
            console.error('Copy failed:', error);
        }
        
        document.body.removeChild(textArea);
    }

    /**
     * Handle copy button clicks
     */
    handleCopyClick(e) {
        const button = e.target;
        const card = button.closest('.card');
        
        if (!card) return;

        // Find the output element in the same card
        const outputElement = card.querySelector('.hash-output');
        if (outputElement) {
            this.copyToClipboard(outputElement.id);
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

function clearHash() {
    if (window.app) {
        window.app.clearHash();
    }
}

function switchTab(tabName) {
    if (window.app) {
        window.app.switchTab(tabName);
    }
}

function encryptText() {
    if (window.app) {
        window.app.encryptText();
    }
}

function decryptText() {
    if (window.app) {
        window.app.decryptText();
    }
}

function generateRandomKey() {
    if (window.app) {
        window.app.generateRandomKey();
    }
}

function generateKeyPair() {
    if (window.app) {
        window.app.generateKeyPair();
    }
}

function signText() {
    if (window.app) {
        window.app.signText();
    }
}

function verifySignature() {
    if (window.app) {
        window.app.verifySignature();
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

function generateRandomPassword() {
    if (window.app) {
        window.app.generateRandomPassword();
    }
}

function generateRandomHex() {
    if (window.app) {
        window.app.generateRandomHex();
    }
}

function generateRandomUUID() {
    if (window.app) {
        window.app.generateRandomUUID();
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
