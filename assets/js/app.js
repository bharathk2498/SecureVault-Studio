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
            cidrInput.
