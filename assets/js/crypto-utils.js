/**
 * SecureVault Studio - Cryptographic Utilities
 * Client-side cryptographic functions using Web Crypto API
 */

class CryptoUtils {
    constructor() {
        this.keyPair = null;
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }

    /**
     * Generate hash using specified algorithm
     * @param {string} text - Text to hash
     * @param {string} algorithm - Hash algorithm (SHA-256, SHA-512, SHA-1)
     * @returns {Promise<string>} - Hex encoded hash
     */
    async generateHash(text, algorithm = 'SHA-256') {
        try {
            if (!text) return '';

            // Handle legacy MD5 (not available in Web Crypto API)
            if (algorithm === 'MD5') {
                return this.md5(text);
            }

            const data = this.encoder.encode(text);
            const hashBuffer = await crypto.subtle.digest(algorithm, data);
            return this.bufferToHex(hashBuffer);
        } catch (error) {
            throw new Error(`Hash generation failed: ${error.message}`);
        }
    }

    /**
     * Simple MD5 implementation (for compatibility)
     * Note: MD5 is cryptographically broken - included only for legacy support
     */
    md5(text) {
        // Simplified MD5 - in production, use a proper crypto library
        let hash = 0;
        if (text.length === 0) return hash.toString(16).padStart(32, '0');
        
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        
        // This is a simplified hash - not actual MD5
        return Math.abs(hash).toString(16).padStart(32, '0') + '_simplified';
    }

    /**
     * Encrypt text using AES-GCM
     * @param {string} plaintext - Text to encrypt
     * @param {string} password - Encryption password
     * @returns {Promise<string>} - Base64 encoded encrypted data
     */
    async encryptText(plaintext, password) {
        try {
            if (!plaintext || !password) {
                throw new Error('Plaintext and password are required');
            }

            // Derive key from password
            const key = await this.deriveKey(password);
            
            // Generate random IV
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Encrypt the text
            const encodedText = this.encoder.encode(plaintext);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encodedText
            );

            // Combine IV and encrypted data
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encrypted), iv.length);

            return this.bufferToBase64(combined);
        } catch (error) {
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt text using AES-GCM
     * @param {string} encryptedData - Base64 encoded encrypted data
     * @param {string} password - Decryption password
     * @returns {Promise<string>} - Decrypted plaintext
     */
    async decryptText(encryptedData, password) {
        try {
            if (!encryptedData || !password) {
                throw new Error('Encrypted data and password are required');
            }

            // Decode base64 data
            const combined = this.base64ToBuffer(encryptedData);
            
            // Extract IV and encrypted data
            const iv = combined.slice(0, 12);
            const encrypted = combined.slice(12);

            // Derive key from password
            const key = await this.deriveKey(password);

            // Decrypt the data
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encrypted
            );

            return this.decoder.decode(decrypted);
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    /**
     * Derive AES key from password using PBKDF2
     * @param {string} password - Password to derive key from
     * @returns {Promise<CryptoKey>} - Derived AES key
     */
    async deriveKey(password) {
        // Fixed salt for demonstration - in production, use random salt
        const salt = this.encoder.encode('SecureVault-Studio-Salt-2024');
        
        // Import password as key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            this.encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        // Derive AES key
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Generate RSA key pair for digital signatures
     * @returns {Promise<{publicKey: string, privateKey: string}>}
     */
    async generateRSAKeyPair() {
        try {
            this.keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSA-PSS',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                },
                true,
                ['sign', 'verify']
            );

            // Export keys
            const publicKey = await crypto.subtle.exportKey('spki', this.keyPair.publicKey);
            const privateKey = await crypto.subtle.exportKey('pkcs8', this.keyPair.privateKey);

            return {
                publicKey: this.bufferToBase64(publicKey),
                privateKey: this.bufferToBase64(privateKey)
            };
        } catch (error) {
            throw new Error(`Key generation failed: ${error.message}`);
        }
    }

    /**
     * Sign text using RSA-PSS
     * @param {string} text - Text to sign
     * @returns {Promise<string>} - Base64 encoded signature
     */
    async signText(text) {
        try {
            if (!this.keyPair) {
                throw new Error('No key pair available. Generate keys first.');
            }

            const data = this.encoder.encode(text);
            const signature = await crypto.subtle.sign(
                {
                    name: 'RSA-PSS',
                    saltLength: 32
                },
                this.keyPair.privateKey,
                data
            );

            return this.bufferToBase64(signature);
        } catch (error) {
            throw new Error(`Signing failed: ${error.message}`);
        }
    }

    /**
     * Verify signature using RSA-PSS
     * @param {string} text - Original text
     * @param {string} signature - Base64 encoded signature
     * @returns {Promise<boolean>} - Verification result
     */
    async verifySignature(text, signature) {
        try {
            if (!this.keyPair) {
                throw new Error('No key pair available. Generate keys first.');
            }

            const data = this.encoder.encode(text);
            const signatureBuffer = this.base64ToBuffer(signature);

            return await crypto.subtle.verify(
                {
                    name: 'RSA-PSS',
                    saltLength: 32
                },
                this.keyPair.publicKey,
                signatureBuffer,
                data
            );
        } catch (error) {
            throw new Error(`Verification failed: ${error.message}`);
        }
    }

    /**
     * Generate random password
     * @param {number} length - Password length
     * @param {Object} options - Character set options
     * @returns {string} - Random password
     */
    generateRandomPassword(length = 16, options = {}) {
        const defaults = {
            lowercase: true,
            uppercase: true,
            numbers: true,
            symbols: true,
            excludeSimilar: true
        };

        const config = { ...defaults, ...options };
        let charset = '';

        if (config.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (config.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (config.numbers) charset += '0123456789';
        if (config.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        // Remove similar-looking characters
        if (config.excludeSimilar) {
            charset = charset.replace(/[0O1lI]/g, '');
        }

        if (!charset) {
            throw new Error('No character set selected');
        }

        // Generate cryptographically secure random password
        const randomValues = crypto.getRandomValues(new Uint8Array(length));
        let password = '';

        for (let i = 0; i < length; i++) {
            password += charset[randomValues[i] % charset.length];
        }

        return password;
    }

    /**
     * Generate random hex string
     * @param {number} length - Number of bytes (hex length will be double)
     * @returns {string} - Random hex string
     */
    generateRandomHex(length = 16) {
        const randomValues = crypto.getRandomValues(new Uint8Array(length));
        return Array.from(randomValues)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Generate UUID v4
     * @returns {string} - UUID string
     */
    generateUUID() {
        return crypto.randomUUID();
    }

    /**
     * Calculate CIDR network information
     * @param {string} cidr - CIDR notation (e.g., "192.168.1.0/24")
     * @returns {Object} - Network information
     */
    calculateCIDR(cidr) {
        if (!cidr.includes('/')) {
            throw new Error('Invalid CIDR notation');
        }

        const [ip, prefixStr] = cidr.split('/');
        const prefix = parseInt(prefixStr);

        if (prefix < 0 || prefix > 32) {
            throw new Error('Invalid prefix length');
        }

        // Parse IP address
        const ipParts = ip.split('.').map(part => parseInt(part));
        if (ipParts.length !== 4 || ipParts.some(part => isNaN(part) || part < 0 || part > 255)) {
            throw new Error('Invalid IP address');
        }

        // Calculate network information
        const hostBits = 32 - prefix;
        const hostCount = Math.pow(2, hostBits) - 2; // Subtract network and broadcast
        
        // Calculate subnet mask
        const maskValue = (0xFFFFFFFF << hostBits) >>> 0;
        const subnetMask = [
            (maskValue >>> 24) & 0xFF,
            (maskValue >>> 16) & 0xFF,
            (maskValue >>> 8) & 0xFF,
            maskValue & 0xFF
        ].join('.');

        // Calculate network address
        const ipValue = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
        const networkValue = ipValue & maskValue;
        const networkAddr = [
            (networkValue >>> 24) & 0xFF,
            (networkValue >>> 16) & 0xFF,
            (networkValue >>> 8) & 0xFF,
            networkValue & 0xFF
        ].join('.');

        // Calculate broadcast address
        const broadcastValue = networkValue | (0xFFFFFFFF >>> prefix);
        const broadcastAddr = [
            (broadcastValue >>> 24) & 0xFF,
            (broadcastValue >>> 16) & 0xFF,
            (broadcastValue >>> 8) & 0xFF,
            broadcastValue & 0xFF
        ].join('.');

        return {
            networkAddr,
            broadcastAddr,
            subnetMask,
            hostCount: hostCount > 0 ? hostCount : 0,
            usableRange: hostCount > 0 ? `${this.incrementIP(networkAddr)} - ${this.decrementIP(broadcastAddr)}` : 'None'
        };
    }

    /**
     * Increment IP address by 1
     */
    incrementIP(ip) {
        const parts = ip.split('.').map(Number);
        let carry = 1;
        
        for (let i = 3; i >= 0; i--) {
            parts[i] += carry;
            if (parts[i] > 255) {
                parts[i] = 0;
                carry = 1;
            } else {
                carry = 0;
                break;
            }
        }
        
        return parts.join('.');
    }

    /**
     * Decrement IP address by 1
     */
    decrementIP(ip) {
        const parts = ip.split('.').map(Number);
        let borrow = 1;
        
        for (let i = 3; i >= 0; i--) {
            parts[i] -= borrow;
            if (parts[i] < 0) {
                parts[i] = 255;
                borrow = 1;
            } else {
                borrow = 0;
                break;
            }
        }
        
        return parts.join('.');
    }

    /**
     * Encode/decode Base64
     */
    encodeBase64(text) {
        try {
            return btoa(unescape(encodeURIComponent(text)));
        } catch (error) {
            throw new Error('Base64 encoding failed');
        }
    }

    decodeBase64(base64) {
        try {
            return decodeURIComponent(escape(atob(base64)));
        } catch (error) {
            throw new Error('Base64 decoding failed - invalid format');
        }
    }

    /**
     * Utility functions for buffer/string conversion
     */
    bufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    base64ToBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    /**
     * Generate random encryption key
     */
    generateRandomKey(length = 32) {
        return this.generateRandomPassword(length, {
            lowercase: true,
            uppercase: true,
            numbers: true,
            symbols: true,
            excludeSimilar: false
        });
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoUtils;
} else {
    window.CryptoUtils = CryptoUtils;
}
