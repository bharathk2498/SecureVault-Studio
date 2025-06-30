/**
 * SecureVault Studio - Password Analysis Engine
 * Advanced password strength analysis with entropy calculation and breach checking
 */

class PasswordAnalyzer {
    constructor() {
        // Common compromised passwords database (subset for demo)
        this.breachedPasswords = new Set([
            'password', '123456', 'password123', 'admin', 'qwerty', 'letmein',
            'welcome', 'monkey', '1234567890', 'abc123', 'Password1', 'password1',
            'sunshine', 'master', 'shadow', 'football', 'baseball', 'dragon',
            'princess', 'superman', 'qwertyuiop', 'iloveyou', 'trustno1',
            'startrek', 'freedom', 'whatever', 'nicolejean', 'computer',
            'dallas', 'rangers', 'london', 'klaster', 'corvette', 'heaven',
            'fishing', 'teresa', 'salasana', 'michigan', 'marlboro',
            '987654321', '111111', '666666', '121212', 'charlie', 'pass',
            'mustang', 'gizmodo', 'birthday', 'green', 'honda', 'chocolate'
        ]);

        // Character sets for entropy calculation
        this.charsets = {
            lowercase: 'abcdefghijklmnopqrstuvwxyz',
            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            numbers: '0123456789',
            symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
            extended: '`~"\'\\/ \t\n'
        };

        // Common patterns to detect
        this.commonPatterns = [
            /(.)\1{2,}/g,           // Repeated characters (aaa, 111)
            /012|123|234|345|456|567|678|789|890/gi, // Sequential numbers
            /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/gi, // Sequential letters
            /qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm/gi, // Keyboard patterns
            /password|pass|admin|user|login|guest|test|demo|root/gi, // Common words
            /\d{4}|\d{6}|\d{8}/g,   // Years, dates
            /19\d{2}|20\d{2}/g      // Years
        ];
    }

    /**
     * Analyze password strength and return comprehensive metrics
     * @param {string} password - The password to analyze
     * @returns {Object} Analysis results
     */
    analyze(password) {
        if (!password) {
            return this.getEmptyAnalysis();
        }

        const metrics = {
            length: password.length,
            charsetSize: this.calculateCharsetSize(password),
            entropy: this.calculateEntropy(password),
            patterns: this.detectPatterns(password),
            commonality: this.checkCommonality(password),
            complexity: this.calculateComplexity(password),
            crackTime: this.estimateCrackTime(password),
            score: 0,
            level: 'Very Weak',
            suggestions: []
        };

        // Calculate overall score (0-100)
        metrics.score = this.calculateScore(metrics, password);
        
        // Determine strength level
        metrics.level = this.getStrengthLevel(metrics.score);
        
        // Generate improvement suggestions
        metrics.suggestions = this.generateSuggestions(password, metrics);

        return metrics;
    }

    /**
     * Calculate the effective character set size
     */
    calculateCharsetSize(password) {
        let size = 0;
        
        if (/[a-z]/.test(password)) size += 26;
        if (/[A-Z]/.test(password)) size += 26;
        if (/[0-9]/.test(password)) size += 10;
        if (/[!@#$%^&*()_+\-=\[\]{}|;':\",./<>?]/.test(password)) size += 32;
        if (/[`~\\/ \t\n]/.test(password)) size += 6;
        
        return size;
    }

    /**
     * Calculate Shannon entropy
     */
    calculateEntropy(password) {
        if (!password) return 0;

        const charsetSize = this.calculateCharsetSize(password);
        if (charsetSize === 0) return 0;

        // Shannon entropy: H = L * log2(N)
        // Where L = length, N = character set size
        const entropy = password.length * Math.log2(charsetSize);
        
        // Apply penalty for patterns and repetition
        const patternPenalty = this.calculatePatternPenalty(password);
        
        return Math.max(0, entropy - patternPenalty);
    }

    /**
     * Calculate pattern penalty for entropy
     */
    calculatePatternPenalty(password) {
        let penalty = 0;
        
        // Repeated character penalty
        const repeatedChars = password.match(/(.)\1+/g);
        if (repeatedChars) {
            penalty += repeatedChars.reduce((sum, match) => sum + match.length, 0) * 2;
        }

        // Sequential pattern penalty
        this.commonPatterns.forEach(pattern => {
            const matches = password.match(pattern);
            if (matches) {
                penalty += matches.reduce((sum, match) => sum + match.length, 0) * 1.5;
            }
        });

        return penalty;
    }

    /**
     * Detect various patterns in the password
     */
    detectPatterns(password) {
        const patterns = {
            repeated: false,
            sequential: false,
            keyboard: false,
            dictionary: false,
            dates: false
        };

        // Check for repeated characters
        if (/(.)\1{2,}/.test(password)) {
            patterns.repeated = true;
        }

        // Check for sequential patterns
        if (/012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/gi.test(password)) {
            patterns.sequential = true;
        }

        // Check for keyboard patterns
        if (/qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm/gi.test(password)) {
            patterns.keyboard = true;
        }

        // Check for dictionary words
        if (/password|pass|admin|user|login|guest|test|demo|root|love|secret|welcome/gi.test(password)) {
            patterns.dictionary = true;
        }

        // Check for dates/years
        if (/19\d{2}|20\d{2}|\d{1,2}\/\d{1,2}\/\d{2,4}|\d{1,2}-\d{1,2}-\d{2,4}/.test(password)) {
            patterns.dates = true;
        }

        return patterns;
    }

    /**
     * Check if password is commonly used
     */
    checkCommonality(password) {
        const lowerPassword = password.toLowerCase();
        
        if (this.breachedPasswords.has(lowerPassword)) {
            return 'breached';
        }

        // Check variations with common substitutions
        const variations = [
            lowerPassword.replace(/[@]/g, 'a').replace(/[3]/g, 'e').replace(/[1]/g, 'i').replace(/[0]/g, 'o').replace(/[$]/g, 's'),
            lowerPassword.replace(/[4]/g, 'a').replace(/[3]/g, 'e').replace(/[1]/g, 'l').replace(/[7]/g, 't')
        ];

        for (const variation of variations) {
            if (this.breachedPasswords.has(variation)) {
                return 'similar_to_breached';
            }
        }

        return 'unique';
    }

    /**
     * Calculate complexity score based on character variety
     */
    calculateComplexity(password) {
        let complexity = 0;
        
        if (/[a-z]/.test(password)) complexity++;
        if (/[A-Z]/.test(password)) complexity++;
        if (/[0-9]/.test(password)) complexity++;
        if (/[^A-Za-z0-9]/.test(password)) complexity++;
        
        return complexity;
    }

    /**
     * Estimate time to crack password using brute force
     */
    estimateCrackTime(password) {
        if (!password) return '0 seconds';

        const charsetSize = this.calculateCharsetSize(password);
        const combinations = Math.pow(charsetSize, password.length);
        
        // Assume 1 billion guesses per second (modern GPU)
        const guessesPerSecond = 1e9;
