/*
File: utils.js
Path: infrastructure/source/frontend/js/utils.js
Version: 1
*/

/**
 * Utility functions for OpenDocSeal frontend
 */
const Utils = {
    
    /**
     * Format file size in human readable format
     * @param {number} bytes - File size in bytes
     * @returns {string} Formatted size string
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    /**
     * Format date to French locale string
     * @param {Date|string} date - Date to format
     * @returns {string} Formatted date string
     */
    formatDate(date) {
        const dateObj = date instanceof Date ? date : new Date(date);
        return dateObj.toLocaleDateString('fr-FR', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    },

    /**
     * Generate unique ID
     * @returns {string} Unique identifier
     */
    generateId() {
        return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
    },

    /**
     * Debounce function execution
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in milliseconds
     * @returns {Function} Debounced function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Validate JSON string
     * @param {string} jsonString - JSON string to validate
     * @returns {Object} Validation result with isValid and parsed data
     */
    validateJSON(jsonString) {
        try {
            const parsed = JSON.parse(jsonString);
            return {
                isValid: true,
                data: parsed,
                error: null
            };
        } catch (error) {
            return {
                isValid: false,
                data: null,
                error: error.message
            };
        }
    },

    /**
     * Escape HTML to prevent XSS
     * @param {string} unsafe - Unsafe string
     * @returns {string} HTML escaped string
     */
    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    },

    /**
     * Copy text to clipboard
     * @param {string} text - Text to copy
     * @returns {Promise<boolean>} Success status
     */
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            const success = document.execCommand('copy');
            document.body.removeChild(textArea);
            return success;
        }
    },

    /**
     * Show notification message
     * @param {string} message - Message to show
     * @param {string} type - Type of message (success, error, warning, info)
     * @param {number} duration - Duration in milliseconds (default: 5000)
     */
    showNotification(message, type = 'info', duration = 5000) {
        // Remove existing notifications
        const existing = document.querySelectorAll('.notification');
        existing.forEach(el => el.remove());

        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} notification`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            max-width: 400px;
            animation: slideIn 0.3s ease-out;
        `;
        notification.textContent = message;

        // Add close button
        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '×';
        closeBtn.style.cssText = `
            background: none;
            border: none;
            float: right;
            font-size: 1.2rem;
            cursor: pointer;
            margin-left: 10px;
        `;
        closeBtn.onclick = () => notification.remove();
        notification.appendChild(closeBtn);

        document.body.appendChild(notification);

        // Auto remove after duration
        if (duration > 0) {
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, duration);
        }
    },

    /**
     * Calculate SHA256 hash of file
     * @param {File} file - File to hash
     * @returns {Promise<string>} SHA256 hash in hex format
     */
    async calculateSHA256(file) {
        const arrayBuffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    /**
     * Validate file type and size
     * @param {File} file - File to validate
     * @param {Object} options - Validation options
     * @returns {Object} Validation result
     */
    validateFile(file, options = {}) {
        const {
            maxSize = 100 * 1024 * 1024, // 100MB default
            allowedTypes = null, // null means all types allowed
            minSize = 1
        } = options;

        const errors = [];

        // Check file size
        if (file.size > maxSize) {
            errors.push(`Le fichier est trop volumineux. Taille maximale: ${this.formatFileSize(maxSize)}`);
        }

        if (file.size < minSize) {
            errors.push(`Le fichier est trop petit. Taille minimale: ${this.formatFileSize(minSize)}`);
        }

        // Check file type if restrictions exist
        if (allowedTypes && allowedTypes.length > 0) {
            const fileExtension = file.name.split('.').pop().toLowerCase();
            const mimeType = file.type.toLowerCase();
            
            const isAllowed = allowedTypes.some(type => {
                if (type.startsWith('.')) {
                    return fileExtension === type.substring(1);
                }
                return mimeType.startsWith(type.toLowerCase());
            });

            if (!isAllowed) {
                errors.push(`Type de fichier non autorisé. Types acceptés: ${allowedTypes.join(', ')}`);
            }
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    },

    /**
     * Parse query string parameters
     * @param {string} queryString - Query string (default: window.location.search)
     * @returns {Object} Parsed parameters
     */
    parseQueryParams(queryString = window.location.search) {
        const params = {};
        const urlParams = new URLSearchParams(queryString);
        
        for (const [key, value] of urlParams) {
            params[key] = value;
        }
        
        return params;
    },

    /**
     * Deep clone object
     * @param {*} obj - Object to clone
     * @returns {*} Cloned object
     */
    deepClone(obj) {
        if (obj === null || typeof obj !== 'object') {
            return obj;
        }
        
        if (obj instanceof Date) {
            return new Date(obj.getTime());
        }
        
        if (obj instanceof Array) {
            return obj.map(item => this.deepClone(item));
        }
        
        if (typeof obj === 'object') {
            const cloned = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    cloned[key] = this.deepClone(obj[key]);
                }
            }
            return cloned;
        }
    },

    /**
     * Throttle function execution
     * @param {Function} func - Function to throttle
     * @param {number} limit - Time limit in milliseconds
     * @returns {Function} Throttled function
     */
    throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    },

    /**
     * Check if element is in viewport
     * @param {HTMLElement} element - Element to check
     * @returns {boolean} True if in viewport
     */
    isInViewport(element) {
        const rect = element.getBoundingClientRect();
        return (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth)
        );
    },

    /**
     * Get file extension from filename
     * @param {string} filename - Filename
     * @returns {string} File extension (without dot)
     */
    getFileExtension(filename) {
        return filename.split('.').pop().toLowerCase();
    },

    /**
     * Truncate string with ellipsis
     * @param {string} str - String to truncate
     * @param {number} length - Maximum length
     * @returns {string} Truncated string
     */
    truncateString(str, length) {
        if (str.length <= length) return str;
        return str.substring(0, length) + '...';
    }
};

// Add CSS for notifications animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Utils;
}