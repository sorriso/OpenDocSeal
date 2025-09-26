/*
File: api-client.js
Path: infrastructure/source/frontend/js/api-client.js
Version: 1
*/

/**
 * API Client for OpenDocSeal backend communication
 */
class APIClient {
    constructor() {
        this.baseURL = '/api/v1';
        this.authToken = localStorage.getItem('auth_token');
        
        // Default headers
        this.defaultHeaders = {
            'Content-Type': 'application/json'
        };
    }

    /**
     * Get headers with authentication if available
     * @returns {Object} Headers object
     */
    getHeaders(additionalHeaders = {}) {
        const headers = { ...this.defaultHeaders, ...additionalHeaders };
        
        if (this.authToken) {
            headers['Authorization'] = `Bearer ${this.authToken}`;
        }
        
        return headers;
    }

    /**
     * Make HTTP request
     * @param {string} endpoint - API endpoint
     * @param {Object} options - Fetch options
     * @returns {Promise<Object>} Response data
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        
        const config = {
            ...options,
            headers: this.getHeaders(options.headers)
        };

        try {
            const response = await fetch(url, config);
            
            // Handle authentication errors
            if (response.status === 401) {
                this.clearAuth();
                throw new Error('Session expirée. Veuillez vous reconnecter.');
            }
            
            // Handle other HTTP errors
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `Erreur HTTP: ${response.status}`);
            }
            
            // Return JSON data if content type is JSON
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            }
            
            return response;
            
        } catch (error) {
            console.error('API Request failed:', error);
            throw error;
        }
    }

    /**
     * GET request
     * @param {string} endpoint - API endpoint
     * @param {Object} params - Query parameters
     * @returns {Promise<Object>} Response data
     */
    async get(endpoint, params = {}) {
        const url = new URL(`${this.baseURL}${endpoint}`, window.location.origin);
        
        // Add query parameters
        Object.keys(params).forEach(key => {
            if (params[key] !== null && params[key] !== undefined) {
                url.searchParams.append(key, params[key]);
            }
        });
        
        return this.request(url.pathname + url.search, { method: 'GET' });
    }

    /**
     * POST request
     * @param {string} endpoint - API endpoint
     * @param {*} data - Request data
     * @returns {Promise<Object>} Response data
     */
    async post(endpoint, data = null) {
        const options = { method: 'POST' };
        
        if (data) {
            if (data instanceof FormData) {
                // For file uploads, don't set Content-Type, let browser set it
                options.body = data;
                options.headers = {}; // Clear content-type for FormData
            } else {
                options.body = JSON.stringify(data);
            }
        }
        
        return this.request(endpoint, options);
    }

    /**
     * PUT request
     * @param {string} endpoint - API endpoint
     * @param {*} data - Request data
     * @returns {Promise<Object>} Response data
     */
    async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    /**
     * DELETE request
     * @param {string} endpoint - API endpoint
     * @returns {Promise<Object>} Response data
     */
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }

    // ========================================
    // Authentication Methods
    // ========================================

    /**
     * Set authentication token
     * @param {string} token - JWT token
     */
    setAuthToken(token) {
        this.authToken = token;
        localStorage.setItem('auth_token', token);
    }

    /**
     * Clear authentication
     */
    clearAuth() {
        this.authToken = null;
        localStorage.removeItem('auth_token');
        localStorage.removeItem('user_info');
    }

    /**
     * Check if user is authenticated
     * @returns {boolean} Authentication status
     */
    isAuthenticated() {
        return !!this.authToken;
    }

    /**
     * Login user (if not using SSO)
     * @param {string} username - Username
     * @param {string} password - Password
     * @returns {Promise<Object>} Login response
     */
    async login(username, password) {
        const response = await this.post('/auth/login', {
            username,
            password
        });
        
        if (response.token) {
            this.setAuthToken(response.token);
            localStorage.setItem('user_info', JSON.stringify(response.user));
        }
        
        return response;
    }

    /**
     * Logout user
     * @returns {Promise<void>}
     */
    async logout() {
        try {
            await this.post('/auth/logout');
        } finally {
            this.clearAuth();
        }
    }

    /**
     * Get current user info
     * @returns {Promise<Object>} User information
     */
    async getCurrentUser() {
        return this.get('/auth/me');
    }

    // ========================================
    // Document Management Methods
    // ========================================

    /**
     * Create new document record
     * @param {Object} documentData - Document metadata
     * @returns {Promise<Object>} Created document
     */
    async createDocument(documentData) {
        return this.post('/documents', documentData);
    }

    /**
     * Upload file for a document
     * @param {string} documentId - Document ID
     * @param {File} file - File to upload
     * @param {Function} progressCallback - Progress callback function
     * @returns {Promise<Object>} Upload response
     */
    async uploadFile(documentId, file, progressCallback = null) {
        const formData = new FormData();
        formData.append('file', file);
        
        // Create custom request for progress tracking
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            
            // Upload progress
            if (progressCallback) {
                xhr.upload.addEventListener('progress', (event) => {
                    if (event.lengthComputable) {
                        const percentComplete = (event.loaded / event.total) * 100;
                        progressCallback(percentComplete);
                    }
                });
            }
            
            xhr.addEventListener('load', () => {
                if (xhr.status >= 200 && xhr.status < 300) {
                    try {
                        const response = JSON.parse(xhr.responseText);
                        resolve(response);
                    } catch (e) {
                        resolve(xhr.responseText);
                    }
                } else {
                    reject(new Error(`Upload failed: ${xhr.status}`));
                }
            });
            
            xhr.addEventListener('error', () => {
                reject(new Error('Upload failed'));
            });
            
            xhr.open('POST', `${this.baseURL}/documents/${documentId}/upload`);
            
            // Add auth header
            if (this.authToken) {
                xhr.setRequestHeader('Authorization', `Bearer ${this.authToken}`);
            }
            
            xhr.send(formData);
        });
    }

    /**
     * Get document by ID
     * @param {string} documentId - Document ID
     * @returns {Promise<Object>} Document data
     */
    async getDocument(documentId) {
        return this.get(`/documents/${documentId}`);
    }

    /**
     * Get user's documents
     * @param {Object} params - Query parameters (page, limit, search, etc.)
     * @returns {Promise<Array>} List of documents
     */
    async getDocuments(params = {}) {
        return this.get('/documents', params);
    }

    /**
     * Search documents
     * @param {string} query - Search query
     * @param {Object} params - Additional parameters
     * @returns {Promise<Array>} Search results
     */
    async searchDocuments(query, params = {}) {
        return this.get('/documents/search', { q: query, ...params });
    }

    /**
     * Get document download URL
     * @param {string} documentId - Document ID
     * @returns {Promise<Object>} Download URL and metadata
     */
    async getDownloadUrl(documentId) {
        return this.get(`/documents/${documentId}/download`);
    }

    /**
     * Get document blockchain proof
     * @param {string} documentId - Document ID
     * @returns {Promise<Object>} Blockchain proof data
     */
    async getBlockchainProof(documentId) {
        return this.get(`/documents/${documentId}/proof`);
    }

    /**
     * Update document metadata
     * @param {string} documentId - Document ID
     * @param {Object} metadata - Updated metadata
     * @returns {Promise<Object>} Updated document
     */
    async updateDocument(documentId, metadata) {
        return this.put(`/documents/${documentId}`, metadata);
    }

    /**
     * Delete document
     * @param {string} documentId - Document ID
     * @returns {Promise<void>}
     */
    async deleteDocument(documentId) {
        return this.delete(`/documents/${documentId}`);
    }

    // ========================================
    // Health and Status Methods
    // ========================================

    /**
     * Get API health status
     * @returns {Promise<Object>} Health status
     */
    async getHealth() {
        return this.get('/health');
    }

    /**
     * Get system status
     * @returns {Promise<Object>} System status
     */
    async getSystemStatus() {
        return this.get('/status');
    }

    // ========================================
    // Utility Methods
    // ========================================

    /**
     * Handle API errors consistently
     * @param {Error} error - Error object
     * @returns {string} User-friendly error message
     */
    handleError(error) {
        console.error('API Error:', error);
        
        // Network errors
        if (!navigator.onLine) {
            return 'Pas de connexion internet. Vérifiez votre connexion.';
        }
        
        // Timeout errors
        if (error.name === 'AbortError') {
            return 'La requête a expiré. Veuillez réessayer.';
        }
        
        // Custom error messages
        if (error.message) {
            return error.message;
        }
        
        return 'Une erreur inattendue s\'est produite.';
    }

    /**
     * Retry failed request
     * @param {Function} requestFunction - Function to retry
     * @param {number} maxRetries - Maximum number of retries
     * @param {number} delay - Delay between retries in ms
     * @returns {Promise<*>} Request result
     */
    async retry(requestFunction, maxRetries = 3, delay = 1000) {
        for (let i = 0; i < maxRetries; i++) {
            try {
                return await requestFunction();
            } catch (error) {
                if (i === maxRetries - 1) throw error;
                
                console.warn(`Request failed, retrying in ${delay}ms (attempt ${i + 1}/${maxRetries})`);
                await new Promise(resolve => setTimeout(resolve, delay));
                delay *= 2; // Exponential backoff
            }
        }
    }
}

// Create global instance
const apiClient = new APIClient();

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = APIClient;
}