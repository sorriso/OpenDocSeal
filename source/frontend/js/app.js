/*
File: app.js
Path: infrastructure/source/frontend/js/app.js
Version: 1
*/

/**
 * Main application controller for OpenDocSeal
 */
class OpenDocSealApp {
    constructor() {
        this.currentTab = 'upload';
        this.isAuthenticated = false;
        this.currentUser = null;
        this.submissionInProgress = false;
        
        this.initialize();
    }

    /**
     * Initialize the application
     */
    async initialize() {
        console.log('🔒 OpenDocSeal - Initializing application...');
        
        try {
            // Check authentication status
            await this.checkAuthentication();
            
            // Initialize UI components
            this.initializeUI();
            
            // Setup event listeners
            this.setupEventListeners();
            
            // Load initial data
            await this.loadInitialData();
            
            console.log('✅ OpenDocSeal - Application ready');
            
        } catch (error) {
            console.error('❌ Application initialization failed:', error);
            Utils.showNotification('Erreur lors de l\'initialisation de l\'application', 'error');
        }
    }

    /**
     * Check user authentication status
     */
    async checkAuthentication() {
        try {
            if (apiClient.isAuthenticated()) {
                const user = await apiClient.getCurrentUser();
                this.setAuthenticatedUser(user);
            } else {
                this.setUnauthenticatedState();
            }
        } catch (error) {
            console.warn('Authentication check failed:', error);
            this.setUnauthenticatedState();
        }
    }

    /**
     * Set authenticated user state
     * @param {Object} user - User information
     */
    setAuthenticatedUser(user) {
        this.isAuthenticated = true;
        this.currentUser = user;
        
        // Update UI
        const userNameElement = document.getElementById('user-name');
        const authButton = document.getElementById('auth-button');
        
        if (userNameElement) {
            userNameElement.textContent = user.name || user.email || 'Utilisateur connecté';
        }
        
        if (authButton) {
            authButton.textContent = 'Se déconnecter';
            authButton.onclick = () => this.logout();
        }
        
        console.log('👤 User authenticated:', user.email);
    }

    /**
     * Set unauthenticated state
     */
    setUnauthenticatedState() {
        this.isAuthenticated = false;
        this.currentUser = null;
        
        // Update UI
        const userNameElement = document.getElementById('user-name');
        const authButton = document.getElementById('auth-button');
        
        if (userNameElement) {
            userNameElement.textContent = 'Non connecté';
        }
        
        if (authButton) {
            authButton.textContent = 'Se connecter';
            authButton.onclick = () => this.showLoginModal();
        }
        
        console.log('🔓 User not authenticated');
    }

    /**
     * Initialize UI components
     */
    initializeUI() {
        // Setup tab navigation
        this.setupTabNavigation();
        
        // Initialize form validation
        this.setupFormValidation();
        
        // Setup keyboard shortcuts
        this.setupKeyboardShortcuts();
        
        // Show initial tab
        this.switchTab(this.currentTab);
    }

    /**
     * Setup tab navigation
     */
    setupTabNavigation() {
        const tabButtons = document.querySelectorAll('.tab-btn');
        
        tabButtons.forEach(button => {
            button.addEventListener('click', (event) => {
                const tabName = button.getAttribute('data-tab');
                this.switchTab(tabName);
            });
        });
    }

    /**
     * Switch to specified tab
     * @param {string} tabName - Tab name to switch to
     */
    switchTab(tabName) {
        if (this.currentTab === tabName) return;
        
        // Update current tab
        this.currentTab = tabName;
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`)?.classList.add('active');
        
        // Update tab panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${tabName}-tab`)?.classList.add('active');
        
        // Handle tab-specific logic
        this.onTabSwitch(tabName);
    }

    /**
     * Handle tab switch logic
     * @param {string} tabName - Name of the switched tab
     */
    async onTabSwitch(tabName) {
        switch (tabName) {
            case 'list':
                // Load documents when switching to list tab
                if (documentList && !documentList.isLoading) {
                    await documentList.loadDocuments();
                }
                break;
                
            case 'upload':
                // Reset form when switching to upload tab
                this.resetUploadForm();
                break;
        }
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Form submission
        const documentForm = document.getElementById('document-form');
        if (documentForm) {
            documentForm.addEventListener('submit', (event) => {
                event.preventDefault();
                this.handleDocumentSubmission();
            });
        }

        // Window events
        window.addEventListener('beforeunload', (event) => {
            if (this.submissionInProgress) {
                event.preventDefault();
                event.returnValue = 'Une soumission est en cours. Êtes-vous sûr de vouloir quitter ?';
            }
        });

        // Online/offline status
        window.addEventListener('online', () => {
            Utils.showNotification('Connexion rétablie', 'success', 2000);
        });

        window.addEventListener('offline', () => {
            Utils.showNotification('Connexion perdue', 'warning');
        });
    }

    /**
     * Setup form validation
     */
    setupFormValidation() {
        // Real-time validation for form inputs
        const requiredInputs = document.querySelectorAll('input[required], textarea[required]');
        
        requiredInputs.forEach(input => {
            input.addEventListener('blur', () => {
                this.validateInput(input);
            });
        });
    }

    /**
     * Setup keyboard shortcuts
     */
    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (event) => {
            // Ctrl/Cmd + 1: Switch to upload tab
            if ((event.ctrlKey || event.metaKey) && event.key === '1') {
                event.preventDefault();
                this.switchTab('upload');
            }
            
            // Ctrl/Cmd + 2: Switch to list tab
            if ((event.ctrlKey || event.metaKey) && event.key === '2') {
                event.preventDefault();
                this.switchTab('list');
            }
            
            // Escape: Close modals
            if (event.key === 'Escape') {
                documentList.closeModal();
            }
        });
    }

    /**
     * Load initial data
     */
    async loadInitialData() {
        // Load documents if on list tab
        if (this.currentTab === 'list') {
            await documentList.loadDocuments();
        }
    }

    /**
     * Handle document submission
     */
    async handleDocumentSubmission() {
        if (this.submissionInProgress) {
            Utils.showNotification('Une soumission est déjà en cours', 'warning');
            return;
        }

        try {
            // Validate form
            const validationResult = this.validateForm();
            if (!validationResult.isValid) {
                Utils.showNotification(validationResult.errors.join(', '), 'error');
                return;
            }

            this.submissionInProgress = true;
            this.showProgress();

            // Prepare document data
            const documentData = await this.prepareDocumentData();
            
            this.updateProgress(20, 'Envoi des métadonnées...');
            
            // Create document record
            const document = await apiClient.createDocument(documentData);
            
            this.updateProgress(50, 'Document enregistré...');

            // Upload file if requested
            const uploadFile = document.getElementById('upload-file')?.checked;
            if (uploadFile && fileHandler.getCurrentFile()) {
                this.updateProgress(60, 'Upload du fichier...');
                
                await apiClient.uploadFile(
                    document.id, 
                    fileHandler.getCurrentFile(),
                    (progress) => {
                        const totalProgress = 60 + (progress * 0.3); // 60% to 90%
                        this.updateProgress(totalProgress, `Upload en cours... ${Math.round(progress)}%`);
                    }
                );
            }

            this.updateProgress(100, 'Notarisation terminée !');
            
            // Show success
            Utils.showNotification(
                `Document enregistré avec succès ! Référence: ${document.reference}`, 
                'success'
            );

            // Reset form
            setTimeout(() => {
                this.resetUploadForm();
                this.hideProgress();
                
                // Switch to list tab to show the new document
                this.switchTab('list');
            }, 2000);

        } catch (error) {
            console.error('Document submission failed:', error);
            Utils.showNotification(
                'Erreur lors de l\'enregistrement: ' + apiClient.handleError(error), 
                'error'
            );
            this.hideProgress();
        } finally {
            this.submissionInProgress = false;
        }
    }

    /**
     * Validate form before submission
     * @returns {Object} Validation result
     */
    validateForm() {
        const errors = [];

        // Validate file
        const fileValidation = fileHandler.validateForSubmission();
        if (!fileValidation.isValid) {
            errors.push(fileValidation.error);
        }

        // Validate metadata
        try {
            metadataEditor.getMetadata();
        } catch (error) {
            errors.push('Métadonnées invalides: ' + error.message);
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }

    /**
     * Validate individual input
     * @param {HTMLElement} input - Input element to validate
     */
    validateInput(input) {
        if (input.hasAttribute('required') && !input.value.trim()) {
            input.classList.add('invalid');
            return false;
        } else {
            input.classList.remove('invalid');
            return true;
        }
    }

    /**
     * Prepare document data for submission
     * @returns {Object} Document data
     */
    async prepareDocumentData() {
        const fileInfo = fileHandler.getFileInfo();
        const metadata = metadataEditor.getMetadata();
        const uploadFile = document.getElementById('upload-file')?.checked || false;

        return {
            name: fileInfo.name,
            description: '', // Could be added to form later
            hash: fileInfo.hash,
            size: fileInfo.size,
            file_type: fileInfo.type,
            metadata: metadata,
            upload_file: uploadFile
        };
    }

    /**
     * Show progress indicator
     */
    showProgress() {
        const progressSection = document.getElementById('progress-section');
        const submitButton = document.querySelector('button[type="submit"]');
        
        if (progressSection) {
            progressSection.classList.remove('hidden');
        }
        
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = '⏳ Traitement en cours...';
        }
    }

    /**
     * Update progress
     * @param {number} percent - Progress percentage
     * @param {string} status - Status message
     */
    updateProgress(percent, status) {
        const progressFill = document.getElementById('progress-fill');
        const progressStatus = document.getElementById('progress-status');
        
        if (progressFill) {
            progressFill.style.width = `${Math.min(percent, 100)}%`;
        }
        
        if (progressStatus) {
            progressStatus.textContent = status;
        }
    }

    /**
     * Hide progress indicator
     */
    hideProgress() {
        const progressSection = document.getElementById('progress-section');
        const submitButton = document.querySelector('button[type="submit"]');
        
        if (progressSection) {
            progressSection.classList.add('hidden');
        }
        
        if (submitButton) {
            submitButton.disabled = false;
            submitButton.textContent = '🔐 Enregistrer et Notariser';
        }
        
        // Reset progress
        this.updateProgress(0, '');
    }

    /**
     * Reset upload form
     */
    resetUploadForm() {
        const form = document.getElementById('document-form');
        if (form) {
            // Reset form fields
            form.reset();
            
            // Reset file handler
            fileHandler.reset();
            
            // Clear metadata
            metadataEditor.clear();
            
            // Reset UI state
            this.hideProgress();
        }
    }

    /**
     * Show login modal
     */
    showLoginModal() {
        // Simple login modal for development
        // In production, this would redirect to SSO
        const loginHtml = `
            <div class="modal-overlay" onclick="app.closeLoginModal()">
                <div class="modal-content" onclick="event.stopPropagation()">
                    <div class="modal-header">
                        <h2>🔐 Connexion</h2>
                        <button class="modal-close" onclick="app.closeLoginModal()">×</button>
                    </div>
                    <div class="modal-body">
                        <form id="login-form" onsubmit="app.handleLogin(event)">
                            <div style="margin-bottom: 1rem;">
                                <label for="login-username">Nom d'utilisateur:</label>
                                <input type="text" id="login-username" name="username" required 
                                       placeholder="demo" style="width: 100%; margin-top: 0.5rem;">
                            </div>
                            <div style="margin-bottom: 1rem;">
                                <label for="login-password">Mot de passe:</label>
                                <input type="password" id="login-password" name="password" required 
                                       placeholder="demo" style="width: 100%; margin-top: 0.5rem;">
                            </div>
                            <button type="submit" class="btn btn-primary" style="width: 100%;">
                                Se connecter
                            </button>
                        </form>
                        <div style="margin-top: 1rem; text-align: center; font-size: 0.85rem; color: #666;">
                            <p>Mode développement - utilisez demo/demo</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', loginHtml);
    }

    /**
     * Handle login form submission
     * @param {Event} event - Form submit event
     */
    async handleLogin(event) {
        event.preventDefault();
        
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        
        try {
            const response = await apiClient.login(username, password);
            this.setAuthenticatedUser(response.user);
            this.closeLoginModal();
            Utils.showNotification('Connexion réussie', 'success');
            
            // Reload data if needed
            await this.loadInitialData();
            
        } catch (error) {
            Utils.showNotification('Erreur de connexion: ' + apiClient.handleError(error), 'error');
        }
    }

    /**
     * Close login modal
     */
    closeLoginModal() {
        const modal = document.querySelector('.modal-overlay');
        if (modal) {
            modal.remove();
        }
    }

    /**
     * Logout user
     */
    async logout() {
        try {
            await apiClient.logout();
            this.setUnauthenticatedState();
            Utils.showNotification('Déconnexion réussie', 'success');
            
            // Clear any loaded data
            documentList.documents = [];
            documentList.filteredDocuments = [];
            documentList.renderDocuments();
            
        } catch (error) {
            console.warn('Logout error:', error);
            // Force logout even if API call fails
            this.setUnauthenticatedState();
        }
    }

    /**
     * Handle application errors globally
     * @param {Error} error - Error object
     * @param {string} context - Error context
     */
    handleError(error, context = '') {
        console.error(`App Error ${context}:`, error);
        
        // Don't show notification for authentication errors
        if (error.message && error.message.includes('Session expirée')) {
            this.setUnauthenticatedState();
            return;
        }
        
        Utils.showNotification(
            `Erreur ${context}: ${apiClient.handleError(error)}`, 
            'error'
        );
    }

    /**
     * Get current application state
     * @returns {Object} Application state
     */
    getState() {
        return {
            currentTab: this.currentTab,
            isAuthenticated: this.isAuthenticated,
            currentUser: this.currentUser,
            submissionInProgress: this.submissionInProgress
        };
    }
}

// Add CSS for form validation
const style = document.createElement('style');
style.textContent = `
    .invalid {
        border-color: #ef4444 !important;
        box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1) !important;
    }
    
    .valid {
        border-color: #10b981 !important;
        box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1) !important;
    }
    
    #login-form {
        max-width: 400px;
    }
    
    #login-form input {
        padding: 0.8rem;
        border: 2px solid #e5e7eb;
        border-radius: 6px;
        font-size: 0.9rem;
    }
    
    #login-form input:focus {
        outline: none;
        border-color: #667eea;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
`;
document.head.appendChild(style);

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new OpenDocSealApp();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = OpenDocSealApp;
}