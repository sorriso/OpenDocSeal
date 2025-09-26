/*
File: document-list.js
Path: infrastructure/source/frontend/js/document-list.js
Version: 1
*/

/**
 * Document list management and display
 */
class DocumentList {
    constructor() {
        this.documents = [];
        this.filteredDocuments = [];
        this.isLoading = false;
        this.searchQuery = '';
        this.sortBy = 'created_at';
        this.sortOrder = 'desc';
        this.currentPage = 1;
        this.itemsPerPage = 20;
        
        this.initializeControls();
    }

    /**
     * Initialize list controls
     */
    initializeControls() {
        this.setupSearchInput();
        this.setupRefreshButton();
        this.setupSortControls();
    }

    /**
     * Setup search input functionality
     */
    setupSearchInput() {
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.addEventListener('input', Utils.debounce((event) => {
                this.searchQuery = event.target.value.trim();
                this.filterDocuments();
            }, 300));
        }
    }

    /**
     * Setup refresh button
     */
    setupRefreshButton() {
        const refreshButton = document.getElementById('refresh-button');
        if (refreshButton) {
            refreshButton.addEventListener('click', () => {
                this.loadDocuments(true);
            });
        }
    }

    /**
     * Setup sort controls
     */
    setupSortControls() {
        // Create sort dropdown if it doesn't exist
        this.createSortControls();
    }

    /**
     * Create sort controls dynamically
     */
    createSortControls() {
        const listControls = document.querySelector('.list-controls');
        if (!listControls || listControls.querySelector('.sort-controls')) return;

        const sortControls = document.createElement('div');
        sortControls.className = 'sort-controls';
        sortControls.innerHTML = `
            <select id="sort-select" class="btn btn-secondary">
                <option value="created_at-desc">Plus récent</option>
                <option value="created_at-asc">Plus ancien</option>
                <option value="name-asc">Nom A-Z</option>
                <option value="name-desc">Nom Z-A</option>
                <option value="size-desc">Taille ↓</option>
                <option value="size-asc">Taille ↑</option>
            </select>
        `;
        
        listControls.appendChild(sortControls);

        const sortSelect = sortControls.querySelector('#sort-select');
        sortSelect.addEventListener('change', (event) => {
            const [field, order] = event.target.value.split('-');
            this.sortBy = field;
            this.sortOrder = order;
            this.sortDocuments();
        });
    }

    /**
     * Load documents from API
     * @param {boolean} force - Force reload even if already loaded
     */
    async loadDocuments(force = false) {
        if (this.isLoading && !force) return;

        try {
            this.setLoadingState(true);

            const response = await apiClient.getDocuments({
                page: this.currentPage,
                limit: this.itemsPerPage
            });

            this.documents = Array.isArray(response) ? response : (response.documents || []);
            this.filterDocuments();

            Utils.showNotification(`${this.documents.length} document(s) chargé(s)`, 'success', 2000);

        } catch (error) {
            console.error('Failed to load documents:', error);
            Utils.showNotification('Erreur lors du chargement des documents: ' + apiClient.handleError(error), 'error');
            this.documents = [];
            this.filteredDocuments = [];
        } finally {
            this.setLoadingState(false);
        }
    }

    /**
     * Search documents
     * @param {string} query - Search query
     */
    async searchDocuments(query) {
        if (!query.trim()) {
            this.loadDocuments();
            return;
        }

        try {
            this.setLoadingState(true);
            
            const results = await apiClient.searchDocuments(query);
            this.documents = Array.isArray(results) ? results : (results.documents || []);
            this.filteredDocuments = [...this.documents];
            this.renderDocuments();

        } catch (error) {
            console.error('Search failed:', error);
            Utils.showNotification('Erreur lors de la recherche: ' + apiClient.handleError(error), 'error');
        } finally {
            this.setLoadingState(false);
        }
    }

    /**
     * Filter documents based on search query
     */
    filterDocuments() {
        if (!this.searchQuery) {
            this.filteredDocuments = [...this.documents];
        } else {
            const query = this.searchQuery.toLowerCase();
            this.filteredDocuments = this.documents.filter(doc => 
                doc.name.toLowerCase().includes(query) ||
                (doc.description && doc.description.toLowerCase().includes(query)) ||
                doc.hash.toLowerCase().includes(query) ||
                doc.reference.toLowerCase().includes(query) ||
                Object.values(doc.metadata || {}).some(value => 
                    String(value).toLowerCase().includes(query)
                )
            );
        }
        
        this.sortDocuments();
    }

    /**
     * Sort filtered documents
     */
    sortDocuments() {
        this.filteredDocuments.sort((a, b) => {
            let aValue = a[this.sortBy];
            let bValue = b[this.sortBy];

            // Handle different data types
            if (this.sortBy === 'created_at') {
                aValue = new Date(aValue);
                bValue = new Date(bValue);
            } else if (this.sortBy === 'size') {
                aValue = parseInt(aValue) || 0;
                bValue = parseInt(bValue) || 0;
            } else if (typeof aValue === 'string') {
                aValue = aValue.toLowerCase();
                bValue = (bValue || '').toLowerCase();
            }

            if (aValue < bValue) {
                return this.sortOrder === 'asc' ? -1 : 1;
            }
            if (aValue > bValue) {
                return this.sortOrder === 'asc' ? 1 : -1;
            }
            return 0;
        });

        this.renderDocuments();
    }

    /**
     * Render documents list
     */
    renderDocuments() {
        const listContainer = document.getElementById('documents-list');
        if (!listContainer) return;

        if (this.filteredDocuments.length === 0) {
            this.renderEmptyState(listContainer);
            return;
        }

        listContainer.innerHTML = this.filteredDocuments
            .map(doc => this.createDocumentCard(doc))
            .join('');

        // Add event listeners to cards
        this.attachCardEventListeners();
    }

    /**
     * Render empty state
     * @param {HTMLElement} container - Container element
     */
    renderEmptyState(container) {
        const message = this.searchQuery 
            ? `Aucun document trouvé pour "${this.searchQuery}"`
            : 'Aucun document enregistré';

        container.innerHTML = `
            <div class="empty-state">
                <h3>📭 ${message}</h3>
                <p>
                    ${this.searchQuery 
                        ? 'Essayez avec d\'autres mots-clés ou effacez votre recherche.'
                        : 'Commencez par enregistrer votre premier document dans l\'onglet "Enregistrer Document".'
                    }
                </p>
                ${this.searchQuery ? `
                    <button class="btn btn-secondary" onclick="documentList.clearSearch()">
                        Effacer la recherche
                    </button>
                ` : ''}
            </div>
        `;
    }

    /**
     * Create document card HTML
     * @param {Object} doc - Document object
     * @returns {string} HTML string
     */
    createDocumentCard(doc) {
        const status = this.getStatusInfo(doc.status);
        const createdDate = Utils.formatDate(doc.created_at);
        const hasMetadata = doc.metadata && Object.keys(doc.metadata).length > 0;

        return `
            <div class="document-card" data-document-id="${doc.id}">
                <div class="document-header">
                    <h3 class="document-title">${Utils.escapeHtml(doc.name)}</h3>
                    <span class="document-status ${status.class}">${status.text}</span>
                </div>
                
                <div class="document-meta">
                    <div class="meta-item">
                        <span class="meta-label">Référence:</span>
                        <span class="meta-value">${doc.reference}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Hash:</span>
                        <span class="meta-value">${Utils.truncateString(doc.hash, 16)}...</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Créé le:</span>
                        <span class="meta-value">${createdDate}</span>
                    </div>
                    ${doc.size ? `
                    <div class="meta-item">
                        <span class="meta-label">Taille:</span>
                        <span class="meta-value">${Utils.formatFileSize(doc.size)}</span>
                    </div>
                    ` : ''}
                    ${doc.description ? `
                    <div class="meta-item">
                        <span class="meta-label">Description:</span>
                        <span class="meta-value">${Utils.truncateString(doc.description, 100)}</span>
                    </div>
                    ` : ''}
                </div>

                ${hasMetadata ? `
                <div class="document-metadata">
                    <details>
                        <summary>📋 Métadonnées (${Object.keys(doc.metadata).length})</summary>
                        <div class="metadata-content">
                            ${Object.entries(doc.metadata).map(([key, value]) => `
                                <div class="metadata-item">
                                    <strong>${Utils.escapeHtml(key)}:</strong> ${Utils.escapeHtml(String(value))}
                                </div>
                            `).join('')}
                        </div>
                    </details>
                </div>
                ` : ''}

                <div class="document-actions">
                    <button class="btn btn-secondary" onclick="documentList.viewDocument('${doc.id}')">
                        👁️ Détails
                    </button>
                    <button class="btn btn-primary" onclick="documentList.downloadDocument('${doc.id}')">
                        💾 Télécharger
                    </button>
                    ${doc.status === 'completed' ? `
                    <button class="btn btn-success" onclick="documentList.showBlockchainProof('${doc.id}')">
                        🔗 Preuve
                    </button>
                    ` : ''}
                    <button class="btn btn-secondary" onclick="documentList.copyHash('${doc.hash}')">
                        📋 Hash
                    </button>
                </div>
            </div>
        `;
    }

    /**
     * Get status information
     * @param {string} status - Document status
     * @returns {Object} Status info with class and text
     */
    getStatusInfo(status) {
        const statusMap = {
            'processing': { class: 'status-processing', text: '⏳ En cours' },
            'completed': { class: 'status-completed', text: '✅ Complété' },
            'error': { class: 'status-error', text: '❌ Erreur' },
            'pending': { class: 'status-processing', text: '⏳ En attente' }
        };
        
        return statusMap[status] || { class: 'status-processing', text: status };
    }

    /**
     * Attach event listeners to document cards
     */
    attachCardEventListeners() {
        // Add hover effects and other interactions
        const cards = document.querySelectorAll('.document-card');
        cards.forEach(card => {
            card.addEventListener('mouseenter', () => {
                card.style.transform = 'translateY(-4px)';
            });
            
            card.addEventListener('mouseleave', () => {
                card.style.transform = 'translateY(0)';
            });
        });
    }

    /**
     * View document details
     * @param {string} documentId - Document ID
     */
    async viewDocument(documentId) {
        try {
            const doc = await apiClient.getDocument(documentId);
            this.showDocumentModal(doc);
        } catch (error) {
            Utils.showNotification('Erreur lors du chargement du document: ' + apiClient.handleError(error), 'error');
        }
    }

    /**
     * Download document
     * @param {string} documentId - Document ID
     */
    async downloadDocument(documentId) {
        try {
            const downloadInfo = await apiClient.getDownloadUrl(documentId);
            
            // Open download URL in new tab/window
            window.open(downloadInfo.download_url, '_blank');
            Utils.showNotification('Téléchargement initié', 'success');
            
        } catch (error) {
            Utils.showNotification('Erreur lors du téléchargement: ' + apiClient.handleError(error), 'error');
        }
    }

    /**
     * Show blockchain proof
     * @param {string} documentId - Document ID
     */
    async showBlockchainProof(documentId) {
        try {
            const proof = await apiClient.getBlockchainProof(documentId);
            this.showProofModal(proof);
        } catch (error) {
            Utils.showNotification('Erreur lors du chargement de la preuve: ' + apiClient.handleError(error), 'error');
        }
    }

    /**
     * Copy document hash
     * @param {string} hash - Document hash
     */
    async copyHash(hash) {
        const success = await Utils.copyToClipboard(hash);
        if (success) {
            Utils.showNotification('Hash copié dans le presse-papier', 'success', 2000);
        } else {
            Utils.showNotification('Erreur lors de la copie', 'error');
        }
    }

    /**
     * Show document details modal
     * @param {Object} doc - Document object
     */
    showDocumentModal(doc) {
        const modalHtml = `
            <div class="modal-overlay" onclick="documentList.closeModal()">
                <div class="modal-content" onclick="event.stopPropagation()">
                    <div class="modal-header">
                        <h2>📄 ${Utils.escapeHtml(doc.name)}</h2>
                        <button class="modal-close" onclick="documentList.closeModal()">×</button>
                    </div>
                    <div class="modal-body">
                        <div class="detail-group">
                            <label>Référence:</label>
                            <code>${doc.reference}</code>
                        </div>
                        <div class="detail-group">
                            <label>Hash SHA256:</label>
                            <code class="selectable">${doc.hash}</code>
                        </div>
                        <div class="detail-group">
                            <label>Créé le:</label>
                            <span>${Utils.formatDate(doc.created_at)}</span>
                        </div>
                        ${doc.description ? `
                        <div class="detail-group">
                            <label>Description:</label>
                            <p>${Utils.escapeHtml(doc.description)}</p>
                        </div>
                        ` : ''}
                        ${Object.keys(doc.metadata || {}).length > 0 ? `
                        <div class="detail-group">
                            <label>Métadonnées:</label>
                            <pre class="selectable">${JSON.stringify(doc.metadata, null, 2)}</pre>
                        </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }

    /**
     * Show blockchain proof modal
     * @param {Object} proof - Proof object
     */
    showProofModal(proof) {
        const modalHtml = `
            <div class="modal-overlay" onclick="documentList.closeModal()">
                <div class="modal-content" onclick="event.stopPropagation()">
                    <div class="modal-header">
                        <h2>🔗 Preuve Blockchain</h2>
                        <button class="modal-close" onclick="documentList.closeModal()">×</button>
                    </div>
                    <div class="modal-body">
                        <div class="proof-details">
                            <div class="detail-group">
                                <label>Transaction ID:</label>
                                <code class="selectable">${proof.transaction_id}</code>
                            </div>
                            <div class="detail-group">
                                <label>Block Hash:</label>
                                <code class="selectable">${proof.block_hash}</code>
                            </div>
                            <div class="detail-group">
                                <label>Block Height:</label>
                                <span>${proof.block_height}</span>
                            </div>
                            <div class="detail-group">
                                <label>Confirmations:</label>
                                <span>${proof.confirmations}</span>
                            </div>
                            <div class="detail-group">
                                <label>Timestamp:</label>
                                <span>${Utils.formatDate(proof.timestamp)}</span>
                            </div>
                        </div>
                        <div class="proof-verification">
                            <h4>🔍 Vérification</h4>
                            <p>Cette preuve peut être vérifiée de manière indépendante sur la blockchain Bitcoin.</p>
                            <a href="https://blockstream.info/tx/${proof.transaction_id}" target="_blank" class="btn btn-primary">
                                Voir sur Blockstream
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }

    /**
     * Close modal
     */
    closeModal() {
        const modal = document.querySelector('.modal-overlay');
        if (modal) {
            modal.remove();
        }
    }

    /**
     * Clear search
     */
    clearSearch() {
        const searchInput = document.getElementById('search-input');
        if (searchInput) {
            searchInput.value = '';
            this.searchQuery = '';
            this.filterDocuments();
        }
    }

    /**
     * Set loading state
     * @param {boolean} loading - Loading state
     */
    setLoadingState(loading) {
        this.isLoading = loading;
        
        const loadingIndicator = document.getElementById('loading-indicator');
        const refreshButton = document.getElementById('refresh-button');
        
        if (loadingIndicator) {
            loadingIndicator.classList.toggle('hidden', !loading);
        }
        
        if (refreshButton) {
            refreshButton.disabled = loading;
            refreshButton.textContent = loading ? '⏳ Chargement...' : '🔄 Actualiser';
        }
    }

    /**
     * Refresh documents list
     */
    refresh() {
        this.loadDocuments(true);
    }
}

// Add CSS for modals
const style = document.createElement('style');
style.textContent = `
    .modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
    }
    
    .modal-content {
        background: white;
        border-radius: 8px;
        max-width: 600px;
        max-height: 80vh;
        overflow: auto;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
    }
    
    .modal-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 1.5rem;
        border-bottom: 1px solid #e5e7eb;
    }
    
    .modal-close {
        background: none;
        border: none;
        font-size: 1.5rem;
        cursor: pointer;
    }
    
    .modal-body {
        padding: 1.5rem;
    }
    
    .detail-group {
        margin-bottom: 1rem;
    }
    
    .detail-group label {
        font-weight: 600;
        display: block;
        margin-bottom: 0.25rem;
    }
    
    .selectable {
        user-select: all;
        background: #f3f4f6;
        padding: 0.5rem;
        border-radius: 4px;
        display: block;
        font-family: monospace;
    }
    
    .metadata-content {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 4px;
        margin-top: 0.5rem;
    }
    
    .metadata-item {
        margin-bottom: 0.5rem;
    }
`;
document.head.appendChild(style);

// Create global instance
const documentList = new DocumentList();

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = DocumentList;
}