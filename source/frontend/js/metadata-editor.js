/*
File: metadata-editor.js
Path: infrastructure/source/frontend/js/metadata-editor.js
Version: 1
*/

/**
 * Metadata editor with key-value and JSON modes
 */
class MetadataEditor {
    constructor() {
        this.currentMode = 'keyvalue';
        this.metadata = {};
        this.keyValuePairs = [];
        
        this.initializeEditor();
    }

    /**
     * Initialize metadata editor
     */
    initializeEditor() {
        this.setupModeToggle();
        this.initializeKeyValueEditor();
        this.initializeJSONEditor();
        this.addInitialKeyValuePair();
    }

    /**
     * Setup mode toggle between key-value and JSON
     */
    setupModeToggle() {
        const metadataTabs = document.querySelectorAll('.metadata-tab');
        
        metadataTabs.forEach(tab => {
            tab.addEventListener('click', (event) => {
                event.preventDefault();
                const mode = tab.getAttribute('data-mode');
                this.switchMode(mode);
            });
        });
    }

    /**
     * Switch between editing modes
     * @param {string} mode - Either 'keyvalue' or 'json'
     */
    switchMode(mode) {
        if (mode === this.currentMode) return;

        // Sync data before switching
        try {
            if (this.currentMode === 'keyvalue') {
                this.syncFromKeyValue();
            } else {
                this.syncFromJSON();
            }
        } catch (error) {
            Utils.showNotification('Erreur lors du changement de mode: ' + error.message, 'error');
            return;
        }

        // Update mode
        this.currentMode = mode;

        // Update tabs
        document.querySelectorAll('.metadata-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector(`[data-mode="${mode}"]`).classList.add('active');

        // Show/hide editors
        const keyValueEditor = document.getElementById('keyvalue-editor');
        const jsonEditor = document.getElementById('json-editor');

        if (mode === 'keyvalue') {
            keyValueEditor.classList.remove('hidden');
            jsonEditor.classList.add('hidden');
            this.updateKeyValueFromMetadata();
        } else {
            keyValueEditor.classList.add('hidden');
            jsonEditor.classList.remove('hidden');
            this.updateJSONFromMetadata();
        }
    }

    /**
     * Initialize key-value editor
     */
    initializeKeyValueEditor() {
        const addButton = document.getElementById('add-metadata');
        if (addButton) {
            addButton.addEventListener('click', () => {
                this.addKeyValuePair();
            });
        }
    }

    /**
     * Initialize JSON editor
     */
    initializeJSONEditor() {
        const jsonTextarea = document.getElementById('json-textarea');
        if (jsonTextarea) {
            jsonTextarea.addEventListener('input', Utils.debounce(() => {
                this.validateJSON();
            }, 500));
        }
    }

    /**
     * Add initial key-value pair
     */
    addInitialKeyValuePair() {
        if (this.keyValuePairs.length === 0) {
            this.addKeyValuePair('', '', false);
        }
    }

    /**
     * Add a new key-value pair row
     * @param {string} key - Initial key value
     * @param {string} value - Initial value
     * @param {boolean} removable - Whether the row can be removed
     */
    addKeyValuePair(key = '', value = '', removable = true) {
        const container = document.getElementById('keyvalue-container');
        if (!container) return;

        const id = Utils.generateId();
        const pair = {
            id: id,
            key: key,
            value: value,
            removable: removable
        };

        this.keyValuePairs.push(pair);

        const row = document.createElement('div');
        row.className = 'keyvalue-row';
        row.setAttribute('data-id', id);
        
        row.innerHTML = `
            <input type="text" class="key-input" placeholder="Clé" value="${Utils.escapeHtml(key)}">
            <input type="text" class="value-input" placeholder="Valeur" value="${Utils.escapeHtml(value)}">
            <button type="button" class="remove-btn" ${!removable ? 'disabled' : ''}>🗑️</button>
        `;

        container.appendChild(row);

        // Add event listeners
        const keyInput = row.querySelector('.key-input');
        const valueInput = row.querySelector('.value-input');
        const removeBtn = row.querySelector('.remove-btn');

        keyInput.addEventListener('input', () => {
            pair.key = keyInput.value;
            this.syncFromKeyValue();
        });

        valueInput.addEventListener('input', () => {
            pair.value = valueInput.value;
            this.syncFromKeyValue();
        });

        if (removable) {
            removeBtn.addEventListener('click', () => {
                this.removeKeyValuePair(id);
            });
        }

        // Auto-add new row when last row is filled
        if (key || value) {
            keyInput.addEventListener('input', this.checkForAutoAdd.bind(this));
            valueInput.addEventListener('input', this.checkForAutoAdd.bind(this));
        }
    }

    /**
     * Remove key-value pair
     * @param {string} id - Pair ID to remove
     */
    removeKeyValuePair(id) {
        const row = document.querySelector(`[data-id="${id}"]`);
        if (row) {
            row.remove();
        }

        this.keyValuePairs = this.keyValuePairs.filter(pair => pair.id !== id);
        this.syncFromKeyValue();

        // Ensure at least one empty row exists
        if (this.keyValuePairs.length === 0) {
            this.addKeyValuePair('', '', false);
        }
    }

    /**
     * Check if we need to auto-add a new row
     */
    checkForAutoAdd() {
        const lastPair = this.keyValuePairs[this.keyValuePairs.length - 1];
        if (lastPair && (lastPair.key || lastPair.value)) {
            this.addKeyValuePair();
        }
    }

    /**
     * Sync metadata from key-value pairs
     */
    syncFromKeyValue() {
        const newMetadata = {};
        
        this.keyValuePairs.forEach(pair => {
            const key = pair.key?.trim();
            const value = pair.value?.trim();
            
            if (key && value) {
                newMetadata[key] = value;
            }
        });

        this.metadata = newMetadata;
        this.validateMetadata();
    }

    /**
     * Update key-value pairs from metadata
     */
    updateKeyValueFromMetadata() {
        const container = document.getElementById('keyvalue-container');
        if (!container) return;

        // Clear existing pairs
        container.innerHTML = '';
        this.keyValuePairs = [];

        // Add pairs from metadata
        const entries = Object.entries(this.metadata);
        
        if (entries.length > 0) {
            entries.forEach(([key, value]) => {
                this.addKeyValuePair(key, value, true);
            });
        }

        // Always add one empty row
        this.addKeyValuePair('', '', true);
    }

    /**
     * Sync metadata from JSON editor
     */
    syncFromJSON() {
        const jsonTextarea = document.getElementById('json-textarea');
        if (!jsonTextarea) return;

        const jsonString = jsonTextarea.value.trim();
        
        if (!jsonString) {
            this.metadata = {};
            return;
        }

        const validation = Utils.validateJSON(jsonString);
        
        if (!validation.isValid) {
            throw new Error('JSON invalide: ' + validation.error);
        }

        // Ensure it's a flat object
        if (typeof validation.data !== 'object' || validation.data === null || Array.isArray(validation.data)) {
            throw new Error('Les métadonnées doivent être un objet JSON');
        }

        // Check for nested objects
        for (const [key, value] of Object.entries(validation.data)) {
            if (typeof value === 'object' && value !== null) {
                throw new Error(`La valeur de "${key}" ne peut pas être un objet imbriqué`);
            }
        }

        this.metadata = validation.data;
        this.validateMetadata();
    }

    /**
     * Update JSON editor from metadata
     */
    updateJSONFromMetadata() {
        const jsonTextarea = document.getElementById('json-textarea');
        if (!jsonTextarea) return;

        if (Object.keys(this.metadata).length === 0) {
            jsonTextarea.value = '{}';
        } else {
            jsonTextarea.value = JSON.stringify(this.metadata, null, 2);
        }

        this.validateJSON();
    }

    /**
     * Validate JSON in textarea
     */
    validateJSON() {
        const jsonTextarea = document.getElementById('json-textarea');
        const validationDiv = document.getElementById('json-validation');
        
        if (!jsonTextarea || !validationDiv) return;

        const jsonString = jsonTextarea.value.trim();
        
        if (!jsonString) {
            validationDiv.innerHTML = '';
            return;
        }

        const validation = Utils.validateJSON(jsonString);
        
        if (validation.isValid) {
            validationDiv.innerHTML = `
                <div class="validation-message valid">
                    ✅ JSON valide (${Object.keys(validation.data).length} propriétés)
                </div>
            `;
        } else {
            validationDiv.innerHTML = `
                <div class="validation-message invalid">
                    ❌ JSON invalide: ${Utils.escapeHtml(validation.error)}
                </div>
            `;
        }
    }

    /**
     * Validate metadata rules
     */
    validateMetadata() {
        const keys = Object.keys(this.metadata);
        const errors = [];

        // Check for empty keys
        keys.forEach(key => {
            if (!key.trim()) {
                errors.push('Les clés ne peuvent pas être vides');
            }
        });

        // Check for duplicate keys (case insensitive)
        const lowerKeys = keys.map(k => k.toLowerCase());
        const duplicates = lowerKeys.filter((key, index) => lowerKeys.indexOf(key) !== index);
        if (duplicates.length > 0) {
            errors.push('Clés dupliquées détectées: ' + [...new Set(duplicates)].join(', '));
        }

        // Check for reserved keys
        const reservedKeys = ['id', 'hash', 'timestamp', 'signature', 'type'];
        const usedReserved = keys.filter(key => reservedKeys.includes(key.toLowerCase()));
        if (usedReserved.length > 0) {
            errors.push('Clés réservées utilisées: ' + usedReserved.join(', '));
        }

        // Check key and value lengths
        keys.forEach(key => {
            if (key.length > 100) {
                errors.push(`Clé trop longue: "${Utils.truncateString(key, 20)}" (max 100 caractères)`);
            }
            
            const value = String(this.metadata[key]);
            if (value.length > 1000) {
                errors.push(`Valeur trop longue pour "${key}" (max 1000 caractères)`);
            }
        });

        // Show validation errors
        if (errors.length > 0) {
            Utils.showNotification('Erreurs de validation: ' + errors.join(', '), 'warning');
        }

        return errors.length === 0;
    }

    /**
     * Get current metadata
     * @returns {Object} Current metadata object
     */
    getMetadata() {
        try {
            if (this.currentMode === 'keyvalue') {
                this.syncFromKeyValue();
            } else {
                this.syncFromJSON();
            }
        } catch (error) {
            throw new Error('Erreur de validation des métadonnées: ' + error.message);
        }

        return Utils.deepClone(this.metadata);
    }

    /**
     * Set metadata
     * @param {Object} metadata - Metadata to set
     */
    setMetadata(metadata) {
        this.metadata = Utils.deepClone(metadata) || {};
        
        if (this.currentMode === 'keyvalue') {
            this.updateKeyValueFromMetadata();
        } else {
            this.updateJSONFromMetadata();
        }
    }

    /**
     * Clear all metadata
     */
    clear() {
        this.metadata = {};
        
        if (this.currentMode === 'keyvalue') {
            this.updateKeyValueFromMetadata();
        } else {
            this.updateJSONFromMetadata();
        }
    }

    /**
     * Import metadata from file
     * @param {File} file - JSON file to import
     */
    async importFromFile(file) {
        try {
            const text = await file.text();
            const validation = Utils.validateJSON(text);
            
            if (!validation.isValid) {
                throw new Error('Fichier JSON invalide: ' + validation.error);
            }

            this.setMetadata(validation.data);
            Utils.showNotification('Métadonnées importées avec succès', 'success');
            
        } catch (error) {
            Utils.showNotification('Erreur d\'importation: ' + error.message, 'error');
        }
    }

    /**
     * Export metadata to file
     */
    exportToFile() {
        try {
            const metadata = this.getMetadata();
            const jsonString = JSON.stringify(metadata, null, 2);
            
            const blob = new Blob([jsonString], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.href = url;
            a.download = 'metadata.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            Utils.showNotification('Métadonnées exportées', 'success');
            
        } catch (error) {
            Utils.showNotification('Erreur d\'exportation: ' + error.message, 'error');
        }
    }

    /**
     * Get metadata summary
     * @returns {Object} Summary information
     */
    getSummary() {
        const keys = Object.keys(this.metadata);
        
        return {
            count: keys.length,
            keys: keys,
            totalSize: JSON.stringify(this.metadata).length,
            isEmpty: keys.length === 0
        };
    }
}

// Create global instance
const metadataEditor = new MetadataEditor();

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = MetadataEditor;
}