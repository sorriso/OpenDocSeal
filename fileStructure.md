OpenDocSeal Frontend - Structure de Projet
===========================================

OpenDocSeal/
├── frontend/
│   ├── index.html
│   ├── css/
│   │   ├── main.css
│   │   └── components.css
│   ├── js/
│   │   ├── app.js               # Application principale
│   │   ├── api-client.js        # Client API
│   │   ├── file-handler.js      # Gestion fichiers + SHA256
│   │   ├── metadata-editor.js   # Éditeur métadonnées
│   │   ├── document-list.js     # Liste documents
│   │   └── utils.js             # Utilitaires
│   └── components/
│       ├── upload-form.html
│       └── document-card.html
│
├── api/
│   ├── main.py                  # Point d'entrée FastAPI
│   ├── models/
│   │   ├── document.py          # Modèles document
│   │   ├── user.py              # Modèles utilisateur
│   │   └── metadata.py          # Modèles métadonnées
│   ├── routes/
│   │   ├── auth.py              # Routes authentification
│   │   ├── documents.py         # Routes documents
│   │   └── metadata.py          # Routes métadonnées
│   └── services/
│       ├── blockchain.py        # Service blockchain/OTS
│       ├── storage.py           # Service MinIO
│       └── notary.py            # Service notarisation
│
└── documentation/
    └── fileStructure.md