# OpenDocSeal API

API REST complète pour OpenDocSeal - Système de notarisation de documents avec blockchain et horodatage cryptographique.

## 🎯 Fonctionnalités

- **📄 Gestion des documents** : Upload, stockage sécurisé et récupération
- **🔗 Horodatage blockchain** : Preuve d'intégrité via OpenTimestamps
- **👤 Authentification complète** : JWT, SSO, API Keys
- **🪣 Stockage objet** : MinIO pour les fichiers et preuves
- **📋 Audit complet** : Traçabilité de toutes les opérations
- **⚡ Rate limiting** : Protection contre les abus
- **🧪 Tests intégrés** : Services mock pour développement

## 🚀 Installation et Configuration

### 1. Prérequis

- Python 3.11+
- MongoDB 4.4+
- MinIO ou S3 compatible
- Redis (optionnel, pour cache/rate limiting)

### 2. Installation

```bash
cd infrastructure/source/api
pip install -r requirements.txt
```

### 3. Configuration

```bash
# Copier le fichier de configuration d'exemple
cp .env.example .env

# Éditer .env avec vos paramètres
nano .env
```

#### Configuration minimale requise :

```env
# Sécurité (OBLIGATOIRE - changer en production)
SECRET_KEY="your-super-secret-key-change-this-in-production-min-32-chars"

# Base de données
MONGODB_URL="mongodb://localhost:27017"

# Stockage objet
MINIO_ENDPOINT="localhost:9000"
MINIO_ACCESS_KEY="minioadmin"
MINIO_SECRET_KEY="minioadmin"
MINIO_SECURE=false  # true en production
```

### 4. Validation de l'installation

```bash
python validate.py
```

### 5. Démarrage

```bash
# Mode développement
python run.py

# Mode production
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker
```

## 🎯 Endpoints Principaux

Une fois l'API démarrée :

- **📚 Documentation interactive** : http://localhost:8000/docs
- **🔍 Health Check** : http://localhost:8000/health
- **ℹ️ Version** : http://localhost:8000/version
- **🔐 Authentification** : http://localhost:8000/api/v1/auth/*
- **📄 Documents** : http://localhost:8000/api/v1/documents/*

## 🧪 Mode Test et Développement

### Démarrage en mode test

```bash
TEST_MODE=true python run.py
```

En mode test :
- Services blockchain et stockage simulés
- Base de données test séparée
- Endpoints de contrôle disponibles : http://localhost:8000/api/test/*
- Pas de rate limiting
- Logs détaillés

### Endpoints de test

- `GET /api/test/state` - État de l'environnement de test
- `POST /api/test/reset` - Reset complet de l'environnement
- `POST /api/test/services/control` - Contrôle des services mock
- `GET /api/test/events` - Événements de test capturés

## 🗗️ Architecture

### Pattern de Factory

L'API utilise le pattern Factory pour une architecture modulaire :

```python
# Services en mode production
factory = get_service_factory()
blockchain_service = factory.create_blockchain_service()  # Service réel
storage_service = factory.create_storage_service()       # MinIO réel

# Services en mode test
test_factory = get_test_service_factory()
blockchain_service = test_factory.create_blockchain_service()  # Service mock
storage_service = test_factory.create_storage_service()       # Service mock
```

### Services Disponibles

- **🔗 BlockchainService** : Horodatage OpenTimestamps/Bitcoin
- **🪣 StorageService** : Stockage MinIO/S3
- **👤 AuthService** : Authentification JWT/SSO
- **📄 DocumentService** : Orchestration des documents

### Modes de Fonctionnement

| Service | Production | Mock | Description |
|---------|------------|------|-------------|
| **Blockchain** | OpenTimestamps réel | Simulation rapide | Horodatage cryptographique |
| **Storage** | MinIO/S3 | Stockage mémoire | Stockage des fichiers |
| **Auth** | JWT + Base | Utilisateurs test | Authentification |

## 📁 Structure du Projet

```
infrastructure/source/api/
├── 📄 main.py              # Point d'entrée FastAPI
├── ⚙️ config.py           # Configuration centralisée
├── 🗄️ database.py         # Gestion MongoDB avec indexes
├── 🔗 dependencies.py     # Dépendances FastAPI injectées
├── 🚀 run.py              # Script de démarrage
├── ✅ validate.py         # Validation de l'installation
├── 📋 requirements.txt    # Dépendances Python
├── 🔧 .env.example        # Configuration d'exemple
│
├── 📊 models/             # Modèles Pydantic
│   ├── base.py           # Modèles de base et énumérations
│   ├── auth.py           # Modèles d'authentification
│   ├── document.py       # Modèles de documents
│   ├── blockchain.py     # Modèles blockchain
│   ├── metadata.py       # Modèles de métadonnées
│   └── user.py           # Modèles utilisateur étendus
│
├── 🔧 services/          # Services métier
│   ├── interfaces.py     # Interfaces abstraites
│   ├── auth.py          # Service d'authentification
│   ├── blockchain.py    # Service blockchain
│   ├── storage.py       # Service de stockage
│   ├── document.py      # Service de documents
│   └── mocks/           # Services simulés pour tests
│
├── 🌐 routes/            # Endpoints REST (FIXED: was routers/)
│   ├── auth.py          # Authentification
│   ├── documents.py     # Gestion des documents
│   ├── health.py        # Contrôles de santé
│   └── test_control.py  # Contrôle des tests
│
├── 🛠️ utils/             # Utilitaires
│   ├── logging.py       # Logging avec corrélation
│   ├── security.py      # Sécurité et cryptographie
│   └── rate_limiting.py # Limitation de débit
│
└── 🏭 factories/         # Factory Pattern
    └── service_factory.py  # Factory pour services
```

## 🔐 Sécurité

### Authentification

- **JWT** : Tokens d'accès avec expiration
- **Refresh tokens** : Renouvellement sécurisé
- **API Keys** : Accès programmatique
- **SSO** : Support OIDC/SAML (optionnel)

### Protection

- **Rate limiting** : Multiple stratégies (sliding window, token bucket)
- **Input validation** : Validation stricte des entrées
- **Audit logging** : Traçabilité complète
- **CORS** : Configuration des origines autorisées

### Chiffrement

- **Bcrypt** : Hachage des mots de passe
- **JWT** : Tokens signés
- **SHA256** : Intégrité des documents
- **HMAC** : Signature des URLs

## 📊 Monitoring et Observabilité

### Health Checks

- `GET /health` - Santé basique
- `GET /health/ready` - Disponibilité complète
- `GET /health/live` - Test de vivacité
- `GET /health/detailed` - Santé détaillée (admin)
- `GET /health/metrics` - Métriques système (admin)

### Logs Structurés

- **Corrélation** : ID de suivi des requêtes
- **Niveaux** : DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Formats** : Text (dev) / JSON (prod)
- **Audit** : Traçabilité des actions utilisateur

### Rate Limiting

Règles prédéfinies par type d'utilisateur :
- **Anonymous** : 100 req/h
- **API Key** : 1000 req/h  
- **Admin** : 5000 req/h
- **Auth endpoints** : 5 req/5min

## 🗄️ Base de Données

### Collections MongoDB

- **users** : Utilisateurs et profils
- **documents** : Métadonnées des documents
- **blockchain_transactions** : Transactions blockchain
- **audit_logs** : Logs d'audit (TTL 90 jours)
- **api_keys** : Clés d'API
- **user_sessions** : Sessions utilisateur (TTL)

### Indexes Automatiques

Tous les indexes sont créés automatiquement au démarrage :
- Index unique sur email utilisateur
- Index de performance sur les documents
- Index TTL pour les données temporaires
- Index de recherche textuelle

## 🚀 Déploiement

### Variables d'Environnement Importantes

```env
# Production
ENVIRONMENT="production"
DEBUG=false
SECRET_KEY="production-secret-key-32-chars-minimum"

# Base de données
MONGODB_URL="mongodb://prod-host:27017"
MONGODB_DB_NAME="opendocseal_prod"

# Stockage
MINIO_ENDPOINT="prod-minio:9000"
MINIO_SECURE=true
MINIO_ACCESS_KEY="production-access-key"
MINIO_SECRET_KEY="production-secret-key"

# Blockchain
BLOCKCHAIN_NETWORK="mainnet"
BLOCKCHAIN_MODE="production"

# Sécurité
RATE_LIMIT_ENABLED=true
LOG_LEVEL="WARNING"
LOG_FORMAT="json"
```

### Docker (Recommandé)

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Production avec Gunicorn

```bash
gunicorn main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile - \
  --error-logfile -
```

## 🧪 Tests

### Tests Unitaires

```bash
# Avec pytest (à installer)
pytest tests/

# Tests manuels avec les endpoints de test
curl -X POST http://localhost:8000/api/test/reset
curl -X GET http://localhost:8000/api/test/health
```

### Scénarios de Test

L'API inclut des endpoints de test pour valider :
- ✅ Création et récupération de documents
- ✅ Horodatage blockchain (simulé)
- ✅ Authentification et autorisation
- ✅ Rate limiting
- ✅ Corrélation des requêtes

## 📖 API Usage Examples

### Authentification

```bash
# Inscription
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!","name":"Test User"}'

# Connexion
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"SecurePass123!"}'
```

### Gestion des Documents

```bash
# Créer un document
curl -X POST http://localhost:8000/api/v1/documents \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"contract.pdf",
    "hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "size":1024,
    "file_type":"application/pdf",
    "metadata":{"author":"John Doe","type":"contract"}
  }'

# Vérifier un document
curl -X POST http://localhost:8000/api/v1/documents/verify \
  -H "Content-Type: application/json" \
  -d '{"hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'
```

## 🤝 Contribution

### Code Style

- **Format** : Black + isort
- **Linting** : flake8 + mypy
- **Docstrings** : Google style
- **Comments** : English only

### Tests

Tous les nouveaux services doivent inclure :
- Interface abstraite
- Implémentation production  
- Service mock pour tests
- Tests unitaires

## 📄 License

Ce projet est sous licence propriétaire. Voir le fichier LICENSE pour plus de détails.

---

## 🎯 Statut du Projet

✅ **Architecture complète** - Factory pattern, services, interfaces (FIXED)
✅ **Authentification** - JWT, API Keys, SSO ready (FIXED: LoginRequest signature)  
✅ **Documents** - Upload, stockage, récupération sécurisée (FIXED: Mock service added)
✅ **Blockchain** - Horodatage OpenTimestamps
✅ **Base de données** - MongoDB avec indexes optimisés
✅ **Sécurité** - Rate limiting, validation, audit
✅ **Tests** - Services mock, endpoints de contrôle (FIXED: Complete mock coverage)
✅ **Monitoring** - Health checks, logs corrélés, métriques
✅ **Production ready** - Configuration, déploiement, documentation (FIXED: Dependency injection)

**L'API OpenDocSeal est maintenant complète, cohérente et prête pour la production ! 🚀**

### 🔧 Corrections Récentes (Version 4)

- ✅ **CRITIQUE** : Fixed FastAPI dependency injection pattern avec cache LRU
- ✅ **CRITIQUE** : Supprimé duplication MockAuthService et ajouté DocumentMockService 
- ✅ **MAJEUR** : Harmonisé signatures interface LoginRequest vs routes
- ✅ **MAJEUR** : Corrigé TestServiceFactory pour respecter la configuration
- ✅ **MAJEUR** : Mis à jour structure `routers/` → `routes/` dans documentation
- ✅ **MINEUR** : Amélioré cohérence architecturale générale