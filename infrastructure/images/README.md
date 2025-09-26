# Build System - OpenDocSeal

Automated build system for OpenDocSeal project Docker images with build-time configuration.

**Version**: 4 (Updated: 2025-09-18)

## 🚀 Quick Start

```bash
# Build all images
make build

# Build specific image
make build-api
make build-app
make build-rp
make build-minio
make build-mongo    # Auto-configures MongoDB
make build-n8n

# Build information
make info
make info-mongo     # MongoDB-specific configuration
```

## 📁 Structure

```
/images/
├── Makefile                 # Build system
├── .env.build              # Build configuration
├── api/Dockerfile.api      # FastAPI API image
├── app/Dockerfile.app      # Frontend image (Caddy)
├── rp/Dockerfile.rp        # Reverse Proxy image (Caddy)
├── minio/
│   ├── Dockerfile.minio    # MinIO image
│   ├── .env.minio         # Runtime MinIO config (auto-created)
│   └── init-scripts/      # Bucket initialization
├── mongo/
│   ├── Dockerfile.mongo    # MongoDB image
│   ├── .env.mongo         # Runtime MongoDB config (auto-created)
│   ├── mongod.conf        # MongoDB server configuration
│   └── init-scripts/      # Database initialization
└── n8n/Dockerfile.n8n      # N8N automation image
```

## 🔧 Configuration Files

### **Global Build Configuration (`.env.build`)**

```bash
# Base images
PYTHON_BASE_IMAGE=python:3.11-slim
CADDY_BASE_IMAGE=caddy:latest
CADDY_BUILDER_BASE_IMAGE=caddy:builder-alpine
MINIO_BASE_IMAGE=minio/minio:RELEASE.2024-01-01T16-36-33Z
MONGO_BASE_IMAGE=mongo:7.0
N8N_BASE_IMAGE=n8nio/n8n:1.19.4

# Versioning (automatically updated)
IMAGE_BUILD_VERSION=1.0.0
IMAGE_BUILD_NUMBER=15
IMAGE_BUILD_DATE=2025-09-18T14:42:00Z
```

### **MongoDB Runtime Config (`mongo/.env.mongo`)**

```bash
# MongoDB System Configuration
MONGO_INITDB_ROOT_USERNAME=admin
MONGO_INITDB_ROOT_PASSWORD=DevRootPassword123!  # ⚠️ Change this!
MONGO_INITDB_DATABASE=opendocseal

# Application Database Configuration
NOTARY_DB_NAME=opendocseal
NOTARY_DB_USER=notary_user
NOTARY_DB_PASSWORD=NotarySecurePass2025!  # ⚠️ Change this!
NOTARY_ADMIN_EMAIL=admin@opendocseal.local
```

### **MinIO Runtime Config (`minio/.env.minio`)**

```bash
# MinIO Admin Credentials
MINIO_ROOT_USER=opendocseal
MINIO_ROOT_PASSWORD=OpenDocSeal2025!  # ⚠️ Change this!

# MinIO Configuration
MINIO_BROWSER=on
MINIO_BROWSER_REDIRECT_URL=http://localhost:9001
MINIO_SERVER_URL=http://localhost:9000

# Application Configuration
OPENDOCSEAL_BUCKET_NAME=opendocseal-documents
OPENDOCSEAL_BUCKET_REGION=us-east-1
```

## 🔄 Automatic Processes

### **All Images:**
1. **Auto-increment**: Build number automatically increments
2. **Timestamp**: Build date automatically updated  
3. **Multi-tagging**: 
   - `notary_<service>:v<build_number>`
   - `localhost/notary_<service>:v<build_number>` (for Kubernetes)

### **Special Service Features:**

#### **MongoDB:**
1. **Runtime configuration**: Uses `mongo/.env.mongo` for environment variables
2. **Auto-file creation**: Creates `.env.mongo` from defaults if missing
3. **Database initialization**: Pre-configured collections and indexes
4. **Default admin user**: Ready-to-use admin account

#### **MinIO:**
1. **Runtime configuration**: Uses `minio/.env.minio` for environment variables  
2. **Auto-file creation**: Creates `.env.minio` from defaults if missing
3. **Bucket initialization**: Auto-creates application buckets with structure
4. **MinIO Console**: Web interface ready at http://localhost:9001

## 📦 Generated Images

| Service | Image | Description | Ports |
|---------|-------|-------------|-------|
| API | `notary_api:v15` | FastAPI Backend | 8000 |
| App | `notary_app:v15` | Frontend (Caddy) | 80, 443 |
| RP | `notary_rp:v15` | Reverse Proxy (Caddy) | 80, 443, 8080 |
| MinIO | `notary_minio:v15` | Object Storage + Console | 9000, 9001 |
| MongoDB | `notary_mongo:v15` | Database | 27017 |
| N8N | `notary_n8n:v15` | Workflow Automation | 5678 |

## 🛠️ Commands

| Command | Description |
|----------|-------------|
| `make build` | Build all images + increment build number |
| `make build-<service>` | Build specific image (api, app, rp, minio, mongo, n8n) |
| `make pull-all` | Pull all base images |
| `make info` | Show current global configuration |
| `make clean` | Clean Docker artifacts |
| `make help` | Help |

## 🔧 Service Configuration

Both MongoDB and MinIO use **runtime environment variables** with automatic default setup:

### **MongoDB:**
```bash
# Build MongoDB image (creates .env.mongo with defaults if missing)
make build-mongo

# Edit MongoDB configuration
nano mongo/.env.mongo

# Run with environment variables
docker run -d --name mongodb \
  --env-file mongo/.env.mongo \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  localhost/notary_mongo:v1
```

**Default MongoDB values:**
- Database: `opendocseal` | User: `notary_user` | Admin: `admin@opendocseal.local`
- ⚠️ **Change passwords for production!**

### **MinIO:**
```bash
# Build MinIO image (creates .env.minio with defaults if missing)
make build-minio

# Edit MinIO configuration
nano minio/.env.minio

# Run with environment variables
docker run -d --name minio \
  --env-file minio/.env.minio \
  -p 9000:9000 -p 9001:9001 \
  -v minio_data:/data \
  localhost/notary_minio:v1
```

**Default MinIO values:**
- User: `opendocseal` | Password: `OpenDocSeal2025!` | Bucket: `opendocseal-documents`
- Console: http://localhost:9001 | API: http://localhost:9000
- ⚠️ **Change passwords for production!**

## 🔧 Prerequisites

- Docker Engine
- Make
- Access to base image registries

## 💡 Typical Workflow

```bash
# 1. Check configuration
make info

# 2. Build
make build

# 3. Verify images
docker images | grep notary
```

---

**Note** : Build number automatically increments on each `make build`. `localhost/` tags are created for Kubernetes integration.