# MongoDB Runtime Configuration

## 🎯 Overview

The MongoDB container uses **runtime environment variables** from `mongo/.env.mongo` for database configuration. The file is automatically created with default values during the build process.

## 🔧 Quick Start

```bash
# 1. Build MongoDB image (creates .env.mongo with defaults)
make build-mongo

# 2. Customize configuration for your environment (optional)
nano images/mongo/.env.mongo

# 3. Run MongoDB container
docker run -d --name mongodb \
  --env-file mongo/.env.mongo \
  -p 27017:27017 \
  -v mongodb_data:/data/db \
  localhost/notary_mongo:v1
```

## 📁 Files Structure

```
images/mongo/
├── Dockerfile.mongo           # MongoDB container (config-agnostic)
├── .env.mongo                 # Runtime configuration (auto-created)
├── mongod.conf               # MongoDB server configuration
├── init-scripts/
│   └── 01-init-notary.js     # Database initialization script
└── README-MongoDB.md         # This documentation
```

## ⚙️ Configuration Variables

All variables in `mongo/.env.mongo` are passed as environment variables at **container runtime**:

### **MongoDB System Variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_INITDB_ROOT_USERNAME` | `admin` | MongoDB root user |
| `MONGO_INITDB_ROOT_PASSWORD` | `DevRootPassword123!` | **⚠️ Change for production!** |
| `MONGO_INITDB_DATABASE` | `opendocseal` | Initial database name |

### **Application Variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `NOTARY_DB_NAME` | `opendocseal` | Application database name |
| `NOTARY_DB_USER` | `notary_user` | Application database user |
| `NOTARY_DB_PASSWORD` | `NotarySecurePass2025!` | **⚠️ Change for production!** |
| `NOTARY_ADMIN_EMAIL` | `admin@opendocseal.local` | Default admin email |

### **Performance Variables:**
| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_LOG_LEVEL` | `1` | MongoDB log verbosity (0-5) |
| `MONGO_SLOW_QUERY_THRESHOLD` | `100` | Slow query threshold (ms) |

## 🏗️ Build vs Runtime

### **Build Time (make build-mongo):**
- ✅ Creates generic MongoDB image
- ✅ Installs tools and scripts
- ✅ Sets up file permissions
- ✅ Copies initialization scripts
- ✅ Creates `.env.mongo` with defaults if missing
- ❌ **No configuration embedded in image**

### **Runtime (docker run):**
- ✅ Loads `.env.mongo` variables
- ✅ Creates database and users
- ✅ Applies configuration
- ✅ Runs initialization scripts

## 🚀 Usage Examples

### **Development Setup:**
```bash
# 1. Build with defaults
make build-mongo

# 2. Start MongoDB
docker run -d --name mongodb \
  --env-file mongo/.env.mongo \
  -p 27017:27017 \
  localhost/notary_mongo:v1

# 3. Connect to database
mongosh mongodb://notary_user:NotarySecurePass2025!@localhost:27017/opendocseal
```

### **Production Setup:**
```bash
# 1. Build image
make build-mongo

# 2. Customize production configuration
nano mongo/.env.mongo
# Change passwords and settings!

# 3. Deploy with production environment file
docker run -d --name mongodb \
  --env-file mongo/.env.mongo \
  -v mongodb_data:/data/db \
  -v mongodb_logs:/var/log/mongodb \
  --restart unless-stopped \
  localhost/notary_mongo:v1
```

### **Connection String:**
```javascript
// Read from environment or .env.mongo
const connectionString = `mongodb://${process.env.NOTARY_DB_USER}:${process.env.NOTARY_DB_PASSWORD}@mongodb:27017/${process.env.NOTARY_DB_NAME}`;

// Example with default values
const connectionString = "mongodb://notary_user:NotarySecurePass2025!@mongodb:27017/opendocseal";
```

## 🛠️ Makefile Commands

| Command | Purpose |
|---------|---------|
| `make build-mongo` | Build MongoDB image (creates .env.mongo if missing) |
| `make build` | Build all images (includes MongoDB) |
| `make info` | Show build information |

## 📋 Best Practices

### **🔐 Security:**
- Always change default passwords in `.env.mongo`
- Use strong, unique passwords for each environment
- Restrict network access to MongoDB port (27017)
- Keep `.env.mongo` out of version control

### **🔄 Configuration Management:**
- Keep separate `.env.mongo` files per environment
- Use container orchestration secrets in production
- Test configuration changes in development first

### **📊 Monitoring:**
- Configure appropriate `MONGO_LOG_LEVEL` for your needs
- Set `MONGO_SLOW_QUERY_THRESHOLD` based on performance requirements
- Use persistent volumes for data retention

## ⚠️ Important Notes

- **Runtime configuration**: Changes take effect on container restart
- **Environment file security**: Keep `.env.mongo` files secure
- **Default passwords**: Always change for production use
- **Data persistence**: Use Docker volumes for `/data/db` in production

## 📜 Example Production Configuration

```bash
# mongo/.env.mongo for production
MONGO_INITDB_ROOT_USERNAME=admin
MONGO_INITDB_ROOT_PASSWORD=YourVerySecureRootPassword2025!
MONGO_INITDB_DATABASE=opendocseal_prod

NOTARY_DB_NAME=opendocseal_prod
NOTARY_DB_USER=notary_prod_user  
NOTARY_DB_PASSWORD=SuperSecureNotaryPassword2025!
NOTARY_ADMIN_EMAIL=admin@yourcompany.com

MONGO_LOG_LEVEL=2
MONGO_SLOW_QUERY_THRESHOLD=50
MONGO_DISABLE_JAVASCRIPT=true
MONGO_ENABLE_AUTH=true
```