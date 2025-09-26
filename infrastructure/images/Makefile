# File: Makefile
# Path: images/Makefile
# Version: 39 - FIXED BASE IMAGE DISPLAY
# =============================================================================
# OpenDocSeal Build System - Docker Images Builder
# =============================================================================

# Load configuration from environment file
include .env.build

# Detect operating system for sed compatibility
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    SED_INPLACE = sed -i ''
else
    SED_INPLACE = sed -i
endif

# Common variables (computed at runtime)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build info display colors
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[1;37m
RESET := \033[0m

# =============================================================================
# Main Targets
# =============================================================================

.PHONY: build build-api build-app build-rp build-minio build-mongo build-n8n
.PHONY: update-build create-mongo-env create-minio-env
.PHONY: pull-all info info-mongo status clean clean-all help

# Build all images with automatic version increment
build: update-build
	@CURRENT_BUILD=$$(grep '^IMAGE_BUILD_NUMBER=' .env.build | cut -d'=' -f2) && \
	echo "$(CYAN)🚀 Building OpenDocSeal Docker Images...$(RESET)" && \
	echo "$(WHITE)Build Number: v$$CURRENT_BUILD$(RESET)" && \
	echo "$(WHITE)Build Date: $(BUILD_DATE)$(RESET)" && \
	echo ""
	$(MAKE) build-api
	$(MAKE) build-app
	$(MAKE) build-rp
	$(MAKE) build-minio
	$(MAKE) build-mongo
	$(MAKE) build-n8n
	@echo ""
	@echo "$(GREEN)✅ All images built successfully!$(RESET)"
	@echo "$(YELLOW)📋 To see all images: make status$(RESET)"

# =============================================================================
# Build Information Update
# =============================================================================

# Update build information in .env.build file
update-build:
	@echo "$(BLUE)📄 Updating build information...$(RESET)"
	@NEXT_BUILD=$$(expr $(IMAGE_BUILD_NUMBER) + 1) && \
	$(SED_INPLACE) "s/^IMAGE_BUILD_NUMBER=.*/IMAGE_BUILD_NUMBER=$$NEXT_BUILD/" .env.build && \
	$(SED_INPLACE) "s/^IMAGE_BUILD_DATE=.*/IMAGE_BUILD_DATE=$(BUILD_DATE)/" .env.build && \
	echo "$(GREEN)✅ Build updated: v$$NEXT_BUILD - $(BUILD_DATE)$(RESET)"

# =============================================================================
# Individual Service Builds
# =============================================================================

# Build FastAPI Backend
build-api:
	@if [ ! -f ../../source/api/requirements.txt ]; then \
		echo "$(RED)❌ Error: ../../source/api/requirements.txt not found$(RESET)"; \
		exit 1; \
	fi; \
	CURRENT_BUILD=$$(grep '^IMAGE_BUILD_NUMBER=' .env.build | cut -d'=' -f2); \
	echo "$(PURPLE)🔨 Building API image v$$CURRENT_BUILD...$(RESET)"; \
	echo "$(PURPLE)🔨 Base image: $(PYTHON_BASE_IMAGE)$(RESET)"; \
	cd ../..; \
	nerdctl build \
		--namespace k8s.io \
		--build-arg PYTHON_BASE_IMAGE=$(PYTHON_BASE_IMAGE) \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_VERSION="$(IMAGE_BUILD_VERSION)" \
		-t k8s.io/opendocseal_api:v$$CURRENT_BUILD \
		-t k8s.io/opendocseal_api:latest \
		-f infrastructure/images/api/Dockerfile.api \
		.; \
	echo "$(GREEN)✅ API image built: k8s.io/opendocseal_api:v$$CURRENT_BUILD$(RESET)"

# Build Frontend Application
build-app:
	@CURRENT_BUILD=$$(grep '^IMAGE_BUILD_NUMBER=' .env.build | cut -d'=' -f2); \
	echo "$(PURPLE)🔨 Building App image v$$CURRENT_BUILD...$(RESET)"; \
	echo "$(PURPLE)🔨 Base image: $(CADDY_BASE_IMAGE)$(RESET)"; \
	cd ../..; \
	nerdctl build \
		--namespace k8s.io \
		--build-arg CADDY_BASE_IMAGE=$(CADDY_BASE_IMAGE) \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_VERSION="$(IMAGE_BUILD_VERSION)" \
		-t k8s.io/opendocseal_app:v$$CURRENT_BUILD \
		-t k8s.io/opendocseal_app:latest \
		-f infrastructure/images/app/Dockerfile.app \
		.; \
	echo "$(GREEN)✅ App image built: k8s.io/opendocseal_app:v$$CURRENT_BUILD$(RESET)"

# Build Reverse Proxy
build-rp:
	@CURRENT_BUILD=$$(grep '^IMAGE_BUILD_NUMBER=' .env.build | cut -d'=' -f2); \
	echo "$(PURPLE)🔨 Building Reverse Proxy image v$$CURRENT_BUILD...$(RESET)"; \
	echo "$(PURPLE)🔨 Base image: $(CADDY_BUILDER_BASE_IMAGE)$(RESET)"; \
	cd ../..; \
	nerdctl build \
		--namespace k8s.io \
		--build-arg CADDY_BUILDER_BASE_IMAGE=$(CADDY_BUILDER_BASE_IMAGE) \
		--build-arg CADDY_BASE_IMAGE=$(CADDY_BASE_IMAGE) \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_VERSION="$(IMAGE_BUILD_VERSION)" \
		-t k8s.io/opendocseal_rp:v$$CURRENT_BUILD \
		-t k8s.io/opendocseal_rp:latest \
		-f infrastructure/images/rp/Dockerfile.rp \
		.; \
	echo "$(GREEN)✅ Reverse Proxy image built: k8s.io/opendocseal_rp:v$$CURRENT_BUILD$(RESET)"

# Build MinIO Object Storage
build-minio: create-minio-env
	@CURRENT_BUILD=$$(grep '^IMAGE_BUILD_NUMBER=' .env.build | cut -d'=' -f2); \
	echo "$(PURPLE)🔨 Building MinIO image v$$CURRENT_BUILD...$(RESET)"; \
	echo "$(PURPLE)🔨 Base image: $(MINIO_BASE_IMAGE)$(RESET)"; \
	cd ../..; \
	nerdctl build \
		--namespace k8s.io \
		--build-arg MINIO_BASE_IMAGE=$(MINIO_BASE_IMAGE) \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_VERSION="$(IMAGE_BUILD_VERSION)" \
		-t k8s.io/opendocseal_minio:v$$CURRENT_BUILD \
		-t k8s.io/opendocseal_minio:latest \
		-f infrastructure/images/minio/Dockerfile.minio \
		.; \
	echo "$(GREEN)✅ MinIO image built: k8s.io/opendocseal_minio:v$$CURRENT_BUILD$(RESET)"; \
	echo "$(YELLOW)📋 MinIO Console: http://localhost:9001 | API: http://localhost:9000$(RESET)"

# Build MongoDB Database
build-mongo: create-mongo-env
	@CURRENT_BUILD=$$(grep '^IMAGE_BUILD_NUMBER=' .env.build | cut -d'=' -f2); \
	echo "$(PURPLE)🔨 Building MongoDB image v$$CURRENT_BUILD...$(RESET)"; \
	echo "$(PURPLE)🔨 Base image: $(MONGO_BASE_IMAGE)$(RESET)"; \
	cd ../..; \
	nerdctl build \
		--namespace k8s.io \
		--build-arg MONGO_BASE_IMAGE=$(MONGO_BASE_IMAGE) \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_VERSION="$(IMAGE_BUILD_VERSION)" \
		-t k8s.io/opendocseal_mongo:v$$CURRENT_BUILD \
		-t k8s.io/opendocseal_mongo:latest \
		-f infrastructure/images/mongo/Dockerfile.mongo \
		.; \
	echo "$(GREEN)✅ MongoDB image built: k8s.io/opendocseal_mongo:v$$CURRENT_BUILD$(RESET)"; \
	echo "$(YELLOW)📋 Database: opendocseal | User: opendocseal_user | Port: 27017$(RESET)"

# Build N8N Automation
build-n8n:
	@CURRENT_BUILD=$$(grep '^IMAGE_BUILD_NUMBER=' .env.build | cut -d'=' -f2); \
	echo "$(PURPLE)🔨 Building N8N image v$$CURRENT_BUILD...$(RESET)"; \
	echo "$(PURPLE)🔨 Base image: $(N8N_BASE_IMAGE)$(RESET)"; \
	cd ../..; \
	nerdctl build \
		--namespace k8s.io \
		--build-arg N8N_BASE_IMAGE=$(N8N_BASE_IMAGE) \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_VERSION="$(IMAGE_BUILD_VERSION)" \
		-t k8s.io/opendocseal_n8n:v$$CURRENT_BUILD \
		-t k8s.io/opendocseal_n8n:latest \
		-f infrastructure/images/n8n/Dockerfile.n8n \
		.; \
	echo "$(GREEN)✅ N8N image built: k8s.io/opendocseal_n8n:v$$CURRENT_BUILD$(RESET)"

# =============================================================================
# Environment Files Creation
# =============================================================================

# Create MinIO environment file with defaults if missing
create-minio-env:
	@if [ ! -f minio/.env.minio ]; then \
		echo "$(BLUE)🔧 Creating default MinIO configuration...$(RESET)"; \
		mkdir -p minio; \
		echo "# File: .env.minio" > minio/.env.minio; \
		echo "# Path: images/minio/.env.minio" >> minio/.env.minio; \
		echo "# Version: 1" >> minio/.env.minio; \
		echo "# =============================================================================" >> minio/.env.minio; \
		echo "# MinIO Runtime Configuration - OpenDocSeal" >> minio/.env.minio; \
		echo "# =============================================================================" >> minio/.env.minio; \
		echo "" >> minio/.env.minio; \
		echo "# MinIO Admin Credentials" >> minio/.env.minio; \
		echo "MINIO_ROOT_USER=opendocseal" >> minio/.env.minio; \
		echo "MINIO_ROOT_PASSWORD=OpenDocSeal2025!" >> minio/.env.minio; \
		echo "" >> minio/.env.minio; \
		echo "# MinIO Configuration" >> minio/.env.minio; \
		echo "MINIO_BROWSER=on" >> minio/.env.minio; \
		echo "MINIO_BROWSER_REDIRECT_URL=http://localhost:9001" >> minio/.env.minio; \
		echo "MINIO_SERVER_URL=http://localhost:9000" >> minio/.env.minio; \
		echo "" >> minio/.env.minio; \
		echo "# Application Configuration" >> minio/.env.minio; \
		echo "OPENDOCSEAL_BUCKET_NAME=opendocseal-documents" >> minio/.env.minio; \
		echo "OPENDOCSEAL_BUCKET_REGION=us-east-1" >> minio/.env.minio; \
		echo "$(GREEN)✅ MinIO configuration created: minio/.env.minio$(RESET)"; \
	fi

# Create MongoDB environment file with defaults if missing
create-mongo-env:
	@if [ ! -f mongo/.env.mongo ]; then \
		echo "$(BLUE)🔧 Creating default MongoDB configuration...$(RESET)"; \
		mkdir -p mongo; \
		echo "# File: .env.mongo" > mongo/.env.mongo; \
		echo "# Path: images/mongo/.env.mongo" >> mongo/.env.mongo; \
		echo "# Version: 1" >> mongo/.env.mongo; \
		echo "# =============================================================================" >> mongo/.env.mongo; \
		echo "# MongoDB Runtime Configuration - OpenDocSeal" >> mongo/.env.mongo; \
		echo "# =============================================================================" >> mongo/.env.mongo; \
		echo "" >> mongo/.env.mongo; \
		echo "# MongoDB System Configuration" >> mongo/.env.mongo; \
		echo "MONGO_INITDB_ROOT_USERNAME=admin" >> mongo/.env.mongo; \
		echo "MONGO_INITDB_ROOT_PASSWORD=DevRootPassword123!" >> mongo/.env.mongo; \
		echo "MONGO_INITDB_DATABASE=opendocseal" >> mongo/.env.mongo; \
		echo "" >> mongo/.env.mongo; \
		echo "# Application Database Configuration" >> mongo/.env.mongo; \
		echo "OPENDOCSEAL_DB_NAME=opendocseal" >> mongo/.env.mongo; \
		echo "OPENDOCSEAL_DB_USER=opendocseal_user" >> mongo/.env.mongo; \
		echo "OPENDOCSEAL_DB_PASSWORD=opendocsealSecurePass2025!" >> mongo/.env.mongo; \
		echo "OPENDOCSEAL_ADMIN_EMAIL=admin@opendocseal.local" >> mongo/.env.mongo; \
		echo "" >> mongo/.env.mongo; \
		echo "# Performance Configuration" >> mongo/.env.mongo; \
		echo "MONGO_LOG_LEVEL=1" >> mongo/.env.mongo; \
		echo "MONGO_SLOW_QUERY_THRESHOLD=100" >> mongo/.env.mongo; \
		echo "$(GREEN)✅ MongoDB configuration created: mongo/.env.mongo$(RESET)"; \
	fi

# =============================================================================
# Utility Targets
# =============================================================================

# Pull all base images
pull-all:
	@echo "$(BLUE)📥 Pulling all base images...$(RESET)"
	docker pull $(PYTHON_BASE_IMAGE)
	docker pull $(CADDY_BASE_IMAGE)
	docker pull $(CADDY_BUILDER_BASE_IMAGE)
	docker pull $(MINIO_BASE_IMAGE)
	docker pull $(MONGO_BASE_IMAGE)
	docker pull $(N8N_BASE_IMAGE)
	@echo "$(GREEN)✅ All base images pulled$(RESET)"

# List available OpenDocSeal images
status:
	@echo "$(CYAN)📋 OpenDocSeal Available Images$(RESET)"
	@echo "$(WHITE)=================================================$(RESET)"
	@echo ""
	@echo "$(YELLOW)🏷️  Default Namespace (k8s.io/opendocseal_*):$(RESET)"
	@nerdctl --namespace default images | head -1
	@nerdctl --namespace default images | grep "^k8s.io/opendocseal_" | sort || echo "$(RED)  No k8s.io/opendocseal images found in default namespace$(RESET)"
	@echo ""
	@echo "$(YELLOW)🏷️  K8s.io Namespace (k8s.io/opendocseal_*):$(RESET)"
	@nerdctl --namespace k8s.io images | head -1 2>/dev/null || echo "REPOSITORY                     TAG              IMAGE ID        CREATED           PLATFORM       SIZE       BLOB SIZE"
	@nerdctl --namespace k8s.io images | grep "^k8s.io/opendocseal_" | sort 2>/dev/null || echo "$(RED)  No k8s.io/opendocseal images found in k8s.io namespace$(RESET)"
	@echo ""
	@CURRENT_BUILD=$$(grep '^IMAGE_BUILD_NUMBER=' .env.build 2>/dev/null | cut -d'=' -f2); \
	if [ -z "$$CURRENT_BUILD" ]; then CURRENT_BUILD="unknown"; fi; \
	echo "$(PURPLE)📊 Current Build Info:$(RESET)"; \
	echo "  Expected Version: v$$CURRENT_BUILD"; \
	echo "$(YELLOW)💡 Use 'make build' to create images $(RESET)"

# Display build information
info:
	@echo "$(CYAN)📋 OpenDocSeal Build Information$(RESET)"
	@echo "$(WHITE)=================================================$(RESET)"
	@echo "$(YELLOW)  Project Version:$(RESET) $(IMAGE_BUILD_VERSION)"
	@echo "$(YELLOW)  Current Build:$(RESET)   $(IMAGE_BUILD_NUMBER)"
	@echo "$(YELLOW)  Build Date:$(RESET)      $(IMAGE_BUILD_DATE)"
	@echo "$(WHITE)=================================================$(RESET)"
	@echo "$(PURPLE)  Base Images:$(RESET)"
	@echo "    Python:       $(PYTHON_BASE_IMAGE)"
	@echo "    Caddy:        $(CADDY_BASE_IMAGE)"
	@echo "    Caddy Builder: $(CADDY_BUILDER_BASE_IMAGE)"
	@echo "    MinIO:        $(MINIO_BASE_IMAGE)"
	@echo "    MongoDB:      $(MONGO_BASE_IMAGE)"
	@echo "    N8N:          $(N8N_BASE_IMAGE)"

# Display MongoDB specific information
info-mongo:
	@echo "$(CYAN)📋 MongoDB Configuration$(RESET)"
	@echo "$(WHITE)=================================================$(RESET)"
	@if [ -f mongo/.env.mongo ]; then \
		echo "$(GREEN)✅ Configuration file: mongo/.env.mongo$(RESET)"; \
		echo "$(YELLOW)  Default Database:$(RESET) opendocseal"; \
		echo "$(YELLOW)  Default User:$(RESET)     opendocseal_user"; \
		echo "$(YELLOW)  Admin Email:$(RESET)      admin@opendocseal.local"; \
		echo "$(YELLOW)  Port:$(RESET)             27017"; \
		echo "$(RED)⚠️  Change passwords for production!$(RESET)"; \
	else \
		echo "$(RED)❌ Configuration file not found$(RESET)"; \
		echo "$(YELLOW)🔧 Run 'make create-mongo-env' to create defaults$(RESET)"; \
	fi

# =============================================================================
# Clean Targets
# =============================================================================

# Clean only OpenDocSeal images
clean:
	@echo "$(BLUE)🧹 Cleaning OpenDocSeal images...$(RESET)"
	@echo "$(YELLOW)  -> Removing opendocseal_* images...$(RESET)"
	@nerdctl images --namespace "default" --format "{{.Repository}}:{{.Tag}}" | grep "opendocseal" | xargs -r nerdctl --namespace "default" rmi -f 2>/dev/null || true
	@nerdctl images --namespace "k8s.io" --format "{{.Repository}}:{{.Tag}}" | grep "opendocseal" | xargs -r nerdctl --namespace "k8s.io" rmi -f 2>/dev/null || true
	@echo "$(GREEN)✅ OpenDocSeal images cleaned$(RESET)"

# Clean OpenDocSeal images + intermediate images + cache
clean-all: clean
	@echo "$(BLUE)🧹 Deep cleaning: intermediate images + cache...$(RESET)"
	@echo "$(YELLOW)  -> Removing dangling images...$(RESET)"
	@nerdctl image prune -f 2>/dev/null || true
	@echo "$(YELLOW)  -> Cleaning build cache...$(RESET)"
	@nerdctl builder prune -f 2>/dev/null || true
	@echo "$(YELLOW)  -> Cleaning system cache...$(RESET)"
	@nerdctl system prune -f 2>/dev/null || true
	@echo "$(GREEN)✅ Complete cleanup finished$(RESET)"

# Display help information
help:
	@echo "$(CYAN)OpenDocSeal Build System$(RESET)"
	@echo "$(WHITE)========================$(RESET)"
	@echo ""
	@echo "$(YELLOW)🚀 Main Commands:$(RESET)"
	@echo "  $(GREEN)make build$(RESET)           - Build all images with version increment"
	@echo "  $(GREEN)make info$(RESET)            - Show current build information"
	@echo "  $(GREEN)make status$(RESET)     - List available OpenDocSeal images"
	@echo "  $(GREEN)make clean$(RESET)           - Clean OpenDocSeal images only"
	@echo "  $(GREEN)make clean-all$(RESET)       - Clean images + intermediate + cache"
	@echo ""
	@echo "$(YELLOW)🔨 Individual Builds:$(RESET)"
	@echo "  $(GREEN)make build-api$(RESET)       - Build FastAPI backend"
	@echo "  $(GREEN)make build-app$(RESET)       - Build frontend application"
	@echo "  $(GREEN)make build-rp$(RESET)        - Build reverse proxy"
	@echo "  $(GREEN)make build-minio$(RESET)     - Build MinIO object storage"
	@echo "  $(GREEN)make build-mongo$(RESET)     - Build MongoDB database"
	@echo "  $(GREEN)make build-n8n$(RESET)       - Build N8N automation"
	@echo ""
	@echo "$(YELLOW)🔧 Configuration:$(RESET)"
	@echo "  $(GREEN)make info-mongo$(RESET)      - MongoDB configuration details"
	@echo "  $(GREEN)make pull-all$(RESET)        - Pull all base images"
	@echo ""
	@echo "$(YELLOW)🏷️ Generated Images:$(RESET)"
	@echo "  - localhost/opendocseal_<service>:v<build_number> (default namespace)"
	@echo "  - localhost/opendocseal_<service>:latest (default namespace)"
	@echo "  - k8s.io/opendocseal_<service>:v<build_number> (k8s.io namespace)"
	@echo "  - k8s.io/opendocseal_<service>:latest (k8s.io namespace)"
	@echo ""
	@echo "$(YELLOW)📂 Image Distribution:$(RESET)"
	@echo "  - Build: Images created in k8s.io namespaces"
	@echo ""
	@echo "$(RED)⚠️  Security Note:$(RESET)"
	@echo "  Always change default passwords in .env files for production!"

# =============================================================================
# Default target
# =============================================================================

.DEFAULT_GOAL := help