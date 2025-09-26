# File: Makefile
# Path: infrastructure/kube/Makefile
# Version: 18 - COHERENCE FIXES
# =============================================================================
# OpenDocSeal Kubernetes Deployment Makefile (Production + Debug modes)
# =============================================================================

# Variables
PROJECT_ROOT := $(shell pwd)/../../
NAMESPACE := opendocseal
SMOOTH := false

# Detect operating system for sed compatibility
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    SED_INPLACE = sed -i ''
else
    SED_INPLACE = sed -i
endif

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
CYAN := \033[0;36m
RESET := \033[0m

# Get absolute project path (resolve PROJECT_ROOT to absolute path)
ABS_PROJECT_ROOT := $(shell cd "$(PROJECT_ROOT)" && pwd)

# =============================================================================
# Main Targets
# =============================================================================

.PHONY: run run-debug stop status clean help
.PHONY: fix-pv-paths
.PHONY: apply-volumes apply-volume-claims apply-workloads
.PHONY: apply-volumes-debug apply-volume-claims-debug apply-workloads-debug
.PHONY: apply-secrets apply-configmaps
.PHONY: create-namespace delete-namespace create-data-dirs-production

# Production mode deployment (no APP/API volumes)
run: create-namespace create-data-dirs-production fix-pv-paths
	@echo "$(BLUE)Starting OpenDocSeal Kubernetes deployment [PRODUCTION MODE]...$(RESET)"
	@echo "$(YELLOW)Namespace: $(NAMESPACE)$(RESET)"
	@echo "$(CYAN)Mode: Production (no APP/API volumes)$(RESET)"
	$(MAKE) apply-volumes
	$(MAKE) apply-volume-claims
	$(MAKE) apply-secrets
	$(MAKE) apply-configmaps
	$(MAKE) apply-workloads
	@echo "$(GREEN)✅ Production deployment completed successfully$(RESET)"

# Debug mode deployment (with APP/API volumes for development)
run-debug: create-namespace create-data-dirs-production fix-pv-paths
	@echo "$(BLUE)Starting OpenDocSeal Kubernetes deployment [DEBUG MODE]...$(RESET)"
	@echo "$(YELLOW)Namespace: $(NAMESPACE)$(RESET)"
	@echo "$(CYAN)Mode: Debug (with APP/API volumes for development)$(RESET)"
	$(MAKE) apply-volumes-debug
	$(MAKE) apply-volume-claims-debug
	$(MAKE) apply-secrets
	$(MAKE) apply-configmaps
	$(MAKE) apply-workloads-debug
	@echo "$(GREEN)✅ Debug deployment completed successfully$(RESET)"

# Stop all resources (detects mode automatically)
stop:
	@echo "$(BLUE)Stopping OpenDocSeal Kubernetes deployment...$(RESET)"
	@echo "$(YELLOW)Step 1: Deleting Ingress...$(RESET)"
	@kubectl delete -f ingress-http.yaml --namespace=$(NAMESPACE) --ignore-not-found=true || true
	@kubectl delete -f TSK-init-job.yaml --namespace=$(NAMESPACE) --ignore-not-found=true || true
	
	@echo "$(YELLOW)Step 2: Deleting Services...$(RESET)"
	@for serv in API-service.yaml APP-service.yaml DB-service.yaml RP-service.yaml STR-service.yaml TSK-service.yaml; do \
		if [ -f "$$serv" ]; then \
			echo "$(BLUE)Deleting: $$serv$(RESET)"; \
			kubectl delete -f "$$serv" --namespace=$(NAMESPACE) --ignore-not-found=true || true; \
		fi; \
	done
	@echo "$(GREEN)✅ Services deleted$(RESET)"

	@echo "$(YELLOW)Step 3: Deleting Workloads...$(RESET)"
	@for deplo in API-deployment.yaml APP-deployment.yaml API-deployment-debug.yaml APP-deployment-debug.yaml DB-deployment.yaml RP-deployment.yaml STR-deployment.yaml TSK-deployment.yaml; do \
		if [ -f "$$deplo" ]; then \
			echo "$(BLUE)Deleting: $$deplo$(RESET)"; \
			kubectl delete -f "$$deplo" --namespace=$(NAMESPACE) --force --ignore-not-found=true || true; \
		fi; \
	done
	@echo "$(GREEN)✅ Workloads deleted$(RESET)"

	@echo "$(YELLOW)Step 4: Deleting ConfigMaps and Secrets...$(RESET)"
	@for confi in APP-configmap.yaml RP-configmap.yaml; do \
		if [ -f "$$confi" ]; then \
			echo "$(BLUE)Deleting: $$confi$(RESET)"; \
			kubectl delete -f "$$confi" --namespace=$(NAMESPACE) --ignore-not-found=true || true; \
		fi; \
	done
	@for secr in API-secret.yaml DB-secret.yaml STR-secret.yaml TSK-secret.yaml; do \
		if [ -f "$$secr" ]; then \
			echo "$(BLUE)Deleting: $$secr$(RESET)"; \
			kubectl delete -f "$$secr" --namespace=$(NAMESPACE) --ignore-not-found=true || true; \
		fi; \
	done
	@echo "$(GREEN)✅ ConfigMaps and Secrets deleted$(RESET)"

	@echo "$(YELLOW)Step 5: Deleting PersistentVolumeClaims...$(RESET)"
	@for pvc in API-PersistentVolumeClaim.yaml APP-PersistentVolumeClaim.yaml DB-PersistentVolumeClaim.yaml STR-PersistentVolumeClaim.yaml TSK-PersistentVolumeClaim.yaml LOGS-PersistentVolumeClaim.yaml; do \
		if [ -f "$$pvc" ]; then \
			echo "$(BLUE)Deleting: $$pvc$(RESET)"; \
			kubectl delete -f "$$pvc" --namespace=$(NAMESPACE) --ignore-not-found=true || true; \
		fi; \
	done
	@echo "$(GREEN)✅ PersistentVolumeClaims deleted$(RESET)"

	@echo "$(YELLOW)Step 6: Deleting PersistentVolumes...$(RESET)"
	@for pv in API-PersistentVolume.yaml APP-PersistentVolume.yaml DB-PersistentVolume.yaml STR-PersistentVolume.yaml TSK-PersistentVolume.yaml LOGS-PersistentVolume.yaml; do \
		if [ -f "$$pv" ]; then \
			echo "$(BLUE)Deleting: $$pv$(RESET)"; \
			kubectl delete -f "$$pv" --ignore-not-found=true || true; \
		fi; \
	done
	@echo "$(GREEN)✅ PersistentVolumes deleted$(RESET)"

	@echo "$(YELLOW)Step 7: Deleting Namespace...$(RESET)"
	@kubectl delete namespace $(NAMESPACE) --ignore-not-found=true
	@echo "$(GREEN)✅ Clean shutdown completed$(RESET)"

# Show deployment status
status:
	@echo "$(BLUE)OpenDocSeal Deployment Status:$(RESET)"
	@echo "$(YELLOW)Namespace: $(NAMESPACE)$(RESET)"
	@kubectl get namespace $(NAMESPACE) 2>/dev/null || echo "Namespace $(NAMESPACE) not found"
	@echo ""
	@echo "$(YELLOW)Jobs:$(RESET)"
	@kubectl get jobs --namespace=$(NAMESPACE) -o wide 2>/dev/null || echo "No jobs found"
	@echo ""
	@echo "$(YELLOW)Persistent Volumes:$(RESET)"
	@kubectl get pv --namespace=$(NAMESPACE) -o wide 2>/dev/null || echo "No PVs found"
	@echo ""
	@echo "$(YELLOW)Persistent Volume Claims:$(RESET)"
	@kubectl get pvc --namespace=$(NAMESPACE) -o wide 2>/dev/null || echo "No PVCs found"
	@echo ""
	@echo "$(YELLOW)Secrets:$(RESET)"
	@kubectl get secrets --namespace=$(NAMESPACE) 2>/dev/null || echo "No secrets found"
	@echo ""
	@echo "$(YELLOW)ConfigMaps:$(RESET)"
	@kubectl get configmaps --namespace=$(NAMESPACE) 2>/dev/null || echo "No configmaps found"
	@echo ""
	@echo "$(YELLOW)Deployments:$(RESET)"
	@kubectl get deployments --namespace=$(NAMESPACE) -o wide 2>/dev/null || echo "No deployments found"
	@echo ""
	@echo "$(YELLOW)StatefulSets:$(RESET)"
	@kubectl get statefulsets --namespace=$(NAMESPACE) -o wide 2>/dev/null || echo "No statefulsets found"
	@echo ""
	@echo "$(YELLOW)Services:$(RESET)"
	@kubectl get services --namespace=$(NAMESPACE) -o wide 2>/dev/null || echo "No services found"
	@echo ""
	@echo "$(YELLOW)Ingress:$(RESET)"
	@kubectl get ingress --namespace=$(NAMESPACE) -o wide 2>/dev/null || echo "No ingress found"
	@echo ""
	@echo "$(YELLOW)Pods:$(RESET)"
	@kubectl get pods --namespace=$(NAMESPACE) -o wide 2>/dev/null || echo "No pods found"

# Clean
clean:
	@echo "$(YELLOW)No temporary directories to clean$(RESET)"
	@echo "$(GREEN)✅ Nothing to clean$(RESET)"

# =============================================================================
# Namespace Management  
# =============================================================================

create-namespace:
	@echo "$(YELLOW)Creating namespace $(NAMESPACE)...$(RESET)"
	@kubectl get namespace $(NAMESPACE) >/dev/null 2>&1 || kubectl create namespace $(NAMESPACE)
	@echo "$(GREEN)✅ Namespace $(NAMESPACE) ready$(RESET)"

delete-namespace:
	@echo "$(YELLOW)Deleting namespace $(NAMESPACE)...$(RESET)"
	@kubectl delete namespace $(NAMESPACE) --ignore-not-found=true
	@echo "$(GREEN)✅ Namespace $(NAMESPACE) deleted$(RESET)"

# =============================================================================
# Data Directory Management
# =============================================================================

# Production directories (only data persistence)
create-data-dirs-production:
	@echo "$(YELLOW)Creating production directories...$(RESET)"
	@echo "$(BLUE)Project root: $(ABS_PROJECT_ROOT)$(RESET)"
	@mkdir -p "$(ABS_PROJECT_ROOT)/infrastructure/_data/mongo"
	@mkdir -p "$(ABS_PROJECT_ROOT)/infrastructure/_data/minio"
	@mkdir -p "$(ABS_PROJECT_ROOT)/infrastructure/_data/n8n"
	@mkdir -p "$(ABS_PROJECT_ROOT)/infrastructure/_data/logs"
	@echo "$(CYAN)Production mode: APP/API use container storage$(RESET)"
	@echo "$(GREEN)✅ Production directories created$(RESET)"

# =============================================================================
# PersistentVolume Path Updates
# =============================================================================

# Fix PV paths for both production and debug modes
fix-pv-paths:
	@echo "$(YELLOW)Fixing PersistentVolume paths...$(RESET)"
	@echo "$(BLUE)Using project paths for development:$(RESET)"
	@echo "  Data: $(ABS_PROJECT_ROOT)/infrastructure/_data"
	@echo "  API:  $(ABS_PROJECT_ROOT)/source/api"
	@echo "  APP:  $(ABS_PROJECT_ROOT)/source/app"
	@if [ -f "API-PersistentVolume.yaml" ]; then \
		echo "Processing API-PersistentVolume.yaml"; \
		$(SED_INPLACE) 's|path: .*|path: $(ABS_PROJECT_ROOT)/source/api|g' API-PersistentVolume.yaml; \
	fi
	@if [ -f "APP-PersistentVolume.yaml" ]; then \
		echo "Processing APP-PersistentVolume.yaml"; \
		$(SED_INPLACE) 's|path: .*|path: $(ABS_PROJECT_ROOT)/source/app|g' APP-PersistentVolume.yaml; \
	fi
	@if [ -f "DB-PersistentVolume.yaml" ]; then \
		echo "Processing DB-PersistentVolume.yaml"; \
		$(SED_INPLACE) 's|path: .*|path: $(ABS_PROJECT_ROOT)/infrastructure/_data/mongo|g' DB-PersistentVolume.yaml; \
	fi
	@if [ -f "STR-PersistentVolume.yaml" ]; then \
		echo "Processing STR-PersistentVolume.yaml"; \
		$(SED_INPLACE) 's|path: .*|path: $(ABS_PROJECT_ROOT)/infrastructure/_data/minio|g' STR-PersistentVolume.yaml; \
	fi
	@if [ -f "TSK-PersistentVolume.yaml" ]; then \
		echo "Processing TSK-PersistentVolume.yaml"; \
		$(SED_INPLACE) 's|path: .*|path: $(ABS_PROJECT_ROOT)/infrastructure/_data/n8n|g' TSK-PersistentVolume.yaml; \
	fi
	@if [ -f "LOGS-PersistentVolume.yaml" ]; then \
		echo "Processing LOGS-PersistentVolume.yaml"; \
		$(SED_INPLACE) 's|path: .*|path: $(ABS_PROJECT_ROOT)/infrastructure/_data/logs|g' LOGS-PersistentVolume.yaml; \
	fi
	@echo "$(GREEN)✅ PersistentVolume paths fixed$(RESET)"

# =============================================================================
# Resource Application - Production Mode
# =============================================================================

apply-volumes:
	@echo "$(YELLOW)Applying PersistentVolumes...$(RESET)"
	@echo "$(CYAN)Production mode: Only DB and STR volumes$(RESET)"
	@for pv in DB-PersistentVolume.yaml STR-PersistentVolume.yaml TSK-PersistentVolume.yaml LOGS-PersistentVolume.yaml; do \
		if [ -f "$$pv" ]; then \
			echo "$(BLUE)Applying: $$pv$(RESET)"; \
			kubectl apply -f "$$pv" || echo "$(RED)Failed to apply $$pv$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Production PersistentVolumes applied$(RESET)"

apply-volume-claims:
	@echo "$(YELLOW)Applying PersistentVolumeClaims...$(RESET)"
	@for pvc in DB-PersistentVolumeClaim.yaml STR-PersistentVolumeClaim.yaml TSK-PersistentVolumeClaim.yaml LOGS-PersistentVolumeClaim.yaml; do \
		if [ -f "$$pvc" ]; then \
			echo "$(BLUE)Applying: $$pvc$(RESET)"; \
			kubectl apply -f "$$pvc" --namespace=$(NAMESPACE) || echo "$(RED)Failed to apply $$pvc$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Production PersistentVolumeClaims applied$(RESET)"

apply-workloads:
	@echo "$(YELLOW)Applying workloads...$(RESET)"
	@for deplo in API-deployment.yaml APP-deployment.yaml DB-deployment.yaml RP-deployment.yaml STR-deployment.yaml TSK-deployment.yaml; do \
		if [ -f "$$deplo" ]; then \
			echo "$(BLUE)Applying: $$deplo$(RESET)"; \
			kubectl apply -f "$$deplo" --namespace=$(NAMESPACE) || echo "$(RED)Failed to apply $$deplo$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Production workloads applied$(RESET)"

	@echo "$(YELLOW)Applying services [PRODUCTION]...$(RESET)"
	@for serv in API-service.yaml APP-service.yaml DB-service.yaml RP-service.yaml STR-service.yaml TSK-service.yaml; do \
		if [ -f "$$serv" ]; then \
			echo "$(BLUE)Applying: $$serv$(RESET)"; \
			kubectl apply -f "$$serv" --namespace=$(NAMESPACE) || echo "$(RED)Failed to apply $$serv$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Production services applied$(RESET)"

	@echo "$(BLUE)Applying Ingress...$(RESET)"
	@kubectl apply -f TSK-init-job.yaml --namespace=$(NAMESPACE) || echo "$(YELLOW)No TSK-init-job.yaml found$(RESET)"
	@kubectl apply -f ingress-http.yaml --namespace=$(NAMESPACE) || echo "$(YELLOW)No ingress-http.yaml found$(RESET)"
	

# =============================================================================
# Resource Application - Debug Mode
# =============================================================================

apply-volumes-debug:
	@echo "$(YELLOW)Applying PersistentVolumes [DEBUG]...$(RESET)"
	@echo "$(CYAN)Debug mode: All volumes (API, APP, DB, STR)$(RESET)"
	@for pv in DB-PersistentVolume.yaml STR-PersistentVolume.yaml TSK-PersistentVolume.yaml API-PersistentVolume.yaml APP-PersistentVolume.yaml; do \
		if [ -f "$$pv" ]; then \
			echo "$(BLUE)Applying: $$pv$(RESET)"; \
			kubectl apply -f "$$pv" || echo "$(RED)Failed to apply $$pv$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Debug PersistentVolumes applied$(RESET)"

apply-volume-claims-debug:
	@echo "$(YELLOW)Applying PersistentVolumeClaims [DEBUG]...$(RESET)"
	@for pvc in DB-PersistentVolumeClaim.yaml STR-PersistentVolumeClaim.yaml TSK-PersistentVolumeClaim.yaml API-PersistentVolumeClaim.yaml APP-PersistentVolumeClaim.yaml; do \
		if [ -f "$$pvc" ]; then \
			echo "$(BLUE)Applying: $$pvc$(RESET)"; \
			kubectl apply -f "$$pvc" --namespace=$(NAMESPACE) || echo "$(RED)Failed to apply $$pvc$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Debug PersistentVolumeClaims applied$(RESET)"

apply-workloads-debug:
	@echo "$(YELLOW)Applying workloads [DEBUG]...$(RESET)"
	@for deplo in API-deployment-debug.yaml APP-deployment-debug.yaml DB-deployment.yaml RP-deployment.yaml STR-deployment.yaml TSK-deployment.yaml; do \
		if [ -f "$$deplo" ]; then \
			echo "$(BLUE)Applying: $$deplo$(RESET)"; \
			kubectl apply -f "$$deplo" --namespace=$(NAMESPACE) || echo "$(RED)Failed to apply $$deplo$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Debug workloads applied$(RESET)"

	@echo "$(YELLOW)Applying services [DEBUG]...$(RESET)"
	@for serv in API-service.yaml APP-service.yaml DB-service.yaml RP-service.yaml STR-service.yaml TSK-service.yaml; do \
		if [ -f "$$serv" ]; then \
			echo "$(BLUE)Applying: $$serv$(RESET)"; \
			kubectl apply -f "$$serv" --namespace=$(NAMESPACE) || echo "$(RED)Failed to apply $$serv$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Debug services applied$(RESET)"

	@echo "$(BLUE)Applying Ingress...$(RESET)"
	@kubectl apply -f ingress-http.yaml --namespace=$(NAMESPACE) || echo "$(YELLOW)No ingress-http.yaml found$(RESET)"

# =============================================================================
# Shared Resource Application
# =============================================================================

apply-secrets:
	@echo "$(YELLOW)Applying Secrets...$(RESET)"
	@for secret in API-secret.yaml DB-secret.yaml STR-secret.yaml TSK-secret.yaml; do \
		if [ -f "$$secret" ]; then \
			echo "$(BLUE)Applying: $$secret$(RESET)"; \
			kubectl apply -f "$$secret" --namespace=$(NAMESPACE) || echo "$(RED)Failed to apply $$secret$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ Secrets applied$(RESET)"

apply-configmaps:
	@echo "$(YELLOW)Applying ConfigMaps...$(RESET)"
	@for cm in APP-configmap.yaml RP-configmap.yaml; do \
		if [ -f "$$cm" ]; then \
			echo "$(BLUE)Applying: $$cm$(RESET)"; \
			kubectl apply -f "$$cm" --namespace=$(NAMESPACE) || echo "$(RED)Failed to apply $$cm$(RESET)"; \
		fi; \
	done
	@echo "$(GREEN)✅ ConfigMaps applied$(RESET)"

# =============================================================================
# Help
# =============================================================================

help:
	@echo "$(BLUE)OpenDocSeal Kubernetes Makefile - Dual Mode$(RESET)"
	@echo "$(YELLOW)============================================$(RESET)"
	@echo ""
	@echo "$(CYAN)🚀 DEPLOYMENT MODES:$(RESET)"
	@echo "  $(GREEN)make run$(RESET)           - Production mode (no APP/API volumes)"
	@echo "  $(GREEN)make run-debug$(RESET)     - Debug mode (with APP/API volumes for development)"
	@echo ""
	@echo "$(YELLOW)Main Commands:$(RESET)"
	@echo "  $(GREEN)make stop$(RESET)          - Delete all resources"
	@echo "  $(GREEN)make status$(RESET)        - Show deployment status"
	@echo "  $(GREEN)make clean$(RESET)         - Clean"
	@echo ""

# =============================================================================
# Default Target
# =============================================================================

.DEFAULT_GOAL := help