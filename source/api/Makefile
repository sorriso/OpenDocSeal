# Path: infrastructure/source/api/Makefile
# Version: 2

# Configuration
PYTHON := python3
PIP := pip3
PYTEST := pytest
TEST_DIR := tests
SRC_DIR := .
COVERAGE_MIN := 80
COVERAGE_REPORT_DIR := htmlcov

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

# Help target
.PHONY: help
help: ## Show this help message
	@echo "$(GREEN)OpenDocSeal API - Test Management$(NC)"
	@echo ""
	@echo "$(YELLOW)Available targets:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Installation targets
.PHONY: install-test-deps
install-test-deps: ## Install test dependencies
	@echo "$(YELLOW)Installing test dependencies...$(NC)"
	$(PIP) install -r requirements-test.txt

.PHONY: install-deps
install-deps: ## Install all dependencies (production + test)
	@echo "$(YELLOW)Installing production dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	@echo "$(YELLOW)Installing test dependencies...$(NC)"
	$(PIP) install -r requirements-test.txt

# Test targets
.PHONY: test
test: ## Run all unit tests
	@echo "$(YELLOW)Running unit tests...$(NC)"
	$(PYTEST) $(TEST_DIR)/ -v

.PHONY: test-fast
test-fast: ## Run tests without coverage (faster)
	@echo "$(YELLOW)Running fast unit tests...$(NC)"
	$(PYTEST) $(TEST_DIR)/ -x -q

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "$(YELLOW)Running unit tests with coverage...$(NC)"
	$(PYTEST) $(TEST_DIR)/ \
		--cov=$(SRC_DIR) \
		--cov-report=term-missing \
		--cov-report=html:$(COVERAGE_REPORT_DIR) \
		--cov-fail-under=$(COVERAGE_MIN) \
		--cov-config=.coveragerc \
		-v

.PHONY: test-coverage-simple
test-coverage-simple: ## Run tests with simple coverage report
	@echo "$(YELLOW)Running unit tests with simple coverage...$(NC)"
	$(PYTEST) $(TEST_DIR)/ --cov=$(SRC_DIR) --cov-report=term

.PHONY: test-specific
test-specific: ## Run specific test file (usage: make test-specific FILE=test_filename.py)
	@if [ -z "$(FILE)" ]; then \
		echo "$(RED)Error: Please specify FILE parameter$(NC)"; \
		echo "$(YELLOW)Usage: make test-specific FILE=test_filename.py$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Running specific test: $(FILE)$(NC)"
	$(PYTEST) $(TEST_DIR)/$(FILE) -v

# Quality targets
.PHONY: lint
lint: ## Run code linting
	@echo "$(YELLOW)Running flake8 linting...$(NC)"
	flake8 $(SRC_DIR) $(TEST_DIR) --exclude=venv,__pycache__,.git --max-line-length=88

.PHONY: format
format: ## Format code with black
	@echo "$(YELLOW)Formatting code with black...$(NC)"
	black $(SRC_DIR) $(TEST_DIR) --line-length=88 --exclude="/(\.git|__pycache__|\.pytest_cache|venv)/"

.PHONY: format-check
format-check: ## Check if code is formatted correctly
	@echo "$(YELLOW)Checking code formatting...$(NC)"
	black $(SRC_DIR) $(TEST_DIR) --check --line-length=88 --exclude="/(\.git|__pycache__|\.pytest_cache|venv)/"

.PHONY: quality
quality: format-check lint ## Run all quality checks

# Combined targets
.PHONY: test-all
test-all: quality test-coverage ## Run quality checks and tests with coverage

.PHONY: ci
ci: install-test-deps test-all ## Complete CI pipeline (install deps + quality + tests)

# Clean targets
.PHONY: clean
clean: ## Clean cache and temporary files
	@echo "$(YELLOW)Cleaning cache and temporary files...$(NC)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(COVERAGE_REPORT_DIR)
	rm -f .coverage

.PHONY: clean-all
clean-all: clean ## Deep clean including reports and logs
	@echo "$(YELLOW)Deep cleaning...$(NC)"
	find . -name "*.log" -delete 2>/dev/null || true
	find . -name "junit-*.xml" -delete 2>/dev/null || true

# Development targets
.PHONY: watch
watch: ## Run tests in watch mode (requires pytest-watch)
	@echo "$(YELLOW)Running tests in watch mode...$(NC)"
	@if command -v ptw >/dev/null 2>&1; then \
		ptw $(TEST_DIR)/; \
	else \
		echo "$(RED)Error: pytest-watch not installed$(NC)"; \
		echo "$(YELLOW)Install with: pip install pytest-watch$(NC)"; \
		exit 1; \
	fi

.PHONY: debug
debug: ## Run tests with detailed output for debugging
	@echo "$(YELLOW)Running tests in debug mode...$(NC)"
	$(PYTEST) $(TEST_DIR)/ -v -s --tb=long --capture=no

# Report targets
.PHONY: coverage-report
coverage-report: ## Generate and open HTML coverage report
	@if [ -f "$(COVERAGE_REPORT_DIR)/index.html" ]; then \
		echo "$(GREEN)Opening coverage report...$(NC)"; \
		python -m webbrowser "$(COVERAGE_REPORT_DIR)/index.html"; \
	else \
		echo "$(RED)No coverage report found. Run 'make test-coverage' first.$(NC)"; \
	fi

.PHONY: test-summary
test-summary: ## Show test and coverage summary
	@echo "$(GREEN)=== Test Summary ===$(NC)"
	@echo "$(YELLOW)Test directory:$(NC) $(TEST_DIR)/"
	@echo "$(YELLOW)Source directory:$(NC) $(SRC_DIR)"
	@echo "$(YELLOW)Coverage minimum:$(NC) $(COVERAGE_MIN)%"
	@echo "$(YELLOW)Available test files:$(NC)"
	@find $(TEST_DIR) -name "test_*.py" -o -name "*_test.py" 2>/dev/null | sort | sed 's/^/  - /' || echo "  - No test files found"