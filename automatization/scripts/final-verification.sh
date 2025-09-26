#!/bin/bash
# Final Verification Script for OpenDocSeal
# Performs comprehensive checks before deployment or release

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="OpenDocSeal"
REPORTS_DIR="reports"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_FILE="${REPORTS_DIR}/final-verification-${TIMESTAMP}.log"

# Create reports directory
mkdir -p "$REPORTS_DIR"

# Logging function
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run check and report result
run_check() {
    local check_name="$1"
    local command="$2"
    local required="$3"
    
    log "${BLUE}🔍 Checking: $check_name${NC}"
    
    if eval "$command" >> "$LOG_FILE" 2>&1; then
        log "${GREEN}✅ PASS: $check_name${NC}"
        return 0
    else
        log "${RED}❌ FAIL: $check_name${NC}"
        if [ "$required" = "true" ]; then
            log "${RED}🚨 This is a required check. Aborting.${NC}"
            exit 1
        fi
        return 1
    fi
}

# Function to check Python environment
check_python_environment() {
    log "${BLUE}🐍 Checking Python Environment${NC}"
    
    # Check Python version
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        log "   Python version: $PYTHON_VERSION"
        
        # Check if version is >= 3.9
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
            log "${GREEN}✅ Python version is compatible${NC}"
        else
            log "${RED}❌ Python version must be >= 3.9${NC}"
            return 1
        fi
    else
        log "${RED}❌ Python 3 not found${NC}"
        return 1
    fi
    
    # Check virtual environment
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        log "${GREEN}✅ Virtual environment active: $VIRTUAL_ENV${NC}"
    else
        log "${YELLOW}⚠️  No virtual environment detected${NC}"
    fi
    
    # Check pip
    if command_exists pip; then
        PIP_VERSION=$(pip --version | cut -d' ' -f2)
        log "   pip version: $PIP_VERSION"
        log "${GREEN}✅ pip is available${NC}"
    else
        log "${RED}❌ pip not found${NC}"
        return 1
    fi
    
    return 0
}

# Function to check dependencies
check_dependencies() {
    log "${BLUE}📦 Checking Dependencies${NC}"
    
    # Check if requirements.txt exists
    if [ -f "requirements.txt" ]; then
        log "   Found requirements.txt"
        
        # Check if all requirements are installed
        if pip check >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ All dependencies are compatible${NC}"
        else
            log "${YELLOW}⚠️  Some dependency conflicts detected${NC}"
            pip check || true
        fi
    else
        log "${YELLOW}⚠️  No requirements.txt found${NC}"
    fi
    
    # Generate dependency report
    if command_exists python3; then
        python3 .github/scripts/dependency-dashboard.py >> "$LOG_FILE" 2>&1 || true
        log "   Dependency dashboard generated"
    fi
    
    return 0
}

# Function to run security checks
run_security_checks() {
    log "${BLUE}🔒 Running Security Checks${NC}"
    
    local security_passed=0
    
    # Bandit security scanner
    if command_exists bandit; then
        if bandit -r . -f json -o "${REPORTS_DIR}/bandit-final.json" --exit-zero >> "$LOG_FILE" 2>&1; then
            BANDIT_ISSUES=$(python3 -c "import json; data=json.load(open('${REPORTS_DIR}/bandit-final.json')); print(len(data.get('results', [])))" 2>/dev/null || echo "0")
            if [ "$BANDIT_ISSUES" = "0" ]; then
                log "${GREEN}✅ Bandit: No security issues found${NC}"
            else
                log "${YELLOW}⚠️  Bandit: $BANDIT_ISSUES issues found${NC}"
                security_passed=1
            fi
        else
            log "${RED}❌ Bandit scan failed${NC}"
            security_passed=1
        fi
    else
        log "${YELLOW}⚠️  Bandit not installed${NC}"
    fi
    
    # Safety vulnerability check
    if command_exists safety; then
        if safety check --json --output "${REPORTS_DIR}/safety-final.json" >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ Safety: No vulnerabilities found${NC}"
        else
            log "${YELLOW}⚠️  Safety: Vulnerabilities detected${NC}"
            safety check || true
            security_passed=1
        fi
    else
        log "${YELLOW}⚠️  Safety not installed${NC}"
    fi
    
    # Check for secrets
    if command_exists detect-secrets; then
        if detect-secrets scan --all-files >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ No secrets detected${NC}"
        else
            log "${YELLOW}⚠️  Potential secrets detected${NC}"
            security_passed=1
        fi
    fi
    
    return $security_passed
}

# Function to run code quality checks
run_quality_checks() {
    log "${BLUE}📝 Running Code Quality Checks${NC}"
    
    local quality_passed=0
    
    # Black formatting check
    if command_exists black; then
        if black --check --diff . >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ Black: Code formatting is correct${NC}"
        else
            log "${YELLOW}⚠️  Black: Code formatting issues found${NC}"
            quality_passed=1
        fi
    fi
    
    # isort import sorting
    if command_exists isort; then
        if isort --check-only --diff . >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ isort: Import sorting is correct${NC}"
        else
            log "${YELLOW}⚠️  isort: Import sorting issues found${NC}"
            quality_passed=1
        fi
    fi
    
    # Flake8 linting
    if command_exists flake8; then
        if flake8 . >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ Flake8: No linting issues found${NC}"
        else
            log "${YELLOW}⚠️  Flake8: Linting issues found${NC}"
            quality_passed=1
        fi
    fi
    
    # MyPy type checking
    if command_exists mypy; then
        if mypy . --ignore-missing-imports >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ MyPy: No type checking issues found${NC}"
        else
            log "${YELLOW}⚠️  MyPy: Type checking issues found${NC}"
            quality_passed=1
        fi
    fi
    
    return $quality_passed
}

# Function to run tests
run_tests() {
    log "${BLUE}🧪 Running Tests${NC}"
    
    if command_exists pytest; then
        # Run tests with coverage
        if pytest --cov=. --cov-report=html:"${REPORTS_DIR}/coverage" --cov-report=json:"${REPORTS_DIR}/coverage.json" --junit-xml="${REPORTS_DIR}/pytest.xml" >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ All tests passed${NC}"
            
            # Check coverage
            if [ -f "${REPORTS_DIR}/coverage.json" ]; then
                COVERAGE=$(python3 -c "import json; data=json.load(open('${REPORTS_DIR}/coverage.json')); print(f'{data[\"totals\"][\"percent_covered\"]:.1f}%')" 2>/dev/null || echo "Unknown")
                log "   Code coverage: $COVERAGE"
            fi
            
            return 0
        else
            log "${RED}❌ Some tests failed${NC}"
            return 1
        fi
    else
        log "${YELLOW}⚠️  pytest not installed, skipping tests${NC}"
        return 0
    fi
}

# Function to check documentation
check_documentation() {
    log "${BLUE}📚 Checking Documentation${NC}"
    
    local docs_passed=0
    
    # Check for required documentation files
    local required_docs=("README.md" "SECURITY.md" "INSTALLATION.md")
    
    for doc in "${required_docs[@]}"; do
        if [ -f "$doc" ]; then
            if [ -s "$doc" ] && ! grep -q "todo" "$doc"; then
                log "${GREEN}✅ $doc exists and has content${NC}"
            else
                log "${YELLOW}⚠️  $doc exists but may need content${NC}"
                docs_passed=1
            fi
        else
            log "${RED}❌ $doc is missing${NC}"
            docs_passed=1
        fi
    done
    
    # Check for API documentation
    if [ -d "docs/" ]; then
        log "${GREEN}✅ Documentation directory exists${NC}"
    else
        log "${YELLOW}⚠️  No documentation directory found${NC}"
        docs_passed=1
    fi
    
    return $docs_passed
}

# Function to check configuration files
check_configuration() {
    log "${BLUE}⚙️  Checking Configuration Files${NC}"
    
    local config_passed=0
    
    # Check GitHub workflow files
    if [ -d ".github/workflows" ]; then
        WORKFLOW_COUNT=$(find .github/workflows -name "*.yml" -o -name "*.yaml" | wc -l)
        if [ "$WORKFLOW_COUNT" -gt 0 ]; then
            log "${GREEN}✅ GitHub workflows configured ($WORKFLOW_COUNT files)${NC}"
        else
            log "${YELLOW}⚠️  No GitHub workflow files found${NC}"
            config_passed=1
        fi
    else
        log "${YELLOW}⚠️  No .github/workflows directory${NC}"
        config_passed=1
    fi
    
    # Check pre-commit configuration
    if [ -f ".pre-commit-config.yaml" ]; then
        log "${GREEN}✅ Pre-commit configuration exists${NC}"
    else
        log "${YELLOW}⚠️  No pre-commit configuration${NC}"
        config_passed=1
    fi
    
    # Check security configuration
    if [ -f ".bandit" ] || [ -f "pyproject.toml" ]; then
        log "${GREEN}✅ Security configuration exists${NC}"
    else
        log "${YELLOW}⚠️  No security configuration found${NC}"
        config_passed=1
    fi
    
    return $config_passed
}

# Function to generate final report
generate_final_report() {
    log "${BLUE}📊 Generating Final Report${NC}"
    
    local report_file="${REPORTS_DIR}/final-verification-report-${TIMESTAMP}.md"
    
    cat > "$report_file" << EOF
# OpenDocSeal - Final Verification Report

**Generated:** $(date)
**Project:** $PROJECT_NAME

## Summary

This report contains the results of the final verification process run before deployment or release.

## Verification Results

$(grep -E "(✅|❌|⚠️)" "$LOG_FILE" | sed 's/\x1b\[[0-9;]*m//g')

## Detailed Logs

For detailed logs, see: \`$LOG_FILE\`

## Reports Generated

- Security scan results: \`${REPORTS_DIR}/bandit-final.json\`, \`${REPORTS_DIR}/safety-final.json\`
- Test coverage: \`${REPORTS_DIR}/coverage/\`
- Test results: \`${REPORTS_DIR}/pytest.xml\`

## Next Steps

1. Review any warnings or failures above
2. Fix any critical issues before proceeding
3. Update documentation if needed
4. Run deployment if all checks pass

---
*This report was automatically generated by the final verification script.*
EOF

    log "${GREEN}✅ Final report generated: $report_file${NC}"
}

# Main verification function
main() {
    log "${BLUE}🚀 Starting Final Verification for $PROJECT_NAME${NC}"
    log "Timestamp: $(date)"
    log "Log file: $LOG_FILE"
    log ""
    
    local overall_status=0
    
    # Run all checks
    check_python_environment || overall_status=1
    check_dependencies || overall_status=1
    run_security_checks || overall_status=1
    run_quality_checks || overall_status=1
    run_tests || overall_status=1
    check_documentation || overall_status=1
    check_configuration || overall_status=1
    
    # Generate final report
    generate_final_report
    
    log ""
    if [ $overall_status -eq 0 ]; then
        log "${GREEN}🎉 ALL CHECKS PASSED! Project is ready for deployment.${NC}"
    else
        log "${YELLOW}⚠️  Some checks failed or have warnings. Please review before proceeding.${NC}"
    fi
    
    log "${BLUE}📄 Verification complete. Check the reports in: $REPORTS_DIR/${NC}"
    
    exit $overall_status
}

# Run main function
main "$@"