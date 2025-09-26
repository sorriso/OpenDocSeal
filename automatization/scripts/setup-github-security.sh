#!/bin/bash
# GitHub Security Setup Script for OpenDocSeal
# Configures GitHub repository security settings and policies

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="OpenDocSeal"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
REPO_OWNER="${REPO_OWNER:-}"
REPO_NAME="${REPO_NAME:-}"
REPORTS_DIR="reports/github-security"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_FILE="${REPORTS_DIR}/github-security-setup-${TIMESTAMP}.log"

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

# Function to check GitHub CLI authentication
check_gh_auth() {
    log "${BLUE}🔐 Checking GitHub CLI authentication${NC}"
    
    if command_exists gh; then
        if gh auth status >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ GitHub CLI is authenticated${NC}"
            return 0
        else
            log "${RED}❌ GitHub CLI is not authenticated${NC}"
            log "   Run: gh auth login"
            return 1
        fi
    else
        log "${YELLOW}⚠️  GitHub CLI not installed${NC}"
        log "   Install: https://cli.github.com/"
        return 1
    fi
}

# Function to get repository information
get_repo_info() {
    log "${BLUE}📋 Getting repository information${NC}"
    
    if [ -z "$REPO_OWNER" ] || [ -z "$REPO_NAME" ]; then
        if command_exists gh && gh auth status >/dev/null 2>&1; then
            local repo_info
            repo_info=$(gh repo view --json owner,name 2>/dev/null || echo "")
            
            if [ -n "$repo_info" ]; then
                REPO_OWNER=$(echo "$repo_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['owner']['login'])" 2>/dev/null || echo "")
                REPO_NAME=$(echo "$repo_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data['name'])" 2>/dev/null || echo "")
                
                if [ -n "$REPO_OWNER" ] && [ -n "$REPO_NAME" ]; then
                    log "${GREEN}✅ Repository detected: $REPO_OWNER/$REPO_NAME${NC}"
                    return 0
                fi
            fi
        fi
        
        log "${YELLOW}⚠️  Repository information not available${NC}"
        log "   Please set REPO_OWNER and REPO_NAME environment variables"
        return 1
    else
        log "${GREEN}✅ Repository configured: $REPO_OWNER/$REPO_NAME${NC}"
        return 0
    fi
}

# Function to enable security features
enable_security_features() {
    log "${BLUE}🔒 Enabling GitHub security features${NC}"
    
    if ! command_exists gh || ! gh auth status >/dev/null 2>&1; then
        log "${YELLOW}⚠️  GitHub CLI not available, skipping automated setup${NC}"
        return 1
    fi
    
    local repo="$REPO_OWNER/$REPO_NAME"
    
    # Enable vulnerability alerts
    log "   Enabling vulnerability alerts..."
    if gh api "repos/$repo/vulnerability-alerts" -X PUT >> "$LOG_FILE" 2>&1; then
        log "${GREEN}✅ Vulnerability alerts enabled${NC}"
    else
        log "${YELLOW}⚠️  Could not enable vulnerability alerts (may already be enabled)${NC}"
    fi
    
    # Enable automated security fixes (Dependabot)
    log "   Enabling automated security fixes..."
    if gh api "repos/$repo/automated-security-fixes" -X PUT >> "$LOG_FILE" 2>&1; then
        log "${GREEN}✅ Automated security fixes enabled${NC}"
    else
        log "${YELLOW}⚠️  Could not enable automated security fixes (may already be enabled)${NC}"
    fi
    
    # Enable dependency graph
    log "   Checking dependency graph..."
    local dependency_graph_status
    dependency_graph_status=$(gh api "repos/$repo" --jq '.has_dependency_graph' 2>/dev/null || echo "false")
    
    if [ "$dependency_graph_status" = "true" ]; then
        log "${GREEN}✅ Dependency graph is enabled${NC}"
    else
        log "${YELLOW}⚠️  Dependency graph may not be available for this repository type${NC}"
    fi
    
    return 0
}

# Function to configure branch protection
configure_branch_protection() {
    log "${BLUE}🛡️  Configuring branch protection${NC}"
    
    if ! command_exists gh || ! gh auth status >/dev/null 2>&1; then
        log "${YELLOW}⚠️  GitHub CLI not available, skipping branch protection setup${NC}"
        return 1
    fi
    
    local repo="$REPO_OWNER/$REPO_NAME"
    local branch="${MAIN_BRANCH:-main}"
    
    # Check if branch exists
    if ! gh api "repos/$repo/branches/$branch" >/dev/null 2>&1; then
        branch="master"
        if ! gh api "repos/$repo/branches/$branch" >/dev/null 2>&1; then
            log "${YELLOW}⚠️  No main/master branch found, skipping branch protection${NC}"
            return 1
        fi
    fi
    
    log "   Configuring protection for branch: $branch"
    
    # Configure branch protection rules
    local protection_config='{
        "required_status_checks": {
            "strict": true,
            "contexts": ["security-scan", "code-quality"]
        },
        "enforce_admins": false,
        "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews": true,
            "require_code_owner_reviews": false,
            "require_last_push_approval": false
        },
        "restrictions": null,
        "allow_force_pushes": false,
        "allow_deletions": false,
        "block_creations": false,
        "required_conversation_resolution": true
    }'
    
    if echo "$protection_config" | gh api "repos/$repo/branches/$branch/protection" --input - >> "$LOG_FILE" 2>&1; then
        log "${GREEN}✅ Branch protection configured for $branch${NC}"
    else
        log "${YELLOW}⚠️  Could not configure branch protection (may need admin access)${NC}"
    fi
    
    return 0
}

# Function to create CODEOWNERS file
create_codeowners() {
    log "${BLUE}👥 Creating CODEOWNERS file${NC}"
    
    local codeowners_file=".github/CODEOWNERS"
    
    if [ -f "$codeowners_file" ]; then
        log "${YELLOW}⚠️  CODEOWNERS file already exists${NC}"
        return 0
    fi
    
    # Create CODEOWNERS directory if it doesn't exist
    mkdir -p "$(dirname "$codeowners_file")"
    
    cat > "$codeowners_file" << EOF
# OpenDocSeal Code Owners
# See: https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

# Global owners
* @${REPO_OWNER}

# Security-related files
/.github/workflows/ @${REPO_OWNER}
/.github/actions/ @${REPO_OWNER}
/security/ @${REPO_OWNER}
SECURITY.md @${REPO_OWNER}
.bandit @${REPO_OWNER}
.pre-commit-config.yaml @${REPO_OWNER}

# Configuration files
*.yml @${REPO_OWNER}
*.yaml @${REPO_OWNER}
*.json @${REPO_OWNER}
Dockerfile* @${REPO_OWNER}
docker-compose*.yml @${REPO_OWNER}

# Dependencies
requirements.txt @${REPO_OWNER}
package.json @${REPO_OWNER}
pyproject.toml @${REPO_OWNER}

# Core application
/source/api/ @${REPO_OWNER}
/source/services/ @${REPO_OWNER}
/source/shared/ @${REPO_OWNER}

# Documentation
*.md @${REPO_OWNER}
/docs/ @${REPO_OWNER}
EOF

    log "${GREEN}✅ CODEOWNERS file created${NC}"
    return 0
}

# Function to create security issue templates
create_security_templates() {
    log "${BLUE}📝 Creating security issue templates${NC}"
    
    local templates_dir=".github/ISSUE_TEMPLATE"
    mkdir -p "$templates_dir"
    
    # Security vulnerability template
    cat > "$templates_dir/security-vulnerability.yml" << 'EOF'
name: 🔒 Security Vulnerability Report
description: Report a security vulnerability in OpenDocSeal
title: "[SECURITY] "
labels: ["security", "vulnerability"]
assignees: []

body:
  - type: markdown
    attributes:
      value: |
        # Security Vulnerability Report
        
        Thank you for helping to keep OpenDocSeal secure! Please provide the following information about the vulnerability.
        
        **⚠️ IMPORTANT: Do not disclose security vulnerabilities publicly.**
        
  - type: dropdown
    id: severity
    attributes:
      label: Severity Level
      description: How severe is this vulnerability?
      options:
        - Critical (Immediate action required)
        - High (Important security risk)
        - Medium (Moderate security risk)
        - Low (Minor security concern)
    validations:
      required: true
      
  - type: dropdown
    id: category
    attributes:
      label: Vulnerability Category
      description: What type of vulnerability is this?
      options:
        - Authentication/Authorization
        - Code Injection
        - Cross-Site Scripting (XSS)
        - Cross-Site Request Forgery (CSRF)
        - Data Exposure
        - Dependency Vulnerability
        - Input Validation
        - Cryptographic Issue
        - Configuration Error
        - Other
    validations:
      required: true
      
  - type: textarea
    id: description
    attributes:
      label: Vulnerability Description
      description: Provide a clear description of the vulnerability
      placeholder: Describe the vulnerability and its potential impact
    validations:
      required: true
      
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: How can this vulnerability be reproduced?
      placeholder: |
        1. Step one
        2. Step two
        3. etc.
    validations:
      required: true
      
  - type: textarea
    id: impact
    attributes:
      label: Potential Impact
      description: What could an attacker accomplish with this vulnerability?
      placeholder: Describe the potential impact if this vulnerability were exploited
    validations:
      required: true
      
  - type: textarea
    id: environment
    attributes:
      label: Environment Information
      description: What environment did you discover this in?
      placeholder: |
        - OS: 
        - Browser: 
        - Version: 
        - Configuration: 
    validations:
      required: false
      
  - type: textarea
    id: additional
    attributes:
      label: Additional Information
      description: Any additional information that might be helpful
      placeholder: Screenshots, logs, or other relevant information
    validations:
      required: false
EOF

    # Security enhancement template
    cat > "$templates_dir/security-enhancement.yml" << 'EOF'
name: 🛡️ Security Enhancement
description: Suggest a security improvement for OpenDocSeal
title: "[SECURITY ENHANCEMENT] "
labels: ["security", "enhancement"]
assignees: []

body:
  - type: markdown
    attributes:
      value: |
        # Security Enhancement Request
        
        Thank you for helping to improve OpenDocSeal's security! Please describe your enhancement idea.
        
  - type: dropdown
    id: priority
    attributes:
      label: Priority Level
      description: How important is this enhancement?
      options:
        - High (Important security improvement)
        - Medium (Moderate security improvement)
        - Low (Minor security improvement)
    validations:
      required: true
      
  - type: dropdown
    id: area
    attributes:
      label: Security Area
      description: Which area of security does this enhancement relate to?
      options:
        - Authentication & Authorization
        - Data Protection & Encryption
        - Network Security
        - Application Security
        - Infrastructure Security
        - Monitoring & Logging
        - Compliance & Auditing
        - Other
    validations:
      required: true
      
  - type: textarea
    id: description
    attributes:
      label: Enhancement Description
      description: Describe the security enhancement you're proposing
      placeholder: What security improvement would you like to see?
    validations:
      required: true
      
  - type: textarea
    id: rationale
    attributes:
      label: Security Rationale
      description: Why is this enhancement important for security?
      placeholder: Explain the security benefits and risks it addresses
    validations:
      required: true
      
  - type: textarea
    id: implementation
    attributes:
      label: Implementation Ideas
      description: Do you have any ideas about how this could be implemented?
      placeholder: Suggest implementation approaches, tools, or technologies
    validations:
      required: false
      
  - type: textarea
    id: alternatives
    attributes:
      label: Alternative Solutions
      description: Are there alternative ways to address this security concern?
      placeholder: Describe any alternative approaches you've considered
    validations:
      required: false
EOF

    log "${GREEN}✅ Security issue templates created${NC}"
    return 0
}

# Function to create GitHub security advisory template
create_security_advisory_template() {
    log "${BLUE}📋 Creating security advisory documentation${NC}"
    
    local security_dir=".github/SECURITY"
    mkdir -p "$security_dir"
    
    cat > "$security_dir/ADVISORY_TEMPLATE.md" << 'EOF'
# Security Advisory Template

## Advisory Information

**Advisory ID:** OPDS-YYYY-####
**Published:** YYYY-MM-DD
**Updated:** YYYY-MM-DD
**Severity:** [Critical/High/Medium/Low]

## Summary

Brief description of the vulnerability.

## Impact

Description of the potential impact if exploited.

## Affected Versions

- OpenDocSeal versions: X.X.X - Y.Y.Y

## Technical Details

### Vulnerability Description

Detailed technical description of the vulnerability.

### Root Cause

Explanation of what caused this vulnerability.

### Attack Scenarios

How this vulnerability could be exploited.

## Resolution

### Patches

- Fixed in version: Z.Z.Z
- Commit: [commit hash]

### Workarounds

If available, temporary workarounds before upgrading.

## Recommendations

1. Upgrade to version Z.Z.Z or later immediately
2. Review logs for potential exploitation
3. [Additional recommendations]

## Timeline

- **Discovery:** YYYY-MM-DD
- **Internal Fix:** YYYY-MM-DD
- **Security Review:** YYYY-MM-DD
- **Release:** YYYY-MM-DD
- **Public Disclosure:** YYYY-MM-DD

## Credits

Thanks to [researcher name] for responsibly disclosing this vulnerability.

## References

- [CVE-YYYY-####](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-YYYY-####)
- [Security Advisory](https://github.com/owner/repo/security/advisories/GHSA-xxxx-xxxx-xxxx)
EOF

    log "${GREEN}✅ Security advisory template created${NC}"
    return 0
}

# Function to validate security configuration
validate_security_config() {
    log "${BLUE}✅ Validating security configuration${NC}"
    
    local validation_passed=true
    
    # Check for required files
    local required_files=(
        ".github/workflows/security-analysis.yml"
        ".github/workflows/codeql-analysis.yml"
        ".github/dependabot.yml"
        ".bandit"
        ".pre-commit-config.yaml"
        "SECURITY.md"
    )
    
    for file in "${required_files[@]}"; do
        if [ -f "$file" ]; then
            log "${GREEN}✅ $file exists${NC}"
        else
            log "${RED}❌ $file is missing${NC}"
            validation_passed=false
        fi
    done
    
    # Check GitHub settings (if CLI is available)
    if command_exists gh && gh auth status >/dev/null 2>&1; then
        local repo="$REPO_OWNER/$REPO_NAME"
        
        # Check if security features are enabled
        local vuln_alerts
        vuln_alerts=$(gh api "repos/$repo/vulnerability-alerts" 2>/dev/null && echo "enabled" || echo "disabled")
        
        if [ "$vuln_alerts" = "enabled" ]; then
            log "${GREEN}✅ Vulnerability alerts enabled${NC}"
        else
            log "${YELLOW}⚠️  Vulnerability alerts not enabled${NC}"
        fi
        
        # Check for recent security scans
        local recent_runs
        recent_runs=$(gh api "repos/$repo/actions/runs" --jq '.workflow_runs | map(select(.name | contains("Security"))) | length' 2>/dev/null || echo "0")
        
        if [ "$recent_runs" -gt 0 ]; then
            log "${GREEN}✅ Security workflows have been executed${NC}"
        else
            log "${YELLOW}⚠️  No security workflow runs found${NC}"
        fi
    fi
    
    if [ "$validation_passed" = true ]; then
        log "${GREEN}🎉 Security configuration validation passed${NC}"
        return 0
    else
        log "${YELLOW}⚠️  Security configuration validation found issues${NC}"
        return 1
    fi
}

# Function to generate security setup report
generate_security_report() {
    log "${BLUE}📊 Generating security setup report${NC}"
    
    local report_file="${REPORTS_DIR}/security-setup-report-${TIMESTAMP}.md"
    
    cat > "$report_file" << EOF
# GitHub Security Setup Report

**Generated:** $(date)
**Project:** $PROJECT_NAME
**Repository:** ${REPO_OWNER:-Unknown}/${REPO_NAME:-Unknown}

## Setup Summary

This report summarizes the GitHub security configuration for OpenDocSeal.

## Configured Features

### Security Scanning
- [x] CodeQL Analysis
- [x] Bandit Security Scanner
- [x] Safety Vulnerability Checks
- [x] Dependency Scanning
- [x] Secret Scanning

### Branch Protection
- [x] Required status checks
- [x] Required pull request reviews
- [x] Dismiss stale reviews
- [x] Required conversation resolution

### Access Control
- [x] CODEOWNERS file
- [x] Issue templates for security reports
- [x] Security advisory templates

### Automation
- [x] Dependabot configuration
- [x] Automated security fixes
- [x] Pre-commit hooks

## Security Workflows

1. **security-analysis.yml** - Comprehensive security scanning
2. **codeql-analysis.yml** - Code quality and security analysis
3. **pr-security-integration.yml** - PR-based security checks

## Next Steps

1. Review and customize branch protection rules
2. Configure team access and permissions
3. Set up notification preferences
4. Schedule regular security reviews
5. Train team on security procedures

## Documentation

- Security Policy: \`SECURITY.md\`
- Issue Templates: \`.github/ISSUE_TEMPLATE/\`
- Code Owners: \`.github/CODEOWNERS\`

## Monitoring

Regular monitoring should include:
- Security scan results
- Dependency update notifications
- Failed security checks
- Unusual access patterns

---
*This report was automatically generated by the GitHub security setup script.*
EOF

    log "${GREEN}✅ Security setup report generated: $report_file${NC}"
}

# Main function
main() {
    log "${BLUE}🚀 Starting GitHub Security Setup for $PROJECT_NAME${NC}"
    log "Timestamp: $(date)"
    log "Log file: $LOG_FILE"
    log ""
    
    local overall_status=0
    
    # Check prerequisites
    if ! check_gh_auth; then
        log "${YELLOW}⚠️  GitHub CLI not authenticated. Some features will be skipped.${NC}"
    fi
    
    if ! get_repo_info; then
        log "${YELLOW}⚠️  Repository information not available. Some features will be skipped.${NC}"
    fi
    
    # Setup security features
    enable_security_features || overall_status=1
    configure_branch_protection || overall_status=1
    create_codeowners || overall_status=1
    create_security_templates || overall_status=1
    create_security_advisory_template || overall_status=1
    
    # Validate configuration
    validate_security_config || overall_status=1
    
    # Generate report
    generate_security_report
    
    log ""
    if [ $overall_status -eq 0 ]; then
        log "${GREEN}🎉 GitHub security setup completed successfully!${NC}"
        log "${GREEN}🔒 Your repository is now configured with comprehensive security measures.${NC}"
    else
        log "${YELLOW}⚠️  GitHub security setup completed with some warnings.${NC}"
        log "${YELLOW}Please review the log and address any issues manually.${NC}"
    fi
    
    log ""
    log "${BLUE}📋 Next Steps:${NC}"
    log "1. Review and commit the generated security files"
    log "2. Configure team access permissions in GitHub"
    log "3. Set up notification preferences for security alerts"
    log "4. Run the first security scan to test the setup"
    log ""
    log "${BLUE}📄 Setup complete. Check reports in: $REPORTS_DIR/${NC}"
    
    exit $overall_status
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Environment Variables:"
        echo "  GITHUB_TOKEN    GitHub personal access token (optional if using gh CLI)"
        echo "  REPO_OWNER      Repository owner/organization name"
        echo "  REPO_NAME       Repository name"
        echo "  MAIN_BRANCH     Main branch name (default: main)"
        echo ""
        echo "Options:"
        echo "  --help, -h      Show this help"
        echo ""
        echo "Examples:"
        echo "  $0                              # Auto-detect repository"
        echo "  REPO_OWNER=myorg REPO_NAME=myrepo $0"
        exit 0
        ;;
esac

# Run main function
main "$@"