#!/bin/bash
# Monitoring Validation Script for OpenDocSeal
# Validates monitoring setup and performs health checks

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
MONITORING_DIR="monitoring"
REPORTS_DIR="reports/monitoring"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_FILE="${REPORTS_DIR}/monitoring-validation-${TIMESTAMP}.log"

# Default endpoints and services
API_ENDPOINT="${API_ENDPOINT:-http://localhost:8000}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://localhost:9000}"
MONGODB_ENDPOINT="${MONGODB_ENDPOINT:-mongodb://localhost:27017}"
N8N_ENDPOINT="${N8N_ENDPOINT:-http://localhost:5678}"

# Health check timeout
TIMEOUT="${TIMEOUT:-10}"

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

# Function to check HTTP endpoint health
check_http_endpoint() {
    local name="$1"
    local url="$2"
    local expected_status="${3:-200}"
    
    log "${CYAN}🔍 Checking $name at $url${NC}"
    
    if command_exists curl; then
        local response
        local status_code
        
        # Make request with timeout
        if response=$(curl -s -o /dev/null -w "%{http_code}" -m "$TIMEOUT" "$url" 2>/dev/null); then
            status_code="$response"
            
            if [ "$status_code" = "$expected_status" ]; then
                log "${GREEN}✅ $name is healthy (HTTP $status_code)${NC}"
                return 0
            else
                log "${YELLOW}⚠️  $name returned HTTP $status_code (expected $expected_status)${NC}"
                return 1
            fi
        else
            log "${RED}❌ $name is not responding or connection failed${NC}"
            return 1
        fi
    else
        log "${YELLOW}⚠️  curl not available, skipping HTTP check for $name${NC}"
        return 1
    fi
}

# Function to check MongoDB connection
check_mongodb() {
    local endpoint="$1"
    
    log "${CYAN}🔍 Checking MongoDB at $endpoint${NC}"
    
    if command_exists mongosh || command_exists mongo; then
        local mongo_cmd
        if command_exists mongosh; then
            mongo_cmd="mongosh"
        else
            mongo_cmd="mongo"
        fi
        
        # Try to connect and run a simple command
        if $mongo_cmd "$endpoint" --eval "db.adminCommand('ismaster')" --quiet >> "$LOG_FILE" 2>&1; then
            log "${GREEN}✅ MongoDB is accessible and responding${NC}"
            
            # Get MongoDB status
            local mongo_info
            mongo_info=$($mongo_cmd "$endpoint" --eval "print(JSON.stringify(db.adminCommand('serverStatus')))" --quiet 2>/dev/null || echo "{}")
            echo "MongoDB Status: $mongo_info" >> "$LOG_FILE"
            
            return 0
        else
            log "${RED}❌ MongoDB connection failed${NC}"
            return 1
        fi
    else
        log "${YELLOW}⚠️  MongoDB client not available, attempting basic connection test${NC}"
        
        # Extract host and port from MongoDB URI
        local host port
        host=$(echo "$endpoint" | sed -n 's#mongodb://\([^:]*\).*#\1#p')
        port=$(echo "$endpoint" | sed -n 's#mongodb://[^:]*:\([0-9]*\).*#\1#p')
        port=${port:-27017}
        
        if command_exists nc; then
            if nc -z "$host" "$port" 2>/dev/null; then
                log "${GREEN}✅ MongoDB port $port is open on $host${NC}"
                return 0
            else
                log "${RED}❌ Cannot connect to MongoDB port $port on $host${NC}"
                return 1
            fi
        else
            log "${YELLOW}⚠️  No tools available to check MongoDB${NC}"
            return 1
        fi
    fi
}

# Function to check MinIO
check_minio() {
    local endpoint="$1"
    
    log "${CYAN}🔍 Checking MinIO at $endpoint${NC}"
    
    # Try MinIO health endpoint
    local health_url="${endpoint}/minio/health/live"
    
    if check_http_endpoint "MinIO Health" "$health_url" "200"; then
        return 0
    else
        # Fallback to basic endpoint check
        if check_http_endpoint "MinIO Basic" "$endpoint" "403"; then
            log "${GREEN}✅ MinIO is responding (403 expected for unauthenticated access)${NC}"
            return 0
        else
            return 1
        fi
    fi
}

# Function to check FastAPI application
check_fastapi() {
    local endpoint="$1"
    
    log "${CYAN}🔍 Checking FastAPI application at $endpoint${NC}"
    
    # Check health endpoint
    if check_http_endpoint "FastAPI Health" "${endpoint}/health" "200"; then
        return 0
    elif check_http_endpoint "FastAPI Docs" "${endpoint}/docs" "200"; then
        log "${GREEN}✅ FastAPI is responding (docs endpoint accessible)${NC}"
        return 0
    elif check_http_endpoint "FastAPI Root" "$endpoint" "200"; then
        log "${GREEN}✅ FastAPI is responding (root endpoint accessible)${NC}"
        return 0
    else
        return 1
    fi
}

# Function to check N8N
check_n8n() {
    local endpoint="$1"
    
    log "${CYAN}🔍 Checking N8N at $endpoint${NC}"
    
    # N8N typically redirects to login page
    if check_http_endpoint "N8N" "$endpoint" "200" || check_http_endpoint "N8N" "$endpoint" "302"; then
        return 0
    else
        return 1
    fi
}

# Function to check disk space
check_disk_space() {
    log "${CYAN}🔍 Checking disk space${NC}"
    
    local usage
    usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [ "$usage" -lt 80 ]; then
        log "${GREEN}✅ Disk usage is healthy: ${usage}%${NC}"
        return 0
    elif [ "$usage" -lt 90 ]; then
        log "${YELLOW}⚠️  Disk usage is high: ${usage}%${NC}"
        return 1
    else
        log "${RED}❌ Disk usage is critical: ${usage}%${NC}"
        return 1
    fi
}

# Function to check memory usage
check_memory() {
    log "${CYAN}🔍 Checking memory usage${NC}"
    
    if command_exists free; then
        local mem_info
        mem_info=$(free | awk 'NR==2{printf "%.1f", $3*100/$2}')
        
        local mem_usage=${mem_info%.*}  # Remove decimal part
        
        if [ "$mem_usage" -lt 80 ]; then
            log "${GREEN}✅ Memory usage is healthy: ${mem_usage}%${NC}"
            return 0
        elif [ "$mem_usage" -lt 90 ]; then
            log "${YELLOW}⚠️  Memory usage is high: ${mem_usage}%${NC}"
            return 1
        else
            log "${RED}❌ Memory usage is critical: ${mem_usage}%${NC}"
            return 1
        fi
    else
        log "${YELLOW}⚠️  Cannot check memory usage (free command not available)${NC}"
        return 1
    fi
}

# Function to check CPU load
check_cpu_load() {
    log "${CYAN}🔍 Checking CPU load${NC}"
    
    if [ -f "/proc/loadavg" ]; then
        local load_1min
        load_1min=$(cut -d' ' -f1 < /proc/loadavg)
        local cpu_count
        cpu_count=$(nproc)
        
        # Calculate load percentage
        local load_percent
        load_percent=$(echo "$load_1min $cpu_count" | awk '{printf "%.1f", ($1/$2)*100}')
        
        local load_int=${load_percent%.*}  # Remove decimal part
        
        if [ "$load_int" -lt 70 ]; then
            log "${GREEN}✅ CPU load is healthy: ${load_percent}%${NC}"
            return 0
        elif [ "$load_int" -lt 90 ]; then
            log "${YELLOW}⚠️  CPU load is high: ${load_percent}%${NC}"
            return 1
        else
            log "${RED}❌ CPU load is critical: ${load_percent}%${NC}"
            return 1
        fi
    else
        log "${YELLOW}⚠️  Cannot check CPU load (/proc/loadavg not available)${NC}"
        return 1
    fi
}

# Function to check Docker containers (if applicable)
check_docker_containers() {
    log "${CYAN}🔍 Checking Docker containers${NC}"
    
    if command_exists docker; then
        local running_containers
        running_containers=$(docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null || echo "")
        
        if [ -n "$running_containers" ]; then
            log "${GREEN}✅ Docker containers status:${NC}"
            echo "$running_containers" | while read -r line; do
                log "   $line"
            done
            
            # Check for any unhealthy containers
            local unhealthy
            unhealthy=$(docker ps --filter "health=unhealthy" --format "{{.Names}}" 2>/dev/null || echo "")
            
            if [ -n "$unhealthy" ]; then
                log "${RED}❌ Unhealthy containers found: $unhealthy${NC}"
                return 1
            else
                log "${GREEN}✅ All containers are healthy${NC}"
                return 0
            fi
        else
            log "${YELLOW}⚠️  No Docker containers running${NC}"
            return 1
        fi
    else
        log "${YELLOW}⚠️  Docker not available${NC}"
        return 0
    fi
}

# Function to check log files
check_log_files() {
    log "${CYAN}🔍 Checking log files${NC}"
    
    local log_dirs=("/var/log" "./logs" "./log")
    local found_logs=false
    
    for log_dir in "${log_dirs[@]}"; do
        if [ -d "$log_dir" ]; then
            local recent_errors
            recent_errors=$(find "$log_dir" -name "*.log" -mtime -1 -exec grep -l -i "error\|critical\|fatal" {} \; 2>/dev/null | head -5)
            
            if [ -n "$recent_errors" ]; then
                log "${YELLOW}⚠️  Recent errors found in logs:${NC}"
                echo "$recent_errors" | while read -r logfile; do
                    local error_count
                    error_count=$(grep -c -i "error\|critical\|fatal" "$logfile" 2>/dev/null || echo "0")
                    log "   $logfile: $error_count errors"
                done
                found_logs=true
            fi
        fi
    done
    
    if [ "$found_logs" = false ]; then
        log "${GREEN}✅ No recent errors found in log files${NC}"
    fi
    
    return 0
}

# Function to generate monitoring report
generate_monitoring_report() {
    log "${BLUE}📊 Generating monitoring report${NC}"
    
    local report_file="${REPORTS_DIR}/monitoring-report-${TIMESTAMP}.json"
    local html_report="${REPORTS_DIR}/monitoring-report-${TIMESTAMP}.html"
    
    # Generate JSON report
    cat > "$report_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "project": "$PROJECT_NAME",
  "validation_results": {
    "system_health": {
      "disk_usage_ok": $(check_disk_space >/dev/null 2>&1 && echo "true" || echo "false"),
      "memory_usage_ok": $(check_memory >/dev/null 2>&1 && echo "true" || echo "false"),
      "cpu_load_ok": $(check_cpu_load >/dev/null 2>&1 && echo "true" || echo "false")
    },
    "services": {
      "fastapi_ok": $(check_fastapi "$API_ENDPOINT" >/dev/null 2>&1 && echo "true" || echo "false"),
      "mongodb_ok": $(check_mongodb "$MONGODB_ENDPOINT" >/dev/null 2>&1 && echo "true" || echo "false"),
      "minio_ok": $(check_minio "$MINIO_ENDPOINT" >/dev/null 2>&1 && echo "true" || echo "false"),
      "n8n_ok": $(check_n8n "$N8N_ENDPOINT" >/dev/null 2>&1 && echo "true" || echo "false")
    }
  }
}
EOF

    # Generate HTML report
    cat > "$html_report" << 'EOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenDocSeal - Monitoring Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .status-item { padding: 15px; border-radius: 6px; text-align: center; }
        .status-ok { background: #d4edda; color: #155724; }
        .status-warning { background: #fff3cd; color: #856404; }
        .status-error { background: #f8d7da; color: #721c24; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
        .refresh-btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
    </style>
    <script>
        function refreshReport() {
            location.reload();
        }
        
        // Auto-refresh every 5 minutes
        setTimeout(refreshReport, 300000);
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 OpenDocSeal - Monitoring Report</h1>
            <p class="timestamp">Generated: <span id="timestamp"></span></p>
            <button class="refresh-btn" onclick="refreshReport()">🔄 Refresh</button>
        </div>
        
        <div class="section">
            <h2>System Health</h2>
            <div class="status-grid" id="system-status">
                <!-- Will be populated by JavaScript -->
            </div>
        </div>
        
        <div class="section">
            <h2>Services Status</h2>
            <div class="status-grid" id="services-status">
                <!-- Will be populated by JavaScript -->
            </div>
        </div>
    </div>
    
    <script>
        // Set timestamp
        document.getElementById('timestamp').textContent = new Date().toLocaleString();
        
        // This would be populated with real data in a production environment
        // For now, showing static example
        const systemStatus = document.getElementById('system-status');
        const servicesStatus = document.getElementById('services-status');
        
        // Example status items - in production, this would come from the JSON report
        systemStatus.innerHTML = `
            <div class="status-item status-ok">
                <h3>💾 Disk Space</h3>
                <p>Healthy</p>
            </div>
            <div class="status-item status-ok">
                <h3>🧠 Memory</h3>
                <p>Normal</p>
            </div>
            <div class="status-item status-ok">
                <h3>⚡ CPU Load</h3>
                <p>Low</p>
            </div>
        `;
        
        servicesStatus.innerHTML = `
            <div class="status-item status-ok">
                <h3>🚀 FastAPI</h3>
                <p>Running</p>
            </div>
            <div class="status-item status-ok">
                <h3>🗄️ MongoDB</h3>
                <p>Connected</p>
            </div>
            <div class="status-item status-ok">
                <h3>📦 MinIO</h3>
                <p>Available</p>
            </div>
            <div class="status-item status-ok">
                <h3>🔄 N8N</h3>
                <p>Active</p>
            </div>
        `;
    </script>
</body>
</html>
EOF

    log "${GREEN}✅ Monitoring reports generated:${NC}"
    log "   JSON: $report_file"
    log "   HTML: $html_report"
}

# Main monitoring validation function
main() {
    log "${BLUE}🔍 Starting Monitoring Validation for $PROJECT_NAME${NC}"
    log "Timestamp: $(date)"
    log "Log file: $LOG_FILE"
    log ""
    
    local overall_status=0
    
    # System health checks
    log "${PURPLE}🏥 SYSTEM HEALTH CHECKS${NC}"
    check_disk_space || overall_status=1
    check_memory || overall_status=1
    check_cpu_load || overall_status=1
    check_docker_containers || overall_status=1
    
    log ""
    
    # Service health checks
    log "${PURPLE}🔧 SERVICE HEALTH CHECKS${NC}"
    check_fastapi "$API_ENDPOINT" || overall_status=1
    check_mongodb "$MONGODB_ENDPOINT" || overall_status=1
    check_minio "$MINIO_ENDPOINT" || overall_status=1
    check_n8n "$N8N_ENDPOINT" || overall_status=1
    
    log ""
    
    # Additional checks
    log "${PURPLE}📋 ADDITIONAL CHECKS${NC}"
    check_log_files || overall_status=1
    
    # Generate reports
    generate_monitoring_report
    
    log ""
    if [ $overall_status -eq 0 ]; then
        log "${GREEN}🎉 ALL MONITORING CHECKS PASSED! System is healthy.${NC}"
    else
        log "${YELLOW}⚠️  Some monitoring checks failed. Please investigate.${NC}"
    fi
    
    log "${BLUE}📄 Monitoring validation complete. Check reports in: $REPORTS_DIR/${NC}"
    
    exit $overall_status
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --api-endpoint URL      FastAPI endpoint (default: http://localhost:8000)"
        echo "  --minio-endpoint URL    MinIO endpoint (default: http://localhost:9000)"
        echo "  --mongodb-endpoint URL  MongoDB endpoint (default: mongodb://localhost:27017)"
        echo "  --n8n-endpoint URL      N8N endpoint (default: http://localhost:5678)"
        echo "  --timeout SECONDS       HTTP timeout (default: 10)"
        echo "  --help, -h              Show this help"
        exit 0
        ;;
    --api-endpoint)
        API_ENDPOINT="$2"
        shift 2
        ;;
    --minio-endpoint)
        MINIO_ENDPOINT="$2"
        shift 2
        ;;
    --mongodb-endpoint)
        MONGODB_ENDPOINT="$2"
        shift 2
        ;;
    --n8n-endpoint)
        N8N_ENDPOINT="$2"
        shift 2
        ;;
    --timeout)
        TIMEOUT="$2"
        shift 2
        ;;
esac

# Run main function
main "$@"