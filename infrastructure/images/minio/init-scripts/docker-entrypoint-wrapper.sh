#!/bin/bash
# File: docker-entrypoint-wrapper.sh
# Path: infrastructure/images/minio/init-scripts/docker-entrypoint-wrapper.sh
# Version: 3 

set -e

echo "=== OpenDocSeal MinIO Starting ==="
echo "User: ${MINIO_ROOT_USER}"
echo "Browser: ${MINIO_BROWSER}"
echo "Console URL: ${MINIO_BROWSER_REDIRECT_URL:-http://localhost:9001}"
echo "Server URL: ${MINIO_SERVER_URL:-http://localhost:9000}"

# Start MinIO server in background
echo "Starting MinIO server..."
minio server /data --console-address ":9001" &
MINIO_PID=$!

# Function to cleanup on exit
cleanup() {
    echo "Shutting down MinIO..."
    kill $MINIO_PID 2>/dev/null || true
    wait $MINIO_PID 2>/dev/null || true
    exit 0
}

# Set trap for cleanup
trap cleanup SIGTERM SIGINT

# Wait for MinIO to be ready (healthcheck)
echo "Waiting for MinIO to be ready..."
for i in {1..30}; do
    if curl -f http://localhost:9000/minio/health/live >/dev/null 2>&1; then
        echo "✅ MinIO is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ MinIO failed to start within 30 seconds"
        exit 1
    fi
    sleep 1
done

# Run initialization scripts if they exist and if not already done
INIT_MARKER="/data/.opendocseal-initialized"
if [ ! -f "$INIT_MARKER" ] && [ -d "/docker-entrypoint.d" ]; then
    echo "Running initialization scripts..."
    for script in /docker-entrypoint.d/*.sh; do
        if [ -f "$script" ] && [ "$(basename $script)" != "$(basename $0)" ]; then
            echo "Executing: $(basename $script)"
            if bash "$script"; then
                echo "✅ $(basename $script) completed successfully"
            else
                echo "❌ $(basename $script) failed"
            fi
        fi
    done
    
    # Mark as initialized
    echo "$(date): OpenDocSeal MinIO initialized" > "$INIT_MARKER"
    echo "✅ Initialization completed"
else
    echo "ℹ️  MinIO already initialized, skipping init scripts"
fi

# Display final status
echo ""
echo "=== MinIO is ready! ==="
echo "Console: ${MINIO_BROWSER_REDIRECT_URL:-http://localhost:9001}"
echo "API: ${MINIO_SERVER_URL:-http://localhost:9000}"
echo "Health: http://localhost:9000/minio/health/live"
echo ""

# Keep the container running by waiting for MinIO process
wait $MINIO_PID