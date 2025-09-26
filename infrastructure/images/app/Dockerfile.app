# File: Dockerfile.app
# Path: infrastructure/images/app/Dockerfile.app
# Version: 9
# =============================================================================
# OpenDocSeal Frontend - Static Website with Caddy
# =============================================================================

# Build arguments from .env.build with default values
ARG CADDY_BASE_IMAGE=unknown
ARG BUILD_DATE=unknown
ARG BUILD_VERSION=unknown

FROM ${CADDY_BASE_IMAGE}

# Add labels for metadata
LABEL org.opencontainers.image.title="OpenDocSeal Frontend"
LABEL org.opencontainers.image.description="Frontend application served by Caddy"
LABEL org.opencontainers.image.version="${BUILD_VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.source="https://github.com/opendocseal/opendocseal"
LABEL org.opencontainers.image.vendor="OpenDocSeal"
LABEL maintainer="OpenDocSeal Team"

# Create basic frontend structure
RUN mkdir -p /usr/share/caddy

# Copy frontend files from source/frontend/
# Context is project root, so frontend is source/frontend/
COPY source/frontend/ /usr/share/caddy/

# Copy Caddy configuration for frontend
COPY infrastructure/images/app/Caddyfile /etc/caddy/Caddyfile

# Create necessary directories with proper permissions
# Note: Use root ownership since caddy user may not exist in base image
RUN mkdir -p /var/log/caddy /var/lib/caddy && \
    chmod -R 755 /var/log/caddy /var/lib/caddy /usr/share/caddy

# Health check
# HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
#     CMD curl -f http://localhost:80/ || exit 1

# Expose port
EXPOSE 8001

# Start Caddy (uses JSON array format - recommended)
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]