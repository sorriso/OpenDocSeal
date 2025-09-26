#!/bin/bash
# File: 01-init-buckets.sh
# Path: infrastructure/images/minio/init-scripts/01-init-buckets.sh
# Version: 1
# =============================================================================
# MinIO Initialization Script for OpenDocSeal
# Creates necessary buckets and configures policies
# =============================================================================

set -e

# Configuration from environment variables
BUCKET_NAME=${OPENDOCSEAL_BUCKET_NAME:-"opendocseal-documents"}
BUCKET_REGION=${OPENDOCSEAL_BUCKET_REGION:-"us-east-1"}
MINIO_ENDPOINT="http://localhost:9000"
MINIO_USER=${MINIO_ROOT_USER:-"opendocseal"}
MINIO_PASS=${MINIO_ROOT_PASSWORD:-"OpenDocSeal2025!"}

echo "=== OpenDocSeal MinIO Initialization ==="
echo "Bucket Name: $BUCKET_NAME"
echo "Region: $BUCKET_REGION"
echo "Endpoint: $MINIO_ENDPOINT"

# Wait for MinIO to be ready
echo "Waiting for MinIO to be ready..."
sleep 10

# Configure mc client
echo "Configuring MinIO client..."
mc alias set opendocseal $MINIO_ENDPOINT $MINIO_USER $MINIO_PASS

# Check if bucket exists
if mc ls opendocseal/$BUCKET_NAME > /dev/null 2>&1; then
    echo "⚠️  Bucket '$BUCKET_NAME' already exists"
else
    # Create main bucket
    echo "Creating bucket '$BUCKET_NAME'..."
    mc mb opendocseal/$BUCKET_NAME --region=$BUCKET_REGION
    echo "✅ Bucket '$BUCKET_NAME' created successfully"
fi

# Set bucket policy for documents (private by default)
echo "Setting bucket policy..."
cat > /tmp/bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "s3:GetBucketLocation",
        "s3:ListBucket"
      ],
      "Resource": "arn:aws:s3:::$BUCKET_NAME"
    }
  ]
}
EOF

mc policy set-json /tmp/bucket-policy.json opendocseal/$BUCKET_NAME 2>/dev/null || echo "⚠️  Could not set bucket policy (may require admin privileges)"

# Create subdirectories structure
echo "Creating bucket structure..."
mc mkdir -p opendocseal/$BUCKET_NAME/documents 2>/dev/null || true
mc mkdir -p opendocseal/$BUCKET_NAME/sealed 2>/dev/null || true
mc mkdir -p opendocseal/$BUCKET_NAME/temp 2>/dev/null || true

echo "✅ Bucket structure created:"
echo "  - documents/ (original uploaded files)"
echo "  - sealed/ (sealed zip files with blockchain proofs)"
echo "  - temp/ (temporary processing files)"

# Create a test file to verify everything works
echo "Creating test file..."
echo "OpenDocSeal Storage Test - $(date)" | mc pipe opendocseal/$BUCKET_NAME/documents/.test-file.txt
echo "✅ Test file created successfully"

# Display bucket information
echo ""
echo "=== MinIO Configuration Complete ==="
echo "Bucket: $BUCKET_NAME"
echo "Region: $BUCKET_REGION"
echo "Endpoint: $MINIO_ENDPOINT"
echo "Console: ${MINIO_BROWSER_REDIRECT_URL:-http://localhost:9001}"
echo ""
echo "Access Information:"
echo "  Username: $MINIO_USER"
echo "  Password: $MINIO_PASS"
echo ""
echo "Application Configuration:"
echo "  MINIO_ENDPOINT=$MINIO_ENDPOINT"
echo "  MINIO_ACCESS_KEY=$MINIO_USER"
echo "  MINIO_SECRET_KEY=$MINIO_PASS"
echo "  MINIO_BUCKET_NAME=$BUCKET_NAME"
echo ""

# Clean up
rm -f /tmp/bucket-policy.json

echo "=== Initialization completed successfully ==="