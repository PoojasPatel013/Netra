#!/bin/bash
set -e

echo "🚀 Starting Netra v2 'Lightweight' Infrastructure Setup..."

# Function to check command existence
check_cmd() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ Error: $1 is not installed. Please install it first."
        exit 1
    fi
}

check_cmd helm
check_cmd kubectl

echo "📦 Adding Helm Repositories..."
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add neo4j https://helm.neo4j.com/neo4j
helm repo update

echo "💾 Deploying Redis (Message Bus)..."
# Standalone architecture to save RAM (vs cluster)
helm upgrade --install netra-redis bitnami/redis \
  --set architecture=standalone \
  --set master.resources.requests.memory="128Mi" \
  --set master.resources.limits.memory="256Mi"

echo "🕸️ Deploying Neo4j (Graph Database)..."
# Community edition, disabled auth for simple local dev
helm upgrade --install netra-neo4j neo4j/neo4j-admin \
  --set neo4j.password=netra-secret \
  --set neo4j.edition=community \
  --set neo4j.resources.requests.memory="512Mi" \
  --set neo4j.resources.limits.memory="1Gi"

echo "🗄️ Deploying MinIO (Model Storage)..."
helm upgrade --install netra-minio bitnami/minio \
  --set auth.rootUser=admin \
  --set auth.rootPassword=netra-storage-secret \
  --set resources.requests.memory="256Mi" \
  --set resources.limits.memory="512Mi"

# ClickHouse is skipped as requested ("RAM not heavy") for the initial v2 setup
# To enable: helm install netra-clickhouse bitnami/clickhouse

echo "✅ Deployment commands sent. Check status with: kubectl get pods"
