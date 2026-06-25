#!/bin/bash
# Hanzo IAM Deployment Script for Digital Ocean
#
# Prerequisites:
# - doctl CLI configured with API token
# - Docker installed locally
# - SSH access to target droplet
#
# Usage:
#   ./scripts/deploy-do.sh [environment]
#   environment: staging (default) | production
#
# Environment Variables:
#   DO_DROPLET_IP - Target droplet IP address
#   DO_SSH_KEY - Path to SSH key (default: ~/.ssh/id_rsa)

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENVIRONMENT="${1:-staging}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[IAM]${NC} $1"; }
warn() { echo -e "${YELLOW}[IAM]${NC} $1"; }
error() { echo -e "${RED}[IAM]${NC} $1" >&2; }

# Environment-specific configuration
case "$ENVIRONMENT" in
  production)
    DROPLET_NAME="iam-production"
    COMPOSE_FILE="compose.yml"
    DOMAINS="iam.hanzo.ai,hanzo.id,zoo.id,lux.id,pars.id"
    ;;
  staging)
    DROPLET_NAME="iam-staging"
    COMPOSE_FILE="compose.yml"
    DOMAINS="stg.iam.hanzo.ai"
    ;;
  *)
    error "Unknown environment: $ENVIRONMENT"
    exit 1
    ;;
esac

# Check prerequisites
check_prerequisites() {
  log "Checking prerequisites..."

  if ! command -v doctl &> /dev/null; then
    error "doctl CLI not found. Install with: brew install doctl"
    exit 1
  fi

  if ! command -v docker &> /dev/null; then
    error "Docker not found. Install Docker first."
    exit 1
  fi

  if [ -z "${DO_DROPLET_IP:-}" ]; then
    # Try to get IP from doctl
    DO_DROPLET_IP=$(doctl compute droplet list --format Name,PublicIPv4 | grep "$DROPLET_NAME" | awk '{print $2}' || true)
    if [ -z "$DO_DROPLET_IP" ]; then
      error "DO_DROPLET_IP not set and droplet '$DROPLET_NAME' not found"
      exit 1
    fi
  fi

  log "Target: $DO_DROPLET_IP ($ENVIRONMENT)"
}

# Build and push Docker image
build_and_push() {
  log "Building Docker image..."
  cd "$PROJECT_DIR"

  # Build with BuildKit
  DOCKER_BUILDKIT=1 docker build -t ghcr.io/hanzoai/iam:latest .

  log "Pushing to GitHub Container Registry..."
  docker push ghcr.io/hanzoai/iam:latest
}

# Deploy to droplet
deploy_to_droplet() {
  local ssh_key="${DO_SSH_KEY:-$HOME/.ssh/id_rsa}"

  log "Deploying to $DO_DROPLET_IP..."

  # Create deployment directory
  ssh -i "$ssh_key" "root@$DO_DROPLET_IP" "mkdir -p /opt/hanzo/iam"

  # Copy configuration files
  scp -i "$ssh_key" "$PROJECT_DIR/compose.yml" "root@$DO_DROPLET_IP:/opt/hanzo/iam/"
  scp -i "$ssh_key" "$PROJECT_DIR/init_data.json" "root@$DO_DROPLET_IP:/opt/hanzo/iam/"

  # Copy .env if it exists
  if [ -f "$PROJECT_DIR/.env" ]; then
    scp -i "$ssh_key" "$PROJECT_DIR/.env" "root@$DO_DROPLET_IP:/opt/hanzo/iam/"
  else
    warn ".env file not found. Using defaults."
  fi

  # Pull and deploy
  ssh -i "$ssh_key" "root@$DO_DROPLET_IP" << 'DEPLOY_SCRIPT'
    cd /opt/hanzo/iam

    # Login to GHCR
    echo "$GITHUB_TOKEN" | docker login ghcr.io -u hanzoai --password-stdin || true

    # Pull latest images
    docker compose pull

    # Deploy with zero downtime
    docker compose up -d --remove-orphans

    # Wait for health check
    echo "Waiting for services to be healthy..."
    sleep 10

    # Check status
    docker compose ps
DEPLOY_SCRIPT

  log "Deployment complete!"
}

# Health check
health_check() {
  log "Running health checks..."

  local domains=("iam.hanzo.ai" "hanzo.id" "zoo.id" "lux.id" "pars.id")

  for domain in "${domains[@]}"; do
    local status=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://$domain/api/health" 2>/dev/null || echo "000")
    if [ "$status" == "200" ]; then
      log "✓ $domain: healthy"
    else
      warn "✗ $domain: status $status"
    fi
  done
}

# Main execution
main() {
  log "Starting Hanzo IAM deployment ($ENVIRONMENT)..."

  check_prerequisites
  build_and_push
  deploy_to_droplet
  health_check

  log "Deployment finished!"
  log "Domains: $DOMAINS"
}

main "$@"
