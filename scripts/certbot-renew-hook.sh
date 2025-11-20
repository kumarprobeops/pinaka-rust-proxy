#!/bin/bash
#
# Certbot renewal hook for Rust Proxy
# Place this in: /etc/letsencrypt/renewal-hooks/deploy/reload-rust-proxy.sh
#
# This script is automatically executed by certbot after certificate renewal
# It sends SIGHUP to the Rust proxy to trigger hot certificate reload
#

set -e

COMPOSE_FILE="/home/ubuntu/probe-node-2/docker-compose-server2.yml"
CONTAINER_NAME="probe-proxy"  # Will be this name after Rust deployment

echo "[$(date)] Certbot certificate renewal completed"
echo "[$(date)] Triggering Rust proxy certificate reload..."

# Send SIGHUP to the Rust proxy container
if docker compose -f "$COMPOSE_FILE" ps | grep -q "$CONTAINER_NAME"; then
    echo "[$(date)] Sending SIGHUP to $CONTAINER_NAME..."

    # Send SIGHUP signal to the main process in the container
    docker compose -f "$COMPOSE_FILE" kill -s SIGHUP "$CONTAINER_NAME"

    if [ $? -eq 0 ]; then
        echo "[$(date)] ✓ SIGHUP sent successfully to $CONTAINER_NAME"
        echo "[$(date)] ✓ Certificate reload initiated"

        # Wait a moment for reload to complete
        sleep 2

        # Check container logs for reload confirmation
        echo "[$(date)] Checking reload status..."
        docker compose -f "$COMPOSE_FILE" logs --tail=10 "$CONTAINER_NAME" | \
            grep -E "(Reloading TLS|reloaded successfully)" || \
            echo "[$(date)] ⚠ Warning: Could not confirm reload in logs"

    else
        echo "[$(date)] ✗ ERROR: Failed to send SIGHUP to $CONTAINER_NAME"
        exit 1
    fi
else
    echo "[$(date)] ✗ ERROR: Container $CONTAINER_NAME is not running"
    exit 1
fi

echo "[$(date)] Certificate reload hook completed"
