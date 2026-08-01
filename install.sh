#!/bin/bash
# pqscan installer
# Usage: curl -sSfL https://raw.githubusercontent.com/Hacker21-punk/pqscan/main/install.sh | bash

set -e

REPO="Hacker21-punk/pqscan"
# Determine version dynamically from GitHub Releases if not pre-set
if [ -z "$VERSION" ] || [ "$VERSION" = "v0.1.0" ]; then
  LATEST_RELEASE=$(curl -sSfL --connect-timeout 5 "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)
  if [ -n "$LATEST_RELEASE" ]; then
    VERSION=$(echo "$LATEST_RELEASE" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
  else
    VERSION="v0.1.0" # Fallback
  fi
fi

INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)       echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case $OS in
  linux)  BINARY="pqscan-linux-${ARCH}" ;;
  darwin) BINARY="pqscan-darwin-${ARCH}" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

echo "Installing pqscan ${VERSION} for ${OS}/${ARCH}..."

URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

# Download binary and checksums
curl -sSfL "$URL" -o /tmp/pqscan
curl -sSfL "$CHECKSUM_URL" -o /tmp/checksums.txt 2>/dev/null || true

# Integrity verification
if [ -f /tmp/checksums.txt ]; then
  echo "Verifying checksum..."
  grep "${BINARY}" /tmp/checksums.txt > /tmp/check.txt || true
  if [ -s /tmp/check.txt ]; then
    cd /tmp
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c check.txt
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 -c check.txt
    else
      echo "⚠ Verification tools missing (sha256sum/shasum); skipping check"
    fi
    cd - >/dev/null
  else
    echo "⚠ Binary checksum not found in checksums.txt; skipping verification"
  fi
else
  echo "⚠ No checksums.txt found for release; skipping verification"
fi

chmod +x /tmp/pqscan

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv /tmp/pqscan "$INSTALL_DIR/pqscan"
else
  sudo mv /tmp/pqscan "$INSTALL_DIR/pqscan"
fi

echo ""
echo "✅ pqscan installed successfully!"
echo ""
echo "Usage:"
echo "  pqscan google.com"
echo "  pqscan --format html -o report.html example.com"
echo ""
pqscan --version

